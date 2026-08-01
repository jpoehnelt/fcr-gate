use std::{path::PathBuf, sync::Arc, time::Instant};

use anyhow::{Context, Result};
use axum::{
    Json, Router,
    extract::State,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use serde::Serialize;
use tokio::{net::TcpListener, sync::oneshot, task::JoinHandle};
use tracing::{error, info};

use crate::{
    config::Config,
    impinj::ReaderHealth,
    logging::LokiMetrics,
    store::{Store, now_ms},
};

#[derive(Clone)]
struct AppState {
    db_path: Arc<PathBuf>,
    reader_health: ReaderHealth,
    health_stale_after_ms: i64,
    started_at: Instant,
    loki_metrics: Arc<LokiMetrics>,
}

pub struct WebHandle {
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

impl WebHandle {
    pub async fn shutdown(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let _ = self.task.await;
    }
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    reader: &'static str,
    reader_last_activity_ms_ago: Option<i64>,
    database: &'static str,
    uptime_seconds: u64,
    version: &'static str,
}

pub async fn start(
    config: &Config,
    reader_health: ReaderHealth,
    loki_metrics: Arc<LokiMetrics>,
) -> Result<WebHandle> {
    let state = AppState {
        db_path: Arc::new(config.state_db.clone()),
        reader_health,
        health_stale_after_ms: i64::try_from(config.health_stale_after.as_millis())
            .unwrap_or(i64::MAX),
        started_at: Instant::now(),
        loki_metrics,
    };
    let app = Router::new()
        .route("/healthz", get(health))
        .route("/metrics", get(metrics))
        .fallback(not_found)
        .with_state(state);
    let listener = TcpListener::bind(config.web_bind)
        .await
        .with_context(|| format!("failed to bind health endpoint at {}", config.web_bind))?;
    let address = listener.local_addr()?;
    let (shutdown_sender, shutdown_receiver) = oneshot::channel();
    let task = tokio::spawn(async move {
        let result = axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = shutdown_receiver.await;
            })
            .await;
        if let Err(error) = result {
            error!(event = "health_service_failed", %error, "health endpoint stopped unexpectedly");
        }
    });
    info!(event = "health_service_listening", %address, "gateway health service listening on loopback");
    Ok(WebHandle {
        shutdown: Some(shutdown_sender),
        task,
    })
}

async fn health(State(state): State<AppState>) -> Response {
    let reader = state.reader_health.snapshot();
    let age = reader
        .last_activity_ms
        .map(|last| now_ms().saturating_sub(last));
    let reader_ok = age.is_some_and(|age| age >= 0 && age <= state.health_stale_after_ms);
    let db_path = Arc::clone(&state.db_path);
    let database_ok = tokio::task::spawn_blocking(move || Store::health_check_path(&db_path))
        .await
        .is_ok_and(|result| result.is_ok());
    let status = if reader_ok && database_ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    let body = HealthResponse {
        status: if status == StatusCode::OK {
            "ok"
        } else {
            "degraded"
        },
        reader: if reader.connected {
            "connected"
        } else {
            "reconnecting"
        },
        reader_last_activity_ms_ago: age,
        database: if database_ok { "ok" } else { "error" },
        uptime_seconds: state.started_at.elapsed().as_secs(),
        version: env!("CARGO_PKG_VERSION"),
    };
    no_store((status, Json(body)).into_response())
}

async fn metrics(State(state): State<AppState>) -> Response {
    let mut response = state.loki_metrics.render_prometheus().into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        "text/plain; version=0.0.4; charset=utf-8"
            .parse()
            .expect("static content type is valid"),
    );
    no_store(response)
}

async fn not_found() -> Response {
    no_store((StatusCode::NOT_FOUND, "not found").into_response())
}

fn no_store(mut response: Response) -> Response {
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        "no-store".parse().expect("static cache policy is valid"),
    );
    response
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    fn state(path: PathBuf) -> AppState {
        AppState {
            db_path: Arc::new(path),
            reader_health: ReaderHealth::default(),
            health_stale_after_ms: 120_000,
            started_at: Instant::now(),
            loki_metrics: Arc::new(LokiMetrics::default()),
        }
    }

    #[tokio::test]
    async fn health_endpoint_accepts_recent_reader_activity() {
        let directory = tempdir().unwrap();
        let db_path = directory.path().join("state.sqlite3");
        Store::open(&db_path, "test").unwrap();
        let app = state(db_path);
        app.reader_health.mark_connected();

        let response = health(State(app.clone())).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");

        app.reader_health.mark_disconnected();
        assert_eq!(health(State(app)).await.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn health_endpoint_fails_for_stale_reader_or_unusable_database() {
        let directory = tempdir().unwrap();
        let stale = state(directory.path().join("state.sqlite3"));
        assert_eq!(
            health(State(stale)).await.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );

        let bad_database = state(directory.path().to_path_buf());
        bad_database.reader_health.mark_connected();
        assert_eq!(
            health(State(bad_database)).await.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[tokio::test]
    async fn metrics_endpoint_exposes_only_delivery_counters() {
        let directory = tempdir().unwrap();
        let response = metrics(State(state(directory.path().join("state.sqlite3")))).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "text/plain; version=0.0.4; charset=utf-8"
        );
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = std::str::from_utf8(&body).unwrap();
        assert!(body.contains("fcr_gate_loki_events_dropped_total"));
        assert!(!body.contains("tid"));
        assert!(!body.contains("plate"));
        assert!(!body.contains("user"));
    }
}

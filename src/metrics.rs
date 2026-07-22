use std::{path::PathBuf, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use axum::{
    Router,
    extract::State,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use prometheus_client::{
    encoding::{EncodeLabelSet, text::encode},
    metrics::{counter::Counter, family::Family, gauge::Gauge, histogram::Histogram},
    registry::Registry,
};
use tokio::{net::TcpListener, sync::oneshot, task::JoinHandle};
use tracing::{error, info};

use crate::{config::Config, impinj::ReaderHealth, store::Store};

const OPENMETRICS_CONTENT_TYPE: &str = "application/openmetrics-text; version=1.0.0; charset=utf-8";
const ENCODING_FAILURE_REASONS: [&str; 4] = ["queue", "access", "timeout", "conflict"];
const LPR_OUTCOMES: [&str; 3] = ["matched", "none", "ambiguous"];
const GATE_DECISIONS: [&str; 3] = ["granted", "denied", "error"];
const GATE_MODES: [&str; 2] = ["dry-run", "live"];
const UNIFI_OPERATIONS: [&str; 7] = [
    "list_users",
    "fetch_lpr_events",
    "unlock_gate",
    "fetch_user",
    "fetch_user_policies",
    "fetch_door_group",
    "fetch_schedule",
];
const REQUEST_RESULTS: [&str; 2] = ["success", "error"];

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct ReasonLabels {
    reason: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct OutcomeLabels {
    outcome: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct GateDecisionLabels {
    decision: &'static str,
    mode: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct UnifiRequestLabels {
    operation: &'static str,
    result: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct BuildLabels {
    version: &'static str,
}

#[derive(Clone)]
pub struct AppMetrics {
    registry: Arc<Registry>,
    reader_connected: Gauge,
    reader_last_activity_timestamp_seconds: Gauge,
    database_healthy: Gauge,
    reader_events: Counter,
    reader_reconnects: Counter,
    encoding_attempts: Counter,
    encoding_failures: Family<ReasonLabels, Counter>,
    encodings: Counter,
    lpr_correlations: Family<OutcomeLabels, Counter>,
    gate_decisions: Family<GateDecisionLabels, Counter>,
    unifi_request_duration_seconds: Family<UnifiRequestLabels, Histogram, fn() -> Histogram>,
}

impl AppMetrics {
    pub fn new() -> Self {
        let reader_connected = Gauge::default();
        let reader_last_activity_timestamp_seconds = Gauge::default();
        let database_healthy = Gauge::default();
        let reader_events = Counter::default();
        let reader_reconnects = Counter::default();
        let encoding_attempts = Counter::default();
        let encoding_failures = Family::<ReasonLabels, Counter>::default();
        let encodings = Counter::default();
        let lpr_correlations = Family::<OutcomeLabels, Counter>::default();
        let gate_decisions = Family::<GateDecisionLabels, Counter>::default();
        let unifi_request_duration_seconds =
            Family::new_with_constructor(request_duration_histogram as fn() -> Histogram);
        let build_info = Family::<BuildLabels, Gauge>::default();

        for reason in ENCODING_FAILURE_REASONS {
            let _ = encoding_failures.get_or_create(&ReasonLabels { reason });
        }
        for outcome in LPR_OUTCOMES {
            let _ = lpr_correlations.get_or_create(&OutcomeLabels { outcome });
        }
        for decision in GATE_DECISIONS {
            for mode in GATE_MODES {
                let _ = gate_decisions.get_or_create(&GateDecisionLabels { decision, mode });
            }
        }
        for operation in UNIFI_OPERATIONS {
            for result in REQUEST_RESULTS {
                let _ = unifi_request_duration_seconds
                    .get_or_create(&UnifiRequestLabels { operation, result });
            }
        }
        build_info
            .get_or_create(&BuildLabels {
                version: env!("CARGO_PKG_VERSION"),
            })
            .set(1);

        let mut registry = Registry::default();
        registry.register(
            "fcr_gate_reader_connected",
            "Whether the Impinj reader event stream is currently connected",
            reader_connected.clone(),
        );
        registry.register(
            "fcr_gate_reader_last_activity_timestamp_seconds",
            "Unix timestamp of the latest Impinj reader stream activity",
            reader_last_activity_timestamp_seconds.clone(),
        );
        registry.register(
            "fcr_gate_database_healthy",
            "Whether the RFID state database passed its health check",
            database_healthy.clone(),
        );
        registry.register(
            "fcr_gate_reader_events",
            "Reader events received by the encoder service",
            reader_events.clone(),
        );
        registry.register(
            "fcr_gate_reader_reconnects",
            "Reader event stream reconnect attempts",
            reader_reconnects.clone(),
        );
        registry.register(
            "fcr_gate_encoding_attempts",
            "EPC write requests sent to the reader",
            encoding_attempts.clone(),
        );
        registry.register(
            "fcr_gate_encoding_failures",
            "Encoding failures by bounded failure reason",
            encoding_failures.clone(),
        );
        registry.register(
            "fcr_gate_encodings",
            "EPC encodings verified and confirmed by inventory",
            encodings.clone(),
        );
        registry.register(
            "fcr_gate_lpr_correlations",
            "LPR correlation outcomes",
            lpr_correlations.clone(),
        );
        registry.register(
            "fcr_gate_gate_decisions",
            "Final gate authorization outcomes by operating mode",
            gate_decisions.clone(),
        );
        registry.register(
            "fcr_gate_unifi_request_duration_seconds",
            "Duration of UniFi Access API requests",
            unifi_request_duration_seconds.clone(),
        );
        registry.register(
            "fcr_gate_build_info",
            "FCR Gate service build information",
            build_info,
        );

        Self {
            registry: Arc::new(registry),
            reader_connected,
            reader_last_activity_timestamp_seconds,
            database_healthy,
            reader_events,
            reader_reconnects,
            encoding_attempts,
            encoding_failures,
            encodings,
            lpr_correlations,
            gate_decisions,
            unifi_request_duration_seconds,
        }
    }

    pub fn reader_event(&self) {
        self.reader_events.inc();
    }

    pub fn reader_reconnect(&self) {
        self.reader_reconnects.inc();
    }

    pub fn encoding_attempt(&self) {
        self.encoding_attempts.inc();
    }

    pub fn encoding_failure(&self, reason: &'static str) {
        debug_assert!(ENCODING_FAILURE_REASONS.contains(&reason));
        self.encoding_failures
            .get_or_create(&ReasonLabels { reason })
            .inc();
    }

    pub fn encoding_completed(&self) {
        self.encodings.inc();
    }

    pub fn lpr_correlation(&self, outcome: &'static str) {
        debug_assert!(LPR_OUTCOMES.contains(&outcome));
        self.lpr_correlations
            .get_or_create(&OutcomeLabels { outcome })
            .inc();
    }

    pub fn gate_decision(&self, decision: &'static str, mode: &'static str) {
        debug_assert!(GATE_DECISIONS.contains(&decision));
        debug_assert!(GATE_MODES.contains(&mode));
        self.gate_decisions
            .get_or_create(&GateDecisionLabels { decision, mode })
            .inc();
    }

    pub fn unifi_request(&self, operation: &'static str, successful: bool, duration: Duration) {
        debug_assert!(UNIFI_OPERATIONS.contains(&operation));
        let result = if successful { "success" } else { "error" };
        self.unifi_request_duration_seconds
            .get_or_create(&UnifiRequestLabels { operation, result })
            .observe(duration.as_secs_f64());
    }

    async fn render(&self, reader_health: &ReaderHealth, db_path: Arc<PathBuf>) -> Result<String> {
        let snapshot = reader_health.snapshot();
        self.reader_connected.set(i64::from(snapshot.connected));
        self.reader_last_activity_timestamp_seconds
            .set(snapshot.last_activity_ms.unwrap_or_default() / 1000);
        let database_ok = tokio::task::spawn_blocking(move || {
            Store::open(&db_path, "metrics")
                .and_then(|store| store.health_check())
                .is_ok()
        })
        .await
        .unwrap_or(false);
        self.database_healthy.set(i64::from(database_ok));

        let mut body = String::new();
        encode(&mut body, &self.registry).context("failed to encode Prometheus metrics")?;
        Ok(body)
    }
}

impl Default for AppMetrics {
    fn default() -> Self {
        Self::new()
    }
}

fn request_duration_histogram() -> Histogram {
    Histogram::new([0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0])
}

#[derive(Clone)]
struct MetricsState {
    metrics: AppMetrics,
    reader_health: ReaderHealth,
    db_path: Arc<PathBuf>,
}

pub struct MetricsHandle {
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

impl MetricsHandle {
    pub async fn shutdown(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let _ = self.task.await;
    }
}

pub async fn bind(config: &Config) -> Result<TcpListener> {
    TcpListener::bind(config.metrics_bind)
        .await
        .with_context(|| {
            format!(
                "failed to bind Prometheus metrics to {}",
                config.metrics_bind
            )
        })
}

pub fn start(
    config: &Config,
    metrics: AppMetrics,
    reader_health: ReaderHealth,
    listener: TcpListener,
) -> MetricsHandle {
    let state = MetricsState {
        metrics,
        reader_health,
        db_path: Arc::new(config.state_db.clone()),
    };
    let router = Router::new()
        .route("/metrics", get(metrics_endpoint))
        .with_state(state);
    let (shutdown_sender, shutdown_receiver) = oneshot::channel();
    let address = config.metrics_bind;
    let task = tokio::spawn(async move {
        let server = axum::serve(listener, router).with_graceful_shutdown(async {
            let _ = shutdown_receiver.await;
        });
        if let Err(error) = server.await {
            error!(%error, "Prometheus metrics endpoint stopped unexpectedly");
        }
    });
    info!(%address, "Prometheus metrics endpoint listening");
    MetricsHandle {
        shutdown: Some(shutdown_sender),
        task,
    }
}

async fn metrics_endpoint(State(state): State<MetricsState>) -> Response {
    match state
        .metrics
        .render(&state.reader_health, state.db_path.clone())
        .await
    {
        Ok(body) => {
            let mut response = body.into_response();
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static(OPENMETRICS_CONTENT_TYPE),
            );
            response
        }
        Err(error) => {
            error!(%error, "could not render Prometheus metrics");
            (StatusCode::INTERNAL_SERVER_ERROR, "metrics unavailable\n").into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use tempfile::tempdir;

    #[tokio::test]
    async fn metrics_include_health_counters_histograms_and_no_tag_identity() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("metrics.sqlite3");
        Store::open(&db_path, "test").unwrap();
        let health = ReaderHealth::default();
        health.mark_connected();
        let metrics = AppMetrics::new();
        metrics.reader_event();
        metrics.reader_reconnect();
        metrics.encoding_attempt();
        metrics.encoding_failure("access");
        metrics.encoding_completed();
        metrics.lpr_correlation("matched");
        metrics.gate_decision("granted", "dry-run");
        metrics.unifi_request("fetch_user", true, Duration::from_millis(125));

        let body = metrics.render(&health, Arc::new(db_path)).await.unwrap();
        assert!(body.contains("fcr_gate_reader_connected 1"));
        assert!(body.contains("fcr_gate_database_healthy 1"));
        assert!(body.contains("fcr_gate_reader_events_total 1"));
        assert!(body.contains("fcr_gate_reader_reconnects_total 1"));
        assert!(body.contains("fcr_gate_encoding_attempts_total 1"));
        assert!(body.contains("fcr_gate_encoding_failures_total{reason=\"access\"} 1"));
        assert!(body.contains("fcr_gate_encodings_total 1"));
        assert!(body.contains("fcr_gate_lpr_correlations_total{outcome=\"matched\"} 1"));
        assert!(
            body.contains("fcr_gate_gate_decisions_total{decision=\"granted\",mode=\"dry-run\"} 1")
        );
        assert!(body.contains(
            "fcr_gate_unifi_request_duration_seconds_count{operation=\"fetch_user\",result=\"success\"} 1"
        ));
        assert!(body.contains("fcr_gate_build_info{version=\""));
        assert!(!body.contains("300833B2DDD9014000000000"));
        assert!(!body.contains("operator@example.com"));
    }

    #[tokio::test]
    async fn database_failure_is_exposed_without_breaking_the_scrape() {
        let dir = tempdir().unwrap();
        let metrics = AppMetrics::new();
        let health = ReaderHealth::default();
        let body = metrics
            .render(&health, Arc::new(dir.path().to_path_buf()))
            .await
            .unwrap();
        assert!(body.contains("fcr_gate_reader_connected 0"));
        assert!(body.contains("fcr_gate_database_healthy 0"));
    }

    #[tokio::test]
    async fn endpoint_returns_openmetrics_without_operator_authentication() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("endpoint.sqlite3");
        Store::open(&db_path, "test").unwrap();
        let response = metrics_endpoint(State(MetricsState {
            metrics: AppMetrics::new(),
            reader_health: ReaderHealth::default(),
            db_path: Arc::new(db_path),
        }))
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            OPENMETRICS_CONTENT_TYPE
        );
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert!(String::from_utf8_lossy(&body).ends_with("# EOF\n"));
    }
}

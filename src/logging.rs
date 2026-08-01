use std::{
    env,
    io::{self, Write},
    mem,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use reqwest::{Client, Url};
use serde_json::json;
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
};
use tracing::Subscriber;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::MakeWriter;

const LOKI_PUSH_PATH: &str = "/loki/api/v1/push";
const LOKI_QUEUE_CAPACITY: usize = 4096;
const LOKI_BATCH_SIZE: usize = 100;
const LOKI_FLUSH_INTERVAL: Duration = Duration::from_secs(1);
const LOKI_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const LOKI_MAX_BACKOFF: Duration = Duration::from_secs(30);

#[derive(Default)]
pub struct LokiMetrics {
    enabled: AtomicU64,
    events_enqueued: AtomicU64,
    events_dropped: AtomicU64,
    events_sent: AtomicU64,
    requests_succeeded: AtomicU64,
    requests_failed: AtomicU64,
    queue_depth: AtomicU64,
    last_success_timestamp_seconds: AtomicU64,
}

impl LokiMetrics {
    pub fn enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed) == 1
    }

    pub fn render_prometheus(&self) -> String {
        format!(
            concat!(
                "# HELP fcr_gate_loki_enabled Whether direct Loki delivery is configured.\n",
                "# TYPE fcr_gate_loki_enabled gauge\n",
                "fcr_gate_loki_enabled {}\n",
                "# HELP fcr_gate_loki_events_enqueued_total JSON log events accepted by the Loki queue.\n",
                "# TYPE fcr_gate_loki_events_enqueued_total counter\n",
                "fcr_gate_loki_events_enqueued_total {}\n",
                "# HELP fcr_gate_loki_events_dropped_total JSON log events dropped from remote delivery; journald still retains them.\n",
                "# TYPE fcr_gate_loki_events_dropped_total counter\n",
                "fcr_gate_loki_events_dropped_total {}\n",
                "# HELP fcr_gate_loki_events_sent_total JSON log events accepted by Loki.\n",
                "# TYPE fcr_gate_loki_events_sent_total counter\n",
                "fcr_gate_loki_events_sent_total {}\n",
                "# HELP fcr_gate_loki_requests_total Loki push requests by result.\n",
                "# TYPE fcr_gate_loki_requests_total counter\n",
                "fcr_gate_loki_requests_total{{result=\"success\"}} {}\n",
                "fcr_gate_loki_requests_total{{result=\"failure\"}} {}\n",
                "# HELP fcr_gate_loki_queue_depth Events currently waiting in the bounded Loki queue.\n",
                "# TYPE fcr_gate_loki_queue_depth gauge\n",
                "fcr_gate_loki_queue_depth {}\n",
                "# HELP fcr_gate_loki_last_success_timestamp_seconds Unix timestamp of the most recent successful Loki push.\n",
                "# TYPE fcr_gate_loki_last_success_timestamp_seconds gauge\n",
                "fcr_gate_loki_last_success_timestamp_seconds {}\n",
            ),
            self.enabled.load(Ordering::Relaxed),
            self.events_enqueued.load(Ordering::Relaxed),
            self.events_dropped.load(Ordering::Relaxed),
            self.events_sent.load(Ordering::Relaxed),
            self.requests_succeeded.load(Ordering::Relaxed),
            self.requests_failed.load(Ordering::Relaxed),
            self.queue_depth.load(Ordering::Relaxed),
            self.last_success_timestamp_seconds.load(Ordering::Relaxed),
        )
    }
}

pub struct LoggingHandle {
    metrics: Arc<LokiMetrics>,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
}

impl LoggingHandle {
    pub fn metrics(&self) -> Arc<LokiMetrics> {
        Arc::clone(&self.metrics)
    }

    pub async fn shutdown(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}

#[derive(Clone, Debug)]
struct LokiConfig {
    url: Url,
    host: String,
    site: String,
}

impl LokiConfig {
    fn from_env() -> Result<Option<Self>> {
        let Ok(raw_url) = env::var("FCR_GATE_LOKI_URL") else {
            return Ok(None);
        };
        if raw_url.trim().is_empty() {
            return Ok(None);
        }
        let url = validate_loki_url(&raw_url)?;
        let host = loki_label("FCR_GATE_HOST", "falls-creek-ranch-gate")?;
        let site = loki_label("FCR_GATE_SITE", "falls-creek-ranch")?;
        Ok(Some(Self { url, host, site }))
    }
}

#[derive(Debug)]
struct LokiRecord {
    timestamp_ns: String,
    line: String,
}

#[derive(Clone)]
struct LokiSink {
    sender: mpsc::Sender<String>,
}

#[derive(Clone)]
struct JournalAndLoki<W> {
    journal: W,
    sink: Option<LokiSink>,
    metrics: Arc<LokiMetrics>,
}

struct JournalAndLokiWriter<W> {
    journal: W,
    sink: Option<LokiSink>,
    metrics: Arc<LokiMetrics>,
    buffer: Vec<u8>,
    journal_failed: bool,
}

impl<'writer, W> MakeWriter<'writer> for JournalAndLoki<W>
where
    W: MakeWriter<'writer>,
{
    type Writer = JournalAndLokiWriter<W::Writer>;

    fn make_writer(&'writer self) -> Self::Writer {
        JournalAndLokiWriter {
            journal: self.journal.make_writer(),
            sink: self.sink.clone(),
            metrics: Arc::clone(&self.metrics),
            buffer: Vec::new(),
            journal_failed: false,
        }
    }
}

impl<W: Write> Write for JournalAndLokiWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let written = match self.journal.write(bytes) {
            Ok(written) => written,
            Err(error) => {
                self.journal_failed = true;
                return Err(error);
            }
        };
        if written == 0 && !bytes.is_empty() {
            self.journal_failed = true;
        }
        if self.sink.is_some() {
            self.buffer.extend_from_slice(&bytes[..written]);
        }
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.journal.flush() {
            Ok(()) => Ok(()),
            Err(error) => {
                self.journal_failed = true;
                Err(error)
            }
        }
    }
}

impl<W> Drop for JournalAndLokiWriter<W> {
    fn drop(&mut self) {
        if self.journal_failed {
            return;
        }
        let Some(sink) = &self.sink else {
            return;
        };
        while matches!(self.buffer.last(), Some(b'\n' | b'\r')) {
            self.buffer.pop();
        }
        if self.buffer.is_empty() {
            return;
        }
        let Ok(line) = String::from_utf8(mem::take(&mut self.buffer)) else {
            self.metrics.events_dropped.fetch_add(1, Ordering::Relaxed);
            return;
        };
        self.metrics.queue_depth.fetch_add(1, Ordering::Relaxed);
        match sink.sender.try_send(line) {
            Ok(()) => {
                self.metrics.events_enqueued.fetch_add(1, Ordering::Relaxed);
            }
            Err(_) => {
                self.metrics.queue_depth.fetch_sub(1, Ordering::Relaxed);
                self.metrics.events_dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

pub fn init() -> LoggingHandle {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let metrics = Arc::new(LokiMetrics::default());
    let config = match LokiConfig::from_env() {
        Ok(config) => config,
        Err(error) => {
            internal_event(
                "ERROR",
                "loki_config_invalid",
                "direct Loki delivery is disabled; journald remains active",
                Some(&error.to_string()),
            );
            None
        }
    };
    let (sink, shutdown, task) = if let Some(config) = config {
        metrics.enabled.store(1, Ordering::Relaxed);
        let (sender, receiver) = mpsc::channel(LOKI_QUEUE_CAPACITY);
        let (shutdown_sender, shutdown_receiver) = oneshot::channel();
        let task_metrics = Arc::clone(&metrics);
        let task = tokio::spawn(async move {
            loki_worker(config, receiver, shutdown_receiver, task_metrics).await;
        });
        (Some(LokiSink { sender }), Some(shutdown_sender), Some(task))
    } else {
        (None, None, None)
    };
    tracing::subscriber::set_global_default(subscriber(
        std::io::stderr,
        filter,
        sink,
        Arc::clone(&metrics),
    ))
    .expect("global tracing subscriber was already initialized");
    LoggingHandle {
        metrics,
        shutdown,
        task,
    }
}

fn subscriber<W>(
    writer: W,
    filter: EnvFilter,
    sink: Option<LokiSink>,
    metrics: Arc<LokiMetrics>,
) -> impl Subscriber + Send + Sync
where
    W: for<'writer> MakeWriter<'writer> + Send + Sync + 'static,
{
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .json()
        .flatten_event(true)
        .with_current_span(false)
        .with_span_list(false)
        .with_ansi(false)
        .with_target(false)
        .with_writer(JournalAndLoki {
            journal: writer,
            sink,
            metrics,
        })
        .finish()
}

async fn loki_worker(
    config: LokiConfig,
    mut receiver: mpsc::Receiver<String>,
    mut shutdown: oneshot::Receiver<()>,
    metrics: Arc<LokiMetrics>,
) {
    let client = match Client::builder()
        .connect_timeout(Duration::from_secs(3))
        .timeout(LOKI_REQUEST_TIMEOUT)
        .user_agent(concat!("fcr-gate/", env!("CARGO_PKG_VERSION")))
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            internal_event(
                "ERROR",
                "loki_client_failed",
                "could not build the Loki HTTP client; journald remains active",
                Some(&error.to_string()),
            );
            return;
        }
    };
    let mut batch = Vec::with_capacity(LOKI_BATCH_SIZE);
    let mut flush = tokio::time::interval(LOKI_FLUSH_INTERVAL);
    flush.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    flush.tick().await;
    let mut backoff = Duration::from_secs(1);
    let mut delivery_failed = false;
    let clock = AtomicU64::new(0);

    loop {
        let should_flush = tokio::select! {
            _ = &mut shutdown => {
                while batch.len() < LOKI_BATCH_SIZE {
                    let Ok(line) = receiver.try_recv() else { break; };
                    metrics.queue_depth.fetch_sub(1, Ordering::Relaxed);
                    batch.push(LokiRecord {
                        timestamp_ns: next_timestamp_ns(&clock).to_string(),
                        line,
                    });
                }
                if !batch.is_empty() {
                    record_push_result(push_batch(&client, &config, &batch).await, &batch, &metrics);
                }
                return;
            }
            line = receiver.recv() => {
                let Some(line) = line else { return; };
                metrics.queue_depth.fetch_sub(1, Ordering::Relaxed);
                batch.push(LokiRecord {
                    timestamp_ns: next_timestamp_ns(&clock).to_string(),
                    line,
                });
                batch.len() >= LOKI_BATCH_SIZE
            }
            _ = flush.tick(), if !batch.is_empty() => true,
        };

        if !should_flush {
            continue;
        }
        match push_batch(&client, &config, &batch).await {
            Ok(()) => {
                metrics.requests_succeeded.fetch_add(1, Ordering::Relaxed);
                metrics
                    .events_sent
                    .fetch_add(batch.len() as u64, Ordering::Relaxed);
                metrics.last_success_timestamp_seconds.store(
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                    Ordering::Relaxed,
                );
                batch.clear();
                backoff = Duration::from_secs(1);
                if delivery_failed {
                    internal_event(
                        "INFO",
                        "loki_delivery_recovered",
                        "direct Loki delivery recovered; journald remained active",
                        None,
                    );
                    delivery_failed = false;
                }
            }
            Err(error) => {
                metrics.requests_failed.fetch_add(1, Ordering::Relaxed);
                if !delivery_failed {
                    internal_event(
                        "WARN",
                        "loki_delivery_failed",
                        "direct Loki delivery failed; retaining logs in journald and retrying",
                        Some(&error.to_string()),
                    );
                    delivery_failed = true;
                }
                tokio::select! {
                    _ = &mut shutdown => return,
                    _ = tokio::time::sleep(backoff) => {}
                }
                backoff = (backoff * 2).min(LOKI_MAX_BACKOFF);
            }
        }
    }
}

async fn push_batch(client: &Client, config: &LokiConfig, batch: &[LokiRecord]) -> Result<()> {
    let values: Vec<[&str; 2]> = batch
        .iter()
        .map(|record| [record.timestamp_ns.as_str(), record.line.as_str()])
        .collect();
    let payload = json!({
        "streams": [{
            "stream": {
                "service_name": "fcr-gate",
                "host": config.host,
                "site": config.site,
            },
            "values": values,
        }]
    });
    client
        .post(config.url.clone())
        .json(&payload)
        .send()
        .await
        .context("Loki push request failed")?
        .error_for_status()
        .context("Loki rejected the push request")?;
    Ok(())
}

fn record_push_result(result: Result<()>, batch: &[LokiRecord], metrics: &LokiMetrics) {
    match result {
        Ok(()) => {
            metrics.requests_succeeded.fetch_add(1, Ordering::Relaxed);
            metrics
                .events_sent
                .fetch_add(batch.len() as u64, Ordering::Relaxed);
            metrics.last_success_timestamp_seconds.store(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                Ordering::Relaxed,
            );
        }
        Err(_) => {
            metrics.requests_failed.fetch_add(1, Ordering::Relaxed);
            metrics
                .events_dropped
                .fetch_add(batch.len() as u64, Ordering::Relaxed);
        }
    }
}

fn validate_loki_url(value: &str) -> Result<Url> {
    let url = Url::parse(value.trim()).context("FCR_GATE_LOKI_URL is not a valid URL")?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || url.path() != LOKI_PUSH_PATH
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        bail!(
            "FCR_GATE_LOKI_URL must be an HTTP(S) URL without credentials, query, or fragment and must end with {LOKI_PUSH_PATH}"
        );
    }
    Ok(url)
}

fn loki_label(name: &str, default: &str) -> Result<String> {
    let value = env::var(name).unwrap_or_else(|_| default.to_owned());
    let value = value.trim();
    if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
        bail!("{name} must contain 1-128 printable characters");
    }
    Ok(value.to_owned())
}

fn next_timestamp_ns(clock: &AtomicU64) -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .min(u128::from(u64::MAX)) as u64;
    let mut previous = clock.load(Ordering::Relaxed);
    loop {
        let next = now.max(previous.saturating_add(1));
        match clock.compare_exchange_weak(previous, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return next,
            Err(actual) => previous = actual,
        }
    }
}

fn internal_event(level: &str, event: &str, message: &str, error: Option<&str>) {
    let mut record = json!({
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "level": level,
        "event": event,
        "message": message,
    });
    if let Some(error) = error {
        record["error"] = error.into();
    }
    eprintln!("{record}");
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use axum::{Json, Router, extract::State, routing::post};
    use serde_json::Value;
    use tokio::net::TcpListener;
    use tracing::info;

    use super::*;

    #[derive(Clone, Default)]
    struct SharedWriter(Arc<Mutex<Vec<u8>>>);

    struct SharedGuard(Arc<Mutex<Vec<u8>>>);

    #[derive(Clone)]
    struct FailingWriter;

    struct FailingGuard;

    impl Write for SharedGuard {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'writer> MakeWriter<'writer> for SharedWriter {
        type Writer = SharedGuard;

        fn make_writer(&'writer self) -> Self::Writer {
            SharedGuard(Arc::clone(&self.0))
        }
    }

    impl Write for FailingGuard {
        fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("journal unavailable"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::other("journal unavailable"))
        }
    }

    impl<'writer> MakeWriter<'writer> for FailingWriter {
        type Writer = FailingGuard;

        fn make_writer(&'writer self) -> Self::Writer {
            FailingGuard
        }
    }

    async fn capture_loki_payload(
        State(captured): State<Arc<Mutex<Option<Value>>>>,
        Json(payload): Json<Value>,
    ) {
        *captured.lock().unwrap() = Some(payload);
    }

    #[test]
    fn service_events_are_flat_json_and_copied_to_loki() {
        let output = SharedWriter::default();
        let metrics = Arc::new(LokiMetrics::default());
        let (sender, mut receiver) = mpsc::channel(1);
        tracing::subscriber::with_default(
            subscriber(
                output.clone(),
                EnvFilter::new("info"),
                Some(LokiSink { sender }),
                Arc::clone(&metrics),
            ),
            || {
                info!(
                    event = "lpr_correlation_match",
                    mode = "dry-run",
                    decision = "would-assign",
                    tid = "E2801234",
                    "test event"
                );
            },
        );

        let bytes = output.0.lock().unwrap().clone();
        let journal_event: Value = serde_json::from_slice(&bytes).unwrap();
        let loki_line = receiver.try_recv().unwrap();
        let loki_event: Value = serde_json::from_str(&loki_line).unwrap();
        assert_eq!(journal_event, loki_event);
        assert_eq!(journal_event["level"], "INFO");
        assert_eq!(journal_event["event"], "lpr_correlation_match");
        assert_eq!(journal_event["mode"], "dry-run");
        assert_eq!(journal_event["decision"], "would-assign");
        assert_eq!(journal_event["tid"], "E2801234");
        assert_eq!(journal_event["message"], "test event");
        assert!(journal_event.get("fields").is_none());
        assert!(journal_event.get("target").is_none());
        assert_eq!(metrics.events_enqueued.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.events_dropped.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn full_loki_queue_drops_only_the_remote_copy() {
        let output = SharedWriter::default();
        let metrics = Arc::new(LokiMetrics::default());
        let (sender, _receiver) = mpsc::channel(1);
        sender.try_send("{}".into()).unwrap();
        tracing::subscriber::with_default(
            subscriber(
                output.clone(),
                EnvFilter::new("info"),
                Some(LokiSink { sender }),
                Arc::clone(&metrics),
            ),
            || info!(event = "queue_test", "journal survives"),
        );

        let event: Value = serde_json::from_slice(&output.0.lock().unwrap()).unwrap();
        assert_eq!(event["event"], "queue_test");
        assert_eq!(metrics.events_dropped.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn failed_journal_write_is_not_copied_to_loki() {
        let metrics = Arc::new(LokiMetrics::default());
        let (sender, mut receiver) = mpsc::channel(1);
        tracing::subscriber::with_default(
            subscriber(
                FailingWriter,
                EnvFilter::new("info"),
                Some(LokiSink { sender }),
                Arc::clone(&metrics),
            ),
            || info!(event = "journal_failure_test", "must not reach Loki"),
        );

        assert!(receiver.try_recv().is_err());
        assert_eq!(metrics.events_enqueued.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn loki_url_requires_the_push_path_and_rejects_credentials() {
        assert!(validate_loki_url("http://loki.tail1f002.ts.net:3100/loki/api/v1/push").is_ok());
        assert!(validate_loki_url("http://loki.tail1f002.ts.net:3100/ready").is_err());
        assert!(validate_loki_url("http://user:secret@loki.test/loki/api/v1/push").is_err());
    }

    #[tokio::test]
    async fn push_batch_uses_the_loki_stream_format_and_stable_labels() {
        let captured = Arc::new(Mutex::new(None));
        let app = Router::new()
            .route(LOKI_PUSH_PATH, post(capture_loki_payload))
            .with_state(Arc::clone(&captured));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let config = LokiConfig {
            url: Url::parse(&format!("http://{address}{LOKI_PUSH_PATH}")).unwrap(),
            host: "gate-test".into(),
            site: "fcr-test".into(),
        };
        let records = [LokiRecord {
            timestamp_ns: "123456789".into(),
            line: r#"{"event":"service_ready"}"#.into(),
        }];

        push_batch(&Client::new(), &config, &records).await.unwrap();

        let payload = captured.lock().unwrap().take().unwrap();
        assert_eq!(payload["streams"][0]["stream"]["service_name"], "fcr-gate");
        assert_eq!(payload["streams"][0]["stream"]["host"], "gate-test");
        assert_eq!(payload["streams"][0]["stream"]["site"], "fcr-test");
        assert_eq!(payload["streams"][0]["values"][0][0], "123456789");
        assert_eq!(
            payload["streams"][0]["values"][0][1],
            r#"{"event":"service_ready"}"#
        );
        server.abort();
    }

    #[test]
    fn prometheus_metrics_explain_that_journald_retains_dropped_events() {
        let metrics = LokiMetrics::default();
        metrics.events_dropped.store(2, Ordering::Relaxed);
        let rendered = metrics.render_prometheus();
        assert!(rendered.contains("fcr_gate_loki_events_dropped_total 2"));
        assert!(rendered.contains("journald still retains them"));
    }
}

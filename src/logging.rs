use tracing::Subscriber;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::MakeWriter;

pub fn init() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing::subscriber::set_global_default(subscriber(std::io::stderr, filter))
        .expect("global tracing subscriber was already initialized");
}

fn subscriber<W>(writer: W, filter: EnvFilter) -> impl Subscriber + Send + Sync
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
        .with_writer(writer)
        .finish()
}

#[cfg(test)]
mod tests {
    use std::io::{self, Write};
    use std::sync::{Arc, Mutex};

    use serde_json::Value;
    use tracing::info;

    use super::*;

    #[derive(Clone, Default)]
    struct SharedWriter(Arc<Mutex<Vec<u8>>>);

    struct SharedGuard(Arc<Mutex<Vec<u8>>>);

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

    #[test]
    fn service_events_are_flat_json() {
        let output = SharedWriter::default();
        tracing::subscriber::with_default(
            subscriber(output.clone(), EnvFilter::new("info")),
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
        let event: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(event["level"], "INFO");
        assert_eq!(event["event"], "lpr_correlation_match");
        assert_eq!(event["mode"], "dry-run");
        assert_eq!(event["decision"], "would-assign");
        assert_eq!(event["tid"], "E2801234");
        assert_eq!(event["message"], "test event");
        assert!(event.get("fields").is_none());
        assert!(event.get("target").is_none());
    }
}

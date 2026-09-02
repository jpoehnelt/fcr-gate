use std::{
    fs,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicI64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use futures_util::StreamExt;
use reqwest::Client;
use serde::Deserialize;
use serde_json::Value;
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::{config::Config, model::ReaderEvent};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const STREAM_STALL_TIMEOUT: Duration = Duration::from_secs(90);
const MAX_STREAM_LINE_BYTES: usize = 1024 * 1024;

#[derive(Clone, Default)]
pub struct ReaderHealth {
    inner: Arc<ReaderHealthInner>,
}

#[derive(Default)]
struct ReaderHealthInner {
    connected: AtomicBool,
    last_activity_ms: AtomicI64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReaderHealthSnapshot {
    pub connected: bool,
    pub last_activity_ms: Option<i64>,
}

impl ReaderHealth {
    pub fn snapshot(&self) -> ReaderHealthSnapshot {
        let last_activity_ms = self.inner.last_activity_ms.load(Ordering::Relaxed);
        ReaderHealthSnapshot {
            connected: self.inner.connected.load(Ordering::Relaxed),
            last_activity_ms: (last_activity_ms > 0).then_some(last_activity_ms),
        }
    }

    pub(crate) fn mark_connected(&self) {
        self.inner.connected.store(true, Ordering::Relaxed);
        self.mark_activity();
    }

    fn mark_activity(&self) {
        self.inner
            .last_activity_ms
            .store(system_now_ms(), Ordering::Relaxed);
    }

    pub(crate) fn mark_disconnected(&self) {
        self.inner.connected.store(false, Ordering::Relaxed);
    }
}

#[derive(Clone)]
pub struct ImpinjClient {
    http: Client,
    base_url: String,
    username: String,
    password: String,
    health: ReaderHealth,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReaderStatus {
    interface: String,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    active_preset: Option<ActivePreset>,
}

#[derive(Debug, Deserialize)]
struct ActivePreset {
    #[serde(default)]
    id: Option<String>,
    profile: String,
}

fn active_inventory_preset(status: &ReaderStatus) -> Result<Option<String>> {
    if status.interface != "IoT" {
        bail!(
            "reader interface is {}; select the Impinj IoT Device Interface before running the RFID service",
            status.interface
        );
    }
    if status.status.as_deref() == Some("no region") {
        bail!("reader has no regulatory region configured");
    }
    match status.status.as_deref() {
        Some("running" | "armed") => {
            let active = status
                .active_preset
                .as_ref()
                .context("reader is active but did not report an active preset")?;
            if active.profile != "inventory" {
                bail!(
                    "reader is running profile {} ({}); the service only streams an externally managed inventory preset",
                    active.profile,
                    active.id.as_deref().unwrap_or("transient")
                );
            }
            Ok(active.id.clone())
        }
        Some("idle") => bail!(
            "reader is idle; start the externally managed inventory preset before running the RFID service"
        ),
        Some(other) => bail!("reader is in unsupported state {other}"),
        None => bail!("reader did not report an IoT inventory state"),
    }
}

/// Read-only check that the externally owned preset reports the fields learned
/// ownership depends on: TID (via FastID) on the watched antenna. An EPC-only
/// preset would silently downgrade tag keys from TID to `EPC:<epc>`.
///
/// The R700 omits defaulted keys from preset bodies, so an absent key means
/// "reader default", not "disabled": warn and continue. Only an explicit
/// non-enabled value fails startup.
fn verify_tid_reporting(preset: &Value, preset_id: &str, antenna_port: u16) -> Result<()> {
    match preset
        .pointer("/eventConfig/tagInventory/tidHex")
        .and_then(Value::as_str)
    {
        Some("enabled") => {}
        Some(other) => bail!(
            "preset {preset_id} sets eventConfig.tagInventory.tidHex to {other}; enable TID reporting on the reader before running the RFID service"
        ),
        None => warn!(
            event = "reader_preset_tid_unverified",
            preset = preset_id,
            "preset omits eventConfig.tagInventory.tidHex; relying on the reader default"
        ),
    }
    let antenna = match preset.pointer("/antennaConfigs").and_then(Value::as_array) {
        None => {
            warn!(
                event = "reader_preset_antenna_unverified",
                preset = preset_id,
                "preset omits antennaConfigs; relying on the reader default"
            );
            return Ok(());
        }
        Some(configs) => configs
            .iter()
            .find(|config| {
                config.pointer("/antennaPort").and_then(Value::as_u64)
                    == Some(u64::from(antenna_port))
            })
            .with_context(|| {
                format!("preset {preset_id} has no antennaConfig for antenna port {antenna_port}")
            })?,
    };
    match antenna.pointer("/fastId").and_then(Value::as_str) {
        Some("enabled") => {}
        Some(other) => bail!(
            "preset {preset_id} sets fastId to {other} on antenna port {antenna_port}; TID reporting requires FastID"
        ),
        None => warn!(
            event = "reader_preset_fastid_unverified",
            preset = preset_id,
            antenna = antenna_port,
            "preset omits fastId on the watched antenna; relying on the reader default"
        ),
    }
    Ok(())
}

impl ImpinjClient {
    pub fn new(config: &Config) -> Result<Self> {
        let mut builder = Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .danger_accept_invalid_certs(!config.verify_tls);
        if let Some(path) = &config.ca_certificate {
            let pem = fs::read(path)
                .with_context(|| format!("failed to read CA certificate {}", path.display()))?;
            builder = builder.add_root_certificate(
                reqwest::Certificate::from_pem(&pem).context("invalid PEM CA certificate")?,
            );
        }
        Ok(Self {
            http: builder.build()?,
            base_url: format!("{}/api/v1", config.reader_base_url),
            username: config.reader_username.clone(),
            password: config.reader_password.clone(),
            health: ReaderHealth::default(),
        })
    }

    pub fn health(&self) -> ReaderHealth {
        self.health.clone()
    }

    /// Verifies that an externally managed inventory preset is already running
    /// and reports the fields discovery depends on. The service never installs,
    /// overwrites, starts, or stops reader presets.
    pub async fn require_inventory_preset(&self, config: &Config) -> Result<()> {
        let status: ReaderStatus = self
            .authorized(self.http.get(self.url("/status")).timeout(REQUEST_TIMEOUT))
            .send()
            .await
            .context("failed to query reader status")?
            .error_for_status()
            .context("reader status request failed")?
            .json()
            .await
            .context("invalid reader status response")?;
        let Some(preset_id) = active_inventory_preset(&status)? else {
            warn!(
                event = "reader_preset_unverified",
                "the active inventory preset is transient; cannot verify TID reporting"
            );
            return Ok(());
        };
        let preset: Value = self
            .authorized(
                self.http
                    .get(self.url(&format!("/profiles/inventory/presets/{preset_id}")))
                    .timeout(REQUEST_TIMEOUT),
            )
            .send()
            .await
            .context("failed to fetch the active preset")?
            .error_for_status()
            .context("active preset request failed")?
            .json()
            .await
            .context("invalid active preset response")?;
        verify_tid_reporting(&preset, &preset_id, config.antenna_port)?;
        info!(event = "reader_preset_reused", preset = %preset_id, "streaming the externally managed inventory preset");
        Ok(())
    }

    pub async fn stream_events(self, sender: mpsc::Sender<ReaderEvent>) {
        let mut backoff = Duration::from_secs(1);
        loop {
            match self.stream_once(&sender).await {
                Ok(()) => {
                    self.health.mark_disconnected();
                    return;
                }
                Err(error) => {
                    self.health.mark_disconnected();
                    warn!(event = "reader_stream_disconnected", %error, retry_seconds = backoff.as_secs(), "reader event stream disconnected");
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(30));
                }
            }
        }
    }

    async fn stream_once(&self, sender: &mpsc::Sender<ReaderEvent>) -> Result<()> {
        let response = self
            .authorized(self.http.get(self.url("/data/stream")))
            .send()
            .await
            .context("failed to connect to reader event stream")?
            .error_for_status()
            .context("reader event stream request failed")?;
        info!(
            event = "reader_stream_connected",
            "connected to reader event stream"
        );
        self.health.mark_connected();
        let mut bytes = response.bytes_stream();
        let mut buffer = Vec::with_capacity(8192);
        loop {
            let Some(chunk) = tokio::time::timeout(STREAM_STALL_TIMEOUT, bytes.next())
                .await
                .context("reader event stream stalled for 90 seconds")?
            else {
                bail!("reader closed event stream");
            };
            let chunk = chunk.context("reader event stream read failed")?;
            self.health.mark_activity();
            buffer.extend_from_slice(&chunk);
            if buffer.len() > MAX_STREAM_LINE_BYTES && !buffer.contains(&b'\n') {
                bail!("reader event stream exceeded maximum JSON line size");
            }
            while let Some(newline) = buffer.iter().position(|byte| *byte == b'\n') {
                let mut line: Vec<u8> = buffer.drain(..=newline).collect();
                while matches!(line.last(), Some(b'\n' | b'\r')) {
                    line.pop();
                }
                if line.is_empty() {
                    continue;
                }
                match serde_json::from_slice::<ReaderEvent>(&line) {
                    Ok(event) => {
                        if sender.send(event).await.is_err() {
                            return Ok(());
                        }
                    }
                    Err(error) => {
                        warn!(event = "reader_event_malformed", %error, "discarding malformed reader event")
                    }
                }
            }
        }
    }

    fn authorized(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        request.basic_auth(&self.username, Some(&self.password))
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }
}

fn system_now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| i64::try_from(duration.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reader_health_tracks_connection_and_recent_activity() {
        let health = ReaderHealth::default();
        assert_eq!(
            health.snapshot(),
            ReaderHealthSnapshot {
                connected: false,
                last_activity_ms: None,
            }
        );
        health.mark_connected();
        let connected = health.snapshot();
        assert!(connected.connected);
        assert!(connected.last_activity_ms.is_some());
        health.mark_disconnected();
        let reconnecting = health.snapshot();
        assert!(!reconnecting.connected);
        assert_eq!(reconnecting.last_activity_ms, connected.last_activity_ms);
    }

    fn status(state: Option<&str>, preset: Option<(&str, &str)>) -> ReaderStatus {
        ReaderStatus {
            interface: "IoT".into(),
            status: state.map(Into::into),
            active_preset: preset.map(|(id, profile)| ActivePreset {
                id: Some(id.into()),
                profile: profile.into(),
            }),
        }
    }

    #[test]
    fn running_inventory_preset_is_reused_whatever_its_name() {
        let preset =
            active_inventory_preset(&status(Some("running"), Some(("Preferred", "inventory"))))
                .unwrap();
        assert_eq!(preset.as_deref(), Some("Preferred"));
    }

    #[test]
    fn non_inventory_profile_is_refused() {
        let error = active_inventory_preset(&status(Some("running"), Some(("custom", "location"))))
            .unwrap_err();
        assert!(error.to_string().contains("only streams"));
    }

    #[test]
    fn idle_reader_is_refused_without_any_preset_write() {
        let error = active_inventory_preset(&status(Some("idle"), None)).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("start the externally managed inventory preset")
        );
    }

    fn preset(tid_hex: &str, antenna_port: u16, fast_id: &str) -> Value {
        serde_json::json!({
            "eventConfig": { "tagInventory": { "epcHex": "enabled", "tidHex": tid_hex } },
            "antennaConfigs": [{ "antennaPort": antenna_port, "fastId": fast_id }]
        })
    }

    #[test]
    fn preset_with_tid_reporting_on_the_watched_antenna_passes() {
        verify_tid_reporting(&preset("enabled", 1, "enabled"), "Preferred", 1).unwrap();
    }

    #[test]
    fn preset_relying_on_reader_defaults_warns_but_streams() {
        // Literal body of the live R700 `default` preset: the reader omits
        // defaulted keys (no eventConfig, no fastId), so absence must not bail.
        let default_preset = serde_json::json!({
            "antennaConfigs": [{
                "antennaPort": 1,
                "transmitPowerCdbm": 3300,
                "inventorySession": 2,
                "inventorySearchMode": "dual-target",
                "estimatedTagPopulation": 32,
                "rfMode": 1110
            }]
        });
        verify_tid_reporting(&default_preset, "default", 1).unwrap();
        verify_tid_reporting(&serde_json::json!({}), "bare", 1).unwrap();
    }

    #[test]
    fn explicitly_epc_only_preset_is_refused_before_streaming() {
        let error =
            verify_tid_reporting(&preset("disabled", 1, "enabled"), "Preferred", 1).unwrap_err();
        assert!(error.to_string().contains("tidHex"));
    }

    #[test]
    fn preset_without_fastid_or_watched_antenna_is_refused() {
        let error =
            verify_tid_reporting(&preset("enabled", 1, "disabled"), "Preferred", 1).unwrap_err();
        assert!(error.to_string().contains("fastId"));

        let error =
            verify_tid_reporting(&preset("enabled", 2, "enabled"), "Preferred", 1).unwrap_err();
        assert!(error.to_string().contains("no antennaConfig"));
    }
}

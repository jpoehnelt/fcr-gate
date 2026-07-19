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
use reqwest::{Client, Response, StatusCode};
use serde::Deserialize;
use serde_json::{Value, json};
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

    pub async fn ensure_profile(&self, config: &Config) -> Result<()> {
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
        if status.interface != "IoT" {
            bail!(
                "reader interface is {}; select the Impinj IoT Device Interface before running the encoder",
                status.interface
            );
        }
        if status.status.as_deref() == Some("no region") {
            bail!("reader has no regulatory region configured");
        }
        if config.writes_enabled {
            self.ensure_tag_access_supported().await?;
        }

        match status.status.as_deref() {
            Some("running" | "armed") => {
                let active = status
                    .active_preset
                    .context("reader is active but did not report an active preset")?;
                if active.profile == "inventory"
                    && active.id.as_deref() == Some(config.profile_id.as_str())
                {
                    info!(profile = %config.profile_id, "reusing active reader profile");
                    return Ok(());
                }
                bail!(
                    "reader is already running profile {} ({}) and will not be taken over",
                    active.profile,
                    active.id.as_deref().unwrap_or("transient")
                );
            }
            Some("idle") => {}
            Some(other) => bail!("reader is in unsupported state {other}"),
            None => bail!("reader did not report an IoT inventory state"),
        }

        let profile = build_inventory_request(config);
        let response = self
            .authorized(
                self.http
                    .put(self.url(&format!(
                        "/profiles/inventory/presets/{}",
                        config.profile_id
                    )))
                    .timeout(REQUEST_TIMEOUT)
                    .json(&profile),
            )
            .send()
            .await
            .context("failed to install reader profile")?;
        expect(
            response,
            &[StatusCode::CREATED, StatusCode::NO_CONTENT],
            "install profile",
        )
        .await?;

        let response = self
            .authorized(
                self.http
                    .post(self.url(&format!(
                        "/profiles/inventory/presets/{}/start",
                        config.profile_id
                    )))
                    .timeout(REQUEST_TIMEOUT),
            )
            .send()
            .await
            .context("failed to start reader profile")?;
        expect(response, &[StatusCode::NO_CONTENT], "start profile").await?;
        info!(profile = %config.profile_id, "reader inventory profile started");
        Ok(())
    }

    pub async fn stop_profile(&self, profile_id: &str) -> Result<()> {
        let response = self
            .authorized(
                self.http
                    .post(self.url(&format!("/profiles/inventory/presets/{profile_id}/stop")))
                    .timeout(REQUEST_TIMEOUT),
            )
            .send()
            .await
            .context("failed to stop reader profile")?;
        expect(response, &[StatusCode::NO_CONTENT], "stop profile").await?;
        info!(profile = profile_id, "reader inventory profile stopped");
        Ok(())
    }

    pub async fn queue_epc_write(
        &self,
        tid: &str,
        epc: &str,
        access_password: Option<&str>,
    ) -> Result<()> {
        let payload = build_access_request(tid, epc, access_password)?;
        let response = self
            .authorized(
                self.http
                    .post(self.url("/profiles/inventory/tag-access"))
                    .timeout(REQUEST_TIMEOUT)
                    .json(&payload),
            )
            .send()
            .await
            .context("failed to queue tag access request")?;
        expect(response, &[StatusCode::ACCEPTED], "queue tag access").await?;
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
                    warn!(%error, retry_seconds = backoff.as_secs(), "reader event stream disconnected");
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
        info!("connected to reader event stream");
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
                    Err(error) => warn!(%error, "discarding malformed reader event"),
                }
            }
        }
    }

    async fn ensure_tag_access_supported(&self) -> Result<()> {
        let document: Value = self
            .authorized(
                self.http
                    .get(self.url("/openapi.json"))
                    .timeout(REQUEST_TIMEOUT),
            )
            .send()
            .await
            .context("failed to retrieve reader OpenAPI document")?
            .error_for_status()
            .context("reader OpenAPI request failed")?
            .json()
            .await
            .context("invalid reader OpenAPI response")?;
        if document
            .pointer("/paths/~1profiles~1inventory~1tag-access/post")
            .is_none()
        {
            bail!(
                "reader firmware does not expose /profiles/inventory/tag-access; update to a firmware/API version that supports tag-memory encoding"
            );
        }
        Ok(())
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

pub fn build_inventory_request(config: &Config) -> Value {
    json!({
        "eventConfig": {
            "common": { "hostname": "enabled" },
            "tagInventory": {
                "tagReporting": {
                    "reportingIntervalSeconds": 0,
                    "tagIdentifier": "tid",
                    "antennaIdentifier": "antennaPort"
                },
                "epc": "disabled",
                "epcHex": "enabled",
                "tid": "disabled",
                "tidHex": "enabled",
                "antennaPort": "enabled",
                "transmitPowerCdbm": "enabled",
                "peakRssiCdbm": "enabled",
                "frequency": "disabled",
                "pc": "disabled"
            }
        },
        "antennaConfigs": [{
            "antennaName": "fcr-gate-encoder",
            "antennaPort": config.antenna_port,
            "transmitPowerCdbm": config.transmit_power_cdbm,
            "rfMode": config.rf_mode,
            "inventorySession": 1,
            "inventorySearchMode": "dual-target",
            "estimatedTagPopulation": 16,
            "fastId": "enabled"
        }]
    })
}

pub fn build_access_request(tid: &str, epc: &str, access_password: Option<&str>) -> Result<Value> {
    if tid.is_empty()
        || tid.len() % 2 != 0
        || tid.len() * 4 > 255
        || !tid.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        bail!("TID must be complete hexadecimal bytes no longer than 255 bits");
    }
    if epc.len() != 24 || !epc.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("assigned EPC must be exactly 96 bits (24 hexadecimal characters)");
    }

    let mut access_commands = Vec::with_capacity(7);
    for (index, word) in epc.as_bytes().chunks_exact(4).enumerate() {
        let word = std::str::from_utf8(word).expect("validated hexadecimal is UTF-8");
        access_commands.push(json!({
            "identifier": format!("write-epc-{index}"),
            "write": {
                "memoryBank": "epc",
                "wordOffset": 2 + index,
                "dataHex": word.to_ascii_uppercase()
            }
        }));
    }
    access_commands.push(json!({
        "identifier": "verify-epc",
        "read": {
            "memoryBank": "epc",
            "wordOffset": 2,
            "wordCount": 6
        }
    }));

    let mut configuration = json!({
        "tagSelectors": [{
            "action": "include",
            "tagMemoryBank": "tid",
            "bitOffset": 0,
            "mask": tid.to_ascii_uppercase(),
            "maskLength": tid.len() * 4
        }],
        "accessCommands": access_commands
    });
    if let Some(password) = access_password {
        if password.len() != 8 || !password.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            bail!("tag access password must be exactly 32 bits (8 hexadecimal characters)");
        }
        configuration["tagAccessPasswordHex"] = json!(password.to_ascii_uppercase());
    }
    Ok(json!({ "accessConfigurations": [configuration] }))
}

async fn expect(response: Response, allowed: &[StatusCode], operation: &str) -> Result<Response> {
    if allowed.contains(&response.status()) {
        return Ok(response);
    }
    let status = response.status();
    let mut detail = response.text().await.unwrap_or_default();
    detail.truncate(1000);
    bail!("reader failed to {operation}: HTTP {status}: {detail}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_request_targets_tid_and_writes_six_words() {
        let payload =
            build_access_request("E28011606000020497CB0065", "FCA700010000000000000001", None)
                .unwrap();
        let configuration = &payload["accessConfigurations"][0];
        assert_eq!(configuration["tagSelectors"][0]["tagMemoryBank"], "tid");
        assert_eq!(configuration["tagSelectors"][0]["bitOffset"], 0);
        assert_eq!(configuration["tagSelectors"][0]["maskLength"], 96);
        let commands = configuration["accessCommands"].as_array().unwrap();
        assert_eq!(commands.len(), 7);
        assert_eq!(commands[0]["write"]["wordOffset"], 2);
        assert_eq!(commands[5]["write"]["wordOffset"], 7);
        assert_eq!(commands[6]["read"]["wordCount"], 6);
    }

    #[test]
    fn access_request_rejects_an_invalid_password() {
        assert!(
            build_access_request(
                "E28011606000020497CB0065",
                "FCA700010000000000000001",
                Some("not-hex")
            )
            .is_err()
        );
    }

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
}

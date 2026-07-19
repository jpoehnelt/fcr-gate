use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    env, fs,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, bail};
use reqwest::{Client, Method, RequestBuilder, Response};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const DEFAULT_UNIFI_ACCESS_HOST: &str = "https://100.89.168.42:12445";
const DEFAULT_ENTRY_GATE_DOOR_ID: &str = "1b620b81-f457-45f7-9fd2-27de1d8c4fdc";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
const VISITORS_PER_PAGE: usize = 100;
const MAX_VISITOR_PAGES: usize = 1000;
const LPR_REMARK: &str = "LPR_BULK";
const CANCELLED_STATUS: i64 = 4;

#[derive(Clone, Debug)]
pub struct AdminConfig {
    base_url: String,
    api_key: String,
    verify_tls: bool,
    ca_certificate: Option<PathBuf>,
    entry_gate_door_id: Option<String>,
}

impl AdminConfig {
    pub fn from_env(needs_entry_gate: bool) -> Result<Self> {
        let _ = dotenvy::dotenv();
        let base_url = normalize_base_url(
            &env::var("UNIFI_ACCESS_HOST").unwrap_or_else(|_| DEFAULT_UNIFI_ACCESS_HOST.to_owned()),
        )?;
        let api_key = read_secret("UNIFI_API_KEY_FILE", "UNIFI_API_KEY")?
            .context("UNIFI_API_KEY_FILE or UNIFI_API_KEY is required")?;
        let verify_tls = boolean("UNIFI_TLS_VERIFY", false)?;
        let ca_certificate = env::var_os("UNIFI_CA_CERTIFICATE").map(PathBuf::from);
        if ca_certificate.is_some() && !verify_tls {
            bail!("UNIFI_CA_CERTIFICATE requires UNIFI_TLS_VERIFY=true");
        }
        let entry_gate_door_id = env::var("UNIFI_ENTRY_GATE_DOOR_ID")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .map(|value| validate_uuid(&value, "UNIFI_ENTRY_GATE_DOOR_ID"))
            .transpose()?;
        let entry_gate_door_id = entry_gate_door_id
            .or_else(|| needs_entry_gate.then(|| DEFAULT_ENTRY_GATE_DOOR_ID.to_owned()));

        Ok(Self {
            base_url,
            api_key,
            verify_tls,
            ca_certificate,
            entry_gate_door_id,
        })
    }

    pub fn entry_gate_door_id(&self) -> Result<&str> {
        self.entry_gate_door_id
            .as_deref()
            .context("UNIFI_ENTRY_GATE_DOOR_ID is not configured")
    }
}

#[derive(Clone)]
pub struct AdminClient {
    http: Client,
    base_url: String,
    api_key: String,
}

impl AdminClient {
    pub fn new(config: &AdminConfig) -> Result<Self> {
        let mut builder = Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(REQUEST_TIMEOUT)
            .danger_accept_invalid_certs(!config.verify_tls);
        if let Some(path) = &config.ca_certificate {
            let pem = fs::read(path).with_context(|| {
                format!("failed to read UniFi CA certificate {}", path.display())
            })?;
            builder = builder.add_root_certificate(
                reqwest::Certificate::from_pem(&pem).context("invalid UniFi PEM CA certificate")?,
            );
        }
        Ok(Self {
            http: builder.build()?,
            base_url: format!("{}/api/v1/developer", config.base_url),
            api_key: config.api_key.clone(),
        })
    }

    pub async fn fetch_system_logs(&self, since: i64, until: i64) -> Result<Value> {
        self.send_json(
            self.request(Method::POST, "/system/logs")
                .query(&[("page_size", 10_000), ("page_num", 1)])
                .json(&json!({
                    "topic": "door_openings",
                    "since": since,
                    "until": until,
                })),
            "fetch UniFi system logs",
        )
        .await
    }

    pub async fn create_visitor(&self, payload: &Value) -> Result<String> {
        let response = self
            .send_json(
                self.request(Method::POST, "/visitors").json(payload),
                "create UniFi visitor",
            )
            .await?;
        response
            .pointer("/data/id")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .context("create visitor response omitted data.id")
    }

    pub async fn assign_license_plates(&self, visitor_id: &str, plates: &[String]) -> Result<()> {
        validate_path_id(visitor_id, "visitor ID")?;
        self.send_success(
            self.request(
                Method::PUT,
                &format!("/visitors/{visitor_id}/license_plates"),
            )
            .json(plates),
            "assign visitor license plates",
        )
        .await
    }

    pub async fn list_visitors(&self) -> Result<Vec<Visitor>> {
        let mut visitors = Vec::new();
        for page in 1..=MAX_VISITOR_PAGES {
            let response = self
                .send_json(
                    self.request(Method::GET, "/visitors")
                        .query(&[("page_num", page), ("page_size", VISITORS_PER_PAGE)]),
                    "list UniFi visitors",
                )
                .await?;
            let hits = visitor_values(&response)?;
            let page_len = hits.len();
            for hit in hits {
                visitors
                    .push(serde_json::from_value(hit).context("invalid visitor in list response")?);
            }
            let total = response
                .pointer("/pagination/total")
                .and_then(Value::as_u64)
                .map(|value| value as usize);
            if page_len < VISITORS_PER_PAGE
                || total.is_some_and(|reported| visitors.len() >= reported)
            {
                return Ok(visitors);
            }
        }
        bail!("visitor listing exceeded {MAX_VISITOR_PAGES} pages")
    }

    pub async fn visitor(&self, visitor_id: &str) -> Result<Visitor> {
        validate_path_id(visitor_id, "visitor ID")?;
        let response = self
            .send_json(
                self.request(Method::GET, &format!("/visitors/{visitor_id}")),
                "fetch UniFi visitor",
            )
            .await?;
        serde_json::from_value(
            response
                .get("data")
                .cloned()
                .context("visitor response omitted data")?,
        )
        .context("invalid visitor detail response")
    }

    pub async fn cancel_visitor(&self, visitor_id: &str) -> Result<()> {
        validate_path_id(visitor_id, "visitor ID")?;
        self.send_success(
            self.request(Method::DELETE, &format!("/visitors/{visitor_id}")),
            "cancel UniFi visitor",
        )
        .await
    }

    pub async fn unassign_license_plate(&self, visitor_id: &str, plate_id: &str) -> Result<()> {
        validate_path_id(visitor_id, "visitor ID")?;
        validate_path_id(plate_id, "license plate ID")?;
        self.send_success(
            self.request(
                Method::DELETE,
                &format!("/visitors/{visitor_id}/license_plates/{plate_id}"),
            ),
            "unassign visitor license plate",
        )
        .await
    }

    fn request(&self, method: Method, path: &str) -> RequestBuilder {
        self.http
            .request(method, format!("{}{}", self.base_url, path))
            .bearer_auth(&self.api_key)
            .header("accept", "application/json")
            .header("content-type", "application/json")
    }

    async fn send_json(&self, request: RequestBuilder, operation: &str) -> Result<Value> {
        let response = request
            .send()
            .await
            .with_context(|| format!("failed to {operation}"))?;
        let body = success_body(response, operation).await?;
        let value: Value = serde_json::from_slice(&body)
            .with_context(|| format!("invalid {operation} response"))?;
        validate_api_code(&value, operation)?;
        Ok(value)
    }

    async fn send_success(&self, request: RequestBuilder, operation: &str) -> Result<()> {
        let response = request
            .send()
            .await
            .with_context(|| format!("failed to {operation}"))?;
        let body = success_body(response, operation).await?;
        if !body.is_empty() {
            if let Ok(value) = serde_json::from_slice::<Value>(&body) {
                validate_api_code(&value, operation)?;
            }
        }
        Ok(())
    }
}

fn validate_api_code(value: &Value, operation: &str) -> Result<()> {
    if let Some(code) = value.get("code").and_then(Value::as_str) {
        if code != "SUCCESS" {
            let message = value.get("msg").and_then(Value::as_str).unwrap_or_default();
            bail!("failed to {operation}: {code}: {message}");
        }
    }
    Ok(())
}

async fn success_body(response: Response, operation: &str) -> Result<Vec<u8>> {
    let status = response.status();
    let body = response
        .bytes()
        .await
        .with_context(|| format!("failed to read response while trying to {operation}"))?;
    if !status.is_success() {
        let mut detail = String::from_utf8_lossy(&body).into_owned();
        detail.truncate(1000);
        bail!("failed to {operation}: HTTP {status}: {detail}");
    }
    Ok(body.to_vec())
}

fn visitor_values(response: &Value) -> Result<Vec<Value>> {
    let data = response
        .get("data")
        .context("visitor list response omitted data")?;
    if let Some(values) = data.as_array() {
        return Ok(values.clone());
    }
    data.get("hits")
        .and_then(Value::as_array)
        .cloned()
        .context("visitor list data was neither an array nor an object containing hits")
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct Visitor {
    pub id: String,
    #[serde(default)]
    pub status: Value,
    #[serde(default)]
    pub remarks: String,
    #[serde(default)]
    pub first_name: String,
    #[serde(default)]
    pub license_plates: Vec<LicensePlate>,
}

impl Visitor {
    pub fn is_lpr(&self) -> bool {
        self.remarks == LPR_REMARK || self.first_name == "LPR"
    }

    pub fn is_cancelled(&self) -> bool {
        self.status.as_i64() == Some(CANCELLED_STATUS) || self.status.as_str() == Some("CANCELLED")
    }

    pub fn status_name(&self) -> String {
        match self.status.as_i64() {
            Some(1) => "UPCOMING".into(),
            Some(2) => "VISITED".into(),
            Some(3) => "VISITING".into(),
            Some(4) => "CANCELLED".into(),
            Some(5) => "NO_VISIT".into(),
            Some(6) => "ACTIVE".into(),
            _ => self.status.as_str().unwrap_or("UNKNOWN").to_owned(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct LicensePlate {
    pub id: String,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct PlateRow {
    pub timestamp: String,
    pub plate: String,
    pub result: String,
    pub gate: String,
    pub door_id: String,
}

pub fn extract_plate_rows(response: &Value) -> Result<Vec<PlateRow>> {
    let hits = response
        .pointer("/data/hits")
        .and_then(Value::as_array)
        .context("system log response omitted data.hits")?;
    let mut rows = Vec::new();
    for hit in hits {
        let source = hit.get("_source").unwrap_or(&Value::Null);
        let authentication = source.get("authentication").unwrap_or(&Value::Null);
        if authentication
            .get("credential_provider")
            .and_then(Value::as_str)
            != Some("LICENSEPLATE")
        {
            continue;
        }
        let Some(plate) = authentication.get("issuer").and_then(Value::as_str) else {
            continue;
        };
        let plate = plate.trim();
        if plate.is_empty() {
            continue;
        }
        let door = source
            .get("target")
            .and_then(Value::as_array)
            .and_then(|targets| {
                targets
                    .iter()
                    .find(|target| target.get("type").and_then(Value::as_str) == Some("door"))
            });
        rows.push(PlateRow {
            timestamp: string_field(hit, "@timestamp"),
            plate: plate.to_owned(),
            result: source
                .get("event")
                .map(|event| string_field(event, "result"))
                .unwrap_or_default(),
            gate: door
                .map(|value| string_field(value, "display_name"))
                .unwrap_or_default(),
            door_id: door
                .map(|value| string_field(value, "id"))
                .unwrap_or_default(),
        });
    }
    rows.sort();
    Ok(rows)
}

pub fn write_plate_csv(path: &Path, rows: &[PlateRow]) -> Result<()> {
    let mut writer = csv::Writer::from_path(path)
        .with_context(|| format!("failed to create CSV {}", path.display()))?;
    writer.write_record(["timestamp", "plate", "result", "gate", "door_id"])?;
    for row in rows {
        writer.write_record([
            &row.timestamp,
            &row.plate,
            &row.result,
            &row.gate,
            &row.door_id,
        ])?;
    }
    writer.flush()?;
    Ok(())
}

fn string_field(value: &Value, name: &str) -> String {
    value
        .get(name)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

pub fn load_plate_issuers(path: &Path) -> Result<Vec<String>> {
    let file = fs::File::open(path)
        .with_context(|| format!("failed to open system-log JSON {}", path.display()))?;
    let response: Value = serde_json::from_reader(file)
        .with_context(|| format!("invalid system-log JSON {}", path.display()))?;
    Ok(extract_plate_rows(&response)?
        .into_iter()
        .map(|row| row.plate)
        .collect())
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct PlateGroup {
    pub canonical: String,
    pub variants: Vec<String>,
    pub reads: usize,
}

pub fn build_plate_groups(plates: &[String]) -> Vec<PlateGroup> {
    let mut counts = HashMap::<String, usize>::new();
    for plate in plates {
        *counts.entry(plate.clone()).or_default() += 1;
    }
    let mut groups = HashMap::<String, BTreeSet<String>>::new();
    for plate in counts.keys() {
        groups
            .entry(canonical_plate(plate))
            .or_default()
            .insert(plate.clone());
    }
    let mut plan = groups
        .into_values()
        .map(|variants| {
            let canonical = variants
                .iter()
                .max_by_key(|variant| (counts.get(*variant).copied().unwrap_or_default(), *variant))
                .cloned()
                .unwrap_or_default();
            let reads = variants
                .iter()
                .map(|variant| counts.get(variant).copied().unwrap_or_default())
                .sum();
            PlateGroup {
                canonical,
                variants: variants.into_iter().collect(),
                reads,
            }
        })
        .collect::<Vec<_>>();
    plan.sort_by(|left, right| {
        right
            .reads
            .cmp(&left.reads)
            .then_with(|| left.canonical.cmp(&right.canonical))
    });
    plan
}

fn canonical_plate(plate: &str) -> String {
    plate
        .to_ascii_uppercase()
        .replace('O', "0")
        .replace('I', "1")
}

pub fn visitor_payload(group: &PlateGroup, door_id: &str, start: i64, end: i64) -> Value {
    let full_day = json!([{"start_time": "00:00:00", "end_time": "23:59:59"}]);
    json!({
        "first_name": "LPR",
        "last_name": group.canonical,
        "start_time": start,
        "end_time": end,
        "visit_reason": "Others",
        "remarks": LPR_REMARK,
        "resources": [{"type": "door", "id": door_id}],
        "week_schedule": {
            "sunday": full_day,
            "monday": full_day,
            "tuesday": full_day,
            "wednesday": full_day,
            "thursday": full_day,
            "friday": full_day,
            "saturday": full_day,
        }
    })
}

#[derive(Clone, Debug, Serialize)]
pub struct EnrollmentResult {
    pub canonical: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub visitor_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plates: Option<Vec<String>>,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct EnrollmentLog {
    pub start_time: i64,
    pub end_time: i64,
    pub results: Vec<EnrollmentResult>,
}

pub fn write_json<T: Serialize>(path: &Path, value: &T, pretty: bool) -> Result<()> {
    let file = fs::File::create(path)
        .with_context(|| format!("failed to create JSON output {}", path.display()))?;
    if pretty {
        serde_json::to_writer_pretty(file, value)?;
    } else {
        serde_json::to_writer(file, value)?;
    }
    Ok(())
}

pub fn normalize_epc(value: &str) -> Result<String> {
    let trimmed = value.trim();
    let without_prefix = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    let epc = without_prefix.to_ascii_uppercase();
    if epc.is_empty() {
        bail!("EPC is empty");
    }
    if epc.len() % 2 != 0 {
        bail!("EPC must contain complete bytes: {value:?}");
    }
    if !epc.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("EPC is not hexadecimal: {value:?}");
    }
    Ok(epc)
}

pub fn read_epcs(path: &Path) -> Result<Vec<String>> {
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .from_path(path)
        .with_context(|| format!("failed to open EPC report {}", path.display()))?;
    let headers = reader.headers()?.clone();
    let epc_index = headers
        .iter()
        .position(|header| {
            header
                .trim_start_matches('\u{feff}')
                .trim()
                .eq_ignore_ascii_case("epc")
        })
        .context("CSV does not contain an EPC column")?;
    let mut epcs = Vec::new();
    for (index, record) in reader.records().enumerate() {
        let record = record.with_context(|| format!("invalid CSV record on line {}", index + 2))?;
        let raw = record.get(epc_index).unwrap_or_default();
        if raw.trim().is_empty() {
            continue;
        }
        epcs.push(normalize_epc(raw).with_context(|| format!("line {}", index + 2))?);
    }
    Ok(epcs)
}

pub fn summarize_statuses(visitors: &[Visitor]) -> BTreeMap<String, usize> {
    let mut statuses = BTreeMap::new();
    for visitor in visitors {
        *statuses.entry(visitor.status_name()).or_default() += 1;
    }
    statuses
}

fn normalize_base_url(value: &str) -> Result<String> {
    let value = value.trim().trim_end_matches('/');
    let parsed = reqwest::Url::parse(value).context("UNIFI_ACCESS_HOST is not a valid URL")?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        bail!("UNIFI_ACCESS_HOST must contain only an HTTP(S) scheme and host");
    }
    Ok(value.to_owned())
}

fn read_secret(file_name: &str, value_name: &str) -> Result<Option<String>> {
    if let Some(path) = env::var_os(file_name) {
        let path = PathBuf::from(path);
        let value = fs::read_to_string(&path)
            .with_context(|| format!("failed to read {file_name} {}", path.display()))?;
        let value = value.trim_end_matches(['\r', '\n']).to_owned();
        if value.is_empty() {
            bail!("{file_name} is empty");
        }
        return Ok(Some(value));
    }
    Ok(env::var(value_name)
        .ok()
        .filter(|value| !value.trim().is_empty()))
}

fn boolean(name: &str, default: bool) -> Result<bool> {
    let Ok(value) = env::var(name) else {
        return Ok(default);
    };
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => bail!("{name} must be true or false"),
    }
}

fn validate_uuid(value: &str, name: &str) -> Result<String> {
    let value = value.trim().to_ascii_lowercase();
    let valid = value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        });
    if !valid {
        bail!("{name} must be a UUID");
    }
    Ok(value)
}

fn validate_path_id(value: &str, name: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        bail!("{name} is not safe for a URL path");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use tempfile::NamedTempFile;

    use super::*;

    #[test]
    fn extract_keeps_only_license_plate_events() {
        let response = json!({
            "data": {"hits": [
                {
                    "@timestamp": "2026-07-16T12:00:00Z",
                    "_source": {
                        "authentication": {
                            "credential_provider": "LICENSEPLATE",
                            "issuer": " ABC123 "
                        },
                        "event": {"result": "BLOCKED"},
                        "target": [{"type": "door", "display_name": "Entry", "id": "door-1"}]
                    }
                },
                {"_source": {"authentication": {"credential_provider": "NFC", "issuer": "ignored"}}}
            ]}
        });
        assert_eq!(
            extract_plate_rows(&response).unwrap(),
            vec![PlateRow {
                timestamp: "2026-07-16T12:00:00Z".into(),
                plate: "ABC123".into(),
                result: "BLOCKED".into(),
                gate: "Entry".into(),
                door_id: "door-1".into(),
            }]
        );
    }

    #[test]
    fn groups_collapse_common_ocr_variants() {
        let groups = build_plate_groups(&["ABOI".into(), "AB01".into(), "ABOI".into()]);
        assert_eq!(
            groups,
            vec![PlateGroup {
                canonical: "ABOI".into(),
                variants: vec!["AB01".into(), "ABOI".into()],
                reads: 3,
            }]
        );
    }

    #[test]
    fn lpr_visitors_match_remark_or_generated_name() {
        let visitor = |remarks: &str, first_name: &str| Visitor {
            id: "visitor-1".into(),
            status: json!(6),
            remarks: remarks.into(),
            first_name: first_name.into(),
            license_plates: Vec::new(),
        };
        assert!(visitor("LPR_BULK", "Someone").is_lpr());
        assert!(visitor("", "LPR").is_lpr());
        assert!(!visitor("", "Someone").is_lpr());
    }

    #[test]
    fn epc_normalization_is_strict() {
        assert_eq!(normalize_epc("0x30f269fb").unwrap(), "30F269FB");
        assert!(normalize_epc("not-an-epc").is_err());
        assert!(normalize_epc("ABC").is_err());
    }

    #[test]
    fn epc_report_handles_bom_and_case_insensitive_header() {
        let mut file = NamedTempFile::new().unwrap();
        write!(
            file,
            "\u{feff}Epc,Reads,Last RSSI\n30f269fb,5,-78.50\n30F269FB,2,-70.00\n"
        )
        .unwrap();
        assert_eq!(
            read_epcs(file.path()).unwrap(),
            vec!["30F269FB", "30F269FB"]
        );
    }

    #[test]
    fn recurring_visitor_payload_contains_every_day_and_the_gate() {
        let group = PlateGroup {
            canonical: "ABC123".into(),
            variants: vec!["ABC123".into()],
            reads: 1,
        };
        let payload = visitor_payload(&group, "1b620b81-f457-45f7-9fd2-27de1d8c4fdc", 10, 20);
        assert_eq!(payload["resources"][0]["type"], "door");
        assert_eq!(payload["week_schedule"].as_object().unwrap().len(), 7);
        assert_eq!(payload["start_time"], 10);
        assert_eq!(payload["end_time"], 20);
    }

    #[test]
    fn successful_http_with_an_api_error_code_still_fails() {
        assert!(validate_api_code(&json!({"code": "SUCCESS"}), "test").is_ok());
        assert!(validate_api_code(&json!({"code": "FAILED", "msg": "denied"}), "test").is_err());
    }

    #[test]
    fn visitor_lists_accept_both_documented_response_shapes() {
        assert_eq!(
            visitor_values(&json!({"data": [{"id": "one"}]})).unwrap(),
            vec![json!({"id": "one"})]
        );
        assert_eq!(
            visitor_values(&json!({"data": {"hits": [{"id": "two"}]}})).unwrap(),
            vec![json!({"id": "two"})]
        );
    }
}

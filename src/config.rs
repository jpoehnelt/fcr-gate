use std::{
    env, fs,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    time::Duration,
};

use anyhow::{Context, Result, bail};

pub const DEFAULT_UNENCODED_EPC: &str = "300833B2DDD9014000000000";
pub const DEFAULT_UNIFI_ACCESS_HOST: &str = "https://100.89.168.42:12445";
pub const DEFAULT_ENTRY_GATE_DOOR_ID: &str = "1b620b81-f457-45f7-9fd2-27de1d8c4fdc";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GateMode {
    Disabled,
    DryRun,
    Live,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LprCorrelationMode {
    Disabled,
    DryRun,
    Live,
}

impl LprCorrelationMode {
    pub fn enabled(self) -> bool {
        self != Self::Disabled
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::DryRun => "dry-run",
            Self::Live => "live",
        }
    }
}

impl GateMode {
    pub fn enabled(self) -> bool {
        self != Self::Disabled
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::DryRun => "dry-run",
            Self::Live => "live",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Config {
    pub reader_base_url: String,
    pub reader_username: String,
    pub reader_password: String,
    pub verify_tls: bool,
    pub ca_certificate: Option<PathBuf>,
    pub profile_id: String,
    pub antenna_port: u16,
    pub transmit_power_cdbm: i32,
    pub rf_mode: u16,
    pub writes_enabled: bool,
    pub default_epc: String,
    pub epc_prefix: Option<String>,
    pub min_rssi_cdbm: i32,
    pub confirm_reads: u32,
    pub confirm_window: Duration,
    pub access_timeout: Duration,
    pub retry_cooldown: Duration,
    pub max_attempts: u32,
    pub state_db: PathBuf,
    pub tag_access_password: Option<String>,
    pub actor: String,
    pub web_enabled: bool,
    pub health_enabled: bool,
    pub health_stale_after: Duration,
    pub web_bind: SocketAddr,
    pub metrics_enabled: bool,
    pub metrics_bind: SocketAddr,
    pub claim_window: Duration,
    pub lpr_correlation_mode: LprCorrelationMode,
    pub lpr_correlation_window: Duration,
    pub lpr_correlation_poll: Duration,
    pub discovery_mode: LprCorrelationMode,
    pub discovery_match_window: Duration,
    pub discovery_poll: Duration,
    pub discovery_passage_gap: Duration,
    pub discovery_max_dwell: Duration,
    pub discovery_min_rssi_cdbm: i32,
    pub discovery_min_occurrences: u32,
    pub discovery_min_days: u32,
    pub discovery_min_confidence_percent: u8,
    pub discovery_conflict_occurrences: u32,
    pub discovery_evidence_retention: Duration,
    pub discovery_lease: Duration,
    pub gate_mode: GateMode,
    pub gate_unlock_cooldown: Duration,
    pub unifi_base_url: Option<String>,
    pub unifi_api_key: Option<String>,
    pub unifi_verify_tls: bool,
    pub unifi_ca_certificate: Option<PathBuf>,
    pub entry_gate_door_id: String,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let host = required("IMPINJ_HOST")?;
        let reader_base_url = normalize_base_url(&host)?;
        let reader_username = env::var("IMPINJ_USERNAME").unwrap_or_else(|_| "root".into());
        let reader_password = read_password()?;
        let verify_tls = boolean("IMPINJ_TLS_VERIFY", false)?;
        let ca_certificate = env::var_os("IMPINJ_CA_CERTIFICATE").map(PathBuf::from);
        if ca_certificate.is_some() && !verify_tls {
            bail!("IMPINJ_CA_CERTIFICATE requires IMPINJ_TLS_VERIFY=true");
        }

        let writes_enabled = boolean("RFID_WRITES_ENABLED", false)?;
        let default_epc = normalize_hex(
            &env::var("RFID_DEFAULT_EPC").unwrap_or_else(|_| DEFAULT_UNENCODED_EPC.into()),
            Some(24),
            "RFID_DEFAULT_EPC",
        )?;
        let epc_prefix = env::var("RFID_EPC_PREFIX")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .map(|value| normalize_hex(&value, Some(16), "RFID_EPC_PREFIX"))
            .transpose()?;
        if writes_enabled && epc_prefix.is_none() {
            bail!("RFID_EPC_PREFIX is required when RFID_WRITES_ENABLED=true");
        }

        let tag_access_password = env::var("IMPINJ_TAG_ACCESS_PASSWORD")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .map(|value| normalize_hex(&value, Some(8), "IMPINJ_TAG_ACCESS_PASSWORD"))
            .transpose()?;
        let profile_id = validate_profile_id(
            &env::var("IMPINJ_PROFILE_ID").unwrap_or_else(|_| "fcr-gate-encoder".into()),
        )?;
        let web_enabled = boolean("FCR_GATE_WEB_ENABLED", false)?;
        let health_enabled = boolean("FCR_GATE_HEALTH_ENABLED", true)?;
        let metrics_enabled = boolean("FCR_GATE_METRICS_ENABLED", false)?;
        let gate_mode =
            parse_gate_mode(&env::var("RFID_GATE_MODE").unwrap_or_else(|_| "disabled".into()))?;
        let lpr_correlation_mode = parse_lpr_correlation_mode(
            &env::var("RFID_LPR_CORRELATION_MODE").unwrap_or_else(|_| "disabled".into()),
        )?;
        let lpr_correlation_window =
            Duration::from_millis(positive_number("RFID_LPR_CORRELATION_WINDOW_MS", 10_000)?);
        let lpr_correlation_poll =
            Duration::from_millis(positive_number("RFID_LPR_CORRELATION_POLL_MS", 2_000)?);
        if lpr_correlation_poll > lpr_correlation_window {
            bail!("RFID_LPR_CORRELATION_POLL_MS must not exceed RFID_LPR_CORRELATION_WINDOW_MS");
        }
        let discovery_mode = parse_discovery_mode(
            &env::var("RFID_DISCOVERY_MODE").unwrap_or_else(|_| "disabled".into()),
        )?;
        let discovery_match_window =
            Duration::from_millis(positive_number("RFID_DISCOVERY_MATCH_WINDOW_MS", 10_000)?);
        let discovery_poll =
            Duration::from_millis(positive_number("RFID_DISCOVERY_POLL_MS", 2_000)?);
        if discovery_poll > discovery_match_window {
            bail!("RFID_DISCOVERY_POLL_MS must not exceed RFID_DISCOVERY_MATCH_WINDOW_MS");
        }
        let discovery_passage_gap =
            Duration::from_millis(positive_number("RFID_DISCOVERY_PASSAGE_GAP_MS", 30_000)?);
        let discovery_max_dwell =
            Duration::from_millis(positive_number("RFID_DISCOVERY_MAX_DWELL_MS", 120_000)?);
        if discovery_max_dwell <= discovery_passage_gap {
            bail!("RFID_DISCOVERY_MAX_DWELL_MS must exceed RFID_DISCOVERY_PASSAGE_GAP_MS");
        }
        let discovery_min_confidence_percent =
            positive_number("RFID_DISCOVERY_MIN_CONFIDENCE_PERCENT", 80_u8)?;
        if discovery_min_confidence_percent > 100 {
            bail!("RFID_DISCOVERY_MIN_CONFIDENCE_PERCENT must not exceed 100");
        }
        let web_bind = web_bind()?;
        let metrics_bind = metrics_bind()?;
        let unifi_needed = web_enabled
            || gate_mode.enabled()
            || lpr_correlation_mode.enabled()
            || discovery_mode.enabled();
        let unifi_base_url = unifi_needed
            .then(|| {
                normalize_url(
                    &env::var("UNIFI_ACCESS_HOST")
                        .unwrap_or_else(|_| DEFAULT_UNIFI_ACCESS_HOST.into()),
                    "UNIFI_ACCESS_HOST",
                )
            })
            .transpose()?;
        let unifi_api_key = if unifi_needed {
            read_optional_secret("UNIFI_API_KEY_FILE", "UNIFI_API_KEY")?
        } else {
            None
        };
        if unifi_needed && unifi_api_key.is_none() {
            bail!(
                "UNIFI_API_KEY_FILE or UNIFI_API_KEY is required for the operator UI, LPR correlation, RFID discovery, or gate unlock"
            );
        }
        let unifi_verify_tls = boolean("UNIFI_TLS_VERIFY", false)?;
        let unifi_ca_certificate = env::var_os("UNIFI_CA_CERTIFICATE").map(PathBuf::from);
        if unifi_ca_certificate.is_some() && !unifi_verify_tls {
            bail!("UNIFI_CA_CERTIFICATE requires UNIFI_TLS_VERIFY=true");
        }
        let entry_gate_door_id = validate_uuid(
            &env::var("UNIFI_ENTRY_GATE_DOOR_ID")
                .unwrap_or_else(|_| DEFAULT_ENTRY_GATE_DOOR_ID.into()),
            "UNIFI_ENTRY_GATE_DOOR_ID",
        )?;

        Ok(Self {
            reader_base_url,
            reader_username,
            reader_password,
            verify_tls,
            ca_certificate,
            profile_id,
            antenna_port: number("IMPINJ_ANTENNA_PORT", 1)?,
            transmit_power_cdbm: number("IMPINJ_TX_POWER_CDBM", 3000)?,
            rf_mode: number("IMPINJ_RF_MODE", 4)?,
            writes_enabled,
            default_epc,
            epc_prefix,
            min_rssi_cdbm: number("RFID_MIN_RSSI_CDBM", -5000)?,
            confirm_reads: positive_number("RFID_CONFIRM_READS", 5)?,
            confirm_window: Duration::from_millis(positive_number("RFID_CONFIRM_WINDOW_MS", 1500)?),
            access_timeout: Duration::from_millis(positive_number(
                "RFID_ACCESS_TIMEOUT_MS",
                15_000,
            )?),
            retry_cooldown: Duration::from_millis(positive_number("RFID_RETRY_COOLDOWN_MS", 3000)?),
            max_attempts: positive_number("RFID_MAX_ATTEMPTS", 3)?,
            state_db: state_db_path(),
            tag_access_password,
            actor: env::var("RFID_ENCODER_ACTOR").unwrap_or_else(|_| "gate-auto".into()),
            web_enabled,
            health_enabled,
            health_stale_after: Duration::from_millis(positive_number(
                "FCR_GATE_HEALTH_STALE_MS",
                120_000,
            )?),
            web_bind,
            metrics_enabled,
            metrics_bind,
            claim_window: Duration::from_millis(positive_number("RFID_CLAIM_WINDOW_MS", 60_000)?),
            lpr_correlation_mode,
            lpr_correlation_window,
            lpr_correlation_poll,
            discovery_mode,
            discovery_match_window,
            discovery_poll,
            discovery_passage_gap,
            discovery_max_dwell,
            discovery_min_rssi_cdbm: number("RFID_DISCOVERY_MIN_RSSI_CDBM", -6000)?,
            discovery_min_occurrences: positive_number("RFID_DISCOVERY_MIN_OCCURRENCES", 3)?,
            discovery_min_days: positive_number("RFID_DISCOVERY_MIN_DAYS", 2)?,
            discovery_min_confidence_percent,
            discovery_conflict_occurrences: positive_number(
                "RFID_DISCOVERY_CONFLICT_OCCURRENCES",
                2,
            )?,
            discovery_evidence_retention: days_duration("RFID_DISCOVERY_EVIDENCE_DAYS", 60)?,
            discovery_lease: days_duration("RFID_DISCOVERY_LEASE_DAYS", 60)?,
            gate_mode,
            gate_unlock_cooldown: Duration::from_millis(positive_number(
                "RFID_GATE_UNLOCK_COOLDOWN_MS",
                30_000,
            )?),
            unifi_base_url,
            unifi_api_key,
            unifi_verify_tls,
            unifi_ca_certificate,
            entry_gate_door_id,
        })
    }
}

fn parse_gate_mode(value: &str) -> Result<GateMode> {
    match value.trim().to_ascii_lowercase().as_str() {
        "disabled" | "off" => Ok(GateMode::Disabled),
        "dry-run" | "dry_run" | "dryrun" => Ok(GateMode::DryRun),
        "live" => Ok(GateMode::Live),
        _ => bail!("RFID_GATE_MODE must be disabled, dry-run, or live"),
    }
}

fn parse_lpr_correlation_mode(value: &str) -> Result<LprCorrelationMode> {
    match value.trim().to_ascii_lowercase().as_str() {
        "disabled" | "off" => Ok(LprCorrelationMode::Disabled),
        "dry-run" | "dry_run" | "dryrun" => Ok(LprCorrelationMode::DryRun),
        "live" => Ok(LprCorrelationMode::Live),
        _ => bail!("RFID_LPR_CORRELATION_MODE must be disabled, dry-run, or live"),
    }
}

fn parse_discovery_mode(value: &str) -> Result<LprCorrelationMode> {
    match value.trim().to_ascii_lowercase().as_str() {
        "disabled" | "off" => Ok(LprCorrelationMode::Disabled),
        "dry-run" | "dry_run" | "dryrun" => Ok(LprCorrelationMode::DryRun),
        "live" => Ok(LprCorrelationMode::Live),
        _ => bail!("RFID_DISCOVERY_MODE must be disabled, dry-run, or live"),
    }
}

pub fn state_db_path() -> PathBuf {
    env::var_os("RFID_STATE_DB")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("rfid-encoder.sqlite3"))
}

fn read_password() -> Result<String> {
    read_optional_secret("IMPINJ_PASSWORD_FILE", "IMPINJ_PASSWORD")?
        .context("IMPINJ_PASSWORD_FILE or IMPINJ_PASSWORD is required")
}

fn read_optional_secret(file_name: &str, value_name: &str) -> Result<Option<String>> {
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

fn normalize_base_url(value: &str) -> Result<String> {
    normalize_url(value, "IMPINJ_HOST")
}

fn normalize_url(value: &str, name: &str) -> Result<String> {
    let value = value.trim().trim_end_matches('/');
    if value.is_empty() {
        bail!("{name} is empty");
    }
    let url = if value.starts_with("http://") || value.starts_with("https://") {
        value.to_owned()
    } else {
        format!("https://{value}")
    };
    let parsed =
        reqwest::Url::parse(&url).with_context(|| format!("{name} is not a valid URL or host"))?;
    if parsed.host_str().is_none()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        bail!("{name} must contain only a scheme and host, without a path");
    }
    Ok(url)
}

fn web_bind() -> Result<SocketAddr> {
    let ip: IpAddr = env::var("FCR_GATE_WEB_BIND")
        .unwrap_or_else(|_| "127.0.0.1".into())
        .parse()
        .context("FCR_GATE_WEB_BIND must be an IP address")?;
    if !ip.is_loopback() {
        bail!("FCR_GATE_WEB_BIND must be a loopback address");
    }
    Ok(SocketAddr::new(ip, number("FCR_GATE_WEB_PORT", 8080)?))
}

fn metrics_bind() -> Result<SocketAddr> {
    let ip: IpAddr = env::var("FCR_GATE_METRICS_BIND")
        .unwrap_or_else(|_| "127.0.0.1".into())
        .parse()
        .context("FCR_GATE_METRICS_BIND must be an IP address")?;
    validate_metrics_bind(ip, number("FCR_GATE_METRICS_PORT", 9101)?)
}

fn validate_metrics_bind(ip: IpAddr, port: u16) -> Result<SocketAddr> {
    if ip.is_unspecified() {
        bail!("FCR_GATE_METRICS_BIND must not expose metrics on every interface");
    }
    Ok(SocketAddr::new(ip, port))
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

fn validate_profile_id(value: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        bail!("IMPINJ_PROFILE_ID may contain only letters, digits, dot, dash, and underscore");
    }
    Ok(value.to_owned())
}

pub fn normalize_hex(value: &str, exact_len: Option<usize>, name: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_uppercase();
    if normalized.is_empty() || !normalized.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("{name} must be hexadecimal");
    }
    if normalized.len() % 2 != 0 {
        bail!("{name} must contain complete bytes");
    }
    if let Some(length) = exact_len {
        if normalized.len() != length {
            bail!("{name} must contain exactly {length} hexadecimal characters");
        }
    }
    Ok(normalized)
}

fn required(name: &str) -> Result<String> {
    let value = env::var(name).with_context(|| format!("{name} is required"))?;
    if value.trim().is_empty() {
        bail!("{name} is empty");
    }
    Ok(value)
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

fn number<T>(name: &str, default: T) -> Result<T>
where
    T: std::str::FromStr,
    T::Err: std::error::Error + Send + Sync + 'static,
{
    let Ok(value) = env::var(name) else {
        return Ok(default);
    };
    value
        .trim()
        .parse()
        .with_context(|| format!("{name} is not a valid number"))
}

fn positive_number<T>(name: &str, default: T) -> Result<T>
where
    T: std::str::FromStr + PartialOrd + Default + Copy,
    T::Err: std::error::Error + Send + Sync + 'static,
{
    let value = number(name, default)?;
    if value <= T::default() {
        bail!("{name} must be greater than zero");
    }
    Ok(value)
}

fn days_duration(name: &str, default: u64) -> Result<Duration> {
    let days = positive_number(name, default)?;
    let seconds = days
        .checked_mul(24 * 60 * 60)
        .with_context(|| format!("{name} is too large"))?;
    Ok(Duration::from_secs(seconds))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_normalization_is_strict() {
        assert_eq!(normalize_hex(" aa00 ", Some(4), "TEST").unwrap(), "AA00");
        assert!(normalize_hex("xyz", None, "TEST").is_err());
        assert!(normalize_hex("AAA", None, "TEST").is_err());
        assert!(normalize_hex("AA", Some(4), "TEST").is_err());
    }

    #[test]
    fn base_url_defaults_to_https() {
        assert_eq!(
            normalize_base_url("192.168.10.229/").unwrap(),
            "https://192.168.10.229"
        );
        assert!(normalize_base_url("https://reader.local/path").is_err());
        assert!(normalize_base_url("https://user:password@reader.local").is_err());
        assert!(normalize_base_url("https://reader.local?query=value").is_err());
    }

    #[test]
    fn profile_id_is_safe_for_a_url_path() {
        assert_eq!(
            validate_profile_id(" fcr-gate_encoder.1 ").unwrap(),
            "fcr-gate_encoder.1"
        );
        assert!(validate_profile_id("../other/profile").is_err());
    }

    #[test]
    fn unifi_ids_are_validated_before_use_in_paths() {
        assert_eq!(
            validate_uuid("1B620B81-F457-45F7-9FD2-27DE1D8C4FDC", "TEST_ID").unwrap(),
            "1b620b81-f457-45f7-9fd2-27de1d8c4fdc"
        );
        assert!(validate_uuid("../../unlock", "TEST_ID").is_err());
    }

    #[test]
    fn gate_mode_has_an_explicit_dry_run() {
        assert_eq!(parse_gate_mode("disabled").unwrap(), GateMode::Disabled);
        assert_eq!(parse_gate_mode("dry-run").unwrap(), GateMode::DryRun);
        assert_eq!(parse_gate_mode("live").unwrap(), GateMode::Live);
        assert!(parse_gate_mode("true").is_err());
    }

    #[test]
    fn lpr_correlation_mode_has_an_explicit_dry_run() {
        assert_eq!(
            parse_lpr_correlation_mode("disabled").unwrap(),
            LprCorrelationMode::Disabled
        );
        assert_eq!(
            parse_lpr_correlation_mode("dry-run").unwrap(),
            LprCorrelationMode::DryRun
        );
        assert_eq!(
            parse_lpr_correlation_mode("live").unwrap(),
            LprCorrelationMode::Live
        );
        assert!(parse_lpr_correlation_mode("true").is_err());
    }

    #[test]
    fn discovery_mode_has_an_explicit_dry_run() {
        assert_eq!(
            parse_discovery_mode("disabled").unwrap(),
            LprCorrelationMode::Disabled
        );
        assert_eq!(
            parse_discovery_mode("dry-run").unwrap(),
            LprCorrelationMode::DryRun
        );
        assert_eq!(
            parse_discovery_mode("live").unwrap(),
            LprCorrelationMode::Live
        );
        assert!(parse_discovery_mode("true").is_err());
    }

    #[test]
    fn metrics_cannot_bind_every_network_interface() {
        assert!(validate_metrics_bind("0.0.0.0".parse().unwrap(), 9101).is_err());
        assert!(validate_metrics_bind("::".parse().unwrap(), 9101).is_err());
        assert_eq!(
            validate_metrics_bind("100.89.168.42".parse().unwrap(), 9101).unwrap(),
            "100.89.168.42:9101".parse().unwrap()
        );
    }
}

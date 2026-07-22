use std::{
    collections::{BTreeSet, HashMap},
    fs,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Datelike, Local, NaiveTime, Timelike, Utc, Weekday};
use reqwest::{Client, RequestBuilder, Response};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::json;

use crate::{config::Config, metrics::AppMetrics};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const USERS_PER_PAGE: usize = 100;
const MAX_USER_PAGES: usize = 100;
const SYSTEM_LOGS_PER_PAGE: usize = 200;

#[derive(Clone)]
pub struct UnifiClient {
    http: Client,
    base_url: String,
    api_key: String,
    entry_gate_door_id: String,
    metrics: AppMetrics,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct UnifiUser {
    pub id: String,
    #[serde(default)]
    pub first_name: String,
    #[serde(default)]
    pub last_name: String,
    #[serde(default)]
    pub full_name: String,
    #[serde(default)]
    pub user_email: String,
    #[serde(default)]
    pub employee_number: String,
    pub status: String,
}

impl UnifiUser {
    pub fn display_name(&self) -> String {
        if !self.full_name.trim().is_empty() {
            return self.full_name.trim().to_owned();
        }
        let name = format!("{} {}", self.first_name.trim(), self.last_name.trim())
            .trim()
            .to_owned();
        if name.is_empty() {
            self.user_email.clone()
        } else {
            name
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthorizationDecision {
    Granted {
        user: UnifiUser,
        policy_name: String,
    },
    Denied {
        user: Option<UnifiUser>,
        reason: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LprUserMatch {
    pub user_id: String,
    pub plate: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LprCorrelation {
    NoMatch,
    Match(LprUserMatch),
    Ambiguous { reason: String },
}

#[derive(Debug, Deserialize)]
struct Envelope<T> {
    code: String,
    #[serde(default)]
    msg: String,
    data: T,
    #[serde(default)]
    pagination: Option<Pagination>,
}

#[derive(Debug, Deserialize)]
struct Pagination {
    total: usize,
}

#[derive(Debug, Deserialize)]
struct SystemLogData {
    #[serde(default)]
    hits: Vec<SystemLogHit>,
}

#[derive(Clone, Debug, Deserialize)]
struct SystemLogHit {
    #[serde(rename = "@timestamp")]
    timestamp: String,
    #[serde(rename = "_source")]
    source: SystemLogSource,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct SystemLogSource {
    #[serde(default)]
    actor: Option<SystemLogActor>,
    #[serde(default)]
    authentication: Option<SystemLogAuthentication>,
    #[serde(default)]
    event: Option<SystemLogEvent>,
    #[serde(default)]
    target: Vec<SystemLogTarget>,
}

#[derive(Clone, Debug, Deserialize)]
struct SystemLogActor {
    #[serde(default)]
    id: String,
    #[serde(rename = "type", default)]
    kind: String,
}

#[derive(Clone, Debug, Deserialize)]
struct SystemLogAuthentication {
    #[serde(default)]
    credential_provider: String,
    #[serde(default)]
    issuer: String,
}

#[derive(Clone, Debug, Deserialize)]
struct SystemLogEvent {
    #[serde(default)]
    result: String,
}

#[derive(Clone, Debug, Deserialize)]
struct SystemLogTarget {
    #[serde(default)]
    id: String,
    #[serde(rename = "type", default)]
    kind: String,
}

#[derive(Clone, Debug, Deserialize)]
struct AccessPolicy {
    name: String,
    #[serde(default)]
    resources: Vec<Resource>,
    schedule_id: String,
}

#[derive(Clone, Debug, Deserialize)]
struct Resource {
    id: String,
    #[serde(rename = "type")]
    kind: String,
}

#[derive(Debug, Deserialize)]
struct DoorGroup {
    #[serde(default)]
    resources: Vec<Resource>,
}

#[derive(Clone, Debug, Deserialize)]
struct Schedule {
    #[serde(default)]
    weekly: Option<HashMap<String, Vec<TimeRange>>>,
    #[serde(default)]
    holiday_schedule: Option<Vec<TimeRange>>,
    #[serde(default)]
    holiday_group: Option<HolidayGroup>,
}

#[derive(Clone, Debug, Deserialize)]
struct TimeRange {
    start_time: String,
    end_time: String,
}

#[derive(Clone, Debug, Deserialize)]
struct HolidayGroup {
    #[serde(default)]
    holidays: Vec<Holiday>,
}

#[derive(Clone, Debug, Deserialize)]
struct Holiday {
    start_time: String,
    end_time: String,
    #[serde(default)]
    repeat: bool,
}

impl UnifiClient {
    pub fn new(config: &Config) -> Result<Self> {
        Self::with_metrics(config, AppMetrics::new())
    }

    pub fn with_metrics(config: &Config, metrics: AppMetrics) -> Result<Self> {
        let mut builder = Client::builder()
            .connect_timeout(REQUEST_TIMEOUT)
            .danger_accept_invalid_certs(!config.unifi_verify_tls);
        if let Some(path) = &config.unifi_ca_certificate {
            let pem = fs::read(path).with_context(|| {
                format!("failed to read UniFi CA certificate {}", path.display())
            })?;
            builder = builder.add_root_certificate(
                reqwest::Certificate::from_pem(&pem).context("invalid UniFi PEM CA certificate")?,
            );
        }
        Ok(Self {
            http: builder.build()?,
            base_url: format!(
                "{}/api/v1/developer",
                config
                    .unifi_base_url
                    .as_deref()
                    .context("UniFi Access host is not configured")?
            ),
            api_key: config
                .unifi_api_key
                .clone()
                .context("UniFi Access API key is not configured")?,
            entry_gate_door_id: config.entry_gate_door_id.clone(),
            metrics,
        })
    }

    pub async fn list_users(&self, query: &str) -> Result<Vec<UnifiUser>> {
        let mut users = Vec::new();
        for page in 1..=MAX_USER_PAGES {
            let response: Envelope<Vec<UnifiUser>> = self
                .get_envelope(
                    self.http.get(self.url("/users")).query(&[
                        ("page_num", page.to_string()),
                        ("page_size", USERS_PER_PAGE.to_string()),
                    ]),
                    "list UniFi users",
                    "list_users",
                )
                .await?;
            let page_len = response.data.len();
            let reported_total = response.pagination.as_ref().map(|page| page.total);
            users.extend(response.data);
            if page_len < USERS_PER_PAGE || reported_total.is_some_and(|total| users.len() >= total)
            {
                break;
            }
        }

        let query = query.trim().to_ascii_lowercase();
        users.retain(|user| {
            user.status == "ACTIVE"
                && (query.is_empty()
                    || [
                        user.display_name(),
                        user.user_email.clone(),
                        user.employee_number.clone(),
                    ]
                    .iter()
                    .any(|value| value.to_ascii_lowercase().contains(&query)))
        });
        users.sort_by_key(UnifiUser::display_name);
        users.truncate(200);
        Ok(users)
    }

    pub async fn find_lpr_user_match(
        &self,
        since: DateTime<Utc>,
        until: DateTime<Utc>,
    ) -> Result<LprCorrelation> {
        if until <= since {
            return Ok(LprCorrelation::NoMatch);
        }
        let response: Envelope<SystemLogData> = self
            .get_envelope(
                self.http
                    .post(self.url("/system/logs"))
                    .query(&[("page_num", 1_usize), ("page_size", SYSTEM_LOGS_PER_PAGE)])
                    .json(&json!({
                            "topic": "door_openings",
                            "since": since.timestamp(),
                            "until": until.timestamp(),
                    })),
                "fetch recent UniFi Entry Gate plate events",
                "fetch_lpr_events",
            )
            .await?;
        let truncated = response.pagination.as_ref().map_or_else(
            || response.data.hits.len() >= SYSTEM_LOGS_PER_PAGE,
            |pagination| pagination.total > response.data.hits.len(),
        );
        correlate_lpr_hits(
            &response.data.hits,
            &self.entry_gate_door_id,
            since,
            until,
            truncated,
        )
    }

    pub async fn validate_claim_user(&self, user_id: &str) -> Result<UnifiUser> {
        validate_uuid(user_id, "UniFi user ID")?;
        let user = self.get_user(user_id).await?;
        if user.status != "ACTIVE" {
            bail!("UniFi user {} is {}", user.display_name(), user.status);
        }
        let policies = self.get_user_policies(user_id).await?;
        for policy in policies {
            if self.policy_grants_entry_gate(&policy).await? {
                return Ok(user);
            }
        }
        bail!(
            "UniFi user {} has no Entry Gate access policy",
            user.display_name()
        )
    }

    pub async fn authorize_now(&self, user_id: &str) -> Result<AuthorizationDecision> {
        validate_uuid(user_id, "UniFi user ID")?;
        let user = self.get_user(user_id).await?;
        if user.status != "ACTIVE" {
            let status = user.status.clone();
            return Ok(AuthorizationDecision::Denied {
                user: Some(user),
                reason: format!("UniFi user status is {status}"),
            });
        }

        let policies = self.get_user_policies(user_id).await?;
        let now_local = Local::now();
        let now_utc = Utc::now();
        let mut gate_policy_found = false;
        for policy in policies {
            if !self.policy_grants_entry_gate(&policy).await? {
                continue;
            }
            gate_policy_found = true;
            let schedule = self.get_schedule(&policy.schedule_id).await?;
            if schedule_allows(&schedule, now_local, now_utc)? {
                return Ok(AuthorizationDecision::Granted {
                    user,
                    policy_name: policy.name,
                });
            }
        }

        let reason = if gate_policy_found {
            "Entry Gate policy is outside its current schedule"
        } else {
            "user has no Entry Gate access policy"
        };
        Ok(AuthorizationDecision::Denied {
            user: Some(user),
            reason: reason.into(),
        })
    }

    pub async fn unlock_entry_gate(
        &self,
        user: &UnifiUser,
        tid: &str,
        epc: &str,
        policy_name: &str,
    ) -> Result<()> {
        let payload = json!({
            "actor_id": user.id,
            "actor_name": user.display_name(),
            "extra": {
                "source": "fcr-rfid",
                "tid": tid,
                "epc": epc,
                "access_policy": policy_name,
            }
        });
        let _: Envelope<String> = self
            .get_envelope(
                self.http
                    .put(self.url(&format!("/doors/{}/unlock", self.entry_gate_door_id)))
                    .json(&payload),
                "unlock the Entry Gate",
                "unlock_gate",
            )
            .await?;
        Ok(())
    }

    async fn get_user(&self, user_id: &str) -> Result<UnifiUser> {
        let response: Envelope<UnifiUser> = self
            .get_envelope(
                self.http.get(self.url(&format!("/users/{user_id}"))),
                "fetch UniFi user",
                "fetch_user",
            )
            .await?;
        Ok(response.data)
    }

    async fn get_user_policies(&self, user_id: &str) -> Result<Vec<AccessPolicy>> {
        let response: Envelope<Vec<AccessPolicy>> = self
            .get_envelope(
                self.http
                    .get(self.url(&format!("/users/{user_id}/access_policies")))
                    .query(&[("only_user_policies", "false")]),
                "fetch UniFi user access policies",
                "fetch_user_policies",
            )
            .await?;
        Ok(response.data)
    }

    async fn policy_grants_entry_gate(&self, policy: &AccessPolicy) -> Result<bool> {
        for resource in &policy.resources {
            match resource.kind.as_str() {
                "door" if resource.id == self.entry_gate_door_id => return Ok(true),
                "door_group" => {
                    validate_uuid(&resource.id, "UniFi door group ID")?;
                    let response: Envelope<DoorGroup> = self
                        .get_envelope(
                            self.http
                                .get(self.url(&format!("/door_groups/{}", resource.id))),
                            "fetch UniFi door group",
                            "fetch_door_group",
                        )
                        .await?;
                    if response
                        .data
                        .resources
                        .iter()
                        .any(|door| door.kind == "door" && door.id == self.entry_gate_door_id)
                    {
                        return Ok(true);
                    }
                }
                _ => {}
            }
        }
        Ok(false)
    }

    async fn get_schedule(&self, schedule_id: &str) -> Result<Schedule> {
        validate_uuid(schedule_id, "UniFi schedule ID")?;
        let response: Envelope<Schedule> = self
            .get_envelope(
                self.http
                    .get(self.url(&format!("/access_policies/schedules/{schedule_id}"))),
                "fetch UniFi access schedule",
                "fetch_schedule",
            )
            .await?;
        Ok(response.data)
    }

    async fn get_envelope<T>(
        &self,
        request: RequestBuilder,
        operation: &str,
        metric_operation: &'static str,
    ) -> Result<Envelope<T>>
    where
        T: DeserializeOwned,
    {
        let started = Instant::now();
        let result = async {
            let response = self
                .authorized(request.timeout(REQUEST_TIMEOUT))
                .send()
                .await
                .with_context(|| format!("failed to {operation}"))?;
            parse_envelope(response, operation).await
        }
        .await;
        self.metrics
            .unifi_request(metric_operation, result.is_ok(), started.elapsed());
        result
    }

    fn authorized(&self, request: RequestBuilder) -> RequestBuilder {
        request.bearer_auth(&self.api_key)
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }
}

async fn parse_envelope<T>(response: Response, operation: &str) -> Result<Envelope<T>>
where
    T: DeserializeOwned,
{
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
    let envelope: Envelope<T> = serde_json::from_slice(&body)
        .with_context(|| format!("invalid UniFi response while trying to {operation}"))?;
    if envelope.code != "SUCCESS" {
        bail!("failed to {operation}: {}: {}", envelope.code, envelope.msg);
    }
    Ok(envelope)
}

fn correlate_lpr_hits(
    hits: &[SystemLogHit],
    entry_gate_door_id: &str,
    since: DateTime<Utc>,
    until: DateTime<Utc>,
    truncated: bool,
) -> Result<LprCorrelation> {
    if truncated {
        return Ok(LprCorrelation::Ambiguous {
            reason: "UniFi returned more plate events than fit in one page".into(),
        });
    }

    let mut plates = BTreeSet::new();
    let mut user_pairs = BTreeSet::new();
    let mut matches = Vec::new();
    let mut access_without_one_user = false;

    for hit in hits {
        let Some(authentication) = &hit.source.authentication else {
            continue;
        };
        if !authentication
            .credential_provider
            .eq_ignore_ascii_case("LICENSEPLATE")
        {
            continue;
        }
        if hit.source.target.is_empty() {
            return Ok(LprCorrelation::Ambiguous {
                reason: "a license-plate event omitted its target door".into(),
            });
        }
        if !hit.source.target.iter().any(|target| {
            target.kind.eq_ignore_ascii_case("door") && target.id == entry_gate_door_id
        }) {
            continue;
        }
        let timestamp = match parse_datetime(&hit.timestamp) {
            Ok(timestamp) => timestamp,
            Err(_) => {
                return Ok(LprCorrelation::Ambiguous {
                    reason: "an Entry Gate plate event had an invalid timestamp".into(),
                });
            }
        };
        // The lower bound is exclusive so an ambiguity cutoff cannot be reused.
        if timestamp <= since || timestamp > until {
            continue;
        }
        let plate = authentication.issuer.trim().to_ascii_uppercase();
        if plate.is_empty() {
            return Ok(LprCorrelation::Ambiguous {
                reason: "an Entry Gate plate event omitted its plate".into(),
            });
        }
        plates.insert(plate.clone());

        let Some(event) = &hit.source.event else {
            return Ok(LprCorrelation::Ambiguous {
                reason: "an Entry Gate plate event omitted its access result".into(),
            });
        };
        if event.result.trim().is_empty() {
            return Ok(LprCorrelation::Ambiguous {
                reason: "an Entry Gate plate event omitted its access result".into(),
            });
        }
        let is_access = event.result.eq_ignore_ascii_case("ACCESS");
        if !is_access {
            continue;
        }
        let Some(actor) = &hit.source.actor else {
            access_without_one_user = true;
            continue;
        };
        if !actor.kind.eq_ignore_ascii_case("user")
            || actor.id.trim().is_empty()
            || validate_uuid(actor.id.trim(), "UniFi LPR actor ID").is_err()
        {
            access_without_one_user = true;
            continue;
        }
        let user_id = actor.id.trim().to_ascii_lowercase();
        user_pairs.insert((user_id.clone(), plate.clone()));
        matches.push(LprUserMatch {
            user_id,
            plate,
            timestamp,
        });
    }

    if plates.len() > 1 {
        return Ok(LprCorrelation::Ambiguous {
            reason: format!(
                "{} different license plates were observed at the Entry Gate",
                plates.len()
            ),
        });
    }
    if access_without_one_user {
        return Ok(LprCorrelation::Ambiguous {
            reason: "an Entry Gate access event did not identify one permanent UniFi user".into(),
        });
    }
    if user_pairs.len() > 1 {
        return Ok(LprCorrelation::Ambiguous {
            reason: format!(
                "{} different user/plate pairs received Entry Gate access",
                user_pairs.len()
            ),
        });
    }
    let Some((user_id, plate)) = user_pairs.into_iter().next() else {
        return Ok(LprCorrelation::NoMatch);
    };
    let matched = matches
        .into_iter()
        .filter(|candidate| candidate.user_id == user_id && candidate.plate == plate)
        .max_by_key(|candidate| candidate.timestamp)
        .context("matched UniFi LPR pair had no source event")?;
    Ok(LprCorrelation::Match(matched))
}

fn schedule_allows(
    schedule: &Schedule,
    now_local: DateTime<Local>,
    now_utc: DateTime<Utc>,
) -> Result<bool> {
    let mut holiday_is_active = false;
    if let Some(group) = &schedule.holiday_group {
        for holiday in &group.holidays {
            if holiday_active(holiday, now_utc)? {
                holiday_is_active = true;
                break;
            }
        }
    }
    if holiday_is_active {
        return schedule
            .holiday_schedule
            .as_deref()
            .map_or(Ok(false), |ranges| {
                time_ranges_allow(ranges, now_local.time())
            });
    }

    let Some(weekly) = &schedule.weekly else {
        return Ok(true);
    };
    let day = weekday_name(now_local.weekday());
    let ranges = weekly.get(day).map(Vec::as_slice).unwrap_or_default();
    time_ranges_allow(ranges, now_local.time())
}

fn time_ranges_allow(ranges: &[TimeRange], now: NaiveTime) -> Result<bool> {
    for range in ranges {
        let start = parse_time(&range.start_time)?;
        let end = parse_time(&range.end_time)?;
        let allowed = if start <= end {
            now >= start && now <= end
        } else {
            now >= start || now <= end
        };
        if allowed {
            return Ok(true);
        }
    }
    Ok(false)
}

fn parse_time(value: &str) -> Result<NaiveTime> {
    NaiveTime::parse_from_str(value, "%H:%M:%S")
        .with_context(|| format!("invalid UniFi schedule time {value}"))
}

fn holiday_active(holiday: &Holiday, now: DateTime<Utc>) -> Result<bool> {
    let start = parse_datetime(&holiday.start_time)?;
    let end = parse_datetime(&holiday.end_time)?;
    if end <= start {
        bail!("invalid UniFi holiday range: end must be after start");
    }
    if !holiday.repeat {
        return Ok(now >= start && now < end);
    }

    let current = (
        now.month(),
        now.day(),
        now.hour(),
        now.minute(),
        now.second(),
    );
    let start_key = (
        start.month(),
        start.day(),
        start.hour(),
        start.minute(),
        start.second(),
    );
    let end_key = (
        end.month(),
        end.day(),
        end.hour(),
        end.minute(),
        end.second(),
    );
    Ok(if start_key <= end_key {
        current >= start_key && current < end_key
    } else {
        current >= start_key || current < end_key
    })
}

fn parse_datetime(value: &str) -> Result<DateTime<Utc>> {
    let normalized = value.trim().replace(' ', "T");
    DateTime::parse_from_rfc3339(&normalized)
        .map(|value| value.with_timezone(&Utc))
        .with_context(|| format!("invalid UniFi holiday time {value}"))
}

fn weekday_name(day: Weekday) -> &'static str {
    match day {
        Weekday::Mon => "monday",
        Weekday::Tue => "tuesday",
        Weekday::Wed => "wednesday",
        Weekday::Thu => "thursday",
        Weekday::Fri => "friday",
        Weekday::Sat => "saturday",
        Weekday::Sun => "sunday",
    }
}

fn validate_uuid(value: &str, name: &str) -> Result<()> {
    let valid = value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        });
    if !valid {
        bail!("{name} is not a UUID");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use chrono::{Local, TimeZone, Utc};
    use serde_json::json;

    use super::*;

    fn local_time(year: i32, month: u32, day: u32, hour: u32, minute: u32) -> DateTime<Local> {
        Local
            .with_ymd_and_hms(year, month, day, hour, minute, 0)
            .single()
            .unwrap()
    }

    fn lpr_hit(
        timestamp: &str,
        plate: &str,
        result: &str,
        actor: Option<(&str, &str)>,
        door_id: &str,
    ) -> SystemLogHit {
        let actor = actor.map(|(kind, id)| json!({"type": kind, "id": id}));
        serde_json::from_value(json!({
            "@timestamp": timestamp,
            "_source": {
                "actor": actor,
                "authentication": {
                    "credential_provider": "LICENSEPLATE",
                    "issuer": plate
                },
                "event": {"result": result},
                "target": [{"type": "door", "id": "ignored"}, {"type": "door", "id": door_id}]
            }
        }))
        .unwrap()
    }

    fn lpr_window() -> (DateTime<Utc>, DateTime<Utc>) {
        (
            Utc.with_ymd_and_hms(2026, 7, 19, 12, 0, 0).unwrap(),
            Utc.with_ymd_and_hms(2026, 7, 19, 12, 1, 0).unwrap(),
        )
    }

    #[test]
    fn repeated_plate_access_for_one_user_is_one_match() {
        let door = "1b620b81-f457-45f7-9fd2-27de1d8c4fdc";
        let user = "17d2f099-99df-429b-becb-1399a6937e5a";
        let hits = vec![
            lpr_hit(
                "2026-07-19T12:00:10Z",
                "ABC123",
                "ACCESS",
                Some(("user", user)),
                door,
            ),
            lpr_hit(
                "2026-07-19T12:00:11Z",
                "abc123",
                "ACCESS",
                Some(("user", user)),
                door,
            ),
        ];
        let (since, until) = lpr_window();

        assert_eq!(
            correlate_lpr_hits(&hits, door, since, until, false).unwrap(),
            LprCorrelation::Match(LprUserMatch {
                user_id: user.into(),
                plate: "ABC123".into(),
                timestamp: Utc.with_ymd_and_hms(2026, 7, 19, 12, 0, 11).unwrap(),
            })
        );
    }

    #[test]
    fn different_plates_make_the_window_ambiguous_even_if_one_was_blocked() {
        let door = "1b620b81-f457-45f7-9fd2-27de1d8c4fdc";
        let user = "17d2f099-99df-429b-becb-1399a6937e5a";
        let hits = vec![
            lpr_hit(
                "2026-07-19T12:00:10Z",
                "ABC123",
                "ACCESS",
                Some(("user", user)),
                door,
            ),
            lpr_hit("2026-07-19T12:00:11Z", "XYZ789", "BLOCKED", None, door),
        ];
        let (since, until) = lpr_window();

        assert!(matches!(
            correlate_lpr_hits(&hits, door, since, until, false).unwrap(),
            LprCorrelation::Ambiguous { .. }
        ));
    }

    #[test]
    fn visitor_access_is_not_treated_as_a_permanent_user_match() {
        let door = "1b620b81-f457-45f7-9fd2-27de1d8c4fdc";
        let hits = vec![lpr_hit(
            "2026-07-19T12:00:10Z",
            "ABC123",
            "ACCESS",
            Some(("visitor", "17d2f099-99df-429b-becb-1399a6937e5a")),
            door,
        )];
        let (since, until) = lpr_window();

        assert!(matches!(
            correlate_lpr_hits(&hits, door, since, until, false).unwrap(),
            LprCorrelation::Ambiguous { .. }
        ));
    }

    #[test]
    fn two_users_for_the_same_plate_are_ambiguous() {
        let door = "1b620b81-f457-45f7-9fd2-27de1d8c4fdc";
        let first = "17d2f099-99df-429b-becb-1399a6937e5a";
        let second = "27d2f099-99df-429b-becb-1399a6937e5b";
        let hits = vec![
            lpr_hit(
                "2026-07-19T12:00:10Z",
                "ABC123",
                "ACCESS",
                Some(("user", first)),
                door,
            ),
            lpr_hit(
                "2026-07-19T12:00:11Z",
                "ABC123",
                "ACCESS",
                Some(("user", second)),
                door,
            ),
        ];
        let (since, until) = lpr_window();

        assert!(matches!(
            correlate_lpr_hits(&hits, door, since, until, false).unwrap(),
            LprCorrelation::Ambiguous { .. }
        ));
    }

    #[test]
    fn malformed_entry_gate_plate_event_is_ambiguous() {
        let door = "1b620b81-f457-45f7-9fd2-27de1d8c4fdc";
        let user = "17d2f099-99df-429b-becb-1399a6937e5a";
        let hits = vec![lpr_hit(
            "not-a-time",
            "ABC123",
            "ACCESS",
            Some(("user", user)),
            door,
        )];
        let (since, until) = lpr_window();

        assert!(matches!(
            correlate_lpr_hits(&hits, door, since, until, false).unwrap(),
            LprCorrelation::Ambiguous { .. }
        ));
    }

    #[test]
    fn blocked_or_wrong_door_events_do_not_match() {
        let door = "1b620b81-f457-45f7-9fd2-27de1d8c4fdc";
        let other = "2b620b81-f457-45f7-9fd2-27de1d8c4fdc";
        let user = "17d2f099-99df-429b-becb-1399a6937e5a";
        let hits = vec![
            lpr_hit("2026-07-19T12:00:10Z", "ABC123", "BLOCKED", None, door),
            lpr_hit(
                "2026-07-19T12:00:11Z",
                "ABC123",
                "ACCESS",
                Some(("user", user)),
                other,
            ),
        ];
        let (since, until) = lpr_window();

        assert_eq!(
            correlate_lpr_hits(&hits, door, since, until, false).unwrap(),
            LprCorrelation::NoMatch
        );
    }

    #[test]
    fn truncated_log_window_fails_closed_as_ambiguous() {
        let (since, until) = lpr_window();
        assert!(matches!(
            correlate_lpr_hits(&[], "door", since, until, true).unwrap(),
            LprCorrelation::Ambiguous { .. }
        ));
    }

    #[test]
    fn weekly_schedule_is_enforced() {
        let schedule = Schedule {
            weekly: Some(HashMap::from([(
                "monday".into(),
                vec![TimeRange {
                    start_time: "08:00:00".into(),
                    end_time: "17:00:00".into(),
                }],
            )])),
            holiday_schedule: None,
            holiday_group: None,
        };
        let monday = local_time(2026, 7, 20, 9, 0);
        let sunday = local_time(2026, 7, 19, 9, 0);
        assert!(schedule_allows(&schedule, monday, Utc::now()).unwrap());
        assert!(!schedule_allows(&schedule, sunday, Utc::now()).unwrap());
    }

    #[test]
    fn a_holiday_overrides_the_weekly_schedule() {
        let schedule = Schedule {
            weekly: None,
            holiday_schedule: Some(Vec::new()),
            holiday_group: Some(HolidayGroup {
                holidays: vec![Holiday {
                    start_time: "2026-07-18 00:00:00Z".into(),
                    end_time: "2026-07-19 00:00:00Z".into(),
                    repeat: false,
                }],
            }),
        };
        let now_utc = Utc.with_ymd_and_hms(2026, 7, 18, 12, 0, 0).unwrap();
        let now_local = now_utc.with_timezone(&Local);
        assert!(!schedule_allows(&schedule, now_local, now_utc).unwrap());
    }

    #[test]
    fn malformed_holiday_times_fail_closed() {
        let schedule = Schedule {
            weekly: None,
            holiday_schedule: None,
            holiday_group: Some(HolidayGroup {
                holidays: vec![Holiday {
                    start_time: "not-a-time".into(),
                    end_time: "2026-07-19 00:00:00Z".into(),
                    repeat: false,
                }],
            }),
        };
        let now_utc = Utc.with_ymd_and_hms(2026, 7, 18, 12, 0, 0).unwrap();
        let now_local = now_utc.with_timezone(&Local);
        assert!(schedule_allows(&schedule, now_local, now_utc).is_err());
    }

    #[test]
    fn overnight_weekly_ranges_cover_both_sides_of_midnight() {
        let ranges = vec![TimeRange {
            start_time: "22:00:00".into(),
            end_time: "05:00:00".into(),
        }];
        assert!(time_ranges_allow(&ranges, NaiveTime::from_hms_opt(23, 30, 0).unwrap()).unwrap());
        assert!(time_ranges_allow(&ranges, NaiveTime::from_hms_opt(4, 30, 0).unwrap()).unwrap());
        assert!(!time_ranges_allow(&ranges, NaiveTime::from_hms_opt(12, 0, 0).unwrap()).unwrap());
    }

    #[test]
    fn annually_repeating_holiday_handles_a_year_boundary() {
        let holiday = Holiday {
            start_time: "2025-12-31T00:00:00Z".into(),
            end_time: "2026-01-02T00:00:00Z".into(),
            repeat: true,
        };
        let new_years_day = Utc.with_ymd_and_hms(2027, 1, 1, 12, 0, 0).unwrap();
        let january_third = Utc.with_ymd_and_hms(2027, 1, 3, 12, 0, 0).unwrap();
        assert!(holiday_active(&holiday, new_years_day).unwrap());
        assert!(!holiday_active(&holiday, january_third).unwrap());
    }

    #[test]
    fn malformed_weekly_time_fails_closed() {
        let ranges = vec![TimeRange {
            start_time: "tomorrow".into(),
            end_time: "17:00:00".into(),
        }];
        assert!(time_ranges_allow(&ranges, NaiveTime::from_hms_opt(12, 0, 0).unwrap()).is_err());
    }

    #[test]
    fn user_display_name_has_safe_fallbacks() {
        let user = UnifiUser {
            id: "17d2f099-99df-429b-becb-1399a6937e5a".into(),
            first_name: "Example".into(),
            last_name: "User".into(),
            full_name: String::new(),
            user_email: "example@test".into(),
            employee_number: String::new(),
            status: "ACTIVE".into(),
        };
        assert_eq!(user.display_name(), "Example User");
    }
}

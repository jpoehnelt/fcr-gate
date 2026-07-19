use std::{
    collections::{HashMap, HashSet},
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use fcr_rfid_encoder::{
    config::{Config, GateMode, LprCorrelationMode, normalize_hex, state_db_path},
    engine::{Action, Engine},
    impinj::ImpinjClient,
    model::{ReaderEvent, TagObservation},
    store::{Store, now_ms},
    unifi::{AuthorizationDecision, LprCorrelation, UnifiClient},
    web,
};
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(about, version)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the R700 inventory and encode-on-first-arrival loop.
    Run,
    /// Show durable EPC assignments and their current state.
    Status {
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Show recent live and dry-run gate authorization decisions.
    GateEvents {
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Reset a failed or conflicted TID for another controlled attempt.
    Retry { tid: String },
}

struct GateRuntime {
    unifi: Option<UnifiClient>,
    last_attempts: HashMap<String, Instant>,
    lpr_last_attempts: HashMap<String, Instant>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    match Cli::parse().command.unwrap_or(Command::Run) {
        Command::Run => run().await,
        Command::Status { limit } => status(limit),
        Command::GateEvents { limit } => gate_events(limit),
        Command::Retry { tid } => retry(&tid),
    }
}

async fn run() -> Result<()> {
    let config = Config::from_env()?;
    let mut store = Store::open(&config.state_db, config.actor.clone())?;
    let recovered = store.recover_interrupted()?;
    if recovered > 0 {
        warn!(recovered, "recovered interrupted encoding assignments");
    }

    let reader = ImpinjClient::new(&config)?;
    reader.ensure_profile(&config).await?;
    let reader_health = reader.health();
    let unifi =
        (config.web_enabled || config.gate_mode.enabled() || config.lpr_correlation_mode.enabled())
            .then(|| UnifiClient::new(&config))
            .transpose()?;

    let (sender, mut receiver) = mpsc::channel::<ReaderEvent>(4096);
    let stream_task = tokio::spawn(reader.clone().stream_events(sender));
    let web_handle = if config.web_enabled || config.health_enabled {
        Some(web::start(&config, unifi.clone(), reader_health).await?)
    } else {
        None
    };
    let mut engine = Engine::new(
        config.antenna_port,
        config.default_epc.clone(),
        config.min_rssi_cdbm,
        config.confirm_reads,
        config.confirm_window,
    );
    let mut dry_run_reported = HashSet::new();
    let mut gate = GateRuntime {
        unifi,
        last_attempts: HashMap::new(),
        lpr_last_attempts: HashMap::new(),
    };
    let mut timeout_check = tokio::time::interval(Duration::from_secs(1));
    timeout_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);

    info!(
        writes_enabled = config.writes_enabled,
        antenna = config.antenna_port,
        min_rssi_dbm = config.min_rssi_cdbm as f64 / 100.0,
        confirm_reads = config.confirm_reads,
        operator_ui = config.web_enabled,
        health_endpoint = config.health_enabled,
        lpr_correlation_mode = config.lpr_correlation_mode.as_str(),
        gate_mode = config.gate_mode.as_str(),
        "RFID encoder service ready"
    );
    if !config.writes_enabled {
        warn!(
            "RFID writes are disabled; candidates will be observed but never allocated or modified"
        );
    }

    loop {
        tokio::select! {
            result = &mut shutdown => {
                result?;
                info!("shutdown requested");
                stream_task.abort();
                if let Err(error) = reader.stop_profile(&config.profile_id).await {
                    warn!(%error, "could not stop the owned reader profile during shutdown");
                }
                if let Some(web_handle) = web_handle {
                    web_handle.shutdown().await;
                }
                return Ok(());
            }
            _ = timeout_check.tick() => {
                if let Some(tid) = engine.expire_in_flight(Instant::now(), config.access_timeout) {
                    let reason = "tag access/read-back inventory confirmation timed out";
                    store.mark_access_failed(
                        &tid,
                        reason,
                        config.retry_cooldown,
                        config.max_attempts,
                    )?;
                    warn!(%tid, "encoding transaction timed out and was released for retry");
                }
            }
            event = receiver.recv() => {
                let Some(event) = event else {
                    stream_task.abort();
                    anyhow::bail!("reader event task stopped unexpectedly");
                };
                if let Err(error) = handle_event(
                    &config,
                    &reader,
                    &mut store,
                    &mut engine,
                    &mut dry_run_reported,
                    &mut gate,
                    event,
                ).await {
                    error!(%error, "failed to process reader event");
                }
            }
        }
    }
}

async fn shutdown_signal() -> Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .context("failed to install SIGTERM handler")?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result.context("failed to install Ctrl-C handler"),
            _ = terminate.recv() => Ok(()),
        }
    }

    #[cfg(not(unix))]
    tokio::signal::ctrl_c()
        .await
        .context("failed to install Ctrl-C handler")
}

async fn handle_event(
    config: &Config,
    reader: &ImpinjClient,
    store: &mut Store,
    engine: &mut Engine,
    dry_run_reported: &mut HashSet<String>,
    gate: &mut GateRuntime,
    event: ReaderEvent,
) -> Result<()> {
    let Some(observation) = TagObservation::from_reader_event(&event) else {
        return Ok(());
    };
    let assignment = store.get_by_tid(&observation.tid)?;
    if assignment.as_ref().is_some_and(|encoding| {
        encoding.status == "completed" && encoding.assigned_epc == observation.epc
    }) {
        store.record_seen(
            &observation.tid,
            &observation.epc,
            observation.peak_rssi_cdbm,
        )?;
        maybe_correlate_lpr(config, gate, store, &observation).await?;
        maybe_unlock_gate(config, gate, store, &observation).await?;
    }
    let action = engine.observe(&observation, assignment.as_ref(), Instant::now());

    match action {
        Action::None => {}
        Action::CandidateReady { tid } => {
            if !config.writes_enabled {
                if dry_run_reported.insert(tid.clone()) {
                    info!(
                        %tid,
                        rssi_dbm = observation.peak_rssi_cdbm as f64 / 100.0,
                        "dry-run candidate satisfied all encoding gates"
                    );
                }
                return Ok(());
            }

            let prefix = config
                .epc_prefix
                .as_deref()
                .context("missing EPC prefix while writes are enabled")?;
            let encoding = match assignment {
                Some(encoding) => encoding,
                None => store.allocate(&tid, prefix)?,
            };
            if !encoding.may_attempt(now_ms(), config.max_attempts) {
                return Ok(());
            }

            match reader
                .queue_epc_write(
                    &encoding.tid,
                    &encoding.assigned_epc,
                    config.tag_access_password.as_deref(),
                )
                .await
            {
                Ok(()) => {
                    store.mark_queued(&encoding.tid)?;
                    engine.set_in_flight(encoding.tid.clone(), Instant::now());
                    info!(
                        tid = %encoding.tid,
                        epc = %encoding.assigned_epc,
                        attempt = encoding.attempts + 1,
                        "queued exact-TID EPC write"
                    );
                }
                Err(error) => {
                    store.mark_post_failed(
                        &encoding.tid,
                        &error.to_string(),
                        config.retry_cooldown,
                    )?;
                    engine.clear_in_flight(&encoding.tid);
                    return Err(error);
                }
            }
        }
        Action::AccessVerified { tid, epc } => {
            store.mark_verified(&tid, &epc)?;
            info!(%tid, %epc, "all EPC words and read-back verified; awaiting inventory confirmation");
        }
        Action::AccessFailed { tid, reason } => {
            store.mark_access_failed(&tid, &reason, config.retry_cooldown, config.max_attempts)?;
            engine.clear_in_flight(&tid);
            warn!(%tid, %reason, "EPC write transaction failed");
        }
        Action::Completed { tid, epc } => {
            store.mark_completed(&tid, &epc)?;
            store.record_seen(&tid, &epc, observation.peak_rssi_cdbm)?;
            engine.clear_in_flight(&tid);
            info!(%tid, %epc, "encoding completed and confirmed by normal inventory");
            maybe_correlate_lpr(config, gate, store, &observation).await?;
        }
        Action::Conflict { tid, observed_epc } => {
            store.mark_conflict(&tid, &observed_epc)?;
            engine.clear_in_flight(&tid);
            error!(%tid, %observed_epc, "TID reported an EPC different from its durable assignment");
        }
    }
    Ok(())
}

async fn maybe_correlate_lpr(
    config: &Config,
    gate: &mut GateRuntime,
    store: &mut Store,
    observation: &TagObservation,
) -> Result<()> {
    if config.lpr_correlation_mode == LprCorrelationMode::Disabled
        || store.get_active_owner(&observation.tid)?.is_some()
    {
        return Ok(());
    }

    let attempt_time = Instant::now();
    if gate
        .lpr_last_attempts
        .get(&observation.tid)
        .is_some_and(|last| attempt_time.duration_since(*last) < config.lpr_correlation_poll)
    {
        return Ok(());
    }
    gate.lpr_last_attempts
        .insert(observation.tid.clone(), attempt_time);

    let now = Utc::now();
    let now_ms = now.timestamp_millis();
    let recent_tids = store.recent_never_assigned_tids(config.lpr_correlation_window)?;
    if recent_tids.len() != 1 || recent_tids[0] != observation.tid {
        if recent_tids.iter().any(|tid| tid == &observation.tid) && recent_tids.len() > 1 {
            for tid in &recent_tids {
                store.advance_lpr_correlation_not_before(tid, now_ms)?;
            }
            warn!(
                tid = %observation.tid,
                tag_count = recent_tids.len(),
                "LPR correlation deferred because multiple unassigned RFID tags are present; a new plate event will be required"
            );
        }
        return Ok(());
    }

    let window_ms = i64::try_from(config.lpr_correlation_window.as_millis()).unwrap_or(i64::MAX);
    let window_start_ms = now_ms.saturating_sub(window_ms);
    let since_ms = store
        .lpr_correlation_not_before_ms(&observation.tid)?
        .map_or(window_start_ms, |cutoff| cutoff.max(window_start_ms));
    let since = DateTime::<Utc>::from_timestamp_millis(since_ms)
        .context("LPR correlation cutoff is outside the supported date range")?;
    if since >= now {
        return Ok(());
    }
    let unifi = gate
        .unifi
        .as_ref()
        .context("LPR correlation requires a UniFi Access client")?;

    match unifi.find_lpr_user_match(since, now).await? {
        LprCorrelation::NoMatch => {}
        LprCorrelation::Ambiguous { reason } => {
            store.advance_lpr_correlation_not_before(&observation.tid, now_ms)?;
            let detail = serde_json::json!({"reason": reason}).to_string();
            store.record_lpr_correlation_audit(
                &observation.tid,
                &observation.epc,
                "lpr-correlation-ambiguous",
                &detail,
            )?;
            warn!(
                tid = %observation.tid,
                %reason,
                "LPR correlation was ambiguous; a new plate event will be required"
            );
        }
        LprCorrelation::Match(candidate) => {
            let user = match unifi.validate_claim_user(&candidate.user_id).await {
                Ok(user) => user,
                Err(error) => {
                    store.advance_lpr_correlation_not_before(&observation.tid, now_ms)?;
                    let detail = serde_json::json!({
                        "reason": error.to_string(),
                        "plate": candidate.plate,
                        "unifi_user_id": candidate.user_id,
                    })
                    .to_string();
                    store.record_lpr_correlation_audit(
                        &observation.tid,
                        &observation.epc,
                        "lpr-correlation-ambiguous",
                        &detail,
                    )?;
                    warn!(
                        tid = %observation.tid,
                        %error,
                        "LPR user failed the ownership eligibility check; a new plate event will be required"
                    );
                    return Ok(());
                }
            };
            let detail = serde_json::json!({
                "plate": candidate.plate,
                "unifi_user_id": user.id,
                "unifi_user_name": user.display_name(),
                "lpr_timestamp": candidate.timestamp.to_rfc3339(),
            })
            .to_string();
            if config.lpr_correlation_mode == LprCorrelationMode::DryRun {
                store.record_lpr_correlation_audit(
                    &observation.tid,
                    &observation.epc,
                    "lpr-correlation-dry-run",
                    &detail,
                )?;
                store.advance_lpr_correlation_not_before(&observation.tid, now_ms)?;
                info!(
                    tid = %observation.tid,
                    plate = %candidate.plate,
                    user = %user.display_name(),
                    "dry run: LPR event would assign RFID tag to existing UniFi user"
                );
                return Ok(());
            }

            let vehicle = format!("License plate {}", candidate.plate);
            store.claim_tag(
                &observation.tid,
                &user.id,
                &user.display_name(),
                Some(&vehicle),
                config.claim_window,
            )?;
            // The successful LPR event already opened the gate. Avoid a redundant
            // remote unlock on the same pass when RFID gate mode is also enabled.
            gate.last_attempts
                .insert(observation.tid.clone(), Instant::now());
            info!(
                tid = %observation.tid,
                plate = %candidate.plate,
                user = %user.display_name(),
                "assigned RFID tag to the existing UniFi user matched by Entry Gate LPR"
            );
        }
    }
    Ok(())
}

async fn maybe_unlock_gate(
    config: &Config,
    gate: &mut GateRuntime,
    store: &mut Store,
    observation: &TagObservation,
) -> Result<()> {
    if config.gate_mode == GateMode::Disabled {
        return Ok(());
    }
    let Some(owner) = store.get_active_owner(&observation.tid)? else {
        return Ok(());
    };
    let now = Instant::now();
    if gate
        .last_attempts
        .get(&observation.tid)
        .is_some_and(|last| now.duration_since(*last) < config.gate_unlock_cooldown)
    {
        return Ok(());
    }
    gate.last_attempts.insert(observation.tid.clone(), now);
    let unifi = gate
        .unifi
        .as_ref()
        .context("gate unlock requires a UniFi Access client")?;

    match unifi.authorize_now(&owner.unifi_user_id).await {
        Ok(AuthorizationDecision::Granted { user, policy_name }) => {
            if config.gate_mode == GateMode::DryRun {
                store.record_gate_decision(
                    &observation.tid,
                    &observation.epc,
                    Some(&user.id),
                    config.gate_mode.as_str(),
                    "granted",
                    Some(&policy_name),
                )?;
                info!(
                    tid = %observation.tid,
                    epc = %observation.epc,
                    user = %user.display_name(),
                    policy = %policy_name,
                    "dry run: assigned RFID tag would unlock the Entry Gate"
                );
                return Ok(());
            }
            match unifi
                .unlock_entry_gate(&user, &observation.tid, &observation.epc, &policy_name)
                .await
            {
                Ok(()) => {
                    store.record_gate_decision(
                        &observation.tid,
                        &observation.epc,
                        Some(&user.id),
                        config.gate_mode.as_str(),
                        "granted",
                        Some(&policy_name),
                    )?;
                    info!(
                        tid = %observation.tid,
                        epc = %observation.epc,
                        user = %user.display_name(),
                        policy = %policy_name,
                        "authorized RFID tag unlocked the Entry Gate"
                    );
                }
                Err(error) => {
                    store.record_gate_decision(
                        &observation.tid,
                        &observation.epc,
                        Some(&user.id),
                        config.gate_mode.as_str(),
                        "error",
                        Some(&error.to_string()),
                    )?;
                    return Err(error.context("authorized RFID unlock command failed"));
                }
            }
        }
        Ok(AuthorizationDecision::Denied { user, reason }) => {
            store.record_gate_decision(
                &observation.tid,
                &observation.epc,
                user.as_ref().map(|user| user.id.as_str()),
                config.gate_mode.as_str(),
                "denied",
                Some(&reason),
            )?;
            warn!(
                tid = %observation.tid,
                epc = %observation.epc,
                %reason,
                gate_mode = config.gate_mode.as_str(),
                "assigned RFID tag denied by current UniFi user policy"
            );
        }
        Err(error) => {
            store.record_gate_decision(
                &observation.tid,
                &observation.epc,
                Some(&owner.unifi_user_id),
                config.gate_mode.as_str(),
                "error",
                Some(&error.to_string()),
            )?;
            return Err(error.context("could not verify current UniFi access; gate remains locked"));
        }
    }
    Ok(())
}

fn status(limit: usize) -> Result<()> {
    let store = Store::open(&state_db_path(), "status")?;
    println!("SEQUENCE\tSTATUS\tATTEMPTS\tTID\tEPC\tLAST ERROR");
    for encoding in store.list(limit)? {
        println!(
            "{}\t{}\t{}\t{}\t{}\t{}",
            encoding.sequence,
            encoding.status,
            encoding.attempts,
            encoding.tid,
            encoding.assigned_epc,
            encoding.last_error.as_deref().unwrap_or("")
        );
    }
    Ok(())
}

fn retry(tid: &str) -> Result<()> {
    let tid = normalize_hex(tid, None, "TID")?;
    let mut store = Store::open(&state_db_path(), "manual-cli")?;
    store.retry(&tid)?;
    println!("reset {tid} for a controlled retry");
    Ok(())
}

fn gate_events(limit: usize) -> Result<()> {
    let store = Store::open(&state_db_path(), "status")?;
    println!("TIMESTAMP\tMODE\tDECISION\tTID\tEPC\tUNIFI USER\tDETAIL");
    for event in store.list_gate_events(limit)? {
        println!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}",
            event.timestamp,
            event.mode,
            event.decision,
            event.tid,
            event.epc,
            event.unifi_user_id.as_deref().unwrap_or(""),
            one_line(event.detail.as_deref().unwrap_or(""))
        );
    }
    Ok(())
}

fn one_line(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use std::{
        path::PathBuf,
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
    };

    use axum::{
        Json, Router,
        extract::State,
        routing::{get, post, put},
    };
    use serde_json::{Value, json};
    use tempfile::tempdir;
    use tokio::{net::TcpListener, task::JoinHandle};

    use super::*;

    const USER_ID: &str = "17d2f099-99df-429b-becb-1399a6937e5a";
    const DOOR_ID: &str = "1b620b81-f457-45f7-9fd2-27de1d8c4fdc";
    const GROUP_ID: &str = "5c496423-6d25-4e4f-8cdf-95ad5135188a";
    const SCHEDULE_ID: &str = "73facd6c-839e-4521-a4f4-c07e1d44e748";

    #[derive(Default)]
    struct MockCounts {
        user_active: AtomicBool,
        user_reads: AtomicUsize,
        policy_reads: AtomicUsize,
        group_reads: AtomicUsize,
        schedule_reads: AtomicUsize,
        lpr_reads: AtomicUsize,
        unlocks: AtomicUsize,
        lpr_hits: Mutex<Vec<Value>>,
    }

    async fn mock_user(State(counts): State<Arc<MockCounts>>) -> Json<Value> {
        counts.user_reads.fetch_add(1, Ordering::SeqCst);
        let status = if counts.user_active.load(Ordering::SeqCst) {
            "ACTIVE"
        } else {
            "DEACTIVATED"
        };
        Json(json!({
            "code": "SUCCESS",
            "msg": "success",
            "data": {
                "id": USER_ID,
                "first_name": "Example",
                "last_name": "User",
                "full_name": "Example User",
                "user_email": "example@example.com",
                "employee_number": "100",
                "status": status
            }
        }))
    }

    async fn mock_policies(State(counts): State<Arc<MockCounts>>) -> Json<Value> {
        counts.policy_reads.fetch_add(1, Ordering::SeqCst);
        Json(json!({
            "code": "SUCCESS",
            "msg": "success",
            "data": [{
                "name": "Entry Gate policy",
                "resources": [{"id": GROUP_ID, "type": "door_group"}],
                "schedule_id": SCHEDULE_ID
            }]
        }))
    }

    async fn mock_group(State(counts): State<Arc<MockCounts>>) -> Json<Value> {
        counts.group_reads.fetch_add(1, Ordering::SeqCst);
        Json(json!({
            "code": "SUCCESS",
            "msg": "success",
            "data": {"resources": [{"id": DOOR_ID, "type": "door"}]}
        }))
    }

    async fn mock_schedule(State(counts): State<Arc<MockCounts>>) -> Json<Value> {
        counts.schedule_reads.fetch_add(1, Ordering::SeqCst);
        Json(json!({
            "code": "SUCCESS",
            "msg": "success",
            "data": {"weekly": null}
        }))
    }

    async fn mock_unlock(
        State(counts): State<Arc<MockCounts>>,
        Json(payload): Json<Value>,
    ) -> Json<Value> {
        assert_eq!(payload["actor_id"], USER_ID);
        assert_eq!(payload["actor_name"], "Example User");
        assert_eq!(payload["extra"]["source"], "fcr-rfid");
        assert_eq!(payload["extra"]["access_policy"], "Entry Gate policy");
        counts.unlocks.fetch_add(1, Ordering::SeqCst);
        Json(json!({"code": "SUCCESS", "msg": "success", "data": "success"}))
    }

    async fn mock_logs(
        State(counts): State<Arc<MockCounts>>,
        Json(payload): Json<Value>,
    ) -> Json<Value> {
        assert_eq!(payload["topic"], "door_openings");
        counts.lpr_reads.fetch_add(1, Ordering::SeqCst);
        let hits = counts.lpr_hits.lock().unwrap().clone();
        Json(json!({
            "code": "SUCCESS",
            "msg": "success",
            "pagination": {"total": hits.len()},
            "data": {"hits": hits}
        }))
    }

    async fn mock_unifi(user_active: bool) -> (String, Arc<MockCounts>, JoinHandle<()>) {
        let counts = Arc::new(MockCounts::default());
        counts.user_active.store(user_active, Ordering::SeqCst);
        let app = Router::new()
            .route("/api/v1/developer/users/{id}", get(mock_user))
            .route(
                "/api/v1/developer/users/{id}/access_policies",
                get(mock_policies),
            )
            .route("/api/v1/developer/door_groups/{id}", get(mock_group))
            .route(
                "/api/v1/developer/access_policies/schedules/{id}",
                get(mock_schedule),
            )
            .route("/api/v1/developer/system/logs", post(mock_logs))
            .route("/api/v1/developer/doors/{id}/unlock", put(mock_unlock))
            .with_state(counts.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{address}"), counts, task)
    }

    fn test_config(db: PathBuf, unifi_base_url: String, gate_mode: GateMode) -> Config {
        Config {
            reader_base_url: "https://reader.test".into(),
            reader_username: "root".into(),
            reader_password: "secret".into(),
            verify_tls: false,
            ca_certificate: None,
            profile_id: "test".into(),
            antenna_port: 1,
            transmit_power_cdbm: 3000,
            rf_mode: 4,
            writes_enabled: false,
            default_epc: "300833B2DDD9014000000000".into(),
            epc_prefix: None,
            min_rssi_cdbm: -5000,
            confirm_reads: 5,
            confirm_window: Duration::from_secs(1),
            access_timeout: Duration::from_secs(15),
            retry_cooldown: Duration::from_secs(3),
            max_attempts: 3,
            state_db: db,
            tag_access_password: None,
            actor: "test".into(),
            web_enabled: false,
            health_enabled: false,
            health_stale_after: Duration::from_secs(120),
            web_bind: "127.0.0.1:8080".parse().unwrap(),
            claim_window: Duration::from_secs(60),
            lpr_correlation_mode: LprCorrelationMode::Disabled,
            lpr_correlation_window: Duration::from_secs(10),
            lpr_correlation_poll: Duration::from_secs(2),
            gate_mode,
            gate_unlock_cooldown: Duration::from_secs(30),
            unifi_base_url: Some(unifi_base_url),
            unifi_api_key: Some("test-token".into()),
            unifi_verify_tls: false,
            unifi_ca_certificate: None,
            entry_gate_door_id: DOOR_ID.into(),
        }
    }

    fn assigned_tag(store: &mut Store) -> TagObservation {
        let observation = unassigned_tag(store);
        store
            .claim_tag(
                &observation.tid,
                USER_ID,
                "Example User",
                None,
                Duration::from_secs(60),
            )
            .unwrap();
        observation
    }

    fn unassigned_tag(store: &mut Store) -> TagObservation {
        let encoding = store.allocate("E2801111", "FCA7000100000000").unwrap();
        store
            .mark_completed(&encoding.tid, &encoding.assigned_epc)
            .unwrap();
        store
            .record_seen(&encoding.tid, &encoding.assigned_epc, -4200)
            .unwrap();
        TagObservation {
            tid: encoding.tid,
            epc: encoding.assigned_epc,
            antenna_port: 1,
            peak_rssi_cdbm: -4200,
            access_responses: Vec::new(),
        }
    }

    fn lpr_hit(timestamp: DateTime<Utc>, plate: &str, result: &str) -> Value {
        json!({
            "@timestamp": timestamp.to_rfc3339(),
            "_source": {
                "actor": if result == "ACCESS" {
                    json!({"type": "user", "id": USER_ID})
                } else {
                    json!({"type": "", "id": ""})
                },
                "authentication": {
                    "credential_provider": "LICENSEPLATE",
                    "issuer": plate
                },
                "event": {"result": result},
                "target": [{"type": "door", "id": DOOR_ID}]
            }
        })
    }

    #[tokio::test]
    async fn dry_run_evaluates_every_policy_layer_without_unlocking() {
        let (base_url, counts, server) = mock_unifi(true).await;
        let directory = tempdir().unwrap();
        let db = directory.path().join("state.sqlite3");
        let dry_run = test_config(db.clone(), base_url.clone(), GateMode::DryRun);
        let mut store = Store::open(&db, "operator@example.com").unwrap();
        let observation = assigned_tag(&mut store);
        let mut gate = GateRuntime {
            unifi: Some(UnifiClient::new(&dry_run).unwrap()),
            last_attempts: HashMap::new(),
            lpr_last_attempts: HashMap::new(),
        };

        maybe_unlock_gate(&dry_run, &mut gate, &mut store, &observation)
            .await
            .unwrap();

        assert_eq!(counts.user_reads.load(Ordering::SeqCst), 1);
        assert_eq!(counts.policy_reads.load(Ordering::SeqCst), 1);
        assert_eq!(counts.group_reads.load(Ordering::SeqCst), 1);
        assert_eq!(counts.schedule_reads.load(Ordering::SeqCst), 1);
        assert_eq!(counts.unlocks.load(Ordering::SeqCst), 0);
        let dry_event = &store.list_gate_events(1).unwrap()[0];
        assert_eq!(dry_event.mode, "dry-run");
        assert_eq!(dry_event.decision, "granted");

        let live = test_config(db, base_url, GateMode::Live);
        let mut live_gate = GateRuntime {
            unifi: Some(UnifiClient::new(&live).unwrap()),
            last_attempts: HashMap::new(),
            lpr_last_attempts: HashMap::new(),
        };
        maybe_unlock_gate(&live, &mut live_gate, &mut store, &observation)
            .await
            .unwrap();
        assert_eq!(counts.unlocks.load(Ordering::SeqCst), 1);
        let live_event = &store.list_gate_events(1).unwrap()[0];
        assert_eq!(live_event.mode, "live");
        assert_eq!(live_event.decision, "granted");
        server.abort();
    }

    #[tokio::test]
    async fn deactivated_user_is_denied_before_policy_or_unlock_calls() {
        let (base_url, counts, server) = mock_unifi(false).await;
        let directory = tempdir().unwrap();
        let db = directory.path().join("state.sqlite3");
        let config = test_config(db.clone(), base_url, GateMode::DryRun);
        let mut store = Store::open(&db, "operator@example.com").unwrap();
        let observation = assigned_tag(&mut store);
        let mut gate = GateRuntime {
            unifi: Some(UnifiClient::new(&config).unwrap()),
            last_attempts: HashMap::new(),
            lpr_last_attempts: HashMap::new(),
        };

        maybe_unlock_gate(&config, &mut gate, &mut store, &observation)
            .await
            .unwrap();

        assert_eq!(counts.user_reads.load(Ordering::SeqCst), 1);
        assert_eq!(counts.policy_reads.load(Ordering::SeqCst), 0);
        assert_eq!(counts.unlocks.load(Ordering::SeqCst), 0);
        let event = &store.list_gate_events(1).unwrap()[0];
        assert_eq!(event.mode, "dry-run");
        assert_eq!(event.decision, "denied");
        assert_eq!(
            event.detail.as_deref(),
            Some("UniFi user status is DEACTIVATED")
        );
        server.abort();
    }

    #[tokio::test]
    async fn a_new_clean_lpr_event_resolves_durable_first_pass_ambiguity() {
        let (base_url, counts, server) = mock_unifi(true).await;
        let directory = tempdir().unwrap();
        let db = directory.path().join("state.sqlite3");
        let mut config = test_config(db.clone(), base_url, GateMode::Disabled);
        config.lpr_correlation_mode = LprCorrelationMode::Live;
        config.lpr_correlation_poll = Duration::from_millis(1);
        let mut store = Store::open(&db, "gate-auto").unwrap();
        let observation = unassigned_tag(&mut store);
        let first_event = Utc::now() - chrono::Duration::seconds(1);
        *counts.lpr_hits.lock().unwrap() = vec![
            lpr_hit(first_event, "ABC123", "ACCESS"),
            lpr_hit(first_event, "XYZ789", "BLOCKED"),
        ];
        let mut gate = GateRuntime {
            unifi: Some(UnifiClient::new(&config).unwrap()),
            last_attempts: HashMap::new(),
            lpr_last_attempts: HashMap::new(),
        };

        maybe_correlate_lpr(&config, &mut gate, &mut store, &observation)
            .await
            .unwrap();
        assert!(store.get_active_owner(&observation.tid).unwrap().is_none());
        assert!(
            store
                .lpr_correlation_not_before_ms(&observation.tid)
                .unwrap()
                .is_some()
        );

        // Reopen the database to prove the ambiguity cutoff survives a service
        // restart. Elapsed wall-clock time does not affect future eligibility.
        drop(store);
        tokio::time::sleep(Duration::from_millis(5)).await;
        let clean_event = Utc::now();
        counts
            .lpr_hits
            .lock()
            .unwrap()
            .push(lpr_hit(clean_event, "ABC123", "ACCESS"));
        let mut store = Store::open(&db, "gate-auto").unwrap();
        let mut restarted_gate = GateRuntime {
            unifi: Some(UnifiClient::new(&config).unwrap()),
            last_attempts: HashMap::new(),
            lpr_last_attempts: HashMap::new(),
        };

        maybe_correlate_lpr(&config, &mut restarted_gate, &mut store, &observation)
            .await
            .unwrap();

        let owner = store.get_active_owner(&observation.tid).unwrap().unwrap();
        assert_eq!(owner.unifi_user_id, USER_ID);
        assert_eq!(
            owner.vehicle_description.as_deref(),
            Some("License plate ABC123")
        );
        assert_eq!(counts.lpr_reads.load(Ordering::SeqCst), 2);
        assert_eq!(counts.unlocks.load(Ordering::SeqCst), 0);
        server.abort();
    }
}

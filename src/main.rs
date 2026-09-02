use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use fcr_rfid_encoder::{
    config::{Config, DiscoveryMode, GateMode, normalize_hex, state_db_path},
    impinj::ImpinjClient,
    logging,
    model::{DiscoveryObservation, ReaderEvent},
    plate::same_plate_family,
    store::{
        DiscoveryCandidate, DiscoverySeen, PassageMatchOutcome, PendingDiscoveryPassage, Store,
    },
    unifi::{AuthorizationDecision, LprCorrelation, UnifiClient},
    web,
};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

#[derive(Debug, Parser)]
#[command(about, version)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the R700 inventory, tag discovery, and gate-authorization loop.
    Run,
    /// Show recent live and dry-run gate authorization decisions.
    GateEvents {
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Show multi-visit EPC/TID-to-vehicle discovery candidates.
    DiscoveryStatus {
        #[arg(long, default_value_t = 100)]
        limit: usize,
    },
    /// Associate a mature visitor-backed discovery candidate with a permanent user.
    AssociateDiscovered {
        tag_key: String,
        unifi_user_id: String,
        /// Print the validated plan without writing. This is the default.
        #[arg(long, conflicts_with = "apply")]
        dry_run: bool,
        /// Persist the association. Without this flag, only print the validated plan.
        #[arg(long)]
        apply: bool,
    },
    /// Permanently revoke a learned tag assignment.
    RevokeLearned { tag_key: String },
    /// Clear a suspended learned tag's evidence so it can learn again.
    ResetLearned { tag_key: String },
}

struct GateRuntime {
    unifi: Option<UnifiClient>,
    last_attempts: HashMap<String, Instant>,
    discovery_last_attempts: HashMap<String, Instant>,
    discovery_retry_attempts: HashMap<i64, DiscoveryRetryState>,
    discovery_lpr_cache: Option<CachedDiscoveryLpr>,
}

struct DiscoveryRetryState {
    attempts: u8,
    last_attempt: Instant,
}

struct CachedDiscoveryLpr {
    fetched_at: Instant,
    observed_at_ms: i64,
    correlation: LprCorrelation,
}

const DISCOVERY_LPR_RETRY_DELAY: Duration = Duration::from_secs(15);
const DISCOVERY_LPR_RETRY_INTERVAL: Duration = Duration::from_secs(15);
const DISCOVERY_LPR_MAX_RETRIES: u8 = 3;
const DISCOVERY_LPR_RETRY_HORIZON: Duration = Duration::from_secs(90);
const DISCOVERY_LPR_RETRY_PASS_TIMEOUT: Duration = Duration::from_secs(2);
const DISCOVERY_LPR_RETRY_BATCH: usize = 20;

#[tokio::main]
async fn main() -> Result<()> {
    let logging = logging::init();
    let loki_metrics = logging.metrics();

    let result = match Cli::parse().command.unwrap_or(Command::Run) {
        Command::Run => run(loki_metrics).await,
        Command::GateEvents { limit } => gate_events(limit),
        Command::DiscoveryStatus { limit } => discovery_status(limit),
        Command::AssociateDiscovered {
            tag_key,
            unifi_user_id,
            dry_run: _,
            apply,
        } => associate_discovered(&tag_key, &unifi_user_id, apply).await,
        Command::RevokeLearned { tag_key } => revoke_learned(&tag_key),
        Command::ResetLearned { tag_key } => reset_learned(&tag_key),
    };
    logging.shutdown().await;
    result
}

async fn run(loki_metrics: std::sync::Arc<logging::LokiMetrics>) -> Result<()> {
    let config = Config::from_env()?;
    let mut store = Store::open(&config.state_db, config.actor.clone())?;

    let reader = ImpinjClient::new(&config)?;
    reader.ensure_profile(&config).await?;
    let reader_health = reader.health();
    let unifi = (config.gate_mode.enabled() || config.discovery_mode.enabled())
        .then(|| UnifiClient::new(&config))
        .transpose()?;

    let web_handle = if config.health_enabled {
        Some(web::start(&config, reader_health, std::sync::Arc::clone(&loki_metrics)).await?)
    } else {
        None
    };
    let (sender, mut receiver) = mpsc::channel::<ReaderEvent>(4096);
    let stream_task = tokio::spawn(reader.clone().stream_events(sender));
    let mut gate = GateRuntime {
        unifi,
        last_attempts: HashMap::new(),
        discovery_last_attempts: HashMap::new(),
        discovery_retry_attempts: HashMap::new(),
        discovery_lpr_cache: None,
    };
    let mut timeout_check = tokio::time::interval(Duration::from_secs(1));
    timeout_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);

    info!(
        event = "service_ready",
        antenna = config.antenna_port,
        health_endpoint = config.health_enabled,
        loki_delivery = loki_metrics.enabled(),
        discovery_mode = config.discovery_mode.as_str(),
        gate_mode = config.gate_mode.as_str(),
        "RFID gate service ready"
    );

    loop {
        tokio::select! {
            result = &mut shutdown => {
                result?;
                info!(event = "service_shutdown_requested", "shutdown requested");
                stream_task.abort();
                if config.preset_reuse_only {
                    info!(event = "reader_profile_left_running", profile = %config.profile_id, "leaving the externally owned reader preset running");
                } else if let Err(error) = reader.stop_profile(&config.profile_id).await {
                    warn!(event = "reader_profile_stop_failed", %error, "could not stop the owned reader profile during shutdown");
                }
                if let Some(web_handle) = web_handle {
                    web_handle.shutdown().await;
                }
                return Ok(());
            }
            _ = timeout_check.tick() => {
                if config.discovery_mode.enabled() {
                    match tokio::time::timeout(
                        DISCOVERY_LPR_RETRY_PASS_TIMEOUT,
                        retry_pending_discovery_matches(&config, &mut gate, &mut store),
                    )
                    .await
                    {
                        Ok(Ok(())) => {}
                        Ok(Err(error)) => {
                            error!(event = "discovery_retry_failed", %error, "failed to retry pending RFID/LPR discovery passages");
                        }
                        Err(_) => {
                            warn!(event = "discovery_retry_paused", "paused delayed RFID/LPR retries to keep the reader loop responsive");
                        }
                    }
                }
            }
            event = receiver.recv() => {
                let Some(event) = event else {
                    stream_task.abort();
                    anyhow::bail!("reader event task stopped unexpectedly");
                };
                if let Err(error) = handle_event(
                    &config,
                    &mut store,
                    &mut gate,
                    event,
                ).await {
                    error!(event = "reader_event_processing_failed", %error, "failed to process reader event");
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
    store: &mut Store,
    gate: &mut GateRuntime,
    event: ReaderEvent,
) -> Result<()> {
    let Some(observation) = DiscoveryObservation::from_reader_event(&event) else {
        return Ok(());
    };
    if observation.antenna_port != config.antenna_port {
        return Ok(());
    }

    if config.discovery_mode.enabled()
        && observation.peak_rssi_cdbm >= config.discovery_min_rssi_cdbm
    {
        maybe_learn_discovered_tag(config, gate, store, &observation).await?;
    }
    maybe_unlock_gate_identity(config, gate, store, &observation.tag_key, &observation.epc).await?;
    Ok(())
}

async fn maybe_learn_discovered_tag(
    config: &Config,
    gate: &mut GateRuntime,
    store: &mut Store,
    observation: &DiscoveryObservation,
) -> Result<()> {
    let attempt_time = Instant::now();
    if gate
        .discovery_last_attempts
        .get(&observation.tag_key)
        .is_some_and(|last| attempt_time.duration_since(*last) < config.discovery_poll)
    {
        return Ok(());
    }
    gate.discovery_last_attempts
        .insert(observation.tag_key.clone(), attempt_time);

    let seen = store.record_discovery_seen(
        &observation.tag_key,
        observation.identity_kind,
        observation.tid.as_deref(),
        &observation.epc,
        observation.peak_rssi_cdbm,
        observation.observed_at_ms,
        config.discovery_passage_gap,
        config.discovery_max_dwell,
        config.discovery_evidence_retention,
    )?;
    if seen.new_passage {
        info!(
            event = "rfid_passage_started",
            passage_id = seen.passage_id,
            tag = %observation.tag_key,
            identity_kind = observation.identity_kind,
            tid = observation.tid.as_deref().unwrap_or(""),
            epc = %observation.epc,
            antenna = observation.antenna_port,
            rssi_dbm = observation.peak_rssi_cdbm as f64 / 100.0,
            "observed a new RFID passage"
        );
    }
    if seen.became_long_dwell {
        let reason = "tag remained continuously readable beyond the discovery dwell limit";
        if config.discovery_mode == DiscoveryMode::Live
            && store.suspend_discovered_tag(&observation.tag_key, reason)?
        {
            warn!(
                event = "discovered_tag_suspended_stationary",
                tag = %observation.tag_key,
                "suspended learned tag because it appears stationary near the reader"
            );
        } else if config.discovery_mode == DiscoveryMode::DryRun {
            warn!(
                event = "discovered_tag_stationary",
                mode = "dry-run",
                tag = %observation.tag_key,
                "dry run: stationary-tag evidence would suspend an active learned tag"
            );
        }
    }
    if seen.long_dwell || seen.correlation_status == "ambiguous" {
        return Ok(());
    }

    match_discovery_passage(config, gate, store, observation, &seen).await
}

async fn match_discovery_passage(
    config: &Config,
    gate: &mut GateRuntime,
    store: &mut Store,
    observation: &DiscoveryObservation,
    seen: &DiscoverySeen,
) -> Result<()> {
    let attempt_time = Instant::now();
    let window_ms = i64::try_from(config.discovery_match_window.as_millis()).unwrap_or(i64::MAX);
    let since_ms = seen.started_at_ms.saturating_sub(window_ms);
    let now_ms = Utc::now().timestamp_millis();
    let until_ms = seen.last_seen_ms.saturating_add(window_ms).min(now_ms);
    let since = DateTime::<Utc>::from_timestamp_millis(since_ms)
        .context("discovery match window is outside the supported date range")?;
    let until = DateTime::<Utc>::from_timestamp_millis(until_ms)
        .context("discovery match window is outside the supported date range")?;
    if until <= since {
        return Ok(());
    }
    let poll_ms = i64::try_from(config.discovery_poll.as_millis()).unwrap_or(i64::MAX);
    let cached_correlation = gate.discovery_lpr_cache.as_ref().and_then(|cached| {
        let timestamp_matches = match &cached.correlation {
            LprCorrelation::Match(candidate) => {
                candidate.timestamp > since && candidate.timestamp <= until
            }
            LprCorrelation::NoMatch | LprCorrelation::Ambiguous { .. } => true,
        };
        (attempt_time.duration_since(cached.fetched_at) < config.discovery_poll
            && seen.last_seen_ms.abs_diff(cached.observed_at_ms)
                <= u64::try_from(poll_ms).unwrap_or(u64::MAX)
            && timestamp_matches)
            .then(|| cached.correlation.clone())
    });
    let correlation = if let Some(correlation) = cached_correlation {
        correlation
    } else {
        let correlation = gate
            .unifi
            .as_ref()
            .context("RFID discovery requires a UniFi Access client")?
            .find_lpr_user_match(since, until)
            .await?;
        gate.discovery_lpr_cache = Some(CachedDiscoveryLpr {
            fetched_at: attempt_time,
            observed_at_ms: seen.last_seen_ms,
            correlation: correlation.clone(),
        });
        correlation
    };

    let lpr_match = match correlation {
        LprCorrelation::NoMatch => return Ok(()),
        LprCorrelation::Ambiguous { reason } => {
            let invalidated_match = seen.correlation_status == "matched";
            if store.mark_discovery_passage_ambiguous(seen.passage_id)? {
                warn!(
                    event = "discovery_passage_ambiguous",
                    tag = %observation.tag_key,
                    %reason,
                    "discarded ambiguous multi-visit discovery passage"
                );
            }
            if invalidated_match
                && config.discovery_mode == DiscoveryMode::Live
                && store.suspend_discovered_tag(
                    &observation.tag_key,
                    "an RFID passage later contained ambiguous LPR evidence",
                )?
            {
                warn!(
                    event = "discovered_tag_suspended_ambiguous",
                    tag = %observation.tag_key,
                    "suspended learned tag after a previously matched passage became ambiguous"
                );
            }
            return Ok(());
        }
        LprCorrelation::Match(candidate) => candidate,
    };
    let outcome = store.record_discovery_match(
        seen.passage_id,
        lpr_match.timestamp.timestamp_millis(),
        &lpr_match.plate,
        &lpr_match.actor_type,
        &lpr_match.actor_id,
    )?;
    match outcome {
        PassageMatchOutcome::Duplicate => return Ok(()),
        PassageMatchOutcome::Ambiguous => {
            if config.discovery_mode == DiscoveryMode::Live
                && store.suspend_discovered_tag(
                    &observation.tag_key,
                    "one RFID passage correlated with more than one LPR identity",
                )?
            {
                warn!(
                    event = "discovered_tag_suspended_multiple_vehicles",
                    tag = %observation.tag_key,
                    "suspended learned tag after one passage matched multiple vehicles"
                );
            } else if config.discovery_mode == DiscoveryMode::DryRun {
                warn!(
                    event = "discovery_passage_multiple_vehicles",
                    mode = "dry-run",
                    tag = %observation.tag_key,
                    "dry run: ambiguous passage would suspend an active learned tag"
                );
            }
            return Ok(());
        }
        PassageMatchOutcome::Recorded => {}
    }

    if let Some(assignment) = store.learned_assignment(&observation.tag_key)? {
        if assignment.status != "active" {
            return Ok(());
        }
        if assignment.lpr_actor_type == lpr_match.actor_type
            && assignment.lpr_actor_id == lpr_match.actor_id
            && same_plate_family(&assignment.plate, &lpr_match.plate)
        {
            if config.discovery_mode == DiscoveryMode::Live {
                store.renew_discovered_lease(
                    &observation.tag_key,
                    &lpr_match.actor_type,
                    &lpr_match.actor_id,
                    &lpr_match.plate,
                    config.discovery_lease,
                )?;
            }
            gate.last_attempts
                .insert(observation.tag_key.clone(), Instant::now());
            return Ok(());
        }
        let conflicts = store.count_discovery_conflicts(
            &observation.tag_key,
            &assignment.lpr_actor_type,
            &assignment.lpr_actor_id,
            &assignment.plate,
            config.discovery_evidence_retention,
        )?;
        if config.discovery_mode == DiscoveryMode::Live
            && conflicts >= config.discovery_conflict_occurrences
            && store.suspend_discovered_tag(
                &observation.tag_key,
                "repeated LPR evidence tied the tag to another vehicle",
            )?
        {
            warn!(
                event = "discovered_tag_suspended_conflict",
                tag = %observation.tag_key,
                conflicts,
                original_plate = %assignment.plate,
                observed_plate = %lpr_match.plate,
                "suspended learned tag after repeated conflicting vehicle evidence"
            );
        } else if config.discovery_mode == DiscoveryMode::DryRun
            && conflicts >= config.discovery_conflict_occurrences
        {
            warn!(
                event = "discovered_tag_conflict",
                mode = "dry-run",
                tag = %observation.tag_key,
                conflicts,
                original_plate = %assignment.plate,
                observed_plate = %lpr_match.plate,
                "dry run: repeated conflicting evidence would suspend the learned tag"
            );
        }
        gate.last_attempts
            .insert(observation.tag_key.clone(), Instant::now());
        return Ok(());
    }

    let min_occurrences = if observation.identity_kind == "epc" {
        config.discovery_min_occurrences.max(5)
    } else {
        config.discovery_min_occurrences
    };
    let Some(candidate) = store.discovery_candidate(
        &observation.tag_key,
        config.discovery_evidence_retention,
        min_occurrences,
        config.discovery_min_days,
        config.discovery_min_confidence_percent,
        config.discovery_conflict_occurrences,
    )?
    else {
        return Ok(());
    };
    if !candidate.ready {
        return Ok(());
    }
    if candidate.lpr_actor_type == "visitor" {
        if store.record_discovery_candidate_audit(&candidate)? {
            info!(
                event = "discovery_candidate_needs_resident",
                tag = %candidate.tag_key,
                epc = %candidate.epc,
                plate = %candidate.plate,
                visitor_id = %candidate.lpr_actor_id,
                occurrences = candidate.matched_occurrences,
                days = candidate.distinct_days,
                confidence = candidate.confidence_percent,
                "visitor-backed RFID evidence is ready for manual resident association"
            );
        }
        return Ok(());
    }
    let user = match gate
        .unifi
        .as_ref()
        .context("RFID discovery requires a UniFi Access client")?
        .validate_claim_user(&candidate.lpr_actor_id)
        .await
    {
        Ok(user) => user,
        Err(error) => {
            warn!(
                event = "discovery_user_validation_failed",
                tag = %candidate.tag_key,
                plate = %candidate.plate,
                user_id = %candidate.lpr_actor_id,
                %error,
                "learned RFID candidate did not pass current UniFi user validation"
            );
            return Ok(());
        }
    };
    if config.discovery_mode == DiscoveryMode::DryRun {
        if store.record_discovery_candidate_audit(&candidate)? {
            info!(
                event = "discovery_candidate_ready",
                mode = "dry-run",
                tag = %candidate.tag_key,
                epc = %candidate.epc,
                plate = %candidate.plate,
                user_id = %user.id,
                user = %user.display_name(),
                occurrences = candidate.matched_occurrences,
                days = candidate.distinct_days,
                confidence = candidate.confidence_percent,
                "dry run: multi-visit evidence would activate an existing RFID tag"
            );
        }
        return Ok(());
    }

    store.activate_discovered_tag(
        &candidate,
        &user.id,
        &user.display_name(),
        config.discovery_lease,
    )?;
    gate.last_attempts
        .insert(observation.tag_key.clone(), Instant::now());
    info!(
        event = "discovered_tag_activated",
        tag = %candidate.tag_key,
        epc = %candidate.epc,
        plate = %candidate.plate,
        user_id = %user.id,
        user = %user.display_name(),
        occurrences = candidate.matched_occurrences,
        days = candidate.distinct_days,
        confidence = candidate.confidence_percent,
        "activated existing RFID tag from multi-visit vehicle evidence"
    );
    Ok(())
}

async fn retry_pending_discovery_matches(
    config: &Config,
    gate: &mut GateRuntime,
    store: &mut Store,
) -> Result<()> {
    let now_ms = Utc::now().timestamp_millis();
    let retry_delay_ms = i64::try_from(DISCOVERY_LPR_RETRY_DELAY.as_millis()).unwrap_or(i64::MAX);
    let retry_horizon_ms =
        i64::try_from(DISCOVERY_LPR_RETRY_HORIZON.as_millis()).unwrap_or(i64::MAX);
    let pending = store.pending_discovery_passages(
        now_ms.saturating_sub(retry_delay_ms),
        now_ms.saturating_sub(retry_horizon_ms),
        DISCOVERY_LPR_RETRY_BATCH,
    )?;
    gate.discovery_retry_attempts
        .retain(|_, state| state.last_attempt.elapsed() < DISCOVERY_LPR_RETRY_HORIZON);

    for passage in pending {
        let retry_due = gate
            .discovery_retry_attempts
            .get(&passage.passage_id)
            .is_none_or(|state| {
                state.attempts < DISCOVERY_LPR_MAX_RETRIES
                    && state.last_attempt.elapsed() >= DISCOVERY_LPR_RETRY_INTERVAL
            });
        if !retry_due {
            continue;
        }
        let attempts = gate
            .discovery_retry_attempts
            .get(&passage.passage_id)
            .map_or(1, |state| state.attempts.saturating_add(1));
        gate.discovery_retry_attempts.insert(
            passage.passage_id,
            DiscoveryRetryState {
                attempts,
                last_attempt: Instant::now(),
            },
        );

        let observation = pending_discovery_observation(config, &passage);
        let seen = DiscoverySeen {
            passage_id: passage.passage_id,
            new_passage: false,
            started_at_ms: passage.started_at_ms,
            last_seen_ms: passage.last_seen_ms,
            correlation_status: "pending".into(),
            long_dwell: false,
            became_long_dwell: false,
        };
        if let Err(error) = match_discovery_passage(config, gate, store, &observation, &seen).await
        {
            warn!(
                event = "discovery_passage_retry_failed",
                passage_id = passage.passage_id,
                tag = %passage.tag_key,
                attempt = attempts,
                %error,
                "delayed RFID/LPR discovery retry failed"
            );
        }
    }
    Ok(())
}

fn pending_discovery_observation(
    config: &Config,
    passage: &PendingDiscoveryPassage,
) -> DiscoveryObservation {
    let identity_kind = match passage.identity_kind.as_str() {
        "tid" => "tid",
        "epc" => "epc",
        _ => unreachable!("discovery identity kind is constrained by SQLite"),
    };
    DiscoveryObservation {
        tag_key: passage.tag_key.clone(),
        identity_kind,
        tid: passage.tid.clone(),
        epc: passage.epc.clone(),
        antenna_port: config.antenna_port,
        peak_rssi_cdbm: passage.peak_rssi_cdbm,
        observed_at_ms: passage.last_seen_ms,
    }
}

async fn maybe_unlock_gate_identity(
    config: &Config,
    gate: &mut GateRuntime,
    store: &mut Store,
    tag_key: &str,
    epc: &str,
) -> Result<()> {
    if config.gate_mode == GateMode::Disabled {
        return Ok(());
    }
    let Some(owner) = store.get_gate_owner(tag_key)? else {
        return Ok(());
    };
    let now = Instant::now();
    if gate
        .last_attempts
        .get(tag_key)
        .is_some_and(|last| now.duration_since(*last) < config.gate_unlock_cooldown)
    {
        return Ok(());
    }
    gate.last_attempts.insert(tag_key.to_owned(), now);
    let unifi = gate
        .unifi
        .as_ref()
        .context("gate unlock requires a UniFi Access client")?;

    match unifi.authorize_now(&owner.unifi_user_id).await {
        Ok(AuthorizationDecision::Granted { user, policy_name }) => {
            if config.gate_mode == GateMode::DryRun {
                store.record_gate_decision(
                    tag_key,
                    epc,
                    Some(&user.id),
                    config.gate_mode.as_str(),
                    "granted",
                    Some(&policy_name),
                )?;
                info!(
                    event = "gate_authorization",
                    mode = "dry-run",
                    decision = "granted",
                    tag = %tag_key,
                    %epc,
                    user_id = %user.id,
                    user = %user.display_name(),
                    policy = %policy_name,
                    "dry run: assigned RFID tag would unlock the Entry Gate"
                );
                return Ok(());
            }
            match unifi
                .unlock_entry_gate(&user, tag_key, epc, &policy_name)
                .await
            {
                Ok(()) => {
                    store.record_gate_decision(
                        tag_key,
                        epc,
                        Some(&user.id),
                        config.gate_mode.as_str(),
                        "granted",
                        Some(&policy_name),
                    )?;
                    info!(
                        event = "gate_authorization",
                        mode = "live",
                        decision = "granted",
                        tag = %tag_key,
                        %epc,
                        user_id = %user.id,
                        user = %user.display_name(),
                        policy = %policy_name,
                        "authorized RFID tag unlocked the Entry Gate"
                    );
                }
                Err(error) => {
                    store.record_gate_decision(
                        tag_key,
                        epc,
                        Some(&user.id),
                        config.gate_mode.as_str(),
                        "error",
                        Some(&error.to_string()),
                    )?;
                    error!(
                        event = "gate_authorization",
                        mode = "live",
                        decision = "error",
                        tag = %tag_key,
                        %epc,
                        user_id = %user.id,
                        %error,
                        "authorized RFID unlock command failed"
                    );
                    return Err(error.context("authorized RFID unlock command failed"));
                }
            }
        }
        Ok(AuthorizationDecision::Denied { user, reason }) => {
            store.record_gate_decision(
                tag_key,
                epc,
                user.as_ref().map(|user| user.id.as_str()),
                config.gate_mode.as_str(),
                "denied",
                Some(&reason),
            )?;
            warn!(
                event = "gate_authorization",
                decision = "denied",
                tag = %tag_key,
                %epc,
                user_id = %owner.unifi_user_id,
                %reason,
                mode = config.gate_mode.as_str(),
                "assigned RFID tag denied by current UniFi user policy"
            );
        }
        Err(error) => {
            store.record_gate_decision(
                tag_key,
                epc,
                Some(&owner.unifi_user_id),
                config.gate_mode.as_str(),
                "error",
                Some(&error.to_string()),
            )?;
            error!(
                event = "gate_authorization",
                decision = "error",
                tag = %tag_key,
                %epc,
                user_id = %owner.unifi_user_id,
                %error,
                mode = config.gate_mode.as_str(),
                "could not verify current UniFi access; gate remains locked"
            );
            return Err(error.context("could not verify current UniFi access; gate remains locked"));
        }
    }
    Ok(())
}

fn gate_events(limit: usize) -> Result<()> {
    let store = Store::open(&state_db_path(), "status")?;
    println!("TIMESTAMP\tMODE\tDECISION\tTAG KEY\tEPC\tUNIFI USER\tDETAIL");
    for event in store.list_gate_events(limit)? {
        println!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}",
            event.timestamp,
            event.mode,
            event.decision,
            event.tag_key,
            event.epc,
            event.unifi_user_id.as_deref().unwrap_or(""),
            one_line(event.detail.as_deref().unwrap_or(""))
        );
    }
    Ok(())
}

fn discovery_status(limit: usize) -> Result<()> {
    let config = Config::from_env()?;
    let store = Store::open(&config.state_db, "status")?;
    println!(
        "STATUS\tIDENTITY\tEPC\tPLATE\tMATCHES\tDAYS\tPASSAGES\tCONFIDENCE\tCONFLICTS\tLPR ACTOR TYPE\tLPR ACTOR ID"
    );
    for mut candidate in store.list_discovery_candidates(
        limit.clamp(1, 500),
        config.discovery_evidence_retention,
        config.discovery_min_occurrences,
        config.discovery_min_days,
        config.discovery_min_confidence_percent,
        config.discovery_conflict_occurrences,
    )? {
        if candidate.identity_kind == "epc"
            && candidate.matched_occurrences < config.discovery_min_occurrences.max(5)
        {
            candidate.ready = false;
        }
        print_discovery_candidate(&candidate);
    }
    Ok(())
}

fn print_discovery_candidate(candidate: &DiscoveryCandidate) {
    let status = candidate.assignment_status.as_deref().unwrap_or(
        if candidate.ready && candidate.lpr_actor_type == "visitor" {
            "needs-resident"
        } else if candidate.ready {
            "ready"
        } else {
            "learning"
        },
    );
    println!(
        "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}%\t{}\t{}\t{}",
        status,
        candidate.tag_key,
        candidate.epc,
        candidate.plate,
        candidate.matched_occurrences,
        candidate.distinct_days,
        candidate.total_passages,
        candidate.confidence_percent,
        candidate.conflicting_occurrences,
        candidate.lpr_actor_type,
        candidate.lpr_actor_id,
    );
}

async fn associate_discovered(tag_key: &str, unifi_user_id: &str, apply: bool) -> Result<()> {
    let config = Config::from_env()?;
    let mut store = Store::open(&config.state_db, "manual-cli")?;
    associate_discovered_with(&config, &mut store, tag_key, unifi_user_id, apply).await
}

async fn associate_discovered_with(
    config: &Config,
    store: &mut Store,
    tag_key: &str,
    unifi_user_id: &str,
    apply: bool,
) -> Result<()> {
    let tag_key = normalize_discovery_key(tag_key)?;
    let candidate = store
        .discovery_candidate(
            &tag_key,
            config.discovery_evidence_retention,
            config.discovery_min_occurrences,
            config.discovery_min_days,
            config.discovery_min_confidence_percent,
            config.discovery_conflict_occurrences,
        )?
        .with_context(|| format!("discovered tag {tag_key} has no correlated LPR evidence"))?;
    let minimum_occurrences = if candidate.identity_kind == "epc" {
        config.discovery_min_occurrences.max(5)
    } else {
        config.discovery_min_occurrences
    };
    if !candidate.ready || candidate.matched_occurrences < minimum_occurrences {
        anyhow::bail!(
            "discovered tag {tag_key} has not met the configured occurrence, day, confidence, and conflict thresholds"
        );
    }
    if candidate.lpr_actor_type != "visitor" {
        anyhow::bail!(
            "discovered tag {tag_key} is backed by a {} actor and does not require visitor association",
            candidate.lpr_actor_type
        );
    }
    let unifi = UnifiClient::new(config)?;
    let user = unifi.validate_claim_user(unifi_user_id).await?;
    println!(
        "{}: tag {} / EPC {} / plate {} / visitor {} -> user {} ({})",
        if apply { "applying" } else { "dry-run" },
        candidate.tag_key,
        candidate.epc,
        candidate.plate,
        candidate.lpr_actor_id,
        user.display_name(),
        user.id,
    );
    if !apply {
        println!("no changes made; re-run with --apply to persist this association");
        return Ok(());
    }
    store.activate_discovered_tag(
        &candidate,
        &user.id,
        &user.display_name(),
        config.discovery_lease,
    )?;
    println!(
        "associated discovered tag {} with {}",
        candidate.tag_key,
        user.display_name()
    );
    Ok(())
}

fn revoke_learned(tag_key: &str) -> Result<()> {
    let tag_key = normalize_discovery_key(tag_key)?;
    let mut store = Store::open(&state_db_path(), "manual-cli")?;
    store.revoke_discovered_tag(&tag_key)?;
    println!("revoked learned tag {tag_key}");
    Ok(())
}

fn reset_learned(tag_key: &str) -> Result<()> {
    let tag_key = normalize_discovery_key(tag_key)?;
    let mut store = Store::open(&state_db_path(), "manual-cli")?;
    store.reset_suspended_discovery(&tag_key)?;
    println!("cleared suspended evidence for {tag_key}; it can now relearn");
    Ok(())
}

fn normalize_discovery_key(value: &str) -> Result<String> {
    let value = value.trim();
    if value
        .get(..4)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("EPC:"))
    {
        return Ok(format!(
            "EPC:{}",
            normalize_hex(&value[4..], None, "EPC discovery key")?
        ));
    }
    normalize_hex(value, None, "TID discovery key")
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
    use fcr_rfid_encoder::store::now_ms;

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
            preset_reuse_only: false,
            antenna_port: 1,
            transmit_power_cdbm: 3000,
            rf_mode: 4,
            state_db: db,
            actor: "test".into(),
            health_enabled: false,
            health_stale_after: Duration::from_secs(120),
            web_bind: "127.0.0.1:8080".parse().unwrap(),
            discovery_mode: DiscoveryMode::Disabled,
            discovery_match_window: Duration::from_secs(10),
            discovery_poll: Duration::from_secs(2),
            discovery_passage_gap: Duration::from_secs(30),
            discovery_max_dwell: Duration::from_secs(120),
            discovery_min_rssi_cdbm: -6000,
            discovery_min_occurrences: 3,
            discovery_min_days: 2,
            discovery_min_confidence_percent: 80,
            discovery_conflict_occurrences: 2,
            discovery_evidence_retention: Duration::from_secs(60 * 86_400),
            discovery_lease: Duration::from_secs(60 * 86_400),
            gate_mode,
            gate_unlock_cooldown: Duration::from_secs(30),
            unifi_base_url: Some(unifi_base_url),
            unifi_api_key: Some("test-token".into()),
            unifi_verify_tls: false,
            unifi_ca_certificate: None,
            entry_gate_door_id: DOOR_ID.into(),
        }
    }

    fn discovered_tid(tag_key: &str, epc: &str) -> DiscoveryObservation {
        DiscoveryObservation {
            tag_key: tag_key.into(),
            identity_kind: "tid",
            tid: Some(tag_key.into()),
            epc: epc.into(),
            antenna_port: 1,
            peak_rssi_cdbm: -4200,
            observed_at_ms: now_ms(),
        }
    }

    fn lpr_hit(timestamp: DateTime<Utc>, plate: &str, result: &str) -> Value {
        lpr_hit_for_actor(timestamp, plate, result, "user", USER_ID)
    }

    fn lpr_hit_for_actor(
        timestamp: DateTime<Utc>,
        plate: &str,
        result: &str,
        actor_type: &str,
        actor_id: &str,
    ) -> Value {
        json!({
            "@timestamp": timestamp.to_rfc3339(),
            "_source": {
                "actor": if result == "ACCESS" {
                    json!({"type": actor_type, "id": actor_id})
                } else {
                    json!({"type": "", "id": ""})
                },
                "authentication": {
                    "credential_provider": "LICENSEPLATE",
                    "issuer": plate
                },
                "event": {"result": result},
                "target": [
                    {"type": "door", "id": DOOR_ID},
                    {"type": "device_config", "display_name": "entry"}
                ]
            }
        })
    }

    fn record_ready_discovery_candidate(
        store: &mut Store,
        tag_key: &str,
        identity_kind: &'static str,
        epc: &str,
        actor_type: &str,
        actor_id: &str,
    ) {
        let at = now_ms() - 1_000;
        let seen = store
            .record_discovery_seen(
                tag_key,
                identity_kind,
                (identity_kind == "tid").then_some(tag_key),
                epc,
                -4200,
                at,
                Duration::from_secs(30),
                Duration::from_secs(120),
                Duration::from_secs(60 * 86_400),
            )
            .unwrap();
        store
            .record_discovery_match(seen.passage_id, at, "ABC123", actor_type, actor_id)
            .unwrap();
    }

    fn assigned_tag(store: &mut Store) -> DiscoveryObservation {
        let observation = discovered_tid("E2801111", "300833B2DDD9014000000000");
        record_ready_discovery_candidate(
            store,
            &observation.tag_key,
            observation.identity_kind,
            &observation.epc,
            "user",
            USER_ID,
        );
        let candidate = store
            .discovery_candidate(
                &observation.tag_key,
                Duration::from_secs(60 * 86_400),
                1,
                1,
                100,
                2,
            )
            .unwrap()
            .unwrap();
        store
            .activate_discovered_tag(
                &candidate,
                USER_ID,
                "Example User",
                Duration::from_secs(60 * 86_400),
            )
            .unwrap();
        observation
    }

    #[test]
    fn associate_discovered_accepts_explicit_dry_run_and_rejects_both_modes() {
        let dry_run = Cli::try_parse_from([
            "fcr-rfid-encoder",
            "associate-discovered",
            "E2801111",
            USER_ID,
            "--dry-run",
        ])
        .unwrap();
        assert!(matches!(
            dry_run.command,
            Some(Command::AssociateDiscovered {
                dry_run: true,
                apply: false,
                ..
            })
        ));
        assert!(
            Cli::try_parse_from([
                "fcr-rfid-encoder",
                "associate-discovered",
                "E2801111",
                USER_ID,
                "--dry-run",
                "--apply",
            ])
            .is_err()
        );
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
            discovery_last_attempts: HashMap::new(),
            discovery_retry_attempts: HashMap::new(),
            discovery_lpr_cache: None,
        };

        maybe_unlock_gate_identity(
            &dry_run,
            &mut gate,
            &mut store,
            &observation.tag_key,
            &observation.epc,
        )
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
            discovery_last_attempts: HashMap::new(),
            discovery_retry_attempts: HashMap::new(),
            discovery_lpr_cache: None,
        };
        maybe_unlock_gate_identity(
            &live,
            &mut live_gate,
            &mut store,
            &observation.tag_key,
            &observation.epc,
        )
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
            discovery_last_attempts: HashMap::new(),
            discovery_retry_attempts: HashMap::new(),
            discovery_lpr_cache: None,
        };

        maybe_unlock_gate_identity(
            &config,
            &mut gate,
            &mut store,
            &observation.tag_key,
            &observation.epc,
        )
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
    async fn multi_visit_discovery_activates_an_existing_tag_without_redundant_unlock() {
        let (base_url, counts, server) = mock_unifi(true).await;
        let directory = tempdir().unwrap();
        let db = directory.path().join("state.sqlite3");
        let mut config = test_config(db.clone(), base_url, GateMode::Live);
        config.discovery_mode = DiscoveryMode::Live;
        config.discovery_min_occurrences = 1;
        config.discovery_min_days = 1;
        config.discovery_min_confidence_percent = 100;
        config.discovery_poll = Duration::from_millis(1);
        *counts.lpr_hits.lock().unwrap() = vec![lpr_hit(
            Utc::now() - chrono::Duration::milliseconds(100),
            "ABC123",
            "ACCESS",
        )];
        let mut store = Store::open(&db, "gate-auto").unwrap();
        let observation = discovered_tid("E2809999", "11223344556677889900AABB");
        let mut gate = GateRuntime {
            unifi: Some(UnifiClient::new(&config).unwrap()),
            last_attempts: HashMap::new(),
            discovery_last_attempts: HashMap::new(),
            discovery_retry_attempts: HashMap::new(),
            discovery_lpr_cache: None,
        };

        maybe_learn_discovered_tag(&config, &mut gate, &mut store, &observation)
            .await
            .unwrap();
        let assignment = store
            .learned_assignment(&observation.tag_key)
            .unwrap()
            .unwrap();
        assert_eq!(assignment.status, "active");
        assert_eq!(assignment.plate, "ABC123");
        assert_eq!(assignment.owner.unifi_user_id, USER_ID);

        maybe_unlock_gate_identity(
            &config,
            &mut gate,
            &mut store,
            &observation.tag_key,
            &observation.epc,
        )
        .await
        .unwrap();
        assert_eq!(counts.lpr_reads.load(Ordering::SeqCst), 1);
        assert_eq!(counts.unlocks.load(Ordering::SeqCst), 0);
        server.abort();
    }

    #[tokio::test]
    async fn discovery_dry_run_records_a_ready_candidate_without_assigning_it() {
        let (base_url, counts, server) = mock_unifi(true).await;
        let directory = tempdir().unwrap();
        let db = directory.path().join("state.sqlite3");
        let mut config = test_config(db.clone(), base_url, GateMode::Disabled);
        config.discovery_mode = DiscoveryMode::DryRun;
        config.discovery_min_occurrences = 1;
        config.discovery_min_days = 1;
        config.discovery_min_confidence_percent = 100;
        config.discovery_poll = Duration::from_millis(1);
        *counts.lpr_hits.lock().unwrap() = vec![lpr_hit(
            Utc::now() - chrono::Duration::milliseconds(100),
            "ABC123",
            "ACCESS",
        )];
        let mut store = Store::open(&db, "gate-auto").unwrap();
        let observation = discovered_tid("E280AAAA", "A1223344556677889900AABB");
        let mut gate = GateRuntime {
            unifi: Some(UnifiClient::new(&config).unwrap()),
            last_attempts: HashMap::new(),
            discovery_last_attempts: HashMap::new(),
            discovery_retry_attempts: HashMap::new(),
            discovery_lpr_cache: None,
        };

        maybe_learn_discovered_tag(&config, &mut gate, &mut store, &observation)
            .await
            .unwrap();

        assert!(
            store
                .discovery_candidate(
                    &observation.tag_key,
                    config.discovery_evidence_retention,
                    1,
                    1,
                    100,
                    2,
                )
                .unwrap()
                .unwrap()
                .ready
        );
        assert!(
            store
                .learned_assignment(&observation.tag_key)
                .unwrap()
                .is_none()
        );
        assert_eq!(counts.user_reads.load(Ordering::SeqCst), 1);
        assert_eq!(counts.unlocks.load(Ordering::SeqCst), 0);
        server.abort();
    }

    #[tokio::test]
    async fn visitor_lpr_discovery_records_evidence_without_validating_or_assigning_a_user() {
        let (base_url, counts, server) = mock_unifi(true).await;
        let directory = tempdir().unwrap();
        let db = directory.path().join("state.sqlite3");
        let mut config = test_config(db.clone(), base_url, GateMode::Disabled);
        config.discovery_mode = DiscoveryMode::DryRun;
        config.discovery_min_occurrences = 1;
        config.discovery_min_days = 1;
        config.discovery_min_confidence_percent = 100;
        config.discovery_poll = Duration::from_millis(1);
        let visitor_id = "27d2f099-99df-429b-becb-1399a6937e5b";
        *counts.lpr_hits.lock().unwrap() = vec![lpr_hit_for_actor(
            Utc::now() - chrono::Duration::milliseconds(100),
            "ABC123",
            "ACCESS",
            "visitor",
            visitor_id,
        )];
        let mut store = Store::open(&db, "gate-auto").unwrap();
        let observation = discovered_tid("E280AAAB", "A2223344556677889900AABB");
        let mut gate = GateRuntime {
            unifi: Some(UnifiClient::new(&config).unwrap()),
            last_attempts: HashMap::new(),
            discovery_last_attempts: HashMap::new(),
            discovery_retry_attempts: HashMap::new(),
            discovery_lpr_cache: None,
        };

        maybe_learn_discovered_tag(&config, &mut gate, &mut store, &observation)
            .await
            .unwrap();

        let candidate = store
            .discovery_candidate(
                &observation.tag_key,
                config.discovery_evidence_retention,
                1,
                1,
                100,
                2,
            )
            .unwrap()
            .unwrap();
        assert!(candidate.ready);
        assert_eq!(candidate.lpr_actor_type, "visitor");
        assert_eq!(candidate.lpr_actor_id, visitor_id);
        assert!(
            store
                .learned_assignment(&observation.tag_key)
                .unwrap()
                .is_none()
        );
        assert_eq!(counts.user_reads.load(Ordering::SeqCst), 0);
        assert_eq!(counts.unlocks.load(Ordering::SeqCst), 0);
        server.abort();
    }

    #[tokio::test]
    async fn delayed_retry_recovers_an_lpr_event_published_after_the_reader_event() {
        let (base_url, counts, server) = mock_unifi(true).await;
        let directory = tempdir().unwrap();
        let db = directory.path().join("state.sqlite3");
        let mut config = test_config(db.clone(), base_url, GateMode::Disabled);
        config.discovery_mode = DiscoveryMode::DryRun;
        config.discovery_min_occurrences = 1;
        config.discovery_min_days = 1;
        config.discovery_min_confidence_percent = 100;
        config.discovery_poll = Duration::from_millis(1);
        let visitor_id = "27d2f099-99df-429b-becb-1399a6937e5b";
        let mut store = Store::open(&db, "gate-auto").unwrap();
        let mut observation = discovered_tid("E280AAAF", "A6223344556677889900AABB");
        observation.observed_at_ms =
            now_ms() - i64::try_from(DISCOVERY_LPR_RETRY_DELAY.as_millis()).unwrap() - 1_000;
        let mut gate = GateRuntime {
            unifi: Some(UnifiClient::new(&config).unwrap()),
            last_attempts: HashMap::new(),
            discovery_last_attempts: HashMap::new(),
            discovery_retry_attempts: HashMap::new(),
            discovery_lpr_cache: None,
        };

        maybe_learn_discovered_tag(&config, &mut gate, &mut store, &observation)
            .await
            .unwrap();
        assert_eq!(counts.lpr_reads.load(Ordering::SeqCst), 1);
        assert!(
            store
                .discovery_candidate(
                    &observation.tag_key,
                    config.discovery_evidence_retention,
                    1,
                    1,
                    100,
                    2,
                )
                .unwrap()
                .is_none()
        );

        let lpr_timestamp =
            DateTime::<Utc>::from_timestamp_millis(observation.observed_at_ms + 1_000).unwrap();
        *counts.lpr_hits.lock().unwrap() = vec![lpr_hit_for_actor(
            lpr_timestamp,
            "LATE123",
            "ACCESS",
            "visitor",
            visitor_id,
        )];
        tokio::time::sleep(Duration::from_millis(2)).await;
        let mut restarted_gate = GateRuntime {
            unifi: Some(UnifiClient::new(&config).unwrap()),
            last_attempts: HashMap::new(),
            discovery_last_attempts: HashMap::new(),
            discovery_retry_attempts: HashMap::new(),
            discovery_lpr_cache: None,
        };
        retry_pending_discovery_matches(&config, &mut restarted_gate, &mut store)
            .await
            .unwrap();

        let candidate = store
            .discovery_candidate(
                &observation.tag_key,
                config.discovery_evidence_retention,
                1,
                1,
                100,
                2,
            )
            .unwrap()
            .unwrap();
        assert!(candidate.ready);
        assert_eq!(candidate.plate, "LATE123");
        assert_eq!(candidate.lpr_actor_type, "visitor");
        assert_eq!(candidate.lpr_actor_id, visitor_id);
        assert_eq!(counts.lpr_reads.load(Ordering::SeqCst), 2);

        retry_pending_discovery_matches(&config, &mut restarted_gate, &mut store)
            .await
            .unwrap();
        assert_eq!(counts.lpr_reads.load(Ordering::SeqCst), 2);
        server.abort();
    }

    #[tokio::test]
    async fn associate_discovered_dry_run_does_not_write_and_apply_assigns_the_user() {
        let (base_url, counts, server) = mock_unifi(true).await;
        let directory = tempdir().unwrap();
        let db = directory.path().join("state.sqlite3");
        let mut config = test_config(db.clone(), base_url, GateMode::Disabled);
        config.discovery_min_occurrences = 1;
        config.discovery_min_days = 1;
        config.discovery_min_confidence_percent = 100;
        let visitor_id = "27d2f099-99df-429b-becb-1399a6937e5b";
        let mut store = Store::open(&db, "manual-cli").unwrap();
        record_ready_discovery_candidate(
            &mut store,
            "E280AAAC",
            "tid",
            "A3223344556677889900AABB",
            "visitor",
            visitor_id,
        );

        associate_discovered_with(&config, &mut store, "E280AAAC", USER_ID, false)
            .await
            .unwrap();
        assert!(store.learned_assignment("E280AAAC").unwrap().is_none());

        associate_discovered_with(&config, &mut store, "E280AAAC", USER_ID, true)
            .await
            .unwrap();
        let assignment = store.learned_assignment("E280AAAC").unwrap().unwrap();
        assert_eq!(assignment.owner.unifi_user_id, USER_ID);
        assert_eq!(assignment.lpr_actor_type, "visitor");
        assert_eq!(assignment.lpr_actor_id, visitor_id);
        assert_eq!(counts.user_reads.load(Ordering::SeqCst), 2);
        assert_eq!(counts.unlocks.load(Ordering::SeqCst), 0);
        server.abort();
    }

    #[tokio::test]
    async fn associate_discovered_rejects_user_backed_and_weak_epc_candidates() {
        let (base_url, counts, server) = mock_unifi(true).await;
        let directory = tempdir().unwrap();
        let db = directory.path().join("state.sqlite3");
        let mut config = test_config(db.clone(), base_url, GateMode::Disabled);
        config.discovery_min_occurrences = 1;
        config.discovery_min_days = 1;
        config.discovery_min_confidence_percent = 100;
        let visitor_id = "27d2f099-99df-429b-becb-1399a6937e5b";
        let mut store = Store::open(&db, "manual-cli").unwrap();
        record_ready_discovery_candidate(
            &mut store,
            "E280AAAD",
            "tid",
            "A4223344556677889900AABB",
            "user",
            USER_ID,
        );
        let user_error = associate_discovered_with(&config, &mut store, "E280AAAD", USER_ID, false)
            .await
            .unwrap_err();
        assert!(
            user_error
                .to_string()
                .contains("does not require visitor association")
        );

        let epc = "A5223344556677889900AABB";
        let epc_key = format!("EPC:{epc}");
        record_ready_discovery_candidate(&mut store, &epc_key, "epc", epc, "visitor", visitor_id);
        let epc_error = associate_discovered_with(&config, &mut store, &epc_key, USER_ID, false)
            .await
            .unwrap_err();
        assert!(
            epc_error
                .to_string()
                .contains("has not met the configured occurrence")
        );
        assert_eq!(counts.user_reads.load(Ordering::SeqCst), 0);
        server.abort();
    }

    #[tokio::test]
    async fn multiple_tags_in_one_vehicle_share_one_lpr_read_and_learn_independently() {
        let (base_url, counts, server) = mock_unifi(true).await;
        let directory = tempdir().unwrap();
        let db = directory.path().join("state.sqlite3");
        let mut config = test_config(db.clone(), base_url, GateMode::Live);
        config.discovery_mode = DiscoveryMode::Live;
        config.discovery_min_occurrences = 1;
        config.discovery_min_days = 1;
        config.discovery_min_confidence_percent = 100;
        config.discovery_poll = Duration::from_secs(1);
        *counts.lpr_hits.lock().unwrap() = vec![lpr_hit(
            Utc::now() - chrono::Duration::milliseconds(100),
            "ABC123",
            "ACCESS",
        )];
        let mut store = Store::open(&db, "gate-auto").unwrap();
        let observations = [
            discovered_tid("E280BBBB", "B1223344556677889900AABB"),
            discovered_tid("E280CCCC", "C1223344556677889900AABB"),
        ];
        let mut gate = GateRuntime {
            unifi: Some(UnifiClient::new(&config).unwrap()),
            last_attempts: HashMap::new(),
            discovery_last_attempts: HashMap::new(),
            discovery_retry_attempts: HashMap::new(),
            discovery_lpr_cache: None,
        };

        for observation in &observations {
            maybe_learn_discovered_tag(&config, &mut gate, &mut store, observation)
                .await
                .unwrap();
        }

        for observation in &observations {
            let assignment = store
                .learned_assignment(&observation.tag_key)
                .unwrap()
                .unwrap();
            assert_eq!(assignment.status, "active");
            assert_eq!(assignment.plate, "ABC123");
            assert_eq!(assignment.owner.unifi_user_id, USER_ID);
        }
        assert_eq!(counts.lpr_reads.load(Ordering::SeqCst), 1);
        assert_eq!(counts.unlocks.load(Ordering::SeqCst), 0);
        server.abort();
    }

    #[tokio::test]
    async fn buffered_reader_event_cannot_reuse_a_current_lpr_match() {
        let (base_url, counts, server) = mock_unifi(true).await;
        let directory = tempdir().unwrap();
        let db = directory.path().join("state.sqlite3");
        let mut config = test_config(db.clone(), base_url, GateMode::Disabled);
        config.discovery_mode = DiscoveryMode::Live;
        config.discovery_min_occurrences = 1;
        config.discovery_min_days = 1;
        config.discovery_min_confidence_percent = 100;
        config.discovery_poll = Duration::from_secs(1);
        *counts.lpr_hits.lock().unwrap() = vec![lpr_hit(
            Utc::now() - chrono::Duration::milliseconds(100),
            "ABC123",
            "ACCESS",
        )];
        let mut store = Store::open(&db, "gate-auto").unwrap();
        let current = discovered_tid("E280DDDD", "D1223344556677889900AABB");
        let mut buffered = discovered_tid("E280EEEE", "E1223344556677889900AABB");
        buffered.observed_at_ms -= 86_400_000;
        let mut gate = GateRuntime {
            unifi: Some(UnifiClient::new(&config).unwrap()),
            last_attempts: HashMap::new(),
            discovery_last_attempts: HashMap::new(),
            discovery_retry_attempts: HashMap::new(),
            discovery_lpr_cache: None,
        };

        maybe_learn_discovered_tag(&config, &mut gate, &mut store, &current)
            .await
            .unwrap();
        maybe_learn_discovered_tag(&config, &mut gate, &mut store, &buffered)
            .await
            .unwrap();

        assert!(
            store
                .learned_assignment(&current.tag_key)
                .unwrap()
                .is_some()
        );
        assert!(
            store
                .learned_assignment(&buffered.tag_key)
                .unwrap()
                .is_none()
        );
        assert_eq!(counts.lpr_reads.load(Ordering::SeqCst), 2);
        server.abort();
    }

    #[tokio::test]
    async fn later_ambiguity_in_the_same_passage_suspends_a_learned_tag() {
        let (base_url, counts, server) = mock_unifi(true).await;
        let directory = tempdir().unwrap();
        let db = directory.path().join("state.sqlite3");
        let mut config = test_config(db.clone(), base_url, GateMode::Disabled);
        config.discovery_mode = DiscoveryMode::Live;
        config.discovery_min_occurrences = 1;
        config.discovery_min_days = 1;
        config.discovery_min_confidence_percent = 100;
        config.discovery_poll = Duration::from_millis(1);
        let first_lpr = Utc::now() - chrono::Duration::milliseconds(100);
        *counts.lpr_hits.lock().unwrap() = vec![lpr_hit(first_lpr, "ABC123", "ACCESS")];
        let mut store = Store::open(&db, "gate-auto").unwrap();
        let mut observation = discovered_tid("E280FFFF", "F1223344556677889900AABB");
        let mut gate = GateRuntime {
            unifi: Some(UnifiClient::new(&config).unwrap()),
            last_attempts: HashMap::new(),
            discovery_last_attempts: HashMap::new(),
            discovery_retry_attempts: HashMap::new(),
            discovery_lpr_cache: None,
        };

        maybe_learn_discovered_tag(&config, &mut gate, &mut store, &observation)
            .await
            .unwrap();
        assert_eq!(
            store
                .learned_assignment(&observation.tag_key)
                .unwrap()
                .unwrap()
                .status,
            "active"
        );

        tokio::time::sleep(Duration::from_millis(2)).await;
        observation.observed_at_ms = now_ms();
        let second_lpr =
            DateTime::<Utc>::from_timestamp_millis(observation.observed_at_ms).unwrap();
        counts
            .lpr_hits
            .lock()
            .unwrap()
            .push(lpr_hit(second_lpr, "XYZ789", "BLOCKED"));
        maybe_learn_discovered_tag(&config, &mut gate, &mut store, &observation)
            .await
            .unwrap();

        assert_eq!(
            store
                .learned_assignment(&observation.tag_key)
                .unwrap()
                .unwrap()
                .status,
            "suspended"
        );
        server.abort();
    }
}

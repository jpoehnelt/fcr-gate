use std::{
    collections::{HashMap, HashSet},
    path::Path,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, SecondsFormat, Utc};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde::Serialize;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Encoding {
    pub sequence: u32,
    pub tid: String,
    pub assigned_epc: String,
    pub status: String,
    pub attempts: u32,
    pub retry_after_ms: i64,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TagOwner {
    pub unifi_user_id: String,
    pub unifi_user_name: String,
    pub vehicle_description: Option<String>,
    pub assigned_at: String,
    pub assigned_by: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TagRecord {
    pub sequence: u32,
    pub tid: String,
    pub epc: String,
    pub encoding_status: String,
    pub ownership_status: String,
    pub owner: Option<TagOwner>,
    pub last_seen_at: Option<String>,
    pub last_seen_ms: Option<i64>,
    pub last_rssi_cdbm: Option<i32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GateEvent {
    pub timestamp: String,
    pub tid: String,
    pub epc: String,
    pub unifi_user_id: Option<String>,
    pub mode: String,
    pub decision: String,
    pub detail: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoverySeen {
    pub passage_id: i64,
    pub correlation_status: String,
    pub long_dwell: bool,
    pub became_long_dwell: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PassageMatchOutcome {
    Recorded,
    Duplicate,
    Ambiguous,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DiscoveryCandidate {
    pub tag_key: String,
    pub identity_kind: String,
    pub tid: Option<String>,
    pub epc: String,
    pub plate: String,
    pub unifi_user_id: String,
    pub matched_occurrences: u32,
    pub distinct_days: u32,
    pub total_passages: u32,
    pub confidence_percent: u8,
    pub conflicting_occurrences: u32,
    pub last_match_ms: i64,
    pub ready: bool,
    pub assignment_status: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LearnedTagAssignment {
    pub owner: TagOwner,
    pub plate: String,
    pub status: String,
    pub lease_expires_ms: i64,
}

impl Encoding {
    pub fn may_attempt(&self, now_ms: i64, max_attempts: u32) -> bool {
        matches!(self.status.as_str(), "pending" | "repair")
            && self.attempts < max_attempts
            && now_ms >= self.retry_after_ms
    }
}

pub struct Store {
    connection: Connection,
    actor: String,
}

impl Store {
    pub fn open(path: &Path, actor: impl Into<String>) -> Result<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).with_context(|| {
                    format!("failed to create state directory {}", parent.display())
                })?;
            }
        }
        let connection = Connection::open(path)
            .with_context(|| format!("failed to open state database {}", path.display()))?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=FULL;
             PRAGMA foreign_keys=ON;
             CREATE TABLE IF NOT EXISTS allocator (
                 id INTEGER PRIMARY KEY CHECK (id = 1),
                 next_sequence INTEGER NOT NULL CHECK (next_sequence > 0)
             );
             INSERT OR IGNORE INTO allocator (id, next_sequence) VALUES (1, 1);
             CREATE TABLE IF NOT EXISTS encodings (
                 sequence INTEGER PRIMARY KEY,
                 tid TEXT NOT NULL UNIQUE,
                 assigned_epc TEXT NOT NULL UNIQUE,
                 status TEXT NOT NULL CHECK (
                     status IN ('pending', 'repair', 'queued', 'verified', 'completed', 'failed', 'conflict')
                 ),
                 attempts INTEGER NOT NULL DEFAULT 0,
                 retry_after_ms INTEGER NOT NULL DEFAULT 0,
                 last_error TEXT,
                 created_at TEXT NOT NULL,
                 updated_at TEXT NOT NULL,
                 completed_at TEXT
             );
             CREATE TABLE IF NOT EXISTS audit_log (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 timestamp TEXT NOT NULL,
                 actor TEXT NOT NULL,
                 kind TEXT NOT NULL,
                 tid TEXT,
                 epc TEXT,
                 detail TEXT
             );
             CREATE INDEX IF NOT EXISTS audit_log_timestamp ON audit_log(timestamp);
             CREATE TABLE IF NOT EXISTS tag_ownership (
                 tid TEXT PRIMARY KEY REFERENCES encodings(tid) ON DELETE CASCADE,
                 unifi_user_id TEXT NOT NULL,
                 unifi_user_name TEXT NOT NULL,
                 status TEXT NOT NULL CHECK (status IN ('active', 'revoked', 'lost')),
                 vehicle_description TEXT,
                 assigned_at TEXT NOT NULL,
                 assigned_by TEXT NOT NULL,
                 updated_at TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS tag_ownership_user
                 ON tag_ownership(unifi_user_id, status);
             CREATE TABLE IF NOT EXISTS tag_observations (
                 tid TEXT PRIMARY KEY REFERENCES encodings(tid) ON DELETE CASCADE,
                 epc TEXT NOT NULL,
                 last_seen_at TEXT NOT NULL,
                 last_seen_ms INTEGER NOT NULL,
                 last_rssi_cdbm INTEGER NOT NULL
             );
             CREATE INDEX IF NOT EXISTS tag_observations_last_seen
                 ON tag_observations(last_seen_ms DESC);
             CREATE TABLE IF NOT EXISTS lpr_correlation_state (
                 tid TEXT PRIMARY KEY REFERENCES encodings(tid) ON DELETE CASCADE,
                 not_before_ms INTEGER NOT NULL,
                 updated_at TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS discovery_tags (
                 tag_key TEXT PRIMARY KEY,
                 identity_kind TEXT NOT NULL CHECK (identity_kind IN ('tid', 'epc')),
                 tid TEXT,
                 epc TEXT NOT NULL,
                 first_seen_ms INTEGER NOT NULL,
                 last_seen_ms INTEGER NOT NULL,
                 last_seen_at TEXT NOT NULL,
                 last_rssi_cdbm INTEGER NOT NULL,
                 session_started_ms INTEGER NOT NULL,
                 current_passage_id INTEGER,
                 last_candidate_audit_occurrences INTEGER NOT NULL DEFAULT 0
             );
             CREATE INDEX IF NOT EXISTS discovery_tags_last_seen
                 ON discovery_tags(last_seen_ms DESC);
             CREATE TABLE IF NOT EXISTS discovery_passages (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 tag_key TEXT NOT NULL REFERENCES discovery_tags(tag_key) ON DELETE CASCADE,
                 started_at_ms INTEGER NOT NULL,
                 last_seen_ms INTEGER NOT NULL,
                 epc TEXT NOT NULL,
                 peak_rssi_cdbm INTEGER NOT NULL,
                 stationary INTEGER NOT NULL DEFAULT 0 CHECK (stationary IN (0, 1)),
                 correlation_status TEXT NOT NULL DEFAULT 'pending' CHECK (
                     correlation_status IN ('pending', 'matched', 'ambiguous')
                 ),
                 lpr_event_ms INTEGER,
                 plate TEXT,
                 unifi_user_id TEXT
             );
             CREATE INDEX IF NOT EXISTS discovery_passages_tag_time
                 ON discovery_passages(tag_key, started_at_ms DESC);
             CREATE TABLE IF NOT EXISTS learned_tag_ownership (
                 tag_key TEXT PRIMARY KEY REFERENCES discovery_tags(tag_key) ON DELETE CASCADE,
                 unifi_user_id TEXT NOT NULL,
                 unifi_user_name TEXT NOT NULL,
                 plate TEXT NOT NULL,
                 status TEXT NOT NULL CHECK (status IN ('active', 'suspended', 'revoked')),
                 vehicle_description TEXT,
                 assigned_at TEXT NOT NULL,
                 assigned_by TEXT NOT NULL,
                 lease_expires_ms INTEGER NOT NULL,
                 updated_at TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS learned_tag_ownership_user
                 ON learned_tag_ownership(unifi_user_id, status);
             CREATE TABLE IF NOT EXISTS gate_events (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 timestamp TEXT NOT NULL,
                 tid TEXT NOT NULL,
                 epc TEXT NOT NULL,
                 unifi_user_id TEXT,
                 mode TEXT NOT NULL DEFAULT 'live' CHECK (
                     mode IN ('dry-run', 'live')
                 ),
                 decision TEXT NOT NULL CHECK (
                     decision IN ('granted', 'denied', 'error', 'disabled')
                 ),
                 detail TEXT
             );
             CREATE INDEX IF NOT EXISTS gate_events_timestamp
                 ON gate_events(timestamp DESC);",
        )?;
        ensure_gate_event_mode(&connection)?;
        Ok(Self {
            connection,
            actor: actor.into(),
        })
    }

    pub fn recover_interrupted(&mut self) -> Result<usize> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = transaction.execute(
            "UPDATE encodings
             SET status = 'pending', updated_at = ?1,
                 last_error = 'service restarted before completion'
             WHERE status IN ('queued', 'verified')",
            [timestamp()],
        )?;
        if changed > 0 {
            let detail = format!("returned {changed} interrupted encoding(s) to pending");
            audit_tx(
                &transaction,
                &self.actor,
                "recovery",
                None,
                None,
                Some(&detail),
            )?;
        }
        transaction.commit()?;
        Ok(changed)
    }

    pub fn health_check(&self) -> Result<()> {
        let next_sequence: i64 = self.connection.query_row(
            "SELECT next_sequence FROM allocator WHERE id = 1",
            [],
            |row| row.get(0),
        )?;
        if next_sequence <= 0 {
            bail!("RFID allocator is invalid");
        }
        Ok(())
    }

    pub fn get_by_tid(&self, tid: &str) -> Result<Option<Encoding>> {
        self.connection
            .query_row(
                "SELECT sequence, tid, assigned_epc, status, attempts, retry_after_ms, last_error
                 FROM encodings WHERE tid = ?1",
                [tid],
                row_to_encoding,
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn record_seen(&mut self, tid: &str, epc: &str, rssi_cdbm: i32) -> Result<()> {
        let now_ms = now_ms();
        self.connection.execute(
            "INSERT INTO tag_observations
                 (tid, epc, last_seen_at, last_seen_ms, last_rssi_cdbm)
             SELECT tid, assigned_epc, ?1, ?2, ?3
             FROM encodings
             WHERE tid = ?4 AND assigned_epc = ?5 AND status = 'completed'
             ON CONFLICT(tid) DO UPDATE SET
                 epc = excluded.epc,
                 last_seen_at = excluded.last_seen_at,
                 last_seen_ms = excluded.last_seen_ms,
                 last_rssi_cdbm = excluded.last_rssi_cdbm
             WHERE excluded.last_seen_ms - tag_observations.last_seen_ms >= 1000",
            params![timestamp(), now_ms, rssi_cdbm, tid, epc],
        )?;
        Ok(())
    }

    pub fn get_active_owner(&self, tid: &str) -> Result<Option<TagOwner>> {
        self.connection
            .query_row(
                "SELECT unifi_user_id, unifi_user_name, vehicle_description,
                        assigned_at, assigned_by
                 FROM tag_ownership
                 WHERE tid = ?1 AND status = 'active'",
                [tid],
                row_to_owner,
            )
            .optional()
            .map_err(Into::into)
    }

    /// Return recently observed, completed tags that have never had an owner.
    /// Revoked and lost tags are deliberately excluded from automatic assignment.
    pub fn recent_never_assigned_tids(&self, window: Duration) -> Result<Vec<String>> {
        let cutoff = now_ms().saturating_sub(duration_ms(window));
        let mut statement = self.connection.prepare(
            "SELECT e.tid
             FROM encodings e
             JOIN tag_observations obs ON obs.tid = e.tid
             LEFT JOIN tag_ownership own ON own.tid = e.tid
             WHERE e.status = 'completed'
               AND obs.last_seen_ms >= ?1
               AND own.tid IS NULL
             ORDER BY obs.last_seen_ms DESC, e.sequence DESC",
        )?;
        let rows = statement.query_map([cutoff], |row| row.get(0))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    pub fn lpr_correlation_not_before_ms(&self, tid: &str) -> Result<Option<i64>> {
        self.connection
            .query_row(
                "SELECT not_before_ms FROM lpr_correlation_state WHERE tid = ?1",
                [tid],
                |row| row.get(0),
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn advance_lpr_correlation_not_before(
        &mut self,
        tid: &str,
        not_before_ms: i64,
    ) -> Result<()> {
        self.connection.execute(
            "INSERT INTO lpr_correlation_state (tid, not_before_ms, updated_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(tid) DO UPDATE SET
                 not_before_ms = MAX(lpr_correlation_state.not_before_ms, excluded.not_before_ms),
                 updated_at = excluded.updated_at",
            params![tid, not_before_ms, timestamp()],
        )?;
        Ok(())
    }

    pub fn record_lpr_correlation_audit(
        &mut self,
        tid: &str,
        epc: &str,
        kind: &str,
        detail: &str,
    ) -> Result<()> {
        if !matches!(
            kind,
            "lpr-correlation-dry-run" | "lpr-correlation-ambiguous"
        ) {
            bail!("invalid LPR correlation audit kind {kind}");
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        audit_tx(
            &transaction,
            &self.actor,
            kind,
            Some(tid),
            Some(epc),
            Some(detail),
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn has_encoding_epc(&self, epc: &str) -> Result<bool> {
        self.connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM encodings WHERE assigned_epc = ?1)",
                [epc],
                |row| row.get(0),
            )
            .map_err(Into::into)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_discovery_seen(
        &mut self,
        tag_key: &str,
        identity_kind: &str,
        tid: Option<&str>,
        epc: &str,
        rssi_cdbm: i32,
        observed_at_ms: i64,
        passage_gap: Duration,
        max_dwell: Duration,
        evidence_retention: Duration,
    ) -> Result<DiscoverySeen> {
        validate_tag_key(tag_key)?;
        if !matches!(identity_kind, "tid" | "epc") {
            bail!("invalid discovery identity kind {identity_kind}");
        }
        validate_hex(epc, "discovered EPC")?;
        if let Some(tid) = tid {
            validate_hex(tid, "discovered TID")?;
        }
        let seen_at = timestamp_from_ms(observed_at_ms)?;
        let gap_ms = duration_ms(passage_gap);
        let max_dwell_ms = duration_ms(max_dwell);
        let retention_cutoff = observed_at_ms.saturating_sub(duration_ms(evidence_retention));
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: Option<(i64, i64, Option<i64>)> = transaction
            .query_row(
                "SELECT last_seen_ms, session_started_ms, current_passage_id
                 FROM discovery_tags WHERE tag_key = ?1",
                [tag_key],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;

        let new_passage = existing.is_none_or(|(last_seen_ms, _, current)| {
            current.is_none() || observed_at_ms.saturating_sub(last_seen_ms) > gap_ms
        });
        let (passage_id, session_started_ms, was_stationary) = if new_passage {
            transaction.execute(
                "INSERT INTO discovery_tags
                     (tag_key, identity_kind, tid, epc, first_seen_ms, last_seen_ms,
                      last_seen_at, last_rssi_cdbm, session_started_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?6, ?7, ?5)
                 ON CONFLICT(tag_key) DO UPDATE SET
                     identity_kind = excluded.identity_kind,
                     tid = COALESCE(excluded.tid, discovery_tags.tid),
                     epc = excluded.epc,
                     last_seen_ms = excluded.last_seen_ms,
                     last_seen_at = excluded.last_seen_at,
                     last_rssi_cdbm = excluded.last_rssi_cdbm,
                     session_started_ms = excluded.session_started_ms",
                params![
                    tag_key,
                    identity_kind,
                    tid,
                    epc,
                    observed_at_ms,
                    seen_at,
                    rssi_cdbm
                ],
            )?;
            transaction.execute(
                "INSERT INTO discovery_passages
                     (tag_key, started_at_ms, last_seen_ms, epc, peak_rssi_cdbm)
                 VALUES (?1, ?2, ?2, ?3, ?4)",
                params![tag_key, observed_at_ms, epc, rssi_cdbm],
            )?;
            let passage_id = transaction.last_insert_rowid();
            transaction.execute(
                "UPDATE discovery_tags SET current_passage_id = ?1 WHERE tag_key = ?2",
                params![passage_id, tag_key],
            )?;
            (passage_id, observed_at_ms, false)
        } else {
            let (_, session_started_ms, current_passage_id) = existing.expect("checked above");
            let passage_id = current_passage_id.context("discovery passage disappeared")?;
            let was_stationary: bool = transaction.query_row(
                "SELECT stationary FROM discovery_passages WHERE id = ?1",
                [passage_id],
                |row| row.get(0),
            )?;
            (passage_id, session_started_ms, was_stationary)
        };

        let long_dwell = observed_at_ms.saturating_sub(session_started_ms) >= max_dwell_ms;
        transaction.execute(
            "UPDATE discovery_tags SET
                 identity_kind = ?1, tid = COALESCE(?2, tid), epc = ?3,
                 last_seen_ms = MAX(last_seen_ms, ?4), last_seen_at = ?5,
                 last_rssi_cdbm = ?6
             WHERE tag_key = ?7",
            params![
                identity_kind,
                tid,
                epc,
                observed_at_ms,
                seen_at,
                rssi_cdbm,
                tag_key
            ],
        )?;
        transaction.execute(
            "UPDATE discovery_passages SET
                 last_seen_ms = MAX(last_seen_ms, ?1), epc = ?2,
                 peak_rssi_cdbm = MAX(peak_rssi_cdbm, ?3),
                 stationary = MAX(stationary, ?4)
             WHERE id = ?5",
            params![
                observed_at_ms,
                epc,
                rssi_cdbm,
                i64::from(long_dwell),
                passage_id
            ],
        )?;
        transaction.execute(
            "UPDATE discovery_tags SET current_passage_id = NULL
             WHERE last_seen_ms < ?1 AND current_passage_id IN (
                 SELECT id FROM discovery_passages WHERE started_at_ms < ?1
             )",
            [retention_cutoff],
        )?;
        transaction.execute(
            "DELETE FROM discovery_passages
             WHERE started_at_ms < ?1
               AND id NOT IN (
                   SELECT current_passage_id FROM discovery_tags
                   WHERE current_passage_id IS NOT NULL
               )",
            [retention_cutoff],
        )?;
        let correlation_status: String = transaction.query_row(
            "SELECT correlation_status FROM discovery_passages WHERE id = ?1",
            [passage_id],
            |row| row.get(0),
        )?;
        transaction.commit()?;
        Ok(DiscoverySeen {
            passage_id,
            correlation_status,
            long_dwell,
            became_long_dwell: long_dwell && !was_stationary,
        })
    }

    pub fn mark_discovery_passage_ambiguous(&mut self, passage_id: i64) -> Result<bool> {
        let changed = self.connection.execute(
            "UPDATE discovery_passages SET correlation_status = 'ambiguous',
                 lpr_event_ms = NULL, plate = NULL, unifi_user_id = NULL
             WHERE id = ?1 AND correlation_status IN ('pending', 'matched')",
            [passage_id],
        )?;
        Ok(changed > 0)
    }

    pub fn record_discovery_match(
        &mut self,
        passage_id: i64,
        lpr_event_ms: i64,
        plate: &str,
        unifi_user_id: &str,
    ) -> Result<PassageMatchOutcome> {
        validate_text(plate, 64, "license plate")?;
        validate_text(unifi_user_id, 128, "UniFi user ID")?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: (String, Option<i64>, Option<String>, Option<String>) = transaction
            .query_row(
                "SELECT correlation_status, lpr_event_ms, plate, unifi_user_id
                 FROM discovery_passages WHERE id = ?1 AND stationary = 0",
                [passage_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .with_context(|| format!("unknown or stationary discovery passage {passage_id}"))?;
        let outcome = match existing.0.as_str() {
            "pending" => {
                transaction.execute(
                    "UPDATE discovery_passages SET correlation_status = 'matched',
                         lpr_event_ms = ?1, plate = ?2, unifi_user_id = ?3
                     WHERE id = ?4",
                    params![lpr_event_ms, plate, unifi_user_id, passage_id],
                )?;
                PassageMatchOutcome::Recorded
            }
            "matched"
                if existing.1 == Some(lpr_event_ms)
                    && existing.2.as_deref() == Some(plate)
                    && existing.3.as_deref() == Some(unifi_user_id) =>
            {
                PassageMatchOutcome::Duplicate
            }
            "matched" => {
                transaction.execute(
                    "UPDATE discovery_passages SET correlation_status = 'ambiguous',
                         lpr_event_ms = NULL, plate = NULL, unifi_user_id = NULL
                     WHERE id = ?1",
                    [passage_id],
                )?;
                PassageMatchOutcome::Ambiguous
            }
            "ambiguous" => PassageMatchOutcome::Duplicate,
            status => bail!("invalid discovery passage status {status}"),
        };
        transaction.commit()?;
        Ok(outcome)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn discovery_candidate(
        &self,
        tag_key: &str,
        evidence_retention: Duration,
        min_occurrences: u32,
        min_days: u32,
        min_confidence_percent: u8,
        conflict_occurrences: u32,
    ) -> Result<Option<DiscoveryCandidate>> {
        let tag: Option<(String, Option<String>, String, Option<i64>)> = self
            .connection
            .query_row(
                "SELECT identity_kind, tid, epc, current_passage_id
                 FROM discovery_tags WHERE tag_key = ?1",
                [tag_key],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        let Some((identity_kind, tid, epc, current_passage_id)) = tag else {
            return Ok(None);
        };
        let current_long_dwell = current_passage_id
            .map(|passage_id| {
                self.connection.query_row(
                    "SELECT stationary FROM discovery_passages WHERE id = ?1",
                    [passage_id],
                    |row| row.get::<_, bool>(0),
                )
            })
            .transpose()?
            .unwrap_or(false);
        let cutoff = now_ms().saturating_sub(duration_ms(evidence_retention));
        let mut statement = self.connection.prepare(
            "SELECT correlation_status, lpr_event_ms, plate, unifi_user_id
             FROM discovery_passages
             WHERE tag_key = ?1 AND started_at_ms >= ?2 AND stationary = 0",
        )?;
        let rows = statement.query_map(params![tag_key, cutoff], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<i64>>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, Option<String>>(3)?,
            ))
        })?;
        let passages = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        drop(statement);
        let total_passages = u32::try_from(passages.len()).unwrap_or(u32::MAX);
        if total_passages == 0 {
            return Ok(None);
        }

        let mut groups: HashMap<(String, String), (u32, HashSet<i64>, i64)> = HashMap::new();
        for (status, event_ms, plate, user_id) in passages {
            if status != "matched" {
                continue;
            }
            let (Some(event_ms), Some(plate), Some(user_id)) = (event_ms, plate, user_id) else {
                continue;
            };
            let entry = groups
                .entry((plate, user_id))
                .or_insert_with(|| (0, HashSet::new(), event_ms));
            entry.0 = entry.0.saturating_add(1);
            entry.1.insert(event_ms.div_euclid(86_400_000));
            entry.2 = entry.2.max(event_ms);
        }
        if groups.is_empty() {
            return Ok(None);
        }
        let mut ranked = groups.into_iter().collect::<Vec<_>>();
        ranked.sort_by(|left, right| {
            right
                .1
                .0
                .cmp(&left.1.0)
                .then_with(|| right.1.2.cmp(&left.1.2))
                .then_with(|| left.0.cmp(&right.0))
        });
        let ((plate, unifi_user_id), (matched_occurrences, days, last_match_ms)) = ranked.remove(0);
        let conflicting_occurrences = ranked
            .iter()
            .map(|(_, (count, _, _))| *count)
            .max()
            .unwrap_or(0);
        let confidence_percent = u8::try_from(
            u64::from(matched_occurrences)
                .saturating_mul(100)
                .checked_div(u64::from(total_passages))
                .unwrap_or(0),
        )
        .unwrap_or(100);
        let distinct_days = u32::try_from(days.len()).unwrap_or(u32::MAX);
        let ready = !current_long_dwell
            && matched_occurrences >= min_occurrences
            && distinct_days >= min_days
            && confidence_percent >= min_confidence_percent
            && conflicting_occurrences < conflict_occurrences;
        let assignment_status = self.learned_assignment(tag_key)?.map(|assignment| {
            if assignment.status == "active" && assignment.lease_expires_ms <= now_ms() {
                "expired".into()
            } else {
                assignment.status
            }
        });
        Ok(Some(DiscoveryCandidate {
            tag_key: tag_key.into(),
            identity_kind,
            tid,
            epc,
            plate,
            unifi_user_id,
            matched_occurrences,
            distinct_days,
            total_passages,
            confidence_percent,
            conflicting_occurrences,
            last_match_ms,
            ready,
            assignment_status,
        }))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn list_discovery_candidates(
        &self,
        limit: usize,
        evidence_retention: Duration,
        min_occurrences: u32,
        min_days: u32,
        min_confidence_percent: u8,
        conflict_occurrences: u32,
    ) -> Result<Vec<DiscoveryCandidate>> {
        let mut statement = self
            .connection
            .prepare("SELECT tag_key FROM discovery_tags ORDER BY last_seen_ms DESC LIMIT ?1")?;
        let keys = statement
            .query_map([limit as i64], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(statement);
        let mut candidates = Vec::new();
        for key in keys {
            if let Some(candidate) = self.discovery_candidate(
                &key,
                evidence_retention,
                min_occurrences,
                min_days,
                min_confidence_percent,
                conflict_occurrences,
            )? {
                candidates.push(candidate);
            }
        }
        Ok(candidates)
    }

    pub fn learned_assignment(&self, tag_key: &str) -> Result<Option<LearnedTagAssignment>> {
        self.connection
            .query_row(
                "SELECT unifi_user_id, unifi_user_name, vehicle_description,
                        assigned_at, assigned_by, plate, status, lease_expires_ms
                 FROM learned_tag_ownership WHERE tag_key = ?1",
                [tag_key],
                |row| {
                    Ok(LearnedTagAssignment {
                        owner: TagOwner {
                            unifi_user_id: row.get(0)?,
                            unifi_user_name: row.get(1)?,
                            vehicle_description: row.get(2)?,
                            assigned_at: row.get(3)?,
                            assigned_by: row.get(4)?,
                        },
                        plate: row.get(5)?,
                        status: row.get(6)?,
                        lease_expires_ms: row.get(7)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn get_gate_owner(&self, tag_key: &str) -> Result<Option<TagOwner>> {
        if let Some(owner) = self.get_active_owner(tag_key)? {
            return Ok(Some(owner));
        }
        Ok(self
            .learned_assignment(tag_key)?
            .filter(|assignment| {
                assignment.status == "active" && assignment.lease_expires_ms > now_ms()
            })
            .map(|assignment| assignment.owner))
    }

    pub fn activate_discovered_tag(
        &mut self,
        candidate: &DiscoveryCandidate,
        unifi_user_name: &str,
        lease: Duration,
    ) -> Result<TagOwner> {
        validate_text(unifi_user_name, 200, "UniFi user name")?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let exists: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM discovery_tags WHERE tag_key = ?1)",
            [&candidate.tag_key],
            |row| row.get(0),
        )?;
        if !exists {
            bail!("unknown discovered tag {}", candidate.tag_key);
        }
        let existing: Option<(String, String, String)> = transaction
            .query_row(
                "SELECT status, unifi_user_id, plate
                 FROM learned_tag_ownership WHERE tag_key = ?1",
                [&candidate.tag_key],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        if let Some((status, user_id, plate)) = existing {
            if status == "active" && user_id == candidate.unifi_user_id && plate == candidate.plate
            {
                transaction.commit()?;
                return self
                    .get_gate_owner(&candidate.tag_key)?
                    .context("active learned owner disappeared");
            }
            bail!(
                "discovered tag {} already has a {status} assignment; review it before reassignment",
                candidate.tag_key
            );
        }
        let now = timestamp();
        let expires_ms = now_ms().saturating_add(duration_ms(lease));
        let vehicle = format!("Learned from license plate {}", candidate.plate);
        transaction.execute(
            "INSERT INTO learned_tag_ownership
                 (tag_key, unifi_user_id, unifi_user_name, plate, status,
                  vehicle_description, assigned_at, assigned_by, lease_expires_ms, updated_at)
             VALUES (?1, ?2, ?3, ?4, 'active', ?5, ?6, ?7, ?8, ?6)",
            params![
                candidate.tag_key,
                candidate.unifi_user_id,
                unifi_user_name,
                candidate.plate,
                vehicle,
                now,
                self.actor,
                expires_ms
            ],
        )?;
        let detail = serde_json::json!({
            "source": "multi-visit-lpr",
            "unifi_user_id": candidate.unifi_user_id,
            "unifi_user_name": unifi_user_name,
            "plate": candidate.plate,
            "matched_occurrences": candidate.matched_occurrences,
            "distinct_days": candidate.distinct_days,
            "confidence_percent": candidate.confidence_percent,
            "lease_expires_ms": expires_ms,
        })
        .to_string();
        audit_tx(
            &transaction,
            &self.actor,
            "discovery-tag-assigned",
            Some(&candidate.tag_key),
            Some(&candidate.epc),
            Some(&detail),
        )?;
        transaction.commit()?;
        self.get_gate_owner(&candidate.tag_key)?
            .context("learned tag owner disappeared")
    }

    pub fn renew_discovered_lease(
        &mut self,
        tag_key: &str,
        unifi_user_id: &str,
        plate: &str,
        lease: Duration,
    ) -> Result<bool> {
        let expires_ms = now_ms().saturating_add(duration_ms(lease));
        let changed = self.connection.execute(
            "UPDATE learned_tag_ownership SET lease_expires_ms = ?1, updated_at = ?2
             WHERE tag_key = ?3 AND status = 'active'
               AND unifi_user_id = ?4 AND plate = ?5",
            params![expires_ms, timestamp(), tag_key, unifi_user_id, plate],
        )?;
        Ok(changed > 0)
    }

    pub fn count_discovery_conflicts(
        &self,
        tag_key: &str,
        unifi_user_id: &str,
        plate: &str,
        evidence_retention: Duration,
    ) -> Result<u32> {
        let cutoff = now_ms().saturating_sub(duration_ms(evidence_retention));
        let count: i64 = self.connection.query_row(
            "SELECT COUNT(*) FROM discovery_passages
             WHERE tag_key = ?1 AND started_at_ms >= ?2 AND stationary = 0
               AND correlation_status = 'matched'
               AND (unifi_user_id != ?3 OR plate != ?4)",
            params![tag_key, cutoff, unifi_user_id, plate],
            |row| row.get(0),
        )?;
        Ok(u32::try_from(count).unwrap_or(u32::MAX))
    }

    pub fn suspend_discovered_tag(&mut self, tag_key: &str, reason: &str) -> Result<bool> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = transaction.execute(
            "UPDATE learned_tag_ownership SET status = 'suspended', updated_at = ?1
             WHERE tag_key = ?2 AND status = 'active'",
            params![timestamp(), tag_key],
        )?;
        if changed > 0 {
            audit_tx(
                &transaction,
                &self.actor,
                "discovery-tag-suspended",
                Some(tag_key),
                None,
                Some(reason),
            )?;
        }
        transaction.commit()?;
        Ok(changed > 0)
    }

    pub fn revoke_discovered_tag(&mut self, tag_key: &str) -> Result<()> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = transaction.execute(
            "UPDATE learned_tag_ownership SET status = 'revoked', updated_at = ?1
             WHERE tag_key = ?2 AND status IN ('active', 'suspended')",
            params![timestamp(), tag_key],
        )?;
        if changed == 0 {
            bail!("discovered tag {tag_key} has no active or suspended assignment");
        }
        audit_tx(
            &transaction,
            &self.actor,
            "discovery-tag-revoked",
            Some(tag_key),
            None,
            None,
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn reset_suspended_discovery(&mut self, tag_key: &str) -> Result<()> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let status: String = transaction
            .query_row(
                "SELECT status FROM learned_tag_ownership WHERE tag_key = ?1",
                [tag_key],
                |row| row.get(0),
            )
            .with_context(|| format!("discovered tag {tag_key} has no learned assignment"))?;
        if status != "suspended" {
            bail!("discovered tag {tag_key} is {status}, not suspended");
        }
        audit_tx(
            &transaction,
            &self.actor,
            "discovery-tag-reset",
            Some(tag_key),
            None,
            Some("operator cleared suspended evidence for relearning"),
        )?;
        transaction.execute(
            "DELETE FROM learned_tag_ownership WHERE tag_key = ?1",
            [tag_key],
        )?;
        transaction.execute(
            "DELETE FROM discovery_passages WHERE tag_key = ?1",
            [tag_key],
        )?;
        transaction.execute(
            "UPDATE discovery_tags SET current_passage_id = NULL,
                 last_candidate_audit_occurrences = 0
             WHERE tag_key = ?1",
            [tag_key],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn record_discovery_candidate_audit(
        &mut self,
        candidate: &DiscoveryCandidate,
    ) -> Result<bool> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = transaction.execute(
            "UPDATE discovery_tags SET last_candidate_audit_occurrences = ?1
             WHERE tag_key = ?2 AND last_candidate_audit_occurrences < ?1",
            params![candidate.matched_occurrences, candidate.tag_key],
        )?;
        if changed > 0 {
            let detail = serde_json::json!({
                "plate": candidate.plate,
                "unifi_user_id": candidate.unifi_user_id,
                "matched_occurrences": candidate.matched_occurrences,
                "distinct_days": candidate.distinct_days,
                "total_passages": candidate.total_passages,
                "confidence_percent": candidate.confidence_percent,
            })
            .to_string();
            audit_tx(
                &transaction,
                &self.actor,
                "discovery-candidate-dry-run",
                Some(&candidate.tag_key),
                Some(&candidate.epc),
                Some(&detail),
            )?;
        }
        transaction.commit()?;
        Ok(changed > 0)
    }

    pub fn list_tags(&self, limit: usize) -> Result<Vec<TagRecord>> {
        let mut statement = self.connection.prepare(
            "SELECT e.sequence, e.tid, e.assigned_epc, e.status,
                    COALESCE(own.status, 'unassigned'),
                    own.unifi_user_id, own.unifi_user_name, own.vehicle_description,
                    own.assigned_at, own.assigned_by,
                    obs.last_seen_at, obs.last_seen_ms, obs.last_rssi_cdbm
             FROM encodings e
             LEFT JOIN tag_ownership own ON own.tid = e.tid
             LEFT JOIN tag_observations obs ON obs.tid = e.tid
             WHERE e.status = 'completed'
             ORDER BY (obs.last_seen_ms IS NULL), obs.last_seen_ms DESC, e.sequence DESC
             LIMIT ?1",
        )?;
        let rows = statement.query_map([limit as i64], row_to_tag_record)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    pub fn claim_tag(
        &mut self,
        tid: &str,
        unifi_user_id: &str,
        unifi_user_name: &str,
        vehicle_description: Option<&str>,
        claim_window: Duration,
    ) -> Result<TagOwner> {
        validate_text(unifi_user_id, 128, "UniFi user ID")?;
        validate_text(unifi_user_name, 200, "UniFi user name")?;
        if let Some(vehicle) = vehicle_description {
            validate_text(vehicle, 200, "vehicle description")?;
        }

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (encoding_status, last_seen_ms): (String, Option<i64>) = transaction
            .query_row(
                "SELECT e.status, obs.last_seen_ms
                 FROM encodings e
                 LEFT JOIN tag_observations obs ON obs.tid = e.tid
                 WHERE e.tid = ?1",
                [tid],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .with_context(|| format!("unknown TID {tid}"))?;
        if encoding_status != "completed" {
            bail!("TID {tid} has not completed encoding");
        }
        let last_seen_ms = last_seen_ms.context("tag has not been observed since encoding")?;
        let age_ms = now_ms().saturating_sub(last_seen_ms);
        if age_ms < 0 || age_ms > duration_ms(claim_window) {
            bail!("tag is no longer inside the claim window; present it to the reader again");
        }

        let existing: Option<(String, String)> = transaction
            .query_row(
                "SELECT status, unifi_user_id FROM tag_ownership WHERE tid = ?1",
                [tid],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((status, existing_user)) = existing {
            if status == "active" {
                if existing_user == unifi_user_id {
                    transaction.commit()?;
                    return self
                        .get_active_owner(tid)?
                        .context("active tag owner disappeared");
                }
                bail!("tag is already actively assigned; revoke it before transferring ownership");
            }
        }

        let now = timestamp();
        let vehicle = vehicle_description
            .map(str::trim)
            .filter(|value| !value.is_empty());
        transaction.execute(
            "INSERT INTO tag_ownership
                 (tid, unifi_user_id, unifi_user_name, status, vehicle_description,
                  assigned_at, assigned_by, updated_at)
             VALUES (?1, ?2, ?3, 'active', ?4, ?5, ?6, ?5)
             ON CONFLICT(tid) DO UPDATE SET
                 unifi_user_id = excluded.unifi_user_id,
                 unifi_user_name = excluded.unifi_user_name,
                 status = 'active',
                 vehicle_description = excluded.vehicle_description,
                 assigned_at = excluded.assigned_at,
                 assigned_by = excluded.assigned_by,
                 updated_at = excluded.updated_at",
            params![
                tid,
                unifi_user_id,
                unifi_user_name,
                vehicle,
                now,
                self.actor
            ],
        )?;
        let detail = serde_json::json!({
            "unifi_user_id": unifi_user_id,
            "unifi_user_name": unifi_user_name,
            "vehicle_description": vehicle,
        })
        .to_string();
        audit_tx(
            &transaction,
            &self.actor,
            "tag-assigned",
            Some(tid),
            None,
            Some(&detail),
        )?;
        transaction.commit()?;
        self.get_active_owner(tid)?
            .context("assigned tag owner disappeared")
    }

    pub fn revoke_tag(&mut self, tid: &str) -> Result<()> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let now = timestamp();
        let changed = transaction.execute(
            "UPDATE tag_ownership
             SET status = 'revoked', updated_at = ?1
             WHERE tid = ?2 AND status = 'active'",
            params![now, tid],
        )?;
        if changed == 0 {
            bail!("TID {tid} does not have an active assignment");
        }
        audit_tx(
            &transaction,
            &self.actor,
            "tag-revoked",
            Some(tid),
            None,
            None,
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn record_gate_decision(
        &mut self,
        tid: &str,
        epc: &str,
        unifi_user_id: Option<&str>,
        mode: &str,
        decision: &str,
        detail: Option<&str>,
    ) -> Result<()> {
        if !matches!(mode, "dry-run" | "live") {
            bail!("invalid gate mode {mode}");
        }
        if !matches!(decision, "granted" | "denied" | "error" | "disabled") {
            bail!("invalid gate decision {decision}");
        }
        self.connection.execute(
            "INSERT INTO gate_events
                 (timestamp, tid, epc, unifi_user_id, mode, decision, detail)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![timestamp(), tid, epc, unifi_user_id, mode, decision, detail],
        )?;
        Ok(())
    }

    pub fn allocate(&mut self, tid: &str, prefix: &str) -> Result<Encoding> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) = transaction
            .query_row(
                "SELECT sequence, tid, assigned_epc, status, attempts, retry_after_ms, last_error
                 FROM encodings WHERE tid = ?1",
                [tid],
                row_to_encoding,
            )
            .optional()?
        {
            transaction.commit()?;
            return Ok(existing);
        }

        let sequence: i64 = transaction.query_row(
            "SELECT next_sequence FROM allocator WHERE id = 1",
            [],
            |row| row.get(0),
        )?;
        if sequence > i64::from(u32::MAX) {
            bail!("EPC sequence space exhausted");
        }
        let assigned_epc = format!("{prefix}{:08X}", sequence as u32);
        let now = timestamp();
        transaction.execute(
            "UPDATE allocator SET next_sequence = next_sequence + 1 WHERE id = 1",
            [],
        )?;
        transaction.execute(
            "INSERT INTO encodings
             (sequence, tid, assigned_epc, status, attempts, retry_after_ms, created_at, updated_at)
             VALUES (?1, ?2, ?3, 'pending', 0, 0, ?4, ?4)",
            params![sequence, tid, assigned_epc, now],
        )?;
        audit_tx(
            &transaction,
            &self.actor,
            "allocated",
            Some(tid),
            Some(&assigned_epc),
            None,
        )?;
        transaction.commit()?;
        self.get_by_tid(tid)?
            .context("allocated encoding disappeared")
    }

    pub fn mark_queued(&mut self, tid: &str) -> Result<()> {
        self.update_with_audit(
            "UPDATE encodings
             SET status = CASE WHEN status = 'repair' THEN 'repair' ELSE 'queued' END,
                 attempts = attempts + 1, retry_after_ms = 0,
                 last_error = NULL, updated_at = ?1 WHERE tid = ?2",
            tid,
            "write-queued",
            None,
        )
    }

    pub fn mark_post_failed(&mut self, tid: &str, error: &str, cooldown: Duration) -> Result<()> {
        let retry_after = now_ms().saturating_add(duration_ms(cooldown));
        let now = timestamp();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = transaction.execute(
            "UPDATE encodings
             SET status = CASE WHEN status = 'repair' THEN 'repair' ELSE 'pending' END,
             retry_after_ms = ?1,
             last_error = ?2, updated_at = ?3 WHERE tid = ?4",
            params![retry_after, error, now, tid],
        )?;
        ensure_changed(changed, tid)?;
        audit_tx(
            &transaction,
            &self.actor,
            "queue-failed",
            Some(tid),
            None,
            Some(error),
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn mark_access_failed(
        &mut self,
        tid: &str,
        error: &str,
        cooldown: Duration,
        max_attempts: u32,
    ) -> Result<()> {
        let encoding = self
            .get_by_tid(tid)?
            .with_context(|| format!("unknown TID {tid}"))?;
        let status = if encoding.attempts >= max_attempts {
            "failed"
        } else if encoding.status == "repair" {
            "repair"
        } else {
            "pending"
        };
        let retry_after = now_ms().saturating_add(duration_ms(cooldown));
        let now = timestamp();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = transaction.execute(
            "UPDATE encodings SET status = ?1, retry_after_ms = ?2,
             last_error = ?3, updated_at = ?4 WHERE tid = ?5",
            params![status, retry_after, error, now, tid],
        )?;
        ensure_changed(changed, tid)?;
        audit_tx(
            &transaction,
            &self.actor,
            "write-failed",
            Some(tid),
            None,
            Some(error),
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn mark_verified(&mut self, tid: &str, epc: &str) -> Result<()> {
        self.update_with_audit(
            "UPDATE encodings SET status = 'verified', last_error = NULL,
             updated_at = ?1 WHERE tid = ?2",
            tid,
            "read-back-verified",
            Some(epc),
        )
    }

    pub fn mark_completed(&mut self, tid: &str, epc: &str) -> Result<()> {
        let now = timestamp();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = transaction.execute(
            "UPDATE encodings SET status = 'completed', last_error = NULL,
             retry_after_ms = 0, updated_at = ?1, completed_at = ?1
             WHERE tid = ?2 AND assigned_epc = ?3",
            params![now, tid, epc],
        )?;
        ensure_changed(changed, tid)?;
        audit_tx(
            &transaction,
            &self.actor,
            "completed",
            Some(tid),
            Some(epc),
            None,
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn mark_conflict(&mut self, tid: &str, observed_epc: &str) -> Result<()> {
        let detail = format!("observed unexpected EPC {observed_epc}");
        let now = timestamp();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = transaction.execute(
            "UPDATE encodings SET status = 'conflict', last_error = ?1,
             updated_at = ?2 WHERE tid = ?3",
            params![detail, now, tid],
        )?;
        ensure_changed(changed, tid)?;
        audit_tx(
            &transaction,
            &self.actor,
            "conflict",
            Some(tid),
            Some(observed_epc),
            Some(&detail),
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn retry(&mut self, tid: &str) -> Result<()> {
        let now = timestamp();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = transaction.execute(
            "UPDATE encodings
             SET status = CASE WHEN status = 'conflict' THEN 'repair' ELSE 'pending' END,
             attempts = 0, retry_after_ms = 0,
             last_error = NULL, updated_at = ?1
             WHERE tid = ?2 AND status IN ('failed', 'conflict')",
            params![now, tid],
        )?;
        if changed == 0 {
            bail!("TID {tid} is not failed or conflicted");
        }
        audit_tx(
            &transaction,
            &self.actor,
            "manual-retry",
            Some(tid),
            None,
            None,
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn list(&self, limit: usize) -> Result<Vec<Encoding>> {
        let mut statement = self.connection.prepare(
            "SELECT sequence, tid, assigned_epc, status, attempts, retry_after_ms, last_error
             FROM encodings ORDER BY sequence DESC LIMIT ?1",
        )?;
        let rows = statement.query_map([limit as i64], row_to_encoding)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    pub fn list_gate_events(&self, limit: usize) -> Result<Vec<GateEvent>> {
        let mut statement = self.connection.prepare(
            "SELECT timestamp, tid, epc, unifi_user_id, mode, decision, detail
             FROM gate_events ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = statement.query_map([limit as i64], row_to_gate_event)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    fn update_with_audit(
        &mut self,
        sql: &str,
        tid: &str,
        kind: &str,
        epc: Option<&str>,
    ) -> Result<()> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = transaction.execute(sql, params![timestamp(), tid])?;
        ensure_changed(changed, tid)?;
        audit_tx(&transaction, &self.actor, kind, Some(tid), epc, None)?;
        transaction.commit()?;
        Ok(())
    }
}

fn audit_tx(
    transaction: &Transaction<'_>,
    actor: &str,
    kind: &str,
    tid: Option<&str>,
    epc: Option<&str>,
    detail: Option<&str>,
) -> Result<()> {
    transaction.execute(
        "INSERT INTO audit_log (timestamp, actor, kind, tid, epc, detail)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![timestamp(), actor, kind, tid, epc, detail],
    )?;
    Ok(())
}

fn row_to_encoding(row: &rusqlite::Row<'_>) -> rusqlite::Result<Encoding> {
    Ok(Encoding {
        sequence: row.get(0)?,
        tid: row.get(1)?,
        assigned_epc: row.get(2)?,
        status: row.get(3)?,
        attempts: row.get(4)?,
        retry_after_ms: row.get(5)?,
        last_error: row.get(6)?,
    })
}

fn row_to_owner(row: &rusqlite::Row<'_>) -> rusqlite::Result<TagOwner> {
    Ok(TagOwner {
        unifi_user_id: row.get(0)?,
        unifi_user_name: row.get(1)?,
        vehicle_description: row.get(2)?,
        assigned_at: row.get(3)?,
        assigned_by: row.get(4)?,
    })
}

fn row_to_tag_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<TagRecord> {
    let unifi_user_id: Option<String> = row.get(5)?;
    let owner = if let Some(unifi_user_id) = unifi_user_id {
        Some(TagOwner {
            unifi_user_id,
            unifi_user_name: row.get(6)?,
            vehicle_description: row.get(7)?,
            assigned_at: row.get(8)?,
            assigned_by: row.get(9)?,
        })
    } else {
        None
    };
    Ok(TagRecord {
        sequence: row.get(0)?,
        tid: row.get(1)?,
        epc: row.get(2)?,
        encoding_status: row.get(3)?,
        ownership_status: row.get(4)?,
        owner,
        last_seen_at: row.get(10)?,
        last_seen_ms: row.get(11)?,
        last_rssi_cdbm: row.get(12)?,
    })
}

fn row_to_gate_event(row: &rusqlite::Row<'_>) -> rusqlite::Result<GateEvent> {
    Ok(GateEvent {
        timestamp: row.get(0)?,
        tid: row.get(1)?,
        epc: row.get(2)?,
        unifi_user_id: row.get(3)?,
        mode: row.get(4)?,
        decision: row.get(5)?,
        detail: row.get(6)?,
    })
}

fn ensure_changed(changed: usize, tid: &str) -> Result<()> {
    if changed == 0 {
        bail!("unknown TID {tid}");
    }
    Ok(())
}

fn ensure_gate_event_mode(connection: &Connection) -> Result<()> {
    let mut statement = connection.prepare("PRAGMA table_info(gate_events)")?;
    let columns = statement.query_map([], |row| row.get::<_, String>(1))?;
    for column in columns {
        if column? == "mode" {
            return Ok(());
        }
    }
    connection.execute(
        "ALTER TABLE gate_events
         ADD COLUMN mode TEXT NOT NULL DEFAULT 'live'
         CHECK (mode IN ('dry-run', 'live'))",
        [],
    )?;
    Ok(())
}

fn validate_text(value: &str, max_length: usize, name: &str) -> Result<()> {
    let value = value.trim();
    if value.is_empty() || value.len() > max_length || value.chars().any(char::is_control) {
        bail!("{name} must contain 1 to {max_length} printable characters");
    }
    Ok(())
}

fn validate_hex(value: &str, name: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 256
        || value.len() % 2 != 0
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        bail!("{name} must contain complete hexadecimal bytes");
    }
    Ok(())
}

fn validate_tag_key(value: &str) -> Result<()> {
    if let Some(epc) = value.strip_prefix("EPC:") {
        return validate_hex(epc, "EPC discovery key");
    }
    validate_hex(value, "TID discovery key")
}

pub fn now_ms() -> i64 {
    Utc::now().timestamp_millis()
}

fn duration_ms(duration: Duration) -> i64 {
    i64::try_from(duration.as_millis()).unwrap_or(i64::MAX)
}

fn timestamp() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn timestamp_from_ms(value: i64) -> Result<String> {
    DateTime::<Utc>::from_timestamp_millis(value)
        .map(|value| value.to_rfc3339_opts(SecondsFormat::Millis, true))
        .context("discovery observation timestamp is outside the supported range")
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn allocation_is_durable_and_idempotent() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("state.sqlite3");
        let mut store = Store::open(&path, "test").unwrap();

        let first = store.allocate("E2801111", "FCA7000100000000").unwrap();
        let duplicate = store.allocate("E2801111", "FCA7000100000000").unwrap();
        let second = store.allocate("E2802222", "FCA7000100000000").unwrap();

        assert_eq!(first, duplicate);
        assert_eq!(first.assigned_epc, "FCA700010000000000000001");
        assert_eq!(second.assigned_epc, "FCA700010000000000000002");
    }

    #[test]
    fn completed_encoding_cannot_be_attempted_again() {
        let directory = tempdir().unwrap();
        let mut store = Store::open(&directory.path().join("state.sqlite3"), "test").unwrap();
        let encoding = store.allocate("E2801111", "FCA7000100000000").unwrap();
        store
            .mark_completed(&encoding.tid, &encoding.assigned_epc)
            .unwrap();

        assert!(
            !store
                .get_by_tid(&encoding.tid)
                .unwrap()
                .unwrap()
                .may_attempt(now_ms(), 3)
        );
    }

    #[test]
    fn retrying_a_conflict_authorizes_an_exact_tid_repair() {
        let directory = tempdir().unwrap();
        let mut store = Store::open(&directory.path().join("state.sqlite3"), "test").unwrap();
        let encoding = store.allocate("E2801111", "FCA7000100000000").unwrap();
        store
            .mark_conflict(&encoding.tid, "DEADBEEF0000000000000001")
            .unwrap();
        store.retry(&encoding.tid).unwrap();

        let repaired = store.get_by_tid(&encoding.tid).unwrap().unwrap();
        assert_eq!(repaired.status, "repair");
        assert!(repaired.may_attempt(now_ms(), 3));
    }

    #[test]
    fn completed_recent_tag_can_be_claimed_and_revoked() {
        let directory = tempdir().unwrap();
        let mut store =
            Store::open(&directory.path().join("state.sqlite3"), "operator@test").unwrap();
        let encoding = store.allocate("E2801111", "FCA7000100000000").unwrap();
        store
            .mark_completed(&encoding.tid, &encoding.assigned_epc)
            .unwrap();
        store
            .record_seen(&encoding.tid, &encoding.assigned_epc, -4200)
            .unwrap();

        let owner = store
            .claim_tag(
                &encoding.tid,
                "17d2f099-99df-429b-becb-1399a6937e5a",
                "Example User",
                Some("White pickup"),
                Duration::from_secs(60),
            )
            .unwrap();
        assert_eq!(owner.unifi_user_name, "Example User");
        assert_eq!(store.list_tags(10).unwrap()[0].ownership_status, "active");

        store.revoke_tag(&encoding.tid).unwrap();
        assert!(store.get_active_owner(&encoding.tid).unwrap().is_none());
        assert_eq!(store.list_tags(10).unwrap()[0].ownership_status, "revoked");
    }

    #[test]
    fn a_tag_must_be_seen_recently_before_claiming() {
        let directory = tempdir().unwrap();
        let mut store =
            Store::open(&directory.path().join("state.sqlite3"), "operator@test").unwrap();
        let encoding = store.allocate("E2801111", "FCA7000100000000").unwrap();
        store
            .mark_completed(&encoding.tid, &encoding.assigned_epc)
            .unwrap();

        let error = store
            .claim_tag(
                &encoding.tid,
                "17d2f099-99df-429b-becb-1399a6937e5a",
                "Example User",
                None,
                Duration::from_secs(60),
            )
            .unwrap_err();
        assert!(error.to_string().contains("not been observed"));
    }

    #[test]
    fn stale_observation_and_wrong_epc_cannot_be_claimed() {
        let directory = tempdir().unwrap();
        let mut store =
            Store::open(&directory.path().join("state.sqlite3"), "operator@test").unwrap();
        let encoding = store.allocate("E2801111", "FCA7000100000000").unwrap();
        store
            .mark_completed(&encoding.tid, &encoding.assigned_epc)
            .unwrap();

        store
            .record_seen(&encoding.tid, "DEADBEEF0000000000000001", -4200)
            .unwrap();
        assert!(store.list_tags(10).unwrap()[0].last_seen_ms.is_none());

        store
            .record_seen(&encoding.tid, &encoding.assigned_epc, -4200)
            .unwrap();
        store
            .connection
            .execute(
                "UPDATE tag_observations SET last_seen_ms = ?1 WHERE tid = ?2",
                params![now_ms() - 61_000, encoding.tid],
            )
            .unwrap();
        let error = store
            .claim_tag(
                &encoding.tid,
                "17d2f099-99df-429b-becb-1399a6937e5a",
                "Example User",
                None,
                Duration::from_secs(60),
            )
            .unwrap_err();
        assert!(error.to_string().contains("claim window"));
    }

    #[test]
    fn transfer_requires_revoke_and_preserves_operator_audit() {
        let directory = tempdir().unwrap();
        let mut store =
            Store::open(&directory.path().join("state.sqlite3"), "operator@test").unwrap();
        let encoding = store.allocate("E2801111", "FCA7000100000000").unwrap();
        store
            .mark_completed(&encoding.tid, &encoding.assigned_epc)
            .unwrap();
        store
            .record_seen(&encoding.tid, &encoding.assigned_epc, -4200)
            .unwrap();
        store
            .claim_tag(
                &encoding.tid,
                "17d2f099-99df-429b-becb-1399a6937e5a",
                "First User",
                None,
                Duration::from_secs(60),
            )
            .unwrap();

        let error = store
            .claim_tag(
                &encoding.tid,
                "27d2f099-99df-429b-becb-1399a6937e5b",
                "Second User",
                None,
                Duration::from_secs(60),
            )
            .unwrap_err();
        assert!(error.to_string().contains("revoke"));
        assert_eq!(
            store
                .get_active_owner(&encoding.tid)
                .unwrap()
                .unwrap()
                .unifi_user_name,
            "First User"
        );

        store.revoke_tag(&encoding.tid).unwrap();
        store
            .claim_tag(
                &encoding.tid,
                "27d2f099-99df-429b-becb-1399a6937e5b",
                "Second User",
                Some("Blue SUV"),
                Duration::from_secs(60),
            )
            .unwrap();
        let owner = store.get_active_owner(&encoding.tid).unwrap().unwrap();
        assert_eq!(owner.unifi_user_name, "Second User");
        assert_eq!(owner.vehicle_description.as_deref(), Some("Blue SUV"));

        let mut statement = store
            .connection
            .prepare(
                "SELECT actor, kind FROM audit_log
                 WHERE kind IN ('tag-assigned', 'tag-revoked') ORDER BY id",
            )
            .unwrap();
        let audit = statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(
            audit,
            vec![
                ("operator@test".into(), "tag-assigned".into()),
                ("operator@test".into(), "tag-revoked".into()),
                ("operator@test".into(), "tag-assigned".into()),
            ]
        );
    }

    #[test]
    fn automatic_correlation_only_considers_recent_never_assigned_tags() {
        let directory = tempdir().unwrap();
        let mut store = Store::open(&directory.path().join("state.sqlite3"), "test").unwrap();

        let eligible = store.allocate("E2801111", "FCA7000100000000").unwrap();
        store
            .mark_completed(&eligible.tid, &eligible.assigned_epc)
            .unwrap();
        store
            .record_seen(&eligible.tid, &eligible.assigned_epc, -4200)
            .unwrap();

        let revoked = store.allocate("E2802222", "FCA7000100000000").unwrap();
        store
            .mark_completed(&revoked.tid, &revoked.assigned_epc)
            .unwrap();
        store
            .record_seen(&revoked.tid, &revoked.assigned_epc, -4200)
            .unwrap();
        store
            .claim_tag(
                &revoked.tid,
                "17d2f099-99df-429b-becb-1399a6937e5a",
                "Example User",
                None,
                Duration::from_secs(60),
            )
            .unwrap();
        store.revoke_tag(&revoked.tid).unwrap();

        let stale = store.allocate("E2803333", "FCA7000100000000").unwrap();
        store
            .mark_completed(&stale.tid, &stale.assigned_epc)
            .unwrap();
        store
            .record_seen(&stale.tid, &stale.assigned_epc, -4200)
            .unwrap();
        store
            .connection
            .execute(
                "UPDATE tag_observations SET last_seen_ms = ?1 WHERE tid = ?2",
                params![now_ms() - 60_000, stale.tid],
            )
            .unwrap();

        assert_eq!(
            store
                .recent_never_assigned_tids(Duration::from_secs(10))
                .unwrap(),
            vec![eligible.tid]
        );
    }

    #[test]
    fn ambiguity_cutoff_is_durable_and_only_moves_forward() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("state.sqlite3");
        let mut store = Store::open(&path, "test").unwrap();
        let encoding = store.allocate("E2801111", "FCA7000100000000").unwrap();

        store
            .advance_lpr_correlation_not_before(&encoding.tid, 1_000)
            .unwrap();
        store
            .advance_lpr_correlation_not_before(&encoding.tid, 500)
            .unwrap();
        drop(store);

        let store = Store::open(&path, "test").unwrap();
        assert_eq!(
            store.lpr_correlation_not_before_ms(&encoding.tid).unwrap(),
            Some(1_000)
        );
    }

    fn discovery_seen(store: &mut Store, tag: &str, epc: &str, at_ms: i64) -> DiscoverySeen {
        store
            .record_discovery_seen(
                tag,
                "tid",
                Some(tag),
                epc,
                -4200,
                at_ms,
                Duration::from_secs(30),
                Duration::from_secs(120),
                Duration::from_secs(60 * 86_400),
            )
            .unwrap()
    }

    #[test]
    fn repeated_reads_and_lpr_events_count_once_per_passage() {
        let directory = tempdir().unwrap();
        let mut store = Store::open(&directory.path().join("state.sqlite3"), "test").unwrap();
        let tag = "E2801111";
        let epc = "11223344556677889900AABB";
        let base = now_ms() - 86_400_000;
        let first = discovery_seen(&mut store, tag, epc, base);
        let repeated = discovery_seen(&mut store, tag, epc, base + 1_000);
        assert_eq!(first.passage_id, repeated.passage_id);

        assert_eq!(
            store
                .record_discovery_match(
                    first.passage_id,
                    base + 500,
                    "ABC123",
                    "17d2f099-99df-429b-becb-1399a6937e5a",
                )
                .unwrap(),
            PassageMatchOutcome::Recorded
        );
        assert_eq!(
            store
                .record_discovery_match(
                    first.passage_id,
                    base + 500,
                    "ABC123",
                    "17d2f099-99df-429b-becb-1399a6937e5a",
                )
                .unwrap(),
            PassageMatchOutcome::Duplicate
        );
        let candidate = store
            .discovery_candidate(tag, Duration::from_secs(60 * 86_400), 1, 1, 100, 2)
            .unwrap()
            .unwrap();
        assert_eq!(candidate.total_passages, 1);
        assert_eq!(candidate.matched_occurrences, 1);
        assert_eq!(candidate.confidence_percent, 100);
    }

    #[test]
    fn candidate_requires_occurrences_days_confidence_and_no_competing_plate() {
        let directory = tempdir().unwrap();
        let mut store = Store::open(&directory.path().join("state.sqlite3"), "test").unwrap();
        let tag = "E2801111";
        let epc = "11223344556677889900AABB";
        let user = "17d2f099-99df-429b-becb-1399a6937e5a";
        let base = now_ms() - 7 * 86_400_000;

        for index in 0..4_i64 {
            let at = base + index * 86_400_000;
            let passage = discovery_seen(&mut store, tag, epc, at);
            if index < 3 {
                store
                    .record_discovery_match(passage.passage_id, at, "ABC123", user)
                    .unwrap();
            }
        }
        let below_confidence = store
            .discovery_candidate(tag, Duration::from_secs(60 * 86_400), 3, 2, 80, 2)
            .unwrap()
            .unwrap();
        assert_eq!(below_confidence.confidence_percent, 75);
        assert!(!below_confidence.ready);

        let fifth_at = base + 4 * 86_400_000;
        let fifth = discovery_seen(&mut store, tag, epc, fifth_at);
        store
            .record_discovery_match(fifth.passage_id, fifth_at, "ABC123", user)
            .unwrap();
        let ready = store
            .discovery_candidate(tag, Duration::from_secs(60 * 86_400), 3, 2, 80, 2)
            .unwrap()
            .unwrap();
        assert_eq!(ready.matched_occurrences, 4);
        assert_eq!(ready.total_passages, 5);
        assert_eq!(ready.confidence_percent, 80);
        assert!(ready.ready);

        for offset in [5_i64, 6] {
            let at = base + offset * 86_400_000;
            let passage = discovery_seen(&mut store, tag, epc, at);
            store
                .record_discovery_match(
                    passage.passage_id,
                    at,
                    "XYZ789",
                    "27d2f099-99df-429b-becb-1399a6937e5b",
                )
                .unwrap();
        }
        let conflicted = store
            .discovery_candidate(tag, Duration::from_secs(60 * 86_400), 3, 2, 50, 2)
            .unwrap()
            .unwrap();
        assert_eq!(conflicted.conflicting_occurrences, 2);
        assert!(!conflicted.ready);
    }

    #[test]
    fn long_dwell_and_two_matches_in_one_passage_fail_closed() {
        let directory = tempdir().unwrap();
        let mut store = Store::open(&directory.path().join("state.sqlite3"), "test").unwrap();
        let tag = "E2801111";
        let epc = "11223344556677889900AABB";
        let base = now_ms() - 300_000;
        let passage = discovery_seen(&mut store, tag, epc, base);
        store
            .record_discovery_match(
                passage.passage_id,
                base,
                "ABC123",
                "17d2f099-99df-429b-becb-1399a6937e5a",
            )
            .unwrap();
        assert_eq!(
            store
                .record_discovery_match(
                    passage.passage_id,
                    base + 1_000,
                    "XYZ789",
                    "27d2f099-99df-429b-becb-1399a6937e5b",
                )
                .unwrap(),
            PassageMatchOutcome::Ambiguous
        );
        assert!(
            store
                .discovery_candidate(tag, Duration::from_secs(60 * 86_400), 1, 1, 1, 2)
                .unwrap()
                .is_none()
        );

        let dwell = store
            .record_discovery_seen(
                tag,
                "tid",
                Some(tag),
                epc,
                -4200,
                base + 120_000,
                Duration::from_secs(30),
                Duration::from_secs(120),
                Duration::from_secs(60 * 86_400),
            )
            .unwrap();
        // The 120-second observation is a new passage because it exceeds the
        // 30-second passage gap; a continuous dwell is tested below.
        assert!(!dwell.long_dwell);
        let continuous = store
            .record_discovery_seen(
                tag,
                "tid",
                Some(tag),
                epc,
                -4200,
                base + 240_000,
                Duration::from_secs(300),
                Duration::from_secs(120),
                Duration::from_secs(60 * 86_400),
            )
            .unwrap();
        assert!(continuous.long_dwell);
        assert!(continuous.became_long_dwell);
    }

    #[test]
    fn learned_assignment_renews_suspends_and_revokes() {
        let directory = tempdir().unwrap();
        let mut store = Store::open(&directory.path().join("state.sqlite3"), "gate-auto").unwrap();
        let tag = "E2801111";
        let epc = "11223344556677889900AABB";
        let user = "17d2f099-99df-429b-becb-1399a6937e5a";
        let at = now_ms() - 1_000;
        let passage = discovery_seen(&mut store, tag, epc, at);
        store
            .record_discovery_match(passage.passage_id, at, "ABC123", user)
            .unwrap();
        let candidate = store
            .discovery_candidate(tag, Duration::from_secs(60 * 86_400), 1, 1, 100, 2)
            .unwrap()
            .unwrap();
        store
            .activate_discovered_tag(&candidate, "Example User", Duration::from_secs(60))
            .unwrap();
        assert_eq!(
            store.get_gate_owner(tag).unwrap().unwrap().unifi_user_id,
            user
        );
        assert!(
            store
                .renew_discovered_lease(tag, user, "ABC123", Duration::from_secs(120))
                .unwrap()
        );
        assert!(
            store
                .suspend_discovered_tag(tag, "conflicting vehicle evidence")
                .unwrap()
        );
        assert!(store.get_gate_owner(tag).unwrap().is_none());
        store.reset_suspended_discovery(tag).unwrap();
        assert!(store.learned_assignment(tag).unwrap().is_none());

        let relearned_at = now_ms();
        let relearned = discovery_seen(&mut store, tag, epc, relearned_at);
        store
            .record_discovery_match(relearned.passage_id, relearned_at, "ABC123", user)
            .unwrap();
        let candidate = store
            .discovery_candidate(tag, Duration::from_secs(60 * 86_400), 1, 1, 100, 2)
            .unwrap()
            .unwrap();
        store
            .activate_discovered_tag(&candidate, "Example User", Duration::from_secs(60))
            .unwrap();
        store.revoke_discovered_tag(tag).unwrap();
        assert_eq!(
            store.learned_assignment(tag).unwrap().unwrap().status,
            "revoked"
        );
    }

    #[test]
    fn legacy_gate_events_are_migrated_for_dry_run_decisions() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("state.sqlite3");
        let legacy = Connection::open(&path).unwrap();
        legacy
            .execute_batch(
                "CREATE TABLE gate_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    tid TEXT NOT NULL,
                    epc TEXT NOT NULL,
                    unifi_user_id TEXT,
                    decision TEXT NOT NULL CHECK (
                        decision IN ('granted', 'denied', 'error', 'disabled')
                    ),
                    detail TEXT
                );",
            )
            .unwrap();
        drop(legacy);

        let mut store = Store::open(&path, "test").unwrap();
        store
            .record_gate_decision(
                "E2801111",
                "FCA700010000000000000001",
                Some("user-id"),
                "dry-run",
                "granted",
                Some("Gate policy"),
            )
            .unwrap();
        let result: (String, String) = store
            .connection
            .query_row("SELECT mode, decision FROM gate_events", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .unwrap();
        assert_eq!(result, ("dry-run".into(), "granted".into()));
    }
}

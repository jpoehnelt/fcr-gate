use std::{
    collections::{HashMap, HashSet},
    path::Path,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, SecondsFormat, Utc};
use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};
use serde::Serialize;

use crate::plate::{canonical_plate_key, same_plate_family};

type DiscoveryIdentityKey = (String, String, String);

struct DiscoveryEvidence {
    plate: String,
    matched_occurrences: u32,
    days: HashSet<i64>,
    last_match_ms: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TagOwner {
    pub unifi_user_id: String,
    pub unifi_user_name: String,
    pub vehicle_description: Option<String>,
    pub assigned_at: String,
    pub assigned_by: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GateEvent {
    pub timestamp: String,
    pub tag_key: String,
    pub epc: String,
    pub unifi_user_id: Option<String>,
    pub mode: String,
    pub decision: String,
    pub detail: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoverySeen {
    pub passage_id: i64,
    pub new_passage: bool,
    pub started_at_ms: i64,
    pub last_seen_ms: i64,
    pub correlation_status: String,
    pub long_dwell: bool,
    pub became_long_dwell: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingDiscoveryPassage {
    pub passage_id: i64,
    pub tag_key: String,
    pub identity_kind: String,
    pub tid: Option<String>,
    pub epc: String,
    pub peak_rssi_cdbm: i32,
    pub started_at_ms: i64,
    pub last_seen_ms: i64,
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
    pub lpr_actor_type: String,
    pub lpr_actor_id: String,
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
    pub lpr_actor_type: String,
    pub lpr_actor_id: String,
    pub status: String,
    pub lease_expires_ms: i64,
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
                 lpr_actor_id TEXT,
                 lpr_actor_type TEXT NOT NULL DEFAULT 'user'
                     CHECK (lpr_actor_type IN ('user', 'visitor'))
             );
             CREATE INDEX IF NOT EXISTS discovery_passages_tag_time
                 ON discovery_passages(tag_key, started_at_ms DESC);
             CREATE INDEX IF NOT EXISTS discovery_passages_pending_retry
                 ON discovery_passages(correlation_status, stationary, last_seen_ms);
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
                 updated_at TEXT NOT NULL,
                 lpr_actor_type TEXT NOT NULL DEFAULT 'user'
                     CHECK (lpr_actor_type IN ('user', 'visitor')),
                 lpr_actor_id TEXT
             );
             CREATE INDEX IF NOT EXISTS learned_tag_ownership_user
                 ON learned_tag_ownership(unifi_user_id, status);
             CREATE TABLE IF NOT EXISTS gate_events (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 timestamp TEXT NOT NULL,
                 tag_key TEXT NOT NULL,
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
        ensure_gate_event_tag_key(&connection)?;
        ensure_gate_event_mode(&connection)?;
        ensure_lpr_actor_columns(&connection)?;
        Ok(Self {
            connection,
            actor: actor.into(),
        })
    }

    pub fn health_check_path(path: &Path) -> Result<()> {
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .with_context(|| format!("failed to open state database {} read-only", path.display()))?;
        connection.query_row("SELECT 1", [], |_| Ok(()))?;
        Ok(())
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
            new_passage,
            started_at_ms: session_started_ms,
            last_seen_ms: observed_at_ms,
            correlation_status,
            long_dwell,
            became_long_dwell: long_dwell && !was_stationary,
        })
    }

    pub fn mark_discovery_passage_ambiguous(&mut self, passage_id: i64) -> Result<bool> {
        let changed = self.connection.execute(
            "UPDATE discovery_passages SET correlation_status = 'ambiguous',
                 lpr_event_ms = NULL, plate = NULL, lpr_actor_id = NULL,
                 lpr_actor_type = 'user'
             WHERE id = ?1 AND correlation_status IN ('pending', 'matched')",
            [passage_id],
        )?;
        Ok(changed > 0)
    }

    pub fn pending_discovery_passages(
        &self,
        retry_before_ms: i64,
        cutoff_ms: i64,
        limit: usize,
    ) -> Result<Vec<PendingDiscoveryPassage>> {
        let mut statement = self.connection.prepare(
            "SELECT p.id, p.tag_key, t.identity_kind, t.tid, p.epc,
                    p.peak_rssi_cdbm, p.started_at_ms, p.last_seen_ms
             FROM discovery_passages p
             JOIN discovery_tags t ON t.tag_key = p.tag_key
             WHERE p.correlation_status = 'pending'
               AND p.stationary = 0
               AND p.last_seen_ms <= ?1
               AND p.last_seen_ms >= ?2
             ORDER BY p.last_seen_ms, p.id
             LIMIT ?3",
        )?;
        let rows = statement.query_map(
            params![
                retry_before_ms,
                cutoff_ms,
                i64::try_from(limit).unwrap_or(i64::MAX)
            ],
            |row| {
                Ok(PendingDiscoveryPassage {
                    passage_id: row.get(0)?,
                    tag_key: row.get(1)?,
                    identity_kind: row.get(2)?,
                    tid: row.get(3)?,
                    epc: row.get(4)?,
                    peak_rssi_cdbm: row.get(5)?,
                    started_at_ms: row.get(6)?,
                    last_seen_ms: row.get(7)?,
                })
            },
        )?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    pub fn record_discovery_match(
        &mut self,
        passage_id: i64,
        lpr_event_ms: i64,
        plate: &str,
        lpr_actor_type: &str,
        lpr_actor_id: &str,
    ) -> Result<PassageMatchOutcome> {
        validate_text(plate, 64, "license plate")?;
        validate_lpr_actor_type(lpr_actor_type)?;
        validate_text(lpr_actor_id, 128, "UniFi LPR actor ID")?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: (String, Option<String>, Option<String>, String) = transaction
            .query_row(
                "SELECT correlation_status, plate, lpr_actor_id, lpr_actor_type
                 FROM discovery_passages WHERE id = ?1 AND stationary = 0",
                [passage_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .with_context(|| format!("unknown or stationary discovery passage {passage_id}"))?;
        let outcome = match existing.0.as_str() {
            "pending" => {
                transaction.execute(
                    "UPDATE discovery_passages SET correlation_status = 'matched',
                         lpr_event_ms = ?1, plate = ?2, lpr_actor_id = ?3,
                         lpr_actor_type = ?4
                     WHERE id = ?5",
                    params![
                        lpr_event_ms,
                        plate,
                        lpr_actor_id,
                        lpr_actor_type,
                        passage_id
                    ],
                )?;
                PassageMatchOutcome::Recorded
            }
            "matched"
                if existing
                    .1
                    .as_deref()
                    .is_some_and(|stored| same_plate_family(stored, plate))
                    && existing.2.as_deref() == Some(lpr_actor_id)
                    && existing.3 == lpr_actor_type =>
            {
                PassageMatchOutcome::Duplicate
            }
            "matched" => {
                transaction.execute(
                    "UPDATE discovery_passages SET correlation_status = 'ambiguous',
                         lpr_event_ms = NULL, plate = NULL, lpr_actor_id = NULL,
                         lpr_actor_type = 'user'
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
            "SELECT correlation_status, lpr_event_ms, plate, lpr_actor_id,
                    lpr_actor_type
             FROM discovery_passages
             WHERE tag_key = ?1 AND started_at_ms >= ?2 AND stationary = 0",
        )?;
        let rows = statement.query_map(params![tag_key, cutoff], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<i64>>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, String>(4)?,
            ))
        })?;
        let passages = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        drop(statement);
        let total_passages = u32::try_from(passages.len()).unwrap_or(u32::MAX);
        if total_passages == 0 {
            return Ok(None);
        }

        let mut groups: HashMap<DiscoveryIdentityKey, DiscoveryEvidence> = HashMap::new();
        for (status, event_ms, plate, actor_id, actor_type) in passages {
            if status != "matched" {
                continue;
            }
            let (Some(event_ms), Some(plate), Some(actor_id)) = (event_ms, plate, actor_id) else {
                continue;
            };
            let entry = groups
                .entry((canonical_plate_key(&plate), actor_type, actor_id))
                .or_insert_with(|| DiscoveryEvidence {
                    plate: plate.clone(),
                    matched_occurrences: 0,
                    days: HashSet::new(),
                    last_match_ms: event_ms,
                });
            entry.matched_occurrences = entry.matched_occurrences.saturating_add(1);
            entry.days.insert(event_ms.div_euclid(86_400_000));
            if event_ms >= entry.last_match_ms {
                entry.plate = plate;
                entry.last_match_ms = event_ms;
            }
        }
        if groups.is_empty() {
            return Ok(None);
        }
        let mut ranked = groups.into_iter().collect::<Vec<_>>();
        ranked.sort_by(|left, right| {
            right
                .1
                .matched_occurrences
                .cmp(&left.1.matched_occurrences)
                .then_with(|| right.1.last_match_ms.cmp(&left.1.last_match_ms))
                .then_with(|| left.0.cmp(&right.0))
        });
        let (
            (_, lpr_actor_type, lpr_actor_id),
            DiscoveryEvidence {
                plate,
                matched_occurrences,
                days,
                last_match_ms,
            },
        ) = ranked.remove(0);
        let conflicting_occurrences = ranked
            .iter()
            .map(|(_, evidence)| evidence.matched_occurrences)
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
            lpr_actor_type,
            lpr_actor_id,
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
                        assigned_at, assigned_by, plate, lpr_actor_type,
                        lpr_actor_id, status, lease_expires_ms
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
                        lpr_actor_type: row.get(6)?,
                        lpr_actor_id: row.get(7)?,
                        status: row.get(8)?,
                        lease_expires_ms: row.get(9)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn get_gate_owner(&self, tag_key: &str) -> Result<Option<TagOwner>> {
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
        unifi_user_id: &str,
        unifi_user_name: &str,
        lease: Duration,
    ) -> Result<TagOwner> {
        validate_text(unifi_user_id, 128, "UniFi user ID")?;
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
        let existing: Option<(String, String, String, String, String)> = transaction
            .query_row(
                "SELECT status, unifi_user_id, plate, lpr_actor_type, lpr_actor_id
                 FROM learned_tag_ownership WHERE tag_key = ?1",
                [&candidate.tag_key],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()?;
        if let Some((status, user_id, plate, actor_type, actor_id)) = existing {
            if status == "active"
                && user_id == unifi_user_id
                && same_plate_family(&plate, &candidate.plate)
                && actor_type == candidate.lpr_actor_type
                && actor_id == candidate.lpr_actor_id
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
                  vehicle_description, assigned_at, assigned_by, lease_expires_ms, updated_at,
                  lpr_actor_type, lpr_actor_id)
             VALUES (?1, ?2, ?3, ?4, 'active', ?5, ?6, ?7, ?8, ?6, ?9, ?10)",
            params![
                candidate.tag_key,
                unifi_user_id,
                unifi_user_name,
                candidate.plate,
                vehicle,
                now,
                self.actor,
                expires_ms,
                candidate.lpr_actor_type,
                candidate.lpr_actor_id,
            ],
        )?;
        let detail = serde_json::json!({
            "source": "multi-visit-lpr",
            "unifi_user_id": unifi_user_id,
            "unifi_user_name": unifi_user_name,
            "plate": candidate.plate,
            "lpr_actor_type": candidate.lpr_actor_type,
            "lpr_actor_id": candidate.lpr_actor_id,
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
        lpr_actor_type: &str,
        lpr_actor_id: &str,
        plate: &str,
        lease: Duration,
    ) -> Result<bool> {
        let Some(assignment) = self.learned_assignment(tag_key)? else {
            return Ok(false);
        };
        if assignment.status != "active"
            || assignment.lpr_actor_type != lpr_actor_type
            || assignment.lpr_actor_id != lpr_actor_id
            || !same_plate_family(&assignment.plate, plate)
        {
            return Ok(false);
        }
        let expires_ms = now_ms().saturating_add(duration_ms(lease));
        let changed = self.connection.execute(
            "UPDATE learned_tag_ownership SET lease_expires_ms = ?1, updated_at = ?2
             WHERE tag_key = ?3 AND status = 'active'",
            params![expires_ms, timestamp(), tag_key],
        )?;
        Ok(changed > 0)
    }

    pub fn count_discovery_conflicts(
        &self,
        tag_key: &str,
        lpr_actor_type: &str,
        lpr_actor_id: &str,
        plate: &str,
        evidence_retention: Duration,
    ) -> Result<u32> {
        let cutoff = now_ms().saturating_sub(duration_ms(evidence_retention));
        let mut statement = self.connection.prepare(
            "SELECT lpr_actor_type, lpr_actor_id, plate
             FROM discovery_passages
             WHERE tag_key = ?1 AND started_at_ms >= ?2 AND stationary = 0
               AND correlation_status = 'matched'",
        )?;
        let rows = statement
            .query_map(params![tag_key, cutoff], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let count = rows
            .into_iter()
            .filter(|(actor_type, actor_id, observed_plate)| {
                actor_type != lpr_actor_type
                    || actor_id.as_deref() != Some(lpr_actor_id)
                    || observed_plate
                        .as_deref()
                        .is_none_or(|observed| !same_plate_family(observed, plate))
            })
            .count();
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
                "lpr_actor_type": candidate.lpr_actor_type,
                "lpr_actor_id": candidate.lpr_actor_id,
                "matched_occurrences": candidate.matched_occurrences,
                "distinct_days": candidate.distinct_days,
                "total_passages": candidate.total_passages,
                "confidence_percent": candidate.confidence_percent,
            })
            .to_string();
            audit_tx(
                &transaction,
                &self.actor,
                "discovery-candidate-ready",
                Some(&candidate.tag_key),
                Some(&candidate.epc),
                Some(&detail),
            )?;
        }
        transaction.commit()?;
        Ok(changed > 0)
    }

    pub fn record_gate_decision(
        &mut self,
        tag_key: &str,
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
                 (timestamp, tag_key, epc, unifi_user_id, mode, decision, detail)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                timestamp(),
                tag_key,
                epc,
                unifi_user_id,
                mode,
                decision,
                detail
            ],
        )?;
        Ok(())
    }

    pub fn list_gate_events(&self, limit: usize) -> Result<Vec<GateEvent>> {
        let mut statement = self.connection.prepare(
            "SELECT timestamp, tag_key, epc, unifi_user_id, mode, decision, detail
             FROM gate_events ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = statement.query_map([limit as i64], row_to_gate_event)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
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

fn row_to_gate_event(row: &rusqlite::Row<'_>) -> rusqlite::Result<GateEvent> {
    Ok(GateEvent {
        timestamp: row.get(0)?,
        tag_key: row.get(1)?,
        epc: row.get(2)?,
        unifi_user_id: row.get(3)?,
        mode: row.get(4)?,
        decision: row.get(5)?,
        detail: row.get(6)?,
    })
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

fn ensure_gate_event_tag_key(connection: &Connection) -> Result<()> {
    if table_has_column(connection, "gate_events", "tag_key")? {
        return Ok(());
    }
    if table_has_column(connection, "gate_events", "tid")? {
        connection.execute("ALTER TABLE gate_events RENAME COLUMN tid TO tag_key", [])?;
    }
    Ok(())
}

fn ensure_lpr_actor_columns(connection: &Connection) -> Result<()> {
    let has_legacy_passage_user =
        table_has_column(connection, "discovery_passages", "unifi_user_id")?;
    if !table_has_column(connection, "discovery_passages", "lpr_actor_type")? {
        connection.execute(
            "ALTER TABLE discovery_passages
             ADD COLUMN lpr_actor_type TEXT NOT NULL DEFAULT 'user'
             CHECK (lpr_actor_type IN ('user', 'visitor'))",
            [],
        )?;
    }
    if !table_has_column(connection, "discovery_passages", "lpr_actor_id")? {
        connection.execute(
            "ALTER TABLE discovery_passages ADD COLUMN lpr_actor_id TEXT",
            [],
        )?;
    }
    if has_legacy_passage_user {
        connection.execute(
            "UPDATE discovery_passages
             SET lpr_actor_id = unifi_user_id
             WHERE lpr_actor_id IS NULL AND unifi_user_id IS NOT NULL",
            [],
        )?;
    }
    if !table_has_column(connection, "learned_tag_ownership", "lpr_actor_type")? {
        connection.execute(
            "ALTER TABLE learned_tag_ownership
             ADD COLUMN lpr_actor_type TEXT NOT NULL DEFAULT 'user'
             CHECK (lpr_actor_type IN ('user', 'visitor'))",
            [],
        )?;
    }
    if !table_has_column(connection, "learned_tag_ownership", "lpr_actor_id")? {
        connection.execute(
            "ALTER TABLE learned_tag_ownership ADD COLUMN lpr_actor_id TEXT",
            [],
        )?;
    }
    connection.execute(
        "UPDATE learned_tag_ownership
         SET lpr_actor_id = unifi_user_id
         WHERE lpr_actor_id IS NULL OR lpr_actor_id = ''",
        [],
    )?;
    Ok(())
}

fn table_has_column(connection: &Connection, table: &str, expected: &str) -> Result<bool> {
    let mut statement = connection.prepare(&format!("PRAGMA table_info({table})"))?;
    let columns = statement.query_map([], |row| row.get::<_, String>(1))?;
    for column in columns {
        if column? == expected {
            return Ok(true);
        }
    }
    Ok(false)
}

fn validate_text(value: &str, max_length: usize, name: &str) -> Result<()> {
    let value = value.trim();
    if value.is_empty() || value.len() > max_length || value.chars().any(char::is_control) {
        bail!("{name} must contain 1 to {max_length} printable characters");
    }
    Ok(())
}

fn validate_lpr_actor_type(value: &str) -> Result<()> {
    if matches!(value, "user" | "visitor") {
        return Ok(());
    }
    bail!("UniFi LPR actor type must be user or visitor")
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
        assert!(first.new_passage);
        assert!(!repeated.new_passage);
        assert_eq!(first.passage_id, repeated.passage_id);

        assert_eq!(
            store
                .record_discovery_match(
                    first.passage_id,
                    base + 500,
                    "ABC123",
                    "user",
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
                    "user",
                    "17d2f099-99df-429b-becb-1399a6937e5a",
                )
                .unwrap(),
            PassageMatchOutcome::Duplicate
        );
        assert_eq!(
            store
                .record_discovery_match(
                    first.passage_id,
                    base + 750,
                    "ABCI23",
                    "user",
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
    fn common_ocr_plate_variants_build_and_renew_one_candidate() {
        let directory = tempdir().unwrap();
        let mut store = Store::open(&directory.path().join("state.sqlite3"), "test").unwrap();
        let tag = "E2801111";
        let epc = "11223344556677889900AABB";
        let visitor = "27d2f099-99df-429b-becb-1399a6937e5b";
        let user = "17d2f099-99df-429b-becb-1399a6937e5a";
        let first_at = now_ms() - 2 * 86_400_000;
        let second_at = first_at + 86_400_000;

        let first = discovery_seen(&mut store, tag, epc, first_at);
        store
            .record_discovery_match(first.passage_id, first_at, "ABOI", "visitor", visitor)
            .unwrap();
        let second = discovery_seen(&mut store, tag, epc, second_at);
        store
            .record_discovery_match(second.passage_id, second_at, "AB01", "visitor", visitor)
            .unwrap();

        let candidate = store
            .discovery_candidate(tag, Duration::from_secs(60 * 86_400), 2, 2, 100, 2)
            .unwrap()
            .unwrap();
        assert!(candidate.ready);
        assert_eq!(candidate.plate, "AB01");
        assert_eq!(candidate.matched_occurrences, 2);
        assert_eq!(candidate.distinct_days, 2);
        assert_eq!(candidate.conflicting_occurrences, 0);
        assert_eq!(
            store
                .count_discovery_conflicts(
                    tag,
                    "visitor",
                    visitor,
                    "ABOI",
                    Duration::from_secs(60 * 86_400),
                )
                .unwrap(),
            0
        );

        store
            .activate_discovered_tag(&candidate, user, "Example User", Duration::from_secs(60))
            .unwrap();
        assert!(
            store
                .renew_discovered_lease(tag, "visitor", visitor, "ABOI", Duration::from_secs(120),)
                .unwrap()
        );
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
                    .record_discovery_match(passage.passage_id, at, "ABC123", "user", user)
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
            .record_discovery_match(fifth.passage_id, fifth_at, "ABC123", "user", user)
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
                    "user",
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
                "user",
                "17d2f099-99df-429b-becb-1399a6937e5a",
            )
            .unwrap();
        assert_eq!(
            store
                .record_discovery_match(
                    passage.passage_id,
                    base + 1_000,
                    "XYZ789",
                    "user",
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
            .record_discovery_match(passage.passage_id, at, "ABC123", "user", user)
            .unwrap();
        let candidate = store
            .discovery_candidate(tag, Duration::from_secs(60 * 86_400), 1, 1, 100, 2)
            .unwrap()
            .unwrap();
        store
            .activate_discovered_tag(&candidate, user, "Example User", Duration::from_secs(60))
            .unwrap();
        assert_eq!(
            store.get_gate_owner(tag).unwrap().unwrap().unifi_user_id,
            user
        );
        assert!(
            store
                .renew_discovered_lease(tag, "user", user, "ABC123", Duration::from_secs(120),)
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
            .record_discovery_match(relearned.passage_id, relearned_at, "ABC123", "user", user)
            .unwrap();
        let candidate = store
            .discovery_candidate(tag, Duration::from_secs(60 * 86_400), 1, 1, 100, 2)
            .unwrap()
            .unwrap();
        store
            .activate_discovered_tag(&candidate, user, "Example User", Duration::from_secs(60))
            .unwrap();
        store.revoke_discovered_tag(tag).unwrap();
        assert_eq!(
            store.learned_assignment(tag).unwrap().unwrap().status,
            "revoked"
        );
    }

    #[test]
    fn visitor_evidence_can_be_manually_associated_without_becoming_the_gate_owner() {
        let directory = tempdir().unwrap();
        let mut store = Store::open(&directory.path().join("state.sqlite3"), "manual-cli").unwrap();
        let tag = "E2802222";
        let epc = "21223344556677889900AABB";
        let visitor = "27d2f099-99df-429b-becb-1399a6937e5b";
        let user = "17d2f099-99df-429b-becb-1399a6937e5a";
        let at = now_ms() - 1_000;
        let passage = discovery_seen(&mut store, tag, epc, at);
        store
            .record_discovery_match(passage.passage_id, at, "ABC123", "visitor", visitor)
            .unwrap();
        let candidate = store
            .discovery_candidate(tag, Duration::from_secs(60 * 86_400), 1, 1, 100, 2)
            .unwrap()
            .unwrap();
        assert_eq!(candidate.lpr_actor_type, "visitor");
        assert_eq!(candidate.lpr_actor_id, visitor);
        assert!(candidate.ready);

        store
            .activate_discovered_tag(&candidate, user, "Example User", Duration::from_secs(60))
            .unwrap();
        let assignment = store.learned_assignment(tag).unwrap().unwrap();
        assert_eq!(assignment.owner.unifi_user_id, user);
        assert_eq!(assignment.lpr_actor_type, "visitor");
        assert_eq!(assignment.lpr_actor_id, visitor);
        assert!(
            store
                .renew_discovered_lease(
                    tag,
                    "visitor",
                    visitor,
                    "ABC123",
                    Duration::from_secs(120),
                )
                .unwrap()
        );
        assert!(
            !store
                .renew_discovered_lease(tag, "user", user, "ABC123", Duration::from_secs(120),)
                .unwrap()
        );
    }

    #[test]
    fn matched_passage_with_null_identity_counts_as_conflicting_evidence() {
        let directory = tempdir().unwrap();
        let mut store = Store::open(&directory.path().join("state.sqlite3"), "test").unwrap();
        let tag = "E2803333";
        let epc = "31223344556677889900AABB";
        let at = now_ms() - 1_000;
        let passage = discovery_seen(&mut store, tag, epc, at);
        store
            .connection
            .execute(
                "UPDATE discovery_passages
                 SET correlation_status = 'matched', lpr_event_ms = ?1,
                     plate = 'ABC123', lpr_actor_type = 'user', lpr_actor_id = NULL
                 WHERE id = ?2",
                params![at, passage.passage_id],
            )
            .unwrap();

        assert_eq!(
            store
                .count_discovery_conflicts(
                    tag,
                    "user",
                    "17d2f099-99df-429b-becb-1399a6937e5a",
                    "ABC123",
                    Duration::from_secs(60 * 86_400),
                )
                .unwrap(),
            1
        );
    }

    #[test]
    fn legacy_discovery_rows_gain_user_actor_metadata() {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE discovery_passages (
                    id INTEGER PRIMARY KEY,
                    unifi_user_id TEXT
                );
                CREATE TABLE learned_tag_ownership (
                    tag_key TEXT PRIMARY KEY,
                    unifi_user_id TEXT NOT NULL
                );
                INSERT INTO discovery_passages (id, unifi_user_id)
                VALUES (1, '17d2f099-99df-429b-becb-1399a6937e5a');
                INSERT INTO learned_tag_ownership (tag_key, unifi_user_id)
                VALUES ('E2801111', '17d2f099-99df-429b-becb-1399a6937e5a');",
            )
            .unwrap();

        ensure_lpr_actor_columns(&connection).unwrap();

        let migrated: (String, String) = connection
            .query_row(
                "SELECT lpr_actor_type, lpr_actor_id FROM learned_tag_ownership",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            migrated,
            ("user".into(), "17d2f099-99df-429b-becb-1399a6937e5a".into())
        );
        let passage: (String, String) = connection
            .query_row(
                "SELECT lpr_actor_type, lpr_actor_id FROM discovery_passages",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(passage, migrated);
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

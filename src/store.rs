use std::{path::Path, time::Duration};

use anyhow::{Context, Result, bail};
use chrono::{SecondsFormat, Utc};
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

pub fn now_ms() -> i64 {
    Utc::now().timestamp_millis()
}

fn duration_ms(duration: Duration) -> i64 {
    i64::try_from(duration.as_millis()).unwrap_or(i64::MAX)
}

fn timestamp() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
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

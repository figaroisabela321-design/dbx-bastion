//! SQLite [`AuditService`] implementation (TASK-005B).
//!
//! - `record_started` inserts the `started` row in one transaction and
//!   returns its id. Any storage error means the audit trail is
//!   unavailable: the caller must not execute.
//! - `record_finished` transitions a `started` row to a terminal state.
//!   It refuses to overwrite a row that already left `started` (no
//!   silent double-finish), and it never fabricates a rollback: if the
//!   update itself fails after execution, the caller marks the gateway
//!   fail-closed.
//! - `has_untriaged_interruptions` is true while any row is `started`
//!   (crash before finish) or `unknown_interrupted`.

use std::sync::Arc;

use chrono::Utc;
use uuid::Uuid;

use super::{
    AuditEvent, AuditOutcome, AuditService, AuditStatus, RecoveryEvent, TriageConclusion, UnfinishedAudit,
    MAX_TRIAGE_EVIDENCE_LEN, MAX_TRIAGE_REASON_LEN,
};
use crate::error::{BastionError, Result};
use crate::storage::SqliteStore;

/// Mask string and numeric literals in SQL text before it is stored.
///
/// The audit trail keeps the SHA-256 of the *exact* SQL for
/// tamper-evident correlation; the stored text is for operator
/// forensics and must not leak credentials or PII pasted into
/// literals. This is a best-effort lexical mask, not a parser: the
/// exact bytes are never persisted.
pub fn redact_sql(sql: &str) -> String {
    let mut out = String::with_capacity(sql.len());
    let mut chars = sql.chars().peekable();
    // The last emitted char, to avoid masking digits inside identifiers
    // (`id2` keeps its `2`; only standalone numeric literals are masked).
    let mut prev: Option<char> = None;
    while let Some(c) = chars.next() {
        match c {
            '\'' => {
                // Single-quoted literal: consume to the closing quote,
                // honoring '' escapes.
                out.push_str("'?'");
                prev = Some('\'');
                loop {
                    match chars.next() {
                        Some('\'') => {
                            if chars.peek() == Some(&'\'') {
                                chars.next();
                            } else {
                                break;
                            }
                        }
                        Some(_) => {}
                        None => break,
                    }
                }
            }
            c if c.is_ascii_digit()
                && !matches!(prev, Some(p) if p.is_ascii_alphanumeric() || p == '_' || p == '.') =>
            {
                // Standalone numeric literal: mask the whole run,
                // including one decimal point.
                out.push('?');
                prev = Some('?');
                let mut seen_dot = false;
                while let Some(&n) = chars.peek() {
                    if n.is_ascii_digit() {
                        chars.next();
                    } else if n == '.' && !seen_dot {
                        seen_dot = true;
                        chars.next();
                    } else {
                        break;
                    }
                }
            }
            _ => {
                out.push(c);
                prev = Some(c);
            }
        }
    }
    out
}

pub struct SqliteAuditService {
    store: Arc<SqliteStore>,
}

impl SqliteAuditService {
    pub fn new(store: Arc<SqliteStore>) -> Self {
        Self { store }
    }

    /// Count rows by status. Used by operators and integration tests to
    /// verify that denials actually produced `blocked` rows (rather than
    /// merely claiming to).
    pub async fn count_by_status(&self, status: AuditStatus) -> Result<u64> {
        let count: i64 = self
            .store
            .blocking(move |conn| {
                conn.query_row("SELECT COUNT(*) FROM audit_events WHERE status = ?1", [status.as_str()], |row| {
                    row.get(0)
                })
                .map_err(BastionError::from)
            })
            .await?;
        Ok(count as u64)
    }
}

#[async_trait::async_trait]
impl AuditService for SqliteAuditService {
    async fn record_started(&self, event: AuditEvent) -> Result<Uuid> {
        let id = event.id;
        self.store
            .blocking(move |conn| {
                // A single INSERT is atomic; no explicit transaction needed.
                let inserted = conn.execute(
                    "INSERT INTO audit_events (
                        id, user_id, session_id, asset_id, database_name, schema_name,
                        sql_text, sql_hash, action, sql_kind, risk_level, policy_decision,
                        source_ip, client_request_id, status, success, row_count,
                        duration_ms, error_message, started_at, finished_at
                    ) VALUES (
                        ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                        ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21
                    )",
                    rusqlite::params![
                        id.to_string(),
                        event.user_id.to_string(),
                        event.session_id.to_string(),
                        event.asset_id.to_string(),
                        event.database,
                        event.schema,
                        event.sql_text,
                        event.sql_hash,
                        format!("{:?}", event.action),
                        format!("{:?}", event.action),
                        format!("{:?}", event.risk_level),
                        event.policy_decision,
                        event.source_ip,
                        event.client_request_id,
                        event.status.as_str(),
                        event.success.map(i64::from),
                        event.row_count.map(|n| n as i64),
                        event.duration_ms,
                        event.error_message,
                        event.started_at.to_rfc3339(),
                        event.finished_at.map(|t| t.to_rfc3339()),
                    ],
                )?;
                if inserted != 1 {
                    return Err(BastionError::AuditUnavailable("audit insert affected 0 rows".to_string()));
                }
                Ok(())
            })
            .await
            .map_err(|e| match e {
                BastionError::AuditUnavailable(_) => e,
                other => BastionError::AuditUnavailable(other.to_string()),
            })?;
        Ok(id)
    }

    async fn record_finished(&self, id: Uuid, outcome: AuditOutcome) -> Result<()> {
        let updated = self
            .store
            .blocking(move |conn| {
                // Only a `started` row may transition: a second finish is
                // a bug, never silently absorbed.
                let updated = conn.execute(
                    "UPDATE audit_events SET status = ?1, success = ?2, row_count = ?3,
                     duration_ms = ?4, error_message = ?5, finished_at = ?6
                     WHERE id = ?7 AND status = 'started'",
                    rusqlite::params![
                        outcome.status.as_str(),
                        outcome.success.map(i64::from),
                        outcome.row_count.map(|n| n as i64),
                        outcome.duration_ms,
                        outcome.error_message,
                        Utc::now().to_rfc3339(),
                        id.to_string(),
                    ],
                )?;
                Ok(updated)
            })
            .await?;
        if updated != 1 {
            return Err(BastionError::Storage(rusqlite::Error::QueryReturnedNoRows));
        }
        Ok(())
    }

    async fn has_untriaged_interruptions(&self) -> Result<bool> {
        // An interruption blocks while it has NO recovery event, or its
        // recovery conclusion is `still_unknown`. Only
        // `confirmed_committed` / `confirmed_not_executed` lift the block.
        // The original audit row is never modified by triage.
        let count: i64 = self
            .store
            .blocking(|conn| {
                let c: i64 = conn
                    .query_row(
                        "SELECT COUNT(*) FROM audit_events e
                     WHERE e.status IN ('started', 'unknown_interrupted')
                     AND NOT EXISTS (
                         SELECT 1 FROM audit_recovery_events r
                         WHERE r.audit_event_id = e.id
                         AND r.conclusion IN ('confirmed_committed', 'confirmed_not_executed')
                     )",
                        [],
                        |row| row.get(0),
                    )
                    .map_err(BastionError::Storage)?;
                Ok(c)
            })
            .await?;
        Ok(count > 0)
    }

    async fn list_unfinished(&self) -> Result<Vec<UnfinishedAudit>> {
        self.store
            .blocking(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT id, status, started_at FROM audit_events
                     WHERE status IN ('started', 'unknown_interrupted')
                     ORDER BY started_at ASC",
                )?;
                let rows = stmt.query_map([], |row| {
                    let id: String = row.get(0)?;
                    let status: String = row.get(1)?;
                    let started_at: String = row.get(2)?;
                    let parse_err = |what: &'static str| {
                        rusqlite::Error::FromSqlConversionFailure(
                            0,
                            rusqlite::types::Type::Text,
                            Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, what)),
                        )
                    };
                    Ok(UnfinishedAudit {
                        id: id.parse().map_err(|_| parse_err("bad audit id"))?,
                        status: match status.as_str() {
                            "started" => AuditStatus::Started,
                            _ => AuditStatus::UnknownInterrupted,
                        },
                        started_at: started_at.parse().map_err(|_| parse_err("bad audit timestamp"))?,
                    })
                })?;
                let mut out = Vec::new();
                for row in rows {
                    out.push(row?);
                }
                Ok(out)
            })
            .await
    }
}

impl SqliteAuditService {
    /// Triage an unfinished audit record (`started` or
    /// `unknown_interrupted`) after operator review (TASK-005E P0-2).
    ///
    /// The original `audit_events` row is NEVER modified. The triage
    /// appends one row to `audit_recovery_events` with the operator,
    /// time, reason, evidence, original status, and conclusion.
    ///
    /// Rules (fail-closed):
    /// - `reason` non-empty, `reason` <= 2000 chars, `evidence` <= 10000.
    /// - `conclusion` is required: the caller must state what the
    ///   evidence proves. `StillUnknown` keeps the execution block.
    /// - Records in `in_flight` (actively executing) are rejected:
    ///   only orphaned interruptions may be triaged.
    /// - Already-triaged records are rejected (one triage per event).
    /// - Triage failure never unblocks execution.
    pub async fn triage_interruption(
        &self,
        id: Uuid,
        triaged_by: Uuid,
        reason: &str,
        evidence: &str,
        conclusion: TriageConclusion,
        in_flight: &std::collections::HashSet<Uuid>,
    ) -> Result<()> {
        let reason = reason.trim();
        let evidence = evidence.trim();
        if reason.is_empty() {
            return Err(BastionError::InvalidData("triage reason is required".to_string()));
        }
        if reason.len() > MAX_TRIAGE_REASON_LEN {
            return Err(BastionError::InvalidData(format!("triage reason exceeds {} chars", MAX_TRIAGE_REASON_LEN)));
        }
        if evidence.len() > MAX_TRIAGE_EVIDENCE_LEN {
            return Err(BastionError::InvalidData(format!(
                "triage evidence exceeds {} chars",
                MAX_TRIAGE_EVIDENCE_LEN
            )));
        }
        // confirmed_* conclusions require evidence; still_unknown may
        // document the investigation without proof.
        if conclusion.unblocks() && evidence.is_empty() {
            return Err(BastionError::InvalidData(format!("conclusion '{}' requires evidence", conclusion.as_str())));
        }
        if in_flight.contains(&id) {
            return Err(BastionError::InvalidData(format!(
                "audit record {id} is actively executing; triage is forbidden"
            )));
        }

        let reason = reason.to_string();
        let evidence = evidence.to_string();
        let now = chrono::Utc::now().to_rfc3339();
        let conclusion_str = conclusion.as_str().to_string();
        let recovery_id = Uuid::new_v4().to_string();

        self.store
            .blocking(move |conn| {
                // 1. The record must exist and be unfinished.
                let original_status: String = conn
                    .query_row(
                        "SELECT status FROM audit_events WHERE id = ?1",
                        [id.to_string()],
                        |row| row.get(0),
                    )
                    .map_err(|_| BastionError::NotFound(format!("audit record {id} not found")))?;
                if !matches!(original_status.as_str(), "started" | "unknown_interrupted") {
                    return Err(BastionError::InvalidData(format!(
                        "audit record {id} is already terminal (status={original_status}); triage is only for interruptions"
                    )));
                }
                // 2. Append the recovery event. UNIQUE(audit_event_id)
                //    rejects duplicate triage.
                let inserted = conn.execute(
                    "INSERT INTO audit_recovery_events
                     (id, audit_event_id, triaged_by, triaged_at, original_status, conclusion, reason, evidence)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    rusqlite::params![
                        recovery_id,
                        id.to_string(),
                        triaged_by.to_string(),
                        now,
                        original_status,
                        conclusion_str,
                        reason,
                        evidence,
                    ],
                )?;
                if inserted != 1 {
                    return Err(BastionError::Storage(rusqlite::Error::QueryReturnedNoRows));
                }
                Ok(())
            })
            .await
            .map_err(|e| match e {
                // UNIQUE violation -> already triaged.
                BastionError::Storage(rusqlite::Error::SqliteFailure(err, _)) if err.extended_code == 2067 => {
                    BastionError::InvalidData(format!("audit record {id} has already been triaged"))
                }
                other => other,
            })
    }

    /// Get the recovery event for an audit record, if triaged.
    pub async fn get_recovery_event(&self, audit_event_id: Uuid) -> Result<Option<RecoveryEvent>> {
        self.store
            .blocking(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT id, triaged_by, triaged_at, original_status, conclusion, reason, evidence
                     FROM audit_recovery_events WHERE audit_event_id = ?1",
                )?;
                let mut rows = stmt.query_map([audit_event_id.to_string()], |row| {
                    let id: String = row.get(0)?;
                    let triaged_by: String = row.get(1)?;
                    let triaged_at: String = row.get(2)?;
                    let original_status: String = row.get(3)?;
                    let conclusion: String = row.get(4)?;
                    let reason: String = row.get(5)?;
                    let evidence: String = row.get(6)?;
                    Ok(RecoveryEvent {
                        id: id.parse().map_err(|_| rusqlite::Error::InvalidQuery)?,
                        audit_event_id,
                        triaged_by: triaged_by.parse().map_err(|_| rusqlite::Error::InvalidQuery)?,
                        triaged_at: triaged_at.parse().map_err(|_| rusqlite::Error::InvalidQuery)?,
                        original_status: match original_status.as_str() {
                            "started" => AuditStatus::Started,
                            _ => AuditStatus::UnknownInterrupted,
                        },
                        conclusion: TriageConclusion::from_str(&conclusion).ok_or(rusqlite::Error::InvalidQuery)?,
                        reason,
                        evidence,
                    })
                })?;
                match rows.next() {
                    Some(row) => Ok(Some(row?)),
                    None => Ok(None),
                }
            })
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_masks_literals() {
        assert_eq!(
            redact_sql("SELECT * FROM t WHERE pw = 's3cret' AND id = 42"),
            "SELECT * FROM t WHERE pw = '?' AND id = ?"
        );
        assert_eq!(redact_sql("SELECT 'it''s'"), "SELECT '?'");
        // Identifiers are untouched.
        assert_eq!(redact_sql("SELECT id2 FROM t2"), "SELECT id2 FROM t2");
    }
}

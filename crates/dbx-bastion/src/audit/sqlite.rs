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

use super::{AuditEvent, AuditOutcome, AuditService};
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
        let count: i64 = self
            .store
            .blocking(|conn| {
                conn.query_row(
                    "SELECT COUNT(*) FROM audit_events WHERE status IN ('started', 'unknown_interrupted')",
                    [],
                    |row| row.get(0),
                )
                .map_err(BastionError::from)
            })
            .await?;
        Ok(count > 0)
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

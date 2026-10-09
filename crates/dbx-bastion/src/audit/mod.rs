//! Audit domain: lifecycle, service contract, and evidence rules (TASK-005A).
//!
//! The reliable lifecycle is implemented in TASK-005B; this module
//! defines the contract it must satisfy:
//!
//! - Every gateway execution writes `Started` **before** touching the
//!   database. A failed `Started` write **prohibits execution**
//!   (fail-closed).
//! - Terminal states are `Succeeded` / `Failed` / `Blocked`.
//!   `Blocked` covers policy/RBAC/approval denials (the database was
//!   never touched).
//! - `UnknownInterrupted` is the crash-recovery state: execution was
//!   dispatched but no terminal record exists. On recovery the record
//!   stays `UnknownInterrupted` — the implementation must **never**
//!   pretend the database operation was rolled back — and the system
//!   enters a mode that refuses new executions until an operator
//!   triages the record.
//!
//! Concurrency model (V1: single gateway process per audit store):
//! - A `started` row is **not** an interruption while its owning
//!   gateway process is alive: the gateway tracks its in-flight audit
//!   IDs in memory and excludes them when checking for interruptions.
//!   Concurrent queries in the same process never block each other.
//! - After a restart the in-memory set is empty, so any surviving
//!   `started` row is an orphaned interruption and refuses new
//!   executions until triaged.
//! - `unknown_interrupted` rows always count as interruptions,
//!   regardless of ownership.
//!
//! Evidence rules:
//! - SQL text is stored (forensics need it); result **rows are never
//!   stored**, only counts/hashes/truncation markers.
//! - Parameters are stored only in redacted form (no credentials).
//! - Retention: configurable, default 180 days; reads are
//!   auditor-role only (enforced in TASK-005B service layer).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::Result;
use crate::policy::RiskLevel;
use crate::query::analyzer::StatementAction;

pub mod sqlite;
pub use sqlite::{redact_sql, SqliteAuditService};

/// Audit lifecycle states. See module docs for the fail-closed rules
/// attached to each transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditStatus {
    Started,
    Succeeded,
    Failed,
    Blocked,
    UnknownInterrupted,
}

impl AuditStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Started => "started",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Blocked => "blocked",
            Self::UnknownInterrupted => "unknown_interrupted",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "started" => Some(Self::Started),
            "succeeded" => Some(Self::Succeeded),
            "failed" => Some(Self::Failed),
            "blocked" => Some(Self::Blocked),
            "unknown_interrupted" => Some(Self::UnknownInterrupted),
            _ => None,
        }
    }

    /// Terminal states: no further transition is expected.
    pub fn is_terminal(self) -> bool {
        !matches!(self, Self::Started | Self::UnknownInterrupted)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: Uuid,
    pub user_id: Uuid,
    pub session_id: Uuid,
    pub asset_id: Uuid,
    pub database: Option<String>,
    pub schema: Option<String>,
    /// Exact SQL text that was analyzed (and, if executed, executed).
    pub sql_text: String,
    /// SHA256 of `sql_text`, for tamper-evident correlation.
    pub sql_hash: String,
    pub action: StatementAction,
    pub risk_level: RiskLevel,
    /// Policy verdict code (e.g. `side_effect_select`), if evaluated.
    pub policy_decision: Option<String>,
    pub source_ip: Option<String>,
    pub client_request_id: Option<String>,
    pub status: AuditStatus,
    pub success: Option<bool>,
    /// Rows returned/affected; never the row contents.
    pub row_count: Option<u64>,
    pub duration_ms: Option<i64>,
    pub error_message: Option<String>,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
}

/// What the gateway reports when an execution finishes.
#[derive(Debug, Clone)]
pub struct AuditOutcome {
    pub status: AuditStatus,
    pub success: Option<bool>,
    pub row_count: Option<u64>,
    pub duration_ms: Option<i64>,
    pub error_message: Option<String>,
}

/// Audit service contract (implemented in TASK-005B).
/// A non-terminal audit row, for interruption triage.
#[derive(Debug, Clone)]
pub struct UnfinishedAudit {
    pub id: Uuid,
    pub status: AuditStatus,
    pub started_at: DateTime<Utc>,
}

#[async_trait::async_trait]
pub trait AuditService: Send + Sync {
    /// Append a `Started` record. `Err` means the audit store is
    /// unavailable: the caller **must not execute**.
    async fn record_started(&self, event: AuditEvent) -> Result<Uuid>;

    /// Transition a record to a terminal state (or `UnknownInterrupted`
    /// during crash recovery).
    async fn record_finished(&self, id: Uuid, outcome: AuditOutcome) -> Result<()>;

    /// True while an `UnknownInterrupted` record is untriaged: the
    /// gateway refuses new executions.
    async fn has_untriaged_interruptions(&self) -> Result<bool>;

    /// All rows without a terminal state (`started` or
    /// `unknown_interrupted`), oldest first. The gateway uses this to
    /// distinguish its own in-flight executions (tracked in memory)
    /// from orphaned rows left by a crashed process: only the latter
    /// count as interruptions.
    async fn list_unfinished(&self) -> Result<Vec<UnfinishedAudit>>;
}

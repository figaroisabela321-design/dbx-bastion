//! Audit domain types.
//!
//! Audit events are append-only evidence, not query history. The audit
//! service (start/finalize with fail-closed semantics for high-risk
//! operations, read-only list API) is built in a later TASK.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::policy::RiskLevel;
use crate::query::SqlKind;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditStatus {
    Started,
    Succeeded,
    Failed,
    Denied,
}

impl AuditStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Started => "started",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Denied => "denied",
        }
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
    pub sql_text: String,
    /// SHA256 of `sql_text`, for tamper-evident correlation.
    pub sql_hash: String,
    pub sql_kind: SqlKind,
    pub risk_level: RiskLevel,
    pub source_ip: Option<String>,
    pub client_request_id: Option<String>,
    pub status: AuditStatus,
    pub success: Option<bool>,
    pub duration_ms: Option<i64>,
    pub error_message: Option<String>,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
}

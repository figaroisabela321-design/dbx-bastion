//! Approval / work-order domain types.
//!
//! The approval workflow (request creation, state machine, one-time ticket
//! issuance/consumption bound to user + asset + SQL hash + expiry) is built
//! in a later TASK. This module defines the persisted shapes.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::policy::RiskLevel;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Rejected,
    Cancelled,
    Expired,
}

impl ApprovalStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Rejected => "rejected",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "pending" => Some(Self::Pending),
            "approved" => Some(Self::Approved),
            "rejected" => Some(Self::Rejected),
            "cancelled" => Some(Self::Cancelled),
            "expired" => Some(Self::Expired),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub id: Uuid,
    pub requester_id: Uuid,
    pub asset_id: Uuid,
    pub database: Option<String>,
    pub schema: Option<String>,
    pub sql_text: String,
    /// SHA256 of the exact SQL text. Execution re-verifies this hash.
    pub sql_hash: String,
    pub risk_level: RiskLevel,
    pub status: ApprovalStatus,
    pub reason: String,
    pub requested_at: DateTime<Utc>,
    pub decided_at: Option<DateTime<Utc>>,
    pub decided_by: Option<Uuid>,
}

/// A ticket minted from an approved request. Single-use: executing a
/// different SQL (different hash) or reusing a consumed ticket must fail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionTicket {
    pub id: Uuid,
    pub approval_request_id: Uuid,
    pub user_id: Uuid,
    pub asset_id: Uuid,
    pub database: Option<String>,
    pub schema: Option<String>,
    pub sql_hash: String,
    pub expires_at: DateTime<Utc>,
    pub consumed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Approval service contract (TASK-005A: interface only).
///
/// The approved architecture is explicit: TASK-005 defines the
/// interface and the `RequiresApproval` policy decision, but **no**
/// ticket issuance/consumption flow is implemented in TASK-005. Until
/// the approval service is complete, every operation the policy marks
/// `RequireApproval` is denied by the gateway — never default-allowed.
#[async_trait::async_trait]
pub trait ApprovalService: Send + Sync {
    /// Returns `true` iff `ticket_id` names a live, unconsumed ticket
    /// bound to exactly (`user_id`, `asset_id`, `sql_hash`) and not
    /// past `now`. Verification and consumption must be atomic
    /// (single conditional UPDATE); a consumed or mismatched ticket
    /// returns `false`, never an execution.
    async fn verify_and_consume(
        &self,
        ticket_id: Uuid,
        user_id: Uuid,
        asset_id: Uuid,
        sql_hash: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> crate::error::Result<bool>;
}

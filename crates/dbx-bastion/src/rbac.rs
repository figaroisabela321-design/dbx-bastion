//! RBAC domain types.
//!
//! Authorization scope: `User/Role -> Asset -> Database -> Schema -> Table -> Action`.
//! DENY always overrides ALLOW. The evaluator itself (including multi-table
//! checks and temporary grants) is implemented in a later TASK; this module
//! defines the types and the repository boundary the evaluator will read.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::Principal;
use crate::error::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Connect,
    Select,
    Insert,
    Update,
    Delete,
    Ddl,
    Execute,
    Export,
    Import,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Connect => "connect",
            Self::Select => "select",
            Self::Insert => "insert",
            Self::Update => "update",
            Self::Delete => "delete",
            Self::Ddl => "ddl",
            Self::Execute => "execute",
            Self::Export => "export",
            Self::Import => "import",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "connect" => Some(Self::Connect),
            "select" => Some(Self::Select),
            "insert" => Some(Self::Insert),
            "update" => Some(Self::Update),
            "delete" => Some(Self::Delete),
            "ddl" => Some(Self::Ddl),
            "execute" => Some(Self::Execute),
            "export" => Some(Self::Export),
            "import" => Some(Self::Import),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Effect {
    Allow,
    Deny,
}

/// The concrete resource a check is performed against. Every table touched by
/// a statement must be checked individually (never only the first one).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceScope {
    pub asset_id: Uuid,
    pub database: Option<String>,
    pub schema: Option<String>,
    pub table: Option<String>,
}

/// One grant row. `None` on a scope field means "any".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionRule {
    pub effect: Effect,
    pub action: Action,
    pub asset_id: Option<Uuid>,
    pub database_pattern: Option<String>,
    pub schema_pattern: Option<String>,
    pub table_pattern: Option<String>,
}

/// Read boundary for the future RBAC evaluator: all rules granted to the
/// principal's roles for one action. Keeps the evaluator storage-agnostic so
/// the SQLite implementation can later be replaced by PostgreSQL.
#[async_trait]
pub trait AuthorizationRepository: Send + Sync {
    async fn permission_rules(&self, principal: &Principal, action: Action) -> Result<Vec<PermissionRule>>;
}

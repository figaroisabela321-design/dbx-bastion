//! Query gateway boundary types.
//!
//! Every ordinary-user database operation must flow through the gateway
//! pipeline (Principal -> asset resolve -> RBAC -> SQL analyze -> policy ->
//! approval -> execute -> masking -> audit). The gateway itself is built in a
//! later TASK. This module defines the analysis result and the two adapter
//! traits that isolate `dbx-bastion` from DBX implementation details:
//!
//! - `SqlAnalyzer`: implemented in `dbx-web` on top of DBX's real SQL
//!   parser/AST (`dbx-sql-core::analyze_sql_references`), never on keyword
//!   matching. See `SQL_SECURITY_NOTES.md`.
//! - `QueryExecutor`: implemented in `dbx-web`, calls the existing DBX query
//!   functions with the resolved internal connection id.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::error::Result;
use crate::policy::RiskLevel;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SqlKind {
    Select,
    Insert,
    Update,
    Delete,
    Ddl,
    Grant,
    Revoke,
    Execute,
    Transaction,
    Unknown,
}

/// Structured analysis of one SQL statement. Produced from the DBX AST, not
/// from string matching.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SqlAnalysis {
    pub kind: SqlKind,
    pub risk_level: RiskLevel,
    pub statement_count: usize,
    pub is_mutating: bool,
    /// `None` when the analyzer cannot determine it (fail closed downstream).
    pub has_where: Option<bool>,
    pub has_limit: Option<bool>,
    /// Fully qualified `db.schema.table` references, used for per-table RBAC.
    pub tables: Vec<String>,
}

/// One gateway execution request. Ordinary users address the database by
/// `asset_id` only; the server resolves the internal DBX connection id.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayRequest {
    pub asset_id: Uuid,
    pub database: Option<String>,
    pub schema: Option<String>,
    pub sql: String,
    /// One-time approval ticket id, when policy requires approval.
    pub approval_ticket: Option<Uuid>,
    pub client_request_id: Option<String>,
}

#[async_trait]
pub trait SqlAnalyzer: Send + Sync {
    async fn analyze(&self, request: &GatewayRequest) -> Result<SqlAnalysis>;
}

#[async_trait]
pub trait QueryExecutor: Send + Sync {
    async fn execute(&self, request: &GatewayRequest) -> Result<Value>;
}

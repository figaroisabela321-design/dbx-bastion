//! Query gateway domain (TASK-005A: analyzer + policy).
//!
//! Every ordinary-user database operation must flow through the gateway
//! pipeline (TASK-005B):
//!
//! ```text
//! Session -> Asset Resolve -> RBAC CONNECT -> AST -> Resource Authorization
//!   -> Policy -> Audit STARTED -> DBX Execute -> Audit Completion
//! ```
//!
//! This module holds the pieces TASK-005A delivers:
//! - [`analyzer`]: the strict AST analyzer (`SqlAnalyzer` trait +
//!   `StrictSqlAnalyzer`), owned by the bastion and built directly on the
//!   sqlparser AST — never on keyword matching.
//! - [`policy`]: the V1 SQL policy, pure-domain decisions.
//!
//! It also declares the **TASK-005B interface contracts** (types only, no
//! logic yet): [`ExecutionContext`], [`QueryExecutor`], [`QueryResultDto`].
//! Ordinary requests can never construct an authorized
//! [`ExecutionContext`]; only the gateway does (TASK-005B).

pub mod analyzer;
pub mod policy;

pub use analyzer::{
    AnalyzeError, AnalyzeRequest, AnalyzedStatement, SqlAnalyzer, SqlDialect, StatementAction, TableRef,
};
pub use policy::{PolicyContext, PolicyDecision, PolicyReason, SqlPolicy};

use uuid::Uuid;

use crate::auth::AuthenticatedPrincipal;
use crate::error::Result;

/// One gateway execution request (TASK-005B shape, declared here so the
/// analyzer/policy tests and the future gateway share it).
///
/// Ordinary users address the database by `asset_id` only. The request
/// carries no `host`/`port`/`username`/`password`/`private_key`,
/// no `ConnectionConfig`, no `connection_id`, and no caller-supplied
/// permission list — the server resolves everything.
#[derive(Debug, Clone)]
pub struct GatewayRequest {
    /// Raw session token; the gateway authenticates it into an
    /// [`AuthenticatedPrincipal`]. Callers never pass a principal.
    pub session_token: String,
    pub asset_id: Uuid,
    /// Optional database override; still subject to authorization.
    pub database: Option<String>,
    /// The exact SQL text to analyze and (if authorized) execute.
    /// Analysis and execution must use this same immutable string.
    pub sql: String,
    /// One-time approval ticket id, when policy requires approval.
    /// (Issuance/consumption is a later TASK; until then the gateway
    /// denies `RequireApproval`.)
    pub approval_ticket: Option<Uuid>,
    pub client_request_id: Option<String>,
}

/// Internal execution authorization, constructed **only** by the gateway
/// (TASK-005B) after the full pipeline passes.
///
/// `#[non_exhaustive]` lets the future dbx-web adapter *read* the fields
/// while making struct-literal construction outside this crate
/// impossible; the only constructor is `pub(crate)`.
#[derive(Debug, Clone)]
#[non_exhaustive]
#[allow(dead_code)] // Fields are read by the TASK-005B gateway/executor.
pub struct ExecutionContext {
    pub principal: AuthenticatedPrincipal,
    pub asset_id: Uuid,
    /// Resolved server-side from the asset. Never client-supplied.
    pub connection_id: String,
    pub database: String,
    /// The exact analyzed SQL string; the executor must run this
    /// verbatim, with no rewriting or concatenation.
    pub sql: String,
    /// SHA-256 of [`Self::sql`], verified immediately before execution
    /// (analysis/execution consistency).
    pub sql_hash: [u8; 32],
    /// Backend-enforced timeout. The gateway never relies on client-side
    /// truncation as a safety limit.
    pub timeout_secs: u64,
}

/// Gateway result DTO. Row/byte limits are enforced backend-side by the
/// executor (TASK-005B); this type only carries what the backend
/// produced, plus truncation markers.
#[derive(Debug, Clone)]
pub struct QueryResultDto {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<String>>,
    pub affected_rows: Option<u64>,
    pub truncated: bool,
    pub execution_time_ms: u64,
}

/// DBX execution adapter, implemented in `dbx-web` (TASK-005C). The
/// implementation receives only the resolved `connection_id` — never
/// credentials — and must:
/// 1. re-validate the session/user/asset/CONNECT/resource authorization
///    immediately before dispatch (close the authorize→execute window);
/// 2. verify `sql_hash` against [`ExecutionContext::sql`];
/// 3. execute the exact SQL string via the `cancel_token`-capable
///    single-statement core entry point;
/// 4. map errors without leaking credentials or connection strings.
#[async_trait::async_trait]
pub trait QueryExecutor: Send + Sync {
    /// Execute the exact SQL in `ctx`. The implementation must pass
    /// `cancel` through to the `cancel_token`-capable single-statement
    /// core entry point — client disconnect cancels the backend query,
    /// it does not merely stop waiting for it.
    async fn execute(
        &self,
        ctx: &ExecutionContext,
        cancel: tokio_util::sync::CancellationToken,
    ) -> Result<QueryResultDto>;
}

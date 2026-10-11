//! Query gateway domain (TASK-005A analyzer + policy, TASK-005B gateway).
//!
//! Every ordinary-user database operation flows through the gateway
//! pipeline:
//!
//! ```text
//! Principal -> Asset Resolve -> Analyze -> Policy -> Production gate
//!   -> Zero-resource gate -> RBAC (CONNECT + all resources)
//!   -> Audit STARTED -> Re-verify (fresh snapshot) -> Execute
//!   -> Audit completion
//! ```
//!
//! - [`analyzer`]: the strict AST analyzer (`SqlAnalyzer` trait +
//!   `StrictSqlAnalyzer`), owned by the bastion and built directly on the
//!   sqlparser AST — never on keyword matching.
//! - [`policy`]: the V1 SQL policy, pure-domain decisions.
//! - [`gateway`]: the [`QueryGateway`] orchestrator (TASK-005B).
//! - [`mock`]: the [`MockExecutor`] for tests (TASK-005B; the real DBX
//!   adapter lands in `dbx-web` in TASK-005C).
//!
//! Ordinary requests can never construct an authorized
//! [`ExecutionContext`]; only the gateway does.

pub mod analyzer;
pub mod gateway;
pub mod mock;
pub mod policy;

pub use analyzer::{
    AnalyzeError, AnalyzeRequest, AnalyzedStatement, SqlAnalyzer, SqlDialect, StatementAction, TableRef,
};
pub use gateway::QueryGateway;
pub use mock::{MockBehavior, MockExecutor};
pub use policy::{PolicyContext, PolicyDecision, PolicyReason, SqlPolicy};

use std::time::Duration;

use serde::Serialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::auth::AuthenticatedPrincipal;
use crate::error::Result;

/// One gateway execution request.
///
/// Ordinary users address the database by `asset_id` only. The request
/// carries no `host`/`port`/`username`/`password`/`private_key`, no
/// `ConnectionConfig`, no `connection_id`, no caller-supplied permission
/// list and no SQL classification — the server resolves everything from
/// the authenticated principal and the asset. There is deliberately no
/// field for any of those: they cannot be expressed, not merely ignored.
#[derive(Debug, Clone)]
pub struct GatewayRequest {
    pub asset_id: Uuid,
    /// The exact SQL text to analyze and (if authorized) execute.
    /// Analysis, authorization, audit and execution all use this same
    /// immutable string; the gateway hashes it and the executor must run
    /// it verbatim.
    pub sql: String,
    /// Caller-requested limits; the gateway clamps them to server-side
    /// ceilings. The executor enforces the final values.
    pub options: ExecutionOptions,
}

/// Caller-requested execution limits. The gateway clamps each to a
/// server-side ceiling; the executor enforces them.
#[derive(Debug, Clone)]
pub struct ExecutionOptions {
    pub max_rows: u64,
    pub max_bytes: u64,
    pub timeout: Duration,
}

impl Default for ExecutionOptions {
    fn default() -> Self {
        Self { max_rows: 1000, max_bytes: 1024 * 1024, timeout: Duration::from_secs(30) }
    }
}

/// SHA-256 of the exact SQL string, binding analysis, authorization,
/// audit and execution to one immutable request.
pub fn sql_hash(sql: &str) -> [u8; 32] {
    Sha256::digest(sql.as_bytes()).into()
}

/// Internal execution authorization, constructed **only** by the gateway
/// after the full pipeline passes.
///
/// `#[non_exhaustive]` lets the future dbx-web adapter *read* the fields
/// while making struct-literal construction outside this crate
/// impossible; the only constructor is `pub(crate)`.
#[derive(Debug, Clone)]
#[non_exhaustive]
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
    /// Backend-enforced row/byte limits and timeout. The gateway never
    /// relies on client-side truncation as a safety limit.
    pub max_rows: u64,
    pub max_bytes: u64,
    pub timeout: Duration,
}

impl ExecutionContext {
    pub(crate) fn new(
        principal: AuthenticatedPrincipal,
        asset_id: Uuid,
        connection_id: String,
        database: String,
        sql: String,
        options: &ExecutionOptions,
    ) -> Self {
        let sql_hash = sql_hash(&sql);
        Self {
            principal,
            asset_id,
            connection_id,
            database,
            sql,
            sql_hash,
            max_rows: options.max_rows,
            max_bytes: options.max_bytes,
            timeout: options.timeout,
        }
    }
}

/// Gateway result DTO. Row/byte limits are enforced backend-side by the
/// executor; this type only carries what the backend produced, plus
/// truncation markers. It never contains credentials, connection
/// objects, or internal error stacks.
#[derive(Debug, Clone, Serialize)]
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
/// 4. enforce `max_rows` / `max_bytes` / `timeout`, honor `cancel`, and
///    map errors without leaking credentials or connection strings.
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

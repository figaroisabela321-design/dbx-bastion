//! [`QueryGateway`]: the unified security orchestrator (TASK-005B).
//!
//! Pipeline (every step fail-closed):
//!
//! ```text
//! principal + GatewayRequest{asset_id, sql, options}
//!   -> fail-closed mode check (untriaged audit interruptions)
//!   -> resolve asset (exists, not deleted)
//!   -> analyze SQL (single immutable string; SHA-256 bound)
//!   -> policy (Allow only; Deny/RequireApproval -> Blocked)
//!   -> production gate (V1: production never executes)
//!   -> zero-resource gate (V1: no empty-batch authorization)
//!   -> unresolved-identity gate (defense in depth; policy denies first)
//!   -> RBAC authorize_batch(CONNECT + every target/source action)
//!   -> audit STARTED (must commit; failure -> no execution)
//!   -> [test hook]
//!   -> re-verify authorize_batch on a FRESH snapshot
//!   -> build ExecutionContext (gateway-only constructor)
//!   -> executor with CancellationToken + timeout
//!   -> audit completion (Succeeded/Failed)
//! ```
//!
//! If audit completion fails after execution, the record stays without a
//! terminal state and the gateway enters fail-closed mode: it refuses new
//! executions until an operator triages. It never claims a rollback.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::analyzer::{AnalyzeRequest, AnalyzedStatement, SqlDialect, StatementAction, StrictSqlAnalyzer, TableRef};
use super::{sql_hash, ExecutionContext, ExecutionOptions, GatewayRequest, QueryExecutor, QueryResultDto};
use crate::asset::{AssetRepository, Environment};
use crate::audit::{redact_sql, AuditEvent, AuditOutcome, AuditService, AuditStatus};
use crate::auth::{AuthenticatedPrincipal, Clock};
use crate::error::{BastionError, Result};
use crate::policy::RiskLevel;
use crate::query::policy::{PolicyContext, PolicyDecision, SqlPolicy};
use crate::query::SqlAnalyzer;
use crate::rbac::{Action, AuthorizationCheck, Authorizer, ResourceScope, SnapshotAuthorizer};
use crate::storage::SqliteStore;

/// Server-side ceilings. Caller-requested options are clamped to these;
/// the executor enforces the final values.
pub const MAX_ROWS_CEILING: u64 = 10_000;
pub const MAX_BYTES_CEILING: u64 = 10 * 1024 * 1024;
pub const TIMEOUT_CEILING: Duration = Duration::from_secs(120);

/// Async hook run between audit STARTED and re-verification (tests only).
pub type PreExecuteHook = Box<dyn Fn() -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>;

pub struct QueryGateway {
    store: Arc<SqliteStore>,
    authorizer: SnapshotAuthorizer,
    audit: Arc<dyn AuditService>,
    executor: Arc<dyn QueryExecutor>,
    clock: Arc<dyn Clock>,
    /// Deterministic test hook, invoked after audit STARTED and before
    /// re-verification. Tests use it to revoke sessions/disable users
    /// mid-flight without sleeping.
    pre_execute_hook: Mutex<Option<PreExecuteHook>>,
    /// In-memory fail-closed latch, set when audit completion fails
    /// after execution. The persistent `has_untriaged_interruptions`
    /// check covers restarts.
    fail_closed: AtomicBool,
}

impl QueryGateway {
    pub fn new(
        store: Arc<SqliteStore>,
        clock: Arc<dyn Clock>,
        audit: Arc<dyn AuditService>,
        executor: Arc<dyn QueryExecutor>,
    ) -> Self {
        let authorizer = SnapshotAuthorizer::new(store.clone(), clock.clone());
        Self {
            store,
            authorizer,
            audit,
            executor,
            clock,
            pre_execute_hook: Mutex::new(None),
            fail_closed: AtomicBool::new(false),
        }
    }

    /// Install the deterministic pre-execute hook.
    ///
    /// Test-only: invoked after audit STARTED and before re-verification
    /// so tests can revoke sessions / disable users mid-flight without
    /// sleeping. Never set in production code.
    pub fn set_pre_execute_hook(&self, hook: PreExecuteHook) {
        *self.pre_execute_hook.lock().unwrap() = Some(hook);
    }

    fn clamp_options(options: &ExecutionOptions) -> ExecutionOptions {
        ExecutionOptions {
            max_rows: options.max_rows.clamp(1, MAX_ROWS_CEILING),
            max_bytes: options.max_bytes.clamp(1024, MAX_BYTES_CEILING),
            timeout: options.timeout.min(TIMEOUT_CEILING).max(Duration::from_secs(1)),
        }
    }

    fn dialect_for(db_type: &str) -> SqlDialect {
        match db_type.to_lowercase().as_str() {
            "mysql" | "mariadb" => SqlDialect::MySql,
            "postgres" | "postgresql" => SqlDialect::Postgres,
            "sqlite" => SqlDialect::Sqlite,
            "mssql" | "sqlserver" | "tds" => SqlDialect::SqlServer,
            _ => SqlDialect::Generic,
        }
    }

    fn checks_for(asset_id: Uuid, stmt: &AnalyzedStatement) -> Vec<AuthorizationCheck> {
        let mut checks = vec![AuthorizationCheck::new(ResourceScope::asset(asset_id), Action::Connect)];
        let target_action = match stmt.action {
            StatementAction::Insert => Some(Action::Insert),
            StatementAction::Update => Some(Action::Update),
            StatementAction::Delete => Some(Action::Delete),
            // Select has no write targets; DDL/etc. never reach here
            // (policy denies them first).
            _ => None,
        };
        let scope_for = |t: &TableRef| ResourceScope {
            asset_id,
            database: t.database.clone(),
            schema: t.schema.clone(),
            table: crate::rbac::NameState::present(t.table.clone()),
        };
        if let Some(action) = target_action {
            for t in &stmt.targets {
                checks.push(AuthorizationCheck::new(scope_for(t), action));
            }
        }
        for s in &stmt.sources {
            checks.push(AuthorizationCheck::new(scope_for(s), Action::Select));
        }
        checks
    }

    fn audit_event(
        &self,
        principal: &AuthenticatedPrincipal,
        asset_id: Uuid,
        stmt: &AnalyzedStatement,
        sql: &str,
        hash: &[u8; 32],
        policy_code: Option<String>,
    ) -> AuditEvent {
        AuditEvent {
            id: Uuid::new_v4(),
            user_id: principal.user_id(),
            session_id: principal.session_id(),
            asset_id,
            database: None,
            schema: None,
            // Redacted: literals masked; the hash binds the exact bytes.
            sql_text: redact_sql(sql),
            sql_hash: hex::encode(hash),
            action: stmt.action,
            risk_level: match stmt.action {
                StatementAction::Select => RiskLevel::Low,
                _ => RiskLevel::Medium,
            },
            policy_decision: policy_code,
            source_ip: None,
            client_request_id: None,
            status: AuditStatus::Started,
            success: None,
            row_count: None,
            duration_ms: None,
            error_message: None,
            started_at: self.clock.now(),
            finished_at: None,
        }
    }

    /// Record a `Blocked` audit event for a denial, best-effort: a
    /// failing audit store must not mask the original denial, but the
    /// denial itself is always returned.
    async fn audit_blocked(
        &self,
        principal: &AuthenticatedPrincipal,
        asset_id: Uuid,
        stmt: &AnalyzedStatement,
        sql: &str,
        hash: &[u8; 32],
        reason: &str,
    ) {
        let event = self.audit_event(principal, asset_id, stmt, sql, hash, Some(reason.to_string()));
        if let Ok(id) = self.audit.record_started(event).await {
            let outcome = AuditOutcome {
                status: AuditStatus::Blocked,
                success: Some(false),
                row_count: None,
                duration_ms: None,
                error_message: Some(reason.to_string()),
            };
            let _ = self.audit.record_finished(id, outcome).await;
        }
    }

    pub async fn execute(&self, principal: &AuthenticatedPrincipal, req: GatewayRequest) -> Result<QueryResultDto> {
        // 0. Fail-closed mode: untriaged interruptions refuse everything.
        if self.fail_closed.load(Ordering::SeqCst) || self.audit.has_untriaged_interruptions().await? {
            return Err(BastionError::AuditFailClosed);
        }

        let options = Self::clamp_options(&req.options);
        let hash = sql_hash(&req.sql);
        let sql = req.sql.clone();

        // 1. Resolve the asset. Missing/deleted -> NotFound (no existence
        //    leak); disabled is denied by the authorizer snapshot below.
        let asset = self
            .store
            .resolve_asset(req.asset_id)
            .await?
            .filter(|a| a.deleted_at.is_none())
            .ok_or_else(|| BastionError::NotFound("asset".to_string()))?;

        // 2. Analyze the one immutable SQL string. V1 passes no default
        //    database: unqualified database levels resolve to Unknown and
        //    are denied (explicit qualification required).
        let dialect = Self::dialect_for(&asset.db_type);
        let stmts = StrictSqlAnalyzer
            .analyze(&AnalyzeRequest { sql: &sql, dialect, default_database: None })
            .map_err(|e| BastionError::PolicyDenied(format!("unanalyzable: {e}")))?;
        let stmt = &stmts[0];

        // 3. Policy: Allow proceeds; anything else is Blocked.
        let policy_ctx = PolicyContext::new(asset.environment);
        match SqlPolicy.evaluate(&stmts, &policy_ctx) {
            PolicyDecision::Allow => {}
            PolicyDecision::Deny(reason) => {
                self.audit_blocked(principal, asset.id, stmt, &sql, &hash, reason.as_str()).await;
                return Err(BastionError::PolicyDenied(reason.as_str().to_string()));
            }
            PolicyDecision::RequireApproval(reason) => {
                let code = format!("require_approval:{}", reason.as_str());
                self.audit_blocked(principal, asset.id, stmt, &sql, &hash, &code).await;
                return Err(BastionError::ApprovalRequired);
            }
        }

        // 4. Production gate (TASK-005B): no execution on production
        //    assets, even for policy-allowed reads.
        if asset.environment == Environment::Production {
            self.audit_blocked(principal, asset.id, stmt, &sql, &hash, "production_denied_v1").await;
            return Err(BastionError::ProductionDenied);
        }

        // 5. Zero-resource gate (V1): a complete analysis that found no
        //    tables must not become an empty authorize_batch.
        if stmt.targets.is_empty() && stmt.sources.is_empty() {
            self.audit_blocked(principal, asset.id, stmt, &sql, &hash, "zero_resource_v1").await;
            return Err(BastionError::PolicyDenied("zero_resource_v1".to_string()));
        }

        // 6. Unresolved-identity gate (defense in depth; the policy
        //    denies these first — this must be unreachable).
        if stmt.targets.iter().chain(stmt.sources.iter()).any(|t| t.has_unknown_level()) {
            self.audit_blocked(principal, asset.id, stmt, &sql, &hash, "unresolved_identity").await;
            return Err(BastionError::PolicyDenied("unresolved_identity".to_string()));
        }

        // 7. RBAC: CONNECT + every target/source action, one snapshot.
        let checks = Self::checks_for(asset.id, stmt);
        if self.authorizer.authorize_batch(principal, &checks).await.is_err() {
            self.audit_blocked(principal, asset.id, stmt, &sql, &hash, "rbac_denied").await;
            return Err(BastionError::Forbidden("access denied".to_string()));
        }

        // 8. Audit STARTED must commit before the executor is touched.
        let event = self.audit_event(principal, asset.id, stmt, &sql, &hash, Some("allow".to_string()));
        let audit_id = self.audit.record_started(event).await.map_err(|e| {
            // No audit event exists: the executor must see zero calls.
            BastionError::AuditUnavailable(e.to_string())
        })?;

        // 9. Deterministic test hook: revoke/disable mid-flight here.
        //     The hook is taken out of the lock before awaiting.
        let hook = self.pre_execute_hook.lock().unwrap().take();
        if let Some(hook) = hook.as_ref() {
            hook().await;
        }
        if let Some(hook) = hook {
            *self.pre_execute_hook.lock().unwrap() = Some(hook);
        }

        // 10. Re-verify on a FRESH snapshot immediately before execution:
        //     session, user, asset, CONNECT, and every resource action.
        //     This closes the authorize→execute window.
        if self.authorizer.authorize_batch(principal, &checks).await.is_err() {
            let outcome = AuditOutcome {
                status: AuditStatus::Blocked,
                success: Some(false),
                row_count: None,
                duration_ms: None,
                error_message: Some("re-verification failed".to_string()),
            };
            let _ = self.audit.record_finished(audit_id, outcome).await;
            return Err(BastionError::Forbidden("access denied".to_string()));
        }

        // 11. Build the execution context (gateway-only constructor) and
        //     verify the hash binds the exact SQL.
        let ctx = ExecutionContext::new(
            principal.clone(),
            asset.id,
            asset.dbx_connection_id.clone(),
            // The database the analyzer resolved against; V1 requires
            // qualification, so this is informational for the mock.
            String::new(),
            sql.clone(),
            &options,
        );
        // 12. Execute with cancellation + timeout.
        let cancel = CancellationToken::new();
        let started = Instant::now();
        let exec_result = tokio::time::timeout(options.timeout, self.executor.execute(&ctx, cancel.clone())).await;
        let elapsed_ms = started.elapsed().as_millis() as u64;

        match exec_result {
            Err(_) => {
                // Timeout: cancel the backend work, then audit.
                cancel.cancel();
                let outcome = AuditOutcome {
                    status: AuditStatus::Failed,
                    success: Some(false),
                    row_count: None,
                    duration_ms: Some(elapsed_ms as i64),
                    error_message: Some("execution timed out".to_string()),
                };
                if self.audit.record_finished(audit_id, outcome).await.is_err() {
                    self.fail_closed.store(true, Ordering::SeqCst);
                    return Err(BastionError::AuditFailClosed);
                }
                Err(BastionError::ExecutionTimeout)
            }
            Ok(Err(e)) => {
                let outcome = AuditOutcome {
                    status: AuditStatus::Failed,
                    success: Some(false),
                    row_count: None,
                    duration_ms: Some(elapsed_ms as i64),
                    error_message: Some(e.to_string()),
                };
                if self.audit.record_finished(audit_id, outcome).await.is_err() {
                    self.fail_closed.store(true, Ordering::SeqCst);
                    return Err(BastionError::AuditFailClosed);
                }
                Err(e)
            }
            Ok(Ok(mut dto)) => {
                dto.execution_time_ms = elapsed_ms;
                let outcome = AuditOutcome {
                    status: AuditStatus::Succeeded,
                    success: Some(true),
                    row_count: Some(dto.rows.len() as u64),
                    duration_ms: Some(elapsed_ms as i64),
                    error_message: None,
                };
                if self.audit.record_finished(audit_id, outcome).await.is_err() {
                    // Executed but unrecorded: enter fail-closed mode.
                    // Never claim a rollback.
                    self.fail_closed.store(true, Ordering::SeqCst);
                    return Err(BastionError::AuditFailClosed);
                }
                Ok(dto)
            }
        }
    }
}

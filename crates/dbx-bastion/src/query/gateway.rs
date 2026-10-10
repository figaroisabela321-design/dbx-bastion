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

use std::collections::HashSet;
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
    /// Audit IDs this gateway instance started and has not finished.
    /// A `started` row is only an interruption when it is NOT in this
    /// set (orphaned by a crash/restart). V1 is single-process per
    /// audit store; concurrent queries in one process never block
    /// each other.
    ///
    /// Registration happens immediately after `record_started` commits
    /// (see `InflightGuard`); the triage path locks this mutex for its
    /// check+INSERT, so a query starting concurrently cannot slip
    /// through. Wrapped in Arc so the HTTP handler can share ownership
    /// without lifetime issues.
    inflight: Arc<tokio::sync::Mutex<HashSet<Uuid>>>,
}

/// RAII guard: removes the audit ID from the in-flight set on drop.
/// Covers every exit path (success, error, panic, async cancellation)
/// so an active STARTED is never mistaken for an orphan.
struct InflightGuard {
    inflight: Arc<tokio::sync::Mutex<HashSet<Uuid>>>,
    id: Uuid,
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        // try_lock: Drop runs in async context (task abort/cancel), where
        // blocking_lock() would panic. If the lock is contended (triage
        // holding it briefly), the ID may leak; the leak is fail-closed
        // (triage of a terminal row is rejected anyway by the status check).
        if let Ok(mut guard) = self.inflight.try_lock() {
            guard.remove(&self.id);
        }
    }
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
            inflight: Arc::new(tokio::sync::Mutex::new(HashSet::new())),
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

    /// Step 0: refuse new executions when the audit trail shows
    /// untriaged interruptions (crash recovery) or a previous audit
    /// failure latched this gateway into fail-closed mode.
    ///
    /// `started` rows owned by this process (in [`Self::inflight`]) are
    /// normal concurrency, not interruptions. After a restart the set
    /// is empty, so surviving `started` rows are orphaned and refuse
    /// new executions until triaged. `unknown_interrupted` rows always
    /// count, regardless of ownership.
    async fn fail_closed_check(&self) -> Result<()> {
        if self.fail_closed.load(Ordering::SeqCst) {
            return Err(BastionError::AuditFailClosed);
        }
        let unfinished = self
            .audit
            .list_unfinished()
            .await
            .map_err(|e| BastionError::AuditUnavailable(format!("audit unavailable: {e}")))?;
        let inflight = self.inflight.lock().await;
        let interrupted =
            unfinished.iter().any(|u| !matches!(u.status, AuditStatus::Started) || !inflight.contains(&u.id));
        drop(inflight);
        if interrupted {
            self.fail_closed.store(true, Ordering::SeqCst);
            return Err(BastionError::AuditFailClosed);
        }
        Ok(())
    }

    fn clamp_options(options: &ExecutionOptions) -> ExecutionOptions {
        ExecutionOptions {
            max_rows: options.max_rows.clamp(1, MAX_ROWS_CEILING),
            max_bytes: options.max_bytes.clamp(1024, MAX_BYTES_CEILING),
            timeout: options.timeout.min(TIMEOUT_CEILING).max(Duration::from_secs(1)),
        }
    }

    /// True while this gateway instance has an actively executing query
    /// with this audit ID. Triage of in-flight records is forbidden
    /// (P0-2): only orphaned interruptions may be triaged.
    pub fn is_inflight(&self, audit_id: &uuid::Uuid) -> bool {
        self.inflight.try_lock().map(|g| g.contains(audit_id)).unwrap_or(true)
    }

    /// The live in-flight set, for the triage path. The audit service
    /// locks this mutex for its check+INSERT, closing the race between
    /// the HTTP-layer check and the DB commit.
    pub fn inflight_set(&self) -> Arc<tokio::sync::Mutex<HashSet<Uuid>>> {
        self.inflight.clone()
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
        self.execute_with_cancel(principal, req, CancellationToken::new()).await
    }

    /// Execute with a caller-supplied parent cancellation token (e.g.
    /// the HTTP layer cancels it when the client disconnects). The
    /// executor receives a child token so gateway-internal timeouts
    /// and caller cancellation are independent triggers.
    pub async fn execute_with_cancel(
        &self,
        principal: &AuthenticatedPrincipal,
        req: GatewayRequest,
        parent_cancel: CancellationToken,
    ) -> Result<QueryResultDto> {
        self.fail_closed_check().await?;

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
        //     The inflight lock is held across record_started + insert:
        //     triage cannot slip in between and treat this new row as an
        //     orphan. (tokio MutexGuard is Send, safe across await.)
        let event = self.audit_event(principal, asset.id, stmt, &sql, &hash, Some("allow".to_string()));
        let mut _inflight_lock = self.inflight.lock().await;
        let audit_id = self.audit.record_started(event).await.map_err(|e| {
            // No audit event exists: the executor must see zero calls.
            // (No inflight registration: the STARTED row does not exist.)
            BastionError::AuditUnavailable(e.to_string())
        })?;
        // 8b. Register in-flight while holding the lock. The guard removes
        //     the ID on drop, covering every exit path: success, error,
        //     panic, async cancellation.
        _inflight_lock.insert(audit_id);
        drop(_inflight_lock);
        let _inflight_guard = InflightGuard { inflight: self.inflight.clone(), id: audit_id };

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
        // 12. Execute with cancellation + timeout. The child token lets
        //     the caller cancel independently of the gateway timeout.
        let cancel = parent_cancel.child_token();
        let started = Instant::now();
        let exec_result = tokio::time::timeout(options.timeout, self.executor.execute(&ctx, cancel.clone())).await;
        let elapsed_ms = started.elapsed().as_millis() as u64;

        match exec_result {
            Err(_) => {
                // Timeout WITHOUT a confirmed outcome: the database may
                // still be running the statement, it may have completed,
                // or the cancel may land later. We must not record this
                // as a plain failure — the outcome is unknown.
                // Audit `unknown_interrupted` and enter fail-closed mode;
                // the connection must be isolated (never reused) by the
                // real adapter, and an operator triages the record.
                cancel.cancel();
                let outcome = AuditOutcome {
                    status: AuditStatus::UnknownInterrupted,
                    success: None,
                    row_count: None,
                    duration_ms: Some(elapsed_ms as i64),
                    error_message: Some(
                        "execution timed out without a confirmed outcome; the statement may still be running"
                            .to_string(),
                    ),
                };
                self.finish_audit(audit_id, outcome).await?;
                // The outcome is unknown: refuse new executions until an
                // operator triages the `unknown_interrupted` record.
                // (The untriaged-interruptions check would also refuse on
                // the next call; latching immediately closes the gap.)
                self.fail_closed.store(true, Ordering::SeqCst);
                Err(BastionError::ExecutionTimeout)
            }
            Ok(Err(BastionError::ExecutionCancelled)) => {
                // The executor CONFIRMED the statement was cancelled
                // before completing: it had no effect. This is a clean
                // failure, not an unknown outcome — no fail-closed.
                let outcome = AuditOutcome {
                    status: AuditStatus::Failed,
                    success: Some(false),
                    row_count: None,
                    duration_ms: Some(elapsed_ms as i64),
                    error_message: Some("execution cancelled before completion".to_string()),
                };
                self.finish_audit(audit_id, outcome).await?;
                Err(BastionError::ExecutionCancelled)
            }
            Ok(Err(e)) => {
                let outcome = AuditOutcome {
                    status: AuditStatus::Failed,
                    success: Some(false),
                    row_count: None,
                    duration_ms: Some(elapsed_ms as i64),
                    error_message: Some(e.to_string()),
                };
                self.finish_audit(audit_id, outcome).await?;
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
                self.finish_audit(audit_id, outcome).await?;
                Ok(dto)
            }
        }
    }

    /// Record a terminal audit outcome. A failed write latches fail-closed:
    /// an executed statement with no audit record is the worst outcome,
    /// and we never claim the database operation was rolled back.
    /// (In-flight deregistration is handled by `InflightGuard`.)
    async fn finish_audit(&self, audit_id: Uuid, outcome: AuditOutcome) -> Result<()> {
        let write_failed = self.audit.record_finished(audit_id, outcome).await.is_err();
        if write_failed {
            self.fail_closed.store(true, Ordering::SeqCst);
            return Err(BastionError::AuditFailClosed);
        }
        Ok(())
    }
}

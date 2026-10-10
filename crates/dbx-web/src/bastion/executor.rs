//! Real DBX query executor (TASK-005C-3).
//!
//! Implements `dbx_bastion::query::QueryExecutor` against the live DBX
//! single-statement entry point. Security contract:
//! 1. Verify `sql_hash` against `ctx.sql` before anything else.
//! 2. Re-validate CONNECT on the asset immediately before dispatch
//!    (closes the gateway authorize → execute window for the most
//!    critical permission; the gateway already re-verified the full
//!    resource set).
//! 3. Refuse drivers that cannot prove cancellation, result limits,
//!    and connection isolation (currently: mysql, postgres only).
//! 4. Execute the exact SQL string via the cancel-token-capable entry
//!    point; register with `running_queries` so external cancel works.
//! 5. Enforce server-side `max_rows` / `max_bytes` / `timeout` from the
//!    context (never client-supplied).
//! 6. Map errors without leaking credentials, connection strings, or
//!    raw SQL.
//!
//! Timeout is never treated as "the database cancelled successfully":
//! on timeout the executor explicitly cancels via `running_queries`
//! and reports the outcome; the gateway maps unconfirmed outcomes to
//! `UNKNOWN_INTERRUPTED`.

use std::sync::Arc;
use std::time::Instant;

use dbx_bastion::auth::Clock;
use dbx_bastion::query::{ExecutionContext, QueryExecutor, QueryResultDto};
use dbx_bastion::rbac::{connect_check, AuthorizationCheck, Authorizer, SnapshotAuthorizer};
use dbx_bastion::storage::SqliteStore;
use dbx_bastion::{BastionError, Result};
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;

/// Drivers with proven interrupt + limit + isolation support.
/// Others are refused (fail-closed) until proven.
/// Matches on the `DatabaseType` debug name.
fn driver_supported(db_type: &str) -> bool {
    let lower = db_type.to_lowercase();
    lower.contains("mysql") || lower.contains("postgres")
}

pub struct DbxQueryExecutor {
    app: Arc<dbx_core::connection::AppState>,
    store: Arc<SqliteStore>,
    clock: Arc<dyn Clock>,
}

impl DbxQueryExecutor {
    pub fn new(app: Arc<dbx_core::connection::AppState>, store: Arc<SqliteStore>, clock: Arc<dyn Clock>) -> Self {
        Self { app, store, clock }
    }
}

#[async_trait::async_trait]
impl QueryExecutor for DbxQueryExecutor {
    async fn execute(&self, ctx: &ExecutionContext, cancel: CancellationToken) -> Result<QueryResultDto> {
        // 1. Hash binds the exact SQL analyzed by the gateway.
        let actual = Sha256::digest(ctx.sql.as_bytes());
        if actual.as_slice() != ctx.sql_hash {
            return Err(BastionError::Forbidden("sql hash mismatch".to_string()));
        }

        // 2. Re-validate CONNECT immediately before dispatch.
        let check = connect_check(ctx.asset_id);
        let authorizer = SnapshotAuthorizer::new(self.store.clone(), self.clock.clone());
        authorizer.authorize_batch(&ctx.principal, &[AuthorizationCheck::new(check.resource, check.action)]).await?;

        // 3. Resolve the connection config for driver gating.
        let db_type = {
            let configs = self.app.configs.read().await;
            let cfg = configs
                .get(&ctx.connection_id)
                .ok_or_else(|| BastionError::Forbidden(format!("connection {} not registered", ctx.connection_id)))?;
            format!("{:?}", cfg.db_type)
        };
        if !driver_supported(&db_type) {
            return Err(BastionError::Forbidden(format!(
                "driver {db_type:?} is not proven for verified execution (cancel/limits/isolation); refusing"
            )));
        }

        // 4. Register with running_queries so external cancel works.
        let execution_id = format!("bastion-{}", uuid::Uuid::new_v4());
        let registered = self.app.running_queries.register_task(
            execution_id.clone(),
            dbx_core::query::query_cancel::RunningTaskMetadata::query(
                ctx.connection_id.clone(),
                ctx.database.clone(),
                None,
            ),
        );
        let task_token = registered.token();
        // Link the gateway's cancellation to the registered task token.
        {
            let task_token = task_token.clone();
            tokio::spawn(async move {
                cancel.cancelled().await;
                task_token.cancel();
            });
        }

        // 5. Execute the exact SQL with server-side limits from ctx.
        let started = Instant::now();
        let options = dbx_core::query::QueryExecutionOptions {
            max_rows: Some(ctx.max_rows as usize),
            max_result_bytes: Some(ctx.max_bytes as usize),
            timeout_secs: Some(ctx.timeout.as_secs().max(1)),
            execution_id: Some(execution_id.clone()),
            await_cancel_completion: true,
            ..Default::default()
        };
        let result = dbx_core::query::execute_sql_statement_with_options_typed(
            &self.app,
            &ctx.connection_id,
            &ctx.database,
            &ctx.sql,
            None,
            Some(task_token),
            options,
        )
        .await;
        let elapsed_ms = started.elapsed().as_millis() as u64;

        // 6. Finish the registration (handles late cancels).
        registered.finish_with_late_cancel(&result, false);

        // 7. Map to the gateway DTO without leaking internals.
        match result {
            Ok(qr) => Ok(QueryResultDto {
                columns: qr.columns,
                rows: qr.rows.into_iter().map(|r| r.into_iter().map(|c| c.to_string()).collect()).collect(),
                affected_rows: Some(qr.affected_rows),
                truncated: qr.truncated,
                execution_time_ms: elapsed_ms,
            }),
            Err(e) => {
                // Explicitly cancel on error paths to avoid orphaned DB work.
                self.app.running_queries.cancel(&execution_id);
                Err(map_execution_error(e))
            }
        }
    }
}

/// Map DBX execution errors to gateway errors without leaking
/// credentials, connection strings, or raw SQL text.
fn map_execution_error(e: dbx_core::query::QueryExecutionError) -> BastionError {
    use dbx_core::query::QueryExecutionError as QEE;
    match e {
        QEE::Canceled { .. } => BastionError::ExecutionCancelled,
        QEE::Timeout(_) => BastionError::ExecutionTimeout,
        // Sql / SqlWithPosition / Legacy / Agent / DuckDb: sanitize to a
        // generic message. The SQL text itself is never echoed.
        QEE::Sql(_) | QEE::SqlWithPosition { .. } | QEE::Legacy(_) | QEE::Agent(_) | QEE::DuckDb { .. } => {
            BastionError::ExecutorFailed("database execution failed".to_string())
        }
    }
}

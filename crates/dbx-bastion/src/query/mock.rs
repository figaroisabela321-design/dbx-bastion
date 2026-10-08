//! Mock [`QueryExecutor`] for TASK-005B tests.
//!
//! Simulates the backend contract the real DBX adapter (TASK-005C) must
//! satisfy: exact-SQL execution, `sql_hash` verification, backend-side
//! `max_rows` / `max_bytes` / `timeout` enforcement, cancellation, and
//! sanitized errors. Every call is counted so tests can assert the
//! executor was never invoked on any deny path.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tokio_util::sync::CancellationToken;

use super::{sql_hash, ExecutionContext, QueryExecutor, QueryResultDto};
use crate::error::{BastionError, Result};

/// Configurable mock backend behavior.
#[derive(Debug, Clone)]
pub enum MockBehavior {
    /// Return synthetic rows.
    Success { columns: Vec<String>, rows: Vec<Vec<String>>, affected_rows: Option<u64> },
    /// Fail with a sanitized message (no internals leak).
    Fail(String),
    /// Never return (exercises gateway timeout / cancellation).
    Hang,
}

impl Default for MockBehavior {
    fn default() -> Self {
        Self::Success {
            columns: vec!["id".to_string()],
            rows: vec![vec!["1".to_string()], vec!["2".to_string()]],
            affected_rows: None,
        }
    }
}

pub struct MockExecutor {
    behavior: Mutex<MockBehavior>,
    calls: AtomicU64,
    /// The SQL strings actually received, in call order.
    seen_sql: Mutex<Vec<String>>,
}

impl MockExecutor {
    pub fn new() -> Self {
        Self { behavior: Mutex::new(MockBehavior::default()), calls: AtomicU64::new(0), seen_sql: Mutex::new(vec![]) }
    }

    pub fn set_behavior(&self, behavior: MockBehavior) {
        *self.behavior.lock().unwrap() = behavior;
    }

    /// How many times the executor was invoked. Every deny path must
    /// leave this at zero.
    pub fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }

    pub fn seen_sql(&self) -> Vec<String> {
        self.seen_sql.lock().unwrap().clone()
    }
}

impl Default for MockExecutor {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl QueryExecutor for MockExecutor {
    async fn execute(&self, ctx: &ExecutionContext, cancel: CancellationToken) -> Result<QueryResultDto> {
        // Analysis/execution consistency: the executor only runs the
        // exact SQL the gateway authorized.
        if sql_hash(&ctx.sql) != ctx.sql_hash {
            return Err(BastionError::ExecutorFailed("sql hash mismatch".to_string()));
        }
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.seen_sql.lock().unwrap().push(ctx.sql.clone());

        let start = Instant::now();
        let behavior = self.behavior.lock().unwrap().clone();

        // Cancellation races the behavior: a cancelled token aborts
        // immediately, mirroring a backend cancel.
        let run = async {
            match behavior {
                MockBehavior::Fail(msg) => Err(BastionError::ExecutorFailed(msg)),
                MockBehavior::Hang => {
                    // Sleep in small slices so cancellation is prompt.
                    loop {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                }
                MockBehavior::Success { columns, rows, affected_rows } => {
                    // Backend-side row cap.
                    let mut out_rows = rows;
                    let mut truncated = false;
                    if out_rows.len() as u64 > ctx.max_rows {
                        out_rows.truncate(ctx.max_rows as usize);
                        truncated = true;
                    }
                    // Backend-side byte cap (approximate: sum of cell
                    // bytes). Truncation is by whole rows, never by
                    // mid-cell slicing.
                    let mut bytes = 0u64;
                    let mut kept = Vec::with_capacity(out_rows.len());
                    for row in out_rows {
                        let row_bytes: u64 = row.iter().map(|c| c.len() as u64).sum();
                        if bytes + row_bytes > ctx.max_bytes && !kept.is_empty() {
                            truncated = true;
                            break;
                        }
                        bytes += row_bytes;
                        kept.push(row);
                    }
                    Ok(QueryResultDto {
                        columns,
                        rows: kept,
                        affected_rows,
                        truncated,
                        execution_time_ms: start.elapsed().as_millis() as u64,
                    })
                }
            }
        };

        tokio::select! {
            _ = cancel.cancelled() => Err(BastionError::ExecutionCancelled),
            res = run => res,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AuthenticatedPrincipal;

    fn test_ctx() -> ExecutionContext {
        // `#[non_exhaustive]`: only constructible inside the crate.
        ExecutionContext::new(
            AuthenticatedPrincipal::new(uuid::Uuid::new_v4(), "u".to_string(), uuid::Uuid::new_v4()),
            uuid::Uuid::new_v4(),
            "conn".to_string(),
            String::new(),
            "SELECT 1".to_string(),
            &crate::query::ExecutionOptions::default(),
        )
    }

    #[tokio::test]
    async fn cancellation_aborts_execution() {
        let ex = MockExecutor::new();
        ex.set_behavior(MockBehavior::Hang);
        let cancel = CancellationToken::new();
        let c2 = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            c2.cancel();
        });
        let err = ex.execute(&test_ctx(), cancel).await.expect_err("cancelled");
        assert!(matches!(err, BastionError::ExecutionCancelled));
    }

    #[tokio::test]
    async fn hash_mismatch_is_rejected() {
        let ex = MockExecutor::new();
        let mut ctx = test_ctx();
        ctx.sql_hash = [0u8; 32];
        let err = ex.execute(&ctx, CancellationToken::new()).await.expect_err("mismatch");
        assert!(matches!(err, BastionError::ExecutorFailed(_)));
        // The tampered call was not counted as an execution.
        assert_eq!(ex.calls(), 0);
    }
}

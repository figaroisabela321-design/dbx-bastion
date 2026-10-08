use thiserror::Error;

pub type Result<T> = std::result::Result<T, BastionError>;

/// All errors produced by the bastion domain and its storage layer.
///
/// Security-relevant failures are typed explicitly so callers are forced to
/// decide between fail-closed (deny) and fail-open. There is no generic
/// "ignore me" variant on purpose.
#[derive(Debug, Error)]
pub enum BastionError {
    #[error("storage error: {0}")]
    Storage(#[from] rusqlite::Error),

    #[error("storage task failed: {0}")]
    StorageTask(String),

    #[error("migration error: {0}")]
    Migration(String),

    #[error("invalid data: {0}")]
    InvalidData(String),

    /// Unified authentication failure. Returned for unknown user, wrong
    /// password and disabled account alike so callers cannot distinguish
    /// them (anti-enumeration).
    #[error("authentication failed")]
    AuthenticationFailed,

    #[error("session is invalid or expired")]
    InvalidSession,

    #[error("too many login attempts; try again later")]
    RateLimited,

    #[error("admin bootstrap already completed")]
    AlreadyBootstrapped,

    #[error("password does not meet policy: {0}")]
    WeakPassword(String),

    #[error("password hashing error: {0}")]
    PasswordHash(String),

    #[error("secret file has insecure permissions: {0}")]
    InsecureSecretFile(String),

    #[error("bootstrap error: {0}")]
    Bootstrap(String),

    /// A concurrent modification invalidated this operation's precondition
    /// (e.g. the password hash changed between verification and update).
    /// The caller should re-read current state and retry with fresh input.
    #[error("concurrent modification: {0}")]
    ConcurrentModification(String),

    #[error("forbidden: {0}")]
    Forbidden(String),

    /// Unified "not found" used where existence must not leak: unknown
    /// asset ids, assets the caller may not see, and soft-deleted assets
    /// all produce this same error. The web layer maps it to HTTP 404.
    #[error("not found: {0}")]
    NotFound(String),

    #[error("dbx connection adapter unavailable: {0}")]
    AdapterUnavailable(String),

    /// The SQL policy denied the statement (with the policy reason code).
    /// The database was never touched; audited as `blocked`.
    #[error("sql policy denied: {0}")]
    PolicyDenied(String),

    /// Policy returned `RequireApproval` but the approval service does not
    /// exist yet: denied, never executed.
    #[error("approval required: no approval service in V1")]
    ApprovalRequired,

    /// Production assets do not execute in TASK-005B, even for reads.
    #[error("production execution is disabled in V1")]
    ProductionDenied,

    /// The audit store was unavailable before execution: fail-closed, the
    /// executor was never called.
    #[error("audit unavailable: {0}")]
    AuditUnavailable(String),

    /// Untriaged `unknown_interrupted` audit records exist (or a local
    /// audit failure occurred): the gateway refuses new executions until
    /// an operator triages.
    #[error("audit fail-closed: untriaged interrupted executions exist")]
    AuditFailClosed,

    #[error("execution timed out")]
    ExecutionTimeout,

    #[error("execution was cancelled")]
    ExecutionCancelled,

    /// The executor failed; the audit record keeps the failure.
    #[error("execution failed: {0}")]
    ExecutorFailed(String),
}

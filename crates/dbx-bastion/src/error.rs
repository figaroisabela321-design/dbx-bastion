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
}

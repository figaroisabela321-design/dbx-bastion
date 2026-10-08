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
}

// `async_trait` generates `#[must_use]` on its desugared methods; clippy 1.99's
// `double_must_use` lint fires on that generated attribute (the return type is
// already `#[must_use]`). The attribute is not ours to remove, so allow it
// crate-wide.
#![allow(clippy::double_must_use)]

//! DB Bastion security domain.
//!
//! Dependency direction (must be kept):
//!
//! ```text
//! dbx-web
//!   |-- dbx-bastion   (this crate: auth/session principals, users, assets,
//!   |                  RBAC, SQL policy, approvals, audit, query gateway)
//!   |-- dbx-core      (database drivers, connection runtime, SQL execution)
//! ```
//!
//! This crate never depends on `dbx-core` or `dbx-web`. DBX integration
//! happens through the adapter traits in [`query`] (`SqlAnalyzer`,
//! `QueryExecutor`), implemented in `dbx-web`, so upstream DBX changes stay
//! at the adapter boundary.
//!
//! TASK-001 scope: domain types, repository traits, isolated SQLite storage
//! (`bastion.db`) with versioned migrations, and the [`BastionService`]
//! composition root.
//!
//! TASK-002 scope: multi-user authentication — [`auth::AuthService`]
//! (Argon2id passwords, persistent sessions, login rate limiting, one-time
//! admin bootstrap). RBAC evaluator, policy engine, approvals service, audit
//! sink and query gateway follow in later TASKs.

pub mod approval;
pub mod asset;
pub mod audit;
pub mod auth;
pub mod error;
pub mod policy;
pub mod query;
pub mod rbac;
pub mod storage;

pub use error::{BastionError, Result};

use std::path::Path;
use std::sync::Arc;

use auth::{AuthConfig, AuthService};
use storage::SqliteStore;

/// Composition root for the bastion domain.
///
/// Owns the isolated bastion storage and the authentication services built
/// on it. Constructing the service performs one Argon2id computation at
/// startup (pre-generated dummy hash for the unknown-user login path);
/// call `open` once at startup, not per request.
pub struct BastionService {
    store: Arc<SqliteStore>,
    auth: AuthService,
}

impl BastionService {
    /// Open the bastion database at `path`, creating it and applying pending
    /// migrations. Synchronous: call once at startup.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let store = Arc::new(SqliteStore::open(path)?);
        let auth = AuthService::new(store.clone(), AuthConfig::default())?;
        Ok(Self { store, auth })
    }

    /// Access to the isolated bastion storage (repository implementations).
    pub fn store(&self) -> &Arc<SqliteStore> {
        &self.store
    }

    /// Authentication services (login, sessions, rate limiter).
    /// The future web adapter must share this instance (especially the
    /// rate limiter) rather than constructing its own.
    pub fn auth(&self) -> &AuthService {
        &self.auth
    }
}

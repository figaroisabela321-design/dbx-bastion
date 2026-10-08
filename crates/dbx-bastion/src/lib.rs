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
//! composition root. Service implementations (auth/session, RBAC evaluator,
//! policy engine, approvals, audit sink, query gateway) follow in later TASKs.

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

use storage::SqliteStore;

/// Composition root for the bastion domain.
///
/// Owns the isolated bastion storage. Constructible without any service
/// implementation so TASK-001 changes no runtime behavior; services attach
/// in later TASKs.
#[derive(Clone)]
pub struct BastionService {
    store: Arc<SqliteStore>,
}

impl BastionService {
    /// Open the bastion database at `path`, creating it and applying pending
    /// migrations. Synchronous: call once at startup.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Ok(Self { store: Arc::new(SqliteStore::open(path)?) })
    }

    /// Access to the isolated bastion storage (repository implementations).
    pub fn store(&self) -> &Arc<SqliteStore> {
        &self.store
    }
}

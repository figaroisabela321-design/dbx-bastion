//! DBX connection mapping.
//!
//! An asset references a DBX connection by id (`dbx_connection_id`). The
//! bastion database never stores connection credentials — no host, no
//! usernames, no passwords, no private keys, no full `ConnectionConfig`.
//!
//! This module defines the [`DbxConnectionAdapter`] trait: the seam through
//! which the bastion asks DBX-side code "does this connection exist?" and
//! "is it reachable?". The real implementation lives on the `dbx-web` side
//! (a later TASK) per the required dependency direction:
//!
//! ```text
//! dbx-web
//!     ↓
//! Bastion domain/services (this crate)
//!     ↓
//! DBX adapters (this trait)
//!     ↓
//! dbx-core / database drivers
//! ```
//!
//! Contract for implementations: **returned data must never contain**
//! hostnames, database usernames, passwords, private keys, or a full
//! connection config. Only safe metadata and reachability facts cross the
//! boundary.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{BastionError, Result};

/// Last connection-test outcome stored on the asset row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConnectionTestStatus {
    Success,
    Failure,
}

impl ConnectionTestStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "success" => Some(Self::Success),
            "failure" => Some(Self::Failure),
            _ => None,
        }
    }
}

/// Result of a connection test. Credential-free by contract.
#[derive(Debug, Clone)]
pub struct ConnectionTestReport {
    pub connection_id: String,
    pub success: bool,
    pub latency_ms: Option<u64>,
    /// Safe server metadata (e.g. "MySQL 8.0.36"). No credentials.
    pub server_version: Option<String>,
    /// Human-readable summary. Must not contain credentials.
    pub message: String,
    pub tested_at: DateTime<Utc>,
}

/// Safe connection metadata. Credential-free by contract.
#[derive(Debug, Clone)]
pub struct ConnectionMetadata {
    pub connection_id: String,
    pub db_type: String,
    pub display_name: String,
}

#[async_trait]
pub trait DbxConnectionAdapter: Send + Sync {
    /// Whether the referenced DBX connection exists on the DBX side.
    /// Cross-database references have no reliable foreign key, so callers
    /// must check at use time, not just at asset creation.
    async fn connection_exists(&self, connection_id: &str) -> Result<bool>;

    /// Test reachability. Never fabricates success.
    async fn test_connection(&self, connection_id: &str) -> Result<ConnectionTestReport>;

    /// Safe metadata lookup. Default: not provided.
    async fn connection_metadata(&self, _connection_id: &str) -> Result<Option<ConnectionMetadata>> {
        Ok(None)
    }
}

/// Adapter used when no real DBX integration is wired. Every operation
/// fails explicitly with [`BastionError::AdapterUnavailable`] — production
/// code must never mistake "no adapter" for a successful test.
pub struct UnavailableDbxConnectionAdapter;

#[async_trait]
impl DbxConnectionAdapter for UnavailableDbxConnectionAdapter {
    async fn connection_exists(&self, _connection_id: &str) -> Result<bool> {
        Err(BastionError::AdapterUnavailable("no DBX connection adapter is wired; wire the dbx-web adapter".into()))
    }

    async fn test_connection(&self, _connection_id: &str) -> Result<ConnectionTestReport> {
        Err(BastionError::AdapterUnavailable("no DBX connection adapter is wired; wire the dbx-web adapter".into()))
    }
}

/// In-memory mock for tests. The test controls which connection ids exist
/// and what each test reports.
pub struct MockDbxConnectionAdapter {
    existing: Mutex<HashSet<String>>,
    test_results: Mutex<HashMap<String, bool>>,
}

impl MockDbxConnectionAdapter {
    pub fn new() -> Self {
        Self { existing: Mutex::new(HashSet::new()), test_results: Mutex::new(HashMap::new()) }
    }

    pub fn add_connection(&self, connection_id: &str) {
        self.existing.lock().unwrap().insert(connection_id.to_string());
    }

    /// Configure the next test outcome for a connection id.
    pub fn set_test_result(&self, connection_id: &str, success: bool) {
        self.add_connection(connection_id);
        self.test_results.lock().unwrap().insert(connection_id.to_string(), success);
    }
}

impl Default for MockDbxConnectionAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl DbxConnectionAdapter for MockDbxConnectionAdapter {
    async fn connection_exists(&self, connection_id: &str) -> Result<bool> {
        Ok(self.existing.lock().unwrap().contains(connection_id))
    }

    async fn test_connection(&self, connection_id: &str) -> Result<ConnectionTestReport> {
        if !self.connection_exists(connection_id).await? {
            return Err(BastionError::InvalidData(format!("unknown DBX connection: {connection_id}")));
        }
        let success = self.test_results.lock().unwrap().get(connection_id).copied().unwrap_or(true);
        Ok(ConnectionTestReport {
            connection_id: connection_id.to_string(),
            success,
            latency_ms: Some(7),
            server_version: Some("mock-db 1.0".to_string()),
            message: if success {
                "mock connection test succeeded".to_string()
            } else {
                "mock connection test failed: connection refused".to_string()
            },
            tested_at: Utc::now(),
        })
    }
}

//! Real DBX connection adapter (TASK-005C-2).
//!
//! Implements `dbx_bastion::asset::DbxConnectionAdapter` against the
//! live DBX [`AppState`]. This is the dependency-direction-allowed
//! seam: `dbx-web` depends on both `dbx-bastion` and `dbx-core`;
//! `dbx-bastion` never depends on `dbx-core`.
//!
//! Security: the adapter only answers "does this connection exist"
//! and basic metadata. Credentials, private keys, and full
//! `ConnectionConfig` values never leave the server through this
//! adapter — and the asset HTTP surface only exposes `AssetView`
//! DTOs, which exclude `dbx_connection_id` by construction.

use std::sync::Arc;

use dbx_bastion::asset::{ConnectionTestReport, DbxConnectionAdapter};
use dbx_bastion::Result;

/// Live adapter backed by the DBX connection registry.
pub struct WebDbxConnectionAdapter {
    app: Arc<dbx_core::connection::AppState>,
}

impl WebDbxConnectionAdapter {
    pub fn new(app: Arc<dbx_core::connection::AppState>) -> Self {
        Self { app }
    }
}

#[async_trait::async_trait]
impl DbxConnectionAdapter for WebDbxConnectionAdapter {
    /// The connection id is registered in the DBX runtime config map.
    async fn connection_exists(&self, connection_id: &str) -> Result<bool> {
        Ok(self.app.configs.read().await.contains_key(connection_id))
    }

    /// Lightweight liveness probe: existence only. A full connect test
    /// would open a real database connection; asset creation/rebind
    /// uses existence, and query execution performs its own connect.
    /// Never fabricates success: unknown ids report failure.
    async fn test_connection(&self, connection_id: &str) -> Result<ConnectionTestReport> {
        let exists = self.connection_exists(connection_id).await?;
        let message = if exists {
            "connection is registered".to_string()
        } else {
            format!("connection {connection_id:?} is not registered")
        };
        Ok(ConnectionTestReport {
            connection_id: connection_id.to_string(),
            success: exists,
            latency_ms: None,
            server_version: None,
            message,
            tested_at: chrono::Utc::now(),
        })
    }
}

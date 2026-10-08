//! Bastion assets.
//!
//! An asset answers "who may access this database". It maps 1:1 to a DBX
//! connection id, which answers "how to connect". Ordinary users only ever
//! handle `asset_id`; raw host/port/username/password are never exposed.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Environment {
    Development,
    Test,
    Staging,
    Production,
}

impl Environment {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Development => "development",
            Self::Test => "test",
            Self::Staging => "staging",
            Self::Production => "production",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "development" => Some(Self::Development),
            "test" => Some(Self::Test),
            "staging" => Some(Self::Staging),
            "production" => Some(Self::Production),
            _ => None,
        }
    }

    /// Production (and staging) assets get the strictest policy defaults.
    pub fn is_sensitive(self) -> bool {
        matches!(self, Self::Staging | Self::Production)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Asset {
    pub id: Uuid,
    pub name: String,
    pub environment: Environment,
    pub db_type: String,
    /// Internal DBX connection id. Never sent to the browser.
    pub dbx_connection_id: String,
    pub enabled: bool,
}

/// Persistence boundary for assets. Implemented by the storage layer;
/// a future PostgreSQL implementation only needs to satisfy this trait.
#[async_trait]
pub trait AssetRepository: Send + Sync {
    async fn resolve_asset(&self, asset_id: Uuid) -> Result<Option<Asset>>;
    async fn create_asset(&self, asset: &Asset) -> Result<()>;
}

/// Minimal credential record for the future auth service (later TASK).
/// Only the password *hash* is stored; verification happens in the service.
#[derive(Debug, Clone)]
pub struct UserCredentialRecord {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub password_hash: String,
    pub enabled: bool,
}

#[async_trait]
pub trait UserRepository: Send + Sync {
    async fn find_user_by_username(&self, username: &str) -> Result<Option<UserCredentialRecord>>;
}

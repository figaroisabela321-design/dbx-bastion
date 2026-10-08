//! Bastion assets.
//!
//! An asset answers "who may access this database". It references a DBX
//! connection id, which answers "how to connect". Ordinary users only ever
//! handle `asset_id`; raw host/port/username/password are never exposed —
//! not even to administrators through the asset API (see [`AssetView`]).
//!
//! Submodules:
//!
//! - [`group`] — asset groups (hierarchy + membership).
//! - [`service`] — [`service::AssetService`] and the [`service::AssetAdminGuard`].
//! - [`mapping`] — [`mapping::DbxConnectionAdapter`] trait (DBX side).

pub mod group;
pub mod mapping;
pub mod service;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::Result;

pub use group::{AssetGroup, AssetGroupRepository, NewAssetGroup, UpdateAssetGroup};
pub use mapping::{
    ConnectionMetadata, ConnectionTestReport, ConnectionTestStatus, DbxConnectionAdapter, MockDbxConnectionAdapter,
    UnavailableDbxConnectionAdapter,
};
pub use service::{AssetAdminGuard, AssetService};

/// Database types the bastion accepts. Whitelist enforced at the service
/// layer; the database column itself is free-form for forward compatibility.
pub const SUPPORTED_DB_TYPES: &[&str] = &["mysql", "postgresql", "oracle", "mssql", "sqlite"];

/// Maximum page size for asset listing.
pub const MAX_PAGE_SIZE: u32 = 100;

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

/// Full asset record. Internal use (administrators, services).
/// `dbx_connection_id` must never leave the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Asset {
    pub id: Uuid,
    pub name: String,
    pub environment: Environment,
    pub db_type: String,
    /// Internal DBX connection id. Never sent to the browser, never
    /// included in [`AssetView`].
    pub dbx_connection_id: String,
    pub enabled: bool,
    pub description: String,
    /// Soft delete marker. Deleted assets are hidden from listings and
    /// never resolved for new operations, but stay linkable from history.
    pub deleted_at: Option<DateTime<Utc>>,
    pub last_tested_at: Option<DateTime<Utc>>,
    pub last_test_status: Option<ConnectionTestStatus>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Ordinary-user view of an asset. By construction it cannot carry
/// `dbx_connection_id` or any database credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetView {
    pub id: Uuid,
    pub name: String,
    pub environment: Environment,
    pub db_type: String,
    pub description: String,
    pub enabled: bool,
}

impl From<&Asset> for AssetView {
    fn from(asset: &Asset) -> Self {
        Self {
            id: asset.id,
            name: asset.name.clone(),
            environment: asset.environment,
            db_type: asset.db_type.clone(),
            description: asset.description.clone(),
            enabled: asset.enabled,
        }
    }
}

/// Asset creation input. Deliberately contains no connection credentials:
/// only a reference (`dbx_connection_id`) that the service validates
/// against the [`DbxConnectionAdapter`]. Illegal states are
/// unrepresentable — a caller cannot submit host/port/password here.
#[derive(Debug, Clone)]
pub struct NewAsset {
    pub name: String,
    pub environment: String,
    pub db_type: String,
    pub dbx_connection_id: String,
    pub group_ids: Vec<Uuid>,
    pub description: String,
}

/// Asset update input. Note: no `dbx_connection_id` — rebinding a
/// connection is a separate controlled flow
/// ([`AssetService::rebind_connection`]).
#[derive(Debug, Clone, Default)]
pub struct UpdateAsset {
    pub name: Option<String>,
    pub environment: Option<String>,
    pub db_type: Option<String>,
    pub description: Option<String>,
    pub group_ids: Option<Vec<Uuid>>,
}

/// Sortable asset fields (whitelist by construction; never raw SQL input).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AssetSortField {
    #[default]
    Name,
    CreatedAt,
    UpdatedAt,
    Environment,
}

impl AssetSortField {
    pub(crate) fn column(self) -> &'static str {
        match self {
            Self::Name => "name",
            Self::CreatedAt => "created_at",
            Self::UpdatedAt => "updated_at",
            Self::Environment => "environment",
        }
    }
}

#[derive(Debug, Clone)]
pub struct PageRequest {
    /// 1-based page number.
    pub page: u32,
    /// Clamped to [`MAX_PAGE_SIZE`].
    pub page_size: u32,
    pub sort_by: AssetSortField,
    pub sort_desc: bool,
}

impl Default for PageRequest {
    fn default() -> Self {
        Self { page: 1, page_size: 20, sort_by: AssetSortField::Name, sort_desc: false }
    }
}

impl PageRequest {
    pub(crate) fn normalized(&self) -> (u32, u32) {
        let page = self.page.max(1);
        let page_size = self.page_size.clamp(1, MAX_PAGE_SIZE);
        (page, page_size)
    }
}

#[derive(Debug, Clone, Default)]
pub struct AssetFilter {
    pub environment: Option<Environment>,
    pub db_type: Option<String>,
    pub group_id: Option<Uuid>,
    pub name_contains: Option<String>,
    /// When false (default), disabled assets are hidden.
    pub include_disabled: bool,
}

#[derive(Debug, Clone)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub total: u64,
    pub page: u32,
    pub page_size: u32,
}

/// Persistence boundary for assets. Implemented by the storage layer;
/// a future PostgreSQL implementation only needs to satisfy this trait.
///
/// Soft-deleted rows are invisible to `resolve_asset` and `list_assets`;
/// they remain readable through history-linked queries (audit/work orders,
/// later TASKs).
#[async_trait]
pub trait AssetRepository: Send + Sync {
    /// Resolve a usable asset: enabled and not soft-deleted.
    async fn resolve_asset(&self, asset_id: Uuid) -> Result<Option<Asset>>;
    /// Full row regardless of enabled/deleted (service decides visibility).
    async fn find_asset_by_id(&self, asset_id: Uuid) -> Result<Option<Asset>>;
    async fn find_asset_by_name(&self, name: &str) -> Result<Option<Asset>>;
    async fn create_asset(&self, asset: &Asset) -> Result<()>;
    async fn update_asset(&self, asset_id: Uuid, patch: &AssetPatch) -> Result<Asset>;
    async fn set_asset_enabled(&self, asset_id: Uuid, enabled: bool) -> Result<()>;
    /// Soft delete: sets `deleted_at`. Never removes the row.
    async fn soft_delete_asset(&self, asset_id: Uuid) -> Result<()>;
    async fn rebind_connection(&self, asset_id: Uuid, new_connection_id: &str) -> Result<()>;
    async fn update_test_status(
        &self,
        asset_id: Uuid,
        tested_at: DateTime<Utc>,
        status: ConnectionTestStatus,
    ) -> Result<()>;
    async fn list_assets(&self, filter: &AssetFilter, page: &PageRequest) -> Result<Page<Asset>>;
}

/// Field patch for [`AssetRepository::update_asset`]. All fields optional;
/// `dbx_connection_id` is intentionally absent (see
/// [`AssetService::rebind_connection`]).
#[derive(Debug, Clone, Default)]
pub struct AssetPatch {
    pub name: Option<String>,
    pub environment: Option<Environment>,
    pub db_type: Option<String>,
    pub description: Option<String>,
}

/// Minimal credential record for the auth service.
/// Only the password *hash* is stored; verification happens in the service.
#[derive(Debug, Clone)]
pub struct UserCredentialRecord {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub password_hash: String,
    pub enabled: bool,
}

/// Parameters for creating a user. The password hash must already be
/// computed by [`crate::auth::password::PasswordService`]; this layer
/// never sees plaintext passwords.
#[derive(Debug, Clone)]
pub struct NewUser {
    pub username: String,
    pub display_name: String,
    pub password_hash: String,
}

#[async_trait]
pub trait UserRepository: Send + Sync {
    async fn find_user_by_username(&self, username: &str) -> Result<Option<UserCredentialRecord>>;
    async fn find_user_by_id(&self, user_id: Uuid) -> Result<Option<UserCredentialRecord>>;
    async fn create_user(&self, user: &NewUser) -> Result<Uuid>;
    /// Replace the stored password hash (admin reset path; the normal
    /// password-change flow revokes sessions atomically and does not use
    /// this method).
    async fn update_password_hash(&self, user_id: Uuid, password_hash: &str) -> Result<()>;
    async fn set_user_enabled(&self, user_id: Uuid, enabled: bool) -> Result<()>;
    /// Role names currently assigned to the user. Read fresh on every
    /// session validation so admin changes take effect immediately.
    async fn user_role_names(&self, user_id: Uuid) -> Result<Vec<String>>;
}

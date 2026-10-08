//! Asset groups: an optional hierarchy for organizing assets.
//!
//! Groups form a tree via `parent_id`. Assets join groups through the
//! `asset_group_members` many-to-many table. Groups are an organizing
//! unit for the future RBAC evaluator (P3); they carry no permissions
//! themselves in TASK-003.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::Result;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetGroup {
    pub id: Uuid,
    pub name: String,
    pub parent_id: Option<Uuid>,
    pub description: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct NewAssetGroup {
    pub name: String,
    pub parent_id: Option<Uuid>,
    pub description: String,
}

#[derive(Debug, Clone, Default)]
pub struct UpdateAssetGroup {
    pub name: Option<String>,
    pub description: Option<String>,
}

/// Persistence boundary for asset groups.
#[async_trait]
pub trait AssetGroupRepository: Send + Sync {
    async fn create_group(&self, group: &NewAssetGroup) -> Result<AssetGroup>;
    async fn find_group(&self, group_id: Uuid) -> Result<Option<AssetGroup>>;
    async fn find_group_by_name(&self, name: &str) -> Result<Option<AssetGroup>>;
    async fn update_group(&self, group_id: Uuid, patch: &UpdateAssetGroup) -> Result<AssetGroup>;
    async fn set_group_parent(&self, group_id: Uuid, parent_id: Option<Uuid>) -> Result<AssetGroup>;
    /// Delete an empty group. Implementations must refuse non-empty groups;
    /// the service enforces the policy, the repository executes it.
    async fn delete_group(&self, group_id: Uuid) -> Result<()>;
    async fn list_groups(&self) -> Result<Vec<AssetGroup>>;
    async fn child_groups(&self, group_id: Uuid) -> Result<Vec<AssetGroup>>;
    async fn add_asset_to_group(&self, asset_id: Uuid, group_id: Uuid) -> Result<()>;
    async fn remove_asset_from_group(&self, asset_id: Uuid, group_id: Uuid) -> Result<()>;
    async fn group_member_count(&self, group_id: Uuid) -> Result<u64>;
    async fn asset_groups(&self, asset_id: Uuid) -> Result<Vec<AssetGroup>>;
    async fn set_asset_groups(&self, asset_id: Uuid, group_ids: &[Uuid]) -> Result<()>;
}

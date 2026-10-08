//! Asset management service.
//!
//! [`AssetService`] owns asset CRUD, grouping, the DBX connection mapping
//! and connection testing. Every management operation passes through
//! [`AssetAdminGuard`], which re-reads the caller's enabled flag and roles
//! from the database — the `roles` snapshot on [`Principal`] is never
//! trusted for authorization.
//!
//! Credential boundary: [`NewAsset`] cannot express host/port/username/
//! password by construction; [`crate::asset::AssetView`] cannot carry
//! `dbx_connection_id`. The full [`crate::asset::Asset`] (with the
//! connection reference) is only returned to administrators.

use std::sync::Arc;

use chrono::Utc;
use uuid::Uuid;

use crate::asset::group::{AssetGroup, NewAssetGroup, UpdateAssetGroup};
use crate::asset::mapping::{ConnectionTestReport, ConnectionTestStatus, DbxConnectionAdapter};
use crate::asset::{
    Asset, AssetFilter, AssetGroupRepository, AssetPatch, AssetRepository, AssetView, Environment, NewAsset, Page,
    PageRequest, UpdateAsset, UserRepository, SUPPORTED_DB_TYPES,
};
use crate::auth::bootstrap::ADMIN_ROLE_NAME;
use crate::auth::Principal;
use crate::error::{BastionError, Result};
use crate::storage::SqliteStore;

/// Re-reads the caller from the trusted repository and requires the
/// platform asset-administration role (`bastion-admin` in TASK-003; a
/// dedicated role may replace it later). Administrator identity never
/// implies database data-operation permissions — those are granted by the
/// future RBAC evaluator (P3).
pub struct AssetAdminGuard {
    store: Arc<SqliteStore>,
}

impl AssetAdminGuard {
    pub fn new(store: Arc<SqliteStore>) -> Self {
        Self { store }
    }

    /// Verify the caller is an enabled platform asset administrator.
    /// Returns the verified user id.
    pub async fn check(&self, principal: &Principal) -> Result<Uuid> {
        let user = self.store.find_user_by_id(principal.user_id).await?.ok_or(BastionError::AuthenticationFailed)?;
        if !user.enabled {
            return Err(BastionError::AuthenticationFailed);
        }
        let roles = self.store.user_role_names(user.id).await?;
        if !roles.iter().any(|role| role == ADMIN_ROLE_NAME) {
            return Err(BastionError::Forbidden("asset administration requires the bastion-admin role".into()));
        }
        Ok(user.id)
    }

    /// Verify the caller is an enabled authenticated user (no admin role
    /// required). Used for the credential-free view endpoints.
    pub async fn check_authenticated(&self, principal: &Principal) -> Result<Uuid> {
        let user = self.store.find_user_by_id(principal.user_id).await?.ok_or(BastionError::AuthenticationFailed)?;
        if !user.enabled {
            return Err(BastionError::AuthenticationFailed);
        }
        Ok(user.id)
    }
}

pub struct AssetService {
    store: Arc<SqliteStore>,
    guard: AssetAdminGuard,
    dbx: Arc<dyn DbxConnectionAdapter>,
}

impl AssetService {
    pub fn new(store: Arc<SqliteStore>, dbx: Arc<dyn DbxConnectionAdapter>) -> Self {
        Self { guard: AssetAdminGuard::new(store.clone()), store, dbx }
    }

    pub fn guard(&self) -> &AssetAdminGuard {
        &self.guard
    }

    // ---- validation ------------------------------------------------------

    fn validate_name(name: &str) -> Result<String> {
        let name = name.trim();
        if name.is_empty() {
            return Err(BastionError::InvalidData("asset name must not be blank".into()));
        }
        if name.len() > 128 {
            return Err(BastionError::InvalidData("asset name too long (max 128 bytes)".into()));
        }
        Ok(name.to_string())
    }

    fn validate_group_name(name: &str) -> Result<String> {
        let name = name.trim();
        if name.is_empty() {
            return Err(BastionError::InvalidData("group name must not be blank".into()));
        }
        if name.len() > 128 {
            return Err(BastionError::InvalidData("group name too long (max 128 bytes)".into()));
        }
        Ok(name.to_string())
    }

    fn validate_environment(value: &str) -> Result<Environment> {
        Environment::parse(value.trim()).ok_or_else(|| {
            BastionError::InvalidData(format!(
                "invalid environment: {value} (expected development|test|staging|production)"
            ))
        })
    }

    fn validate_db_type(value: &str) -> Result<String> {
        let normalized = value.trim().to_lowercase();
        if !SUPPORTED_DB_TYPES.contains(&normalized.as_str()) {
            return Err(BastionError::InvalidData(format!(
                "unsupported db_type: {value} (expected one of {})",
                SUPPORTED_DB_TYPES.join(", ")
            )));
        }
        Ok(normalized)
    }

    fn validate_description(value: &str) -> Result<String> {
        let value = value.trim();
        if value.chars().count() > 1024 {
            return Err(BastionError::InvalidData("description too long (max 1024 chars)".into()));
        }
        Ok(value.to_string())
    }

    async fn ensure_groups_exist(&self, group_ids: &[Uuid]) -> Result<()> {
        for group_id in group_ids {
            if self.store.find_group(*group_id).await?.is_none() {
                return Err(BastionError::InvalidData(format!("asset group not found: {group_id}")));
            }
        }
        Ok(())
    }

    async fn get_usable_asset(&self, asset_id: Uuid) -> Result<Asset> {
        let asset = self
            .store
            .find_asset_by_id(asset_id)
            .await?
            .ok_or_else(|| BastionError::InvalidData(format!("asset not found: {asset_id}")))?;
        if asset.deleted_at.is_some() {
            return Err(BastionError::InvalidData(format!("asset is deleted: {asset_id}")));
        }
        Ok(asset)
    }

    // ---- asset CRUD (admin) ------------------------------------------------

    /// Create an asset. The referenced DBX connection must exist; group ids
    /// must exist. Name uniqueness is enforced by the service and backed by
    /// a UNIQUE index (race-safe).
    pub async fn create_asset(&self, principal: &Principal, input: NewAsset) -> Result<Asset> {
        self.guard.check(principal).await?;
        let name = Self::validate_name(&input.name)?;
        let environment = Self::validate_environment(&input.environment)?;
        let db_type = Self::validate_db_type(&input.db_type)?;
        let description = Self::validate_description(&input.description)?;
        let connection_id = input.dbx_connection_id.trim();
        if connection_id.is_empty() {
            return Err(BastionError::InvalidData("dbx_connection_id must not be blank".into()));
        }
        if self.store.find_asset_by_name(&name).await?.is_some() {
            return Err(BastionError::InvalidData("asset name already exists".into()));
        }
        // The connection reference must be valid at creation time. It is
        // re-confirmed at use time because cross-database references have
        // no reliable foreign key.
        if !self.dbx.connection_exists(connection_id).await? {
            return Err(BastionError::InvalidData(format!("unknown DBX connection: {connection_id}")));
        }
        self.ensure_groups_exist(&input.group_ids).await?;

        let now = Utc::now();
        let asset = Asset {
            id: Uuid::new_v4(),
            name,
            environment,
            db_type,
            dbx_connection_id: connection_id.to_string(),
            enabled: true,
            description,
            deleted_at: None,
            last_tested_at: None,
            last_test_status: None,
            created_at: now,
            updated_at: now,
        };
        self.store.create_asset(&asset).await?;
        if !input.group_ids.is_empty() {
            self.store.set_asset_groups(asset.id, &input.group_ids).await?;
        }
        Ok(asset)
    }

    /// Update asset fields. `dbx_connection_id` cannot be changed here;
    /// use [`Self::rebind_connection`].
    pub async fn update_asset(&self, principal: &Principal, asset_id: Uuid, input: UpdateAsset) -> Result<Asset> {
        self.guard.check(principal).await?;
        let asset = self.get_usable_asset(asset_id).await?;

        let name = input.name.as_deref().map(Self::validate_name).transpose()?;
        if let Some(ref name) = name {
            if let Some(existing) = self.store.find_asset_by_name(name).await? {
                if existing.id != asset_id {
                    return Err(BastionError::InvalidData("asset name already exists".into()));
                }
            }
        }
        let environment = input.environment.as_deref().map(Self::validate_environment).transpose()?;
        let db_type = input.db_type.as_deref().map(Self::validate_db_type).transpose()?;
        let description = input.description.as_deref().map(Self::validate_description).transpose()?;
        if let Some(ref group_ids) = input.group_ids {
            self.ensure_groups_exist(group_ids).await?;
        }

        let patch = AssetPatch { name, environment, db_type, description };
        let updated = self.store.update_asset(asset.id, &patch).await?;
        if let Some(group_ids) = input.group_ids {
            self.store.set_asset_groups(asset.id, &group_ids).await?;
        }
        Ok(updated)
    }

    pub async fn set_asset_enabled(&self, principal: &Principal, asset_id: Uuid, enabled: bool) -> Result<Asset> {
        self.guard.check(principal).await?;
        let asset = self.get_usable_asset(asset_id).await?;
        self.store.set_asset_enabled(asset.id, enabled).await?;
        self.store
            .find_asset_by_id(asset.id)
            .await?
            .ok_or_else(|| BastionError::InvalidData(format!("asset not found: {asset_id}")))
    }

    /// Soft delete. The row stays for audit/work-order history; listings
    /// and `resolve_asset` hide it. Does not touch the DBX connection.
    pub async fn delete_asset(&self, principal: &Principal, asset_id: Uuid) -> Result<()> {
        self.guard.check(principal).await?;
        let asset = self.get_usable_asset(asset_id).await?;
        self.store.soft_delete_asset(asset.id).await
    }

    /// Rebind the DBX connection reference. Separate controlled flow: the
    /// new reference must exist, and ordinary update cannot rebind.
    pub async fn rebind_connection(
        &self,
        principal: &Principal,
        asset_id: Uuid,
        new_connection_id: &str,
    ) -> Result<Asset> {
        self.guard.check(principal).await?;
        let asset = self.get_usable_asset(asset_id).await?;
        let new_connection_id = new_connection_id.trim();
        if new_connection_id.is_empty() {
            return Err(BastionError::InvalidData("dbx_connection_id must not be blank".into()));
        }
        if !self.dbx.connection_exists(new_connection_id).await? {
            return Err(BastionError::InvalidData(format!("unknown DBX connection: {new_connection_id}")));
        }
        self.store.rebind_connection(asset.id, new_connection_id).await?;
        self.store
            .find_asset_by_id(asset.id)
            .await?
            .ok_or_else(|| BastionError::InvalidData(format!("asset not found: {asset_id}")))
    }

    /// Full asset record (includes `dbx_connection_id`). Administrators only.
    pub async fn get_asset(&self, principal: &Principal, asset_id: Uuid) -> Result<Asset> {
        self.guard.check(principal).await?;
        self.get_usable_asset(asset_id).await
    }

    /// Paginated asset listing (full records). Administrators only.
    pub async fn list_assets(
        &self,
        principal: &Principal,
        filter: AssetFilter,
        page: PageRequest,
    ) -> Result<Page<Asset>> {
        self.guard.check(principal).await?;
        self.store.list_assets(&filter, &page).await
    }

    /// Credential-free view for one asset. Authenticated users only.
    /// NOTE (TASK-003): visibility is not yet authorization-scoped; P3 RBAC
    /// will filter to granted asset IDs. The DTO guarantee (no
    /// `dbx_connection_id`, no credentials) holds from day one.
    pub async fn get_asset_view(&self, principal: &Principal, asset_id: Uuid) -> Result<AssetView> {
        self.guard.check_authenticated(principal).await?;
        let asset = self
            .store
            .resolve_asset(asset_id)
            .await?
            .ok_or_else(|| BastionError::InvalidData(format!("asset not found: {asset_id}")))?;
        Ok(AssetView::from(&asset))
    }

    /// Credential-free paginated listing. Same TASK-003 visibility note as
    /// [`Self::get_asset_view`].
    pub async fn list_asset_views(
        &self,
        principal: &Principal,
        filter: AssetFilter,
        page: PageRequest,
    ) -> Result<Page<AssetView>> {
        self.guard.check_authenticated(principal).await?;
        let page_result = self.store.list_assets(&filter, &page).await?;
        let items = page_result.items.iter().map(AssetView::from).collect();
        Ok(Page { items, total: page_result.total, page: page_result.page, page_size: page_result.page_size })
    }

    /// Test the asset's DBX connection (admin action). Re-confirms the
    /// mapping, runs the test through the adapter, and records the outcome
    /// on the asset row. The report is credential-free by adapter contract.
    pub async fn test_connection(&self, principal: &Principal, asset_id: Uuid) -> Result<ConnectionTestReport> {
        self.guard.check(principal).await?;
        let asset = self.get_usable_asset(asset_id).await?;
        if !self.dbx.connection_exists(&asset.dbx_connection_id).await? {
            return Err(BastionError::InvalidData(format!(
                "DBX connection '{}' no longer exists",
                asset.dbx_connection_id
            )));
        }
        let report = self.dbx.test_connection(&asset.dbx_connection_id).await?;
        self.store
            .update_test_status(
                asset.id,
                report.tested_at,
                if report.success { ConnectionTestStatus::Success } else { ConnectionTestStatus::Failure },
            )
            .await?;
        Ok(report)
    }

    // ---- groups (admin) -----------------------------------------------------

    pub async fn create_group(&self, principal: &Principal, input: NewAssetGroup) -> Result<AssetGroup> {
        self.guard.check(principal).await?;
        let name = Self::validate_group_name(&input.name)?;
        let description = Self::validate_description(&input.description)?;
        if self.store.find_group_by_name(&name).await?.is_some() {
            return Err(BastionError::InvalidData("asset group name already exists".into()));
        }
        if let Some(parent_id) = input.parent_id {
            if self.store.find_group(parent_id).await?.is_none() {
                return Err(BastionError::InvalidData(format!("parent group not found: {parent_id}")));
            }
        }
        let group = NewAssetGroup { name, parent_id: input.parent_id, description };
        self.store.create_group(&group).await
    }

    pub async fn update_group(
        &self,
        principal: &Principal,
        group_id: Uuid,
        input: UpdateAssetGroup,
    ) -> Result<AssetGroup> {
        self.guard.check(principal).await?;
        self.get_group(group_id).await?;
        let name = input.name.as_deref().map(Self::validate_group_name).transpose()?;
        if let Some(ref name) = name {
            if let Some(existing) = self.store.find_group_by_name(name).await? {
                if existing.id != group_id {
                    return Err(BastionError::InvalidData("asset group name already exists".into()));
                }
            }
        }
        let description = input.description.as_deref().map(Self::validate_description).transpose()?;
        let patch = UpdateAssetGroup { name, description };
        self.store.update_group(group_id, &patch).await
    }

    /// Move a group under a new parent (`None` = root). Rejects hierarchy
    /// cycles, including self-parenting.
    pub async fn move_group(
        &self,
        principal: &Principal,
        group_id: Uuid,
        new_parent_id: Option<Uuid>,
    ) -> Result<AssetGroup> {
        self.guard.check(principal).await?;
        self.get_group(group_id).await?;
        if let Some(parent_id) = new_parent_id {
            if self.store.find_group(parent_id).await?.is_none() {
                return Err(BastionError::InvalidData(format!("parent group not found: {parent_id}")));
            }
            self.ensure_no_cycle(group_id, parent_id).await?;
        }
        self.store.set_group_parent(group_id, new_parent_id).await
    }

    async fn ensure_no_cycle(&self, group_id: Uuid, new_parent_id: Uuid) -> Result<()> {
        let mut current = Some(new_parent_id);
        while let Some(ancestor) = current {
            if ancestor == group_id {
                return Err(BastionError::InvalidData("group hierarchy would contain a cycle".into()));
            }
            let group = self
                .store
                .find_group(ancestor)
                .await?
                .ok_or_else(|| BastionError::InvalidData(format!("group not found: {ancestor}")))?;
            current = group.parent_id;
        }
        Ok(())
    }

    /// Delete a group. Refuses non-empty groups (members or child groups):
    /// the operator must empty the group first. No cascading deletes.
    pub async fn delete_group(&self, principal: &Principal, group_id: Uuid) -> Result<()> {
        self.guard.check(principal).await?;
        self.get_group(group_id).await?;
        let members = self.store.group_member_count(group_id).await?;
        if members > 0 {
            return Err(BastionError::InvalidData("cannot delete group with member assets; remove them first".into()));
        }
        let children = self.store.child_groups(group_id).await?;
        if !children.is_empty() {
            return Err(BastionError::InvalidData(
                "cannot delete group with child groups; move or delete them first".into(),
            ));
        }
        self.store.delete_group(group_id).await
    }

    pub async fn list_groups(&self, principal: &Principal) -> Result<Vec<AssetGroup>> {
        self.guard.check(principal).await?;
        self.store.list_groups().await
    }

    pub async fn add_asset_to_group(&self, principal: &Principal, asset_id: Uuid, group_id: Uuid) -> Result<()> {
        self.guard.check(principal).await?;
        self.get_usable_asset(asset_id).await?;
        self.get_group(group_id).await?;
        self.store.add_asset_to_group(asset_id, group_id).await
    }

    pub async fn remove_asset_from_group(&self, principal: &Principal, asset_id: Uuid, group_id: Uuid) -> Result<()> {
        self.guard.check(principal).await?;
        self.get_usable_asset(asset_id).await?;
        self.get_group(group_id).await?;
        self.store.remove_asset_from_group(asset_id, group_id).await
    }

    pub async fn asset_groups(&self, principal: &Principal, asset_id: Uuid) -> Result<Vec<AssetGroup>> {
        self.guard.check(principal).await?;
        self.get_usable_asset(asset_id).await?;
        self.store.asset_groups(asset_id).await
    }

    async fn get_group(&self, group_id: Uuid) -> Result<AssetGroup> {
        self.store
            .find_group(group_id)
            .await?
            .ok_or_else(|| BastionError::InvalidData(format!("asset group not found: {group_id}")))
    }
}

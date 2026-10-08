//! Grant administration (management plane).
//!
//! [`GrantService`] is the only writer of `permissions` rows. Every method
//! requires the platform administrator role, re-verified against the
//! database on each call by [`AssetAdminGuard`]. Managing grants is a
//! platform administration function; it never confers database data
//! permissions — those are decided by the [`Authorizer`](super::Authorizer).
//!
//! Invariants enforced here (the database CHECK in `0004_rbac.sql` is the
//! backstop):
//! - every grant binds exactly one [`AssetScope`] (XOR by construction);
//! - CONNECT grants are asset-level only (no database/schema/table scope);
//! - `"*"` patterns are normalized to the canonical wildcard (`NULL`);
//! - `expires_at`, when set, must be a future RFC3339 timestamp.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::asset::service::AssetAdminGuard;
use crate::asset::{AssetGroupRepository, AssetRepository};
use crate::auth::session::Clock;
use crate::auth::AuthenticatedPrincipal;
use crate::error::{BastionError, Result};
use crate::rbac::resource::normalize_pattern;
use crate::rbac::{Action, Effect};
use crate::storage::SqliteStore;

/// Minimal role record for grant administration.
#[derive(Debug, Clone)]
pub struct RoleInfo {
    pub id: Uuid,
    pub name: String,
}

/// The asset range one grant applies to. Exactly one variant: the
/// "both null / both set" states are unrepresentable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssetScope {
    Asset(Uuid),
    Group(Uuid),
}

/// Input for creating a grant. `None` on a level means "any";
/// `Some("*")` is normalized to `None` on write.
#[derive(Debug, Clone)]
pub struct NewGrant {
    pub role_id: Uuid,
    pub effect: Effect,
    pub action: Action,
    pub scope: AssetScope,
    pub database: Option<String>,
    pub schema: Option<String>,
    pub table: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Stored grant row (read model for administration).
#[derive(Debug, Clone)]
pub struct GrantView {
    pub id: Uuid,
    pub role_id: Uuid,
    pub role_name: String,
    pub effect: Effect,
    pub action: Action,
    pub scope: AssetScope,
    pub database: Option<String>,
    pub schema: Option<String>,
    pub table: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Raw persistence record. The service maps it to [`GrantView`].
#[derive(Debug, Clone)]
pub(crate) struct GrantRecord {
    pub id: Uuid,
    pub role_id: Uuid,
    pub effect: Effect,
    pub action: Action,
    pub asset_id: Option<Uuid>,
    pub asset_group_id: Option<Uuid>,
    pub database: Option<String>,
    pub schema: Option<String>,
    pub table: Option<String>,
    pub expires_at: Option<String>,
    pub created_at: String,
}

impl GrantRecord {
    pub fn scope(&self) -> Result<AssetScope> {
        match (self.asset_id, self.asset_group_id) {
            (Some(id), None) => Ok(AssetScope::Asset(id)),
            (None, Some(id)) => Ok(AssetScope::Group(id)),
            // Unreachable while the CHECK constraint holds; fail closed.
            _ => Err(BastionError::InvalidData(format!("grant {} violates asset scope XOR", self.id))),
        }
    }
}

pub struct GrantService {
    store: Arc<SqliteStore>,
    guard: AssetAdminGuard,
    clock: Arc<dyn Clock>,
}

impl GrantService {
    pub fn new(store: Arc<SqliteStore>, clock: Arc<dyn Clock>) -> Self {
        Self { guard: AssetAdminGuard::new(store.clone()), store, clock }
    }

    fn now(&self) -> DateTime<Utc> {
        self.clock.now()
    }

    /// Create a grant. Platform administrators only.
    pub async fn create_grant(&self, principal: &AuthenticatedPrincipal, grant: NewGrant) -> Result<Uuid> {
        self.guard.check(principal).await?;

        // Referenced rows must exist.
        if self.store.find_role_by_id(grant.role_id).await?.is_none() {
            return Err(BastionError::InvalidData(format!("role not found: {}", grant.role_id)));
        }
        match grant.scope {
            AssetScope::Asset(id) => {
                if self.store.find_asset_by_id(id).await?.is_none() {
                    return Err(BastionError::InvalidData(format!("asset not found: {id}")));
                }
            }
            AssetScope::Group(id) => {
                if self.store.find_group(id).await?.is_none() {
                    return Err(BastionError::InvalidData(format!("asset group not found: {id}")));
                }
            }
        }

        let database = normalize_pattern(grant.database);
        let schema = normalize_pattern(grant.schema);
        let table = normalize_pattern(grant.table);

        // CONNECT is asset-level only: scoped CONNECT grants are rejected.
        if grant.action == Action::Connect && (database.is_some() || schema.is_some() || table.is_some()) {
            return Err(BastionError::InvalidData("connect grants must not scope database/schema/table".into()));
        }

        // Expiry must be a future timestamp; an already-expired grant is a
        // no-op that only invites confusion.
        if let Some(expires_at) = grant.expires_at {
            if expires_at <= self.now() {
                return Err(BastionError::InvalidData("expires_at must be in the future".into()));
            }
        }

        let (asset_id, asset_group_id) = match grant.scope {
            AssetScope::Asset(id) => (Some(id), None),
            AssetScope::Group(id) => (None, Some(id)),
        };
        self.store
            .insert_grant(
                grant.role_id,
                grant.effect,
                grant.action,
                asset_id,
                asset_group_id,
                database,
                schema,
                table,
                grant.expires_at,
            )
            .await
    }

    /// Revoke one grant by id. Returns `true` if a row was deleted.
    /// Platform administrators only.
    pub async fn revoke_grant(&self, principal: &AuthenticatedPrincipal, grant_id: Uuid) -> Result<bool> {
        self.guard.check(principal).await?;
        self.store.delete_grant(grant_id).await
    }

    /// Revoke every grant scoped to an asset group. This is the explicit
    /// step required before a group with grants can be deleted
    /// (`ON DELETE RESTRICT`): grant disappearance is always an explicit
    /// management action, never a cascade side effect.
    pub async fn revoke_grants_for_group(&self, principal: &AuthenticatedPrincipal, group_id: Uuid) -> Result<u64> {
        self.guard.check(principal).await?;
        self.store.delete_grants_for_group(group_id).await
    }

    /// Revoke every grant scoped to an asset. Explicit management action;
    /// assets themselves are soft-deleted, so this is for cleanup.
    pub async fn revoke_grants_for_asset(&self, principal: &AuthenticatedPrincipal, asset_id: Uuid) -> Result<u64> {
        self.guard.check(principal).await?;
        self.store.delete_grants_for_asset(asset_id).await
    }

    /// List all grants (administration view).
    pub async fn list_grants(&self, principal: &AuthenticatedPrincipal) -> Result<Vec<GrantView>> {
        self.guard.check(principal).await?;
        let records = self.store.list_grants().await?;
        let mut views = Vec::with_capacity(records.len());
        for record in records {
            views.push(self.to_view(record).await?);
        }
        Ok(views)
    }

    async fn to_view(&self, record: GrantRecord) -> Result<GrantView> {
        let role_name = self
            .store
            .find_role_by_id(record.role_id)
            .await?
            .map(|role| role.name)
            .unwrap_or_else(|| "<deleted>".to_string());
        Ok(GrantView {
            id: record.id,
            role_id: record.role_id,
            role_name,
            effect: record.effect,
            action: record.action,
            scope: record.scope()?,
            database: record.database,
            schema: record.schema,
            table: record.table,
            expires_at: record
                .expires_at
                .map(|raw| {
                    raw.parse::<DateTime<Utc>>()
                        .map_err(|_| BastionError::InvalidData(format!("grant {} has malformed expires_at", record.id)))
                })
                .transpose()?,
            created_at: record
                .created_at
                .parse::<DateTime<Utc>>()
                .map_err(|_| BastionError::InvalidData(format!("grant {} has malformed created_at", record.id)))?,
        })
    }

    // ---- role management (RBAC administration) ---------------------------

    pub async fn create_role(&self, principal: &AuthenticatedPrincipal, name: &str, description: &str) -> Result<Uuid> {
        self.guard.check(principal).await?;
        let name = name.trim();
        if name.is_empty() || name.len() > 128 {
            return Err(BastionError::InvalidData("role name must be 1-128 characters".into()));
        }
        self.store.insert_role(name, description).await
    }

    pub async fn assign_role_to_user(
        &self,
        principal: &AuthenticatedPrincipal,
        user_id: Uuid,
        role_id: Uuid,
    ) -> Result<()> {
        self.guard.check(principal).await?;
        self.store.assign_role_to_user(user_id, role_id).await
    }

    pub async fn remove_role_from_user(
        &self,
        principal: &AuthenticatedPrincipal,
        user_id: Uuid,
        role_id: Uuid,
    ) -> Result<()> {
        self.guard.check(principal).await?;
        self.store.remove_role_from_user(user_id, role_id).await
    }

    // ---- user group management (RBAC administration) --------------------

    pub async fn create_user_group(
        &self,
        principal: &AuthenticatedPrincipal,
        name: &str,
        description: &str,
    ) -> Result<Uuid> {
        self.guard.check(principal).await?;
        let name = name.trim();
        if name.is_empty() || name.len() > 128 {
            return Err(BastionError::InvalidData("user group name must be 1-128 characters".into()));
        }
        self.store.create_user_group(name, description).await
    }

    pub async fn add_user_to_group(
        &self,
        principal: &AuthenticatedPrincipal,
        user_id: Uuid,
        group_id: Uuid,
    ) -> Result<()> {
        self.guard.check(principal).await?;
        self.store.add_user_to_group(user_id, group_id).await
    }

    pub async fn remove_user_from_group(
        &self,
        principal: &AuthenticatedPrincipal,
        user_id: Uuid,
        group_id: Uuid,
    ) -> Result<()> {
        self.guard.check(principal).await?;
        self.store.remove_user_from_group(user_id, group_id).await
    }

    pub async fn add_role_to_group(
        &self,
        principal: &AuthenticatedPrincipal,
        role_id: Uuid,
        group_id: Uuid,
    ) -> Result<()> {
        self.guard.check(principal).await?;
        if self.store.find_role_by_id(role_id).await?.is_none() {
            return Err(BastionError::InvalidData(format!("role not found: {role_id}")));
        }
        self.store.add_role_to_group(role_id, group_id).await
    }

    pub async fn remove_role_from_group(
        &self,
        principal: &AuthenticatedPrincipal,
        role_id: Uuid,
        group_id: Uuid,
    ) -> Result<()> {
        self.guard.check(principal).await?;
        self.store.remove_role_from_group(role_id, group_id).await
    }
}

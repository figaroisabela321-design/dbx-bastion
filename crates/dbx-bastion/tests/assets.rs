//! TASK-003 integration tests: asset management.
//!
//! Covers: asset CRUD, name uniqueness, the admin guard (role re-read from
//! the DB, disabled users, stale Principal.roles), soft delete vs disable,
//! asset groups (hierarchy, cycle rejection, non-empty delete refusal),
//! the DBX connection adapter seam (mock + unavailable), credential-free
//! DTOs, input validation, pagination/sort boundaries, and migration
//! 0002 -> 0003 upgrade/idempotence/rollback without touching dbx.db.
//!
//! All tests use throwaway SQLite files and the mock adapter; no
//! production database is touched.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use dbx_bastion::asset::{
    AssetFilter, AssetGroupRepository, AssetRepository, AssetService, AssetSortField, DbxConnectionAdapter,
    Environment, MockDbxConnectionAdapter, NewAsset, NewAssetGroup, NewUser, UnavailableDbxConnectionAdapter,
    UpdateAsset, UpdateAssetGroup, UserRepository, MAX_PAGE_SIZE,
};
use dbx_bastion::auth::{
    AdminBootstrap, AuthenticatedPrincipal, BootstrapCredentials, BootstrapPolicy, LoginRequest, PasswordConfig,
    PasswordService,
};
use dbx_bastion::error::BastionError;
use dbx_bastion::storage::apply_one_migration;
use dbx_bastion::BastionService;
use uuid::Uuid;

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_db_path(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let path = std::env::temp_dir()
        .join(format!("dbx-bastion-assets-test-{}-{}-{}", std::process::id(), n, tag))
        .join("test.db");
    dbx_bastion::secure_dir::ensure_secure_dir(path.parent().unwrap()).unwrap();
    path
}

fn fast_password_config() -> PasswordConfig {
    PasswordConfig { memory_kib: 8192, iterations: 1, parallelism: 1, min_password_len: 8, max_concurrent_hashes: 4 }
}

struct Ctx {
    service: BastionService,
    passwords: PasswordService,
    dbx: Arc<MockDbxConnectionAdapter>,
    db_path: PathBuf,
}

impl Ctx {
    async fn new(tag: &str) -> Self {
        let db_path = temp_db_path(tag);
        let _ = std::fs::remove_file(&db_path);
        let service = BastionService::open(&db_path).expect("open");
        let passwords = PasswordService::new(fast_password_config()).expect("passwords");
        let dbx = Arc::new(MockDbxConnectionAdapter::new());
        dbx.add_connection("conn-test-1");
        dbx.add_connection("conn-test-2");
        Self { service, passwords, dbx, db_path }
    }

    fn assets(&self) -> AssetService {
        self.service.asset_service(self.dbx.clone() as Arc<dyn DbxConnectionAdapter>)
    }

    fn password_for(username: &str) -> String {
        format!("{username}-password-1")
    }

    async fn make_admin(&self, username: &str) -> AuthenticatedPrincipal {
        let bootstrap =
            AdminBootstrap::new(self.service.store().clone(), self.passwords.clone(), BootstrapPolicy::default());
        bootstrap
            .bootstrap(&BootstrapCredentials::new(username, username, &Self::password_for(username)))
            .await
            .expect("bootstrap admin");
        self.login(username).await
    }

    async fn make_user(&self, username: &str) -> AuthenticatedPrincipal {
        let hash = self.passwords.hash(&Self::password_for(username)).await.expect("hash");
        self.service
            .store()
            .create_user(&NewUser {
                username: username.to_string(),
                display_name: username.to_string(),
                password_hash: hash,
            })
            .await
            .expect("create user");
        self.login(username).await
    }

    async fn login(&self, username: &str) -> AuthenticatedPrincipal {
        let result = self
            .service
            .auth()
            .login(&LoginRequest {
                username: username.to_string(),
                password: Self::password_for(username),
                source_ip: None,
                user_agent: None,
            })
            .await
            .expect("login");
        self.service.auth().authenticate(&result.token).await.expect("authenticate")
    }

    fn new_asset(&self, name: &str) -> NewAsset {
        // 0001 schema: dbx_connection_id is UNIQUE (asset <-> connection is
        // 1:1), so each test asset gets its own registered connection id.
        let conn_id = format!("conn-{name}");
        self.dbx.add_connection(&conn_id);
        NewAsset {
            name: name.to_string(),
            environment: "development".to_string(),
            db_type: "mysql".to_string(),
            dbx_connection_id: conn_id,
            group_ids: vec![],
            description: "test asset".to_string(),
        }
    }

    async fn create_asset(&self, admin: &AuthenticatedPrincipal, name: &str) -> dbx_bastion::asset::Asset {
        self.assets().create_asset(admin, self.new_asset(name)).await.expect("create asset")
    }
}

impl Drop for Ctx {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.db_path);
        for suffix in ["wal", "shm", "journal"] {
            let mut p = self.db_path.clone();
            p.set_extension(format!("db-{suffix}"));
            let _ = std::fs::remove_file(p);
        }
    }
}

fn assert_forbidden(result: Result<impl std::fmt::Debug, BastionError>) {
    assert!(matches!(result, Err(BastionError::Forbidden(_))), "expected Forbidden, got {result:?}");
}

fn assert_invalid_data(result: Result<impl std::fmt::Debug, BastionError>) {
    assert!(matches!(result, Err(BastionError::InvalidData(_))), "expected InvalidData, got {result:?}");
}

fn assert_invalid_data_err(err: BastionError) {
    assert!(matches!(err, BastionError::InvalidData(_)), "expected InvalidData, got {err:?}");
}

// ---- 1. asset CRUD ------------------------------------------------------------

#[tokio::test]
async fn asset_create_get_update_roundtrip() {
    let ctx = Ctx::new("crud").await;
    let admin = ctx.make_admin("assetadmin").await;
    let assets = ctx.assets();

    let created = assets.create_asset(&admin, ctx.new_asset("orders-db")).await.unwrap();
    assert_eq!(created.name, "orders-db");
    assert_eq!(created.environment, Environment::Development);
    assert_eq!(created.db_type, "mysql");
    assert_eq!(created.dbx_connection_id, "conn-orders-db");
    assert!(created.enabled);
    assert!(created.deleted_at.is_none());

    let fetched = assets.get_asset(&admin, created.id).await.unwrap();
    assert_eq!(fetched.id, created.id);
    assert_eq!(fetched.description, "test asset");

    let updated = assets
        .update_asset(
            &admin,
            created.id,
            UpdateAsset {
                name: Some("orders-db-v2".to_string()),
                environment: Some("staging".to_string()),
                description: Some("renamed".to_string()),
                ..UpdateAsset::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(updated.name, "orders-db-v2");
    assert_eq!(updated.environment, Environment::Staging);
    assert_eq!(updated.description, "renamed");
    // Unchanged fields survive.
    assert_eq!(updated.dbx_connection_id, "conn-orders-db");

    // resolve_asset sees usable assets.
    let resolved = ctx.service.store().resolve_asset(created.id).await.unwrap().expect("resolvable");
    assert_eq!(resolved.name, "orders-db-v2");
}

// ---- 2. name uniqueness -------------------------------------------------------

#[tokio::test]
async fn asset_name_unique() {
    let ctx = Ctx::new("unique").await;
    let admin = ctx.make_admin("assetadmin").await;
    let assets = ctx.assets();

    ctx.create_asset(&admin, "dup-name").await;
    let err = assets.create_asset(&admin, ctx.new_asset("dup-name")).await.unwrap_err();
    assert!(matches!(err, BastionError::InvalidData(_)), "duplicate name must be rejected, got {err:?}");

    // Renaming onto an existing name is rejected too.
    let other = ctx.create_asset(&admin, "other-name").await;
    let err = assets
        .update_asset(&admin, other.id, UpdateAsset { name: Some("dup-name".to_string()), ..UpdateAsset::default() })
        .await
        .unwrap_err();
    assert_invalid_data_err(err);
}

// ---- 3. unauthorized users cannot manage -------------------------------------

#[tokio::test]
async fn non_admin_cannot_manage_assets() {
    let ctx = Ctx::new("forbidden").await;
    let admin = ctx.make_admin("assetadmin").await;
    let user = ctx.make_user("mallory").await;
    let assets = ctx.assets();

    let asset = ctx.create_asset(&admin, "guarded-db").await;

    assert_forbidden(assets.create_asset(&user, ctx.new_asset("nope")).await.map(|_| ()));
    assert_forbidden(assets.update_asset(&user, asset.id, UpdateAsset::default()).await.map(|_| ()));
    assert_forbidden(assets.delete_asset(&user, asset.id).await.map(|_| ()));
    assert_forbidden(assets.test_connection(&user, asset.id).await.map(|_| ()));
    assert_forbidden(
        assets
            .create_group(
                &user,
                NewAssetGroup { name: "nope".to_string(), parent_id: None, description: String::new() },
            )
            .await
            .map(|_| ()),
    );
    assert_forbidden(assets.get_asset(&user, asset.id).await.map(|_| ()));
    assert_forbidden(assets.list_assets(&user, AssetFilter::default(), Default::default()).await.map(|_| ()));
    // RBAC visibility: without a CONNECT grant the credential-free views
    // hide the asset (404-unified), and the listing is empty.
    assert_not_found(assets.get_asset_view(&user, asset.id).await.map(|_| ()));
    let page = assets.list_asset_views(&user, AssetFilter::default(), Default::default()).await.unwrap();
    assert_eq!(page.total, 0);
    // Platform admin without a CONNECT grant: management views work, data
    // views stay hidden (admin identity != data permission).
    let full = assets.get_asset(&admin, asset.id).await.unwrap();
    assert_eq!(full.name, "guarded-db");
    assert_not_found(assets.get_asset_view(&admin, asset.id).await.map(|_| ()));
}

// ---- 3b. RBAC visibility on views: CONNECT-gated, 404-unified ---------

fn assert_not_found(result: Result<impl std::fmt::Debug, BastionError>) {
    assert!(matches!(result, Err(BastionError::NotFound(_))), "expected NotFound, got {result:?}");
}

#[tokio::test]
async fn view_rbac_visibility_connect_gated() {
    use dbx_bastion::auth::session::SystemClock;
    use dbx_bastion::rbac::{Action, AssetScope, Effect, GrantService, NewGrant};

    let ctx = Ctx::new("view-rbac").await;
    let admin = ctx.make_admin("assetadmin").await;
    let user = ctx.make_user("mallory").await;
    let assets = ctx.assets();
    let asset = ctx.create_asset(&admin, "guarded-db").await;

    let grants = GrantService::new(ctx.service.store().clone(), Arc::new(SystemClock));
    let role_id = grants.create_role(&admin, "analyst", "").await.unwrap();
    grants.assign_role_to_user(&admin, user.user_id(), role_id).await.unwrap();

    // Ordinary user without CONNECT: single view and listing both hide the
    // asset, indistinguishably from "does not exist".
    assert_not_found(assets.get_asset_view(&user, asset.id).await.map(|_| ()));
    let page = assets.list_asset_views(&user, AssetFilter::default(), Default::default()).await.unwrap();
    assert_eq!(page.total, 0);
    assert!(page.items.is_empty());
    // Unknown ids are indistinguishable from unauthorized ones.
    assert_not_found(assets.get_asset_view(&user, Uuid::new_v4()).await.map(|_| ()));

    // Platform admin without a CONNECT grant: management identity confers
    // no data visibility either.
    assert_not_found(assets.get_asset_view(&admin, asset.id).await.map(|_| ()));

    // Grant CONNECT: the asset becomes visible with identical results on
    // both views.
    grants
        .create_grant(
            &admin,
            NewGrant {
                role_id,
                effect: Effect::Allow,
                action: Action::Connect,
                scope: AssetScope::Asset(asset.id),
                database: None,
                schema: None,
                table: None,
                expires_at: None,
            },
        )
        .await
        .unwrap();
    let view = assets.get_asset_view(&user, asset.id).await.unwrap();
    assert_eq!(view.id, asset.id);
    assert_eq!(view.name, "guarded-db");
    let page = assets.list_asset_views(&user, AssetFilter::default(), Default::default()).await.unwrap();
    assert_eq!(page.total, 1);
    assert_eq!(page.items[0].id, asset.id);

    // Disabled user: sessions are revoked atomically with the disable, so
    // the snapshot denies and views hide the asset again.
    ctx.service.store().set_user_enabled(user.user_id(), false).await.unwrap();
    assert_not_found(assets.get_asset_view(&user, asset.id).await.map(|_| ()));
    // Re-enabling does NOT resurrect the revoked session: still hidden.
    // This proves the snapshot re-validates session state per call.
    ctx.service.store().set_user_enabled(user.user_id(), true).await.unwrap();
    assert_not_found(assets.get_asset_view(&user, asset.id).await.map(|_| ()));
    // Fresh login after re-enable: the grant still applies, visible again
    // on the next call (no permission caching).
    let user = ctx.login("mallory").await;
    assets.get_asset_view(&user, asset.id).await.unwrap();

    // Role revoked out-of-band: the next call hides the asset immediately.
    grants.remove_role_from_user(&admin, user.user_id(), role_id).await.unwrap();
    assert_not_found(assets.get_asset_view(&user, asset.id).await.map(|_| ()));
    let page = assets.list_asset_views(&user, AssetFilter::default(), Default::default()).await.unwrap();
    assert_eq!(page.total, 0);
}

#[tokio::test]
async fn guard_rereads_roles_from_db() {
    let ctx = Ctx::new("stale-roles").await;
    let admin = ctx.make_admin("assetadmin").await;
    // Sanity: the admin really has the role before we revoke it.
    assert!(ctx.service.store().user_role_names(admin.user_id()).await.unwrap().contains(&"bastion-admin".to_string()));

    // Revoke the role out-of-band: the guard must re-read the database
    // and refuse, regardless of when the principal was authenticated.
    {
        let conn = rusqlite::Connection::open(&ctx.db_path).unwrap();
        conn.execute("DELETE FROM user_roles WHERE user_id = ?1", [admin.user_id().to_string()]).unwrap();
    }
    let err = ctx.assets().create_asset(&admin, ctx.new_asset("stale-role")).await.unwrap_err();
    assert!(matches!(err, BastionError::Forbidden(_)), "stale role snapshot must not authorize, got {err:?}");
}

// ---- 4. disabled users cannot manage ------------------------------------------

#[tokio::test]
async fn disabled_admin_cannot_manage_assets() {
    let ctx = Ctx::new("disabled-admin").await;
    let admin = ctx.make_admin("assetadmin").await;
    ctx.service.store().set_user_enabled(admin.user_id(), false).await.unwrap();

    let err = ctx.assets().create_asset(&admin, ctx.new_asset("nope")).await.unwrap_err();
    assert!(matches!(err, BastionError::AuthenticationFailed), "disabled admin must be rejected, got {err:?}");
}

#[tokio::test]
async fn revoked_session_cannot_manage_assets() {
    // The guard re-validates the session row on every call: a session
    // revoked after the principal was issued retains no administrative
    // power (release-effective, not debug-only).
    let ctx = Ctx::new("revoked-admin").await;
    let admin = ctx.make_admin("assetadmin").await;
    ctx.assets().create_asset(&admin, ctx.new_asset("before")).await.unwrap();

    ctx.service.auth().sessions().revoke_session(admin.session_id()).await.unwrap();

    let err = ctx.assets().create_asset(&admin, ctx.new_asset("after")).await.unwrap_err();
    assert!(matches!(err, BastionError::AuthenticationFailed), "revoked session must lose admin power, got {err:?}");
    // Grant administration is guarded the same way.
    let grants = dbx_bastion::rbac::GrantService::new(
        ctx.service.store().clone(),
        std::sync::Arc::new(dbx_bastion::auth::session::SystemClock),
    );
    let err = grants.create_role(&admin, "nope", "").await.unwrap_err();
    assert!(
        matches!(err, BastionError::AuthenticationFailed),
        "revoked session must lose grant-admin power, got {err:?}"
    );
}

// ---- 5/6. credential-free surfaces --------------------------------------------

#[tokio::test]
async fn asset_surfaces_carry_no_credentials() {
    use dbx_bastion::auth::session::SystemClock;
    use dbx_bastion::rbac::{Action, AssetScope, Effect, GrantService, NewGrant};

    let ctx = Ctx::new("no-creds").await;
    let admin = ctx.make_admin("assetadmin").await;
    let assets = ctx.assets();
    let asset = ctx.create_asset(&admin, "vault-db").await;

    // Grant the admin CONNECT so the view is reachable; the view must
    // still carry no connection reference.
    let grants = GrantService::new(ctx.service.store().clone(), Arc::new(SystemClock));
    let role_id = grants.create_role(&admin, "viewer", "").await.unwrap();
    grants.assign_role_to_user(&admin, admin.user_id(), role_id).await.unwrap();
    grants
        .create_grant(
            &admin,
            NewGrant {
                role_id,
                effect: Effect::Allow,
                action: Action::Connect,
                scope: AssetScope::Asset(asset.id),
                database: None,
                schema: None,
                table: None,
                expires_at: None,
            },
        )
        .await
        .unwrap();

    // Full admin record serialized: must not contain password material.
    // (dbx_connection_id is an opaque reference, not a credential, but it
    // still never leaves in the user view.)
    let full_json = serde_json::to_string(&asset).unwrap();
    for needle in ["password", "secret", "private_key", "private-key"] {
        assert!(!full_json.to_lowercase().contains(needle), "admin asset JSON must not contain {needle}");
    }

    // AssetView DTO: dbx_connection_id is absent by construction
    // (verified through the admin-only view endpoints).
    let view = assets.get_asset_view(&admin, asset.id).await.unwrap();
    let view_json = serde_json::to_string(&view).unwrap();
    assert!(!view_json.contains("dbx_connection_id"), "AssetView must not expose dbx_connection_id: {view_json}");
    assert!(!view_json.contains(&asset.dbx_connection_id), "AssetView must not leak the connection reference");

    let page = assets.list_asset_views(&admin, AssetFilter::default(), Default::default()).await.unwrap();
    assert_eq!(page.items.len(), 1);
    let list_json = serde_json::to_string(&page.items).unwrap();
    assert!(!list_json.contains("dbx_connection_id"));
}

// ---- 7. environment / db_type validation ---------------------------------------

#[tokio::test]
async fn environment_and_db_type_validation() {
    let ctx = Ctx::new("validation").await;
    let admin = ctx.make_admin("assetadmin").await;
    let assets = ctx.assets();

    for bad_env in ["prod", "PRODUCTION", "", "qa "] {
        let mut input = ctx.new_asset("env-test");
        input.environment = bad_env.to_string();
        assert_invalid_data(assets.create_asset(&admin, input).await.map(|_| ()));
    }
    for good_env in ["development", "test", "staging", "production"] {
        let mut input = ctx.new_asset(&format!("env-ok-{good_env}"));
        input.environment = good_env.to_string();
        assets.create_asset(&admin, input).await.unwrap();
    }

    for bad_type in ["mongodb", "", "My SQL"] {
        let mut input = ctx.new_asset("type-test");
        input.db_type = bad_type.to_string();
        assert_invalid_data(assets.create_asset(&admin, input).await.map(|_| ()));
    }
    // db_type is normalized to lowercase.
    let mut input = ctx.new_asset("type-ok");
    input.db_type = "PostgreSQL".to_string();
    let created = assets.create_asset(&admin, input).await.unwrap();
    assert_eq!(created.db_type, "postgresql");

    // Blank / overlong names rejected.
    let mut blank = ctx.new_asset("   ");
    assert_invalid_data(assets.create_asset(&admin, blank).await.map(|_| ()));
    blank = ctx.new_asset(&"x".repeat(129));
    assert_invalid_data(assets.create_asset(&admin, blank).await.map(|_| ()));
}

// ---- 8/9/10. soft delete and disable -------------------------------------------

#[tokio::test]
async fn asset_soft_delete() {
    let ctx = Ctx::new("soft-delete").await;
    let admin = ctx.make_admin("assetadmin").await;
    let assets = ctx.assets();
    let asset = ctx.create_asset(&admin, "doomed-db").await;

    assets.delete_asset(&admin, asset.id).await.unwrap();

    // Row survives with deleted_at set (history stays linkable).
    let row = ctx.service.store().find_asset_by_id(asset.id).await.unwrap().expect("row must survive soft delete");
    assert!(row.deleted_at.is_some());

    // Not resolvable for new operations.
    assert!(ctx.service.store().resolve_asset(asset.id).await.unwrap().is_none(), "deleted asset must not resolve");
    // Admin get refuses as well.
    assert_invalid_data(assets.get_asset(&admin, asset.id).await.map(|_| ()));
    // Second delete is a clear error, not silent success.
    assert_invalid_data(assets.delete_asset(&admin, asset.id).await.map(|_| ()));
    // Hidden from listings.
    let page = assets.list_assets(&admin, AssetFilter::default(), Default::default()).await.unwrap();
    assert!(page.items.iter().all(|a| a.id != asset.id));
    assert_eq!(page.total, 0);
}

#[tokio::test]
async fn disabled_asset_does_not_resolve_but_stays_listed_for_admin() {
    let ctx = Ctx::new("disable-vs-delete").await;
    let admin = ctx.make_admin("assetadmin").await;
    let assets = ctx.assets();
    let asset = ctx.create_asset(&admin, "paused-db").await;

    assets.set_asset_enabled(&admin, asset.id, false).await.unwrap();

    // Disabled != deleted: row has no deleted_at...
    let row = ctx.service.store().find_asset_by_id(asset.id).await.unwrap().expect("row survives disable");
    assert!(row.deleted_at.is_none());
    assert!(!row.enabled);
    // ...but it does not resolve for new operations.
    assert!(ctx.service.store().resolve_asset(asset.id).await.unwrap().is_none(), "disabled asset must not resolve");
    // Admin can still see it (with include_disabled) and re-enable it.
    let page = assets
        .list_assets(&admin, AssetFilter { include_disabled: true, ..AssetFilter::default() }, Default::default())
        .await
        .unwrap();
    assert_eq!(page.total, 1);
    let reenabled = assets.set_asset_enabled(&admin, asset.id, true).await.unwrap();
    assert!(reenabled.enabled);
    assert!(ctx.service.store().resolve_asset(asset.id).await.unwrap().is_some());
}

// ---- 11. groups: CRUD + membership ----------------------------------------------

#[tokio::test]
async fn group_create_update_membership() {
    let ctx = Ctx::new("groups").await;
    let admin = ctx.make_admin("assetadmin").await;
    let assets = ctx.assets();

    let group = assets
        .create_group(
            &admin,
            NewAssetGroup { name: "analytics".to_string(), parent_id: None, description: "analytics team".to_string() },
        )
        .await
        .unwrap();
    assert_eq!(group.name, "analytics");
    assert!(group.parent_id.is_none());

    let renamed = assets
        .update_group(
            &admin,
            group.id,
            UpdateAssetGroup { name: Some("analytics-v2".to_string()), ..UpdateAssetGroup::default() },
        )
        .await
        .unwrap();
    assert_eq!(renamed.name, "analytics-v2");

    // Duplicate group names rejected.
    let err = assets
        .create_group(
            &admin,
            NewAssetGroup { name: "analytics-v2".to_string(), parent_id: None, description: String::new() },
        )
        .await
        .unwrap_err();
    assert_invalid_data_err(err);

    // Membership.
    let asset = ctx.create_asset(&admin, "member-db").await;
    assets.add_asset_to_group(&admin, asset.id, group.id).await.unwrap();
    let groups = assets.asset_groups(&admin, asset.id).await.unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].id, group.id);

    assets.remove_asset_from_group(&admin, asset.id, group.id).await.unwrap();
    let groups = assets.asset_groups(&admin, asset.id).await.unwrap();
    assert!(groups.is_empty());

    // Asset creation with group_ids wires membership atomically.
    let grouped = assets
        .create_asset(&admin, NewAsset { group_ids: vec![group.id], ..ctx.new_asset("grouped-db") })
        .await
        .unwrap();
    let groups = assets.asset_groups(&admin, grouped.id).await.unwrap();
    assert_eq!(groups.len(), 1);
}

// ---- 12. group hierarchy ----------------------------------------------------------

#[tokio::test]
async fn group_parent_child_and_move() {
    let ctx = Ctx::new("hierarchy").await;
    let admin = ctx.make_admin("assetadmin").await;
    let assets = ctx.assets();

    let root = assets
        .create_group(&admin, NewAssetGroup { name: "root".to_string(), parent_id: None, description: String::new() })
        .await
        .unwrap();
    let child = assets
        .create_group(
            &admin,
            NewAssetGroup { name: "child".to_string(), parent_id: Some(root.id), description: String::new() },
        )
        .await
        .unwrap();
    assert_eq!(child.parent_id, Some(root.id));

    let other = assets
        .create_group(&admin, NewAssetGroup { name: "other".to_string(), parent_id: None, description: String::new() })
        .await
        .unwrap();
    let moved = assets.move_group(&admin, child.id, Some(other.id)).await.unwrap();
    assert_eq!(moved.parent_id, Some(other.id));

    // Move to root.
    let to_root = assets.move_group(&admin, child.id, None).await.unwrap();
    assert!(to_root.parent_id.is_none());

    // Moving under a missing parent is rejected.
    assert_invalid_data(assets.move_group(&admin, child.id, Some(Uuid::new_v4())).await.map(|_| ()));
}

// ---- 13. cycle rejection ------------------------------------------------------------

#[tokio::test]
async fn group_cycle_rejected() {
    let ctx = Ctx::new("cycle").await;
    let admin = ctx.make_admin("assetadmin").await;
    let assets = ctx.assets();

    let a = assets
        .create_group(&admin, NewAssetGroup { name: "a".to_string(), parent_id: None, description: String::new() })
        .await
        .unwrap();
    let b = assets
        .create_group(
            &admin,
            NewAssetGroup { name: "b".to_string(), parent_id: Some(a.id), description: String::new() },
        )
        .await
        .unwrap();
    let c = assets
        .create_group(
            &admin,
            NewAssetGroup { name: "c".to_string(), parent_id: Some(b.id), description: String::new() },
        )
        .await
        .unwrap();

    // Self-parenting.
    assert_invalid_data(assets.move_group(&admin, a.id, Some(a.id)).await.map(|_| ()));
    // 2-cycle: a -> b -> a.
    assert_invalid_data(assets.move_group(&admin, a.id, Some(b.id)).await.map(|_| ()));
    // 3-cycle: a -> c -> b -> a.
    assert_invalid_data(assets.move_group(&admin, a.id, Some(c.id)).await.map(|_| ()));
    // Tree unchanged after rejected moves.
    let a_again = ctx.service.store().find_group(a.id).await.unwrap().unwrap();
    assert!(a_again.parent_id.is_none());
}

// ---- 13b. concurrent moves cannot interleave into a cycle ---------------------

#[tokio::test]
async fn concurrent_group_moves_cannot_form_cycle() {
    let ctx = Ctx::new("move-race").await;
    let admin = ctx.make_admin("assetadmin").await;
    let assets =
        Arc::new(AssetService::new(ctx.service.store().clone(), ctx.dbx.clone() as Arc<dyn DbxConnectionAdapter>));

    let mk = |name: &str, parent_id: Option<Uuid>| NewAssetGroup {
        name: name.to_string(),
        parent_id,
        description: String::new(),
    };
    let a = assets.create_group(&admin, mk("a", None)).await.unwrap();
    let b = assets.create_group(&admin, mk("b", None)).await.unwrap();
    let c = assets.create_group(&admin, mk("c", Some(b.id))).await.unwrap();

    // T1: move A under C. T2: move B under A. Sequentially exactly one of
    // these orders is legal; the second committer must observe the first's
    // write inside its transaction and refuse the cycle. With a split
    // check-then-act, the interleaving could produce A -> C -> B -> A.
    let s1 = Arc::clone(&assets);
    let s2 = Arc::clone(&assets);
    let admin2 = admin.clone();
    let t1 = tokio::spawn(async move { s1.move_group(&admin, a.id, Some(c.id)).await });
    let t2 = tokio::spawn(async move { s2.move_group(&admin2, b.id, Some(a.id)).await });
    let r1 = t1.await.unwrap();
    let r2 = t2.await.unwrap();
    assert!(r1.is_ok() ^ r2.is_ok(), "exactly one concurrent move must win, got {r1:?} / {r2:?}");
    let loser = if r1.is_err() { r1.unwrap_err() } else { r2.unwrap_err() };
    assert!(matches!(loser, BastionError::InvalidData(_)), "loser must be rejected with a cycle error, got {loser:?}");

    // No cycle in the final hierarchy: every ancestor walk terminates
    // without revisiting a group.
    let store = ctx.service.store();
    for gid in [a.id, b.id, c.id] {
        let mut seen = std::collections::HashSet::new();
        let mut current = Some(gid);
        while let Some(id) = current {
            assert!(seen.insert(id), "cycle detected in group hierarchy");
            assert!(seen.len() <= 3, "ancestor walk did not terminate");
            current = store.find_group(id).await.unwrap().unwrap().parent_id;
        }
    }
}

// ---- 14. non-empty group delete refused -------------------------------------------------

#[tokio::test]
async fn non_empty_group_delete_refused() {
    let ctx = Ctx::new("group-delete").await;
    let admin = ctx.make_admin("assetadmin").await;
    let assets = ctx.assets();

    let group = assets
        .create_group(&admin, NewAssetGroup { name: "full".to_string(), parent_id: None, description: String::new() })
        .await
        .unwrap();
    let asset = ctx.create_asset(&admin, "boxed-db").await;
    assets.add_asset_to_group(&admin, asset.id, group.id).await.unwrap();

    // Refused while it has members: no cascading delete.
    assert_invalid_data(assets.delete_group(&admin, group.id).await.map(|_| ()));
    assert!(
        ctx.service.store().find_asset_by_id(asset.id).await.unwrap().is_some(),
        "member asset must survive refused group delete"
    );

    // Empty it, then delete works.
    assets.remove_asset_from_group(&admin, asset.id, group.id).await.unwrap();
    assets.delete_group(&admin, group.id).await.unwrap();
    assert!(ctx.service.store().find_group(group.id).await.unwrap().is_none());

    // Group with child groups is refused too.
    let parent = assets
        .create_group(&admin, NewAssetGroup { name: "parent".to_string(), parent_id: None, description: String::new() })
        .await
        .unwrap();
    let _child = assets
        .create_group(
            &admin,
            NewAssetGroup { name: "kid".to_string(), parent_id: Some(parent.id), description: String::new() },
        )
        .await
        .unwrap();
    assert_invalid_data(assets.delete_group(&admin, parent.id).await.map(|_| ()));
}

// ---- 15. unknown connection references rejected --------------------------------------------

#[tokio::test]
async fn unknown_connection_reference_rejected() {
    let ctx = Ctx::new("unknown-conn").await;
    let admin = ctx.make_admin("assetadmin").await;
    let assets = ctx.assets();

    let mut bad = ctx.new_asset("bad-conn-db");
    bad.dbx_connection_id = "conn-does-not-exist".to_string();
    assert_invalid_data(assets.create_asset(&admin, bad).await.map(|_| ()));

    let asset = ctx.create_asset(&admin, "good-db").await;
    let original_conn = asset.dbx_connection_id.clone();
    assert_invalid_data(assets.rebind_connection(&admin, asset.id, "conn-does-not-exist").await.map(|_| ()));
    // Ordinary update cannot rebind the connection at all: the field is
    // absent from UpdateAsset by construction (compile-time), and the
    // stored reference is unchanged after the refused rebind.
    let fetched = assets.get_asset(&admin, asset.id).await.unwrap();
    assert_eq!(fetched.dbx_connection_id, original_conn);

    // Controlled rebind to a valid connection works and clears test state.
    let rebound = assets.rebind_connection(&admin, asset.id, "conn-test-2").await.unwrap();
    assert_eq!(rebound.dbx_connection_id, "conn-test-2");
    assert!(rebound.last_tested_at.is_none());
}

// ---- 16/17. connection testing --------------------------------------------------------------

#[tokio::test]
async fn mock_connection_test_success_and_failure() {
    let ctx = Ctx::new("conn-test").await;
    let admin = ctx.make_admin("assetadmin").await;
    let assets = ctx.assets();
    let asset = ctx.create_asset(&admin, "probed-db").await;
    let conn_id = asset.dbx_connection_id.clone();

    ctx.dbx.set_test_result(&conn_id, true);
    let report = assets.test_connection(&admin, asset.id).await.unwrap();
    assert!(report.success);
    assert_eq!(report.connection_id, conn_id);
    let stored = assets.get_asset(&admin, asset.id).await.unwrap();
    assert!(stored.last_tested_at.is_some());
    assert_eq!(stored.last_test_status, Some(dbx_bastion::asset::ConnectionTestStatus::Success));

    ctx.dbx.set_test_result(&conn_id, false);
    let report = assets.test_connection(&admin, asset.id).await.unwrap();
    assert!(!report.success);
    let stored = assets.get_asset(&admin, asset.id).await.unwrap();
    assert_eq!(stored.last_test_status, Some(dbx_bastion::asset::ConnectionTestStatus::Failure));

    // Report is credential-free (Debug rendering covers all fields).
    let rendered = format!("{report:?}");
    for needle in ["password", "secret", "private", "host"] {
        assert!(!rendered.to_lowercase().contains(needle), "test report must not contain {needle}: {rendered}");
    }
}

#[tokio::test]
async fn unavailable_adapter_returns_explicit_error() {
    let ctx = Ctx::new("unavailable").await;
    let admin = ctx.make_admin("assetadmin").await;
    let assets = AssetService::new(
        ctx.service.store().clone(),
        Arc::new(UnavailableDbxConnectionAdapter) as Arc<dyn DbxConnectionAdapter>,
    );

    // No fake success: creation fails explicitly when the adapter is missing.
    let err = assets.create_asset(&admin, ctx.new_asset("no-adapter-db")).await.unwrap_err();
    assert!(matches!(err, BastionError::AdapterUnavailable(_)), "expected AdapterUnavailable, got {err:?}");
}

// ---- 18. 0002 -> 0003 upgrade ---------------------------------------------------------------

#[tokio::test]
async fn migration_0002_to_0003_upgrade() {
    let db_path = temp_db_path("migrate-0002-0003");
    let _ = std::fs::remove_file(&db_path);
    let asset_id = Uuid::new_v4();
    {
        let mut conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute_batch("CREATE TABLE schema_migrations (version TEXT PRIMARY KEY, applied_at TEXT NOT NULL)")
            .unwrap();
        apply_one_migration(&mut conn, "0001_init", include_str!("../migrations/0001_init.sql")).unwrap();
        apply_one_migration(&mut conn, "0002_auth", include_str!("../migrations/0002_auth.sql")).unwrap();
        conn.execute(
            "INSERT INTO users (id, username, display_name, password_hash, enabled)
             VALUES (?1, 'legacy', 'Legacy', 'x', 1)",
            [Uuid::new_v4().to_string()],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO assets (id, name, environment, db_type, dbx_connection_id, enabled)
             VALUES (?1, 'legacy-asset', 'production', 'mysql', 'conn-old', 1)",
            [asset_id.to_string()],
        )
        .unwrap();
    }

    // Opening applies 0003 and 0004 on top of the 0002 database.
    let service = BastionService::open(&db_path).expect("open applies 0003+0004");
    let store = service.store().clone();

    // Existing data survives with backfilled defaults.
    let asset = store.find_asset_by_name("legacy-asset").await.unwrap().expect("asset survives upgrade");
    assert_eq!(asset.description, "");
    assert!(asset.deleted_at.is_none());
    assert!(asset.last_tested_at.is_none());
    assert!(store.resolve_asset(asset_id).await.unwrap().is_some());
    let user = store.find_user_by_username("legacy").await.unwrap().expect("user survives upgrade");
    assert!(user.enabled);

    // New tables are usable.
    let groups = store.list_groups().await.unwrap();
    assert!(groups.is_empty());

    drop(service);
    let _ = std::fs::remove_file(&db_path);
}

// ---- 19. idempotence + failed migration rollback -----------------------------------------------

#[test]
fn migration_idempotent_and_failed_migration_rolls_back() {
    let db_path = temp_db_path("migrate-idem");
    let _ = std::fs::remove_file(&db_path);
    {
        let service = BastionService::open(&db_path).expect("first open");
        drop(service);
        let _second = BastionService::open(&db_path).expect("second open is idempotent");
    }
    let conn = rusqlite::Connection::open(&db_path).unwrap();
    let versions: Vec<String> = conn
        .prepare("SELECT version FROM schema_migrations ORDER BY version")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    assert_eq!(versions, vec!["0001_init", "0002_auth", "0003_assets", "0004_rbac", "0005_audit"]);

    // A failing migration records nothing and leaves no partial schema.
    let mut conn = conn;
    let err = apply_one_migration(&mut conn, "0099_bad", "CREATE TABLE t1 (id INTEGER PRIMARY KEY); THIS IS NOT SQL;")
        .unwrap_err();
    assert!(matches!(err, BastionError::Migration(_)));
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM schema_migrations WHERE version = '0099_bad'", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 0);
    let partial: i64 =
        conn.query_row("SELECT COUNT(*) FROM sqlite_master WHERE name = 't1'", [], |row| row.get(0)).unwrap();
    assert_eq!(partial, 0);

    drop(conn);
    let _ = std::fs::remove_file(&db_path);
}

// ---- 20. sibling dbx.db untouched ------------------------------------------------------------------

#[tokio::test]
async fn sibling_dbx_db_untouched() {
    let dir = std::env::temp_dir().join(format!(
        "dbx-bastion-assets-dbxdb-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::SeqCst)
    ));
    dbx_bastion::secure_dir::ensure_secure_dir(&dir).unwrap();
    let dbx_path = dir.join("dbx.db");
    {
        let conn = rusqlite::Connection::open(&dbx_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE connections (id TEXT PRIMARY KEY, host TEXT);
             INSERT INTO connections VALUES ('c1', 'db.internal');",
        )
        .unwrap();
    }

    // Run a full asset-management session against the bastion DB.
    let ctx = Ctx::new("dbxdb").await;
    let admin = ctx.make_admin("assetadmin").await;
    let asset = ctx.create_asset(&admin, "isolated-db").await;
    ctx.assets().test_connection(&admin, asset.id).await.unwrap();
    ctx.assets().delete_asset(&admin, asset.id).await.unwrap();

    // The sibling dbx.db is byte-identical in content.
    let conn = rusqlite::Connection::open(&dbx_path).unwrap();
    let host: String = conn.query_row("SELECT host FROM connections WHERE id = 'c1'", [], |row| row.get(0)).unwrap();
    assert_eq!(host, "db.internal");
    drop(conn);
    std::fs::remove_dir_all(&dir).unwrap();
}

// ---- 21. pagination and sort boundaries ---------------------------------------------------------------

#[tokio::test]
async fn asset_pagination_and_sort_boundaries() {
    let ctx = Ctx::new("paging").await;
    let admin = ctx.make_admin("assetadmin").await;
    let assets = ctx.assets();

    for name in ["delta", "alpha", "charlie", "bravo", "echo"] {
        ctx.create_asset(&admin, name).await;
    }
    // One disabled asset for the include_disabled filter.
    let disabled = ctx.create_asset(&admin, "zulu-disabled").await;
    assets.set_asset_enabled(&admin, disabled.id, false).await.unwrap();

    // Default: disabled hidden.
    let page = assets.list_assets(&admin, AssetFilter::default(), Default::default()).await.unwrap();
    assert_eq!(page.total, 5);
    assert_eq!(page.items.len(), 5);
    // Default sort is name ascending.
    let names: Vec<_> = page.items.iter().map(|a| a.name.as_str()).collect();
    assert_eq!(names, vec!["alpha", "bravo", "charlie", "delta", "echo"]);

    // Descending.
    let page = assets
        .list_assets(
            &admin,
            AssetFilter::default(),
            dbx_bastion::asset::PageRequest { sort_desc: true, ..Default::default() },
        )
        .await
        .unwrap();
    let names: Vec<_> = page.items.iter().map(|a| a.name.as_str()).collect();
    assert_eq!(names, vec!["echo", "delta", "charlie", "bravo", "alpha"]);

    // Paging: 2 per page.
    let p1 = assets
        .list_assets(
            &admin,
            AssetFilter::default(),
            dbx_bastion::asset::PageRequest { page: 1, page_size: 2, ..Default::default() },
        )
        .await
        .unwrap();
    let p2 = assets
        .list_assets(
            &admin,
            AssetFilter::default(),
            dbx_bastion::asset::PageRequest { page: 2, page_size: 2, ..Default::default() },
        )
        .await
        .unwrap();
    let p3 = assets
        .list_assets(
            &admin,
            AssetFilter::default(),
            dbx_bastion::asset::PageRequest { page: 3, page_size: 2, ..Default::default() },
        )
        .await
        .unwrap();
    assert_eq!(p1.items.len(), 2);
    assert_eq!(p2.items.len(), 2);
    assert_eq!(p3.items.len(), 1);
    assert_eq!(p1.total, 5);

    // Boundaries: page 0 -> 1, oversized page_size clamped to MAX_PAGE_SIZE.
    let clamped = assets
        .list_assets(
            &admin,
            AssetFilter::default(),
            dbx_bastion::asset::PageRequest { page: 0, page_size: 10_000, ..Default::default() },
        )
        .await
        .unwrap();
    assert_eq!(clamped.page, 1);
    assert_eq!(clamped.page_size, MAX_PAGE_SIZE);

    // Filters: environment, name substring (LIKE-escaped), group.
    let filtered = assets
        .list_assets(
            &admin,
            AssetFilter { name_contains: Some("alp".to_string()), ..AssetFilter::default() },
            Default::default(),
        )
        .await
        .unwrap();
    assert_eq!(filtered.total, 1);
    assert_eq!(filtered.items[0].name, "alpha");

    // LIKE wildcards in input are escaped, not interpreted.
    let escaped = assets
        .list_assets(
            &admin,
            AssetFilter { name_contains: Some("%".to_string()), ..AssetFilter::default() },
            Default::default(),
        )
        .await
        .unwrap();
    assert_eq!(escaped.total, 0, "literal % must not match everything");

    let group = assets
        .create_group(
            &admin,
            NewAssetGroup { name: "filter-group".to_string(), parent_id: None, description: String::new() },
        )
        .await
        .unwrap();
    let alpha = assets
        .list_assets(
            &admin,
            AssetFilter { name_contains: Some("alpha".to_string()), ..AssetFilter::default() },
            Default::default(),
        )
        .await
        .unwrap()
        .items[0]
        .id;
    assets.add_asset_to_group(&admin, alpha, group.id).await.unwrap();
    let by_group = assets
        .list_assets(&admin, AssetFilter { group_id: Some(group.id), ..AssetFilter::default() }, Default::default())
        .await
        .unwrap();
    assert_eq!(by_group.total, 1);

    // Sort field whitelist is by construction (enum); invalid input cannot
    // be expressed. Created_at ordering is verified as an ordering
    // property (rapid creates can share a millisecond timestamp).
    let by_created = assets
        .list_assets(
            &admin,
            AssetFilter::default(),
            dbx_bastion::asset::PageRequest {
                sort_by: AssetSortField::CreatedAt,
                sort_desc: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(
        by_created.items.windows(2).all(|w| w[0].created_at >= w[1].created_at),
        "items must be sorted by created_at descending"
    );
}

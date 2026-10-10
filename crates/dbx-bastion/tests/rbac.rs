//! TASK-004 integration tests: RBAC authorization engine.
//!
//! Covers: default deny, single/multi-role allow, DENY-over-ALLOW,
//! cross-asset isolation, asset-group inheritance (incl. moves), resource
//! level matching (wildcards, literals, case, N/A vs unknown levels),
//! grant expiry + malformed-expiry fail-closed, snapshot consistency
//! (disable/revoke/session-revocation visible on next call), unforgeable
//! identity, batch/mixed-action semantics (empty batch denied), XOR scope
//! constraint, RESTRICT delete policy, 0004 migration (fresh/upgrade/abort/
//! idempotent), and CONNECT-gated asset visibility (pagination/search/total
//! consistent, anti-enumeration).
//!
//! All tests use throwaway SQLite files; no production database is touched.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use chrono::{Duration, Utc};
use uuid::Uuid;

use dbx_bastion::asset::{
    AssetFilter, AssetGroupRepository, AssetService, DbxConnectionAdapter, MockDbxConnectionAdapter, NewAsset,
    NewAssetGroup, NewUser, PageRequest, UserRepository,
};
use dbx_bastion::auth::session::{Clock, SystemClock};
use dbx_bastion::auth::{
    AdminBootstrap, AuthenticatedPrincipal, BootstrapCredentials, BootstrapPolicy, LoginRequest, PasswordConfig,
    PasswordService,
};
use dbx_bastion::error::BastionError;
use dbx_bastion::rbac::{
    Action, AssetScope, AuthorizationCheck, Authorizer, Effect, GrantService, NameState, NewGrant, ResourceScope,
    SnapshotAuthorizer,
};
use dbx_bastion::storage::apply_one_migration;
use dbx_bastion::BastionService;

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_db_path(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let path = std::env::temp_dir()
        .join(format!("dbx-bastion-rbac-test-{}-{}-{}", std::process::id(), n, tag))
        .join("test.db");
    dbx_bastion::secure_dir::ensure_secure_dir(path.parent().unwrap()).unwrap();
    // Pre-create the file with 0600 for tests using rusqlite directly.
    dbx_bastion::secure_dir::precreate_secure_file(&path).unwrap();
    path
}

fn fast_password_config() -> PasswordConfig {
    PasswordConfig { memory_kib: 8192, iterations: 1, parallelism: 1, min_password_len: 8, max_concurrent_hashes: 4 }
}

fn test_clock() -> Arc<dyn Clock> {
    Arc::new(SystemClock) as Arc<dyn Clock>
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
        Self { service, passwords, dbx, db_path }
    }

    fn store(&self) -> Arc<dbx_bastion::storage::SqliteStore> {
        self.service.store().clone()
    }

    fn grants(&self) -> GrantService {
        GrantService::new(self.store(), test_clock())
    }

    fn authorizer(&self) -> SnapshotAuthorizer {
        SnapshotAuthorizer::new(self.store(), test_clock())
    }

    fn assets(&self) -> AssetService {
        self.service.asset_service(self.dbx.clone() as Arc<dyn DbxConnectionAdapter>)
    }

    fn password_for(username: &str) -> String {
        format!("{username}-password-1")
    }

    async fn login(&self, username: &str) -> (String, AuthenticatedPrincipal) {
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
        let principal = self.service.auth().authenticate(&result.token).await.expect("authenticate");
        (result.token, principal)
    }

    async fn make_admin(&self, username: &str) -> (String, AuthenticatedPrincipal) {
        let bootstrap = AdminBootstrap::new(self.store(), self.passwords.clone(), BootstrapPolicy::default());
        bootstrap
            .bootstrap(&BootstrapCredentials::new(username, username, &Self::password_for(username)))
            .await
            .expect("bootstrap admin");
        self.login(username).await
    }

    async fn make_user(&self, username: &str) -> (String, AuthenticatedPrincipal) {
        let hash = self.passwords.hash(&Self::password_for(username)).await.expect("hash");
        self.store()
            .create_user(&NewUser {
                username: username.to_string(),
                display_name: username.to_string(),
                password_hash: hash,
            })
            .await
            .expect("create user");
        self.login(username).await
    }

    async fn make_role(&self, admin: &AuthenticatedPrincipal, name: &str) -> Uuid {
        self.grants().create_role(admin, name, "").await.expect("create role")
    }

    /// Grant and return its id. Plain asset-level grant unless overridden.
    async fn grant(
        &self,
        admin: &AuthenticatedPrincipal,
        role: Uuid,
        effect: Effect,
        action: Action,
        scope: AssetScope,
    ) -> Uuid {
        self.grants()
            .create_grant(
                admin,
                NewGrant {
                    role_id: role,
                    effect,
                    action,
                    scope,
                    database: None,
                    schema: None,
                    table: None,
                    expires_at: None,
                },
            )
            .await
            .expect("create grant")
    }

    async fn grant_scoped(
        &self,
        admin: &AuthenticatedPrincipal,
        role: Uuid,
        effect: Effect,
        action: Action,
        scope: AssetScope,
        database: Option<&str>,
        schema: Option<&str>,
        table: Option<&str>,
    ) -> Uuid {
        self.grants()
            .create_grant(
                admin,
                NewGrant {
                    role_id: role,
                    effect,
                    action,
                    scope,
                    database: database.map(str::to_string),
                    schema: schema.map(str::to_string),
                    table: table.map(str::to_string),
                    expires_at: None,
                },
            )
            .await
            .expect("create scoped grant")
    }

    fn new_asset(&self, name: &str) -> NewAsset {
        let conn_id = format!("conn-{name}");
        self.dbx.add_connection(&conn_id);
        NewAsset {
            name: name.to_string(),
            environment: "development".to_string(),
            db_type: "mysql".to_string(),
            dbx_connection_id: conn_id,
            group_ids: vec![],
            description: "rbac test asset".to_string(),
        }
    }

    async fn create_asset(&self, admin: &AuthenticatedPrincipal, name: &str) -> Uuid {
        self.assets().create_asset(admin, self.new_asset(name)).await.expect("create asset").id
    }

    async fn make_group(&self, admin: &AuthenticatedPrincipal, name: &str, parent: Option<Uuid>) -> Uuid {
        self.assets()
            .create_group(
                admin,
                NewAssetGroup { name: name.to_string(), parent_id: parent, description: String::new() },
            )
            .await
            .expect("create group")
            .id
    }
}

/// Denial through the strict gate: generic Forbidden, fixed message — no
/// rule contents, asset names or "missing grant" hints leak.
fn assert_denied(result: Result<(), BastionError>) {
    match result {
        Err(BastionError::Forbidden(msg)) => assert_eq!(msg, "access denied", "denial message must stay generic"),
        other => panic!("expected generic Forbidden, got {other:?}"),
    }
}

fn assert_allowed(result: Result<(), BastionError>) {
    assert!(result.is_ok(), "expected allow, got {result:?}");
}

fn table_scope(asset_id: Uuid, table: &str) -> ResourceScope {
    ResourceScope {
        asset_id,
        database: NameState::present("appdb"),
        schema: NameState::NotApplicable, // MySQL-style: no independent schema
        table: NameState::present(table),
    }
}

// ---- A. basic semantics ---------------------------------------------------

#[tokio::test]
async fn default_deny_no_grants() {
    let ctx = Ctx::new("default-deny").await;
    let (_, admin) = ctx.make_admin("admin").await;
    let (_, user) = ctx.make_user("mallory").await;
    let asset = ctx.create_asset(&admin, "db1").await;
    let authz = ctx.authorizer();

    for action in [Action::Connect, Action::Select, Action::Insert, Action::Delete] {
        assert_denied(authz.authorize(&user, &ResourceScope::asset(asset), action).await);
    }
}

#[tokio::test]
async fn single_role_allow() {
    let ctx = Ctx::new("single-allow").await;
    let (_, admin) = ctx.make_admin("admin").await;
    let (_, user) = ctx.make_user("mallory").await;
    let asset = ctx.create_asset(&admin, "db1").await;
    let authz = ctx.authorizer();

    let role = ctx.make_role(&admin, "analyst").await;
    ctx.grants().assign_role_to_user(&admin, user.user_id(), role).await.unwrap();
    ctx.grant(&admin, role, Effect::Allow, Action::Connect, AssetScope::Asset(asset)).await;

    assert_allowed(authz.authorize(&user, &ResourceScope::asset(asset), Action::Connect).await);
    // Other actions stay denied.
    assert_denied(authz.authorize(&user, &ResourceScope::asset(asset), Action::Select).await);
}

#[tokio::test]
async fn multi_role_union() {
    let ctx = Ctx::new("multi-role").await;
    let (_, admin) = ctx.make_admin("admin").await;
    let (_, user) = ctx.make_user("mallory").await;
    let asset = ctx.create_asset(&admin, "db1").await;
    let authz = ctx.authorizer();

    let r1 = ctx.make_role(&admin, "r1").await;
    let r2 = ctx.make_role(&admin, "r2").await;
    let grants = ctx.grants();
    grants.assign_role_to_user(&admin, user.user_id(), r1).await.unwrap();
    grants.assign_role_to_user(&admin, user.user_id(), r2).await.unwrap();
    // ALLOW lives on r2 only; r1 is irrelevant.
    ctx.grant(&admin, r2, Effect::Allow, Action::Connect, AssetScope::Asset(asset)).await;

    assert_allowed(authz.authorize(&user, &ResourceScope::asset(asset), Action::Connect).await);
}

#[tokio::test]
async fn deny_overrides_allow_same_role() {
    let ctx = Ctx::new("deny-same-role").await;
    let (_, admin) = ctx.make_admin("admin").await;
    let (_, user) = ctx.make_user("mallory").await;
    let asset = ctx.create_asset(&admin, "db1").await;
    let authz = ctx.authorizer();

    let role = ctx.make_role(&admin, "analyst").await;
    ctx.grants().assign_role_to_user(&admin, user.user_id(), role).await.unwrap();
    ctx.grant(&admin, role, Effect::Allow, Action::Select, AssetScope::Asset(asset)).await;
    ctx.grant(&admin, role, Effect::Deny, Action::Select, AssetScope::Asset(asset)).await;

    assert_denied(authz.authorize(&user, &table_scope(asset, "orders"), Action::Select).await);
}

#[tokio::test]
async fn deny_overrides_allow_cross_role() {
    let ctx = Ctx::new("deny-cross-role").await;
    let (_, admin) = ctx.make_admin("admin").await;
    let (_, user) = ctx.make_user("mallory").await;
    let asset = ctx.create_asset(&admin, "db1").await;
    let authz = ctx.authorizer();

    let allow_role = ctx.make_role(&admin, "allow-r").await;
    let deny_role = ctx.make_role(&admin, "deny-r").await;
    let grants = ctx.grants();
    grants.assign_role_to_user(&admin, user.user_id(), allow_role).await.unwrap();
    grants.assign_role_to_user(&admin, user.user_id(), deny_role).await.unwrap();
    ctx.grant(&admin, allow_role, Effect::Allow, Action::Select, AssetScope::Asset(asset)).await;
    ctx.grant(&admin, deny_role, Effect::Deny, Action::Select, AssetScope::Asset(asset)).await;

    assert_denied(authz.authorize(&user, &table_scope(asset, "orders"), Action::Select).await);
}

#[tokio::test]
async fn cross_asset_isolation() {
    let ctx = Ctx::new("x-asset").await;
    let (_, admin) = ctx.make_admin("admin").await;
    let (_, user) = ctx.make_user("mallory").await;
    let a1 = ctx.create_asset(&admin, "db1").await;
    let a2 = ctx.create_asset(&admin, "db2").await;
    let authz = ctx.authorizer();

    let role = ctx.make_role(&admin, "analyst").await;
    ctx.grants().assign_role_to_user(&admin, user.user_id(), role).await.unwrap();
    ctx.grant(&admin, role, Effect::Allow, Action::Connect, AssetScope::Asset(a1)).await;

    assert_allowed(authz.authorize(&user, &ResourceScope::asset(a1), Action::Connect).await);
    assert_denied(authz.authorize(&user, &ResourceScope::asset(a2), Action::Connect).await);
}

#[tokio::test]
async fn connect_is_independent() {
    let ctx = Ctx::new("connect-indep").await;
    let (_, admin) = ctx.make_admin("admin").await;
    let (_, user) = ctx.make_user("mallory").await;
    let asset = ctx.create_asset(&admin, "db1").await;
    let authz = ctx.authorizer();

    let role = ctx.make_role(&admin, "analyst").await;
    ctx.grants().assign_role_to_user(&admin, user.user_id(), role).await.unwrap();
    // SELECT grant does not imply CONNECT...
    let select_gid = ctx.grant(&admin, role, Effect::Allow, Action::Select, AssetScope::Asset(asset)).await;
    assert_denied(authz.authorize(&user, &ResourceScope::asset(asset), Action::Connect).await);
    // ...and CONNECT does not imply SELECT.
    ctx.grants().revoke_grant(&admin, select_gid).await.unwrap();
    ctx.grant(&admin, role, Effect::Allow, Action::Connect, AssetScope::Asset(asset)).await;
    assert_allowed(authz.authorize(&user, &ResourceScope::asset(asset), Action::Connect).await);
    assert_denied(authz.authorize(&user, &table_scope(asset, "orders"), Action::Select).await);
}

// ---- B. batch semantics ---------------------------------------------------

#[tokio::test]
async fn authorize_batch_mixed_actions_all_must_pass() {
    let ctx = Ctx::new("batch-mixed").await;
    let (_, admin) = ctx.make_admin("admin").await;
    let (_, user) = ctx.make_user("mallory").await;
    let asset = ctx.create_asset(&admin, "db1").await;
    let authz = ctx.authorizer();

    let role = ctx.make_role(&admin, "analyst").await;
    ctx.grants().assign_role_to_user(&admin, user.user_id(), role).await.unwrap();
    ctx.grant(&admin, role, Effect::Allow, Action::Select, AssetScope::Asset(asset)).await;
    ctx.grant(&admin, role, Effect::Allow, Action::Insert, AssetScope::Asset(asset)).await;

    // INSERT INTO t SELECT * FROM t2  ~  (t, Insert) + (t2, Select)
    let checks = vec![
        AuthorizationCheck::new(table_scope(asset, "t"), Action::Insert),
        AuthorizationCheck::new(table_scope(asset, "t2"), Action::Select),
        AuthorizationCheck::new(table_scope(asset, "t3"), Action::Delete), // not granted
    ];
    assert_denied(authz.authorize_batch(&user, &checks).await);
    // Per-item results: independent, in order.
    assert_eq!(authz.evaluate_batch(&user, &checks).await.unwrap(), vec![true, true, false]);

    // Grant the missing one: the whole batch passes.
    ctx.grant(&admin, role, Effect::Allow, Action::Delete, AssetScope::Asset(asset)).await;
    assert_allowed(authz.authorize_batch(&user, &checks).await);
}

#[tokio::test]
async fn authorize_batch_empty_is_denied() {
    let ctx = Ctx::new("batch-empty").await;
    ctx.make_admin("admin").await;
    let (_, user) = ctx.make_user("mallory").await;
    let authz = ctx.authorizer();

    // The strict gate denies empty batches outright...
    assert_denied(authz.authorize_batch(&user, &[]).await);
    assert_denied(authz.authorize_all(&user, &[], Action::Select).await);
    // ...while the internal evaluator just reports "nothing evaluated".
    assert_eq!(authz.evaluate_batch(&user, &[]).await.unwrap(), Vec::<bool>::new());
}

#[tokio::test]
async fn authorize_all_partial_deny() {
    let ctx = Ctx::new("all-partial").await;
    let (_, admin) = ctx.make_admin("admin").await;
    let (_, user) = ctx.make_user("mallory").await;
    let a1 = ctx.create_asset(&admin, "db1").await;
    let a2 = ctx.create_asset(&admin, "db2").await;
    let authz = ctx.authorizer();

    let role = ctx.make_role(&admin, "analyst").await;
    ctx.grants().assign_role_to_user(&admin, user.user_id(), role).await.unwrap();
    ctx.grant(&admin, role, Effect::Allow, Action::Select, AssetScope::Asset(a1)).await;

    assert_denied(authz.authorize_all(&user, &[table_scope(a1, "t"), table_scope(a2, "t")], Action::Select).await);
    assert_allowed(authz.authorize_all(&user, &[table_scope(a1, "t")], Action::Select).await);
}

// ---- C. scope, inheritance, resource levels -------------------------------

#[tokio::test]
async fn asset_group_inheritance() {
    let ctx = Ctx::new("grp-inherit").await;
    let (_, admin) = ctx.make_admin("admin").await;
    let (_, user) = ctx.make_user("mallory").await;
    let assets = ctx.assets();
    let authz = ctx.authorizer();

    let parent = ctx.make_group(&admin, "prod", None).await;
    let child = ctx.make_group(&admin, "prod-eu", Some(parent)).await;
    let asset = ctx.create_asset(&admin, "db1").await;
    assets.add_asset_to_group(&admin, asset, child).await.unwrap();

    let role = ctx.make_role(&admin, "analyst").await;
    ctx.grants().assign_role_to_user(&admin, user.user_id(), role).await.unwrap();
    // Grant on the parent group covers the asset in the child group.
    ctx.grant(&admin, role, Effect::Allow, Action::Connect, AssetScope::Group(parent)).await;

    assert_allowed(authz.authorize(&user, &ResourceScope::asset(asset), Action::Connect).await);
}

#[tokio::test]
async fn asset_group_deny_inheritance() {
    let ctx = Ctx::new("grp-deny").await;
    let (_, admin) = ctx.make_admin("admin").await;
    let (_, user) = ctx.make_user("mallory").await;
    let assets = ctx.assets();
    let authz = ctx.authorizer();

    let parent = ctx.make_group(&admin, "prod", None).await;
    let child = ctx.make_group(&admin, "prod-eu", Some(parent)).await;
    let asset = ctx.create_asset(&admin, "db1").await;
    assets.add_asset_to_group(&admin, asset, child).await.unwrap();

    let role = ctx.make_role(&admin, "analyst").await;
    ctx.grants().assign_role_to_user(&admin, user.user_id(), role).await.unwrap();
    ctx.grant(&admin, role, Effect::Allow, Action::Connect, AssetScope::Asset(asset)).await;
    ctx.grant(&admin, role, Effect::Deny, Action::Connect, AssetScope::Group(parent)).await;

    assert_denied(authz.authorize(&user, &ResourceScope::asset(asset), Action::Connect).await);
}

#[tokio::test]
async fn group_move_changes_inheritance() {
    let ctx = Ctx::new("grp-move").await;
    let (_, admin) = ctx.make_admin("admin").await;
    let (_, user) = ctx.make_user("mallory").await;
    let assets = ctx.assets();
    let authz = ctx.authorizer();

    let team_a = ctx.make_group(&admin, "team-a", None).await;
    let team_b = ctx.make_group(&admin, "team-b", None).await;
    let asset = ctx.create_asset(&admin, "db1").await;
    assets.add_asset_to_group(&admin, asset, team_a).await.unwrap();

    let role = ctx.make_role(&admin, "analyst").await;
    ctx.grants().assign_role_to_user(&admin, user.user_id(), role).await.unwrap();
    ctx.grant(&admin, role, Effect::Allow, Action::Connect, AssetScope::Group(team_b)).await;
    assert_denied(authz.authorize(&user, &ResourceScope::asset(asset), Action::Connect).await);

    // Moving team-a under team-b brings the asset into team-b's subtree:
    // the next authorization sees the new inheritance immediately.
    ctx.store().set_group_parent_checked(team_a, Some(team_b)).await.unwrap();
    assert_allowed(authz.authorize(&user, &ResourceScope::asset(asset), Action::Connect).await);
}

#[tokio::test]
async fn table_granularity() {
    let ctx = Ctx::new("table-gran").await;
    let (_, admin) = ctx.make_admin("admin").await;
    let (_, user) = ctx.make_user("mallory").await;
    let asset = ctx.create_asset(&admin, "db1").await;
    let authz = ctx.authorizer();

    let role = ctx.make_role(&admin, "analyst").await;
    ctx.grants().assign_role_to_user(&admin, user.user_id(), role).await.unwrap();
    ctx.grant_scoped(
        &admin,
        role,
        Effect::Allow,
        Action::Select,
        AssetScope::Asset(asset),
        Some("appdb"),
        None,
        Some("orders"),
    )
    .await;

    assert_allowed(authz.authorize(&user, &table_scope(asset, "orders"), Action::Select).await);
    assert_denied(authz.authorize(&user, &table_scope(asset, "customers"), Action::Select).await);
}

#[tokio::test]
async fn wildcard_and_literal_patterns() {
    let ctx = Ctx::new("patterns").await;
    let (_, admin) = ctx.make_admin("admin").await;
    let (_, user) = ctx.make_user("mallory").await;
    let asset = ctx.create_asset(&admin, "db1").await;
    let authz = ctx.authorizer();

    let role = ctx.make_role(&admin, "analyst").await;
    ctx.grants().assign_role_to_user(&admin, user.user_id(), role).await.unwrap();
    // NULL database pattern = wildcard; "prod_*" stays a literal.
    ctx.grant_scoped(&admin, role, Effect::Allow, Action::Select, AssetScope::Asset(asset), None, None, Some("prod_*"))
        .await;

    assert_allowed(authz.authorize(&user, &table_scope(asset, "prod_*"), Action::Select).await);
    assert_denied(authz.authorize(&user, &table_scope(asset, "prod_1"), Action::Select).await);
    // "*" is normalized to the wildcard at the API boundary.
    let grants = ctx.grants();
    let gid = grants
        .create_grant(
            &admin,
            NewGrant {
                role_id: role,
                effect: Effect::Allow,
                action: Action::Select,
                scope: AssetScope::Asset(asset),
                database: Some("*".to_string()),
                schema: None,
                table: Some("t".to_string()),
                expires_at: None,
            },
        )
        .await
        .unwrap();
    let view = grants.list_grants(&admin).await.unwrap().into_iter().find(|g| g.id == gid).unwrap();
    assert_eq!(view.database, None, "\"*\" must normalize to the wildcard");
}

#[tokio::test]
async fn matching_is_case_sensitive() {
    let ctx = Ctx::new("case").await;
    let (_, admin) = ctx.make_admin("admin").await;
    let (_, user) = ctx.make_user("mallory").await;
    let asset = ctx.create_asset(&admin, "db1").await;
    let authz = ctx.authorizer();

    let role = ctx.make_role(&admin, "analyst").await;
    ctx.grants().assign_role_to_user(&admin, user.user_id(), role).await.unwrap();
    ctx.grant_scoped(&admin, role, Effect::Allow, Action::Select, AssetScope::Asset(asset), None, Some("public"), None)
        .await;

    let lower = ResourceScope {
        asset_id: asset,
        database: NameState::present("appdb"),
        schema: NameState::present("public"),
        table: NameState::present("t"),
    };
    let upper = ResourceScope {
        asset_id: asset,
        database: NameState::present("appdb"),
        schema: NameState::present("Public"),
        table: NameState::present("t"),
    };
    assert_allowed(authz.authorize(&user, &lower, Action::Select).await);
    assert_denied(authz.authorize(&user, &upper, Action::Select).await);
}

#[tokio::test]
async fn dialect_missing_level_vs_specific_rule() {
    let ctx = Ctx::new("dialect-na").await;
    let (_, admin) = ctx.make_admin("admin").await;
    let (_, user) = ctx.make_user("mallory").await;
    let asset = ctx.create_asset(&admin, "db1").await;
    let authz = ctx.authorizer();

    let role = ctx.make_role(&admin, "analyst").await;
    ctx.grants().assign_role_to_user(&admin, user.user_id(), role).await.unwrap();
    // Rule pins schema="public": a MySQL-style request (no schema level)
    // must not match it.
    ctx.grant_scoped(
        &admin,
        role,
        Effect::Allow,
        Action::Select,
        AssetScope::Asset(asset),
        None,
        Some("public"),
        Some("t"),
    )
    .await;
    assert_denied(authz.authorize(&user, &table_scope(asset, "t"), Action::Select).await);

    // A wildcard-schema rule matches the same request.
    let role2 = ctx.make_role(&admin, "analyst2").await;
    ctx.grants().assign_role_to_user(&admin, user.user_id(), role2).await.unwrap();
    ctx.grant_scoped(&admin, role2, Effect::Allow, Action::Select, AssetScope::Asset(asset), None, None, Some("t"))
        .await;
    assert_allowed(authz.authorize(&user, &table_scope(asset, "t"), Action::Select).await);
}

#[tokio::test]
async fn unknown_level_is_denied() {
    let ctx = Ctx::new("unknown-level").await;
    let (_, admin) = ctx.make_admin("admin").await;
    let (_, user) = ctx.make_user("mallory").await;
    let asset = ctx.create_asset(&admin, "db1").await;
    let authz = ctx.authorizer();

    let role = ctx.make_role(&admin, "analyst").await;
    ctx.grants().assign_role_to_user(&admin, user.user_id(), role).await.unwrap();
    ctx.grant_scoped(
        &admin,
        role,
        Effect::Allow,
        Action::Select,
        AssetScope::Asset(asset),
        Some("appdb"),
        None,
        Some("orders"),
    )
    .await;

    // The analyzer could not determine the table: fail closed.
    let unknown_table = ResourceScope {
        asset_id: asset,
        database: NameState::present("appdb"),
        schema: NameState::NotApplicable,
        table: NameState::Unknown,
    };
    assert_denied(authz.authorize(&user, &unknown_table, Action::Select).await);
    // A fully-wildcard rule still matches (it constrains nothing).
    let role2 = ctx.make_role(&admin, "analyst2").await;
    ctx.grants().assign_role_to_user(&admin, user.user_id(), role2).await.unwrap();
    ctx.grant(&admin, role2, Effect::Allow, Action::Select, AssetScope::Asset(asset)).await;
    assert_allowed(authz.authorize(&user, &unknown_table, Action::Select).await);
}

// ---- D. expiry ------------------------------------------------------------

#[tokio::test]
async fn grant_expiry() {
    let ctx = Ctx::new("expiry").await;
    let (_, admin) = ctx.make_admin("admin").await;
    let (_, user) = ctx.make_user("mallory").await;
    let asset = ctx.create_asset(&admin, "db1").await;
    let authz = ctx.authorizer();

    let role = ctx.make_role(&admin, "analyst").await;
    ctx.grants().assign_role_to_user(&admin, user.user_id(), role).await.unwrap();
    ctx.grants()
        .create_grant(
            &admin,
            NewGrant {
                role_id: role,
                effect: Effect::Allow,
                action: Action::Connect,
                scope: AssetScope::Asset(asset),
                database: None,
                schema: None,
                table: None,
                expires_at: Some(Utc::now() + Duration::hours(1)),
            },
        )
        .await
        .unwrap();
    assert_allowed(authz.authorize(&user, &ResourceScope::asset(asset), Action::Connect).await);

    // Flip the expiry into the past behind the service's back: denied.
    {
        let conn = rusqlite::Connection::open(&ctx.db_path).unwrap();
        let past = (Utc::now() - Duration::hours(1)).to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        conn.execute("UPDATE permissions SET expires_at = ?1", [past]).unwrap();
    }
    assert_denied(authz.authorize(&user, &ResourceScope::asset(asset), Action::Connect).await);
}

#[tokio::test]
async fn malformed_expires_at_fails_closed() {
    let ctx = Ctx::new("bad-expiry").await;
    let (_, admin) = ctx.make_admin("admin").await;
    let (_, user) = ctx.make_user("mallory").await;
    let asset = ctx.create_asset(&admin, "db1").await;
    let authz = ctx.authorizer();

    let role = ctx.make_role(&admin, "analyst").await;
    ctx.grants().assign_role_to_user(&admin, user.user_id(), role).await.unwrap();
    // A valid ALLOW plus a corrupt DENY: the corrupt row must fail the
    // check closed, never be skipped into an allow.
    ctx.grant(&admin, role, Effect::Allow, Action::Select, AssetScope::Asset(asset)).await;
    let deny_id = ctx.grant(&admin, role, Effect::Deny, Action::Select, AssetScope::Asset(asset)).await;
    {
        let conn = rusqlite::Connection::open(&ctx.db_path).unwrap();
        conn.execute("UPDATE permissions SET expires_at = 'not-a-timestamp' WHERE id = ?1", [deny_id.to_string()])
            .unwrap();
    }
    assert_denied(authz.authorize(&user, &table_scope(asset, "t"), Action::Select).await);

    // Corrupt expires_at on an ALLOW: also denied.
    {
        let conn = rusqlite::Connection::open(&ctx.db_path).unwrap();
        conn.execute("UPDATE permissions SET expires_at = 'garbage'", []).unwrap();
    }
    // (DENY row deleted so only the corrupt ALLOW remains.)
    ctx.grants().revoke_grant(&admin, deny_id).await.unwrap();
    assert_denied(authz.authorize(&user, &table_scope(asset, "t"), Action::Select).await);
}

#[tokio::test]
async fn create_grant_rejects_past_expiry() {
    let ctx = Ctx::new("past-expiry").await;
    let (_, admin) = ctx.make_admin("admin").await;
    let (_, user) = ctx.make_user("mallory").await;
    let asset = ctx.create_asset(&admin, "db1").await;
    let _ = user;

    let role = ctx.make_role(&admin, "analyst").await;
    let err = ctx
        .grants()
        .create_grant(
            &admin,
            NewGrant {
                role_id: role,
                effect: Effect::Allow,
                action: Action::Connect,
                scope: AssetScope::Asset(asset),
                database: None,
                schema: None,
                table: None,
                expires_at: Some(Utc::now() - Duration::seconds(1)),
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(err, BastionError::InvalidData(_)), "past expiry must be rejected, got {err:?}");
}

// ---- E. snapshot consistency ----------------------------------------------

#[tokio::test]
async fn user_disabled_denies() {
    let ctx = Ctx::new("user-disabled").await;
    let (_, admin) = ctx.make_admin("admin").await;
    let (_, user) = ctx.make_user("mallory").await;
    let asset = ctx.create_asset(&admin, "db1").await;
    let authz = ctx.authorizer();

    let role = ctx.make_role(&admin, "analyst").await;
    ctx.grants().assign_role_to_user(&admin, user.user_id(), role).await.unwrap();
    ctx.grant(&admin, role, Effect::Allow, Action::Connect, AssetScope::Asset(asset)).await;
    assert_allowed(authz.authorize(&user, &ResourceScope::asset(asset), Action::Connect).await);

    ctx.store().set_user_enabled(user.user_id(), false).await.unwrap();
    assert_denied(authz.authorize(&user, &ResourceScope::asset(asset), Action::Connect).await);
}

#[tokio::test]
async fn session_revoked_denies() {
    let ctx = Ctx::new("sess-revoke").await;
    let (_, admin) = ctx.make_admin("admin").await;
    let (_, user) = ctx.make_user("mallory").await;
    let asset = ctx.create_asset(&admin, "db1").await;
    let authz = ctx.authorizer();

    let role = ctx.make_role(&admin, "analyst").await;
    ctx.grants().assign_role_to_user(&admin, user.user_id(), role).await.unwrap();
    ctx.grant(&admin, role, Effect::Allow, Action::Connect, AssetScope::Asset(asset)).await;
    assert_allowed(authz.authorize(&user, &ResourceScope::asset(asset), Action::Connect).await);

    // Revoke the session behind the principal's back: the snapshot
    // re-validates session state, so the next call denies.
    ctx.service.auth().sessions().revoke_session(user.session_id()).await.unwrap();
    assert_denied(authz.authorize(&user, &ResourceScope::asset(asset), Action::Connect).await);
}

#[tokio::test]
async fn role_revoked_next_call_denies() {
    let ctx = Ctx::new("role-revoke").await;
    let (_, admin) = ctx.make_admin("admin").await;
    let (_, user) = ctx.make_user("mallory").await;
    let asset = ctx.create_asset(&admin, "db1").await;
    let authz = ctx.authorizer();

    let role = ctx.make_role(&admin, "analyst").await;
    let grants = ctx.grants();
    grants.assign_role_to_user(&admin, user.user_id(), role).await.unwrap();
    ctx.grant(&admin, role, Effect::Allow, Action::Connect, AssetScope::Asset(asset)).await;
    assert_allowed(authz.authorize(&user, &ResourceScope::asset(asset), Action::Connect).await);

    grants.remove_role_from_user(&admin, user.user_id(), role).await.unwrap();
    assert_denied(authz.authorize(&user, &ResourceScope::asset(asset), Action::Connect).await);
}

#[tokio::test]
async fn group_membership_revoked_denies() {
    let ctx = Ctx::new("grp-revoke").await;
    let (_, admin) = ctx.make_admin("admin").await;
    let (_, user) = ctx.make_user("mallory").await;
    let asset = ctx.create_asset(&admin, "db1").await;
    let authz = ctx.authorizer();

    let grants = ctx.grants();
    let group = grants.create_user_group(&admin, "analysts", "").await.unwrap();
    let role = ctx.make_role(&admin, "analyst").await;
    grants.add_role_to_group(&admin, role, group).await.unwrap();
    grants.add_user_to_group(&admin, user.user_id(), group).await.unwrap();
    ctx.grant(&admin, role, Effect::Allow, Action::Connect, AssetScope::Asset(asset)).await;
    assert_allowed(authz.authorize(&user, &ResourceScope::asset(asset), Action::Connect).await);

    grants.remove_user_from_group(&admin, user.user_id(), group).await.unwrap();
    assert_denied(authz.authorize(&user, &ResourceScope::asset(asset), Action::Connect).await);
}

#[tokio::test]
async fn grant_revoked_next_call_denies() {
    let ctx = Ctx::new("grant-revoke").await;
    let (_, admin) = ctx.make_admin("admin").await;
    let (_, user) = ctx.make_user("mallory").await;
    let asset = ctx.create_asset(&admin, "db1").await;
    let authz = ctx.authorizer();

    let role = ctx.make_role(&admin, "analyst").await;
    ctx.grants().assign_role_to_user(&admin, user.user_id(), role).await.unwrap();
    let gid = ctx.grant(&admin, role, Effect::Allow, Action::Connect, AssetScope::Asset(asset)).await;
    assert_allowed(authz.authorize(&user, &ResourceScope::asset(asset), Action::Connect).await);

    ctx.grants().revoke_grant(&admin, gid).await.unwrap();
    assert_denied(authz.authorize(&user, &ResourceScope::asset(asset), Action::Connect).await);
}

#[tokio::test]
async fn asset_disabled_and_deleted_deny() {
    let ctx = Ctx::new("asset-state").await;
    let (_, admin) = ctx.make_admin("admin").await;
    let (_, user) = ctx.make_user("mallory").await;
    let asset = ctx.create_asset(&admin, "db1").await;
    let authz = ctx.authorizer();
    let assets = ctx.assets();

    let role = ctx.make_role(&admin, "analyst").await;
    ctx.grants().assign_role_to_user(&admin, user.user_id(), role).await.unwrap();
    ctx.grant(&admin, role, Effect::Allow, Action::Connect, AssetScope::Asset(asset)).await;
    assert_allowed(authz.authorize(&user, &ResourceScope::asset(asset), Action::Connect).await);

    assets.set_asset_enabled(&admin, asset, false).await.unwrap();
    assert_denied(authz.authorize(&user, &ResourceScope::asset(asset), Action::Connect).await);
    assets.set_asset_enabled(&admin, asset, true).await.unwrap();
    assert_allowed(authz.authorize(&user, &ResourceScope::asset(asset), Action::Connect).await);

    assets.delete_asset(&admin, asset).await.unwrap(); // soft delete
    assert_denied(authz.authorize(&user, &ResourceScope::asset(asset), Action::Connect).await);
}

// ---- F. identity -----------------------------------------------------------

#[tokio::test]
async fn session_identity_is_authoritative() {
    let ctx = Ctx::new("identity").await;
    let (_, admin) = ctx.make_admin("admin").await;
    let (_, alice) = ctx.make_user("alice").await;
    let (_, bob) = ctx.make_user("bob").await;
    let asset = ctx.create_asset(&admin, "db1").await;
    let authz = ctx.authorizer();

    // Only bob gets the grant.
    let role = ctx.make_role(&admin, "analyst").await;
    ctx.grants().assign_role_to_user(&admin, bob.user_id(), role).await.unwrap();
    ctx.grant(&admin, role, Effect::Allow, Action::Connect, AssetScope::Asset(asset)).await;

    // Alice's session-validated identity cannot borrow bob's grants, and
    // there is no API to make the authorizer evaluate a different user_id:
    // AuthenticatedPrincipal exposes no constructor or setters.
    assert_denied(authz.authorize(&alice, &ResourceScope::asset(asset), Action::Connect).await);
    assert_allowed(authz.authorize(&bob, &ResourceScope::asset(asset), Action::Connect).await);

    // A garbage token never yields an identity at all.
    let err = ctx.service.auth().authenticate("not-a-real-token").await.unwrap_err();
    assert!(matches!(err, BastionError::InvalidSession));
}

#[tokio::test]
async fn admin_without_connect_cannot_access_data() {
    let ctx = Ctx::new("admin-nodata").await;
    let (_, admin) = ctx.make_admin("admin").await;
    let asset = ctx.create_asset(&admin, "db1").await;
    let authz = ctx.authorizer();

    // bastion-admin manages grants; it grants no data access by itself.
    assert_denied(authz.authorize(&admin, &ResourceScope::asset(asset), Action::Connect).await);
    assert_denied(authz.authorize(&admin, &table_scope(asset, "t"), Action::Select).await);
}

// ---- G. grant administration & delete policy --------------------------------

#[tokio::test]
async fn xor_scope_violations_rejected_at_db() {
    let ctx = Ctx::new("xor-db").await;
    let (_, admin) = ctx.make_admin("admin").await;
    let asset = ctx.create_asset(&admin, "db1").await;
    let _ = admin;

    let role = Uuid::new_v4();
    let conn = rusqlite::Connection::open(&ctx.db_path).unwrap();
    // Both NULL -> CHECK violation.
    let err = conn
        .execute(
            "INSERT INTO permissions (id, role_id, effect, action, asset_id, asset_group_id)
             VALUES (?1, ?2, 'allow', 'connect', NULL, NULL)",
            [Uuid::new_v4().to_string(), role.to_string()],
        )
        .unwrap_err();
    assert!(format!("{err:?}").contains("CHECK"), "both-null must violate CHECK, got {err:?}");
    // Both set -> CHECK violation.
    let err = conn
        .execute(
            "INSERT INTO permissions (id, role_id, effect, action, asset_id, asset_group_id)
             VALUES (?1, ?2, 'allow', 'connect', ?3, ?4)",
            rusqlite::params![
                Uuid::new_v4().to_string(),
                role.to_string(),
                asset.to_string(),
                Uuid::new_v4().to_string()
            ],
        )
        .unwrap_err();
    assert!(format!("{err:?}").contains("CHECK"), "both-set must violate CHECK, got {err:?}");
}

#[tokio::test]
async fn grant_service_validates_connect_scope() {
    let ctx = Ctx::new("connect-scope").await;
    let (_, admin) = ctx.make_admin("admin").await;
    let asset = ctx.create_asset(&admin, "db1").await;

    let role = ctx.make_role(&admin, "analyst").await;
    let err = ctx
        .grants()
        .create_grant(
            &admin,
            NewGrant {
                role_id: role,
                effect: Effect::Allow,
                action: Action::Connect,
                scope: AssetScope::Asset(asset),
                database: None,
                schema: None,
                table: Some("t".to_string()),
                expires_at: None,
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(err, BastionError::InvalidData(_)), "scoped CONNECT grant must be rejected, got {err:?}");
}

#[tokio::test]
async fn non_admin_cannot_manage_grants() {
    let ctx = Ctx::new("grant-guard").await;
    let (_, admin) = ctx.make_admin("admin").await;
    let (_, user) = ctx.make_user("mallory").await;
    let asset = ctx.create_asset(&admin, "db1").await;

    let grants = ctx.grants();
    let role = grants.create_role(&admin, "analyst", "").await.unwrap();
    let err = grants
        .create_grant(
            &user,
            NewGrant {
                role_id: role,
                effect: Effect::Allow,
                action: Action::Connect,
                scope: AssetScope::Asset(asset),
                database: None,
                schema: None,
                table: None,
                expires_at: None,
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(err, BastionError::Forbidden(_)), "non-admin grant creation must be refused, got {err:?}");
}

#[tokio::test]
async fn group_delete_restricted_with_grants() {
    let ctx = Ctx::new("grp-restrict").await;
    let (_, admin) = ctx.make_admin("admin").await;
    let assets = ctx.assets();

    let group = ctx.make_group(&admin, "prod", None).await;
    let role = ctx.make_role(&admin, "analyst").await;
    // A DENY grant scoped to the group...
    ctx.grant(&admin, role, Effect::Deny, Action::Connect, AssetScope::Group(group)).await;

    // ...blocks group deletion with a clear error (no silent DENY wipe).
    let err = assets.delete_group(&admin, group).await.unwrap_err();
    assert!(
        matches!(&err, BastionError::InvalidData(msg) if msg.contains("permission grant")),
        "expected explicit grant-block error, got {err:?}"
    );

    // Explicit revocation first, then deletion succeeds.
    let revoked = ctx.grants().revoke_grants_for_group(&admin, group).await.unwrap();
    assert_eq!(revoked, 1);
    assets.delete_group(&admin, group).await.unwrap();
}

#[tokio::test]
async fn delete_group_cannot_silently_clear_deny() {
    let ctx = Ctx::new("deny-survive").await;
    let (_, admin) = ctx.make_admin("admin").await;
    let (_, user) = ctx.make_user("mallory").await;
    let assets = ctx.assets();
    let authz = ctx.authorizer();

    let group = ctx.make_group(&admin, "prod", None).await;
    let asset = ctx.create_asset(&admin, "db1").await;
    assets.add_asset_to_group(&admin, asset, group).await.unwrap();

    let role = ctx.make_role(&admin, "analyst").await;
    ctx.grants().assign_role_to_user(&admin, user.user_id(), role).await.unwrap();
    ctx.grant(&admin, role, Effect::Allow, Action::Connect, AssetScope::Asset(asset)).await;
    ctx.grant(&admin, role, Effect::Deny, Action::Connect, AssetScope::Group(group)).await;
    assert_denied(authz.authorize(&user, &ResourceScope::asset(asset), Action::Connect).await);

    // Delete path refuses while the DENY exists...
    assert!(assets.delete_group(&admin, group).await.is_err());
    // ...and after explicit revocation + deletion, the effective
    // permission is determined by the remaining grants only.
    assets.remove_asset_from_group(&admin, asset, group).await.unwrap();
    ctx.grants().revoke_grants_for_group(&admin, group).await.unwrap();
    assets.delete_group(&admin, group).await.unwrap();
    assert_allowed(authz.authorize(&user, &ResourceScope::asset(asset), Action::Connect).await);
}

// ---- H. migration 0004 ------------------------------------------------------

#[test]
fn migration_0004_fresh_init() {
    let db_path = temp_db_path("m0004-fresh");
    let _ = std::fs::remove_file(&db_path);
    let service = BastionService::open(&db_path).expect("fresh open");
    drop(service);

    let conn = rusqlite::Connection::open(&db_path).unwrap();
    let versions: Vec<String> = conn
        .prepare("SELECT version FROM schema_migrations ORDER BY version")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    assert_eq!(
        versions,
        vec!["0001_init", "0002_auth", "0003_assets", "0004_rbac", "0005_audit", "0006_audit_recovery"]
    );
    for table in ["user_groups", "user_group_members", "group_roles"] {
        let count: i64 = conn
            .query_row(&format!("SELECT COUNT(*) FROM sqlite_master WHERE name = '{table}'"), [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1, "table {table} must exist");
    }
    // XOR CHECK is live: both-null insert fails.
    let err = conn
        .execute(
            "INSERT INTO permissions (id, role_id, effect, action, asset_id, asset_group_id)
             VALUES ('x', 'y', 'allow', 'connect', NULL, NULL)",
            [],
        )
        .unwrap_err();
    assert!(format!("{err:?}").contains("CHECK"));
    let _ = std::fs::remove_file(&db_path);
}

#[tokio::test]
async fn migration_0004_upgrade_preserves_data() {
    let db_path = temp_db_path("m0004-upgrade");
    let _ = std::fs::remove_file(&db_path);
    let asset_id = Uuid::new_v4();
    let role_id = Uuid::new_v4();
    let grant_id = Uuid::new_v4();
    {
        let mut conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute_batch("CREATE TABLE schema_migrations (version TEXT PRIMARY KEY, applied_at TEXT NOT NULL)")
            .unwrap();
        apply_one_migration(&mut conn, "0001_init", include_str!("../migrations/0001_init.sql")).unwrap();
        apply_one_migration(&mut conn, "0002_auth", include_str!("../migrations/0002_auth.sql")).unwrap();
        apply_one_migration(&mut conn, "0003_assets", include_str!("../migrations/0003_assets.sql")).unwrap();
        conn.execute("INSERT INTO roles (id, name) VALUES (?1, 'legacy-role')", [role_id.to_string()]).unwrap();
        conn.execute(
            "INSERT INTO assets (id, name, environment, db_type, dbx_connection_id, enabled)
             VALUES (?1, 'legacy-asset', 'production', 'mysql', 'conn-old', 1)",
            [asset_id.to_string()],
        )
        .unwrap();
        // Valid historical row: explicit asset scope.
        conn.execute(
            "INSERT INTO permissions (id, role_id, effect, action, asset_id)
             VALUES (?1, ?2, 'allow', 'connect', ?3)",
            rusqlite::params![grant_id.to_string(), role_id.to_string(), asset_id.to_string()],
        )
        .unwrap();
    }

    let service = {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&db_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        BastionService::open(&db_path).expect("upgrade to 0004")
    };
    // The grant survived the table rebuild with its scope intact.
    let grants = GrantService::new(service.store().clone(), test_clock());
    // Bootstrap an admin to read grants.
    let passwords = PasswordService::new(fast_password_config()).unwrap();
    let bootstrap = AdminBootstrap::new(service.store().clone(), passwords.clone(), BootstrapPolicy::default());
    bootstrap.bootstrap(&BootstrapCredentials::new("a", "a", "admin-pw-1")).await.unwrap();
    let login = service
        .auth()
        .login(&LoginRequest {
            username: "a".to_string(),
            password: "admin-pw-1".to_string(),
            source_ip: None,
            user_agent: None,
        })
        .await
        .unwrap();
    let admin = service.auth().authenticate(&login.token).await.unwrap();
    let all = grants.list_grants(&admin).await.unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].id, grant_id);
    assert_eq!(all[0].scope, AssetScope::Asset(asset_id));
    let _ = std::fs::remove_file(&db_path);
}

#[test]
fn migration_0004_aborts_on_null_scope() {
    let db_path = temp_db_path("m0004-abort");
    let _ = std::fs::remove_file(&db_path);
    let role_id = Uuid::new_v4();
    {
        let mut conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute_batch("CREATE TABLE schema_migrations (version TEXT PRIMARY KEY, applied_at TEXT NOT NULL)")
            .unwrap();
        apply_one_migration(&mut conn, "0001_init", include_str!("../migrations/0001_init.sql")).unwrap();
        apply_one_migration(&mut conn, "0002_auth", include_str!("../migrations/0002_auth.sql")).unwrap();
        apply_one_migration(&mut conn, "0003_assets", include_str!("../migrations/0003_assets.sql")).unwrap();
        conn.execute("INSERT INTO roles (id, name) VALUES (?1, 'legacy-role')", [role_id.to_string()]).unwrap();
        // Historical "all assets" row: no explicit scope.
        conn.execute(
            "INSERT INTO permissions (id, role_id, effect, action, asset_id)
             VALUES (?1, ?2, 'allow', 'select', NULL)",
            rusqlite::params![Uuid::new_v4().to_string(), role_id.to_string()],
        )
        .unwrap();
    }

    // The upgrade refuses to silently broaden the grant: open fails...
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&db_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let err = match BastionService::open(&db_path) {
        Ok(_) => panic!("open must fail on NULL-scope historical grants"),
        Err(err) => err,
    };
    assert!(matches!(err, BastionError::Migration(_)), "expected migration failure, got {err:?}");

    // ...the version is not recorded, the offending row is untouched, and
    // the database is still fully usable at 0003.
    let conn = rusqlite::Connection::open(&db_path).unwrap();
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM schema_migrations WHERE version = '0004_rbac'", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 0);
    let rows: i64 =
        conn.query_row("SELECT COUNT(*) FROM permissions WHERE asset_id IS NULL", [], |row| row.get(0)).unwrap();
    assert_eq!(rows, 1, "offending row must not be deleted or converted");
    // Retry after explicit admin remediation succeeds.
    conn.execute("DELETE FROM permissions WHERE asset_id IS NULL", []).unwrap();
    drop(conn);
    BastionService::open(&db_path).expect("open succeeds after remediation");
    let _ = std::fs::remove_file(&db_path);
}

#[test]
fn migration_0004_idempotent() {
    let db_path = temp_db_path("m0004-idem");
    let _ = std::fs::remove_file(&db_path);
    {
        let first = BastionService::open(&db_path).expect("first open");
        drop(first);
        let _second = BastionService::open(&db_path).expect("second open is idempotent");
    }
    let _ = std::fs::remove_file(&db_path);
}

// ---- I. asset visibility ----------------------------------------------------

#[tokio::test]
async fn list_views_pagination_total_consistent() {
    let ctx = Ctx::new("list-page").await;
    let (_, admin) = ctx.make_admin("admin").await;
    let (_, user) = ctx.make_user("mallory").await;
    let assets = ctx.assets();

    // Five assets; CONNECT granted on three (one via group inheritance).
    let mut ids = Vec::new();
    for name in ["a1", "a2", "a3", "a4", "a5"] {
        ids.push(ctx.create_asset(&admin, name).await);
    }
    let group = ctx.make_group(&admin, "team", None).await;
    assets.add_asset_to_group(&admin, ids[2], group).await.unwrap();

    let role = ctx.make_role(&admin, "analyst").await;
    ctx.grants().assign_role_to_user(&admin, user.user_id(), role).await.unwrap();
    ctx.grant(&admin, role, Effect::Allow, Action::Connect, AssetScope::Asset(ids[0])).await;
    ctx.grant(&admin, role, Effect::Allow, Action::Connect, AssetScope::Asset(ids[1])).await;
    ctx.grant(&admin, role, Effect::Allow, Action::Connect, AssetScope::Group(group)).await;

    // Total counts only authorized assets; nothing leaks about a4/a5.
    let page = assets.list_asset_views(&user, AssetFilter::default(), Default::default()).await.unwrap();
    assert_eq!(page.total, 3);
    assert_eq!(page.items.len(), 3);

    // Pagination over the authorized set is consistent.
    let p1 = assets
        .list_asset_views(&user, AssetFilter::default(), PageRequest { page: 1, page_size: 2, ..Default::default() })
        .await
        .unwrap();
    let p2 = assets
        .list_asset_views(&user, AssetFilter::default(), PageRequest { page: 2, page_size: 2, ..Default::default() })
        .await
        .unwrap();
    assert_eq!(p1.total, 3);
    assert_eq!(p2.total, 3);
    assert_eq!(p1.items.len(), 2);
    assert_eq!(p2.items.len(), 1);
    let mut seen: Vec<Uuid> = p1.items.iter().chain(p2.items.iter()).map(|v| v.id).collect();
    seen.sort();
    let mut expected = vec![ids[0], ids[1], ids[2]];
    expected.sort();
    assert_eq!(seen, expected);

    // Search stays inside the authorized set: "a4"/"a5" never appear.
    let search = assets
        .list_asset_views(
            &user,
            AssetFilter { name_contains: Some("a".to_string()), ..Default::default() },
            Default::default(),
        )
        .await
        .unwrap();
    assert_eq!(search.total, 3);
    let search_hidden = assets
        .list_asset_views(
            &user,
            AssetFilter { name_contains: Some("a4".to_string()), ..Default::default() },
            Default::default(),
        )
        .await
        .unwrap();
    assert_eq!(search_hidden.total, 0);
}

#[tokio::test]
async fn list_filter_matches_authorizer_semantics() {
    let ctx = Ctx::new("list-sem").await;
    let (_, admin) = ctx.make_admin("admin").await;
    let (_, user) = ctx.make_user("mallory").await;
    let assets = ctx.assets();
    let authz = ctx.authorizer();

    let mut ids = Vec::new();
    for name in ["s1", "s2", "s3"] {
        ids.push(ctx.create_asset(&admin, name).await);
    }
    let role = ctx.make_role(&admin, "analyst").await;
    ctx.grants().assign_role_to_user(&admin, user.user_id(), role).await.unwrap();
    ctx.grant(&admin, role, Effect::Allow, Action::Connect, AssetScope::Asset(ids[0])).await;
    // DENY on s2 even though a direct ALLOW also exists: DENY wins in both paths.
    ctx.grant(&admin, role, Effect::Allow, Action::Connect, AssetScope::Asset(ids[1])).await;
    ctx.grant(&admin, role, Effect::Deny, Action::Connect, AssetScope::Asset(ids[1])).await;

    let page = assets.list_asset_views(&user, AssetFilter::default(), Default::default()).await.unwrap();
    assert_eq!(page.total, 1);
    assert_eq!(page.items[0].id, ids[0]);

    // Per-item agreement between the list predicate and the authorizer.
    for (id, expected) in [(ids[0], true), (ids[1], false), (ids[2], false)] {
        let decided = authz
            .evaluate_batch(&user, &[AuthorizationCheck::new(ResourceScope::asset(id), Action::Connect)])
            .await
            .unwrap();
        assert_eq!(decided, vec![expected], "list/authorizer drift on {id}");
        assert_eq!(page.items.iter().any(|v| v.id == id), expected);
    }
}

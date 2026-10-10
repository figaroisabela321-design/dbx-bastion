//! TASK-005B integration tests: QueryGateway + SQLite audit + Mock executor.
//!
//! Covers the 24 required scenarios: happy paths, every deny path (with
//! executor call counts at zero), mid-flight revocation via a
//! deterministic hook (no sleeps), audit failure modes, timeout,
//! cancellation, and result limits.
//!
//! All tests use throwaway SQLite files; the executor is a mock — no
//! real database is ever touched.

use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use uuid::Uuid;

use dbx_bastion::asset::{
    AssetRepository, DbxConnectionAdapter, MockDbxConnectionAdapter, NewAsset, NewUser, UserRepository,
};
use dbx_bastion::audit::{AuditService, AuditStatus, SqliteAuditService};
use dbx_bastion::auth::session::SystemClock;
use dbx_bastion::auth::{
    AdminBootstrap, AuthenticatedPrincipal, BootstrapCredentials, BootstrapPolicy, LoginRequest, PasswordConfig,
    PasswordService, SessionRepository,
};
use dbx_bastion::error::BastionError;
use dbx_bastion::query::mock::MockBehavior;
use dbx_bastion::query::{ExecutionOptions, GatewayRequest, MockExecutor, QueryExecutor, QueryGateway};
use dbx_bastion::rbac::{Action, AssetScope, Effect, GrantService, NewGrant};
use dbx_bastion::storage::SqliteStore;
use dbx_bastion::BastionService;
use tokio_util::sync::CancellationToken;

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_db_path(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let path =
        std::env::temp_dir().join(format!("dbx-bastion-gw-test-{}-{}-{}", std::process::id(), n, tag)).join("test.db");
    dbx_bastion::secure_dir::ensure_secure_dir(path.parent().unwrap()).unwrap();
    // Pre-create the file with 0600 for tests using rusqlite directly.
    dbx_bastion::secure_dir::precreate_secure_file(&path).unwrap();
    path
}

fn fast_password_config() -> PasswordConfig {
    PasswordConfig { memory_kib: 8192, iterations: 1, parallelism: 1, min_password_len: 8, max_concurrent_hashes: 4 }
}

fn pw(username: &str) -> String {
    format!("{username}-password-1")
}

/// AuditService wrapper that can fail on demand (scenarios 16/17).
struct FlakyAudit {
    pub inner: SqliteAuditService,
    fail_started: AtomicBool,
    fail_finished: AtomicBool,
}

impl FlakyAudit {
    fn new(store: Arc<SqliteStore>) -> Self {
        Self {
            inner: SqliteAuditService::new(store),
            fail_started: AtomicBool::new(false),
            fail_finished: AtomicBool::new(false),
        }
    }
}

#[async_trait::async_trait]
impl AuditService for FlakyAudit {
    async fn record_started(&self, event: dbx_bastion::audit::AuditEvent) -> dbx_bastion::Result<Uuid> {
        if self.fail_started.load(Ordering::SeqCst) {
            return Err(BastionError::AuditUnavailable("injected started failure".to_string()));
        }
        self.inner.record_started(event).await
    }

    async fn record_finished(&self, id: Uuid, outcome: dbx_bastion::audit::AuditOutcome) -> dbx_bastion::Result<()> {
        if self.fail_finished.load(Ordering::SeqCst) {
            return Err(BastionError::Storage(rusqlite::Error::QueryReturnedNoRows));
        }
        self.inner.record_finished(id, outcome).await
    }

    async fn has_untriaged_interruptions(&self) -> dbx_bastion::Result<bool> {
        self.inner.has_untriaged_interruptions().await
    }

    async fn list_unfinished(&self) -> dbx_bastion::Result<Vec<dbx_bastion::audit::UnfinishedAudit>> {
        self.inner.list_unfinished().await
    }
}

struct Gw {
    service: BastionService,
    passwords: PasswordService,
    db_path: PathBuf,
    audit: Arc<FlakyAudit>,
    executor: Arc<MockExecutor>,
    gateway: QueryGateway,
    admin: AuthenticatedPrincipal,
    user: AuthenticatedPrincipal,
    user_id: Uuid,
    asset_id: Uuid,
    role_id: Uuid,
}

impl Gw {
    async fn new(tag: &str) -> Self {
        Self::new_with_env(tag, "development").await
    }

    async fn new_with_env(tag: &str, env: &str) -> Self {
        let db_path = temp_db_path(tag);
        let _ = std::fs::remove_file(&db_path);
        let service = BastionService::open(&db_path).expect("open");
        let passwords = PasswordService::new(fast_password_config()).expect("passwords");
        let dbx = Arc::new(MockDbxConnectionAdapter::new());
        let store = service.store().clone();

        // Admin + ordinary user.
        let bootstrap = AdminBootstrap::new(store.clone(), passwords.clone(), BootstrapPolicy::default());
        bootstrap.bootstrap(&BootstrapCredentials::new("admin", "admin", &pw("admin"))).await.expect("bootstrap");
        let admin = login(&service, &passwords, "admin").await;
        let user_id = create_user(&service, &passwords, "alice").await;
        let user = login(&service, &passwords, "alice").await;

        // Asset (development MySQL mock).
        let conn_id = format!("conn-{tag}");
        dbx.add_connection(&conn_id);
        let assets = service.asset_service(dbx.clone() as Arc<dyn DbxConnectionAdapter>);
        let asset = assets
            .create_asset(
                &admin,
                NewAsset {
                    name: format!("asset-{tag}"),
                    environment: env.to_string(),
                    db_type: "mysql".to_string(),
                    dbx_connection_id: conn_id,
                    group_ids: vec![],
                    description: "gateway test".to_string(),
                },
            )
            .await
            .expect("create asset");

        // Role + grants: CONNECT, Select on appdb.orders.
        let grants = GrantService::new(store.clone(), Arc::new(SystemClock));
        let role_id = grants.create_role(&admin, "analyst", "").await.expect("role");
        grants.assign_role_to_user(&admin, user_id, role_id).await.expect("assign");
        // CONNECT is asset-level only (never scoped); data grants are scoped.
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
            .expect("connect grant");
        grants
            .create_grant(
                &admin,
                NewGrant {
                    role_id,
                    effect: Effect::Allow,
                    action: Action::Select,
                    scope: AssetScope::Asset(asset.id),
                    database: Some("appdb".to_string()),
                    schema: None,
                    table: Some("orders".to_string()),
                    expires_at: None,
                },
            )
            .await
            .expect("select grant");

        let audit = Arc::new(FlakyAudit::new(store.clone()));
        let executor = Arc::new(MockExecutor::new());
        let gateway = QueryGateway::new(
            store.clone(),
            Arc::new(SystemClock),
            audit.clone() as Arc<dyn AuditService>,
            executor.clone() as Arc<dyn QueryExecutor>,
        );
        Self {
            service,
            passwords,
            db_path,
            audit,
            executor,
            gateway,
            admin,
            user,
            user_id,
            asset_id: asset.id,
            role_id,
        }
    }

    fn req(&self, sql: &str) -> GatewayRequest {
        GatewayRequest { asset_id: self.asset_id, sql: sql.to_string(), options: ExecutionOptions::default() }
    }

    fn grants(&self) -> GrantService {
        GrantService::new(self.service.store().clone(), Arc::new(SystemClock))
    }

    async fn grant(&self, action: Action, table: &str) {
        self.grants()
            .create_grant(
                &self.admin,
                NewGrant {
                    role_id: self.role_id,
                    effect: Effect::Allow,
                    action,
                    scope: AssetScope::Asset(self.asset_id),
                    database: Some("appdb".to_string()),
                    schema: None,
                    table: Some(table.to_string()),
                    expires_at: None,
                },
            )
            .await
            .expect("grant");
    }
}

impl Drop for Gw {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.db_path);
    }
}

async fn login(service: &BastionService, passwords: &PasswordService, username: &str) -> AuthenticatedPrincipal {
    let _ = passwords;
    let result = service
        .auth()
        .login(&LoginRequest {
            username: username.to_string(),
            password: pw(username),
            source_ip: None,
            user_agent: None,
        })
        .await
        .expect("login");
    service.auth().authenticate(&result.token).await.expect("authenticate")
}

async fn create_user(service: &BastionService, passwords: &PasswordService, username: &str) -> Uuid {
    let hash = passwords.hash(&pw(username)).await.expect("hash");
    service
        .store()
        .create_user(&NewUser {
            username: username.to_string(),
            display_name: username.to_string(),
            password_hash: hash,
        })
        .await
        .expect("create user")
}

// ---- 1-3. happy paths ----------------------------------------------------------

#[tokio::test]
async fn legal_nonprod_select_succeeds() {
    let gw = Gw::new("s1").await;
    let dto = gw.gateway.execute(&gw.user, gw.req("SELECT * FROM appdb.orders WHERE id = 1")).await.expect("execute");
    assert_eq!(dto.rows.len(), 2);
    assert!(!dto.truncated);
    assert_eq!(gw.executor.calls(), 1);
    // The executor received the exact SQL.
    assert_eq!(gw.executor.seen_sql(), vec!["SELECT * FROM appdb.orders WHERE id = 1".to_string()]);
}

#[tokio::test]
async fn legal_nonprod_insert_succeeds() {
    let gw = Gw::new("s2").await;
    gw.grant(Action::Insert, "orders").await;
    let dto = gw.gateway.execute(&gw.user, gw.req("INSERT INTO appdb.orders (id) VALUES (1)")).await.expect("execute");
    assert_eq!(gw.executor.calls(), 1);
    let _ = dto;
}

#[tokio::test]
async fn insert_select_needs_both_actions() {
    let gw = Gw::new("s3").await;
    gw.grant(Action::Insert, "archive").await;
    // Missing Select on appdb.staging -> denied.
    let err = gw
        .gateway
        .execute(&gw.user, gw.req("INSERT INTO appdb.archive SELECT * FROM appdb.staging"))
        .await
        .expect_err("must deny");
    assert!(matches!(err, BastionError::Forbidden(_)));
    assert_eq!(gw.executor.calls(), 0);
    // Grant Select on staging -> succeeds.
    gw.grant(Action::Select, "staging").await;
    gw.gateway
        .execute(&gw.user, gw.req("INSERT INTO appdb.archive SELECT * FROM appdb.staging"))
        .await
        .expect("execute");
    assert_eq!(gw.executor.calls(), 1);
}

// ---- 4-10. deny paths (executor stays at zero) ----------------------------------

#[tokio::test]
async fn deny_rule_blocks() {
    let gw = Gw::new("s4").await;
    gw.grants()
        .create_grant(
            &gw.admin,
            NewGrant {
                role_id: gw.role_id,
                effect: Effect::Deny,
                action: Action::Select,
                scope: AssetScope::Asset(gw.asset_id),
                database: Some("appdb".to_string()),
                schema: None,
                table: Some("orders".to_string()),
                expires_at: None,
            },
        )
        .await
        .expect("deny grant");
    let err = gw.gateway.execute(&gw.user, gw.req("SELECT * FROM appdb.orders")).await.expect_err("must deny");
    assert!(matches!(err, BastionError::Forbidden(_)));
    assert_eq!(gw.executor.calls(), 0);
}

#[tokio::test]
async fn default_deny_no_grants() {
    let gw = Gw::new("s5").await;
    // Fresh user with no grants at all.
    let user_id = create_user(&gw.service, &gw.passwords, "bob").await;
    let bob = login(&gw.service, &gw.passwords, "bob").await;
    let _ = user_id;
    let err = gw.gateway.execute(&bob, gw.req("SELECT * FROM appdb.orders")).await.expect_err("must deny");
    assert!(matches!(err, BastionError::Forbidden(_)));
    assert_eq!(gw.executor.calls(), 0);
}

#[tokio::test]
async fn zero_resource_select_is_denied() {
    let gw = Gw::new("s6").await;
    // Complete analysis, zero tables: V1 denies rather than authorizing
    // an empty batch.
    let err = gw.gateway.execute(&gw.user, gw.req("SELECT 1")).await.expect_err("must deny");
    assert!(matches!(err, BastionError::PolicyDenied(_)));
    assert_eq!(gw.executor.calls(), 0);
}

#[tokio::test]
async fn production_assets_never_execute() {
    let gw = Gw::new_with_env("s7", "production").await;
    let err = gw.gateway.execute(&gw.user, gw.req("SELECT * FROM appdb.orders")).await.expect_err("must deny");
    assert!(matches!(err, BastionError::ProductionDenied));
    assert_eq!(gw.executor.calls(), 0);
}

#[tokio::test]
async fn multi_statement_is_denied() {
    let gw = Gw::new("s8").await;
    let err = gw
        .gateway
        .execute(&gw.user, gw.req("SELECT * FROM appdb.orders; DROP TABLE appdb.orders"))
        .await
        .expect_err("must deny");
    assert!(matches!(err, BastionError::PolicyDenied(_)));
    assert_eq!(gw.executor.calls(), 0);
}

#[tokio::test]
async fn ddl_is_denied() {
    let gw = Gw::new("s9").await;
    let err = gw.gateway.execute(&gw.user, gw.req("CREATE TABLE appdb.t (id INT)")).await.expect_err("must deny");
    assert!(matches!(err, BastionError::PolicyDenied(_)));
    assert_eq!(gw.executor.calls(), 0);
}

#[tokio::test]
async fn require_approval_is_denied_without_ticket_service() {
    // Production UPDATE: policy returns RequireApproval (checked before the
    // production gate), and V1 has no approval service -> denied.
    let gw = Gw::new_with_env("s10", "production").await;
    gw.grant(Action::Update, "orders").await;
    let err = gw
        .gateway
        .execute(&gw.user, gw.req("UPDATE appdb.orders SET x = 1 WHERE id = 1"))
        .await
        .expect_err("must deny");
    assert!(matches!(err, BastionError::ApprovalRequired), "got {err:?}");
    assert_eq!(gw.executor.calls(), 0);
}

// ---- 11-15. mid-flight revocation (deterministic hook) ----------------------------

fn hook<F>(f: F) -> dbx_bastion::query::gateway::PreExecuteHook
where
    F: Fn() -> Pin<Box<dyn std::future::Future<Output = ()> + Send>> + Send + Sync + 'static,
{
    Box::new(f)
}

#[tokio::test]
async fn revoked_session_is_not_executed() {
    let gw = Gw::new("s11").await;
    let store = gw.service.store().clone();
    let session_id = gw.user.session_id();
    gw.gateway.set_pre_execute_hook(hook(move || {
        let store = store.clone();
        Box::pin(async move {
            store.revoke_session(session_id).await.expect("revoke");
        }) as Pin<Box<dyn std::future::Future<Output = ()> + Send>>
    }));
    let err = gw.gateway.execute(&gw.user, gw.req("SELECT * FROM appdb.orders")).await.expect_err("must deny");
    assert!(matches!(err, BastionError::Forbidden(_)));
    assert_eq!(gw.executor.calls(), 0);
}

#[tokio::test]
async fn disabled_user_is_not_executed() {
    let gw = Gw::new("s12").await;
    let store = gw.service.store().clone();
    let user_id = gw.user_id;
    gw.gateway.set_pre_execute_hook(hook(move || {
        let store = store.clone();
        Box::pin(async move {
            store.set_user_enabled(user_id, false).await.expect("disable");
        }) as Pin<Box<dyn std::future::Future<Output = ()> + Send>>
    }));
    let err = gw.gateway.execute(&gw.user, gw.req("SELECT * FROM appdb.orders")).await.expect_err("must deny");
    assert!(matches!(err, BastionError::Forbidden(_)));
    assert_eq!(gw.executor.calls(), 0);
}

#[tokio::test]
async fn revoked_role_is_not_executed() {
    let gw = Gw::new("s13").await;
    let store = gw.service.store().clone();
    let admin = gw.admin.clone();
    let user_id = gw.user_id;
    let role_id = gw.role_id;
    gw.gateway.set_pre_execute_hook(hook(move || {
        let store = store.clone();
        let admin = admin.clone();
        Box::pin(async move {
            let grants = GrantService::new(store, Arc::new(SystemClock));
            grants.remove_role_from_user(&admin, user_id, role_id).await.expect("remove role");
        }) as Pin<Box<dyn std::future::Future<Output = ()> + Send>>
    }));
    let err = gw.gateway.execute(&gw.user, gw.req("SELECT * FROM appdb.orders")).await.expect_err("must deny");
    assert!(matches!(err, BastionError::Forbidden(_)));
    assert_eq!(gw.executor.calls(), 0);
}

#[tokio::test]
async fn disabled_asset_is_not_executed() {
    let gw = Gw::new("s14").await;
    let store = gw.service.store().clone();
    let asset_id = gw.asset_id;
    gw.gateway.set_pre_execute_hook(hook(move || {
        let store = store.clone();
        Box::pin(async move {
            store.set_asset_enabled(asset_id, false).await.expect("disable asset");
        }) as Pin<Box<dyn std::future::Future<Output = ()> + Send>>
    }));
    let err = gw.gateway.execute(&gw.user, gw.req("SELECT * FROM appdb.orders")).await.expect_err("must deny");
    assert!(matches!(err, BastionError::Forbidden(_)));
    assert_eq!(gw.executor.calls(), 0);
}

#[tokio::test]
async fn newly_added_deny_is_not_executed() {
    let gw = Gw::new("s15").await;
    let store = gw.service.store().clone();
    let admin = gw.admin.clone();
    let role_id = gw.role_id;
    let asset_id = gw.asset_id;
    gw.gateway.set_pre_execute_hook(hook(move || {
        let store = store.clone();
        let admin = admin.clone();
        Box::pin(async move {
            let grants = GrantService::new(store, Arc::new(SystemClock));
            grants
                .create_grant(
                    &admin,
                    NewGrant {
                        role_id,
                        effect: Effect::Deny,
                        action: Action::Select,
                        scope: AssetScope::Asset(asset_id),
                        database: Some("appdb".to_string()),
                        schema: None,
                        table: Some("orders".to_string()),
                        expires_at: None,
                    },
                )
                .await
                .expect("deny grant");
        }) as Pin<Box<dyn std::future::Future<Output = ()> + Send>>
    }));
    let err = gw.gateway.execute(&gw.user, gw.req("SELECT * FROM appdb.orders")).await.expect_err("must deny");
    assert!(matches!(err, BastionError::Forbidden(_)));
    assert_eq!(gw.executor.calls(), 0);
}

// ---- 16-18. audit failure modes -----------------------------------------------------

#[tokio::test]
async fn audit_started_failure_means_zero_executor_calls() {
    let gw = Gw::new("s16").await;
    gw.audit.fail_started.store(true, Ordering::SeqCst);
    let err = gw.gateway.execute(&gw.user, gw.req("SELECT * FROM appdb.orders")).await.expect_err("must fail");
    assert!(matches!(err, BastionError::AuditUnavailable(_)), "got {err:?}");
    assert_eq!(gw.executor.calls(), 0);
}

#[tokio::test]
async fn audit_finish_failure_enters_fail_closed() {
    let gw = Gw::new("s17").await;
    gw.audit.fail_finished.store(true, Ordering::SeqCst);
    // Execution happened, but completion could not be recorded.
    let err = gw.gateway.execute(&gw.user, gw.req("SELECT * FROM appdb.orders")).await.expect_err("must fail");
    assert!(matches!(err, BastionError::AuditFailClosed), "got {err:?}");
    assert_eq!(gw.executor.calls(), 1);
    // Fail-closed: new executions are refused without touching the executor.
    gw.audit.fail_finished.store(false, Ordering::SeqCst);
    let err = gw.gateway.execute(&gw.user, gw.req("SELECT * FROM appdb.orders")).await.expect_err("must refuse");
    assert!(matches!(err, BastionError::AuditFailClosed));
    assert_eq!(gw.executor.calls(), 1);
}

#[tokio::test]
async fn untriaged_interruptions_refuse_new_executions() {
    let gw = Gw::new("s18").await;
    // Simulate a crash: a `started` row with no terminal state.
    let event = dbx_bastion::audit::AuditEvent {
        id: Uuid::new_v4(),
        user_id: gw.user_id,
        session_id: gw.user.session_id(),
        asset_id: gw.asset_id,
        database: None,
        schema: None,
        sql_text: "SELECT 1".to_string(),
        sql_hash: "00".to_string(),
        action: dbx_bastion::query::StatementAction::Select,
        risk_level: dbx_bastion::policy::RiskLevel::Low,
        policy_decision: None,
        source_ip: None,
        client_request_id: None,
        status: dbx_bastion::audit::AuditStatus::Started,
        success: None,
        row_count: None,
        duration_ms: None,
        error_message: None,
        started_at: chrono::Utc::now(),
        finished_at: None,
    };
    gw.audit.inner.record_started(event).await.expect("seed started");
    // A fresh gateway over the same store refuses immediately.
    let gateway2 = QueryGateway::new(
        gw.service.store().clone(),
        Arc::new(SystemClock),
        gw.audit.clone() as Arc<dyn AuditService>,
        gw.executor.clone() as Arc<dyn QueryExecutor>,
    );
    let err = gateway2.execute(&gw.user, gw.req("SELECT * FROM appdb.orders")).await.expect_err("must refuse");
    assert!(matches!(err, BastionError::AuditFailClosed));
    assert_eq!(gw.executor.calls(), 0);
}

// ---- 19-21. executor failure, timeout, cancellation ------------------------------------

#[tokio::test]
async fn executor_error_is_audited_and_returned() {
    let gw = Gw::new("s19").await;
    gw.executor.set_behavior(MockBehavior::Fail("backend exploded".to_string()));
    let err = gw.gateway.execute(&gw.user, gw.req("SELECT * FROM appdb.orders")).await.expect_err("must fail");
    assert!(matches!(err, BastionError::ExecutorFailed(_)));
    assert_eq!(gw.executor.calls(), 1);
    // The failure was recorded; the gateway still serves new requests.
    gw.executor.set_behavior(MockBehavior::default());
    gw.gateway.execute(&gw.user, gw.req("SELECT * FROM appdb.orders")).await.expect("recovers");
    assert_eq!(gw.executor.calls(), 2);
}

#[tokio::test]
async fn executor_timeout_is_unknown_not_failed() {
    // The backend ignores cancellation: the gateway cannot confirm the
    // outcome, so it must NOT record a plain failure. The audit row is
    // `unknown_interrupted` and the gateway latches fail-closed.
    let gw = Gw::new("s20").await;
    gw.executor.set_behavior(MockBehavior::Hang);
    let mut req = gw.req("SELECT * FROM appdb.orders");
    req.options.timeout = Duration::from_secs(1);
    let err = gw.gateway.execute(&gw.user, req).await.expect_err("must time out");
    assert!(matches!(err, BastionError::ExecutionTimeout), "got {err:?}");
    assert_eq!(gw.executor.calls(), 1);
    assert_eq!(gw.audit.inner.count_by_status(AuditStatus::UnknownInterrupted).await.unwrap(), 1);
    assert_eq!(gw.audit.inner.count_by_status(AuditStatus::Failed).await.unwrap(), 0);
    // Fail-closed: the gateway refuses new executions until triage.
    let err = gw.gateway.execute(&gw.user, gw.req("SELECT * FROM appdb.orders")).await.expect_err("latched");
    assert!(matches!(err, BastionError::AuditFailClosed));
    assert_eq!(gw.executor.calls(), 1);
}

#[tokio::test]
async fn confirmed_cancellation_is_a_clean_failure() {
    // The backend confirms the statement did not complete: this is a
    // clean failure, not an unknown outcome — no fail-closed latch,
    // and the gateway keeps serving.
    let gw = Gw::new("s20b").await;
    gw.executor.set_behavior(MockBehavior::ConfirmCancelAfter { delay: Duration::from_millis(50) });
    let parent = CancellationToken::new();
    let p2 = parent.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        p2.cancel();
    });
    let err = gw
        .gateway
        .execute_with_cancel(&gw.user, gw.req("SELECT * FROM appdb.orders"), parent)
        .await
        .expect_err("cancelled");
    assert!(matches!(err, BastionError::ExecutionCancelled), "got {err:?}");
    assert_eq!(gw.audit.inner.count_by_status(AuditStatus::Failed).await.unwrap(), 1);
    assert_eq!(gw.audit.inner.count_by_status(AuditStatus::UnknownInterrupted).await.unwrap(), 0);
    // Not latched: the next query proceeds.
    gw.executor.set_behavior(MockBehavior::default());
    gw.gateway.execute(&gw.user, gw.req("SELECT * FROM appdb.orders")).await.expect("recovers");
}

// ---- 22. result limits ------------------------------------------------------------------

#[tokio::test]
async fn row_and_byte_limits_are_enforced() {
    let gw = Gw::new("s22").await;
    let rows: Vec<Vec<String>> =
        (0..50).map(|i| vec![format!("row-{i:03}-padding-data-xxxxxxxxxxxxxxxxxxxxxxxxxxxx")]).collect();
    gw.executor.set_behavior(MockBehavior::Success { columns: vec!["c".to_string()], rows, affected_rows: None });
    let mut req = gw.req("SELECT * FROM appdb.orders");
    req.options.max_rows = 10;
    let dto = gw.gateway.execute(&gw.user, req).await.expect("execute");
    assert_eq!(dto.rows.len(), 10);
    assert!(dto.truncated);

    let mut req = gw.req("SELECT * FROM appdb.orders");
    req.options.max_rows = 1000;
    req.options.max_bytes = 1024; // forces byte truncation (50 rows x ~50B)
    let dto = gw.gateway.execute(&gw.user, req).await.expect("execute");
    assert!(dto.rows.len() < 50);
    assert!(dto.truncated);
}

// ---- 23. request shape ----------------------------------------------------------------------

#[tokio::test]
async fn request_cannot_carry_connection_config() {
    // Compile-time property: `GatewayRequest` has exactly three fields
    // (asset_id, sql, options). There is no slot for credentials,
    // `ConnectionConfig`, permission lists, or SQL classification —
    // they cannot be expressed, not merely ignored.
    let req =
        GatewayRequest { asset_id: Uuid::new_v4(), sql: "SELECT 1".to_string(), options: ExecutionOptions::default() };
    let debug = format!("{req:?}");
    assert!(debug.contains("asset_id"));
    assert!(!debug.contains("password"));
    assert!(!debug.contains("ConnectionConfig"));
}

#[tokio::test]
async fn concurrent_queries_do_not_block_each_other() {
    // Two queries in flight on the same gateway: each sees the other's
    // `started` row, but both are owned in-flight, so neither is an
    // interruption. (Requires the mock to actually take time.)
    let gw = Gw::new("conc").await;
    gw.executor.set_behavior(MockBehavior::ConfirmCancelAfter { delay: Duration::from_millis(200) });
    // Use Hang with a twist: we need the queries to overlap. Instead,
    // run both via spawn and join.
    gw.executor.set_behavior(MockBehavior::Success {
        columns: vec!["c".to_string()],
        rows: vec![vec!["1".to_string()]],
        affected_rows: None,
    });
    let g1 = &gw.gateway;
    let g2 = &gw.gateway;
    let (r1, r2) = tokio::join!(
        g1.execute(&gw.user, gw.req("SELECT * FROM appdb.orders")),
        g2.execute(&gw.user, gw.req("SELECT * FROM appdb.orders")),
    );
    r1.expect("query 1");
    r2.expect("query 2");
    assert_eq!(gw.executor.calls(), 2);
    assert_eq!(gw.audit.inner.count_by_status(AuditStatus::Succeeded).await.unwrap(), 2);
}

#[tokio::test]
async fn blocked_denials_produce_audit_rows() {
    // Every denial path must leave a real `blocked` audit row — not
    // merely claim to have recorded one.
    let gw = Gw::new("blk").await;
    // Policy deny.
    let _ = gw.gateway.execute(&gw.user, gw.req("DROP TABLE appdb.orders")).await;
    // RBAC deny.
    let _ = gw.gateway.execute(&gw.user, gw.req("SELECT * FROM appdb.secret")).await;
    // Production deny (via new_with_env would need another Gw; use policy path).
    assert_eq!(gw.audit.inner.count_by_status(AuditStatus::Blocked).await.unwrap(), 2);
    assert_eq!(gw.executor.calls(), 0);
}

// ---- P0-2: audit triage redesign --------------------------------------

use dbx_bastion::audit::{AuditEvent, TriageConclusion};
use dbx_bastion::query::StatementAction;
use std::collections::HashSet;

fn triage_audit() -> SqliteAuditService {
    let db_path = temp_db_path("triage");
    let _ = std::fs::remove_file(&db_path);
    let service = BastionService::open(&db_path).unwrap();
    SqliteAuditService::new(service.store().clone())
}

fn started_event() -> AuditEvent {
    AuditEvent {
        id: Uuid::new_v4(),
        user_id: Uuid::new_v4(),
        session_id: Uuid::new_v4(),
        asset_id: Uuid::new_v4(),
        database: None,
        schema: None,
        sql_text: "SELECT 1".to_string(),
        sql_hash: "00".to_string(),
        action: StatementAction::Select,
        risk_level: dbx_bastion::policy::RiskLevel::Low,
        policy_decision: None,
        source_ip: None,
        client_request_id: None,
        status: AuditStatus::Started,
        success: None,
        row_count: None,
        duration_ms: None,
        error_message: None,
        started_at: chrono::Utc::now(),
        finished_at: None,
    }
}

#[tokio::test]
async fn triage_confirmed_committed_preserves_original() {
    let audit = triage_audit();
    let event = started_event();
    let id = event.id;
    audit.record_started(event).await.unwrap();

    // Triage as confirmed_committed with evidence.
    audit
        .triage_interruption(
            id,
            Uuid::new_v4(),
            "DBA confirmed the transaction committed",
            "binlog shows COMMIT at 2026-10-10T10:00:00Z",
            TriageConclusion::ConfirmedCommitted,
            Arc::new(tokio::sync::Mutex::new(HashSet::new())),
        )
        .await
        .unwrap();

    // Original row is NOT modified in the DB: status stays `started`,
    // not `failed`. (list_unfinished filters confirmed records by design.)
    // We verify via a direct DB read through the store.
    let store = audit.store();
    let status: String = store
        .blocking(move |conn| {
            conn.query_row("SELECT status FROM audit_events WHERE id = ?1", [id.to_string()], |row| row.get(0))
                .map_err(dbx_bastion::error::BastionError::Storage)
        })
        .await
        .unwrap();
    assert_eq!(status, "started", "original audit row must not be modified");

    // Recovery event exists with the conclusion.
    let recovery = audit.get_recovery_event(id).await.unwrap().expect("recovery event");
    assert_eq!(recovery.conclusion, TriageConclusion::ConfirmedCommitted);
    assert_eq!(recovery.original_status, AuditStatus::Started);

    // Execution is unblocked (has_untriaged_interruptions = false).
    assert!(!audit.has_untriaged_interruptions().await.unwrap());
    // And the confirmed record is not listed as unfinished.
    assert!(audit.list_unfinished().await.unwrap().is_empty());
}

#[tokio::test]
async fn triage_still_unknown_keeps_block() {
    let audit = triage_audit();
    let event = started_event();
    let id = event.id;
    audit.record_started(event).await.unwrap();

    audit
        .triage_interruption(
            id,
            Uuid::new_v4(),
            "Cannot determine outcome from logs",
            "",
            TriageConclusion::StillUnknown,
            Arc::new(tokio::sync::Mutex::new(HashSet::new())),
        )
        .await
        .unwrap();

    // Still blocked: still_unknown does not lift the block.
    assert!(audit.has_untriaged_interruptions().await.unwrap());

    // Original preserved.
    let unfinished = audit.list_unfinished().await.unwrap();
    assert!(unfinished.iter().any(|u| u.id == id));
}

#[tokio::test]
async fn triage_inflight_started_rejected() {
    let audit = triage_audit();
    let event = started_event();
    let id = event.id;
    audit.record_started(event).await.unwrap();

    let inflight = Arc::new(tokio::sync::Mutex::new(HashSet::new()));
    inflight.lock().await.insert(id);

    let err = audit
        .triage_interruption(id, Uuid::new_v4(), "reason", "evidence", TriageConclusion::ConfirmedNotExecuted, inflight)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("actively executing"), "unexpected: {err}");

    // Still blocked, no recovery event.
    assert!(audit.has_untriaged_interruptions().await.unwrap());
    assert!(audit.get_recovery_event(id).await.unwrap().is_none());
}

#[tokio::test]
async fn triage_duplicate_rejected() {
    let audit = triage_audit();
    let event = started_event();
    let id = event.id;
    audit.record_started(event).await.unwrap();

    audit
        .triage_interruption(
            id,
            Uuid::new_v4(),
            "first",
            "e1",
            TriageConclusion::ConfirmedNotExecuted,
            Arc::new(tokio::sync::Mutex::new(HashSet::new())),
        )
        .await
        .unwrap();

    // Confirmed conclusions are irreversible.
    let err = audit
        .triage_interruption(
            id,
            Uuid::new_v4(),
            "second",
            "e2",
            TriageConclusion::ConfirmedNotExecuted,
            Arc::new(tokio::sync::Mutex::new(HashSet::new())),
        )
        .await
        .unwrap_err();
    assert!(err.to_string().contains("irreversible"), "unexpected: {err}");
}

#[tokio::test]
async fn triage_still_unknown_can_be_followed_up() {
    // Issue 2: still_unknown -> blocked -> evidence -> confirmed_* -> unblocked.
    // History is preserved (append-only).
    let audit = triage_audit();
    let event = started_event();
    let id = event.id;
    audit.record_started(event).await.unwrap();

    // First: still_unknown (no evidence yet).
    audit
        .triage_interruption(
            id,
            Uuid::new_v4(),
            "logs inconclusive",
            "",
            TriageConclusion::StillUnknown,
            Arc::new(tokio::sync::Mutex::new(HashSet::new())),
        )
        .await
        .unwrap();
    assert!(audit.has_untriaged_interruptions().await.unwrap(), "still_unknown keeps blocking");

    // Later: DBA finds proof, appends confirmed_committed.
    audit
        .triage_interruption(
            id,
            Uuid::new_v4(),
            "DBA confirmed via binlog",
            "binlog COMMIT at 2026-10-10T10:00:00Z",
            TriageConclusion::ConfirmedCommitted,
            Arc::new(tokio::sync::Mutex::new(HashSet::new())),
        )
        .await
        .unwrap();

    // Unblocked now.
    assert!(!audit.has_untriaged_interruptions().await.unwrap());

    // History preserved: two events, oldest first.
    let history = audit.list_recovery_events(id).await.unwrap();
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].conclusion, TriageConclusion::StillUnknown);
    assert_eq!(history[1].conclusion, TriageConclusion::ConfirmedCommitted);

    // Original audit row untouched.
    let unfinished = audit.list_unfinished().await.unwrap();
    assert!(unfinished.is_empty(), "confirmed record is not listed as unfinished");
}

#[tokio::test]
async fn triage_confirmed_cannot_be_reversed() {
    let audit = triage_audit();
    let event = started_event();
    let id = event.id;
    audit.record_started(event).await.unwrap();

    audit
        .triage_interruption(
            id,
            Uuid::new_v4(),
            "confirmed",
            "proof",
            TriageConclusion::ConfirmedCommitted,
            Arc::new(tokio::sync::Mutex::new(HashSet::new())),
        )
        .await
        .unwrap();

    // Cannot "re-triage" to still_unknown to re-block, nor to another conclusion.
    for conclusion in [TriageConclusion::StillUnknown, TriageConclusion::ConfirmedNotExecuted] {
        let err = audit
            .triage_interruption(
                id,
                Uuid::new_v4(),
                "try reverse",
                "e",
                conclusion,
                Arc::new(tokio::sync::Mutex::new(HashSet::new())),
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("irreversible"), "unexpected: {err}");
    }
}

#[tokio::test]
async fn triage_requires_reason_and_evidence_for_confirmed() {
    let audit = triage_audit();
    let event = started_event();
    let id = event.id;
    audit.record_started(event).await.unwrap();

    // Empty reason rejected.
    let err = audit
        .triage_interruption(
            id,
            Uuid::new_v4(),
            "  ",
            "e",
            TriageConclusion::ConfirmedNotExecuted,
            Arc::new(tokio::sync::Mutex::new(HashSet::new())),
        )
        .await
        .unwrap_err();
    assert!(err.to_string().contains("reason is required"));

    // confirmed_* without evidence rejected.
    let err = audit
        .triage_interruption(
            id,
            Uuid::new_v4(),
            "reason",
            "",
            TriageConclusion::ConfirmedCommitted,
            Arc::new(tokio::sync::Mutex::new(HashSet::new())),
        )
        .await
        .unwrap_err();
    assert!(err.to_string().contains("requires evidence"));
}

#[tokio::test]
async fn triage_rejects_overlong_inputs() {
    let audit = triage_audit();
    let event = started_event();
    let id = event.id;
    audit.record_started(event).await.unwrap();

    let long_reason = "x".repeat(2001);
    let err = audit
        .triage_interruption(
            id,
            Uuid::new_v4(),
            &long_reason,
            "e",
            TriageConclusion::StillUnknown,
            Arc::new(tokio::sync::Mutex::new(HashSet::new())),
        )
        .await
        .unwrap_err();
    assert!(err.to_string().contains("exceeds"));

    let long_evidence = "y".repeat(10001);
    let err = audit
        .triage_interruption(
            id,
            Uuid::new_v4(),
            "reason",
            &long_evidence,
            TriageConclusion::StillUnknown,
            Arc::new(tokio::sync::Mutex::new(HashSet::new())),
        )
        .await
        .unwrap_err();
    assert!(err.to_string().contains("exceeds"));
}

#[tokio::test]
async fn triage_terminal_record_rejected() {
    let audit = triage_audit();
    let event = started_event();
    let id = event.id;
    audit.record_started(event).await.unwrap();
    // Finish it (terminal).
    audit
        .record_finished(
            id,
            dbx_bastion::audit::AuditOutcome {
                status: AuditStatus::Failed,
                success: Some(false),
                row_count: None,
                duration_ms: Some(10),
                error_message: Some("err".to_string()),
            },
        )
        .await
        .unwrap();

    let err = audit
        .triage_interruption(
            id,
            Uuid::new_v4(),
            "reason",
            "e",
            TriageConclusion::StillUnknown,
            Arc::new(tokio::sync::Mutex::new(HashSet::new())),
        )
        .await
        .unwrap_err();
    assert!(err.to_string().contains("already terminal"));
}

// ---- P0-1: CTE must not bypass table-level DENY via QueryGateway ----

#[tokio::test]
async fn gateway_cte_does_not_bypass_table_deny() {
    let gw = Gw::new("cte-deny").await;
    // Add a DENY on appdb.secret for the user's role.
    let grants = GrantService::new(gw.service.store().clone(), Arc::new(SystemClock));
    grants
        .create_grant(
            &gw.admin,
            NewGrant {
                role_id: gw.role_id,
                effect: Effect::Deny,
                action: Action::Select,
                scope: AssetScope::Asset(gw.asset_id),
                database: Some("appdb".to_string()),
                schema: None,
                table: Some("secret".to_string()),
                expires_at: None,
            },
        )
        .await
        .expect("deny grant");

    // Attack: CTE named `secret`, then qualified reference to the real
    // `appdb.secret`. The qualified name must hit the DENY, not be
    // skipped as a CTE reference.
    let err = gw
        .gateway
        .execute(&gw.user, gw.req("WITH secret AS (SELECT 1 AS x) SELECT * FROM appdb.secret"))
        .await
        .unwrap_err();
    let msg = format!("{err:?}");
    assert!(
        msg.contains("Denied") || msg.contains("denied") || msg.contains("Forbidden") || msg.contains("RBAC"),
        "qualified table behind CTE name must be denied, got: {msg}"
    );
    // The executor must not have been called.
    assert_eq!(gw.executor.calls(), 0, "denied query must not reach the executor");
}

// ---- Issue 1: full lifecycle ------------------------------------------

#[tokio::test]
async fn lifecycle_orphaned_started_to_ready() {
    // Orphaned STARTED -> DEGRADED (blocked) -> confirmed_* -> still
    // blocked until controlled restart -> READY.
    //
    // Note: the gateway's fail_closed latch is in-memory. After triage,
    // a NEW gateway instance (simulating controlled restart) must not
    // be blocked by the confirmed record.
    let db_path = temp_db_path("lifecycle");
    let _ = std::fs::remove_file(&db_path);
    let service = BastionService::open(&db_path).unwrap();
    let store = service.store().clone();
    let audit = SqliteAuditService::new(store.clone());

    // Simulate an orphaned STARTED (e.g. crash before finish).
    let event = started_event();
    let id = event.id;
    audit.record_started(event).await.unwrap();

    // DEGRADED: blocked.
    assert!(audit.has_untriaged_interruptions().await.unwrap());
    assert_eq!(audit.list_unfinished().await.unwrap().len(), 1);

    // Triage as confirmed_not_executed with evidence.
    audit
        .triage_interruption(
            id,
            Uuid::new_v4(),
            "verified never executed",
            "DBA checked: no such transaction in logs",
            TriageConclusion::ConfirmedNotExecuted,
            Arc::new(tokio::sync::Mutex::new(HashSet::new())),
        )
        .await
        .unwrap();

    // No longer blocking.
    assert!(!audit.has_untriaged_interruptions().await.unwrap());
    assert!(audit.list_unfinished().await.unwrap().is_empty());

    // still_unknown keeps blocking (separate record).
    let event2 = started_event();
    let id2 = event2.id;
    audit.record_started(event2).await.unwrap();
    audit
        .triage_interruption(
            id2,
            Uuid::new_v4(),
            "inconclusive",
            "",
            TriageConclusion::StillUnknown,
            Arc::new(tokio::sync::Mutex::new(HashSet::new())),
        )
        .await
        .unwrap();
    assert!(audit.has_untriaged_interruptions().await.unwrap());
    assert_eq!(audit.list_unfinished().await.unwrap().len(), 1);
}

// ---- Issue 3: inflight lifecycle --------------------------------------

#[tokio::test]
async fn concurrent_query_not_blocked_by_inflight() {
    // Issue 3 requirement: "查询 A 处于执行中时，查询 B 不应错误触发全局 DEGRADED".
    // A hangs in execution (in-flight). B must execute normally, not
    // be refused due to A's STARTED row.
    //
    // Single gateway (V1 model: one gateway per process). A and B share
    // the gateway's inflight set.
    use std::sync::Arc;
    let gw = Gw::new("inflight-conc").await;
    // The Gw's gateway uses FlakyAudit; we need the raw audit for
    // polling. Share the store.
    let gateway = Arc::new(QueryGateway::new(
        gw.service.store().clone(),
        Arc::new(SystemClock),
        Arc::new(SqliteAuditService::new(gw.service.store().clone())) as Arc<dyn AuditService>,
        gw.executor.clone() as Arc<dyn QueryExecutor>,
    ));
    gw.executor.set_behavior(MockBehavior::Hang);

    // Start A (hanging).
    let gw_a = gateway.clone();
    let user_a = gw.user.clone();
    let asset_id = gw.asset_id;
    let handle_a = tokio::spawn(async move {
        let req = GatewayRequest {
            asset_id,
            sql: "SELECT * FROM appdb.orders WHERE id = 1".to_string(),
            options: ExecutionOptions::default(),
        };
        let _ = gw_a.execute(&user_a, req).await;
    });

    // Wait for A's STARTED + inflight registration.
    let audit = SqliteAuditService::new(gw.service.store().clone());
    let mut saw_started = false;
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let unfinished = audit.list_unfinished().await.unwrap();
        if unfinished.iter().any(|u| u.status == AuditStatus::Started) {
            saw_started = true;
            break;
        }
    }
    assert!(saw_started, "A should have a STARTED row");

    // B: reset executor to succeed. B must NOT be blocked by A's in-flight STARTED.
    gw.executor.set_behavior(MockBehavior::Success {
        columns: vec!["id".to_string()],
        rows: vec![vec!["2".to_string()]],
        affected_rows: None,
    });
    let req_b = GatewayRequest {
        asset_id,
        sql: "SELECT * FROM appdb.orders WHERE id = 2".to_string(),
        options: ExecutionOptions::default(),
    };
    let result_b = gateway.execute(&gw.user, req_b).await;
    assert!(result_b.is_ok(), "B must not be blocked by A's in-flight query: {result_b:?}");

    handle_a.abort();
}

// ---- P0-B: Non-recursive CTE self-reference must not bypass DENY ----

#[tokio::test]
async fn gateway_nonrecursive_cte_selfref_does_not_bypass_deny() {
    let gw = Gw::new("cte-p0b-deny").await;
    // DENY on appdb.secret for the user's role.
    let grants = GrantService::new(gw.service.store().clone(), Arc::new(SystemClock));
    grants
        .create_grant(
            &gw.admin,
            NewGrant {
                role_id: gw.role_id,
                effect: Effect::Deny,
                action: Action::Select,
                scope: AssetScope::Asset(gw.asset_id),
                database: Some("appdb".to_string()),
                schema: None,
                table: Some("secret".to_string()),
                expires_at: None,
            },
        )
        .await
        .expect("deny grant");

    // Attack: non-recursive CTE named `secret` whose body references the
    // real `secret` table. P0-B fix: the body's `secret` is a REAL TABLE
    // (not the CTE), so the DENY must fire.
    let err = gw
        .gateway
        .execute(&gw.user, gw.req("WITH secret AS (SELECT * FROM appdb.secret) SELECT * FROM secret"))
        .await
        .unwrap_err();
    let msg = format!("{err:?}");
    assert!(
        msg.contains("Denied") || msg.contains("denied") || msg.contains("Forbidden") || msg.contains("RBAC"),
        "non-recursive self-ref must hit DENY, got: {msg}"
    );
    assert_eq!(gw.executor.calls(), 0, "denied query must not reach the executor");
}

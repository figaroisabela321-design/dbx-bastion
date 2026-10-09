//! TASK-002 integration tests: multi-user authentication and persistent sessions.
//!
//! Covers the 18 required scenarios plus the revision focus areas:
//! migration rollback atomicity, concurrent bootstrap, max concurrent
//! sessions, password-change/session-revoke atomicity, validate/revoke
//! races, rate-limit capacity bounds, insecure secret files, admin having no
//! implicit DB permissions, Argon2 executor behavior, and dbx.db isolation.
//!
//! All tests use throwaway SQLite files; no production database is touched.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use dbx_bastion::asset::{NewUser, UserRepository};
use dbx_bastion::auth::{
    AdminBootstrap, AuthConfig, AuthService, BootstrapCredentials, BootstrapPolicy, LoginRateLimiter, LoginRequest,
    LoginResult, ManualClock, PasswordConfig, PasswordService, RateLimitConfig, SameSite, SessionConfig,
    SessionCookiePolicy, SessionService,
};
use dbx_bastion::error::BastionError;
use dbx_bastion::rbac::GrantService;
use dbx_bastion::storage::{apply_one_migration, SqliteStore};
use dbx_bastion::BastionService;
use uuid::Uuid;

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_db_path(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let path = std::env::temp_dir()
        .join(format!("dbx-bastion-auth-test-{}-{}-{}", std::process::id(), n, tag))
        .join("test.db");
    // Ensure the parent exists (securely) for tests using rusqlite directly.
    dbx_bastion::secure_dir::ensure_secure_dir(path.parent().unwrap()).unwrap();
    path
}

/// Fast-but-meaningful Argon2 params for tests (still Argon2id + PHC).
fn fast_password_config() -> PasswordConfig {
    PasswordConfig { memory_kib: 8192, iterations: 1, parallelism: 1, min_password_len: 8, max_concurrent_hashes: 4 }
}

fn fast_auth_config() -> AuthConfig {
    AuthConfig {
        passwords: fast_password_config(),
        sessions: SessionConfig::default(),
        rate_limit: RateLimitConfig::default(),
    }
}

struct Ctx {
    service: BastionService,
    auth: AuthService,
    passwords: PasswordService,
    db_path: PathBuf,
}

impl Ctx {
    async fn new(tag: &str) -> Self {
        let db_path = temp_db_path(tag);
        let service = BastionService::open(&db_path).expect("open bastion db");
        let store = service.store().clone();
        let auth = AuthService::new(store, fast_auth_config()).expect("auth service");
        let passwords = PasswordService::new(fast_password_config()).expect("password service");
        Self { service, auth, passwords, db_path }
    }

    fn store(&self) -> Arc<SqliteStore> {
        self.service.store().clone()
    }

    /// Current stored password hash (the value a login would verify against).
    async fn user_hash(&self, user_id: Uuid) -> String {
        self.store().find_user_by_id(user_id).await.expect("find user").expect("user exists").password_hash
    }

    async fn create_user(&self, username: &str, password: &str) -> Uuid {
        let hash = self.passwords.hash(password).await.expect("hash password");
        self.store()
            .create_user(&NewUser {
                username: username.to_string(),
                display_name: username.to_string(),
                password_hash: hash,
            })
            .await
            .expect("create user")
    }

    async fn login(&self, username: &str, password: &str) -> Result<LoginResult, BastionError> {
        self.auth
            .login(&LoginRequest {
                username: username.to_string(),
                password: password.to_string(),
                source_ip: Some("10.0.0.1".to_string()),
                user_agent: Some("auth-test".to_string()),
            })
            .await
    }
}

fn assert_auth_failed(result: Result<LoginResult, BastionError>) {
    assert!(matches!(result, Err(BastionError::AuthenticationFailed)), "expected AuthenticationFailed");
}

fn assert_invalid_session<T>(result: Result<T, BastionError>) {
    assert!(matches!(result, Err(BastionError::InvalidSession)), "expected InvalidSession");
}

// ---- 5. password hash round-trip ------------------------------------------

#[tokio::test]
async fn password_hash_verify_roundtrip() {
    let passwords = PasswordService::new(fast_password_config()).unwrap();
    let hash = passwords.hash("correct-horse-1").await.unwrap();
    assert!(hash.starts_with("$argon2id$"), "PHC format: {hash}");
    assert!(passwords.verify("correct-horse-1", &hash).await.unwrap());
    assert!(!passwords.verify("correct-horse-2", &hash).await.unwrap());
}

// ---- 6. independent salts --------------------------------------------------

#[tokio::test]
async fn same_password_different_salts() {
    let passwords = PasswordService::new(fast_password_config()).unwrap();
    let a = passwords.hash("same-password").await.unwrap();
    let b = passwords.hash("same-password").await.unwrap();
    assert_ne!(a, b, "same password must produce different hashes");
    assert!(passwords.verify("same-password", &a).await.unwrap());
    assert!(passwords.verify("same-password", &b).await.unwrap());
}

#[tokio::test]
async fn password_policy_enforced() {
    let passwords = PasswordService::new(fast_password_config()).unwrap();
    let err = passwords.hash("short").await.unwrap_err();
    assert!(matches!(err, BastionError::WeakPassword(_)));
}

// ---- 1. correct login ------------------------------------------------------

#[tokio::test]
async fn login_success() {
    let ctx = Ctx::new("login-success").await;
    ctx.create_user("alice", "alice-password-1").await;

    let result = ctx.login("alice", "alice-password-1").await.unwrap();
    assert!(!result.token.is_empty());
    assert_eq!(result.principal.username, "alice");
    assert_eq!(result.principal.source_ip.as_deref(), Some("10.0.0.1"));

    // The issued token validates.
    let principal = ctx.auth.validate_token(&result.token).await.unwrap();
    assert_eq!(principal.user_id, result.principal.user_id);
    assert_eq!(principal.session_id, result.principal.session_id);
}

// ---- 2/3. wrong password vs unknown user: same error -----------------------

#[tokio::test]
async fn login_wrong_password_and_unknown_user_share_error() {
    let ctx = Ctx::new("login-failures").await;
    ctx.create_user("bob", "bob-password-1").await;

    assert_auth_failed(ctx.login("bob", "wrong-password").await);
    // Unknown user: same error variant (anti-enumeration), after a
    // timing-equalized dummy Argon2 verification.
    assert_auth_failed(ctx.login("nobody-here", "whatever").await);
}

// ---- 4. disabled user ------------------------------------------------------

#[tokio::test]
async fn login_disabled_user_fails() {
    let ctx = Ctx::new("login-disabled").await;
    let id = ctx.create_user("carol", "carol-password-1").await;
    ctx.store().set_user_enabled(id, false).await.unwrap();

    assert_auth_failed(ctx.login("carol", "carol-password-1").await);
}

#[tokio::test]
async fn login_username_case_insensitive() {
    let ctx = Ctx::new("login-case").await;
    ctx.create_user("CaseUser", "case-password-1").await;
    assert!(ctx.login("caseuser", "case-password-1").await.is_ok());
    assert!(ctx.login("CASEUSER", "case-password-1").await.is_ok());
    assert_eq!(LoginRateLimiter::normalize_username("  AdMiN "), "admin");
}

// ---- 7/8. session create + validate ----------------------------------------

#[tokio::test]
async fn session_validate_rebuilds_principal_from_db() {
    let ctx = Ctx::new("session-validate").await;
    let store = ctx.store();

    // Bootstrap an admin so roles exist, then log in.
    let bootstrap = AdminBootstrap::new(store.clone(), ctx.passwords.clone(), BootstrapPolicy::default());
    bootstrap.bootstrap(&BootstrapCredentials::new("sessadmin", "Sess Admin", "sess-admin-pw-1")).await.unwrap();
    let login = ctx.login("sessadmin", "sess-admin-pw-1").await.unwrap();
    assert_eq!(login.principal.roles, vec!["bastion-admin".to_string()]);

    // Simulate an out-of-band role grant with a second connection, then
    // validate again: roles must be re-read, not snapshotted at login.
    {
        let conn = rusqlite::Connection::open(&ctx.db_path).unwrap();
        let role_id = Uuid::new_v4().to_string();
        conn.execute(
            "INSERT INTO roles (id, name, description, system_role) VALUES (?1, 'analyst', 'x', 0)",
            [&role_id],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO user_roles (user_id, role_id) VALUES (?1, ?2)",
            [login.principal.user_id.to_string(), role_id],
        )
        .unwrap();
    }
    let principal = ctx.auth.validate_token(&login.token).await.unwrap();
    assert!(principal.roles.contains(&"bastion-admin".to_string()));
    assert!(principal.roles.contains(&"analyst".to_string()));
}

// ---- 9. absolute expiry via controllable clock ------------------------------

#[tokio::test]
async fn session_expired_by_ttl() {
    let ctx = Ctx::new("session-ttl").await;
    let clock = Arc::new(ManualClock::new(Utc::now()));
    let config = SessionConfig { ttl: Duration::from_secs(60), ..SessionConfig::default() };
    let sessions = SessionService::new(ctx.store(), config, clock.clone()).unwrap();

    let user = ctx.create_user("dave", "dave-password-1").await;
    let hash = ctx.user_hash(user).await;
    let (_, token) = sessions.create_session(user, &hash, None, None).await.unwrap();
    assert!(sessions.validate_token(&token).await.is_ok());

    clock.advance(chrono::Duration::seconds(61));
    assert_invalid_session(sessions.validate_token(&token).await);

    // Expired sessions are purged.
    assert_eq!(sessions.purge_expired().await.unwrap(), 1);
    assert_eq!(sessions.purge_expired().await.unwrap(), 0);
}

// ---- idle timeout + touch-throttle boundary --------------------------------

#[tokio::test]
async fn session_idle_timeout_and_touch_boundary() {
    let ctx = Ctx::new("session-idle").await;
    let clock = Arc::new(ManualClock::new(Utc::now()));
    let config = SessionConfig {
        ttl: Duration::from_secs(3600),
        idle_timeout: Duration::from_secs(300),
        max_concurrent_sessions: 5,
        touch_throttle: Duration::from_secs(60),
    };
    let sessions = SessionService::new(ctx.store(), config, clock.clone()).unwrap();

    let user = ctx.create_user("erin", "erin-password-1").await;
    let hash = ctx.user_hash(user).await;
    let (_, token) = sessions.create_session(user, &hash, None, None).await.unwrap();

    // An active user (validating every 100s, each validation refreshing the
    // throttled timestamp) is never kicked, even past the absolute
    // idle_timeout measured from creation.
    for _ in 0..10 {
        clock.advance(chrono::Duration::seconds(100));
        assert!(sessions.validate_token(&token).await.is_ok());
    }

    // Genuine idleness beyond the timeout is rejected.
    clock.advance(chrono::Duration::seconds(301));
    assert_invalid_session(sessions.validate_token(&token).await);
}

#[test]
fn session_config_rejects_bad_throttle_boundary() {
    let bad = SessionConfig {
        touch_throttle: Duration::from_secs(300),
        idle_timeout: Duration::from_secs(300),
        ..SessionConfig::default()
    };
    assert!(bad.validate().is_err());
}

// ---- 10. revoked session ----------------------------------------------------

#[tokio::test]
async fn session_revoked_fails() {
    let ctx = Ctx::new("session-revoke").await;
    ctx.create_user("frank", "frank-password-1").await;
    let login = ctx.login("frank", "frank-password-1").await.unwrap();

    assert!(ctx.auth.sessions().revoke_session(login.principal.session_id).await.unwrap());
    // Second revoke is a no-op returning false (idempotent).
    assert!(!ctx.auth.sessions().revoke_session(login.principal.session_id).await.unwrap());
    assert_invalid_session(ctx.auth.validate_token(&login.token).await);

    // logout() revokes too.
    let login2 = ctx.login("frank", "frank-password-1").await.unwrap();
    ctx.auth.logout(login2.principal.session_id).await.unwrap();
    assert_invalid_session(ctx.auth.validate_token(&login2.token).await);
}

// ---- 11. disabled user -> existing sessions invalid -------------------------

#[tokio::test]
async fn disabled_user_existing_session_invalid() {
    let ctx = Ctx::new("session-disable").await;
    let id = ctx.create_user("grace", "grace-password-1").await;
    let login = ctx.login("grace", "grace-password-1").await.unwrap();
    assert!(ctx.auth.validate_token(&login.token).await.is_ok());

    ctx.store().set_user_enabled(id, false).await.unwrap();
    assert_invalid_session(ctx.auth.validate_token(&login.token).await);
}

// ---- 12. password change revokes sessions, atomically -----------------------

#[tokio::test]
async fn change_password_revokes_sessions_atomically() {
    let ctx = Ctx::new("change-password").await;
    let id = ctx.create_user("heidi", "old-password-1").await;

    let login1 = ctx.login("heidi", "old-password-1").await.unwrap();
    let login2 = ctx.login("heidi", "old-password-1").await.unwrap();

    ctx.auth.change_password(id, "old-password-1", "new-password-2").await.unwrap();

    // Both pre-change sessions are dead.
    assert_invalid_session(ctx.auth.validate_token(&login1.token).await);
    assert_invalid_session(ctx.auth.validate_token(&login2.token).await);
    // Old password no longer works; new one does.
    assert_auth_failed(ctx.login("heidi", "old-password-1").await);
    let login3 = ctx.login("heidi", "new-password-2").await.unwrap();
    assert!(ctx.auth.validate_token(&login3.token).await.is_ok());

    // Wrong old password changes nothing.
    let err = ctx.auth.change_password(id, "not-the-password", "another-new-3").await.unwrap_err();
    assert!(matches!(err, BastionError::AuthenticationFailed));
    assert!(ctx.auth.validate_token(&login3.token).await.is_ok());

    // Weak new password is rejected BEFORE any mutation: sessions survive.
    let err = ctx.auth.change_password(id, "new-password-2", "short").await.unwrap_err();
    assert!(matches!(err, BastionError::WeakPassword(_)));
    assert!(ctx.auth.validate_token(&login3.token).await.is_ok());
    assert!(ctx.login("heidi", "new-password-2").await.is_ok());
}

// ---- 13. no plaintext token in the database ---------------------------------

#[tokio::test]
async fn db_contains_no_plaintext_token() {
    let ctx = Ctx::new("no-plaintext").await;
    ctx.create_user("ivan", "ivan-password-1").await;
    let login = ctx.login("ivan", "ivan-password-1").await.unwrap();

    let conn = rusqlite::Connection::open(&ctx.db_path).unwrap();
    let hashes: Vec<String> = conn
        .prepare("SELECT token_hash FROM sessions")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert!(!hashes.is_empty());
    for hash in &hashes {
        assert_eq!(hash.len(), 64, "SHA256 hex digest");
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(hash, &login.token);
    }
    // And no password plaintext anywhere near the users table either.
    let stored: String =
        conn.query_row("SELECT password_hash FROM users WHERE username = 'ivan'", [], |row| row.get(0)).unwrap();
    assert!(stored.starts_with("$argon2id$"));
    assert!(!stored.contains("ivan-password-1"));
}

// ---- 14. bootstrap: first succeeds, repeat refused --------------------------

#[tokio::test]
async fn bootstrap_first_ok_second_rejected() {
    let ctx = Ctx::new("bootstrap").await;
    let store = ctx.store();
    let bootstrap = AdminBootstrap::new(store.clone(), ctx.passwords.clone(), BootstrapPolicy::default());

    // Default credential pairs are forbidden outright.
    let err = bootstrap.bootstrap(&BootstrapCredentials::new("admin", "Admin", "admin")).await.unwrap_err();
    assert!(matches!(err, BastionError::WeakPassword(_)));

    let id =
        bootstrap.bootstrap(&BootstrapCredentials::new("rootadmin", "Root Admin", "bootstrap-pw-123")).await.unwrap();

    // Persistent marker row exists.
    let conn = rusqlite::Connection::open(&ctx.db_path).unwrap();
    let marked: i64 =
        conn.query_row("SELECT COUNT(*) FROM bootstrap_state WHERE id = 1", [], |row| row.get(0)).unwrap();
    assert_eq!(marked, 1);
    // The admin user really exists and is enabled.
    let enabled: i64 =
        conn.query_row("SELECT enabled FROM users WHERE id = ?1", [id.to_string()], |row| row.get(0)).unwrap();
    assert_eq!(enabled, 1);
    drop(conn);

    // A second initial bootstrap is refused, even with different credentials.
    let err = bootstrap
        .bootstrap(&BootstrapCredentials::new("another", "Another Admin", "bootstrap-pw-456"))
        .await
        .unwrap_err();
    assert!(matches!(err, BastionError::AlreadyBootstrapped));

    // And the first admin can actually log in.
    let login = ctx.login("rootadmin", "bootstrap-pw-123").await.unwrap();
    assert_eq!(login.principal.user_id, id);
}

// ---- admin gets NO implicit database permissions ----------------------------

#[tokio::test]
async fn bootstrap_grants_no_db_permissions() {
    let ctx = Ctx::new("bootstrap-noperms").await;
    let bootstrap = AdminBootstrap::new(ctx.store(), ctx.passwords.clone(), BootstrapPolicy::default());
    bootstrap.bootstrap(&BootstrapCredentials::new("platadmin", "Platform Admin", "plat-admin-pw-1")).await.unwrap();

    let login = ctx.login("platadmin", "plat-admin-pw-1").await.unwrap();
    assert_eq!(login.principal.roles, vec!["bastion-admin".to_string()]);

    // Platform admin != database operator: bootstrap creates no grants at
    // all, so no implicit SELECT/UPDATE/DELETE/DDL/EXPORT.
    let admin = ctx.service.auth().authenticate(&login.token).await.unwrap();
    let grants =
        GrantService::new(ctx.service.store().clone(), std::sync::Arc::new(dbx_bastion::auth::session::SystemClock));
    assert!(grants.list_grants(&admin).await.unwrap().is_empty(), "bootstrap must not create grants");
}

// ---- controlled recovery path ------------------------------------------------

#[tokio::test]
async fn bootstrap_recovery_path() {
    let ctx = Ctx::new("bootstrap-recover").await;
    let store = ctx.store();
    let bootstrap = AdminBootstrap::new(store.clone(), ctx.passwords.clone(), BootstrapPolicy::default());
    let first =
        bootstrap.bootstrap(&BootstrapCredentials::new("firstadmin", "First", "first-admin-pw-1")).await.unwrap();

    // Recovery without the explicit confirmation string is refused.
    let err = bootstrap
        .recover_admin(&BootstrapCredentials::new("recovered", "Recovered", "recovery-pw-123"), "nope")
        .await
        .unwrap_err();
    assert!(matches!(err, BastionError::Bootstrap(_)));

    // Recovery while an enabled admin exists is refused.
    let err = bootstrap
        .recover_admin(&BootstrapCredentials::new("recovered", "Recovered", "recovery-pw-123"), "RECOVER-ADMIN")
        .await
        .unwrap_err();
    assert!(matches!(err, BastionError::Bootstrap(_)));

    // Simulate lockout: disable the only admin, then recover.
    store.set_user_enabled(first, false).await.unwrap();
    assert_auth_failed(ctx.login("firstadmin", "first-admin-pw-1").await);
    let recovered = bootstrap
        .recover_admin(&BootstrapCredentials::new("recovered", "Recovered", "recovery-pw-123"), "RECOVER-ADMIN")
        .await
        .unwrap();
    assert_ne!(recovered, first);
    let login = ctx.login("recovered", "recovery-pw-123").await.unwrap();
    assert!(login.principal.roles.contains(&"bastion-admin".to_string()));
}

// ---- 17. concurrent bootstrap: exactly one wins ------------------------------

#[tokio::test]
async fn concurrent_bootstrap_only_one_wins() {
    let ctx = Ctx::new("bootstrap-race").await;
    let mut handles = Vec::new();
    for i in 0..8u32 {
        let store = ctx.store();
        let passwords = ctx.passwords.clone();
        handles.push(tokio::spawn(async move {
            let bootstrap = AdminBootstrap::new(store, passwords, BootstrapPolicy::default());
            bootstrap.bootstrap(&BootstrapCredentials::new(&format!("raceadmin{i}"), "Race", "race-admin-pw-123")).await
        }));
    }
    let mut ok = 0;
    let mut already = 0;
    for handle in handles {
        match handle.await.unwrap() {
            Ok(_) => ok += 1,
            Err(BastionError::AlreadyBootstrapped) => already += 1,
            Err(other) => panic!("unexpected bootstrap error: {other}"),
        }
    }
    assert_eq!(ok, 1, "exactly one bootstrap must succeed");
    assert_eq!(already, 7);
}

// ---- 15. 0001 -> 0002 upgrade, then idempotent --------------------------------

#[tokio::test]
async fn migration_0001_to_0002_upgrade_idempotent() {
    let db_path = temp_db_path("mig-upgrade");
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute_batch(include_str!("../migrations/0001_init.sql")).unwrap();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_migrations (
                 version TEXT PRIMARY KEY, applied_at TEXT NOT NULL)",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO schema_migrations (version, applied_at)
             VALUES ('0001_init', '2026-01-01T00:00:00Z')",
            [],
        )
        .unwrap();
        // A pre-0002 session row (no last_active_at column yet).
        conn.execute(
            "INSERT INTO users (id, username, display_name, password_hash, enabled)
             VALUES ('u1', 'old', 'Old', 'hash', 1)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO sessions (id, user_id, token_hash, created_at, expires_at)
             VALUES ('s1', 'u1', 'h', '2026-01-01T00:00:00Z', '2027-01-01T00:00:00Z')",
            [],
        )
        .unwrap();
    }

    // Upgrade applies 0002 exactly once.
    let _service = BastionService::open(&db_path).unwrap();
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        // last_active_at backfilled from created_at.
        let last_active: String =
            conn.query_row("SELECT last_active_at FROM sessions WHERE id = 's1'", [], |row| row.get(0)).unwrap();
        assert_eq!(last_active, "2026-01-01T00:00:00Z");
        let marker_tables: i64 = conn
            .query_row("SELECT COUNT(*) FROM sqlite_master WHERE name = 'bootstrap_state'", [], |row| row.get(0))
            .unwrap();
        assert_eq!(marker_tables, 1);
        let versions: Vec<String> = conn
            .prepare("SELECT version FROM schema_migrations ORDER BY version")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(
            versions,
            vec![
                "0001_init".to_string(),
                "0002_auth".to_string(),
                "0003_assets".to_string(),
                "0004_rbac".to_string(),
                "0005_audit".to_string()
            ]
        );
    }

    // Reopening is idempotent: no duplicate migration, no data loss.
    let _service = BastionService::open(&db_path).unwrap();
    let conn = rusqlite::Connection::open(&db_path).unwrap();
    let count: i64 = conn.query_row("SELECT COUNT(*) FROM schema_migrations", [], |row| row.get(0)).unwrap();
    assert_eq!(count, 5);
    let sessions: i64 = conn.query_row("SELECT COUNT(*) FROM sessions", [], |row| row.get(0)).unwrap();
    assert_eq!(sessions, 1);
}

// ---- migration failure rolls back atomically ---------------------------------

#[test]
fn migration_failure_rolls_back_atomically() {
    let db_path = temp_db_path("mig-rollback");
    let mut conn = rusqlite::Connection::open(&db_path).unwrap();
    conn.execute_batch("CREATE TABLE schema_migrations (version TEXT PRIMARY KEY, applied_at TEXT NOT NULL)").unwrap();

    // The batch creates t1 and then fails: nothing may survive.
    let bad_sql = "CREATE TABLE t1 (id INTEGER PRIMARY KEY); THIS IS NOT VALID SQL;";
    let err = apply_one_migration(&mut conn, "0099_bad", bad_sql).unwrap_err();
    assert!(matches!(err, BastionError::Migration(_)), "expected Migration error, got {err:?}");
    let versions: i64 = conn.query_row("SELECT COUNT(*) FROM schema_migrations", [], |row| row.get(0)).unwrap();
    assert_eq!(versions, 0, "failed migration must not record a version");
    let partial: i64 =
        conn.query_row("SELECT COUNT(*) FROM sqlite_master WHERE name = 't1'", [], |row| row.get(0)).unwrap();
    assert_eq!(partial, 0, "partial DDL must be rolled back");

    // A subsequent good migration still applies cleanly.
    apply_one_migration(&mut conn, "0099_good", "CREATE TABLE t2 (id INTEGER PRIMARY KEY);").unwrap();
    let versions: i64 = conn.query_row("SELECT COUNT(*) FROM schema_migrations", [], |row| row.get(0)).unwrap();
    assert_eq!(versions, 1);
}

// ---- 16. sibling dbx.db untouched ----------------------------------------------

#[tokio::test]
async fn sibling_dbx_db_untouched() {
    let dir = std::env::temp_dir().join(format!(
        "dbx-bastion-dbxdb-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::SeqCst)
    ));
    dbx_bastion::secure_dir::ensure_secure_dir(&dir).unwrap();
    let dbx_path = dir.join("dbx.db");
    {
        let conn = rusqlite::Connection::open(&dbx_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE connections (id TEXT PRIMARY KEY);
             INSERT INTO connections VALUES ('c1');",
        )
        .unwrap();
    }

    let bastion_path = dir.join("bastion.db");
    let service = BastionService::open(&bastion_path).unwrap();
    let auth = AuthService::new(service.store().clone(), fast_auth_config()).unwrap();
    // Exercise the full auth flow against bastion.db.
    let passwords = PasswordService::new(fast_password_config()).unwrap();
    let hash = passwords.hash("some-password-1").await.unwrap();
    service
        .store()
        .create_user(&NewUser { username: "zara".to_string(), display_name: "Zara".to_string(), password_hash: hash })
        .await
        .unwrap();
    let login = auth
        .login(&LoginRequest {
            username: "zara".to_string(),
            password: "some-password-1".to_string(),
            source_ip: None,
            user_agent: None,
        })
        .await
        .unwrap();
    auth.validate_token(&login.token).await.unwrap();

    // dbx.db is byte-for-byte the DBX database: original data intact, no
    // bastion tables leaked in.
    let conn = rusqlite::Connection::open(&dbx_path).unwrap();
    let count: i64 = conn.query_row("SELECT COUNT(*) FROM connections", [], |row| row.get(0)).unwrap();
    assert_eq!(count, 1);
    let leaked: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master
              WHERE name IN ('users', 'sessions', 'bootstrap_state', 'schema_migrations')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(leaked, 0);
}

// ---- validate/revoke race -----------------------------------------------------

#[tokio::test]
async fn concurrent_revoke_and_validate() {
    let ctx = Ctx::new("validate-race").await;
    ctx.create_user("judy", "judy-password-1").await;
    let login = ctx.login("judy", "judy-password-1").await.unwrap();
    let auth = Arc::new(ctx.auth);
    let session_id = login.principal.session_id;
    let token = login.token;

    let mut handles = Vec::new();
    for _ in 0..16 {
        let auth_v = Arc::clone(&auth);
        let token_v = token.clone();
        handles.push(tokio::spawn(async move {
            let _ = auth_v.validate_token(&token_v).await;
        }));
        let auth_r = Arc::clone(&auth);
        handles.push(tokio::spawn(async move {
            let _ = auth_r.sessions().revoke_session(session_id).await;
        }));
    }
    for handle in handles {
        handle.await.unwrap();
    }
    // After the race the session is revoked; validation fails closed.
    assert_invalid_session(auth.validate_token(&token).await);
}

// ---- max concurrent sessions ---------------------------------------------------

#[tokio::test]
async fn max_concurrent_sessions_evicts_oldest() {
    let ctx = Ctx::new("max-sessions").await;
    let mut config = fast_auth_config();
    config.sessions.max_concurrent_sessions = 2;
    let auth = AuthService::new(ctx.store(), config).unwrap();
    ctx.create_user("karl", "karl-password-1").await;

    let login_request = || LoginRequest {
        username: "karl".to_string(),
        password: "karl-password-1".to_string(),
        source_ip: Some("10.0.0.9".to_string()),
        user_agent: None,
    };
    let t1 = auth.login(&login_request()).await.unwrap().token;
    let t2 = auth.login(&login_request()).await.unwrap().token;
    let t3 = auth.login(&login_request()).await.unwrap().token;

    // Oldest evicted, the two newest survive.
    assert_invalid_session(auth.validate_token(&t1).await);
    assert!(auth.validate_token(&t2).await.is_ok());
    assert!(auth.validate_token(&t3).await.is_ok());
}

// ---- 18. rate limiting: cooldown + success reset --------------------------------

#[tokio::test]
async fn rate_limit_cooldown_and_success_reset() {
    let ctx = Ctx::new("rate-limit").await;
    let mut config = fast_auth_config();
    config.rate_limit = RateLimitConfig {
        max_attempts: 3,
        window: Duration::from_secs(60),
        cooldown: Duration::from_secs(2),
        max_attempts_per_ip: 1000,
        max_entries: 1000,
    };
    let auth = AuthService::new(ctx.store(), config).unwrap();
    ctx.create_user("leo", "leo-password-1").await;
    let attempt = |password: String| {
        let auth = &auth;
        async move {
            auth.login(&LoginRequest {
                username: "leo".to_string(),
                password,
                source_ip: Some("10.9.9.9".to_string()),
                user_agent: None,
            })
            .await
        }
    };

    for _ in 0..3 {
        assert_auth_failed(attempt("wrong".to_string()).await);
    }
    // Over the budget: locked, even with the right password.
    assert!(matches!(attempt("wrong".to_string()).await, Err(BastionError::RateLimited)));
    assert!(matches!(attempt("leo-password-1".to_string()).await, Err(BastionError::RateLimited)));

    // Bounded cooldown: after it elapses the account is NOT permanently locked.
    tokio::time::sleep(Duration::from_millis(2200)).await;
    assert!(attempt("leo-password-1".to_string()).await.is_ok());

    // Success reset the counter: two more failures stay under the budget.
    assert_auth_failed(attempt("wrong".to_string()).await);
    assert_auth_failed(attempt("wrong".to_string()).await);
    assert!(attempt("leo-password-1".to_string()).await.is_ok());
}

#[tokio::test]
async fn rate_limit_capacity_bounded() {
    let ctx = Ctx::new("rate-cap").await;
    let mut config = fast_auth_config();
    config.rate_limit = RateLimitConfig {
        max_attempts: 1000,
        window: Duration::from_secs(60),
        cooldown: Duration::from_secs(60),
        max_attempts_per_ip: 1000,
        max_entries: 8,
    };
    let auth = AuthService::new(ctx.store(), config).unwrap();

    // Flood distinct usernames: the map must stay bounded.
    for i in 0..30u32 {
        auth.rate_limiter().record_failure(&format!("user{i}"), "10.8.8.8");
    }
    assert!(auth.rate_limiter().len() <= 8, "limiter map must be capacity-bounded");
    // The limiter still functions for new identities.
    assert!(auth.rate_limiter().check("fresh-user", "10.8.8.8").is_ok());
}

// ---- insecure secret file refused (unix) ---------------------------------------

#[cfg(unix)]
#[tokio::test]
async fn insecure_secret_file_refused() {
    use std::os::unix::fs::PermissionsExt;

    let path = std::env::temp_dir().join(format!(
        "bastion-secret-{}-{}.txt",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::write(&path, "s3cr3t-password\n").unwrap();

    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let err = dbx_bastion::auth::read_secret_file(&path).unwrap_err();
    assert!(matches!(err, BastionError::InsecureSecretFile(_)), "group-readable secret must be refused, got {err:?}");

    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let password = dbx_bastion::auth::read_secret_file(&path).unwrap();
    assert_eq!(password, "s3cr3t-password");
    std::fs::remove_file(&path).ok();
}

// ---- HTTP cookie contract (no routes) -------------------------------------------

#[test]
fn cookie_contract_headers() {
    let policy = SessionCookiePolicy::default();
    let set = policy.set_cookie_value("raw-token-123");
    assert!(set.starts_with("__Host-bastion-session=raw-token-123;"), "{set}");
    for part in ["Path=/", "HttpOnly", "Secure", "SameSite=Lax"] {
        assert!(set.contains(part), "{set}");
    }
    assert!(!set.contains("Domain="), "{set}");

    let clear = policy.clear_cookie_value();
    assert!(clear.contains("Max-Age=0"), "{clear}");
    assert!(clear.contains("__Host-bastion-session=;"), "{clear}");

    let strict = SessionCookiePolicy { same_site: SameSite::Strict, ..SessionCookiePolicy::default() };
    assert!(strict.set_cookie_value("t").contains("SameSite=Strict"));
}

// ---- Argon2 runs concurrently without deadlock -------------------------------------

#[tokio::test]
async fn argon2_concurrent_correctness() {
    let passwords = PasswordService::new(fast_password_config()).unwrap();
    let hash = passwords.hash("concurrent-pw").await.unwrap();

    let mut handles = Vec::new();
    for _ in 0..16 {
        let passwords = passwords.clone();
        let hash = hash.clone();
        handles.push(tokio::spawn(async move { passwords.verify("concurrent-pw", &hash).await.unwrap() }));
    }
    for handle in handles {
        assert!(handle.await.unwrap(), "concurrent verify must succeed");
    }
}

// ---- security review: verify-then-create race hardening ----------------------
// These tests are deterministic: they drive the re-validation logic with
// stale vs current hashes directly instead of racing wall-clock timing.

#[tokio::test]
async fn session_create_revalidates_password_hash_and_enabled() {
    let ctx = Ctx::new("revalidate").await;
    let store = ctx.store();
    let sessions = ctx.auth.sessions();

    let user = ctx.create_user("nina", "nina-password-1").await;
    let stale_hash = ctx.user_hash(user).await;

    // Password changed after "verification": creation with the stale hash is
    // refused inside the creation transaction.
    let new_hash = ctx.passwords.hash("nina-password-2").await.unwrap();
    store.update_password_hash(user, &new_hash).await.unwrap();
    let err = sessions.create_session(user, &stale_hash, None, None).await.unwrap_err();
    assert!(matches!(err, BastionError::AuthenticationFailed));

    // With the current hash, creation succeeds.
    let (_, token) = sessions.create_session(user, &new_hash, None, None).await.unwrap();
    assert!(ctx.auth.validate_token(&token).await.is_ok());

    // User disabled after "verification": creation refused.
    let current = ctx.user_hash(user).await;
    store.set_user_enabled(user, false).await.unwrap();
    let err = sessions.create_session(user, &current, None, None).await.unwrap_err();
    assert!(matches!(err, BastionError::AuthenticationFailed));

    // Re-enabled: creation works again with the current hash.
    store.set_user_enabled(user, true).await.unwrap();
    let (_, token2) = sessions.create_session(user, &current, None, None).await.unwrap();
    assert!(ctx.auth.validate_token(&token2).await.is_ok());
}

#[tokio::test]
async fn disable_reenable_does_not_resurrect_sessions() {
    let ctx = Ctx::new("no-resurrect").await;
    let store = ctx.store();
    let user = ctx.create_user("mallory", "mallory-password-1").await;
    let login = ctx.login("mallory", "mallory-password-1").await.unwrap();

    // Disabling revokes sessions atomically (visible at the row level, not
    // just at validation time).
    store.set_user_enabled(user, false).await.unwrap();
    let conn = rusqlite::Connection::open(&ctx.db_path).unwrap();
    let revoked: Option<String> = conn
        .query_row("SELECT revoked_at FROM sessions WHERE id = ?1", [login.principal.session_id.to_string()], |row| {
            row.get(0)
        })
        .unwrap();
    assert!(revoked.is_some(), "disable must revoke sessions in the same tx");
    drop(conn);
    assert_invalid_session(ctx.auth.validate_token(&login.token).await);

    // Re-enabling must NOT resurrect the disabled-period session.
    store.set_user_enabled(user, true).await.unwrap();
    assert_invalid_session(ctx.auth.validate_token(&login.token).await);

    // A fresh login after re-enable works normally.
    let login2 = ctx.login("mallory", "mallory-password-1").await.unwrap();
    assert!(ctx.auth.validate_token(&login2.token).await.is_ok());
}

// ---- security review: concurrent password changes ---------------------------

#[tokio::test]
async fn concurrent_password_change_no_lost_update() {
    let ctx = Ctx::new("pw-race").await;
    let store = ctx.store();
    let id = ctx.create_user("oscar", "oscar-password-1").await;

    // Sequential stale attempt: the old password no longer verifies, so the
    // request fails before reaching the conditional update; the first
    // change is untouched.
    ctx.auth.change_password(id, "oscar-password-1", "oscar-password-2").await.unwrap();
    let err = ctx.auth.change_password(id, "oscar-password-1", "oscar-password-3").await.unwrap_err();
    assert!(matches!(err, BastionError::AuthenticationFailed));
    assert!(ctx.login("oscar", "oscar-password-2").await.is_ok());
    assert_auth_failed(ctx.login("oscar", "oscar-password-3").await);

    // Truly concurrent: both requests verified the same old password, so
    // exactly one conditional update can win; the loser gets a retryable
    // error instead of silently clobbering the winner. The outcome
    // (exactly one success) is deterministic: without the conditional
    // update both would succeed via last-writer-wins.
    let auth = Arc::new(AuthService::new(store, fast_auth_config()).unwrap());
    let first = Arc::clone(&auth);
    let second = Arc::clone(&auth);
    let first_wins =
        tokio::spawn(async move { first.change_password(id, "oscar-password-2", "oscar-password-A").await });
    let second_wins =
        tokio::spawn(async move { second.change_password(id, "oscar-password-2", "oscar-password-B").await });
    let first_result = first_wins.await.unwrap();
    let second_result = second_wins.await.unwrap();
    assert!(first_result.is_ok() ^ second_result.is_ok(), "exactly one concurrent password change must win");
    let winner_password = if first_result.is_ok() {
        assert!(matches!(second_result.unwrap_err(), BastionError::ConcurrentModification(_)));
        "oscar-password-A"
    } else {
        assert!(matches!(first_result.unwrap_err(), BastionError::ConcurrentModification(_)));
        "oscar-password-B"
    };
    // The winner's password is live; nothing else landed.
    let login = ctx
        .auth
        .login(&LoginRequest {
            username: "oscar".to_string(),
            password: winner_password.to_string(),
            source_ip: None,
            user_agent: None,
        })
        .await
        .unwrap();
    assert!(ctx.auth.validate_token(&login.token).await.is_ok());
}

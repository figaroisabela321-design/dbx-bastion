//! TASK-005C-1 integration tests: bastion mode + default-deny firewall.
//!
//! Spawns the real `dbx-web` binary as a subprocess (like
//! `mongodb_dump_http.rs`) and verifies behavior over HTTP. Each test
//! uses an isolated temp data dir.

use std::process::Stdio;
use std::time::Duration;

use dbx_bastion::audit::{AuditEvent, AuditService, AuditStatus, SqliteAuditService};
use dbx_bastion::query::StatementAction;
use dbx_bastion::BastionService;

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

struct Server {
    child: tokio::process::Child,
    port: u16,
    _dir: tempfile::TempDir,
    log_path: std::path::PathBuf,
}

impl Server {
    async fn spawn_bastion() -> Self {
        Self::spawn(&[("DBX_BASTION_MODE", "1")]).await
    }

    async fn spawn(extra_env: &[(&str, &str)]) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let port = free_port();
        let log_path = dir.path().join("server.log");
        let mut cmd = tokio::process::Command::new(env!("CARGO_BIN_EXE_dbx-web"));
        cmd.env("DBX_DATA_DIR", dir.path())
            .env("DBX_PORT", port.to_string())
            .env("DBX_BIND_ADDR", "127.0.0.1")
            .kill_on_drop(true)
            .stdout(Stdio::null())
            .stderr(std::fs::File::create(&log_path).unwrap());
        for (k, v) in extra_env {
            cmd.env(k, v);
        }
        let child = cmd.spawn().unwrap();
        let mut s = Self { child, port, _dir: dir, log_path };
        s.wait_for_health().await;
        s
    }

    async fn wait_for_health(&mut self) {
        let client = reqwest::Client::new();
        let url = format!("http://127.0.0.1:{}/api/bastion/health", self.port);
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                if let Ok(resp) = client.get(&url).send().await {
                    if resp.status().is_success() {
                        return;
                    }
                }
                if let Some(status) = self.child.try_wait().unwrap() {
                    panic!("server exited {status}: {}", std::fs::read_to_string(&self.log_path).unwrap());
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("server did not become healthy");
    }

    fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{}", self.port, path)
    }

    async fn shutdown(mut self) {
        let _ = self.child.kill().await;
        let _ = self.child.wait().await;
    }
}

/// Seed an untriaged `started` audit row directly in the bastion DB.
/// Async: uses the caller's Tokio runtime (never creates a new one).
async fn seed_untriaged_started(data_dir: &std::path::Path) {
    let service = BastionService::open(data_dir.join("bastion").join("bastion.db")).unwrap();
    let audit = SqliteAuditService::new(service.store().clone());
    audit
        .record_started(AuditEvent {
            id: uuid::Uuid::new_v4(),
            user_id: uuid::Uuid::new_v4(),
            session_id: uuid::Uuid::new_v4(),
            asset_id: uuid::Uuid::new_v4(),
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
        })
        .await
        .unwrap();
    // Keep the service alive until the audit write is flushed; the
    // record must survive for the server to see it as untriaged.
    drop(service);
}

/// Bootstrap a bastion admin user directly in the bastion DB (for tests
/// that need an authenticated session). Returns (username, password).
async fn bootstrap_admin(data_dir: &std::path::Path) -> (String, String) {
    use dbx_bastion::auth::{AdminBootstrap, BootstrapCredentials, BootstrapPolicy, PasswordConfig, PasswordService};
    let service = BastionService::open(data_dir.join("bastion").join("bastion.db")).unwrap();
    let passwords = PasswordService::new(PasswordConfig::default()).unwrap();
    let bootstrap = AdminBootstrap::new(service.store().clone(), passwords, BootstrapPolicy::default());
    let username = format!("testadmin{}", uuid::Uuid::new_v4().simple());
    let password = format!("Str0ng!{}", uuid::Uuid::new_v4().simple());
    bootstrap
        .bootstrap(&BootstrapCredentials {
            username: username.clone(),
            display_name: "Test Admin".to_string(),
            password: password.clone(),
        })
        .await
        .unwrap();
    drop(service);
    (username, password)
}

#[tokio::test]
async fn bastion_health_and_status() {
    let s = Server::spawn_bastion().await;
    let client = reqwest::Client::new();
    let health: serde_json::Value =
        client.get(s.url("/api/bastion/health")).send().await.unwrap().json().await.unwrap();
    assert_eq!(health["mode"], "bastion");
    let status: serde_json::Value =
        client.get(s.url("/api/bastion/status")).send().await.unwrap().json().await.unwrap();
    assert_eq!(status["startup_state"], "ready");
    assert_eq!(status["execution_refused"], false);
    s.shutdown().await;
}

#[tokio::test]
async fn bastion_denies_legacy_query_routes() {
    let s = Server::spawn_bastion().await;
    let client = reqwest::Client::new();
    for path in [
        "/api/query/execute",
        "/api/query/execute-multi",
        "/api/query/execute-batch",
        "/api/query/execute-script",
        "/api/query/execute-in-transaction",
        "/api/query/execute-script-2pc",
        "/api/query/cancel",
    ] {
        let resp = client.post(s.url(path)).body("{}").send().await.unwrap();
        assert!(resp.status() == 403 || resp.status() == 404, "{path} must be denied, got {}", resp.status());
    }
    s.shutdown().await;
}

#[tokio::test]
async fn bastion_denies_data_routes() {
    let s = Server::spawn_bastion().await;
    let client = reqwest::Client::new();
    for (method, path) in [
        ("POST", "/api/import/execute"),
        ("POST", "/api/export/table"),
        ("POST", "/api/export/database"),
        ("POST", "/api/transfer/start"),
        ("POST", "/api/sql-file/execute"),
        ("GET", "/api/schema/tables"),
    ] {
        let req = match method {
            "POST" => client.post(s.url(path)),
            _ => client.get(s.url(path)),
        };
        let resp = req.send().await.unwrap();
        assert!(resp.status() == 403 || resp.status() == 404, "{method} {path} must be denied, got {}", resp.status());
    }
    s.shutdown().await;
}

#[tokio::test]
async fn bastion_denies_ai_and_mcp_and_ws() {
    let s = Server::spawn_bastion().await;
    let client = reqwest::Client::new();
    // AI agent.
    let resp = client.post(s.url("/api/ai/agent-stream")).body("{}").send().await.unwrap();
    assert!(resp.status() == 403 || resp.status() == 404, "ai denied, got {}", resp.status());
    // MCP (not mounted).
    let resp = client.post(s.url("/mcp")).body("{}").send().await.unwrap();
    assert!(resp.status() == 403 || resp.status() == 404, "mcp denied, got {}", resp.status());
    // WebSocket (upgrade request to the old path).
    let resp = client
        .get(s.url("/redis/pubsub/ws"))
        .header("Upgrade", "websocket")
        .header("Connection", "Upgrade")
        .send()
        .await
        .unwrap();
    assert!(resp.status() == 403 || resp.status() == 404, "ws denied, got {}", resp.status());
    // Legacy auth.
    let resp = client.post(s.url("/api/auth/login")).body("{}").send().await.unwrap();
    assert!(resp.status() == 403 || resp.status() == 404, "legacy auth denied, got {}", resp.status());
    s.shutdown().await;
}

#[tokio::test]
async fn bastion_firewall_method_and_encoding() {
    let s = Server::spawn_bastion().await;
    let client = reqwest::Client::new();
    // Wrong method on a whitelisted path.
    let resp = client.post(s.url("/api/bastion/health")).send().await.unwrap();
    assert_eq!(resp.status(), 403);
    // Trailing slash.
    let resp = client.get(s.url("/api/bastion/health/")).send().await.unwrap();
    assert!(resp.status() == 403 || resp.status() == 404, "trailing slash, got {}", resp.status());
    // Percent-encoded path.
    let resp = client.get(s.url("/api/bastion/%68ealth")).send().await.unwrap();
    assert!(resp.status() == 403 || resp.status() == 404, "encoded, got {}", resp.status());
    // Unknown path.
    let resp = client.get(s.url("/api/nope")).send().await.unwrap();
    assert!(resp.status() == 403 || resp.status() == 404);
    s.shutdown().await;
}

#[tokio::test]
async fn old_cookie_grants_nothing() {
    let s = Server::spawn_bastion().await;
    let client = reqwest::Client::new();
    // An old dbx_session cookie must not authenticate anything: there
    // are no privileged endpoints in 005C-1, and non-whitelisted paths
    // are denied regardless of cookies.
    let resp =
        client.get(s.url("/api/bastion/status")).header("Cookie", "dbx_session=legacy-token").send().await.unwrap();
    assert_eq!(resp.status(), 200); // public status endpoint
    let resp = client
        .post(s.url("/api/query/execute"))
        .header("Cookie", "dbx_session=legacy-token")
        .body("{}")
        .send()
        .await
        .unwrap();
    assert!(resp.status() == 403 || resp.status() == 404);
    s.shutdown().await;
}

#[tokio::test]
async fn disable_password_conflicts_refuses_startup() {
    let dir = tempfile::tempdir().unwrap();
    let port = free_port();
    let log_path = dir.path().join("server.log");
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_dbx-web"))
        .env("DBX_DATA_DIR", dir.path())
        .env("DBX_PORT", port.to_string())
        .env("DBX_BIND_ADDR", "127.0.0.1")
        .env("DBX_BASTION_MODE", "1")
        .env("DBX_DISABLE_PASSWORD", "1")
        .kill_on_drop(true)
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(&log_path).unwrap())
        .spawn()
        .unwrap();
    let status = tokio::time::timeout(Duration::from_secs(20), child.wait()).await.expect("timed out").unwrap();
    assert!(!status.success(), "conflicting config must refuse startup");
    let log = std::fs::read_to_string(&log_path).unwrap();
    assert!(log.contains("DBX_DISABLE_PASSWORD"), "log should mention the conflict: {log}");
}

#[tokio::test]
async fn invalid_mode_refuses_startup() {
    let dir = tempfile::tempdir().unwrap();
    let port = free_port();
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_dbx-web"))
        .env("DBX_DATA_DIR", dir.path())
        .env("DBX_PORT", port.to_string())
        .env("DBX_BIND_ADDR", "127.0.0.1")
        .env("DBX_BASTION_MODE", "bogus")
        .kill_on_drop(true)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let status = tokio::time::timeout(Duration::from_secs(20), child.wait()).await.expect("timed out").unwrap();
    assert!(!status.success(), "invalid mode must refuse startup");
}

#[tokio::test]
async fn bastion_init_failure_does_not_fall_back_to_legacy() {
    // Point the bastion dir at a file (not a directory): init must fail,
    // and the process must exit — not serve legacy routes.
    let dir = tempfile::tempdir().unwrap();
    let blocker = dir.path().join("bastion");
    std::fs::write(&blocker, b"not a directory").unwrap();
    let port = free_port();
    let log_path = dir.path().join("server.log");
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_dbx-web"))
        .env("DBX_DATA_DIR", dir.path())
        .env("DBX_PORT", port.to_string())
        .env("DBX_BIND_ADDR", "127.0.0.1")
        .env("DBX_BASTION_MODE", "1")
        .kill_on_drop(true)
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(&log_path).unwrap())
        .spawn()
        .unwrap();
    let status = tokio::time::timeout(Duration::from_secs(20), child.wait()).await.expect("timed out").unwrap();
    assert!(!status.success(), "init failure must exit, not fall back");
    // The legacy health endpoint must not be reachable (nothing listening).
    let client = reqwest::Client::new();
    assert!(client.get(format!("http://127.0.0.1:{port}/api/auth/check")).send().await.is_err());
}

#[tokio::test]
async fn untriaged_audit_starts_degraded() {
    let dir = tempfile::tempdir().unwrap();
    seed_untriaged_started(dir.path()).await;
    // Bootstrap an admin so we can test the execution gate with auth.
    let (username, password) = bootstrap_admin(dir.path()).await;
    let port = free_port();
    let log_path = dir.path().join("server.log");
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_dbx-web"))
        .env("DBX_DATA_DIR", dir.path())
        .env("DBX_PORT", port.to_string())
        .env("DBX_BIND_ADDR", "127.0.0.1")
        .env("DBX_BASTION_MODE", "1")
        // Execution switch ON: DEGRADED must still refuse.
        .env("DBX_BASTION_SQL_EXECUTION_ENABLED", "1")
        .kill_on_drop(true)
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(&log_path).unwrap())
        .spawn()
        .unwrap();
    let client = reqwest::Client::new();
    let status: serde_json::Value = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if let Ok(resp) = client.get(format!("http://127.0.0.1:{port}/api/bastion/status")).send().await {
                if resp.status().is_success() {
                    return resp.json().await.unwrap();
                }
            }
            if let Some(status) = child.try_wait().unwrap() {
                panic!("server exited {status}");
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("timed out");
    // Degraded: the service starts (so future admin triage is possible),
    // but execution is refused.
    assert_eq!(status["startup_state"], "degraded");
    assert_eq!(status["execution_refused"], true);

    // Execution gate: login, then query/execute must return 503
    // (DEGRADED refusal), not execute. The audit record is kept.
    let login_resp = client
        .post(format!("http://127.0.0.1:{port}/api/bastion/auth/login"))
        .json(&serde_json::json!({"username": username, "password": password}))
        .send()
        .await
        .unwrap();
    assert_eq!(login_resp.status(), 200, "login must work in DEGRADED (auth is allowed)");
    // Extract the session cookie manually (no cookie_store feature).
    let set_cookie = login_resp.headers().get("set-cookie").unwrap().to_str().unwrap().to_string();
    let session_cookie = set_cookie.split(';').next().unwrap().to_string();
    let exec_resp = client
        .post(format!("http://127.0.0.1:{port}/api/bastion/query/execute"))
        .header("Cookie", session_cookie)
        // CSRF: Origin must match Host for POST.
        .header("Origin", format!("http://127.0.0.1:{port}"))
        .json(&serde_json::json!({
            "asset_id": uuid::Uuid::new_v4().to_string(),
            "sql": "SELECT 1",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(exec_resp.status(), 503, "DEGRADED must refuse SQL execution even with the switch on");

    // The untriaged audit record must still exist (not deleted).
    let service = BastionService::open(dir.path().join("bastion").join("bastion.db")).unwrap();
    let audit = SqliteAuditService::new(service.store().clone());
    assert!(audit.has_untriaged_interruptions().await.unwrap(), "audit record must be kept");

    let _ = child.kill().await;
}

#[tokio::test]
async fn second_instance_cannot_share_audit_db() {
    let first = Server::spawn_bastion().await;
    // Same data dir, different port: the instance lock must refuse.
    let port = free_port();
    let dir_path = first._dir.path().to_path_buf();
    let log_path = dir_path.join("server2.log");
    let mut second = tokio::process::Command::new(env!("CARGO_BIN_EXE_dbx-web"))
        .env("DBX_DATA_DIR", &dir_path)
        .env("DBX_PORT", port.to_string())
        .env("DBX_BIND_ADDR", "127.0.0.1")
        .env("DBX_BASTION_MODE", "1")
        .kill_on_drop(true)
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(&log_path).unwrap())
        .spawn()
        .unwrap();
    let status = tokio::time::timeout(Duration::from_secs(20), second.wait()).await.expect("timed out").unwrap();
    assert!(!status.success(), "second instance must fail fast");
    let log = std::fs::read_to_string(&log_path).unwrap();
    assert!(log.contains("another bastion instance"), "log should mention the lock: {log}");
    // The first instance is unaffected.
    let client = reqwest::Client::new();
    let resp = client.get(first.url("/api/bastion/health")).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    first.shutdown().await;
}

#[tokio::test]
async fn legacy_mode_still_serves_auth_check() {
    // Without DBX_BASTION_MODE, the legacy routes must exist.
    let dir = tempfile::tempdir().unwrap();
    let port = free_port();
    let log_path = dir.path().join("server.log");
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_dbx-web"))
        .env("DBX_DATA_DIR", dir.path())
        .env("DBX_PORT", port.to_string())
        .env("DBX_BIND_ADDR", "127.0.0.1")
        .env("DBX_DISABLE_PASSWORD", "1")
        .kill_on_drop(true)
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(&log_path).unwrap())
        .spawn()
        .unwrap();
    let client = reqwest::Client::new();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Ok(resp) = client.get(format!("http://127.0.0.1:{port}/api/auth/check")).send().await {
                assert!(resp.status().is_success(), "legacy auth check must exist");
                return;
            }
            if let Some(status) = child.try_wait().unwrap() {
                panic!("legacy server exited {status}: {}", std::fs::read_to_string(&log_path).unwrap());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("legacy server did not start");
    // And the bastion endpoints must NOT exist in legacy mode.
    let resp = client.get(format!("http://127.0.0.1:{port}/api/bastion/health")).send().await.unwrap();
    assert_eq!(resp.status(), 404);
    let _ = child.kill().await;
}

/// Spawn a bastion server expected to fail startup; assert it exits
/// non-zero and the log mentions `expect_in_log`.
async fn expect_bastion_startup_failure(data_dir: &std::path::Path, extra_env: &[(&str, &str)], expect_in_log: &str) {
    let port = free_port();
    let log_path = data_dir.join("server.log");
    let mut cmd = tokio::process::Command::new(env!("CARGO_BIN_EXE_dbx-web"));
    cmd.env("DBX_DATA_DIR", data_dir)
        .env("DBX_PORT", port.to_string())
        .env("DBX_BIND_ADDR", "127.0.0.1")
        .env("DBX_BASTION_MODE", "1")
        .kill_on_drop(true)
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(&log_path).unwrap());
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().unwrap();
    let status = tokio::time::timeout(Duration::from_secs(20), child.wait()).await.expect("timed out").unwrap();
    assert!(!status.success(), "bastion must refuse startup");
    let log = std::fs::read_to_string(&log_path).unwrap();
    assert!(log.contains(expect_in_log), "log should mention {expect_in_log:?}: {log}");
    // Nothing must be listening (no legacy fallback).
    let client = reqwest::Client::new();
    assert!(client.get(format!("http://127.0.0.1:{port}/api/bastion/health")).send().await.is_err());
}

#[cfg(unix)]
fn set_mode(path: &std::path::Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

#[tokio::test]
#[cfg(unix)]
async fn bastion_dir_0755_refuses_startup() {
    let outer = tempfile::tempdir().unwrap();
    let data_dir = outer.path().join("data");
    std::fs::create_dir(&data_dir).unwrap();
    let bastion_dir = data_dir.join("bastion");
    std::fs::create_dir(&bastion_dir).unwrap();
    set_mode(&bastion_dir, 0o755);
    expect_bastion_startup_failure(&data_dir, &[], "insecure permissions").await;
}

#[tokio::test]
#[cfg(unix)]
async fn bastion_dir_0777_refuses_startup() {
    let outer = tempfile::tempdir().unwrap();
    let data_dir = outer.path().join("data");
    std::fs::create_dir(&data_dir).unwrap();
    let bastion_dir = data_dir.join("bastion");
    std::fs::create_dir(&bastion_dir).unwrap();
    set_mode(&bastion_dir, 0o777);
    expect_bastion_startup_failure(&data_dir, &[], "insecure permissions").await;
}

#[tokio::test]
#[cfg(unix)]
async fn bastion_dir_symlink_refuses_startup() {
    let outer = tempfile::tempdir().unwrap();
    let data_dir = outer.path().join("data");
    std::fs::create_dir(&data_dir).unwrap();
    let real = outer.path().join("real");
    std::fs::create_dir(&real).unwrap();
    std::os::unix::fs::symlink(&real, data_dir.join("bastion")).unwrap();
    expect_bastion_startup_failure(&data_dir, &[], "symlink").await;
}

#[tokio::test]
#[cfg(unix)]
async fn bastion_secure_dir_starts_normally() {
    // 0700 dir owned by us: full startup, health + status reachable.
    let outer = tempfile::tempdir().unwrap();
    let data_dir = outer.path().join("data");
    std::fs::create_dir(&data_dir).unwrap();
    let bastion_dir = data_dir.join("bastion");
    std::fs::create_dir(&bastion_dir).unwrap();
    set_mode(&bastion_dir, 0o700);

    let port = free_port();
    let log_path = data_dir.join("server.log");
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_dbx-web"))
        .env("DBX_DATA_DIR", &data_dir)
        .env("DBX_PORT", port.to_string())
        .env("DBX_BIND_ADDR", "127.0.0.1")
        .env("DBX_BASTION_MODE", "1")
        .kill_on_drop(true)
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(&log_path).unwrap())
        .spawn()
        .unwrap();
    let client = reqwest::Client::new();
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if let Ok(resp) = client.get(format!("http://127.0.0.1:{port}/api/bastion/health")).send().await {
                assert!(resp.status().is_success());
                return;
            }
            if let Some(status) = child.try_wait().unwrap() {
                panic!("server exited {status}: {}", std::fs::read_to_string(&log_path).unwrap());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("secure dir server did not start");
    // Permissions must not have been "repaired" into something else.
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(&bastion_dir).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700);
    let _ = child.kill().await;
}

#[tokio::test]
async fn illegal_base_path_refuses_startup() {
    let dir = tempfile::tempdir().unwrap();
    for bad in ["/dbx/../evil", "/dbx//api", "/dbx%2fapi", "dbx", "/dbx?x=1"] {
        expect_bastion_startup_failure(dir.path(), &[("DBX_PUBLIC_BASE_PATH", bad)], "DBX_PUBLIC_BASE_PATH").await;
    }
}

#[tokio::test]
async fn legal_base_path_prefix_serves() {
    let dir = tempfile::tempdir().unwrap();
    let port = free_port();
    let log_path = dir.path().join("server.log");
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_dbx-web"))
        .env("DBX_DATA_DIR", dir.path())
        .env("DBX_PORT", port.to_string())
        .env("DBX_BIND_ADDR", "127.0.0.1")
        .env("DBX_BASTION_MODE", "1")
        .env("DBX_PUBLIC_BASE_PATH", "/dbx")
        .kill_on_drop(true)
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(&log_path).unwrap())
        .spawn()
        .unwrap();
    let client = reqwest::Client::new();
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if let Ok(resp) = client.get(format!("http://127.0.0.1:{port}/dbx/api/bastion/health")).send().await {
                assert!(resp.status().is_success(), "health under legal prefix must work");
                return;
            }
            if let Some(status) = child.try_wait().unwrap() {
                panic!("server exited {status}: {}", std::fs::read_to_string(&log_path).unwrap());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("server did not start");
    // Without the prefix: firewall denies (403 or 404, never 200).
    let resp = client.get(format!("http://127.0.0.1:{port}/api/bastion/health")).send().await.unwrap();
    assert!(!resp.status().is_success());
    // Fuzzy prefix bypass: /dbxevil/... must not reach health.
    let resp = client.get(format!("http://127.0.0.1:{port}/dbxevil/api/bastion/health")).send().await.unwrap();
    assert!(!resp.status().is_success(), "fuzzy prefix must not bypass firewall");
    // Encoded traversal under the prefix must not bypass.
    let resp = client.get(format!("http://127.0.0.1:{port}/dbx/api/%2e%2e/bastion/health")).send().await.unwrap();
    assert!(!resp.status().is_success(), "encoded traversal must not bypass firewall");
    // Status endpoint under the prefix: normal.
    let resp = client.get(format!("http://127.0.0.1:{port}/dbx/api/bastion/status")).send().await.unwrap();
    assert_eq!(resp.status(), 200, "status under prefix must work");
    let status: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(status["startup_state"], "ready");
    // Query execute without auth: 401 (auth gate), proving the route
    // exists under the prefix but is protected — not a silent 404.
    let resp = client
        .post(format!("http://127.0.0.1:{port}/dbx/api/bastion/query/execute"))
        .json(&serde_json::json!({"asset_id": uuid::Uuid::new_v4().to_string(), "sql": "SELECT 1"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "query execute without auth must be 401");
    // Legacy query path under the prefix: firewall denies (403),
    // proving old DBX routes are unreachable.
    let resp = client
        .post(format!("http://127.0.0.1:{port}/dbx/api/query/execute"))
        .json(&serde_json::json!({"sql": "SELECT 1"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "legacy query path must be denied by firewall");
    let _ = child.kill().await;
}

#[tokio::test]
async fn base_path_trailing_slash_normalized() {
    let dir = tempfile::tempdir().unwrap();
    let port = free_port();
    let log_path = dir.path().join("server.log");
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_dbx-web"))
        .env("DBX_DATA_DIR", dir.path())
        .env("DBX_PORT", port.to_string())
        .env("DBX_BIND_ADDR", "127.0.0.1")
        .env("DBX_BASTION_MODE", "1")
        .env("DBX_PUBLIC_BASE_PATH", "/dbx/")
        .kill_on_drop(true)
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(&log_path).unwrap())
        .spawn()
        .unwrap();
    let client = reqwest::Client::new();
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if let Ok(resp) = client.get(format!("http://127.0.0.1:{port}/dbx/api/bastion/health")).send().await {
                assert!(resp.status().is_success(), "trailing slash base path must normalize");
                return;
            }
            if let Some(status) = child.try_wait().unwrap() {
                panic!("server exited {status}: {}", std::fs::read_to_string(&log_path).unwrap());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("server did not start");
    let _ = child.kill().await;
}

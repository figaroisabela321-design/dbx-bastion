//! TASK-001 bootstrap tests.
//!
//! - Fresh `bastion.db` initializes with all 9 domain tables + indexes and a
//!   recorded schema version.
//! - Re-running migration on an existing file is safe (idempotent) and
//!   preserves data.
//! - Repository round-trips work through the public trait API.
//! - The bastion database file never touches any other database file next
//!   to it (isolation from the DBX database).

use dbx_bastion::asset::{Asset, AssetRepository, Environment};
use dbx_bastion::BastionService;
use rusqlite::Connection;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use uuid::Uuid;

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_db_path(file: &str) -> PathBuf {
    let id = COUNTER.fetch_add(1, Ordering::SeqCst);
    // Dedicated subdirectory: SqliteStore::open enforces 0700 on the
    // parent dir, and the shared /tmp itself is 1777.
    std::env::temp_dir().join(format!("dbx-bastion-test-{}-{}", std::process::id(), id)).join(file)
}

fn cleanup(path: &PathBuf) {
    let _ = std::fs::remove_file(path);
    // WAL mode sidecars, best-effort.
    let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
    if let Some(parent) = path.parent() {
        let _ = std::fs::remove_file(parent.join(format!("{stem}.db-wal")));
        let _ = std::fs::remove_file(parent.join(format!("{stem}.db-shm")));
    }
}

fn table_names(conn: &Connection) -> Vec<String> {
    let mut stmt = conn.prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name").unwrap();
    stmt.query_map([], |row| row.get(0)).unwrap().map(|r| r.unwrap()).collect()
}

fn index_names(conn: &Connection) -> Vec<String> {
    let mut stmt = conn
        .prepare(
            "SELECT name FROM sqlite_master
              WHERE type = 'index' AND name NOT LIKE 'sqlite_%'
              ORDER BY name",
        )
        .unwrap();
    stmt.query_map([], |row| row.get(0)).unwrap().map(|r| r.unwrap()).collect()
}

fn applied_versions(conn: &Connection) -> Vec<String> {
    let mut stmt = conn.prepare("SELECT version FROM schema_migrations ORDER BY version").unwrap();
    stmt.query_map([], |row| row.get(0)).unwrap().map(|r| r.unwrap()).collect()
}

const EXPECTED_TABLES: &[&str] = &[
    "approval_requests",
    "asset_group_members",
    "asset_groups",
    "assets",
    "audit_events",
    "group_roles",
    "bootstrap_state",
    "execution_tickets",
    "permissions",
    "roles",
    "schema_migrations",
    "sessions",
    "user_group_members",
    "user_groups",
    "user_roles",
    "users",
];

const EXPECTED_INDEXES: &[&str] = &[
    "idx_asset_group_members_asset",
    "idx_asset_group_members_group",
    "idx_asset_groups_parent",
    "idx_assets_deleted",
    "idx_assets_name_unique",
    "idx_audit_events_asset",
    "idx_audit_events_started",
    "idx_audit_events_user",
    "idx_execution_tickets_lookup",
    "idx_group_roles_group",
    "idx_permissions_asset",
    "idx_permissions_asset_group",
    "idx_permissions_role_action",
    "idx_sessions_token",
    "idx_sessions_user",
    "idx_sessions_user_active",
    "idx_user_group_members_user",
];

#[tokio::test]
async fn fresh_init_creates_schema_and_records_version() {
    let path = temp_db_path("bastion.db");
    let service = BastionService::open(&path).expect("open must succeed");
    drop(service);

    let conn = Connection::open(&path).expect("reopen for inspection");
    let tables = table_names(&conn);
    for expected in EXPECTED_TABLES {
        assert!(tables.iter().any(|t| t == expected), "missing table {expected}; have {tables:?}");
    }
    let indexes = index_names(&conn);
    for expected in EXPECTED_INDEXES {
        assert!(indexes.iter().any(|i| i == expected), "missing index {expected}; have {indexes:?}");
    }
    assert_eq!(
        applied_versions(&conn),
        vec![
            "0001_init".to_string(),
            "0002_auth".to_string(),
            "0003_assets".to_string(),
            "0004_rbac".to_string(),
            "0005_audit".to_string(),
            "0006_audit_recovery".to_string(),
            "0007_audit_recovery_followup".to_string(),
            "0008_audit_append_only".to_string()
        ]
    );

    let foreign_keys: i64 = conn.pragma_query_value(None, "foreign_keys", |row| row.get(0)).unwrap();
    assert_eq!(foreign_keys, 1, "foreign_keys pragma must be ON");

    drop(conn);
    cleanup(&path);
}

#[tokio::test]
async fn migration_is_idempotent_and_preserves_data() {
    let path = temp_db_path("bastion.db");

    let asset = Asset {
        id: Uuid::new_v4(),
        name: "prod-mysql-01".to_string(),
        environment: Environment::Production,
        db_type: "mysql".to_string(),
        dbx_connection_id: "conn-123".to_string(),
        enabled: true,
        description: String::new(),
        deleted_at: None,
        last_tested_at: None,
        last_test_status: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    {
        let service = BastionService::open(&path).expect("first open");
        AssetRepository::create_asset(service.store().as_ref(), &asset).await.expect("insert asset");
    } // drop: release the file before reopening

    {
        let service = BastionService::open(&path).expect("second open (re-run)");
        let resolved = AssetRepository::resolve_asset(service.store().as_ref(), asset.id)
            .await
            .expect("resolve after re-open")
            .expect("asset must survive re-migration");
        assert_eq!(resolved.name, "prod-mysql-01");
        assert_eq!(resolved.dbx_connection_id, "conn-123");
        assert_eq!(resolved.environment, Environment::Production);
    }

    let conn = Connection::open(&path).unwrap();
    assert_eq!(applied_versions(&conn).len(), 8, "migration versions must not be recorded twice");
    drop(conn);
    cleanup(&path);
}

#[tokio::test]
async fn asset_repository_roundtrip_and_disabled_filtering() {
    let path = temp_db_path("bastion.db");
    let service = BastionService::open(&path).expect("open");

    // Unknown id resolves to None (fail closed).
    let missing =
        AssetRepository::resolve_asset(service.store().as_ref(), Uuid::new_v4()).await.expect("resolve missing");
    assert!(missing.is_none());

    // Disabled assets are invisible to resolution.
    let disabled = Asset {
        id: Uuid::new_v4(),
        name: "old-mysql".to_string(),
        environment: Environment::Development,
        db_type: "mysql".to_string(),
        dbx_connection_id: "conn-999".to_string(),
        enabled: false,
        description: String::new(),
        deleted_at: None,
        last_tested_at: None,
        last_test_status: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    AssetRepository::create_asset(service.store().as_ref(), &disabled).await.expect("insert disabled asset");
    let resolved =
        AssetRepository::resolve_asset(service.store().as_ref(), disabled.id).await.expect("resolve disabled");
    assert!(resolved.is_none(), "disabled assets must not resolve");

    drop(service);
    cleanup(&path);
}

#[tokio::test]
async fn bastion_db_is_isolated_from_sibling_database_files() {
    // Simulate the DBX database living next to bastion.db.
    let dir = std::env::temp_dir().join(format!(
        "dbx-bastion-test-{}-{}-dir",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::SeqCst)
    ));
    dbx_bastion::secure_dir::ensure_secure_dir(&dir).unwrap();
    let dbx_path = dir.join("dbx.db");
    let bastion_path = dir.join("bastion.db");

    {
        let dbx = Connection::open(&dbx_path).unwrap();
        dbx.execute_batch(
            "CREATE TABLE marker (id INTEGER PRIMARY KEY, note TEXT);
             INSERT INTO marker (note) VALUES ('dbx-data');",
        )
        .unwrap();
    }

    {
        let _service = BastionService::open(&bastion_path).expect("open bastion.db");
    }

    // The sibling DBX file is untouched: marker row intact, no bastion
    // migration bookkeeping leaked into it.
    let dbx = Connection::open(&dbx_path).unwrap();
    let note: String = dbx.query_row("SELECT note FROM marker", [], |row| row.get(0)).unwrap();
    assert_eq!(note, "dbx-data");
    let tables = table_names(&dbx);
    assert!(!tables.iter().any(|t| t == "schema_migrations"), "bastion migrations must not leak into the DBX database");
    drop(dbx);

    // And bastion.db got its own schema.
    let bastion = Connection::open(&bastion_path).unwrap();
    assert!(table_names(&bastion).iter().any(|t| t == "assets"));
    drop(bastion);

    let _ = std::fs::remove_dir_all(&dir);
}

// ===== P2-002: audit_recovery_events append-only triggers =====

#[test]
fn p2_002_recovery_update_rejected() {
    // P2-002: Direct UPDATE on audit_recovery_events must be rejected
    // by the database trigger (not just application code).
    let dir = std::env::temp_dir().join(format!(
        "dbx-bastion-test-{}-{}-p2",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::SeqCst)
    ));
    dbx_bastion::secure_dir::ensure_secure_dir(&dir).unwrap();
    let db_path = dir.join("bastion.db");
    let service = BastionService::open(&db_path).expect("open");
    let conn = Connection::open(&db_path).unwrap();

    // Seed a recovery event via the service (legitimate INSERT).
    // (We use raw SQL here to avoid the full triage setup.)
    conn.execute(
        "INSERT INTO audit_events (id, user_id, session_id, asset_id, sql_text, sql_hash, action, sql_kind, risk_level, status, started_at)
         VALUES ('a1', 'u1', 's1', 'asset1', 'SELECT 1', 'hash', 'Select', 'Select', 'Low', 'started', '2026-01-01T00:00:00Z')",
        [],
    ).unwrap();
    conn.execute(
        "INSERT INTO audit_recovery_events (id, audit_event_id, triaged_by, triaged_at, original_status, conclusion, reason, evidence)
         VALUES ('r1', 'a1', 'admin1', '2026-01-01T01:00:00Z', 'started', 'still_unknown', 'investigating', '')",
        [],
    ).unwrap();

    // UPDATE must fail.
    let err = conn.execute("UPDATE audit_recovery_events SET reason = 'tampered' WHERE id = 'r1'", []).unwrap_err();
    let msg = format!("{err:?}");
    assert!(msg.contains("append-only"), "P2-002: UPDATE must be rejected by trigger, got: {msg}");
    // Row must be unchanged.
    let reason: String =
        conn.query_row("SELECT reason FROM audit_recovery_events WHERE id = 'r1'", [], |row| row.get(0)).unwrap();
    assert_eq!(reason, "investigating");

    drop(service);
    drop(conn);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn p2_002_recovery_delete_rejected() {
    // P2-002: Direct DELETE must be rejected.
    let dir = std::env::temp_dir().join(format!(
        "dbx-bastion-test-{}-{}-p2",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::SeqCst)
    ));
    dbx_bastion::secure_dir::ensure_secure_dir(&dir).unwrap();
    let db_path = dir.join("bastion.db");
    let service = BastionService::open(&db_path).expect("open");
    let conn = Connection::open(&db_path).unwrap();

    conn.execute(
        "INSERT INTO audit_events (id, user_id, session_id, asset_id, sql_text, sql_hash, action, sql_kind, risk_level, status, started_at)
         VALUES ('a2', 'u1', 's1', 'asset1', 'SELECT 1', 'hash', 'Select', 'Select', 'Low', 'started', '2026-01-01T00:00:00Z')",
        [],
    ).unwrap();
    conn.execute(
        "INSERT INTO audit_recovery_events (id, audit_event_id, triaged_by, triaged_at, original_status, conclusion, reason, evidence)
         VALUES ('r2', 'a2', 'admin1', '2026-01-01T01:00:00Z', 'started', 'still_unknown', 'r', '')",
        [],
    ).unwrap();

    let err = conn.execute("DELETE FROM audit_recovery_events WHERE id = 'r2'", []).unwrap_err();
    assert!(format!("{err:?}").contains("append-only"), "P2-002: DELETE must be rejected by trigger");
    // Row must still exist.
    let count: i64 =
        conn.query_row("SELECT COUNT(*) FROM audit_recovery_events WHERE id = 'r2'", [], |row| row.get(0)).unwrap();
    assert_eq!(count, 1);

    drop(service);
    drop(conn);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn p2_002_recovery_insert_allowed() {
    // P2-002: INSERT must still work (triage path unaffected).
    let dir = std::env::temp_dir().join(format!(
        "dbx-bastion-test-{}-{}-p2",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::SeqCst)
    ));
    dbx_bastion::secure_dir::ensure_secure_dir(&dir).unwrap();
    let db_path = dir.join("bastion.db");
    let service = BastionService::open(&db_path).expect("open");
    let conn = Connection::open(&db_path).unwrap();

    conn.execute(
        "INSERT INTO audit_events (id, user_id, session_id, asset_id, sql_text, sql_hash, action, sql_kind, risk_level, status, started_at)
         VALUES ('a3', 'u1', 's1', 'asset1', 'SELECT 1', 'hash', 'Select', 'Select', 'Low', 'started', '2026-01-01T00:00:00Z')",
        [],
    ).unwrap();
    // This INSERT must succeed (triggers only block UPDATE/DELETE).
    conn.execute(
        "INSERT INTO audit_recovery_events (id, audit_event_id, triaged_by, triaged_at, original_status, conclusion, reason, evidence)
         VALUES ('r3', 'a3', 'admin1', '2026-01-01T01:00:00Z', 'started', 'confirmed_not_executed', 'verified', 'logs')",
        [],
    ).expect("P2-002: INSERT must succeed");

    drop(service);
    drop(conn);
    let _ = std::fs::remove_dir_all(&dir);
}

// ===== P2-004: Migration 0006 -> 0007 -> 0008 regression =====

#[test]
fn p2_004_migration_chain_preserves_data() {
    // P2-004: Verify the full 0006 -> 0007 -> 0008 upgrade path.
    // - audit_events history unchanged
    // - recovery data complete
    // - triggers created
    // - append-only still enforced after restart (re-open)
    use dbx_bastion::storage::apply_one_migration;

    let dir = std::env::temp_dir().join(format!(
        "dbx-bastion-test-{}-{}-p2",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::SeqCst)
    ));
    dbx_bastion::secure_dir::ensure_secure_dir(&dir).unwrap();
    let db_path = dir.join("bastion.db");

    // Start with a fresh DB at 0005 (before recovery tables).
    // We simulate by opening (which applies all), then verify the chain
    // works on a DB that already has 0006-era data.
    //
    // Simpler deterministic approach: create DB, apply 0001-0006 manually
    // via apply_one_migration, insert 0006-era data, then open via
    // BastionService (which applies 0007+0008).
    let mut conn = Connection::open(&db_path).unwrap();
    // Create the bookkeeping table (normally done by apply_migrations).
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
            version     TEXT PRIMARY KEY,
            applied_at  TEXT NOT NULL
        )",
    )
    .unwrap();
    let migrations: &[(&str, &str)] = &[
        ("0001_init", include_str!("../migrations/0001_init.sql")),
        ("0002_auth", include_str!("../migrations/0002_auth.sql")),
        ("0003_assets", include_str!("../migrations/0003_assets.sql")),
        ("0004_rbac", include_str!("../migrations/0004_rbac.sql")),
        ("0005_audit", include_str!("../migrations/0005_audit.sql")),
        ("0006_audit_recovery", include_str!("../migrations/0006_audit_recovery.sql")),
    ];
    for (v, sql) in migrations {
        apply_one_migration(&mut conn, v, sql).expect("apply migration");
    }

    // Insert 0006-era data: multiple audit events with recovery rows.
    // 0006 has UNIQUE(audit_event_id), so one row per event.
    for i in 0..3 {
        let aid = format!("audit-{i}");
        let rid = format!("rec-{i}");
        conn.execute(
            "INSERT INTO audit_events (id, user_id, session_id, asset_id, sql_text, sql_hash, action, sql_kind, risk_level, status, started_at)
             VALUES (?1, 'u1', 's1', 'asset1', 'SELECT 1', 'hash', 'Select', 'Select', 'Low', 'started', '2026-01-01T00:00:00Z')",
            [&aid],
        ).unwrap();
        conn.execute(
            "INSERT INTO audit_recovery_events (id, audit_event_id, triaged_by, triaged_at, original_status, conclusion, reason, evidence)
             VALUES (?1, ?2, 'admin', '2026-01-01T01:00:00Z', 'started', 'still_unknown', 'r', '')",
            [&rid, &aid],
        ).unwrap();
    }
    drop(conn);

    // Fix permissions: BastionService::open requires 0600.
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&db_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    // Re-open via BastionService: applies 0007 + 0008.
    let service = BastionService::open(&db_path).expect("open applies 0007+0008");
    let conn = Connection::open(&db_path).unwrap();

    // 1. audit_events unchanged (3 rows).
    let count: i64 = conn.query_row("SELECT COUNT(*) FROM audit_events", [], |r| r.get(0)).unwrap();
    assert_eq!(count, 3, "P2-004: audit_events must be preserved");

    // 2. Recovery data complete (3 rows, all fields).
    let rcount: i64 = conn.query_row("SELECT COUNT(*) FROM audit_recovery_events", [], |r| r.get(0)).unwrap();
    assert_eq!(rcount, 3, "P2-004: recovery rows must be preserved");
    for i in 0..3 {
        let aid = format!("audit-{i}");
        let conclusion: String = conn
            .query_row("SELECT conclusion FROM audit_recovery_events WHERE audit_event_id = ?1", [&aid], |r| r.get(0))
            .unwrap();
        assert_eq!(conclusion, "still_unknown", "P2-004: row {aid} conclusion preserved");
    }

    // 3. Triggers exist.
    let tcount: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'trigger' AND tbl_name = 'audit_recovery_events'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(tcount, 2, "P2-004: both append-only triggers must exist");

    // 4. Append-only enforced after re-open (restart simulation).
    drop(conn);
    drop(service);
    let _service2 = BastionService::open(&db_path).expect("re-open");
    let conn2 = Connection::open(&db_path).unwrap();
    let err = conn2.execute("DELETE FROM audit_recovery_events", []).unwrap_err();
    assert!(format!("{err:?}").contains("append-only"), "P2-004: triggers must survive restart");

    drop(conn2);
    let _ = std::fs::remove_dir_all(&dir);
}

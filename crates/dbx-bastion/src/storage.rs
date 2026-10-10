//! Isolated SQLite storage for the bastion domain.
//!
//! Design rules:
//!
//! - Own database file (`bastion.db`). It is never the DBX database file and
//!   the store never opens or migrates any other file.
//! - rusqlite 0.32, the exact version the DBX workspace already uses.
//! - Schema versioning via a `schema_migrations` table. Migrations listed in
//!   `MIGRATIONS` apply in order, at most once per database file. The SQL
//!   files additionally use `IF NOT EXISTS` so a re-run is harmless.
//! - Repository traits are `async` so a future PostgreSQL implementation can
//!   satisfy them without changing callers. Blocking rusqlite calls run
//!   inside `tokio::task::spawn_blocking`; `open` stays synchronous and is
//!   meant to be called once at startup.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use rusqlite::{Connection, OptionalExtension};
use uuid::Uuid;

use crate::asset::group::{AssetGroup, AssetGroupRepository, NewAssetGroup, UpdateAssetGroup};
use crate::asset::mapping::ConnectionTestStatus;
use crate::asset::{
    Asset, AssetFilter, AssetPatch, AssetRepository, Environment, NewUser, Page, PageRequest, UserCredentialRecord,
    UserRepository,
};
use crate::auth::session::{parse_text, to_text, SessionRecord, SessionRepository};
use crate::error::{BastionError, Result};

/// Ordered migrations. Add new files here; never edit an applied one.
const MIGRATIONS: &[(&str, &str)] = &[
    ("0001_init", include_str!("../migrations/0001_init.sql")),
    ("0002_auth", include_str!("../migrations/0002_auth.sql")),
    ("0003_assets", include_str!("../migrations/0003_assets.sql")),
    ("0004_rbac", include_str!("../migrations/0004_rbac.sql")),
    ("0005_audit", include_str!("../migrations/0005_audit.sql")),
];

/// SQLITE_CONSTRAINT_UNIQUE extended error code.
const SQLITE_CONSTRAINT_UNIQUE: i32 = 2067;

/// Map a unique-constraint violation to a friendly error; pass anything
/// else through unchanged.
pub(crate) fn map_unique_violation(err: BastionError, what: &str) -> BastionError {
    if let BastionError::Storage(rusqlite::Error::SqliteFailure(sqlite_err, _)) = &err {
        if sqlite_err.extended_code == SQLITE_CONSTRAINT_UNIQUE {
            return BastionError::InvalidData(format!("{what} already exists"));
        }
    }
    err
}

pub struct SqliteStore {
    conn: Arc<Mutex<Connection>>,
    path: PathBuf,
}

impl SqliteStore {
    /// Open the bastion database at `path`, creating parent directories and
    /// the file if needed, then apply pending migrations.
    ///
    /// File security (TASK-005D): the parent directory is created with
    /// `0700` at creation time (never 0755-then-chmod) or, if it already
    /// exists, validated and refused when insecure — never silently
    /// repaired. An existing database file is validated BEFORE SQLite
    /// opens it: symlinks and non-regular files are rejected, ownership
    /// and `0600`-or-stricter permissions are checked, and an
    /// `O_NOFOLLOW` open guards the validation→open window. New files
    /// are pre-created with `0600`. Non-Unix platforms are refused.
    ///
    /// Synchronous by design: call once at startup (wrap in
    /// `spawn_blocking` at the call site if already inside async code).
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                crate::secure_dir::ensure_secure_dir(parent)?;
            }
        }
        // Existing file: validate type/ownership/permissions BEFORE
        // SQLite touches it, then guard the TOCTOU window with
        // O_NOFOLLOW. New file: pre-create with 0600.
        let exists = std::fs::symlink_metadata(path).is_ok();
        if exists {
            crate::secure_dir::validate_existing_file(path, "bastion database")?;
            crate::secure_dir::nofollow_open_check(path, "bastion database")?;
        } else {
            crate::secure_dir::precreate_secure_file(path)?;
        }

        let mut conn = Connection::open(path)?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        apply_migrations(&mut conn)?;

        Ok(Self { conn: Arc::new(Mutex::new(conn)), path: path.to_path_buf() })
    }

    /// Absolute path of the bastion database file this store manages.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Run a blocking rusqlite closure without stalling the async executor.
    pub(crate) async fn blocking<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&Connection) -> Result<T> + Send + 'static,
        T: Send + 'static,
    {
        let conn = Arc::clone(&self.conn);
        tokio::task::spawn_blocking(move || {
            let guard = conn.lock().map_err(|_| BastionError::StorageTask("sqlite mutex poisoned".into()))?;
            f(&guard)
        })
        .await
        .map_err(|error| BastionError::StorageTask(format!("storage task join failed: {error}")))?
    }

    /// Run a closure inside a single `BEGIN IMMEDIATE` transaction on a
    /// blocking thread. The guard is never held across `.await`: everything
    /// happens inside the spawned task.
    ///
    /// Used for multi-statement operations that must be atomic (bootstrap,
    /// password change + session revocation, session create + eviction).
    pub(crate) async fn in_transaction<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&rusqlite::Transaction<'_>) -> Result<T> + Send + 'static,
        T: Send + 'static,
    {
        let conn = Arc::clone(&self.conn);
        tokio::task::spawn_blocking(move || {
            let mut guard = conn.lock().map_err(|_| BastionError::StorageTask("sqlite mutex poisoned".into()))?;
            let tx = guard.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let result = f(&tx)?;
            tx.commit()?;
            Ok(result)
        })
        .await
        .map_err(|error| BastionError::StorageTask(format!("storage task join failed: {error}")))?
    }

    /// Run a closure inside a single `BEGIN DEFERRED` **read** transaction.
    ///
    /// Authorization snapshots are built with this: the Deferred behavior
    /// takes a shared lock on first read, so every SELECT in the closure
    /// sees the same database state. Combined with the store's single
    /// mutex-guarded connection (no writer can interleave while the guard
    /// is held), this is a true consistency snapshot — not a series of
    /// independent autocommit reads. The transaction is rolled back
    /// (never committed); callers must not write inside it.
    pub(crate) async fn in_read_transaction<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&rusqlite::Transaction<'_>) -> Result<T> + Send + 'static,
        T: Send + 'static,
    {
        let conn = Arc::clone(&self.conn);
        tokio::task::spawn_blocking(move || {
            let mut guard = conn.lock().map_err(|_| BastionError::StorageTask("sqlite mutex poisoned".into()))?;
            let tx = guard.transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)?;
            let result = f(&tx);
            // Explicit rollback: this is a read-only snapshot. Dropping an
            // open Deferred transaction would also roll back, but being
            // explicit documents the intent.
            tx.rollback()?;
            result
        })
        .await
        .map_err(|error| BastionError::StorageTask(format!("storage task join failed: {error}")))?
    }
}

/// Apply every migration in [`MIGRATIONS`] that is not yet recorded in
/// `schema_migrations`. Safe to call repeatedly.
fn apply_migrations(conn: &mut Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
            version     TEXT PRIMARY KEY,
            applied_at  TEXT NOT NULL
        )",
    )?;

    let applied: HashSet<String> = {
        let mut stmt = conn.prepare("SELECT version FROM schema_migrations")?;
        let versions = stmt.query_map([], |row| row.get(0))?;
        versions.collect::<rusqlite::Result<HashSet<String>>>()?
    };

    for (version, sql) in MIGRATIONS {
        if applied.contains(*version) {
            continue;
        }
        apply_one_migration(conn, version, sql)?;
    }
    Ok(())
}

/// Apply a single migration and record its version **in the same
/// transaction**. On any failure the transaction rolls back completely:
/// no partial schema change and no version record survive.
///
/// Low-level building block; prefer [`SqliteStore::open`] which applies the
/// ordered [`MIGRATIONS`] list.
pub fn apply_one_migration(conn: &mut Connection, version: &str, sql: &str) -> Result<()> {
    let tx = conn.transaction()?;
    tx.execute_batch(sql).map_err(|error| BastionError::Migration(format!("migration {version} failed: {error}")))?;
    tx.execute(
        "INSERT INTO schema_migrations (version, applied_at) VALUES (?1, ?2)",
        rusqlite::params![version, chrono::Utc::now().to_rfc3339()],
    )?;
    tx.commit()?;
    Ok(())
}

pub(crate) fn parse_uuid(value: String) -> Result<Uuid> {
    Uuid::parse_str(&value).map_err(|error| BastionError::InvalidData(error.to_string()))
}

pub(crate) const ASSET_COLUMNS: &str = "id, name, environment, db_type, dbx_connection_id, enabled, description, deleted_at, last_tested_at, last_test_status, created_at, updated_at";

/// Raw asset row in ASSET_COLUMNS order.
type AssetRow = (
    String,         // id
    String,         // name
    String,         // environment
    String,         // db_type
    String,         // dbx_connection_id
    i64,            // enabled
    String,         // description
    Option<String>, // deleted_at
    Option<String>, // last_tested_at
    Option<String>, // last_test_status
    String,         // created_at
    String,         // updated_at
);

pub(crate) fn to_asset(row: AssetRow) -> Result<Asset> {
    let (
        id,
        name,
        environment,
        db_type,
        dbx_connection_id,
        enabled,
        description,
        deleted_at,
        last_tested_at,
        last_test_status,
        created_at,
        updated_at,
    ) = row;
    Ok(Asset {
        id: parse_uuid(id)?,
        name,
        environment: Environment::parse(&environment)
            .ok_or_else(|| BastionError::InvalidData(format!("unknown environment: {environment}")))?,
        db_type,
        dbx_connection_id,
        enabled: enabled != 0,
        description,
        deleted_at: deleted_at.map(|v| parse_text(&v)).transpose()?,
        last_tested_at: last_tested_at.map(|v| parse_text(&v)).transpose()?,
        last_test_status: last_test_status
            .map(|v| {
                ConnectionTestStatus::parse(&v)
                    .ok_or_else(|| BastionError::InvalidData(format!("unknown test status: {v}")))
            })
            .transpose()?,
        created_at: parse_text(&created_at)?,
        updated_at: parse_text(&updated_at)?,
    })
}

pub(crate) fn map_asset_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AssetRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
        row.get(9)?,
        row.get(10)?,
        row.get(11)?,
    ))
}

/// Escape LIKE wildcards in user input (`\`, `%`, `_`).
fn escape_like(value: &str) -> String {
    value.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_")
}

/// Shared WHERE-clause builder for asset listings: SQL conditions plus
/// bound values in order. Used by both the admin listing and the
/// authorization-filtered listing so filter semantics cannot drift.
pub(crate) fn asset_filter_conditions(filter: &AssetFilter) -> (Vec<String>, Vec<String>) {
    let mut conditions = vec!["deleted_at IS NULL".to_string()];
    let mut values: Vec<String> = Vec::new();

    if !filter.include_disabled {
        conditions.push("enabled = 1".to_string());
    }
    if let Some(environment) = filter.environment {
        conditions.push("environment = ?".to_string());
        values.push(environment.as_str().to_string());
    }
    if let Some(db_type) = filter.db_type.clone() {
        conditions.push("db_type = ?".to_string());
        values.push(db_type);
    }
    if let Some(name_contains) = filter.name_contains.clone() {
        conditions.push("name LIKE ? ESCAPE '\\'".to_string());
        values.push(format!("%{}%", escape_like(&name_contains)));
    }
    if let Some(group_id) = filter.group_id {
        conditions.push("id IN (SELECT asset_id FROM asset_group_members WHERE group_id = ?)".to_string());
        values.push(group_id.to_string());
    }
    (conditions, values)
}

/// Build `?, ?, ...` placeholders for an IN list.
pub(crate) fn in_placeholders(count: usize) -> String {
    (0..count).map(|_| "?").collect::<Vec<_>>().join(", ")
}

#[async_trait]
impl AssetRepository for SqliteStore {
    async fn resolve_asset(&self, asset_id: Uuid) -> Result<Option<Asset>> {
        self.blocking(move |conn| {
            let row: Option<AssetRow> = conn
                .query_row(
                    &format!(
                        "SELECT {ASSET_COLUMNS} FROM assets
                          WHERE id = ?1 AND enabled = 1 AND deleted_at IS NULL
                          LIMIT 1"
                    ),
                    [asset_id.to_string()],
                    map_asset_row,
                )
                .optional()?;
            row.map(to_asset).transpose()
        })
        .await
    }

    async fn find_asset_by_id(&self, asset_id: Uuid) -> Result<Option<Asset>> {
        self.blocking(move |conn| {
            let row: Option<AssetRow> = conn
                .query_row(
                    &format!("SELECT {ASSET_COLUMNS} FROM assets WHERE id = ?1 LIMIT 1"),
                    [asset_id.to_string()],
                    map_asset_row,
                )
                .optional()?;
            row.map(to_asset).transpose()
        })
        .await
    }

    async fn find_asset_by_name(&self, name: &str) -> Result<Option<Asset>> {
        let name = name.to_string();
        self.blocking(move |conn| {
            let row: Option<AssetRow> = conn
                .query_row(
                    &format!("SELECT {ASSET_COLUMNS} FROM assets WHERE name = ?1 LIMIT 1"),
                    [&name],
                    map_asset_row,
                )
                .optional()?;
            row.map(to_asset).transpose()
        })
        .await
    }

    async fn create_asset(&self, asset: &Asset) -> Result<()> {
        let asset = asset.clone();
        self.blocking(move |conn| {
            let result = conn.execute(
                "INSERT INTO assets
                    (id, name, environment, db_type, dbx_connection_id, enabled,
                     description, deleted_at, last_tested_at, last_test_status,
                     created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL, NULL, NULL, ?8, ?8)",
                rusqlite::params![
                    asset.id.to_string(),
                    asset.name,
                    asset.environment.as_str(),
                    asset.db_type,
                    asset.dbx_connection_id,
                    if asset.enabled { 1 } else { 0 },
                    asset.description,
                    to_text(asset.created_at),
                ],
            );
            result.map(|_| ()).map_err(|err| map_unique_violation(err.into(), "asset name"))
        })
        .await
    }

    async fn update_asset(&self, asset_id: Uuid, patch: &AssetPatch) -> Result<Asset> {
        let patch = patch.clone();
        self.blocking(move |conn| {
            // Build a dynamic UPDATE from the provided fields only.
            let mut sets = vec!["updated_at = ?".to_string()];
            let mut values: Vec<String> = vec![to_text(chrono::Utc::now())];
            if let Some(name) = patch.name {
                sets.push("name = ?".to_string());
                values.push(name);
            }
            if let Some(environment) = patch.environment {
                sets.push("environment = ?".to_string());
                values.push(environment.as_str().to_string());
            }
            if let Some(db_type) = patch.db_type {
                sets.push("db_type = ?".to_string());
                values.push(db_type);
            }
            if let Some(description) = patch.description {
                sets.push("description = ?".to_string());
                values.push(description);
            }
            values.push(asset_id.to_string());
            let sql = format!("UPDATE assets SET {} WHERE id = ? AND deleted_at IS NULL", sets.join(", "));
            let updated = conn
                .execute(&sql, rusqlite::params_from_iter(values.iter().map(|v| v as &dyn rusqlite::ToSql)))
                .map_err(|err| map_unique_violation(err.into(), "asset name"))?;
            if updated == 0 {
                // Either missing/deleted, or a no-op patch on a missing row.
                // Distinguish for a clear error.
                let exists: bool = conn.query_row(
                    "SELECT EXISTS(SELECT 1 FROM assets WHERE id = ?1 AND deleted_at IS NULL)",
                    [asset_id.to_string()],
                    |row| row.get(0),
                )?;
                if !exists {
                    return Err(BastionError::InvalidData(format!("asset not found: {asset_id}")));
                }
            }
            let row: AssetRow = conn.query_row(
                &format!("SELECT {ASSET_COLUMNS} FROM assets WHERE id = ?1"),
                [asset_id.to_string()],
                map_asset_row,
            )?;
            to_asset(row)
        })
        .await
    }

    async fn set_asset_enabled(&self, asset_id: Uuid, enabled: bool) -> Result<()> {
        self.blocking(move |conn| {
            conn.execute(
                "UPDATE assets SET enabled = ?1, updated_at = ?2
                  WHERE id = ?3 AND deleted_at IS NULL",
                rusqlite::params![if enabled { 1 } else { 0 }, to_text(chrono::Utc::now()), asset_id.to_string(),],
            )?;
            Ok(())
        })
        .await
    }

    async fn soft_delete_asset(&self, asset_id: Uuid) -> Result<()> {
        self.blocking(move |conn| {
            let updated = conn.execute(
                "UPDATE assets SET deleted_at = ?1, updated_at = ?1
                  WHERE id = ?2 AND deleted_at IS NULL",
                rusqlite::params![to_text(chrono::Utc::now()), asset_id.to_string()],
            )?;
            if updated == 0 {
                return Err(BastionError::InvalidData(format!("asset not found: {asset_id}")));
            }
            Ok(())
        })
        .await
    }

    async fn rebind_connection(&self, asset_id: Uuid, new_connection_id: &str) -> Result<()> {
        let new_connection_id = new_connection_id.to_string();
        self.blocking(move |conn| {
            let updated = conn.execute(
                "UPDATE assets SET dbx_connection_id = ?1, updated_at = ?2,
                                 last_tested_at = NULL, last_test_status = NULL
                  WHERE id = ?3 AND deleted_at IS NULL",
                rusqlite::params![new_connection_id, to_text(chrono::Utc::now()), asset_id.to_string()],
            )?;
            if updated == 0 {
                return Err(BastionError::InvalidData(format!("asset not found: {asset_id}")));
            }
            Ok(())
        })
        .await
    }

    async fn update_test_status(
        &self,
        asset_id: Uuid,
        tested_at: chrono::DateTime<chrono::Utc>,
        status: ConnectionTestStatus,
    ) -> Result<()> {
        let tested_at = to_text(tested_at);
        let status = status.as_str().to_string();
        self.blocking(move |conn| {
            conn.execute(
                "UPDATE assets SET last_tested_at = ?1, last_test_status = ?2, updated_at = ?1
                  WHERE id = ?3 AND deleted_at IS NULL",
                rusqlite::params![tested_at, status, asset_id.to_string()],
            )?;
            Ok(())
        })
        .await
    }

    async fn list_assets(&self, filter: &AssetFilter, page: &PageRequest) -> Result<Page<Asset>> {
        let filter = filter.clone();
        let page = page.clone();
        self.blocking(move |conn| {
            let (page_num, page_size) = page.normalized();
            let (conditions, mut values) = asset_filter_conditions(&filter);
            let where_clause = conditions.join(" AND ");
            // Sort column comes from the enum (whitelist by construction).
            // Sort column comes from the enum (whitelist by construction);
            // `id` is a stable tiebreaker so pagination is deterministic.
            let order =
                format!("ORDER BY {} {}, id ASC", page.sort_by.column(), if page.sort_desc { "DESC" } else { "ASC" });

            let total: i64 = conn.query_row(
                &format!("SELECT COUNT(*) FROM assets WHERE {where_clause}"),
                rusqlite::params_from_iter(values.iter().map(|v| v as &dyn rusqlite::ToSql)),
                |row| row.get(0),
            )?;

            values.push((page_size as i64).to_string());
            values.push((((page_num - 1) * page_size) as i64).to_string());
            let sql = format!("SELECT {ASSET_COLUMNS} FROM assets WHERE {where_clause} {order} LIMIT ? OFFSET ?");
            let mut stmt = conn.prepare(&sql)?;
            let items = stmt
                .query_map(rusqlite::params_from_iter(values.iter().map(|v| v as &dyn rusqlite::ToSql)), map_asset_row)?
                .map(|row| row.map_err(BastionError::from).and_then(to_asset))
                .collect::<Result<Vec<Asset>>>()?;

            Ok(Page { items, total: total as u64, page: page_num, page_size })
        })
        .await
    }
}

const GROUP_COLUMNS: &str = "id, name, parent_id, description, created_at, updated_at";

type GroupRow = (
    String,         // id
    String,         // name
    Option<String>, // parent_id
    String,         // description
    String,         // created_at
    String,         // updated_at
);

fn to_group(row: GroupRow) -> Result<AssetGroup> {
    let (id, name, parent_id, description, created_at, updated_at) = row;
    Ok(AssetGroup {
        id: parse_uuid(id)?,
        name,
        parent_id: parent_id.map(parse_uuid).transpose()?,
        description,
        created_at: parse_text(&created_at)?,
        updated_at: parse_text(&updated_at)?,
    })
}

fn map_group_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<GroupRow> {
    Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?))
}

#[async_trait]
impl AssetGroupRepository for SqliteStore {
    async fn create_group(&self, group: &NewAssetGroup) -> Result<AssetGroup> {
        let name = group.name.clone();
        let parent_id = group.parent_id;
        let description = group.description.clone();
        self.blocking(move |conn| {
            let id = Uuid::new_v4();
            let now = chrono::Utc::now();
            let now_text = to_text(now);
            conn.execute(
                "INSERT INTO asset_groups (id, name, parent_id, description, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
                rusqlite::params![id.to_string(), name, parent_id.map(|v| v.to_string()), description, now_text,],
            )
            .map_err(|err| map_unique_violation(err.into(), "asset group name"))?;
            Ok(AssetGroup { id, name, parent_id, description, created_at: now, updated_at: now })
        })
        .await
    }

    async fn find_group(&self, group_id: Uuid) -> Result<Option<AssetGroup>> {
        self.blocking(move |conn| {
            let row: Option<GroupRow> = conn
                .query_row(
                    &format!("SELECT {GROUP_COLUMNS} FROM asset_groups WHERE id = ?1 LIMIT 1"),
                    [group_id.to_string()],
                    map_group_row,
                )
                .optional()?;
            row.map(to_group).transpose()
        })
        .await
    }

    async fn find_group_by_name(&self, name: &str) -> Result<Option<AssetGroup>> {
        let name = name.to_string();
        self.blocking(move |conn| {
            let row: Option<GroupRow> = conn
                .query_row(
                    &format!("SELECT {GROUP_COLUMNS} FROM asset_groups WHERE name = ?1 LIMIT 1"),
                    [&name],
                    map_group_row,
                )
                .optional()?;
            row.map(to_group).transpose()
        })
        .await
    }

    async fn update_group(&self, group_id: Uuid, patch: &UpdateAssetGroup) -> Result<AssetGroup> {
        let patch = patch.clone();
        self.blocking(move |conn| {
            let mut sets = vec!["updated_at = ?".to_string()];
            let mut values: Vec<String> = vec![to_text(chrono::Utc::now())];
            if let Some(name) = patch.name {
                sets.push("name = ?".to_string());
                values.push(name);
            }
            if let Some(description) = patch.description {
                sets.push("description = ?".to_string());
                values.push(description);
            }
            values.push(group_id.to_string());
            let sql = format!("UPDATE asset_groups SET {} WHERE id = ?", sets.join(", "));
            let updated = conn
                .execute(&sql, rusqlite::params_from_iter(values.iter().map(|v| v as &dyn rusqlite::ToSql)))
                .map_err(|err| map_unique_violation(err.into(), "asset group name"))?;
            if updated == 0 {
                return Err(BastionError::InvalidData(format!("asset group not found: {group_id}")));
            }
            let row: GroupRow = conn.query_row(
                &format!("SELECT {GROUP_COLUMNS} FROM asset_groups WHERE id = ?1"),
                [group_id.to_string()],
                map_group_row,
            )?;
            to_group(row)
        })
        .await
    }

    async fn set_group_parent_checked(&self, group_id: Uuid, parent_id: Option<Uuid>) -> Result<AssetGroup> {
        self.in_transaction(move |tx| {
            let exists: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM asset_groups WHERE id = ?1)",
                [group_id.to_string()],
                |row| row.get(0),
            )?;
            if !exists {
                return Err(BastionError::InvalidData(format!("asset group not found: {group_id}")));
            }
            if let Some(pid) = parent_id {
                let parent_exists: bool = tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM asset_groups WHERE id = ?1)",
                    [pid.to_string()],
                    |row| row.get(0),
                )?;
                if !parent_exists {
                    return Err(BastionError::InvalidData(format!("parent group not found: {pid}")));
                }
                // Ancestor walk inside the same transaction. Concurrent
                // moves serialize on the IMMEDIATE transaction (5s busy
                // timeout), so this walk observes their committed writes;
                // no check-then-act interleaving can form a cycle.
                let mut current = Some(pid);
                while let Some(ancestor) = current {
                    if ancestor == group_id {
                        return Err(BastionError::InvalidData("group hierarchy would contain a cycle".into()));
                    }
                    let parent: Option<String> = tx
                        .query_row("SELECT parent_id FROM asset_groups WHERE id = ?1", [ancestor.to_string()], |row| {
                            row.get(0)
                        })
                        .optional()?
                        .flatten();
                    current = parent.map(parse_uuid).transpose()?;
                }
            }
            tx.execute(
                "UPDATE asset_groups SET parent_id = ?1, updated_at = ?2 WHERE id = ?3",
                rusqlite::params![parent_id.map(|v| v.to_string()), to_text(chrono::Utc::now()), group_id.to_string(),],
            )?;
            let sql = format!("SELECT {GROUP_COLUMNS} FROM asset_groups WHERE id = ?1");
            let row: GroupRow = tx.query_row(&sql, [group_id.to_string()], map_group_row)?;
            to_group(row)
        })
        .await
    }

    async fn delete_group(&self, group_id: Uuid) -> Result<()> {
        self.blocking(move |conn| {
            let deleted = conn.execute("DELETE FROM asset_groups WHERE id = ?1", [group_id.to_string()])?;
            if deleted == 0 {
                return Err(BastionError::InvalidData(format!("asset group not found: {group_id}")));
            }
            Ok(())
        })
        .await
    }

    async fn list_groups(&self) -> Result<Vec<AssetGroup>> {
        self.blocking(move |conn| {
            let sql = format!("SELECT {GROUP_COLUMNS} FROM asset_groups ORDER BY name ASC");
            let mut stmt = conn.prepare(&sql)?;
            let rows = stmt.query_map([], map_group_row).map_err(BastionError::from)?;
            let groups: Vec<AssetGroup> =
                rows.map(|row| row.map_err(BastionError::from).and_then(to_group)).collect::<Result<Vec<_>>>()?;
            Ok(groups)
        })
        .await
    }

    async fn child_groups(&self, group_id: Uuid) -> Result<Vec<AssetGroup>> {
        self.blocking(move |conn| {
            let sql = format!("SELECT {GROUP_COLUMNS} FROM asset_groups WHERE parent_id = ?1 ORDER BY name ASC");
            let mut stmt = conn.prepare(&sql)?;
            let rows = stmt.query_map([group_id.to_string()], map_group_row).map_err(BastionError::from)?;
            let groups: Vec<AssetGroup> =
                rows.map(|row| row.map_err(BastionError::from).and_then(to_group)).collect::<Result<Vec<_>>>()?;
            Ok(groups)
        })
        .await
    }

    async fn add_asset_to_group(&self, asset_id: Uuid, group_id: Uuid) -> Result<()> {
        self.blocking(move |conn| {
            conn.execute(
                "INSERT OR IGNORE INTO asset_group_members (asset_id, group_id) VALUES (?1, ?2)",
                rusqlite::params![asset_id.to_string(), group_id.to_string()],
            )?;
            Ok(())
        })
        .await
    }

    async fn remove_asset_from_group(&self, asset_id: Uuid, group_id: Uuid) -> Result<()> {
        self.blocking(move |conn| {
            conn.execute(
                "DELETE FROM asset_group_members WHERE asset_id = ?1 AND group_id = ?2",
                rusqlite::params![asset_id.to_string(), group_id.to_string()],
            )?;
            Ok(())
        })
        .await
    }

    /// Counts non-deleted member assets (deleted assets don't block group
    /// deletion).
    async fn group_member_count(&self, group_id: Uuid) -> Result<u64> {
        self.blocking(move |conn| {
            let count: i64 = conn.query_row(
                "SELECT COUNT(*) FROM asset_group_members m
                  JOIN assets a ON a.id = m.asset_id
                 WHERE m.group_id = ?1 AND a.deleted_at IS NULL",
                [group_id.to_string()],
                |row| row.get(0),
            )?;
            Ok(count as u64)
        })
        .await
    }

    async fn asset_groups(&self, asset_id: Uuid) -> Result<Vec<AssetGroup>> {
        self.blocking(move |conn| {
            let sql = format!(
                "SELECT {GROUP_COLUMNS} FROM asset_groups g
                  JOIN asset_group_members m ON m.group_id = g.id
                 WHERE m.asset_id = ?1
                 ORDER BY g.name ASC"
            );
            let mut stmt = conn.prepare(&sql)?;
            let rows = stmt.query_map([asset_id.to_string()], map_group_row).map_err(BastionError::from)?;
            let groups: Vec<AssetGroup> =
                rows.map(|row| row.map_err(BastionError::from).and_then(to_group)).collect::<Result<Vec<_>>>()?;
            Ok(groups)
        })
        .await
    }

    async fn set_asset_groups(&self, asset_id: Uuid, group_ids: &[Uuid]) -> Result<()> {
        let group_ids: Vec<String> = group_ids.iter().map(|id| id.to_string()).collect();
        self.in_transaction(move |tx| {
            tx.execute("DELETE FROM asset_group_members WHERE asset_id = ?1", [asset_id.to_string()])?;
            for group_id in &group_ids {
                tx.execute(
                    "INSERT INTO asset_group_members (asset_id, group_id) VALUES (?1, ?2)",
                    rusqlite::params![asset_id.to_string(), group_id],
                )?;
            }
            Ok(())
        })
        .await
    }
}

#[async_trait]
impl UserRepository for SqliteStore {
    async fn find_user_by_username(&self, username: &str) -> Result<Option<UserCredentialRecord>> {
        let username = username.to_string();
        self.blocking(move |conn| {
            // `username` column is COLLATE NOCASE, so `=` already matches
            // case-insensitively.
            let row: Option<(String, String, String, String, i64)> = conn
                .query_row(
                    "SELECT id, username, display_name, password_hash, enabled
                       FROM users
                      WHERE username = ?1
                      LIMIT 1",
                    [&username],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
                )
                .optional()?;

            row.map(|(id, username, display_name, password_hash, enabled)| {
                Ok(UserCredentialRecord {
                    id: parse_uuid(id)?,
                    username,
                    display_name,
                    password_hash,
                    enabled: enabled != 0,
                })
            })
            .transpose()
        })
        .await
    }

    async fn find_user_by_id(&self, user_id: Uuid) -> Result<Option<UserCredentialRecord>> {
        self.blocking(move |conn| {
            let row: Option<(String, String, String, String, i64)> = conn
                .query_row(
                    "SELECT id, username, display_name, password_hash, enabled
                       FROM users
                      WHERE id = ?1
                      LIMIT 1",
                    [user_id.to_string()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
                )
                .optional()?;

            row.map(|(id, username, display_name, password_hash, enabled)| {
                Ok(UserCredentialRecord {
                    id: parse_uuid(id)?,
                    username,
                    display_name,
                    password_hash,
                    enabled: enabled != 0,
                })
            })
            .transpose()
        })
        .await
    }

    async fn create_user(&self, user: &NewUser) -> Result<Uuid> {
        let user = user.clone();
        self.blocking(move |conn| {
            let id = Uuid::new_v4();
            conn.execute(
                "INSERT INTO users (id, username, display_name, password_hash, enabled)
                 VALUES (?1, ?2, ?3, ?4, 1)",
                rusqlite::params![id.to_string(), user.username, user.display_name, user.password_hash,],
            )?;
            Ok(id)
        })
        .await
    }

    async fn update_password_hash(&self, user_id: Uuid, password_hash: &str) -> Result<()> {
        let password_hash = password_hash.to_string();
        self.blocking(move |conn| {
            conn.execute(
                "UPDATE users SET password_hash = ?1, updated_at = ?2 WHERE id = ?3",
                rusqlite::params![
                    password_hash,
                    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                    user_id.to_string(),
                ],
            )?;
            Ok(())
        })
        .await
    }

    async fn set_user_enabled(&self, user_id: Uuid, enabled: bool) -> Result<()> {
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        self.in_transaction(move |tx| {
            tx.execute(
                "UPDATE users SET enabled = ?1, updated_at = ?2 WHERE id = ?3",
                rusqlite::params![if enabled { 1 } else { 0 }, now, user_id.to_string(),],
            )?;
            if !enabled {
                // Revoke all sessions atomically with the disable. A session
                // racing the disable is either aborted at creation (hash /
                // enabled re-check) or revoked here; either way it can never
                // be resurrected by a later re-enable.
                tx.execute(
                    "UPDATE sessions SET revoked_at = ?1 WHERE user_id = ?2 AND revoked_at IS NULL",
                    rusqlite::params![now, user_id.to_string()],
                )?;
            }
            Ok(())
        })
        .await
    }

    async fn user_role_names(&self, user_id: Uuid) -> Result<Vec<String>> {
        self.blocking(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT r.name
                   FROM roles r
                   JOIN user_roles ur ON ur.role_id = r.id
                  WHERE ur.user_id = ?1
                  ORDER BY r.name",
            )?;
            let names =
                stmt.query_map([user_id.to_string()], |row| row.get(0))?.collect::<rusqlite::Result<Vec<String>>>()?;
            Ok(names)
        })
        .await
    }
}

/// Raw session row:
/// `(id, user_id, token_hash, login_ip, user_agent, created_at, expires_at,
/// last_active_at, revoked_at)`.
type SessionRow =
    (String, String, String, Option<String>, Option<String>, String, String, Option<String>, Option<String>);

fn map_session_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<SessionRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
    ))
}

fn to_session_record(row: SessionRow) -> Result<SessionRecord> {
    use crate::auth::session::parse_text;
    let (id, user_id, token_hash, source_ip, user_agent, created_at, expires_at, last_active_at, revoked_at) = row;
    Ok(SessionRecord {
        id: parse_uuid(id)?,
        user_id: parse_uuid(user_id)?,
        token_hash,
        source_ip,
        user_agent,
        created_at: parse_text(&created_at)?,
        expires_at: parse_text(&expires_at)?,
        last_active_at: last_active_at.map(|v| parse_text(&v)).transpose()?,
        revoked_at: revoked_at.map(|v| parse_text(&v)).transpose()?,
    })
}

/// 0001 named the column `login_ip`; it maps to the domain's `source_ip`.
const SESSION_COLUMNS: &str =
    "id, user_id, token_hash, login_ip, user_agent, created_at, expires_at, last_active_at, revoked_at";

#[async_trait]
impl SessionRepository for SqliteStore {
    async fn find_session_by_token_hash(&self, token_hash: &str) -> Result<Option<SessionRecord>> {
        let token_hash = token_hash.to_string();
        self.blocking(move |conn| {
            let row = conn
                .query_row(
                    &format!("SELECT {SESSION_COLUMNS} FROM sessions WHERE token_hash = ?1 LIMIT 1"),
                    [&token_hash],
                    map_session_record,
                )
                .optional()?;
            row.map(to_session_record).transpose()
        })
        .await
    }

    async fn touch_session(&self, session_id: Uuid, at: chrono::DateTime<chrono::Utc>) -> Result<()> {
        let at_text = to_text(at);
        self.blocking(move |conn| {
            conn.execute(
                "UPDATE sessions SET last_active_at = ?1 WHERE id = ?2",
                rusqlite::params![at_text, session_id.to_string()],
            )?;
            Ok(())
        })
        .await
    }

    async fn revoke_session(&self, session_id: Uuid) -> Result<bool> {
        self.blocking(move |conn| {
            let affected = conn.execute(
                "UPDATE sessions SET revoked_at = ?1 WHERE id = ?2 AND revoked_at IS NULL",
                rusqlite::params![
                    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                    session_id.to_string(),
                ],
            )?;
            Ok(affected > 0)
        })
        .await
    }

    async fn revoke_all_user_sessions(&self, user_id: Uuid) -> Result<u64> {
        self.blocking(move |conn| {
            let affected = conn.execute(
                "UPDATE sessions SET revoked_at = ?1 WHERE user_id = ?2 AND revoked_at IS NULL",
                rusqlite::params![
                    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                    user_id.to_string(),
                ],
            )?;
            Ok(affected as u64)
        })
        .await
    }

    async fn purge_expired_sessions(&self, now: chrono::DateTime<chrono::Utc>) -> Result<u64> {
        let now_text = to_text(now);
        self.blocking(move |conn| {
            let affected = conn.execute("DELETE FROM sessions WHERE expires_at <= ?1", [&now_text])?;
            Ok(affected as u64)
        })
        .await
    }
}

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

use crate::asset::{Asset, AssetRepository, Environment, UserCredentialRecord, UserRepository};
use crate::auth::Principal;
use crate::error::{BastionError, Result};
use crate::rbac::{Action, AuthorizationRepository, Effect, PermissionRule};

/// Ordered migrations. Add new files here; never edit an applied one.
const MIGRATIONS: &[(&str, &str)] = &[("0001_init", include_str!("../migrations/0001_init.sql"))];

pub struct SqliteStore {
    conn: Arc<Mutex<Connection>>,
    path: PathBuf,
}

impl SqliteStore {
    /// Open the bastion database at `path`, creating parent directories and
    /// the file if needed, then apply pending migrations.
    ///
    /// Synchronous by design: call once at startup (wrap in
    /// `spawn_blocking` at the call site if already inside async code).
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|error| BastionError::Migration(error.to_string()))?;
            }
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
    async fn blocking<F, T>(&self, f: F) -> Result<T>
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
        let tx = conn.transaction()?;
        tx.execute_batch(sql)
            .map_err(|error| BastionError::Migration(format!("migration {version} failed: {error}")))?;
        tx.execute(
            "INSERT INTO schema_migrations (version, applied_at) VALUES (?1, ?2)",
            rusqlite::params![version, chrono::Utc::now().to_rfc3339()],
        )?;
        tx.commit()?;
    }
    Ok(())
}

fn parse_uuid(value: String) -> Result<Uuid> {
    Uuid::parse_str(&value).map_err(|error| BastionError::InvalidData(error.to_string()))
}

#[async_trait]
impl AssetRepository for SqliteStore {
    async fn resolve_asset(&self, asset_id: Uuid) -> Result<Option<Asset>> {
        self.blocking(move |conn| {
            let row: Option<(String, String, String, String, String, i64)> = conn
                .query_row(
                    "SELECT id, name, environment, db_type, dbx_connection_id, enabled
                       FROM assets
                      WHERE id = ?1 AND enabled = 1
                      LIMIT 1",
                    [asset_id.to_string()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
                )
                .optional()?;

            row.map(|(id, name, environment, db_type, dbx_connection_id, enabled)| {
                Ok(Asset {
                    id: parse_uuid(id)?,
                    name,
                    environment: Environment::parse(&environment)
                        .ok_or_else(|| BastionError::InvalidData(format!("unknown environment: {environment}")))?,
                    db_type,
                    dbx_connection_id,
                    enabled: enabled != 0,
                })
            })
            .transpose()
        })
        .await
    }

    async fn create_asset(&self, asset: &Asset) -> Result<()> {
        let asset = asset.clone();
        self.blocking(move |conn| {
            conn.execute(
                "INSERT INTO assets (id, name, environment, db_type, dbx_connection_id, enabled)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![
                    asset.id.to_string(),
                    asset.name,
                    asset.environment.as_str(),
                    asset.db_type,
                    asset.dbx_connection_id,
                    if asset.enabled { 1 } else { 0 },
                ],
            )?;
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
}

#[async_trait]
impl AuthorizationRepository for SqliteStore {
    async fn permission_rules(&self, principal: &Principal, action: Action) -> Result<Vec<PermissionRule>> {
        let user_id = principal.user_id;
        let action_name = action.as_str().to_string();
        self.blocking(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT p.effect, p.action, p.asset_id,
                        p.database_pattern, p.schema_pattern, p.table_pattern
                   FROM permissions p
                   JOIN user_roles ur ON ur.role_id = p.role_id
                  WHERE ur.user_id = ?1
                    AND p.action = ?2",
            )?;
            let raw: Vec<(String, String, Option<String>, Option<String>, Option<String>, Option<String>)> = stmt
                .query_map(rusqlite::params![user_id.to_string(), action_name], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;

            raw.into_iter()
                .map(|(effect, action, asset_id, database_pattern, schema_pattern, table_pattern)| {
                    Ok(PermissionRule {
                        effect: match effect.as_str() {
                            "deny" => Effect::Deny,
                            "allow" => Effect::Allow,
                            other => {
                                return Err(BastionError::InvalidData(format!("unknown permission effect: {other}")))
                            }
                        },
                        action: Action::parse(&action)
                            .ok_or_else(|| BastionError::InvalidData(format!("unknown permission action: {action}")))?,
                        asset_id: asset_id.map(parse_uuid).transpose()?,
                        database_pattern,
                        schema_pattern,
                        table_pattern,
                    })
                })
                .collect()
        })
        .await
    }
}

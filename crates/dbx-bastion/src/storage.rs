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

use crate::asset::{Asset, AssetRepository, Environment, NewUser, UserCredentialRecord, UserRepository};
use crate::auth::session::{to_text, SessionRecord, SessionRepository};
use crate::auth::Principal;
use crate::error::{BastionError, Result};
use crate::rbac::{Action, AuthorizationRepository, Effect, PermissionRule};

/// Ordered migrations. Add new files here; never edit an applied one.
const MIGRATIONS: &[(&str, &str)] = &[
    ("0001_init", include_str!("../migrations/0001_init.sql")),
    ("0002_auth", include_str!("../migrations/0002_auth.sql")),
];

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
        restrict_file_permissions(path)?;

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
}

/// Tighten the database file to owner-only access (Unix). The bastion
/// database holds password hashes and session token hashes; group/other
/// must not read it. Applied on every open (idempotent) so files created
/// before this hardening are fixed too.
fn restrict_file_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(|error| {
            BastionError::Migration(format!("cannot restrict permissions on {}: {error}", path.display()))
        })?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
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
        self.blocking(move |conn| {
            conn.execute(
                "UPDATE users SET enabled = ?1, updated_at = ?2 WHERE id = ?3",
                rusqlite::params![
                    if enabled { 1 } else { 0 },
                    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                    user_id.to_string(),
                ],
            )?;
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

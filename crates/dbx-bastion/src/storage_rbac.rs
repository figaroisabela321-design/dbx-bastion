//! RBAC persistence for [`SqliteStore`]: consistency snapshots, grant CRUD,
//! user groups, and the authorization-filtered asset listing.
//!
//! This is a free extension module (not `impl` blocks inside storage.rs)
//! to keep the RBAC surface in one reviewable place. Everything here runs
//! through the store's blocking/mutex discipline.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use rusqlite::OptionalExtension;
use uuid::Uuid;

use crate::asset::{Asset, AssetFilter, Environment, Page, PageRequest};
use crate::auth::session::{parse_text, Clock};
use crate::error::{BastionError, Result};
use crate::rbac::grants::{GrantRecord, RoleInfo};
use crate::rbac::snapshot::{AuthSnapshot, GrantRule, SnapshotAsset};
use crate::rbac::{Action, Effect};
use crate::storage::{in_placeholders, map_asset_row, parse_uuid, to_asset, SqliteStore, ASSET_COLUMNS};

impl SqliteStore {
    /// Build one authorization consistency snapshot inside a single
    /// Deferred read transaction.
    ///
    /// Reads, in order: session validity (re-checked: revocation/expiry
    /// after [`AuthenticatedPrincipal`](crate::auth::AuthenticatedPrincipal)
    /// issuance denies here), user enabled flag, direct roles, roles via
    /// user groups, grant rows for the effective roles and requested
    /// actions, asset rows, the asset group tree, and asset<->group
    /// memberships — plus the single `now` used for all expiry checks.
    ///
    /// Never cached: every authorization call builds a fresh snapshot, so
    /// permission changes are visible to the next request.
    pub(crate) async fn authorization_snapshot(
        &self,
        user_id: Uuid,
        session_id: Uuid,
        actions: &[Action],
        clock: Arc<dyn Clock>,
    ) -> Result<AuthSnapshot> {
        let actions: Vec<Action> = actions.to_vec();
        self.in_read_transaction(move |tx| Self::load_snapshot_in(tx, user_id, session_id, &actions, &clock)).await
    }

    /// Lightweight session re-validation for the management plane
    /// ([`AssetAdminGuard`](crate::asset::service::AssetAdminGuard)).
    ///
    /// Same semantics as the `session_valid` bit in
    /// [`Self::authorization_snapshot`]: the session row must exist,
    /// belong to `user_id`, be unrevoked and unexpired at `now`. A
    /// revoked or expired session retains no administrative power, even
    /// if the caller still holds a previously issued
    /// [`AuthenticatedPrincipal`](crate::auth::AuthenticatedPrincipal).
    pub(crate) async fn session_active_for_user(
        &self,
        session_id: Uuid,
        user_id: Uuid,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool> {
        self.blocking(move |conn| {
            let row: Option<(String, Option<String>, String)> = conn
                .query_row(
                    "SELECT user_id, revoked_at, expires_at FROM sessions WHERE id = ?1",
                    [session_id.to_string()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()?;
            Ok(row
                .map(|(session_user, revoked_at, expires_at)| {
                    session_user == user_id.to_string()
                        && revoked_at.is_none()
                        && expires_at.parse::<chrono::DateTime<chrono::Utc>>().map(|t| t > now).unwrap_or(false)
                })
                .unwrap_or(false))
        })
        .await
    }

    /// Paginated asset listing restricted to CONNECT-authorized assets.
    ///
    /// The snapshot, the authorized-id computation, the filtered query and
    /// the total count all happen inside **one** read transaction, so
    /// pagination, search and totals are always consistent with the
    /// authorization decision — and reveal nothing about unauthorized
    /// assets (an empty authorized set yields an empty page with total 0).
    pub(crate) async fn list_connect_authorized_assets(
        &self,
        user_id: Uuid,
        session_id: Uuid,
        filter: &AssetFilter,
        page: &PageRequest,
        clock: Arc<dyn Clock>,
    ) -> Result<Page<Asset>> {
        let filter = filter.clone();
        let page = page.clone();
        self.in_read_transaction(move |tx| {
            let snapshot = Self::load_snapshot_in(tx, user_id, session_id, &[Action::Connect], &clock)?;
            let authorized: Vec<String> =
                snapshot.assets.keys().filter(|id| snapshot.connect_allowed(**id)).map(|id| id.to_string()).collect();

            let (page_num, page_size) = page.normalized();
            let (mut conditions, mut values) = crate::storage::asset_filter_conditions(&filter);
            // Authorization first: everything below is scoped to the
            // authorized set. Chunked so large fleets stay under the
            // SQLite variable limit.
            if authorized.is_empty() {
                return Ok(Page { items: vec![], total: 0, page: page_num, page_size });
            }
            let mut auth_placeholders = Vec::new();
            for chunk in authorized.chunks(900) {
                auth_placeholders.push(format!("id IN ({})", in_placeholders(chunk.len())));
                for id in chunk {
                    values.push(id.clone());
                }
            }
            conditions.push(format!("({})", auth_placeholders.join(" OR ")));
            let where_clause = conditions.join(" AND ");
            let order =
                format!("ORDER BY {} {}, id ASC", page.sort_by.column(), if page.sort_desc { "DESC" } else { "ASC" });

            let total: i64 = tx.query_row(
                &format!("SELECT COUNT(*) FROM assets WHERE {where_clause}"),
                rusqlite::params_from_iter(values.iter().map(|v| v as &dyn rusqlite::ToSql)),
                |row| row.get(0),
            )?;

            values.push((page_size as i64).to_string());
            values.push((((page_num - 1) * page_size) as i64).to_string());
            let sql = format!("SELECT {} FROM assets WHERE {where_clause} {order} LIMIT ? OFFSET ?", ASSET_COLUMNS);
            let mut stmt = tx.prepare(&sql)?;
            let items = stmt
                .query_map(rusqlite::params_from_iter(values.iter().map(|v| v as &dyn rusqlite::ToSql)), map_asset_row)?
                .map(|row| row.map_err(BastionError::from).and_then(to_asset))
                .collect::<Result<Vec<Asset>>>()?;

            Ok(Page { items, total: total as u64, page: page_num, page_size })
        })
        .await
    }

    /// Snapshot loader shared by [`Self::authorization_snapshot`] and the
    /// authorized listing: same queries, same transaction discipline.
    fn load_snapshot_in(
        tx: &rusqlite::Transaction<'_>,
        user_id: Uuid,
        session_id: Uuid,
        actions: &[Action],
        clock: &Arc<dyn Clock>,
    ) -> Result<AuthSnapshot> {
        let mut seen_actions = HashSet::new();
        let mut action_names = Vec::new();
        for action in actions {
            if seen_actions.insert(action.as_str()) {
                action_names.push(action.as_str().to_string());
            }
        }
        let now = clock.now();
        let uid = user_id.to_string();
        let sid = session_id.to_string();

        // Identity binding, enforced at runtime (effective in release
        // builds, not just debug_assert): the session row must belong to
        // the user this snapshot is built for. Roles and grants below are
        // loaded by `user_id`; without this check a mismatched
        // (user_id, session_id) pair would evaluate one user's grants
        // against another user's session validity — a confused-deputy
        // hole. Any mismatch fails closed via `session_valid = false`.
        let session_valid: bool = tx
            .query_row("SELECT user_id, revoked_at, expires_at FROM sessions WHERE id = ?1", [&sid], |row| {
                let session_user: String = row.get(0)?;
                let revoked_at: Option<String> = row.get(1)?;
                let expires_at: String = row.get(2)?;
                Ok((session_user, revoked_at, expires_at))
            })
            .optional()?
            .map(|(session_user, revoked_at, expires_at)| {
                session_user == uid
                    && revoked_at.is_none()
                    && expires_at.parse::<chrono::DateTime<chrono::Utc>>().map(|t| t > now).unwrap_or(false)
            })
            .unwrap_or(false);

        let user_enabled: bool = tx
            .query_row("SELECT enabled FROM users WHERE id = ?1", [&uid], |row| row.get::<_, i64>(0))
            .optional()?
            .map(|v| v != 0)
            .unwrap_or(false);

        let mut role_ids: HashSet<Uuid> = tx
            .prepare("SELECT role_id FROM user_roles WHERE user_id = ?1")?
            .query_map([&uid], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?
            .into_iter()
            .map(parse_uuid)
            .collect::<Result<HashSet<_>>>()?;

        let group_ids: Vec<String> = tx
            .prepare("SELECT group_id FROM user_group_members WHERE user_id = ?1")?
            .query_map([&uid], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<String>>>()?;
        if !group_ids.is_empty() {
            let mut stmt = tx.prepare(&format!(
                "SELECT role_id FROM group_roles WHERE group_id IN ({})",
                in_placeholders(group_ids.len())
            ))?;
            let params: Vec<&dyn rusqlite::ToSql> = group_ids.iter().map(|g| g as &dyn rusqlite::ToSql).collect();
            let extra: Vec<String> =
                stmt.query_map(params.as_slice(), |row| row.get(0))?.collect::<rusqlite::Result<_>>()?;
            for id in extra {
                role_ids.insert(parse_uuid(id)?);
            }
        }

        let mut rules = Vec::new();
        if !role_ids.is_empty() && !action_names.is_empty() {
            let role_list: Vec<String> = role_ids.iter().map(|id| id.to_string()).collect();
            let mut stmt = tx.prepare(&format!(
                "SELECT id, role_id, effect, action, asset_id, asset_group_id,
                        database_pattern, schema_pattern, table_pattern, expires_at
                   FROM permissions
                  WHERE role_id IN ({}) AND action IN ({})",
                in_placeholders(role_list.len()),
                in_placeholders(action_names.len()),
            ))?;
            let mut params: Vec<&dyn rusqlite::ToSql> = Vec::new();
            for role in &role_list {
                params.push(role);
            }
            for action in &action_names {
                params.push(action);
            }
            #[allow(clippy::type_complexity)]
            let rows: Vec<(
                String,
                String,
                String,
                String,
                Option<String>,
                Option<String>,
                Option<String>,
                Option<String>,
                Option<String>,
                Option<String>,
            )> = stmt
                .query_map(params.as_slice(), |row| {
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
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            for (id, role_id, effect, action, asset_id, asset_group_id, database, schema, table, expires_at) in rows {
                rules.push(GrantRule {
                    id: parse_uuid(id)?,
                    effect: Effect::parse(&effect)
                        .ok_or_else(|| BastionError::InvalidData(format!("unknown grant effect: {effect}")))?,
                    action: Action::parse(&action)
                        .ok_or_else(|| BastionError::InvalidData(format!("unknown grant action: {action}")))?,
                    role_id: parse_uuid(role_id)?,
                    asset_id: asset_id.map(parse_uuid).transpose()?,
                    asset_group_id: asset_group_id.map(parse_uuid).transpose()?,
                    database,
                    schema,
                    table,
                    expires_at,
                });
            }
        }

        let mut assets = HashMap::new();
        {
            let mut stmt =
                tx.prepare("SELECT id, name, environment, db_type, description, enabled, deleted_at FROM assets")?;
            #[allow(clippy::type_complexity)]
            let rows: Vec<(String, String, String, String, String, i64, Option<String>)> = stmt
                .query_map([], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            for (id, name, environment, db_type, description, enabled, deleted_at) in rows {
                let id = parse_uuid(id)?;
                assets.insert(
                    id,
                    SnapshotAsset {
                        id,
                        name,
                        environment: Environment::parse(&environment)
                            .ok_or_else(|| BastionError::InvalidData(format!("unknown environment: {environment}")))?,
                        db_type,
                        description,
                        enabled: enabled != 0,
                        deleted_at: deleted_at.map(|raw| parse_text(&raw)).transpose()?,
                    },
                );
            }
        }

        let mut group_children: HashMap<Uuid, Vec<Uuid>> = HashMap::new();
        {
            let mut stmt = tx.prepare("SELECT id, parent_id FROM asset_groups")?;
            let rows: Vec<(String, Option<String>)> =
                stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
            for (id, parent_id) in rows {
                if let Some(parent) = parent_id {
                    group_children.entry(parse_uuid(parent)?).or_default().push(parse_uuid(id)?);
                }
            }
        }

        let mut asset_groups: HashMap<Uuid, Vec<Uuid>> = HashMap::new();
        {
            let mut stmt = tx.prepare("SELECT asset_id, group_id FROM asset_group_members")?;
            let rows: Vec<(String, String)> =
                stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
            for (asset_id, group_id) in rows {
                asset_groups.entry(parse_uuid(asset_id)?).or_default().push(parse_uuid(group_id)?);
            }
        }

        Ok(AuthSnapshot { session_valid, user_enabled, rules, assets, group_children, asset_groups, now })
    }

    // ---- grants ----------------------------------------------------------

    pub(crate) async fn insert_grant(
        &self,
        role_id: Uuid,
        effect: Effect,
        action: Action,
        asset_id: Option<Uuid>,
        asset_group_id: Option<Uuid>,
        database: Option<String>,
        schema: Option<String>,
        table: Option<String>,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<Uuid> {
        let id = Uuid::new_v4();
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        self.blocking(move |conn| {
            conn.execute(
                "INSERT INTO permissions
                    (id, role_id, effect, action, asset_id, asset_group_id,
                     database_pattern, schema_pattern, table_pattern, expires_at, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                rusqlite::params![
                    id.to_string(),
                    role_id.to_string(),
                    effect.as_str(),
                    action.as_str(),
                    asset_id.map(|v| v.to_string()),
                    asset_group_id.map(|v| v.to_string()),
                    database,
                    schema,
                    table,
                    expires_at.map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)),
                    now,
                ],
            )?;
            Ok(id)
        })
        .await
    }

    pub(crate) async fn delete_grant(&self, grant_id: Uuid) -> Result<bool> {
        self.blocking(move |conn| {
            let affected = conn.execute("DELETE FROM permissions WHERE id = ?1", [grant_id.to_string()])?;
            Ok(affected > 0)
        })
        .await
    }

    /// Explicit bulk revocation scoped to an asset group (required before
    /// deleting a group that still has grants: `ON DELETE RESTRICT`).
    pub(crate) async fn delete_grants_for_group(&self, group_id: Uuid) -> Result<u64> {
        self.blocking(move |conn| {
            let affected = conn.execute("DELETE FROM permissions WHERE asset_group_id = ?1", [group_id.to_string()])?;
            Ok(affected as u64)
        })
        .await
    }

    /// Count grants scoped to an asset group (for the safe-delete pre-check).
    pub(crate) async fn count_grants_for_group(&self, group_id: Uuid) -> Result<u64> {
        self.blocking(move |conn| {
            let count: i64 = conn.query_row(
                "SELECT COUNT(*) FROM permissions WHERE asset_group_id = ?1",
                [group_id.to_string()],
                |row| row.get(0),
            )?;
            Ok(count as u64)
        })
        .await
    }

    pub(crate) async fn delete_grants_for_asset(&self, asset_id: Uuid) -> Result<u64> {
        self.blocking(move |conn| {
            let affected = conn.execute("DELETE FROM permissions WHERE asset_id = ?1", [asset_id.to_string()])?;
            Ok(affected as u64)
        })
        .await
    }

    pub(crate) async fn list_grants(&self) -> Result<Vec<GrantRecord>> {
        self.blocking(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT id, role_id, effect, action, asset_id, asset_group_id,
                        database_pattern, schema_pattern, table_pattern, expires_at, created_at
                   FROM permissions ORDER BY created_at, id",
            )?;
            #[allow(clippy::type_complexity)]
            let rows: Vec<(
                String,
                String,
                String,
                String,
                Option<String>,
                Option<String>,
                Option<String>,
                Option<String>,
                Option<String>,
                Option<String>,
                String,
            )> = stmt
                .query_map([], |row| {
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
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            rows.into_iter()
                .map(
                    |(
                        id,
                        role_id,
                        effect,
                        action,
                        asset_id,
                        asset_group_id,
                        database,
                        schema,
                        table,
                        expires_at,
                        created_at,
                    )| {
                        Ok(GrantRecord {
                            id: parse_uuid(id)?,
                            role_id: parse_uuid(role_id)?,
                            effect: Effect::parse(&effect)
                                .ok_or_else(|| BastionError::InvalidData(format!("unknown grant effect: {effect}")))?,
                            action: Action::parse(&action)
                                .ok_or_else(|| BastionError::InvalidData(format!("unknown grant action: {action}")))?,
                            asset_id: asset_id.map(parse_uuid).transpose()?,
                            asset_group_id: asset_group_id.map(parse_uuid).transpose()?,
                            database,
                            schema,
                            table,
                            expires_at,
                            created_at,
                        })
                    },
                )
                .collect()
        })
        .await
    }

    pub(crate) async fn insert_role(&self, name: &str, description: &str) -> Result<Uuid> {
        let name = name.to_string();
        let description = description.to_string();
        let id = Uuid::new_v4();
        self.blocking(move |conn| {
            conn.execute(
                "INSERT INTO roles (id, name, description) VALUES (?1, ?2, ?3)",
                rusqlite::params![id.to_string(), name, description],
            )
            .map_err(|err| crate::storage::map_unique_violation(BastionError::from(err), "role"))?;
            Ok(id)
        })
        .await
    }

    pub(crate) async fn assign_role_to_user(&self, user_id: Uuid, role_id: Uuid) -> Result<()> {
        self.blocking(move |conn| {
            conn.execute(
                "INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES (?1, ?2)",
                rusqlite::params![user_id.to_string(), role_id.to_string()],
            )?;
            Ok(())
        })
        .await
    }

    pub(crate) async fn remove_role_from_user(&self, user_id: Uuid, role_id: Uuid) -> Result<()> {
        self.blocking(move |conn| {
            conn.execute(
                "DELETE FROM user_roles WHERE user_id = ?1 AND role_id = ?2",
                rusqlite::params![user_id.to_string(), role_id.to_string()],
            )?;
            Ok(())
        })
        .await
    }

    pub(crate) async fn find_role_by_id(&self, role_id: Uuid) -> Result<Option<RoleInfo>> {
        self.blocking(move |conn| {
            conn.query_row("SELECT id, name FROM roles WHERE id = ?1", [role_id.to_string()], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .optional()?
            .map(|(id, name)| parse_uuid(id).map(|id| RoleInfo { id, name }))
            .transpose()
        })
        .await
    }

    // ---- user groups ------------------------------------------------------

    pub(crate) async fn create_user_group(&self, name: &str, description: &str) -> Result<Uuid> {
        let name = name.to_string();
        let description = description.to_string();
        let id = Uuid::new_v4();
        self.blocking(move |conn| {
            conn.execute(
                "INSERT INTO user_groups (id, name, description) VALUES (?1, ?2, ?3)",
                rusqlite::params![id.to_string(), name, description],
            )
            .map_err(|err| crate::storage::map_unique_violation(BastionError::from(err), "user group"))?;
            Ok(id)
        })
        .await
    }

    pub(crate) async fn add_user_to_group(&self, user_id: Uuid, group_id: Uuid) -> Result<()> {
        self.blocking(move |conn| {
            conn.execute(
                "INSERT OR IGNORE INTO user_group_members (user_id, group_id) VALUES (?1, ?2)",
                rusqlite::params![user_id.to_string(), group_id.to_string()],
            )?;
            Ok(())
        })
        .await
    }

    pub(crate) async fn remove_user_from_group(&self, user_id: Uuid, group_id: Uuid) -> Result<()> {
        self.blocking(move |conn| {
            conn.execute(
                "DELETE FROM user_group_members WHERE user_id = ?1 AND group_id = ?2",
                rusqlite::params![user_id.to_string(), group_id.to_string()],
            )?;
            Ok(())
        })
        .await
    }

    pub(crate) async fn add_role_to_group(&self, role_id: Uuid, group_id: Uuid) -> Result<()> {
        self.blocking(move |conn| {
            conn.execute(
                "INSERT OR IGNORE INTO group_roles (role_id, group_id) VALUES (?1, ?2)",
                rusqlite::params![role_id.to_string(), group_id.to_string()],
            )?;
            Ok(())
        })
        .await
    }

    pub(crate) async fn remove_role_from_group(&self, role_id: Uuid, group_id: Uuid) -> Result<()> {
        self.blocking(move |conn| {
            conn.execute(
                "DELETE FROM group_roles WHERE role_id = ?1 AND group_id = ?2",
                rusqlite::params![role_id.to_string(), group_id.to_string()],
            )?;
            Ok(())
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::session::SystemClock;
    use crate::rbac::resource::ResourceScope;
    use crate::rbac::AuthorizationCheck;

    fn temp_path(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("dbx-bastion-snapshot-bind-{}-{tag}.db", std::process::id()))
    }

    fn rfc3339(dt: chrono::DateTime<chrono::Utc>) -> String {
        dt.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
    }

    /// The session_id <-> user_id binding inside the snapshot loader is a
    /// runtime check, effective in release builds (not a `debug_assert`):
    /// a snapshot built for user B with user A's session must report
    /// `session_valid == false` and deny, even when B holds a grant.
    #[tokio::test]
    async fn snapshot_session_user_binding_is_release_effective() {
        let path = temp_path("mismatch");
        let _ = std::fs::remove_file(&path);
        let store = SqliteStore::open(&path).unwrap();
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);

        let user_a = Uuid::new_v4();
        let user_b = Uuid::new_v4();
        let session_a = Uuid::new_v4();
        let session_b = Uuid::new_v4();
        let role = Uuid::new_v4();
        let asset = Uuid::new_v4();

        let now = chrono::Utc::now();
        let created = rfc3339(now);
        let expires = rfc3339(now + chrono::Duration::hours(1));

        store
            .blocking(move |conn| {
                for (uid, name) in [(user_a, "a"), (user_b, "b")] {
                    conn.execute(
                        "INSERT INTO users (id, username, display_name, password_hash, enabled)
                         VALUES (?1, ?2, ?2, 'x', 1)",
                        rusqlite::params![uid.to_string(), name],
                    )?;
                }
                for (sid, uid) in [(session_a, user_a), (session_b, user_b)] {
                    conn.execute(
                        "INSERT INTO sessions (id, user_id, token_hash, created_at, expires_at, revoked_at)
                         VALUES (?1, ?2, ?3, ?4, ?5, NULL)",
                        rusqlite::params![sid.to_string(), uid.to_string(), format!("hash-{sid}"), created, expires],
                    )?;
                }
                conn.execute("INSERT INTO roles (id, name) VALUES (?1, 'r')", [role.to_string()])?;
                conn.execute(
                    "INSERT INTO user_roles (user_id, role_id) VALUES (?1, ?2)",
                    rusqlite::params![user_b.to_string(), role.to_string()],
                )?;
                conn.execute(
                    "INSERT INTO assets (id, name, environment, db_type, dbx_connection_id, enabled)
                     VALUES (?1, 'x', 'development', 'mysql', 'conn-x', 1)",
                    [asset.to_string()],
                )?;
                conn.execute(
                    "INSERT INTO permissions (id, role_id, effect, action, asset_id, asset_group_id)
                     VALUES (?1, ?2, 'allow', 'connect', ?3, NULL)",
                    rusqlite::params![Uuid::new_v4().to_string(), role.to_string(), asset.to_string()],
                )?;
                Ok::<_, BastionError>(())
            })
            .await
            .unwrap();

        let check = AuthorizationCheck::new(ResourceScope::asset(asset), Action::Connect);

        // Mismatched pair: user B's grants, user A's session -> denied.
        let mismatched =
            store.authorization_snapshot(user_b, session_a, &[Action::Connect], clock.clone()).await.unwrap();
        assert!(!mismatched.session_valid, "session of another user must not validate");
        assert!(!mismatched.decide(&check), "mismatched identity must deny even with a grant");

        // Control: matched pair authorizes.
        let matched = store.authorization_snapshot(user_b, session_b, &[Action::Connect], clock.clone()).await.unwrap();
        assert!(matched.session_valid);
        assert!(matched.decide(&check));

        let _ = std::fs::remove_file(&path);
    }
}

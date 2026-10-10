//! One-time admin bootstrap.
//!
//! Platform administrators are *identity + role* only. Bootstrapping never
//! grants database operation permissions (SELECT/UPDATE/DELETE/DDL/EXPORT
//! …): platform administration and data access are strictly separated, and
//! an admin still needs asset authorization (a later TASK) to touch any
//! database.
//!
//! Guarantees:
//!
//! - Runs inside a single `BEGIN IMMEDIATE` transaction; concurrent
//!   executions serialize and only one can succeed.
//! - A persistent marker row (`bootstrap_state.id = 1`) records completion.
//!   A second initial bootstrap is refused even across restarts.
//! - No default accounts, no default/weak passwords (policy enforced).
//! - Credentials come from a secret file or stdin only — never from CLI
//!   arguments, never from an unauthenticated HTTP endpoint (no such
//!   endpoint exists in this crate).
//! - Nothing sensitive is ever logged: no passwords, hashes or tokens.
//!
//! Recovery: if the marker exists but no enabled admin user remains
//! (operator lockout), [`AdminBootstrap::recover_admin`] provisions a new
//! admin through the same secret channel plus an explicit confirmation
//! string. This is the reserved, controlled recovery path.

use std::path::Path;
use std::sync::Arc;

use chrono::Utc;
use rusqlite::OptionalExtension;
use uuid::Uuid;

use crate::auth::password::PasswordService;
use crate::error::{BastionError, Result};
use crate::storage::SqliteStore;

pub const ADMIN_ROLE_NAME: &str = "bastion-admin";

#[derive(Debug, Clone)]
pub struct BootstrapPolicy {
    pub admin_role_name: String,
    pub admin_role_description: String,
}

impl Default for BootstrapPolicy {
    fn default() -> Self {
        Self {
            admin_role_name: ADMIN_ROLE_NAME.to_string(),
            admin_role_description:
                "Platform administrator: manages users/assets/policies, no implicit database access".to_string(),
        }
    }
}

pub struct BootstrapCredentials {
    pub username: String,
    pub display_name: String,
    pub password: String,
}

impl BootstrapCredentials {
    /// Build from explicit values (e.g. tests). Prefer the secret-file or
    /// stdin constructors in production so the password never appears in
    /// argv, shell history or process listings.
    pub fn new(username: &str, display_name: &str, password: &str) -> Self {
        Self { username: username.to_string(), display_name: display_name.to_string(), password: password.to_string() }
    }

    /// `DB_BASTION_ADMIN_USERNAME` + `DB_BASTION_ADMIN_PASSWORD_FILE`
    /// (preferred) or `DB_BASTION_ADMIN_PASSWORD` (fallback; visible in the
    /// process environment — prefer the file).
    pub fn from_env() -> Result<Self> {
        let username = std::env::var("DB_BASTION_ADMIN_USERNAME")
            .map_err(|_| BastionError::Bootstrap("DB_BASTION_ADMIN_USERNAME is not set".into()))?;
        if let Ok(path) = std::env::var("DB_BASTION_ADMIN_PASSWORD_FILE") {
            let password = read_secret_file(Path::new(&path))?;
            return Ok(Self::new(&username, &username, &password));
        }
        let password = std::env::var("DB_BASTION_ADMIN_PASSWORD").map_err(|_| {
            BastionError::Bootstrap(
                "neither DB_BASTION_ADMIN_PASSWORD_FILE nor DB_BASTION_ADMIN_PASSWORD is set".into(),
            )
        })?;
        Ok(Self::new(&username, &username, &password))
    }

    /// Read the password from a secret file. On Unix the file is *refused*
    /// (not merely warned about) when group/other have any access bits.
    pub fn from_secret_file(username: &str, path: &Path) -> Result<Self> {
        let password = read_secret_file(path)?;
        Ok(Self::new(username, username, &password))
    }

    /// Read the password from stdin (one line; use a pipe or heredoc — a
    /// TTY will echo without extra terminal handling, so prefer the secret
    /// file for interactive use).
    pub fn from_stdin(username: &str) -> Result<Self> {
        use std::io::BufRead;
        let stdin = std::io::stdin();
        let mut line = String::new();
        stdin
            .lock()
            .read_line(&mut line)
            .map_err(|error| BastionError::Bootstrap(format!("stdin read failed: {error}")))?;
        let password = line.trim_end_matches(&['\r', '\n'][..]).to_string();
        if password.is_empty() {
            return Err(BastionError::Bootstrap("empty password from stdin".into()));
        }
        Ok(Self::new(username, username, &password))
    }
}

/// Read a secret file, refusing insecure permissions on Unix.
pub fn read_secret_file(path: &Path) -> Result<String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)
            .map_err(|error| BastionError::Bootstrap(format!("cannot stat secret file {}: {error}", path.display())))?
            .permissions()
            .mode();
        // Refuse — do not merely warn — when group or others can access it.
        if mode & 0o077 != 0 {
            return Err(BastionError::InsecureSecretFile(format!(
                "{} has mode {:o}; expected at most 0600",
                path.display(),
                mode & 0o777
            )));
        }
    }
    let content = std::fs::read_to_string(path)
        .map_err(|error| BastionError::Bootstrap(format!("cannot read secret file {}: {error}", path.display())))?;
    if content.len() > 16 * 1024 {
        return Err(BastionError::Bootstrap("secret file too large".into()));
    }
    let password = content.lines().next().unwrap_or("").trim_end_matches(&['\r', '\n'][..]).to_string();
    if password.is_empty() {
        return Err(BastionError::Bootstrap("secret file is empty".into()));
    }
    Ok(password)
}

pub struct AdminBootstrap {
    store: Arc<SqliteStore>,
    passwords: PasswordService,
    policy: BootstrapPolicy,
}

impl AdminBootstrap {
    pub fn new(store: Arc<SqliteStore>, passwords: PasswordService, policy: BootstrapPolicy) -> Self {
        Self { store, passwords, policy }
    }

    fn validate_credentials(&self, creds: &BootstrapCredentials) -> Result<()> {
        if creds.username.trim().is_empty() {
            return Err(BastionError::Bootstrap("admin username is empty".into()));
        }
        // No default credentials, ever.
        for forbidden in ["admin", "administrator", "root", "bastion"] {
            if creds.username.trim().eq_ignore_ascii_case(forbidden) && creds.password == forbidden {
                return Err(BastionError::WeakPassword("default credential pair is forbidden".into()));
            }
        }
        if creds.password.eq_ignore_ascii_case(creds.username.trim()) {
            return Err(BastionError::WeakPassword("password must not equal the username".into()));
        }
        self.passwords.check_policy(&creds.password)
    }

    /// One-time initial bootstrap. Creates the user, the admin role and the
    /// membership — and nothing else. In particular: **no database operation
    /// permissions are granted here**.
    pub async fn bootstrap(&self, creds: &BootstrapCredentials) -> Result<Uuid> {
        self.validate_credentials(creds)?;
        // Hash BEFORE entering the transaction: Argon2 must never run while
        // the SQLite mutex is held.
        let password_hash = self.passwords.hash(&creds.password).await?;
        let username = creds.username.trim().to_string();
        let display_name = creds.display_name.trim().to_string();
        let role_name = self.policy.admin_role_name.clone();
        let role_description = self.policy.admin_role_description.clone();
        let now = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

        self.store
            .in_transaction(move |tx| {
                let already: bool =
                    tx.query_row("SELECT EXISTS(SELECT 1 FROM bootstrap_state WHERE id = 1)", [], |row| row.get(0))?;
                if already {
                    return Err(BastionError::AlreadyBootstrapped);
                }
                // Defense in depth: an enabled admin-role user also blocks.
                let admins: i64 = tx.query_row(
                    "SELECT COUNT(*) FROM users u
                      JOIN user_roles ur ON ur.user_id = u.id
                      JOIN roles r ON r.id = ur.role_id
                     WHERE r.name = ?1 AND u.enabled = 1",
                    [&role_name],
                    |row| row.get(0),
                )?;
                if admins > 0 {
                    return Err(BastionError::AlreadyBootstrapped);
                }

                let user_id = Uuid::new_v4().to_string();
                tx.execute(
                    "INSERT INTO users (id, username, display_name, password_hash, enabled, created_at, updated_at)
                     VALUES (?1, ?2, ?3, ?4, 1, ?5, ?5)",
                    rusqlite::params![user_id, username, display_name, password_hash, now],
                )?;

                let role_id: Option<String> =
                    tx.query_row("SELECT id FROM roles WHERE name = ?1", [&role_name], |row| row.get(0)).optional()?;
                let role_id = match role_id {
                    Some(id) => id,
                    None => {
                        let role_id = Uuid::new_v4().to_string();
                        tx.execute(
                            "INSERT INTO roles (id, name, description, system_role, created_at)
                             VALUES (?1, ?2, ?3, 1, ?4)",
                            rusqlite::params![role_id, role_name, role_description, now],
                        )?;
                        role_id
                    }
                };

                tx.execute(
                    "INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES (?1, ?2)",
                    rusqlite::params![user_id, role_id],
                )?;
                tx.execute(
                    "INSERT INTO bootstrap_state (id, initialized_at, initialized_by)
                     VALUES (1, ?1, ?2)",
                    rusqlite::params![now, username],
                )?;
                Ok(Uuid::parse_str(&user_id).expect("fresh UUID"))
            })
            .await
    }

    /// Controlled recovery path: provisions a new admin **only** when the
    /// system was initialized before (marker present) but no enabled admin
    /// user remains. Requires the explicit confirmation string
    /// `"RECOVER-ADMIN"` plus secret-channel credentials.
    pub async fn recover_admin(&self, creds: &BootstrapCredentials, confirm: &str) -> Result<Uuid> {
        if confirm != "RECOVER-ADMIN" {
            return Err(BastionError::Bootstrap("recovery requires explicit confirmation".into()));
        }
        self.validate_credentials(creds)?;
        let password_hash = self.passwords.hash(&creds.password).await?;
        let username = creds.username.trim().to_string();
        let display_name = creds.display_name.trim().to_string();
        let role_name = self.policy.admin_role_name.clone();
        let now = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

        self.store
            .in_transaction(move |tx| {
                let initialized: bool =
                    tx.query_row("SELECT EXISTS(SELECT 1 FROM bootstrap_state WHERE id = 1)", [], |row| row.get(0))?;
                if !initialized {
                    return Err(BastionError::Bootstrap(
                        "system was never bootstrapped; use bootstrap() instead".into(),
                    ));
                }
                let admins: i64 = tx.query_row(
                    "SELECT COUNT(*) FROM users u
                      JOIN user_roles ur ON ur.user_id = u.id
                      JOIN roles r ON r.id = ur.role_id
                     WHERE r.name = ?1 AND u.enabled = 1",
                    [&role_name],
                    |row| row.get(0),
                )?;
                if admins > 0 {
                    return Err(BastionError::Bootstrap("an enabled admin already exists; recovery refused".into()));
                }
                let user_id = Uuid::new_v4().to_string();
                tx.execute(
                    "INSERT INTO users (id, username, display_name, password_hash, enabled, created_at, updated_at)
                     VALUES (?1, ?2, ?3, ?4, 1, ?5, ?5)",
                    rusqlite::params![user_id, username, display_name, password_hash, now],
                )?;
                let role_id: String =
                    tx.query_row("SELECT id FROM roles WHERE name = ?1", [&role_name], |row| row.get(0))?;
                tx.execute(
                    "INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES (?1, ?2)",
                    rusqlite::params![user_id, role_id],
                )?;
                Ok(Uuid::parse_str(&user_id).expect("fresh UUID"))
            })
            .await
    }
}

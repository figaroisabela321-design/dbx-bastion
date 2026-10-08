//! Persistent sessions.
//!
//! Security properties:
//!
//! - Session tokens carry 256 bits of entropy from a CSPRNG (`OsRng`) and are
//!   returned to the caller exactly once, at creation. The database stores
//!   only `SHA256(token)` (hex); the raw token never touches the disk, and
//!   tests assert its absence.
//! - Every validation re-reads the user row (enabled flag) and the role
//!   list from the database, so disabling a user or changing roles takes
//!   effect on the next request. Roles are never trusted from client input.
//! - Idle timeout uses an explicit boundary (see [`SessionConfig`]).
//! - Time is abstracted behind [`Clock`] so tests use [`ManualClock`]
//!   instead of sleeping.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use rand_core::{OsRng, RngCore};
use rusqlite::OptionalExtension;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::asset::UserRepository;
use crate::auth::{AuthenticatedPrincipal, Principal};
use crate::error::{BastionError, Result};
use crate::storage::SqliteStore;

/// Trusted records produced by session validation, before being wrapped
/// in an identity type ([`Principal`] or [`AuthenticatedPrincipal`]).
struct ValidatedSession {
    user_id: Uuid,
    username: String,
    display_name: String,
    session_id: Uuid,
    source_ip: Option<String>,
}

/// Time source. Production uses [`SystemClock`]; tests use [`ManualClock`].
pub trait Clock: Send + Sync + std::fmt::Debug {
    fn now(&self) -> DateTime<Utc>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

/// Controllable clock for tests. No sleeping required.
#[derive(Debug)]
pub struct ManualClock {
    now: Mutex<DateTime<Utc>>,
}

impl ManualClock {
    pub fn new(now: DateTime<Utc>) -> Self {
        Self { now: Mutex::new(now) }
    }

    pub fn set(&self, now: DateTime<Utc>) {
        *self.now.lock().unwrap() = now;
    }

    pub fn advance(&self, delta: chrono::Duration) {
        let mut guard = self.now.lock().unwrap();
        *guard += delta;
    }
}

impl Clock for ManualClock {
    fn now(&self) -> DateTime<Utc> {
        *self.now.lock().unwrap()
    }
}

#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Absolute session lifetime from creation.
    pub ttl: Duration,
    /// Maximum allowed inactivity. See the boundary note below.
    pub idle_timeout: Duration,
    /// Maximum concurrently active sessions per user; oldest is evicted.
    pub max_concurrent_sessions: usize,
    /// Minimum interval between `last_active_at` writes (write throttle).
    pub touch_throttle: Duration,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            ttl: Duration::from_secs(12 * 3600),
            idle_timeout: Duration::from_secs(30 * 60),
            max_concurrent_sessions: 5,
            touch_throttle: Duration::from_secs(60),
        }
    }
}

impl SessionConfig {
    /// Idle-timeout boundary contract:
    ///
    /// `last_active_at` is written at most every `touch_throttle`, so the
    /// stored value can lag real activity by up to `touch_throttle`. A
    /// session is therefore rejected when `now - stored_last_active >
    /// idle_timeout`, which means the *effective* minimum inactivity
    /// guarantee is `idle_timeout - touch_throttle`. An active user (real
    /// idle < `idle_timeout - touch_throttle`) can never be kicked by the
    /// throttle. This constructor enforces `touch_throttle < idle_timeout`
    /// so the boundary stays meaningful.
    pub fn validate(&self) -> Result<()> {
        if self.ttl.is_zero() {
            return Err(BastionError::InvalidData("session ttl must be positive".into()));
        }
        if self.idle_timeout.is_zero() {
            return Err(BastionError::InvalidData("session idle_timeout must be positive".into()));
        }
        if self.max_concurrent_sessions == 0 {
            return Err(BastionError::InvalidData("max_concurrent_sessions must be >= 1".into()));
        }
        if self.touch_throttle >= self.idle_timeout {
            return Err(BastionError::InvalidData("touch_throttle must be strictly less than idle_timeout".into()));
        }
        Ok(())
    }
}

/// Parameters for creating a session row (no raw token inside).
pub struct NewSession {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    pub source_ip: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_active_at: DateTime<Utc>,
}

/// A session row as stored.
#[derive(Debug, Clone)]
pub struct SessionRecord {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    pub source_ip: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_active_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

/// Single-operation session persistence. Creation with concurrency-limit
/// eviction is intentionally *not* here: it needs a transaction and lives
/// in [`SessionService::create_session`].
#[async_trait]
pub trait SessionRepository: Send + Sync {
    async fn find_session_by_token_hash(&self, token_hash: &str) -> Result<Option<SessionRecord>>;
    async fn touch_session(&self, session_id: Uuid, at: DateTime<Utc>) -> Result<()>;
    /// Revoke one session. Returns `true` if it was newly revoked.
    async fn revoke_session(&self, session_id: Uuid) -> Result<bool>;
    /// Revoke all sessions of a user. Returns the number newly revoked.
    async fn revoke_all_user_sessions(&self, user_id: Uuid) -> Result<u64>;
    /// Delete expired sessions. Returns the number removed.
    async fn purge_expired_sessions(&self, now: DateTime<Utc>) -> Result<u64>;
}

pub struct SessionService {
    store: Arc<SqliteStore>,
    config: SessionConfig,
    clock: Arc<dyn Clock>,
}

impl SessionService {
    pub fn new(store: Arc<SqliteStore>, config: SessionConfig, clock: Arc<dyn Clock>) -> Result<Self> {
        config.validate()?;
        Ok(Self { store, config, clock })
    }

    pub fn with_system_clock(store: Arc<SqliteStore>, config: SessionConfig) -> Result<Self> {
        Self::new(store, config, Arc::new(SystemClock))
    }

    pub fn config(&self) -> &SessionConfig {
        &self.config
    }

    /// Create a session and return the stored record plus the **raw token**
    /// (shown to the caller exactly once; never persisted).
    ///
    /// `verified_password_hash` is the hash the caller verified the password
    /// against. Inside the same transaction that inserts the session, the
    /// current hash and the enabled flag are re-read: if the password
    /// changed or the user was disabled after verification, creation is
    /// aborted with [`BastionError::AuthenticationFailed`]. This closes the
    /// verify-then-create race — a stale credential can never mint a live
    /// session.
    ///
    /// The concurrency-limit check and oldest-session eviction also run
    /// inside the same transaction.
    pub async fn create_session(
        &self,
        user_id: Uuid,
        verified_password_hash: &str,
        source_ip: Option<String>,
        user_agent: Option<String>,
    ) -> Result<(SessionRecord, String)> {
        let now = self.clock.now();
        let raw_token = generate_token();
        let verified_password_hash = verified_password_hash.to_string();
        let new_session = NewSession {
            id: Uuid::new_v4(),
            user_id,
            token_hash: token_hash(&raw_token),
            source_ip,
            user_agent,
            created_at: now,
            expires_at: now + self.config.ttl,
            last_active_at: now,
        };
        let max_sessions = self.config.max_concurrent_sessions as i64;
        let now_text = to_text(now);

        let record = self
            .store
            .in_transaction(move |tx| {
                // Re-validate inside the transaction: the credential verified
                // before this call may have been superseded (password change)
                // or the account disabled concurrently.
                let current: Option<(String, i64)> = tx
                    .query_row(
                        "SELECT password_hash, enabled FROM users WHERE id = ?1",
                        rusqlite::params![new_session.user_id.to_string()],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .optional()?;
                let Some((current_hash, enabled)) = current else {
                    return Err(BastionError::AuthenticationFailed);
                };
                if enabled == 0 {
                    return Err(BastionError::AuthenticationFailed);
                }
                if current_hash != verified_password_hash {
                    return Err(BastionError::AuthenticationFailed);
                }

                // Evict oldest active sessions while at/over the limit.
                loop {
                    let active: i64 = tx.query_row(
                        "SELECT COUNT(*) FROM sessions
                          WHERE user_id = ?1
                            AND revoked_at IS NULL
                            AND expires_at > ?2",
                        rusqlite::params![new_session.user_id.to_string(), now_text],
                        |row| row.get(0),
                    )?;
                    if active < max_sessions {
                        break;
                    }
                    let oldest: Option<String> = tx
                        .query_row(
                            "SELECT id FROM sessions
                              WHERE user_id = ?1
                                AND revoked_at IS NULL
                                AND expires_at > ?2
                              ORDER BY created_at ASC
                              LIMIT 1",
                            rusqlite::params![new_session.user_id.to_string(), now_text],
                            |row| row.get(0),
                        )
                        .optional()?;
                    let Some(oldest) = oldest else { break };
                    tx.execute(
                        "UPDATE sessions SET revoked_at = ?1 WHERE id = ?2",
                        rusqlite::params![now_text, oldest],
                    )?;
                }

                tx.execute(
                    // NOTE: the 0001 column is named `login_ip` (immutable);
                    // it maps to the domain field `source_ip`.
                    "INSERT INTO sessions
                        (id, user_id, token_hash, login_ip, user_agent,
                         created_at, expires_at, last_active_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    rusqlite::params![
                        new_session.id.to_string(),
                        new_session.user_id.to_string(),
                        new_session.token_hash,
                        new_session.source_ip,
                        new_session.user_agent,
                        to_text(new_session.created_at),
                        to_text(new_session.expires_at),
                        to_text(new_session.last_active_at),
                    ],
                )?;

                Ok(SessionRecord {
                    id: new_session.id,
                    user_id: new_session.user_id,
                    token_hash: new_session.token_hash.clone(),
                    source_ip: new_session.source_ip.clone(),
                    user_agent: new_session.user_agent.clone(),
                    created_at: new_session.created_at,
                    expires_at: new_session.expires_at,
                    last_active_at: Some(new_session.last_active_at),
                    revoked_at: None,
                })
            })
            .await?;
        Ok((record, raw_token))
    }

    /// Validate a raw token and rebuild a trusted [`Principal`].
    ///
    /// Fail-closed: unknown token, revoked, absolute expiry, idle timeout,
    /// missing/disabled user all yield [`BastionError::InvalidSession`]
    /// without distinguishing the cause. Roles are re-read from the
    /// database on every call.
    ///
    /// Prefer [`Self::authenticate`] for new code: it returns the
    /// unforgeable [`AuthenticatedPrincipal`] instead of the forgeable
    /// [`Principal`] snapshot.
    pub async fn validate_token(&self, raw_token: &str) -> Result<Principal> {
        let validated = self.validate(raw_token).await?;
        let roles = self.store.user_role_names(validated.user_id).await?;
        Ok(Principal {
            user_id: validated.user_id,
            username: validated.username,
            display_name: validated.display_name,
            session_id: validated.session_id,
            roles,
            source_ip: validated.source_ip,
        })
    }

    /// Authenticate a raw token and return the unforgeable
    /// [`AuthenticatedPrincipal`].
    ///
    /// Runs the exact same validation as [`Self::validate_token`]; the
    /// difference is the return type, which cannot be constructed or
    /// deserialized outside this module.
    pub async fn authenticate(&self, raw_token: &str) -> Result<AuthenticatedPrincipal> {
        let validated = self.validate(raw_token).await?;
        Ok(AuthenticatedPrincipal::new(validated.user_id, validated.username, validated.session_id))
    }

    /// Shared validation core: token -> live session -> existing enabled
    /// user. Returns the trusted records; callers wrap them in the
    /// appropriate identity type.
    async fn validate(&self, raw_token: &str) -> Result<ValidatedSession> {
        let now = self.clock.now();
        let hash = token_hash(raw_token);

        let session = self.store.find_session_by_token_hash(&hash).await?.ok_or(BastionError::InvalidSession)?;
        if session.revoked_at.is_some() {
            return Err(BastionError::InvalidSession);
        }
        if session.expires_at <= now {
            return Err(BastionError::InvalidSession);
        }

        // Idle check against the stored (possibly throttled) timestamp.
        // NULL is treated as created_at for rows predating the column.
        let last_active = session.last_active_at.unwrap_or(session.created_at);
        let idle = now.signed_duration_since(last_active);
        let idle_timeout = chrono::Duration::from_std(self.config.idle_timeout)
            .map_err(|_| BastionError::InvalidData("idle_timeout out of range".into()))?;
        if idle > idle_timeout {
            return Err(BastionError::InvalidSession);
        }

        // The user must still exist and be enabled; roles are re-read so
        // admin changes take effect on the next request.
        let user = self.store.find_user_by_id(session.user_id).await?.ok_or(BastionError::InvalidSession)?;
        if !user.enabled {
            return Err(BastionError::InvalidSession);
        }

        // Throttled activity touch. The boundary documented on
        // SessionConfig::validate guarantees an active user is never kicked
        // by a skipped write.
        let touch_throttle = chrono::Duration::from_std(self.config.touch_throttle)
            .map_err(|_| BastionError::InvalidData("touch_throttle out of range".into()))?;
        if idle >= touch_throttle {
            self.store.touch_session(session.id, now).await?;
        }

        Ok(ValidatedSession {
            user_id: user.id,
            username: user.username,
            display_name: user.display_name,
            session_id: session.id,
            source_ip: session.source_ip,
        })
    }

    /// Revoke a single session. Returns `true` if it was newly revoked.
    pub async fn revoke_session(&self, session_id: Uuid) -> Result<bool> {
        self.store.revoke_session(session_id).await
    }

    /// Revoke all sessions of a user. Returns the number newly revoked.
    pub async fn revoke_all_user_sessions(&self, user_id: Uuid) -> Result<u64> {
        self.store.revoke_all_user_sessions(user_id).await
    }

    /// Delete expired sessions. Returns the number removed.
    pub async fn purge_expired(&self) -> Result<u64> {
        let now = self.clock.now();
        self.store.purge_expired_sessions(now).await
    }
}

/// 256-bit CSPRNG token, hex-encoded for transport.
fn generate_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    hex_encode(&bytes)
}

/// What is actually stored: hex(SHA256(raw token)).
fn token_hash(raw_token: &str) -> String {
    hex_encode(Sha256::digest(raw_token.as_bytes()).as_slice())
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

pub(crate) fn to_text(dt: DateTime<Utc>) -> String {
    dt.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

pub(crate) fn parse_text(value: &str) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|error| BastionError::InvalidData(format!("bad timestamp: {error}")))
}

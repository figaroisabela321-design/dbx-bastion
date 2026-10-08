//! Multi-user authentication.
//!
//! Login pipeline (all inside [`AuthService`]):
//!
//! ```text
//! username/password (+ trusted source_ip)
//!   -> rate-limit check (user+IP, IP)
//!   -> user lookup (COLLATE NOCASE)
//!   -> Argon2id verify, or timing-equalized dummy verify for unknown users
//!   -> enabled check
//!   -> session create (256-bit token, SHA256 stored)
//!   -> Principal built from trusted DB records
//! ```
//!
//! Identity never comes from client input: `user_id`, `username` and `roles`
//! in a [`Principal`] are always read from server-side persistent records.
//! Roles are re-read on every session validation so admin changes apply to
//! the next request.
//!
//! Submodules:
//!
//! - [`password`] — Argon2id hashing/verification.
//! - [`session`] — persistent sessions.
//! - [`rate_limit`] — login throttling.
//! - [`bootstrap`] — one-time admin initialization + controlled recovery.
//! - [`http`] — session-cookie contract for the future web adapter.

pub mod bootstrap;
pub mod http;
pub mod password;
pub mod rate_limit;
pub mod session;

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::asset::UserRepository;
use crate::error::{BastionError, Result};
use crate::storage::SqliteStore;

pub use bootstrap::{read_secret_file, AdminBootstrap, BootstrapCredentials, BootstrapPolicy};
pub use http::{SameSite, SessionCookiePolicy};
pub use password::{PasswordConfig, PasswordService};
pub use rate_limit::{LoginRateLimiter, RateLimitConfig, RateLimitedInfo};
pub use session::{
    Clock, ManualClock, NewSession, SessionConfig, SessionRecord, SessionRepository, SessionService, SystemClock,
};

/// The authenticated caller of a bastion operation.
///
/// Always constructed by [`AuthService`]/[`SessionService`] from trusted
/// persistent records — never from client-supplied values. `roles` is a
/// point-in-time snapshot refreshed on every session validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Principal {
    pub user_id: Uuid,
    pub username: String,
    pub display_name: String,
    pub session_id: Uuid,
    pub roles: Vec<String>,
    /// Source IP observed by the server for the session's creation.
    pub source_ip: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct AuthConfig {
    pub passwords: PasswordConfig,
    pub sessions: SessionConfig,
    pub rate_limit: RateLimitConfig,
}

/// Login input. `source_ip` **must** come from trusted server context (TCP
/// peer address, or a validated trusted-proxy header) — never from a raw
/// client-supplied `X-Forwarded-For`.
pub struct LoginRequest {
    pub username: String,
    pub password: String,
    pub source_ip: Option<String>,
    pub user_agent: Option<String>,
}

/// Login output. `token` is the raw session token, revealed exactly once.
pub struct LoginResult {
    pub token: String,
    pub principal: Principal,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

pub struct AuthService {
    store: Arc<SqliteStore>,
    passwords: PasswordService,
    sessions: SessionService,
    rate_limiter: LoginRateLimiter,
}

impl AuthService {
    pub fn new(store: Arc<SqliteStore>, config: AuthConfig) -> Result<Self> {
        let passwords = PasswordService::new(config.passwords)?;
        let sessions = SessionService::with_system_clock(store.clone(), config.sessions)?;
        let rate_limiter = LoginRateLimiter::new(config.rate_limit)?;
        Ok(Self { store, passwords, sessions, rate_limiter })
    }

    pub fn sessions(&self) -> &SessionService {
        &self.sessions
    }

    pub fn passwords(&self) -> &PasswordService {
        &self.passwords
    }

    /// Shared rate limiter (the future web adapter must use this instance).
    pub fn rate_limiter(&self) -> &LoginRateLimiter {
        &self.rate_limiter
    }

    fn client_ip(request: &LoginRequest) -> &str {
        request.source_ip.as_deref().unwrap_or("unknown")
    }

    /// Authenticate with username + password.
    ///
    /// Unknown user, wrong password and disabled account all produce the
    /// same [`BastionError::AuthenticationFailed`]. An unknown user still
    /// pays one full Argon2id verification ([`PasswordService::dummy_verify`])
    /// to avoid an obvious enumeration timing gap.
    ///
    /// Password computation never runs while the SQLite mutex is held: the
    /// user row is fetched first, the guard is dropped, and only then does
    /// Argon2 run in its dedicated blocking task.
    pub async fn login(&self, request: &LoginRequest) -> Result<LoginResult> {
        let ip = Self::client_ip(request);
        self.rate_limiter.check(&request.username, ip).map_err(|_| BastionError::RateLimited)?;

        // Fetch first, verify after: no MutexGuard is held across Argon2.
        let user = self.store.find_user_by_username(&request.username).await?;

        let Some(user) = user else {
            self.passwords.dummy_verify().await?;
            self.rate_limiter.record_failure(&request.username, ip);
            return Err(BastionError::AuthenticationFailed);
        };

        let ok = self.passwords.verify(&request.password, &user.password_hash).await?;
        if !ok || !user.enabled {
            // Same error for wrong password and disabled account.
            self.rate_limiter.record_failure(&request.username, ip);
            return Err(BastionError::AuthenticationFailed);
        }

        self.rate_limiter.record_success(&request.username, ip);

        let (session, token) =
            self.sessions.create_session(user.id, request.source_ip.clone(), request.user_agent.clone()).await?;
        let roles = self.store.user_role_names(user.id).await?;

        Ok(LoginResult {
            token,
            expires_at: session.expires_at,
            principal: Principal {
                user_id: user.id,
                username: user.username,
                display_name: user.display_name,
                session_id: session.id,
                roles,
                source_ip: session.source_ip,
            },
        })
    }

    /// Validate a raw session token (delegates to the session service).
    pub async fn validate_token(&self, raw_token: &str) -> Result<Principal> {
        self.sessions.validate_token(raw_token).await
    }

    /// Log out: revoke one session.
    pub async fn logout(&self, session_id: Uuid) -> Result<()> {
        self.sessions.revoke_session(session_id).await?;
        Ok(())
    }

    /// Change a user's password. The old password is verified first; the
    /// hash update and the revocation of all existing sessions happen in a
    /// single transaction so no old session can survive the change.
    pub async fn change_password(&self, user_id: Uuid, old_password: &str, new_password: &str) -> Result<()> {
        let user = self.store.find_user_by_id(user_id).await?.ok_or(BastionError::AuthenticationFailed)?;
        let ok = self.passwords.verify(old_password, &user.password_hash).await?;
        if !ok {
            return Err(BastionError::AuthenticationFailed);
        }
        // Policy is enforced inside hash(); hashing happens before the
        // transaction so no MutexGuard is held across Argon2.
        let new_hash = self.passwords.hash(new_password).await?;
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

        self.store
            .in_transaction(move |tx| {
                tx.execute(
                    "UPDATE users SET password_hash = ?1, updated_at = ?2 WHERE id = ?3",
                    rusqlite::params![new_hash, now, user_id.to_string()],
                )?;
                tx.execute(
                    "UPDATE sessions SET revoked_at = ?1
                      WHERE user_id = ?2 AND revoked_at IS NULL",
                    rusqlite::params![now, user_id.to_string()],
                )?;
                Ok(())
            })
            .await
    }
}

//! Password hashing with Argon2id.
//!
//! Security properties (TASK-002 revisions, all enforced here):
//!
//! - Parameters default to **m=19456 KiB, t=2, p=1**. This matches one of
//!   OWASP's *minimum* recommendations for Argon2id. It is deliberately
//!   documented as such: it is NOT the RFC 9106 recommended (first-choice)
//!   combination. Parameters are configurable via [`PasswordConfig`].
//! - Every password gets an independent random salt ([`SaltString`]); hashes
//!   are stored in PHC string format. Only the hash is persisted, never the
//!   plaintext or a reversibly-encrypted password.
//! - All hashing and verification run inside `tokio::task::spawn_blocking`
//!   and are additionally gated by a semaphore, so Argon2 computation can
//!   neither stall the async executor nor exhaust the machine.
//! - This module never touches storage. Callers must finish all database
//!   work *before* calling into it, so a SQLite `MutexGuard` is never held
//!   across password computation.
//! - For the unknown-user path, [`PasswordService::dummy_verify`] performs a
//!   timing-equalized verification against a **pre-generated** dummy hash.
//!   The dummy hash is created once at service construction and never
//!   regenerated per failed login.

use std::sync::Arc;

use argon2::password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use tokio::sync::Semaphore;

use crate::error::{BastionError, Result};

#[derive(Debug, Clone)]
pub struct PasswordConfig {
    /// Memory cost in KiB. Default 19456 (19 MiB).
    pub memory_kib: u32,
    /// Time cost (iterations). Default 2.
    pub iterations: u32,
    /// Parallelism (lanes). Default 1.
    pub parallelism: u32,
    /// Minimum accepted password length. Default 12.
    pub min_password_len: usize,
    /// Upper bound on concurrent Argon2 computations. Default 4.
    pub max_concurrent_hashes: usize,
}

impl Default for PasswordConfig {
    fn default() -> Self {
        Self { memory_kib: 19456, iterations: 2, parallelism: 1, min_password_len: 12, max_concurrent_hashes: 4 }
    }
}

pub struct PasswordService {
    config: PasswordConfig,
    semaphore: Arc<Semaphore>,
    /// Pre-generated dummy hash for the unknown-user timing path.
    /// Created once here; never regenerated per login attempt.
    dummy_hash: String,
}

impl Clone for PasswordService {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            semaphore: Arc::clone(&self.semaphore),
            dummy_hash: self.dummy_hash.clone(),
        }
    }
}

impl PasswordService {
    /// Build the service. Performs exactly one Argon2id computation to
    /// prepare the dummy hash; call once at startup (it is synchronous and
    /// takes a few hundred milliseconds by design).
    pub fn new(config: PasswordConfig) -> Result<Self> {
        if config.max_concurrent_hashes == 0 {
            return Err(BastionError::InvalidData("max_concurrent_hashes must be >= 1".into()));
        }
        let service = Self {
            semaphore: Arc::new(Semaphore::new(config.max_concurrent_hashes)),
            dummy_hash: String::new(),
            config: config.clone(),
        };
        // Pre-generate the dummy hash with the configured parameters.
        let dummy_hash = hash_blocking(service.argon2_params(), b"dummy-password-for-timing-equality")?;
        Ok(Self { dummy_hash, ..service })
    }

    pub fn config(&self) -> &PasswordConfig {
        &self.config
    }

    fn argon2_params(&self) -> (u32, u32, u32) {
        (self.config.memory_kib, self.config.iterations, self.config.parallelism)
    }

    /// Enforce the password policy (currently: minimum length).
    pub fn check_policy(&self, password: &str) -> Result<()> {
        if password.len() < self.config.min_password_len {
            return Err(BastionError::WeakPassword(format!(
                "password must be at least {} characters",
                self.config.min_password_len
            )));
        }
        Ok(())
    }

    /// Acquire a compute permit without blocking the executor.
    async fn permit(&self) -> Result<tokio::sync::OwnedSemaphorePermit> {
        self.semaphore
            .clone()
            .acquire_owned()
            .await
            .map_err(|error| BastionError::PasswordHash(format!("semaphore closed: {error}")))
    }

    /// Hash a password for storage. Never blocks the async executor.
    pub async fn hash(&self, password: &str) -> Result<String> {
        self.check_policy(password)?;
        let password = password.as_bytes().to_vec();
        let params = self.argon2_params();
        let permit = self.permit().await?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit; // hold the compute permit for the duration
            hash_blocking(params, &password)
        })
        .await
        .map_err(|error| BastionError::PasswordHash(format!("hash task failed: {error}")))?
    }

    /// Verify a password against a stored PHC hash. Returns `Ok(false)` on
    /// mismatch; malformed stored hashes surface as errors (data corruption
    /// must not be silent).
    pub async fn verify(&self, password: &str, expected_hash: &str) -> Result<bool> {
        let password = password.as_bytes().to_vec();
        let expected_hash = expected_hash.to_string();
        let params = self.argon2_params();
        let permit = self.permit().await?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            verify_blocking(params, &password, &expected_hash)
        })
        .await
        .map_err(|error| BastionError::PasswordHash(format!("verify task failed: {error}")))?
    }

    /// Timing-equalized verification for the unknown-user login path.
    /// Always performs one full Argon2id verification against the
    /// pre-generated dummy hash, then discards the result. The dummy hash
    /// is created once at construction and never regenerated here.
    pub async fn dummy_verify(&self) -> Result<()> {
        let dummy_hash = self.dummy_hash.clone();
        let params = self.argon2_params();
        let permit = self.permit().await?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            // Intentionally discard the result: the cost is the point.
            let _ = verify_blocking(params, b"invalid-password", &dummy_hash);
            Ok(())
        })
        .await
        .map_err(|error| BastionError::PasswordHash(format!("dummy verify task failed: {error}")))?
    }
}

/// Synchronous Argon2id hash. `params` are owned so this can move into a
/// `'static` blocking closure; never call it on an async executor thread.
fn hash_blocking(params: (u32, u32, u32), password: &[u8]) -> Result<String> {
    let argon2 = argon2_with_params(params)?;
    let salt = SaltString::generate(&mut OsRng);
    argon2
        .hash_password(password, &salt)
        .map(|hash| hash.to_string())
        .map_err(|error| BastionError::PasswordHash(error.to_string()))
}

/// Synchronous Argon2id verify. Same threading contract as [`hash_blocking`].
fn verify_blocking(params: (u32, u32, u32), password: &[u8], expected_hash: &str) -> Result<bool> {
    let argon2 = argon2_with_params(params)?;
    let parsed = PasswordHash::new(expected_hash).map_err(|error| BastionError::PasswordHash(error.to_string()))?;
    Ok(argon2.verify_password(password, &parsed).is_ok())
}

fn argon2_with_params(params: (u32, u32, u32)) -> Result<Argon2<'static>> {
    let params = Params::new(params.0, params.1, params.2, None)
        .map_err(|error| BastionError::PasswordHash(error.to_string()))?;
    // `Argon2` is covariant over its lifetime and carries no secret here,
    // so the value can be used as `'static`.
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

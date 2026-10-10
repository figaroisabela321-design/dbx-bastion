//! Login rate limiting.
//!
//! Two dimensions are tracked independently:
//!
//! - `(normalized username, source IP)` — stops credential stuffing against
//!   one account without locking the account for everyone else;
//! - `(source IP)` — stops distributed password spraying from one source.
//!
//! Properties:
//!
//! - All lockouts are **bounded** (`cooldown`); no account — including the
//!   last admin — can ever be locked permanently.
//! - The map is capacity-bounded (`max_entries`) with expired-entry eviction,
//!   so an attacker cannot grow memory without bound.
//! - A successful login clears the per-user bucket.
//! - Concurrency-safe via a short-lived `Mutex`; no `.await` inside.
//!
//! **Trust boundary.** `source_ip` must be supplied by trusted *server*
//! context (the TCP peer address, or `X-Forwarded-For` only when an explicit
//! trusted-proxy allowlist is configured by the operator). Never trust a
//! client-supplied header directly — a spoofed IP would let an attacker
//! evade the limiter or, worse, get someone else's address locked.
//!
//! **Deployment note.** This limiter is in-process memory. A multi-instance
//! deployment must replace it with a shared store (e.g. Redis) or pin
//! sessions to instances; otherwise each instance enforces its own budget.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::error::{BastionError, Result};

#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Failed attempts allowed per (username, IP) within `window`.
    pub max_attempts: u32,
    /// Sliding window for counting attempts.
    pub window: Duration,
    /// Bounded lockout applied after `max_attempts` is reached.
    pub cooldown: Duration,
    /// Failed attempts allowed per source IP within `window`.
    pub max_attempts_per_ip: u32,
    /// Upper bound on tracked buckets.
    pub max_entries: usize,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_attempts: 5,
            window: Duration::from_secs(15 * 60),
            cooldown: Duration::from_secs(5 * 60),
            max_attempts_per_ip: 50,
            max_entries: 10_000,
        }
    }
}

/// Details returned when an attempt is rejected.
#[derive(Debug, Clone)]
pub struct RateLimitedInfo {
    pub retry_after: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Key {
    UserIp { user: String, ip: String },
    Ip(String),
}

#[derive(Debug, Clone)]
struct Entry {
    attempts: u32,
    window_start: Instant,
    locked_until: Option<Instant>,
}

pub struct LoginRateLimiter {
    config: RateLimitConfig,
    entries: Mutex<HashMap<Key, Entry>>,
}

impl LoginRateLimiter {
    pub fn new(config: RateLimitConfig) -> Result<Self> {
        if config.max_attempts == 0 || config.max_attempts_per_ip == 0 {
            return Err(BastionError::InvalidData("rate limit max_attempts must be >= 1".into()));
        }
        if config.window.is_zero() || config.cooldown.is_zero() {
            return Err(BastionError::InvalidData("rate limit window/cooldown must be positive".into()));
        }
        if config.max_entries == 0 {
            return Err(BastionError::InvalidData("rate limit max_entries must be >= 1".into()));
        }
        Ok(Self { config, entries: Mutex::new(HashMap::new()) })
    }

    pub fn config(&self) -> &RateLimitConfig {
        &self.config
    }

    /// Normalize a username for keying: trim + Unicode lowercase.
    /// Mirrors the login lookup, whose column is `COLLATE NOCASE`.
    pub fn normalize_username(username: &str) -> String {
        username.trim().to_lowercase()
    }

    /// Check whether an attempt is currently allowed on both dimensions.
    pub fn check(&self, username: &str, ip: &str) -> std::result::Result<(), RateLimitedInfo> {
        let user = Self::normalize_username(username);
        let now = Instant::now();
        let guard = self.entries.lock().unwrap();
        for key in [Key::UserIp { user: user.clone(), ip: ip.to_string() }, Key::Ip(ip.to_string())] {
            if let Some(entry) = guard.get(&key) {
                if let Some(until) = entry.locked_until {
                    if now < until {
                        return Err(RateLimitedInfo { retry_after: until - now });
                    }
                }
            }
        }
        Ok(())
    }

    /// Record a failed attempt on both dimensions; may start a bounded
    /// cooldown.
    pub fn record_failure(&self, username: &str, ip: &str) {
        let user = Self::normalize_username(username);
        let now = Instant::now();
        let mut guard = self.entries.lock().unwrap();
        self.record_failure_for(&mut guard, Key::UserIp { user, ip: ip.to_string() }, self.config.max_attempts, now);
        self.record_failure_for(&mut guard, Key::Ip(ip.to_string()), self.config.max_attempts_per_ip, now);
    }

    fn record_failure_for(&self, guard: &mut HashMap<Key, Entry>, key: Key, max: u32, now: Instant) {
        self.evict_if_needed(guard, now);
        let entry = guard.entry(key).or_insert(Entry { attempts: 0, window_start: now, locked_until: None });
        if now.duration_since(entry.window_start) >= self.config.window {
            entry.attempts = 1;
            entry.window_start = now;
            entry.locked_until = None;
        } else {
            entry.attempts += 1;
            if entry.attempts >= max {
                entry.locked_until = Some(now + self.config.cooldown);
            }
        }
    }

    /// Record a successful login: the per-user bucket is cleared so a
    /// legitimate user is never stuck behind old failures. The per-IP
    /// bucket is intentionally left alone (it tracks the source).
    pub fn record_success(&self, username: &str, ip: &str) {
        let user = Self::normalize_username(username);
        let mut guard = self.entries.lock().unwrap();
        guard.remove(&Key::UserIp { user, ip: ip.to_string() });
    }

    /// Number of tracked buckets (tests / monitoring).
    pub fn len(&self) -> usize {
        self.entries.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.lock().unwrap().is_empty()
    }

    /// Keep the map bounded: drop expired windows and elapsed lockouts
    /// first; if still full, drop the stalest window.
    fn evict_if_needed(&self, guard: &mut HashMap<Key, Entry>, now: Instant) {
        if guard.len() < self.config.max_entries {
            return;
        }
        guard.retain(|_, entry| {
            let window_active = now.duration_since(entry.window_start) < self.config.window;
            let locked = entry.locked_until.map(|until| now < until).unwrap_or(false);
            window_active || locked
        });
        if guard.len() >= self.config.max_entries {
            let oldest = guard.iter().min_by_key(|(_, entry)| entry.window_start).map(|(key, _)| key.clone());
            if let Some(oldest) = oldest {
                guard.remove(&oldest);
            }
        }
    }
}

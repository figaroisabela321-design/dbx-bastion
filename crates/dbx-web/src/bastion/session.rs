//! Bastion session extractor (TASK-005C-2).
//!
//! HTTP adapter between the bastion session cookie and
//! [`AuthenticatedPrincipal`]. Security properties:
//! - The session token comes **only** from the `__Host-bastion-session`
//!   cookie (`HttpOnly`, `Secure` by default, `SameSite=Lax`, `Path=/`,
//!   no `Domain`). It is never read from query params, headers, or
//!   request bodies, and never written to `localStorage`.
//! - The token is validated on **every request** via
//!   `AuthService::authenticate`, which re-checks revocation, expiry,
//!   idle timeout, and user-enabled state. A revoked session is
//!   rejected immediately — there is no caching of the principal.
//! - `user_id` / roles are never taken from browser input. The only
//!   `AuthenticatedPrincipal` constructor reachable here is the
//!   `pub(crate)` one inside `dbx-bastion`, called by `authenticate`.
//! - Write operations (`POST`/`PUT`/`PATCH`/`DELETE`) require CSRF
//!   protection: the `Origin` (or `Referer` fallback) must match the
//!   request `Host`. See [`check_csrf`].
//!
//! TLS boundary: bastion mode does not terminate TLS itself. Deploy
//! behind a TLS-terminating reverse proxy. `Secure` cookies are the
//! default; `DBX_BASTION_ALLOW_INSECURE_COOKIE=1` explicitly opts out
//! for non-TLS dev/test and logs a warning at startup. `X-Forwarded-*`
//! headers are never trusted for authentication decisions; the login
//! `source_ip` is the direct TCP peer.

use std::sync::Arc;

use axum::{
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Response},
};
use dbx_bastion::auth::{AuthenticatedPrincipal, SessionCookiePolicy};

use super::state::BastionState;

/// Authenticated bastion session, extracted per request.
pub struct BastionSession {
    pub principal: AuthenticatedPrincipal,
}

/// Cookie policy for this process, decided at startup.
#[derive(Debug, Clone)]
pub struct CookieConfig {
    pub policy: SessionCookiePolicy,
}

impl CookieConfig {
    pub fn from_env() -> Self {
        let allow_insecure = std::env::var("DBX_BASTION_ALLOW_INSECURE_COOKIE")
            .map(|v| matches!(v.trim().to_lowercase().as_str(), "1" | "true" | "yes" | "on"))
            .unwrap_or(false);
        let mut policy = SessionCookiePolicy::default();
        if allow_insecure {
            policy.secure = false;
            tracing::warn!(
                "DBX_BASTION_ALLOW_INSECURE_COOKIE=1: session cookie without Secure; \
                 only use for non-TLS dev/test, never in production"
            );
        }
        Self { policy }
    }

    pub fn cookie_name(&self) -> &'static str {
        self.policy.name
    }
}

/// Extract the raw session token from the `Cookie` header. Only the
/// exact `__Host-bastion-session` name is accepted.
fn token_from_cookie(parts: &Parts, cookie_name: &str) -> Option<String> {
    let header = parts.headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    for pair in header.split(';') {
        let pair = pair.trim();
        let (name, value) = pair.split_once('=')?;
        if name.trim() == cookie_name {
            let token = value.trim().trim_matches('"');
            if !token.is_empty() {
                return Some(token.to_string());
            }
        }
    }
    None
}

impl FromRequestParts<Arc<BastionState>> for BastionSession {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &Arc<BastionState>) -> Result<Self, Self::Rejection> {
        let token = token_from_cookie(parts, state.cookie_config.cookie_name())
            .ok_or_else(|| (StatusCode::UNAUTHORIZED, "missing or invalid bastion session").into_response())?;
        // Every request re-validates: revocation, expiry, idle timeout,
        // and user-enabled are re-checked inside `authenticate`.
        // Fail-closed: any error (including infrastructure errors)
        // becomes 401 — we never distinguish "bad token" from
        // "auth backend down" to the client.
        let principal = state
            .service
            .auth()
            .authenticate(&token)
            .await
            .map_err(|_| (StatusCode::UNAUTHORIZED, "missing or invalid bastion session").into_response())?;
        Ok(Self { principal })
    }
}

/// CSRF protection for state-changing requests.
///
/// Requires the `Origin` header (or `Referer` fallback) to match the
/// request `Host`. Safe methods (`GET`/`HEAD`/`OPTIONS`) are exempt.
/// Missing `Origin`/`Referer` on a write request is rejected — this is
/// stricter than the legacy behavior, intentionally.
pub fn check_csrf(parts: &Parts) -> Result<(), Response> {
    use axum::http::Method;
    match parts.method {
        Method::GET | Method::HEAD | Method::OPTIONS => return Ok(()),
        _ => {}
    }
    let host = parts.headers.get(axum::http::header::HOST).and_then(|v| v.to_str().ok()).unwrap_or("");
    // Prefer Origin; fall back to Referer.
    let origin = parts
        .headers
        .get(axum::http::header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .or_else(|| parts.headers.get(axum::http::header::REFERER).and_then(|v| v.to_str().ok()))
        .unwrap_or("");
    if origin.is_empty() {
        return Err((StatusCode::FORBIDDEN, "missing Origin/Referer on write request").into_response());
    }
    // Compare authority (host[:port]) of the origin URL with Host.
    let origin_authority = origin.split("://").nth(1).unwrap_or(origin).split('/').next().unwrap_or("");
    if origin_authority != host || host.is_empty() {
        return Err((StatusCode::FORBIDDEN, "Origin/Referer does not match Host").into_response());
    }
    Ok(())
}

/// Direct TCP peer IP for audit/login attribution. Never trusts
/// `X-Forwarded-For` — that header is only meaningful behind an
/// explicitly configured trusted proxy, which 005C-2 does not
/// configure.
pub fn peer_ip(parts: &Parts) -> Option<String> {
    parts.extensions.get::<std::net::SocketAddr>().map(|a| a.ip().to_string())
}

//! HTTP session-cookie contract for the future web adapter.
//!
//! This module defines **types and header builders only**. No HTTP route is
//! opened here; `dbx-web` integration (a later TASK) must honor this
//! contract when it wires login/logout routes.
//!
//! Mandatory rules for the future adapter:
//!
//! - Cookie name uses the `__Host-` prefix, which *requires* `Secure`,
//!   `Path=/` and the absence of `Domain` (enforced by browsers).
//! - `HttpOnly` always: the token must never be readable from JavaScript.
//! - `Secure` whenever served over HTTPS (which is every non-loopback
//!   deployment).
//! - `SameSite=Lax` at minimum; `Strict` where the product flow allows it.
//! - CSRF defense for cookie-authenticated mutations: validate
//!   `Origin`/`Referer` against the configured public base URL *in
//!   addition* to `SameSite` (defense in depth; `SameSite` alone is not a
//!   complete CSRF boundary).
//! - **Never persist the session token in `localStorage`** (or
//!   `sessionStorage`): it is XSS-exfiltratable by design. The `HttpOnly`
//!   cookie is the only client-side home for the token.
//! - Rotate (re-issue) the session token on privilege changes such as
//!   password change or role grant.

/// SameSite attribute for the session cookie.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SameSite {
    /// Strongest; breaks top-level navigational POST logins.
    Strict,
    /// Balanced default for an interactive web app.
    #[default]
    Lax,
    /// Only with `Secure`; not recommended for the session cookie.
    None,
}

impl SameSite {
    fn as_str(self) -> &'static str {
        match self {
            Self::Strict => "Strict",
            Self::Lax => "Lax",
            Self::None => "None",
        }
    }
}

/// Policy for the bastion session cookie.
///
/// Two modes:
/// - **Production** (default): `__Host-bastion-session` with `Secure`,
///   `HttpOnly`, `Path=/`, no `Domain`. The `__Host-` prefix mandates
///   `Secure` per the cookie spec — browsers reject `__Host-` cookies
///   without it.
/// - **Insecure dev** (explicit opt-in): `bastion-session-insecure`
///   (no `__Host-` prefix) without `Secure`. For non-HTTPS dev/test
///   only; never use in production. The different name makes it
///   impossible to confuse the two modes.
#[derive(Debug, Clone)]
pub struct SessionCookiePolicy {
    /// Full cookie name. Production: `__Host-bastion-session`.
    /// Insecure dev: `bastion-session-insecure` (no `__Host-` prefix).
    pub name: &'static str,
    pub same_site: SameSite,
    /// Set when the deployment serves HTTPS (required for `__Host-`).
    pub secure: bool,
    /// Lifetime hint for the browser; server-side expiry is authoritative.
    pub max_age_secs: u64,
}

impl Default for SessionCookiePolicy {
    fn default() -> Self {
        Self { name: "__Host-bastion-session", same_site: SameSite::Lax, secure: true, max_age_secs: 12 * 3600 }
    }
}

impl SessionCookiePolicy {
    /// Insecure development policy: non-HTTPS only. Uses a distinct
    /// cookie name WITHOUT the `__Host-` prefix, because browsers
    /// reject `__Host-` cookies that lack the `Secure` attribute.
    /// Never use in production.
    pub fn insecure_dev() -> Self {
        Self { name: "bastion-session-insecure", same_site: SameSite::Lax, secure: false, max_age_secs: 12 * 3600 }
    }

    /// Build the `Set-Cookie` header value carrying `raw_token`.
    /// `__Host-` prefix mandates `Secure`, `Path=/` and no `Domain`.
    pub fn set_cookie_value(&self, raw_token: &str) -> String {
        let mut value = format!("{}={}; Path=/; HttpOnly; SameSite={}", self.name, raw_token, self.same_site.as_str());
        if self.secure {
            value.push_str("; Secure");
        }
        if self.max_age_secs > 0 {
            value.push_str(&format!("; Max-Age={}", self.max_age_secs));
        }
        value
    }

    /// Build the `Set-Cookie` header value that clears the cookie.
    pub fn clear_cookie_value(&self) -> String {
        let mut value = format!("{}=; Path=/; HttpOnly; SameSite={}; Max-Age=0", self.name, self.same_site.as_str());
        if self.secure {
            value.push_str("; Secure");
        }
        value
    }
}

//! Default-deny firewall middleware (TASK-005C-1, second layer).
//!
//! The primary guarantee is registration-time: bastion mode never
//! registers old routes. This middleware is defense in depth — it
//! rejects anything not on the exact `(method, path)` whitelist with
//! 403 before it reaches the router.
//!
//! The whitelist is exact: no prefix matching, no glob. Path
//! normalization (percent-decoding, trailing-slash handling, base
//! path stripping) happens before comparison so encoded or suffixed
//! variants cannot bypass it.

use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};

/// Exact whitelist entries for bastion mode: `(method, path)` pairs as
/// the router sees them (after base-path stripping).
///
/// `{id}` is a path-parameter placeholder: it matches exactly one
/// segment, which must parse as a UUID. This is still exact matching —
/// not a loose prefix.
const ALLOWLIST: &[(&str, &str)] = &[
    ("GET", "/api/bastion/health"),
    ("GET", "/api/bastion/status"),
    ("POST", "/api/bastion/auth/login"),
    ("POST", "/api/bastion/auth/logout"),
    ("GET", "/api/bastion/auth/me"),
    ("GET", "/api/bastion/assets"),
    ("GET", "/api/bastion/assets/{id}"),
    ("POST", "/api/bastion/query/execute"),
    ("GET", "/api/bastion/audit/interruptions"),
    ("POST", "/api/bastion/audit/interruptions/{id}/triage"),
];

fn path_matches(pattern: &str, path: &str) -> bool {
    if !pattern.contains('{') {
        return pattern == path;
    }
    // Placeholder segments (`{id}`) match exactly one path segment
    // which must parse as a UUID. All other segments match exactly.
    let pattern_segs: Vec<&str> = pattern.split('/').collect();
    let path_segs: Vec<&str> = path.split('/').collect();
    if pattern_segs.len() != path_segs.len() {
        return false;
    }
    for (p, s) in pattern_segs.iter().zip(path_segs.iter()) {
        if *p == "{id}" {
            if s.is_empty() || uuid::Uuid::parse_str(s).is_err() {
                return false;
            }
        } else if p != s {
            return false;
        }
    }
    true
}

/// Validate and normalize `DBX_PUBLIC_BASE_PATH` for bastion mode.
///
/// Returns the normalized base path (`/` when unset/empty) or a
/// diagnosable startup configuration error (no panic). Rejects:
/// - values not starting with `/`,
/// - path traversal (`.` / `..` segments),
/// - empty segments (`//`),
/// - percent-encoded sequences (the value must already be normalized),
/// - control characters, whitespace, and `; , ? # % \`.
/// A single trailing slash is normalized away (`/dbx/` → `/dbx`).
pub fn validate_base_path(value: Option<&str>) -> Result<String, String> {
    let raw = value.unwrap_or("").trim();
    if raw.is_empty() || raw == "/" {
        return Ok("/".to_string());
    }
    if !raw.starts_with('/') {
        return Err(format!("invalid DBX_PUBLIC_BASE_PATH {raw:?}: must start with '/' or be empty"));
    }
    if raw
        .chars()
        .any(|ch| ch.is_ascii_control() || ch.is_ascii_whitespace() || matches!(ch, ';' | ',' | '?' | '#' | '%' | '\\'))
    {
        return Err(format!(
            "invalid DBX_PUBLIC_BASE_PATH {raw:?}: contains characters that are not allowed \
             in a URL path prefix"
        ));
    }
    for seg in raw.split('/').skip(1) {
        if seg.is_empty() {
            return Err(format!("invalid DBX_PUBLIC_BASE_PATH {raw:?}: empty path segment ('//')"));
        }
        if seg == "." || seg == ".." {
            return Err(format!("invalid DBX_PUBLIC_BASE_PATH {raw:?}: path traversal segment {seg:?} is not allowed"));
        }
    }
    let mut normalized = raw.to_string();
    while normalized.len() > 1 && normalized.ends_with('/') {
        normalized.pop();
    }
    Ok(normalized)
}

/// Normalize a request path for whitelist comparison:
/// - require the path to be under the configured public base path on
///   a segment boundary (no fuzzy prefix matching: `/dbx` does not
///   match `/dbxevil/...`),
/// - percent-decode,
/// - reject `..` segments after decoding (encoded traversal),
/// - drop a trailing slash (except for `/` itself).
///
/// Anything suspicious normalizes to `""`, which never matches the
/// whitelist (fail-closed).
fn normalize_path(raw: &str, base_path: &str) -> String {
    let mut path = raw;
    if base_path != "/" {
        // Strict segment-boundary match.
        let under_base = path == base_path || path.starts_with(&format!("{base_path}/"));
        if !under_base {
            // Not under the base path: cannot be a whitelisted route.
            return String::new();
        }
        path = &path[base_path.len()..];
        if path.is_empty() {
            path = "/";
        }
    }
    // Percent-decode (best effort; invalid sequences stay as-is and
    // will simply not match the whitelist).
    let decoded = percent_decode(path);
    // Encoded traversal (`%2e%2e`, `..%2f`, …) is rejected outright.
    if decoded.split('/').any(|seg| seg == "..") {
        return String::new();
    }
    let mut normalized = decoded;
    if normalized.len() > 1 && normalized.ends_with('/') {
        normalized.pop();
    }
    if !normalized.starts_with('/') {
        normalized.insert(0, '/');
    }
    normalized
}

fn percent_decode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut bytes = s.as_bytes().iter().peekable();
    while let Some(&b) = bytes.next() {
        if b == b'%' {
            let hi = bytes.next().copied().unwrap_or(b'%');
            let lo = bytes.next().copied().unwrap_or(b'%');
            if let (Some(h), Some(l)) = (hex_val(hi), hex_val(lo)) {
                out.push((h << 4 | l) as char);
            } else {
                out.push('%');
                out.push(hi as char);
                out.push(lo as char);
            }
        } else {
            out.push(b as char);
        }
    }
    out
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn is_allowed(method: &Method, normalized_path: &str) -> bool {
    ALLOWLIST.iter().any(|(m, p)| method.as_str() == *m && path_matches(p, normalized_path))
}

/// Default-deny middleware. `base_path` is the configured
/// `DBX_PUBLIC_BASE_PATH` (normalized, `/` when unset).
pub async fn firewall_middleware(
    axum::extract::State(base_path): axum::extract::State<String>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let normalized = normalize_path(request.uri().path(), &base_path);
    if !is_allowed(request.method(), &normalized) {
        return (StatusCode::FORBIDDEN, "forbidden by bastion firewall").into_response();
    }
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_match_only() {
        assert!(is_allowed(&Method::GET, "/api/bastion/health"));
        assert!(is_allowed(&Method::GET, "/api/bastion/status"));
        assert!(is_allowed(&Method::POST, "/api/bastion/auth/login"));
        assert!(is_allowed(&Method::POST, "/api/bastion/auth/logout"));
        assert!(is_allowed(&Method::GET, "/api/bastion/auth/me"));
        assert!(is_allowed(&Method::GET, "/api/bastion/assets"));
        // Wrong method.
        assert!(!is_allowed(&Method::POST, "/api/bastion/health"));
        assert!(!is_allowed(&Method::GET, "/api/bastion/auth/login"));
        // Prefix attacks.
        assert!(!is_allowed(&Method::GET, "/api/bastion/health/extra"));
        assert!(!is_allowed(&Method::GET, "/api/bastion"));
        assert!(!is_allowed(&Method::GET, "/api/"));
        // Old routes.
        assert!(!is_allowed(&Method::POST, "/api/query/execute"));
        assert!(!is_allowed(&Method::GET, "/api/query/execute"));
    }

    #[test]
    fn uuid_path_param() {
        let id = "550e8400-e29b-41d4-a716-446655440000";
        assert!(is_allowed(&Method::GET, &format!("/api/bastion/assets/{id}")));
        assert!(is_allowed(&Method::POST, &format!("/api/bastion/audit/interruptions/{id}/triage")));
        // Non-UUID, empty, or multi-segment ids are rejected.
        assert!(!is_allowed(&Method::GET, "/api/bastion/assets/not-a-uuid"));
        assert!(!is_allowed(&Method::GET, "/api/bastion/assets/"));
        assert!(!is_allowed(&Method::GET, "/api/bastion/assets"));
        assert!(!is_allowed(&Method::GET, &format!("/api/bastion/assets/{id}/extra")));
        assert!(!is_allowed(&Method::POST, &format!("/api/bastion/audit/interruptions/{id}/triage/extra")));
        // Wrong method on the parameterized routes.
        assert!(!is_allowed(&Method::POST, &format!("/api/bastion/assets/{id}")));
        assert!(!is_allowed(&Method::GET, &format!("/api/bastion/audit/interruptions/{id}/triage")));
        // Query-execute is allowlisted now (005C-4).
        assert!(is_allowed(&Method::POST, "/api/bastion/query/execute"));
        assert!(!is_allowed(&Method::GET, "/api/bastion/query/execute"));
    }

    #[test]
    fn normalization() {
        // Trailing slash.
        assert_eq!(normalize_path("/api/bastion/health/", "/"), "/api/bastion/health");
        // Percent-encoding.
        assert_eq!(normalize_path("/api/bastion/%68ealth", "/"), "/api/bastion/health");
        assert_eq!(normalize_path("/api/%62astion/health", "/"), "/api/bastion/health");
        // Base path stripping.
        assert_eq!(normalize_path("/dbx/api/bastion/health", "/dbx"), "/api/bastion/health");
        // Not under base path -> empty (never whitelisted).
        assert_eq!(normalize_path("/api/bastion/health", "/dbx"), "");
    }

    #[test]
    fn no_fuzzy_prefix_match() {
        // `/dbx` must not match `/dbxevil/...` — segment boundary required.
        assert_eq!(normalize_path("/dbxevil/api/bastion/health", "/dbx"), "");
        assert_eq!(normalize_path("/dbx2/api/bastion/health", "/dbx"), "");
        // Exact base path alone -> "/" (never whitelisted).
        assert_eq!(normalize_path("/dbx", "/dbx"), "/");
        assert_eq!(normalize_path("/dbx/", "/dbx"), "/");
    }

    #[test]
    fn traversal_rejected() {
        // Plain and encoded `..` segments are rejected (fail-closed).
        assert_eq!(normalize_path("/api/bastion/../bastion/health", "/"), "");
        assert_eq!(normalize_path("/api/%2e%2e/bastion/health", "/"), "");
        assert_eq!(normalize_path("/api/bastion/%2E%2E/health", "/"), "");
        assert_eq!(normalize_path("/dbx/api/bastion/../../health", "/dbx"), "");
        // Legitimate paths still pass.
        assert!(is_allowed(&Method::GET, &normalize_path("/dbx/api/bastion/health", "/dbx")));
    }

    #[test]
    fn base_path_validation() {
        // Unset / empty / root -> "/".
        assert_eq!(validate_base_path(None).unwrap(), "/");
        assert_eq!(validate_base_path(Some("")).unwrap(), "/");
        assert_eq!(validate_base_path(Some("/")).unwrap(), "/");
        // Legal prefixes.
        assert_eq!(validate_base_path(Some("/dbx")).unwrap(), "/dbx");
        assert_eq!(validate_base_path(Some("/dbx/v2")).unwrap(), "/dbx/v2");
        // Trailing slash is normalized.
        assert_eq!(validate_base_path(Some("/dbx/")).unwrap(), "/dbx");
        // Illegal values -> diagnosable errors (no panic).
        assert!(validate_base_path(Some("dbx")).is_err()); // no leading slash
        assert!(validate_base_path(Some("/dbx/../evil")).is_err()); // traversal
        assert!(validate_base_path(Some("/dbx//api")).is_err()); // empty segment
        assert!(validate_base_path(Some("/dbx%2fapi")).is_err()); // encoded
        assert!(validate_base_path(Some("/dbx?x=1")).is_err());
        assert!(validate_base_path(Some("/dbx#frag")).is_err());
        assert!(validate_base_path(Some("/db x")).is_err()); // whitespace
        assert!(validate_base_path(Some("/dbx\\api")).is_err()); // backslash
    }
}

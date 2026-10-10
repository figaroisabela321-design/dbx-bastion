//! Bastion run mode (TASK-005C-1).
//!
//! The web process runs in exactly one mode, decided at startup from
//! the environment. There is no runtime switching and no fallback:
//! an invalid or conflicting configuration is a startup failure.

/// The web process run mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunMode {
    /// Original DBX single-user mode. Unchanged behavior.
    Legacy,
    /// Bastion mode: default-deny route firewall, bastion auth only.
    Bastion,
}

/// Parse `DBX_BASTION_MODE`.
///
/// Accepted (case-insensitive, trimmed):
/// - unset, `""`, `"0"`, `"false"`, `"no"`, `"legacy"` → [`RunMode::Legacy`]
/// - `"1"`, `"true"`, `"yes"`, `"on"`, `"bastion"` → [`RunMode::Bastion`]
/// - anything else → `Err` (never silently downgraded).
pub fn run_mode_from_env() -> Result<RunMode, String> {
    match std::env::var("DBX_BASTION_MODE").ok().as_deref().map(str::trim).map(str::to_lowercase).as_deref() {
        None | Some("") | Some("0") | Some("false") | Some("no") | Some("legacy") => Ok(RunMode::Legacy),
        Some("1") | Some("true") | Some("yes") | Some("on") | Some("bastion") => Ok(RunMode::Bastion),
        Some(other) => Err(format!(
            "invalid DBX_BASTION_MODE={other:?}: expected one of 1/true/bastion or 0/false/legacy; refusing to start"
        )),
    }
}

/// `true` when `DBX_DISABLE_PASSWORD` disables password protection.
///
/// In bastion mode this must never take effect (see [`check_mode_conflict`]).
pub fn password_disabled_from_env() -> bool {
    std::env::var("DBX_DISABLE_PASSWORD")
        .map(|v| matches!(v.trim().to_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
}

/// Refuse to start when bastion mode is combined with disabled password
/// protection. `DBX_DISABLE_PASSWORD` would bypass all authentication;
/// in bastion mode that bypass must not exist, so the combination is a
/// hard startup failure rather than a silent downgrade.
pub fn check_mode_conflict(mode: RunMode) -> Result<(), String> {
    if mode == RunMode::Bastion && password_disabled_from_env() {
        return Err("refusing to start: DBX_BASTION_MODE=1 conflicts with DBX_DISABLE_PASSWORD=1; \
             password protection cannot be disabled in bastion mode"
            .to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_var(key: &str, value: Option<&str>, f: impl FnOnce()) {
        let prev = std::env::var(key).ok();
        match value {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
        f();
        match prev {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
    }

    #[test]
    fn mode_parsing() {
        with_var("DBX_BASTION_MODE", None, || assert_eq!(run_mode_from_env().unwrap(), RunMode::Legacy));
        with_var("DBX_BASTION_MODE", Some("1"), || assert_eq!(run_mode_from_env().unwrap(), RunMode::Bastion));
        with_var("DBX_BASTION_MODE", Some("bastion"), || assert_eq!(run_mode_from_env().unwrap(), RunMode::Bastion));
        with_var("DBX_BASTION_MODE", Some("0"), || assert_eq!(run_mode_from_env().unwrap(), RunMode::Legacy));
        with_var("DBX_BASTION_MODE", Some("bogus"), || assert!(run_mode_from_env().is_err()));
    }

    #[test]
    fn disable_password_conflict() {
        with_var("DBX_DISABLE_PASSWORD", Some("1"), || {
            assert!(check_mode_conflict(RunMode::Bastion).is_err());
            assert!(check_mode_conflict(RunMode::Legacy).is_ok());
        });
        with_var("DBX_DISABLE_PASSWORD", None, || {
            assert!(check_mode_conflict(RunMode::Bastion).is_ok());
        });
    }
}

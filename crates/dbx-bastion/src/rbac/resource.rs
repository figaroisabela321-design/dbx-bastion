//! Resource identity contract for RBAC matching.
//!
//! Authorization scope: `User/Role -> Asset -> Database -> Schema -> Table -> Action`.
//!
//! A request-side resource level is a [`NameState`]:
//! - [`NameState::Present`]: an identifier that is present **and normalized**
//!   by the caller (the future SQL analyzer, P4).
//! - [`NameState::NotApplicable`]: the dialect has no such level
//!   (e.g. `schema` on MySQL/SQLite, where database == schema).
//! - [`NameState::Unknown`]: the level could not be reliably determined.
//!   Unknown levels never match a specific rule value (fail closed).
//!
//! A rule-side level is `Option<String>`: `None` means "any" (wildcard).
//! The API accepts the string `"*"` and [`GrantService`](super::grants::GrantService)
//! normalizes it to `None` on write, so the database stores exactly one
//! wildcard representation. Every other string is a **literal**: `"prod_*"`
//! matches only an object literally named `prod_*`; there is no LIKE,
//! regex or substring matching anywhere in authorization.
//!
//! Case and quoting: V1 does **no** case folding and no quote stripping at
//! the RBAC layer — matching is exact and case-sensitive, byte-wise.
//! Case folding is dialect-dependent (PostgreSQL folds unquoted identifiers
//! to lower case, Oracle to upper case, MySQL depends on
//! `lower_case_table_names`, SQL Server on collation); doing it wrong here
//! would be an authorization bypass. Canonicalization is the SQL analyzer's
//! job (P4):
//! - PostgreSQL: unquoted -> lower case, quoted -> as-is (default schema `public`)
//! - Oracle: unquoted -> UPPER CASE, quoted -> as-is
//! - MySQL / SQLite / SQL Server: as-is (schema N/A on MySQL/SQLite)
//!
//! If the analyzer cannot reliably determine an identifier it must mark the
//! level [`NameState::Unknown`] (or refuse to call the authorizer at all —
//! the QueryGateway contract); the matcher below then denies.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The state of one resource-name level on the request side.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NameState {
    /// The dialect has no such level (e.g. `schema` on MySQL/SQLite).
    NotApplicable,
    /// Present and already normalized by the caller.
    Present(String),
    /// Could not be reliably determined. Never matches a specific rule
    /// value: unknown resources are denied by default.
    Unknown,
}

impl NameState {
    pub fn present(value: impl Into<String>) -> Self {
        NameState::Present(value.into())
    }
}

/// The concrete resource a check is performed against.
///
/// Every table touched by a statement must be checked individually (never
/// only the first one); the future QueryGateway maps analyzer output to a
/// list of these.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceScope {
    pub asset_id: Uuid,
    pub database: NameState,
    pub schema: NameState,
    pub table: NameState,
}

impl ResourceScope {
    /// Asset-level scope, used for [`Action::Connect`](super::Action) checks.
    /// CONNECT is authorized per asset only: it is never implied by
    /// data-action grants, and data-action grants never imply it.
    pub fn asset(asset_id: Uuid) -> Self {
        Self {
            asset_id,
            database: NameState::NotApplicable,
            schema: NameState::NotApplicable,
            table: NameState::NotApplicable,
        }
    }
}

/// Match one level: `rule` is the grant's value (`None` = wildcard),
/// `request` is the [`NameState`] from the check.
pub(crate) fn level_matches(rule: Option<&str>, request: &NameState) -> bool {
    match (rule, request) {
        // Wildcard rules match everything, including N/A and unknown levels:
        // the rule simply does not constrain this level.
        (None, _) => true,
        (Some(pattern), NameState::Present(name)) => pattern == name,
        // A specific rule value can never match a level the dialect does
        // not have, nor one that could not be determined.
        (Some(_), NameState::NotApplicable) => false,
        (Some(_), NameState::Unknown) => false,
    }
}

/// Normalize a caller-supplied pattern for storage: `"*"` becomes the
/// canonical wildcard (`None`); anything else is kept as a literal.
pub(crate) fn normalize_pattern(value: Option<String>) -> Option<String> {
    match value {
        Some(s) if s == "*" => None,
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_rule_matches_everything() {
        assert!(level_matches(None, &NameState::NotApplicable));
        assert!(level_matches(None, &NameState::Unknown));
        assert!(level_matches(None, &NameState::present("anything")));
    }

    #[test]
    fn specific_rule_requires_present_equal() {
        assert!(level_matches(Some("public"), &NameState::present("public")));
        assert!(!level_matches(Some("public"), &NameState::present("Public")));
        assert!(!level_matches(Some("public"), &NameState::NotApplicable));
        assert!(!level_matches(Some("public"), &NameState::Unknown));
    }

    /// Documents the hazard behind the analyzer's `Unknown` handling:
    /// a wildcard ALLOW *would* match an Unknown level, while a
    /// table-level DENY on the real schema would not fire. That is why
    /// the SQL policy denies `Unknown` levels before any RBAC matching
    /// (and why the gateway must refuse to build checks from them) —
    /// otherwise omitting the schema would bypass the DENY.
    #[test]
    fn wildcard_matches_unknown_so_policy_must_deny_first() {
        // The hazard: DENY(public.orders) does not fire on Unknown…
        assert!(!level_matches(Some("public"), &NameState::Unknown));
        // …but a wildcard ALLOW would match the same request.
        assert!(level_matches(None, &NameState::Unknown));
    }

    #[test]
    fn star_is_literal_unless_normalized() {
        // Without normalization "prod_*" is just a literal string.
        assert!(level_matches(Some("prod_*"), &NameState::present("prod_*")));
        assert!(!level_matches(Some("prod_*"), &NameState::present("prod_1")));
        // normalize_pattern turns "*" into the wildcard.
        assert_eq!(normalize_pattern(Some("*".to_string())), None);
        assert_eq!(normalize_pattern(Some("prod_*".to_string())), Some("prod_*".to_string()));
    }
}

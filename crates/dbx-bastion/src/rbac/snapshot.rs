//! Authorization consistency snapshot.
//!
//! One [`AuthSnapshot`] carries **every** input a batch of authorization
//! checks may read: session validity, user enabled flag, effective roles
//! (direct + via user groups), matching grant rows, asset rows, the asset
//! group tree, and asset<->group memberships — plus the single `now` used
//! for all expiry evaluations in the batch.
//!
//! The snapshot is built inside **one** SQLite Deferred read transaction
//! (`SqliteStore::authorization_snapshot`). Evaluation afterwards
//! ([`AuthSnapshot::decide`]) is a pure function: no further database
//! access, no TOCTOU inside the decision. Snapshots are never cached
//! across requests, so a permission change is visible to the very next
//! authorization call.

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::asset::{AssetView, Environment};
use crate::rbac::resource::{level_matches, ResourceScope};
use crate::rbac::{Action, AuthorizationCheck, Effect};

/// One row of the `permissions` table as seen by the evaluator.
/// `asset_id` / `asset_group_id` hold exactly one `Some` value — enforced
/// by the database CHECK constraint; the `_ => false` arm in matching is
/// defense in depth and fails closed.
#[derive(Debug, Clone)]
pub(crate) struct GrantRule {
    /// Diagnostic anchor for future audit logging (which grant decided).
    #[allow(dead_code)]
    pub id: Uuid,
    pub effect: Effect,
    pub action: Action,
    #[allow(dead_code)]
    pub role_id: Uuid,
    pub asset_id: Option<Uuid>,
    pub asset_group_id: Option<Uuid>,
    pub database: Option<String>,
    pub schema: Option<String>,
    pub table: Option<String>,
    /// Raw RFC3339 text. Parsed at evaluation time; unparseable values
    /// fail closed (see [`AuthSnapshot::decide`]).
    pub expires_at: Option<String>,
}

/// Asset row projected for authorization and view rendering.
#[derive(Debug, Clone)]
pub(crate) struct SnapshotAsset {
    pub id: Uuid,
    pub name: String,
    pub environment: Environment,
    pub db_type: String,
    pub description: String,
    pub enabled: bool,
    pub deleted_at: Option<DateTime<Utc>>,
}

impl From<&SnapshotAsset> for AssetView {
    fn from(asset: &SnapshotAsset) -> Self {
        Self {
            id: asset.id,
            name: asset.name.clone(),
            environment: asset.environment,
            db_type: asset.db_type.clone(),
            description: asset.description.clone(),
            enabled: asset.enabled,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MatchOutcome {
    NoMatch,
    /// The rule matched on scope/action but its `expires_at` is malformed.
    /// Failing closed: the whole check is denied (a corrupt DENY must never
    /// be silently ignored into an allow).
    Corrupt,
    Allow,
    Deny,
}

/// Consistency snapshot for one authorization batch. See module docs.
///
/// The snapshot is always built for one principal by the storage loader;
/// the session_id <-> user_id binding is enforced there at runtime
/// (release-effective): a session that does not belong to the user
/// yields `session_valid == false` and every decision denies. No
/// debug-only assertion is relied upon for this binding.
#[derive(Debug, Clone)]
pub(crate) struct AuthSnapshot {
    /// Re-validated inside the snapshot transaction: session row exists,
    /// not revoked, not expired. A session revoked after
    /// [`AuthenticatedPrincipal`](crate::auth::AuthenticatedPrincipal)
    /// issuance is denied here.
    pub session_valid: bool,
    pub user_enabled: bool,
    /// Grant rows for the requested actions, pre-filtered in SQL to the
    /// principal's effective roles (direct `user_roles` ∪ roles via
    /// `user_groups`). No separate role set is kept: the rules are the
    /// single source of truth, so there is nothing to drift.
    pub rules: Vec<GrantRule>,
    pub assets: HashMap<Uuid, SnapshotAsset>,
    /// parent_id -> child ids, for descendant walks.
    pub group_children: HashMap<Uuid, Vec<Uuid>>,
    /// asset_id -> directly containing group ids.
    pub asset_groups: HashMap<Uuid, Vec<Uuid>>,
    /// Single time source for every expiry check in this snapshot.
    pub now: DateTime<Utc>,
}

impl AuthSnapshot {
    /// Pure-function authorization decision for one check.
    ///
    /// Decision order (DENY priority, default deny):
    /// 1. session invalid or user disabled -> deny;
    /// 2. asset missing, disabled or soft-deleted -> deny;
    /// 3. any valid matching DENY -> deny (short-circuit);
    /// 4. any valid matching ALLOW -> allow;
    /// 5. otherwise -> deny.
    ///
    /// A rule whose `expires_at` cannot be parsed fails the whole check
    /// closed — it is never skipped.
    pub fn decide(&self, check: &AuthorizationCheck) -> bool {
        if !self.session_valid || !self.user_enabled {
            return false;
        }
        match self.assets.get(&check.resource.asset_id) {
            Some(asset) if asset.enabled && asset.deleted_at.is_none() => {}
            _ => return false,
        }

        let mut allowed = false;
        for rule in self.rules.iter().filter(|rule| rule.action == check.action) {
            match self.match_rule(rule, check) {
                MatchOutcome::NoMatch => continue,
                // Fail closed. (The offending rule id is available on the
                // snapshot for the future audit service; no logging facade
                // exists in this crate yet.)
                MatchOutcome::Corrupt => return false,
                // Any valid matching DENY wins immediately.
                MatchOutcome::Deny => return false,
                MatchOutcome::Allow => allowed = true,
            }
        }
        allowed
    }

    /// The single predicate shared by the [`Authorizer`](super::Authorizer)
    /// and asset visibility filtering: list filtering and per-check
    /// evaluation cannot drift apart.
    pub fn connect_allowed(&self, asset_id: Uuid) -> bool {
        self.decide(&AuthorizationCheck { resource: ResourceScope::asset(asset_id), action: Action::Connect })
    }

    fn match_rule(&self, rule: &GrantRule, check: &AuthorizationCheck) -> MatchOutcome {
        // 1. Expiry against the snapshot's single time source.
        // Expired rules simply don't apply; malformed values fail the
        // whole check closed (a corrupt DENY must never be skipped).
        match rule.expires_at.as_deref() {
            None => {}
            Some(raw) => match parse_expires_at(raw) {
                Some(valid_until) if valid_until > self.now => {}
                Some(_) => return MatchOutcome::NoMatch,
                None => return MatchOutcome::Corrupt,
            },
        }

        // 2. Asset scope: exactly one of asset_id / asset_group_id is set
        //    (database CHECK). Anything else fails closed.
        let asset_in_scope = match (rule.asset_id, rule.asset_group_id) {
            (Some(asset_id), None) => asset_id == check.resource.asset_id,
            (None, Some(group_id)) => self.asset_in_group_tree(check.resource.asset_id, group_id),
            _ => return MatchOutcome::NoMatch,
        };
        if !asset_in_scope {
            return MatchOutcome::NoMatch;
        }

        // 3. Database / schema / table levels. CONNECT grants are
        //    asset-level by construction (GrantService rejects scoped
        //    CONNECT grants); the check below additionally requires the
        //    rule to leave the levels wildcarded for CONNECT.
        if check.action == Action::Connect && (rule.database.is_some() || rule.schema.is_some() || rule.table.is_some())
        {
            return MatchOutcome::NoMatch;
        }
        if !level_matches(rule.database.as_deref(), &check.resource.database)
            || !level_matches(rule.schema.as_deref(), &check.resource.schema)
            || !level_matches(rule.table.as_deref(), &check.resource.table)
        {
            return MatchOutcome::NoMatch;
        }

        match rule.effect {
            Effect::Allow => MatchOutcome::Allow,
            Effect::Deny => MatchOutcome::Deny,
        }
    }

    /// True if the asset is directly in `group_id` or in any descendant
    /// group. The walk is cycle-defensive (visited set): group moves
    /// already prevent cycles transactionally; this is defense in depth.
    fn asset_in_group_tree(&self, asset_id: Uuid, group_id: Uuid) -> bool {
        let direct = self.asset_groups.get(&asset_id).map(|groups| groups.as_slice()).unwrap_or(&[]);
        if direct.contains(&group_id) {
            return true;
        }
        let mut visited = HashSet::new();
        let mut stack: Vec<Uuid> = self.group_children.get(&group_id).cloned().unwrap_or_default();
        while let Some(current) = stack.pop() {
            if !visited.insert(current) {
                continue;
            }
            if direct.contains(&current) {
                return true;
            }
            if let Some(children) = self.group_children.get(&current) {
                stack.extend(children.iter().copied());
            }
        }
        false
    }
}

/// Parse an `expires_at` value. Only strict RFC3339 is accepted; anything
/// else is `None` and the caller fails closed.
fn parse_expires_at(raw: &str) -> Option<DateTime<Utc>> {
    raw.parse::<DateTime<Utc>>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rbac::resource::NameState;

    fn test_asset(id: Uuid) -> SnapshotAsset {
        SnapshotAsset {
            id,
            name: "a".to_string(),
            environment: Environment::Development,
            db_type: "mysql".to_string(),
            description: String::new(),
            enabled: true,
            deleted_at: None,
        }
    }

    fn base_snapshot(asset_id: Uuid) -> AuthSnapshot {
        AuthSnapshot {
            session_valid: true,
            user_enabled: true,
            rules: vec![],
            assets: HashMap::from([(asset_id, test_asset(asset_id))]),
            group_children: HashMap::new(),
            asset_groups: HashMap::new(),
            now: Utc::now(),
        }
    }

    fn allow_rule(asset_id: Uuid, action: Action) -> GrantRule {
        GrantRule {
            id: Uuid::new_v4(),
            effect: Effect::Allow,
            action,
            role_id: Uuid::new_v4(),
            asset_id: Some(asset_id),
            asset_group_id: None,
            database: None,
            schema: None,
            table: None,
            expires_at: None,
        }
    }

    #[test]
    fn default_deny_without_rules() {
        let asset = Uuid::new_v4();
        let snap = base_snapshot(asset);
        let check = AuthorizationCheck { resource: ResourceScope::asset(asset), action: Action::Connect };
        assert!(!snap.decide(&check));
    }

    #[test]
    fn invalid_session_denies() {
        let asset = Uuid::new_v4();
        let mut snap = base_snapshot(asset);
        snap.rules.push(allow_rule(asset, Action::Connect));
        snap.session_valid = false;
        let check = AuthorizationCheck { resource: ResourceScope::asset(asset), action: Action::Connect };
        assert!(!snap.decide(&check));
    }

    #[test]
    fn malformed_expires_at_fails_closed() {
        let asset = Uuid::new_v4();
        let mut snap = base_snapshot(asset);
        let mut deny = allow_rule(asset, Action::Select);
        deny.effect = Effect::Deny;
        deny.expires_at = Some("not-a-timestamp".to_string());
        snap.rules.push(deny);
        // Even an ALLOW elsewhere must not override the corrupt DENY.
        snap.rules.push(allow_rule(asset, Action::Select));
        let check = AuthorizationCheck {
            resource: ResourceScope {
                asset_id: asset,
                database: NameState::NotApplicable,
                schema: NameState::NotApplicable,
                table: NameState::present("t"),
            },
            action: Action::Select,
        };
        assert!(!snap.decide(&check));
    }
}

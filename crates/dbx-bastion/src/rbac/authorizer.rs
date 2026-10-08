//! The RBAC authorizer: snapshot-backed, DENY-priority decisions.
//!
//! [`Authorizer`] is the single authorization entry point for data-plane
//! operations (the future QueryGateway calls it; asset visibility uses the
//! same snapshot semantics through [`AuthSnapshot::connect_allowed`]).
//!
//! Design rules:
//! - Identity is [`AuthenticatedPrincipal`]: unforgeable, session-validated.
//!   Forged `user_id`s cannot reach the evaluator (type-level).
//! - Every call builds one fresh [`AuthSnapshot`] (single SQLite read
//!   transaction); evaluation is a pure function over it. No cross-request
//!   caching: a grant change is visible to the next call.
//! - `Result<bool>`/`Result<()>` discipline: `Err` means infrastructure
//!   failure, never denial. Denial is `Ok(false)` / `Err(Forbidden)` with
//!   the fixed generic message `"access denied"` — no rule contents, asset
//!   names or "which grant is missing" hints ever reach the caller.
//! - Empty check sets are **denied** on every decision entry point. In
//!   particular, `authorize_batch` with no checks returns `Err`, so an
//!   empty iterator's `.all()` can never be mistaken for "authorized".

use std::sync::Arc;

use async_trait::async_trait;
use uuid::Uuid;

use crate::auth::session::Clock;
use crate::auth::AuthenticatedPrincipal;
use crate::error::{BastionError, Result};
use crate::rbac::resource::ResourceScope;
use crate::rbac::Action;
use crate::storage::SqliteStore;

/// One authorization question: a resource crossed with an action.
/// A single SQL statement typically produces several of these
/// (e.g. `INSERT INTO a SELECT * FROM b` -> `(a, Insert)` + `(b, Select)`).
#[derive(Debug, Clone)]
pub struct AuthorizationCheck {
    pub resource: ResourceScope,
    pub action: Action,
}

impl AuthorizationCheck {
    pub fn new(resource: ResourceScope, action: Action) -> Self {
        Self { resource, action }
    }
}

/// Deny message returned to callers. Fixed text: diagnostics must not leak
/// which rule, asset or grant was involved.
pub(crate) fn denied() -> BastionError {
    BastionError::Forbidden("access denied".to_string())
}

#[async_trait]
pub trait Authorizer: Send + Sync {
    /// Strict gate: **all** checks must pass, otherwise `Err(Forbidden)`.
    /// An empty `checks` slice is denied outright — it must never be read
    /// as "nothing to check, therefore allowed".
    async fn authorize_batch(&self, principal: &AuthenticatedPrincipal, checks: &[AuthorizationCheck]) -> Result<()> {
        if checks.is_empty() {
            return Err(denied());
        }
        let results = self.evaluate_batch(principal, checks).await?;
        // Explicit length check: never let an empty iterator's `.all()`
        // (which is `true`) stand in for an authorization decision.
        if results.len() == checks.len() && results.iter().all(|granted| *granted) {
            Ok(())
        } else {
            Err(denied())
        }
    }

    /// Single resource/action gate.
    async fn authorize(
        &self,
        principal: &AuthenticatedPrincipal,
        resource: &ResourceScope,
        action: Action,
    ) -> Result<()> {
        self.authorize_batch(principal, &[AuthorizationCheck::new(resource.clone(), action)]).await
    }

    /// Same action over many resources: every resource must be allowed.
    /// Empty `resources` -> denied (see [`Self::authorize_batch`]).
    async fn authorize_all(
        &self,
        principal: &AuthenticatedPrincipal,
        resources: &[ResourceScope],
        action: Action,
    ) -> Result<()> {
        let checks: Vec<AuthorizationCheck> =
            resources.iter().map(|r| AuthorizationCheck::new(r.clone(), action)).collect();
        self.authorize_batch(principal, &checks).await
    }

    /// Per-item evaluation under **one** consistency snapshot, returned in
    /// input order. This is *not* an authorization decision: callers must
    /// not treat the vector as a grant. It exists for asset visibility
    /// filtering and (later) internal audit. Empty input -> empty output.
    async fn evaluate_batch(
        &self,
        principal: &AuthenticatedPrincipal,
        checks: &[AuthorizationCheck],
    ) -> Result<Vec<bool>>;
}

/// Snapshot-backed [`Authorizer`].
pub struct SnapshotAuthorizer {
    store: Arc<SqliteStore>,
    clock: Arc<dyn Clock>,
}

impl SnapshotAuthorizer {
    pub fn new(store: Arc<SqliteStore>, clock: Arc<dyn Clock>) -> Self {
        Self { store, clock }
    }
}

#[async_trait]
impl Authorizer for SnapshotAuthorizer {
    async fn evaluate_batch(
        &self,
        principal: &AuthenticatedPrincipal,
        checks: &[AuthorizationCheck],
    ) -> Result<Vec<bool>> {
        if checks.is_empty() {
            return Ok(Vec::new());
        }
        let mut actions: Vec<Action> = Vec::with_capacity(checks.len());
        for check in checks {
            if !actions.contains(&check.action) {
                actions.push(check.action);
            }
        }
        let snapshot = self
            .store
            .authorization_snapshot(principal.user_id(), principal.session_id(), &actions, self.clock.clone())
            .await?;
        // The snapshot must belong to the principal being evaluated; a
        // mix-up here would be an authorization bypass.
        debug_assert_eq!(snapshot.user_id, principal.user_id());
        Ok(checks.iter().map(|check| snapshot.decide(check)).collect())
    }
}

/// Convenience: the CONNECT check for one asset.
pub fn connect_check(asset_id: Uuid) -> AuthorizationCheck {
    AuthorizationCheck::new(ResourceScope::asset(asset_id), Action::Connect)
}

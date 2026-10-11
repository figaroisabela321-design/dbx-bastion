//! V1 SQL policy: pure-domain allow/deny/approval decisions (TASK-005A).
//!
//! Responsibility split:
//! - **RBAC** answers "does the principal have permission" (who x
//!   asset/database/schema/table x action). Enforced by the gateway with
//!   `Authorizer::authorize_batch` (TASK-005B).
//! - **Policy** answers "may it execute directly": risk, approval need,
//!   and execution limits. Its input is the *analyzer's* precise output
//!   plus the asset environment — never the raw SQL string, never
//!   keyword matching.
//!
//! V1 rules are deterministic code (no rule table yet). Every rule is
//! locked by matrix tests.

use crate::asset::Environment;
use crate::query::analyzer::{AnalyzedStatement, StatementAction};

/// Policy verdict for one analyzed statement batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDecision {
    /// May proceed to RBAC authorization and execution.
    Allow,
    /// Must not execute. The reason is exact (for audit/admin
    /// diagnostics); the gateway maps it to the generic denial for
    /// ordinary callers.
    Deny(PolicyReason),
    /// May only execute with a valid approval ticket. Until the
    /// approval service exists, the gateway treats this as deny.
    RequireApproval(PolicyReason),
}

/// Machine-readable denial/approval reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyReason {
    /// Analyzer could not be applied (defensive; the analyzer itself
    /// rejects these first).
    Unanalyzable,
    /// A table reference has an unresolvable identity level (e.g. a
    /// PostgreSQL schema left to `search_path`). Never authorize on a
    /// guess: V1 requires explicit qualification.
    UnresolvedIdentity,
    /// More than one statement (defensive; the analyzer rejects first).
    MultiStatement,
    /// `SELECT INTO`, locking reads, or unknown/non-pure functions:
    /// not a pure read, never passed as an ordinary SELECT.
    SideEffectSelect,
    /// UPDATE/DELETE without a WHERE clause.
    MissingWhere,
    /// UPDATE/DELETE whose WHERE is a syntactic tautology.
    TrivialWhere,
    /// DDL is denied in V1.
    DdlNotAllowed,
    /// GRANT/REVOKE are never executable through the gateway.
    GrantNotAllowed,
    /// Explicit transaction control is denied in V1 (manual
    /// transactions are disabled entirely).
    TransactionNotAllowed,
    /// Stored-procedure calls are denied in V1.
    ProcedureNotAllowed,
    /// MERGE is denied in V1.
    MergeNotAllowed,
    /// Session-utility statements are denied in V1.
    UtilityNotAllowed,
    /// Production DML requires an approval ticket (not yet issuable).
    ProductionDmlRequiresApproval,
}

impl PolicyReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unanalyzable => "unanalyzable_sql",
            Self::UnresolvedIdentity => "unresolved_identity",
            Self::MultiStatement => "multi_statement",
            Self::SideEffectSelect => "side_effect_select",
            Self::MissingWhere => "missing_where",
            Self::TrivialWhere => "trivial_where",
            Self::DdlNotAllowed => "ddl_not_allowed_v1",
            Self::GrantNotAllowed => "grant_not_allowed",
            Self::TransactionNotAllowed => "transaction_not_allowed_v1",
            Self::ProcedureNotAllowed => "procedure_not_allowed_v1",
            Self::MergeNotAllowed => "merge_not_allowed_v1",
            Self::UtilityNotAllowed => "utility_not_allowed_v1",
            Self::ProductionDmlRequiresApproval => "production_dml_requires_approval",
        }
    }
}

/// Policy evaluation context.
#[derive(Debug, Clone, Copy)]
pub struct PolicyContext {
    pub environment: Environment,
}

impl PolicyContext {
    pub fn new(environment: Environment) -> Self {
        Self { environment }
    }

    pub fn is_production(&self) -> bool {
        matches!(self.environment, Environment::Production)
    }
}

/// Deterministic V1 policy.
pub struct SqlPolicy;

impl SqlPolicy {
    pub fn evaluate(&self, statements: &[AnalyzedStatement], ctx: &PolicyContext) -> PolicyDecision {
        // Defensive: the analyzer enforces single-statement first.
        if statements.len() != 1 {
            return PolicyDecision::Deny(PolicyReason::MultiStatement);
        }
        let stmt = &statements[0];
        // Unresolvable object identity: deny before RBAC, where a
        // wildcard rule would match an Unknown level while a
        // table-level DENY on the real schema would not fire.
        if stmt.targets.iter().chain(stmt.sources.iter()).any(|t| t.has_unknown_level()) {
            return PolicyDecision::Deny(PolicyReason::UnresolvedIdentity);
        }
        // Non-pure reads never pass as ordinary SELECTs, in any
        // environment — including production read-only.
        if stmt.has_side_effects {
            return PolicyDecision::Deny(PolicyReason::SideEffectSelect);
        }
        let production = ctx.is_production();
        match stmt.action {
            StatementAction::Select => PolicyDecision::Allow,
            StatementAction::Insert => {
                if production {
                    PolicyDecision::RequireApproval(PolicyReason::ProductionDmlRequiresApproval)
                } else {
                    PolicyDecision::Allow
                }
            }
            StatementAction::Update | StatementAction::Delete => {
                match stmt.has_where {
                    Some(true) if !stmt.where_trivially_true => {
                        if production {
                            PolicyDecision::RequireApproval(PolicyReason::ProductionDmlRequiresApproval)
                        } else {
                            PolicyDecision::Allow
                        }
                    }
                    Some(true) => PolicyDecision::Deny(PolicyReason::TrivialWhere),
                    // None (undeterminable) and Some(false) both deny.
                    _ => PolicyDecision::Deny(PolicyReason::MissingWhere),
                }
            }
            StatementAction::Ddl => PolicyDecision::Deny(PolicyReason::DdlNotAllowed),
            StatementAction::Grant => PolicyDecision::Deny(PolicyReason::GrantNotAllowed),
            StatementAction::Transaction => PolicyDecision::Deny(PolicyReason::TransactionNotAllowed),
            StatementAction::Procedure => PolicyDecision::Deny(PolicyReason::ProcedureNotAllowed),
            StatementAction::Merge => PolicyDecision::Deny(PolicyReason::MergeNotAllowed),
            StatementAction::Utility => PolicyDecision::Deny(PolicyReason::UtilityNotAllowed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::analyzer::TableRef;
    use crate::rbac::resource::NameState;

    fn table(name: &str) -> TableRef {
        TableRef { database: NameState::NotApplicable, schema: NameState::NotApplicable, table: name.to_string() }
    }

    fn stmt(action: StatementAction) -> AnalyzedStatement {
        AnalyzedStatement {
            action,
            targets: vec![table("t")],
            sources: Vec::new(),
            has_where: None,
            where_trivially_true: false,
            has_side_effects: false,
        }
    }

    fn ctx(env: Environment) -> PolicyContext {
        PolicyContext::new(env)
    }

    #[test]
    fn select_allowed_everywhere() {
        let p = SqlPolicy;
        for env in [Environment::Development, Environment::Test, Environment::Staging, Environment::Production] {
            assert_eq!(p.evaluate(&[stmt(StatementAction::Select)], &ctx(env)), PolicyDecision::Allow);
        }
    }

    #[test]
    fn dml_policy_matrix() {
        let p = SqlPolicy;
        let dev = ctx(Environment::Development);
        let prod = ctx(Environment::Production);

        // INSERT: non-prod allow, prod requires approval.
        assert_eq!(p.evaluate(&[stmt(StatementAction::Insert)], &dev), PolicyDecision::Allow);
        assert_eq!(
            p.evaluate(&[stmt(StatementAction::Insert)], &prod),
            PolicyDecision::RequireApproval(PolicyReason::ProductionDmlRequiresApproval)
        );

        // UPDATE/DELETE with WHERE: same split.
        let mut upd = stmt(StatementAction::Update);
        upd.has_where = Some(true);
        assert_eq!(p.evaluate(&[upd.clone()], &dev), PolicyDecision::Allow);
        assert_eq!(
            p.evaluate(&[upd], &prod),
            PolicyDecision::RequireApproval(PolicyReason::ProductionDmlRequiresApproval)
        );

        // Missing WHERE: deny everywhere.
        let mut del = stmt(StatementAction::Delete);
        del.has_where = Some(false);
        assert_eq!(p.evaluate(&[del.clone()], &dev), PolicyDecision::Deny(PolicyReason::MissingWhere));
        assert_eq!(p.evaluate(&[del], &prod), PolicyDecision::Deny(PolicyReason::MissingWhere));

        // Undeterminable WHERE: deny (fail closed).
        let mut upd2 = stmt(StatementAction::Update);
        upd2.has_where = None;
        assert_eq!(p.evaluate(&[upd2], &dev), PolicyDecision::Deny(PolicyReason::MissingWhere));

        // Trivially-true WHERE: deny.
        let mut del2 = stmt(StatementAction::Delete);
        del2.has_where = Some(true);
        del2.where_trivially_true = true;
        assert_eq!(p.evaluate(&[del2], &dev), PolicyDecision::Deny(PolicyReason::TrivialWhere));
    }

    #[test]
    fn denied_kinds_everywhere() {
        let p = SqlPolicy;
        let dev = ctx(Environment::Development);
        let cases = [
            (StatementAction::Ddl, PolicyReason::DdlNotAllowed),
            (StatementAction::Grant, PolicyReason::GrantNotAllowed),
            (StatementAction::Transaction, PolicyReason::TransactionNotAllowed),
            (StatementAction::Procedure, PolicyReason::ProcedureNotAllowed),
            (StatementAction::Merge, PolicyReason::MergeNotAllowed),
            (StatementAction::Utility, PolicyReason::UtilityNotAllowed),
        ];
        for (action, reason) in cases {
            assert_eq!(p.evaluate(&[stmt(action)], &dev), PolicyDecision::Deny(reason), "{action:?}");
        }
    }

    #[test]
    fn side_effects_denied_even_for_select() {
        let p = SqlPolicy;
        let dev = ctx(Environment::Development);
        let mut s = stmt(StatementAction::Select);
        s.has_side_effects = true;
        assert_eq!(p.evaluate(&[s], &dev), PolicyDecision::Deny(PolicyReason::SideEffectSelect));
    }

    #[test]
    fn empty_or_multi_is_denied_defensively() {
        let p = SqlPolicy;
        let dev = ctx(Environment::Development);
        assert_eq!(p.evaluate(&[], &dev), PolicyDecision::Deny(PolicyReason::MultiStatement));
        let two = [stmt(StatementAction::Select), stmt(StatementAction::Select)];
        assert_eq!(p.evaluate(&two, &dev), PolicyDecision::Deny(PolicyReason::MultiStatement));
    }
}

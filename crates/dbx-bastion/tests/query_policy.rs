//! TASK-005A acceptance: policy matrix over real analyzer output
//! (items 6, 9, 10, 14, 18 at the analyzer->policy boundary).
//!
//! These tests wire `StrictSqlAnalyzer` into `SqlPolicy` end to end:
//! the verdicts below are what the TASK-005B gateway will enforce.

use dbx_bastion::asset::Environment;
use dbx_bastion::query::analyzer::{AnalyzeRequest, SqlAnalyzer, SqlDialect, StrictSqlAnalyzer};
use dbx_bastion::query::policy::{PolicyContext, PolicyDecision, PolicyReason, SqlPolicy};

fn decide(sql: &str, dialect: SqlDialect, env: Environment) -> PolicyDecision {
    let stmts = StrictSqlAnalyzer
        .analyze(&AnalyzeRequest { sql, dialect, default_database: Some("appdb") })
        .unwrap_or_else(|e| panic!("expected analyzable SQL for {sql:?}, got {e}"));
    SqlPolicy.evaluate(&stmts, &PolicyContext::new(env))
}

const DEV: Environment = Environment::Development;
const PROD: Environment = Environment::Production;

// ---- V1 production: read-only -------------------------------------------------

#[test]
fn prod_select_allowed() {
    assert_eq!(decide("SELECT id FROM orders WHERE id = 1", SqlDialect::MySql, PROD), PolicyDecision::Allow);
}

#[test]
fn prod_dml_requires_approval_therefore_never_executes() {
    // Acceptance 18: the approval service does not exist yet, so the
    // TASK-005B gateway denies RequireApproval outright. These must
    // never reach execution in V1.
    for sql in [
        "INSERT INTO orders (id) VALUES (1)",
        "UPDATE orders SET x = 1 WHERE id = 1",
        "DELETE FROM orders WHERE id = 1",
    ] {
        assert_eq!(
            decide(sql, SqlDialect::MySql, PROD),
            PolicyDecision::RequireApproval(PolicyReason::ProductionDmlRequiresApproval),
            "{sql}"
        );
    }
}

#[test]
fn prod_side_effect_select_denied() {
    // Not a pure read: denied even in production, not RequireApproval.
    assert_eq!(
        decide("SELECT * FROM orders FOR UPDATE", SqlDialect::Postgres, PROD),
        PolicyDecision::Deny(PolicyReason::SideEffectSelect)
    );
    assert_eq!(
        decide("SELECT pg_sleep(1)", SqlDialect::Postgres, PROD),
        PolicyDecision::Deny(PolicyReason::SideEffectSelect)
    );
}

// ---- non-prod matrix -----------------------------------------------------------

#[test]
fn nonprod_insert_allowed() {
    assert_eq!(decide("INSERT INTO orders (id) VALUES (1)", SqlDialect::MySql, DEV), PolicyDecision::Allow);
}

#[test]
fn nonprod_insert_select_allowed() {
    // Dual-action INSERT..SELECT passes policy; RBAC still checks both
    // (archive.orders, Insert) and (crm.orders, Select) in the gateway.
    assert_eq!(
        decide("INSERT INTO archive.orders SELECT * FROM crm.orders", SqlDialect::MySql, DEV),
        PolicyDecision::Allow
    );
}

#[test]
fn nonprod_update_delete_need_where() {
    assert_eq!(decide("UPDATE orders SET x = 1 WHERE id = 1", SqlDialect::MySql, DEV), PolicyDecision::Allow);
    assert_eq!(
        decide("UPDATE orders SET x = 1", SqlDialect::MySql, DEV),
        PolicyDecision::Deny(PolicyReason::MissingWhere)
    );
    assert_eq!(decide("DELETE FROM orders WHERE id = 1", SqlDialect::MySql, DEV), PolicyDecision::Allow);
    assert_eq!(decide("DELETE FROM orders", SqlDialect::MySql, DEV), PolicyDecision::Deny(PolicyReason::MissingWhere));
    assert_eq!(
        decide("UPDATE orders SET x = 1 WHERE 1 = 1", SqlDialect::MySql, DEV),
        PolicyDecision::Deny(PolicyReason::TrivialWhere)
    );
}

// ---- denied kinds ---------------------------------------------------------------

#[test]
fn ddl_grant_merge_procedure_transaction_denied() {
    let cases = [
        ("CREATE TABLE t (id INT)", PolicyReason::DdlNotAllowed),
        ("DROP TABLE t", PolicyReason::DdlNotAllowed),
        ("GRANT SELECT ON t TO r", PolicyReason::GrantNotAllowed),
        ("MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN UPDATE SET x = 1", PolicyReason::MergeNotAllowed),
        ("CALL p()", PolicyReason::ProcedureNotAllowed),
        ("BEGIN", PolicyReason::TransactionNotAllowed),
        ("SET NAMES 'utf8mb4'", PolicyReason::UtilityNotAllowed),
    ];
    for (sql, reason) in cases {
        let dialect = if sql == "BEGIN" { SqlDialect::Postgres } else { SqlDialect::MySql };
        assert_eq!(decide(sql, dialect, DEV), PolicyDecision::Deny(reason), "{sql}");
        // Same in production: these are never approval-gated, always denied.
        assert_eq!(decide(sql, dialect, PROD), PolicyDecision::Deny(reason), "{sql} @prod");
    }
}

#[test]
fn select_into_denied_as_side_effect() {
    assert_eq!(
        decide("SELECT * INTO t2 FROM orders", SqlDialect::SqlServer, DEV),
        PolicyDecision::Deny(PolicyReason::SideEffectSelect)
    );
}

// ---- analyzer failures never reach policy ----------------------------------------

#[test]
fn unanalyzable_sql_never_reaches_policy() {
    for sql in ["SELECT 1; DROP TABLE t", "SELECT * FROM t MODEL DIMENSION BY (id) MEASURES (x) RULES (x[1] = 2)", ""] {
        let res = StrictSqlAnalyzer.analyze(&AnalyzeRequest {
            sql,
            dialect: SqlDialect::Generic,
            default_database: Some("appdb"),
        });
        assert!(res.is_err(), "{sql:?} must fail analysis, got {res:?}");
    }
}

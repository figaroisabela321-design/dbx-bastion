//! TASK-005A acceptance: SQL analyzer matrix (items 1-17).
//!
//! Conventions: `default_database = "appdb"` unless noted. A `TableRef`
//! is compared by (database, schema, table) with `NameState` semantics:
//! `P(x)` = Present(x), `NA` = NotApplicable.

use dbx_bastion::query::analyzer::{
    AnalyzeError, AnalyzeRequest, AnalyzedStatement, SqlAnalyzer, SqlDialect, StatementAction, StrictSqlAnalyzer,
    TableRef,
};
use dbx_bastion::rbac::resource::NameState;

fn analyze(sql: &str, dialect: SqlDialect) -> Result<Vec<AnalyzedStatement>, AnalyzeError> {
    StrictSqlAnalyzer.analyze(&AnalyzeRequest { sql, dialect, default_database: Some("appdb") })
}

fn analyze_no_default_db(sql: &str, dialect: SqlDialect) -> Result<Vec<AnalyzedStatement>, AnalyzeError> {
    StrictSqlAnalyzer.analyze(&AnalyzeRequest { sql, dialect, default_database: None })
}

fn one(sql: &str, dialect: SqlDialect) -> AnalyzedStatement {
    let stmts = analyze(sql, dialect).unwrap_or_else(|e| panic!("expected Ok for {sql:?}, got {e}"));
    assert_eq!(stmts.len(), 1);
    stmts.into_iter().next().unwrap()
}

fn tables(refs: &[TableRef]) -> Vec<(String, String, String)> {
    let mut v: Vec<_> =
        refs.iter().map(|r| (format!("{:?}", r.database), format!("{:?}", r.schema), r.table.clone())).collect();
    v.sort();
    v
}

fn p(s: &str) -> String {
    format!("{:?}", NameState::present(s))
}
fn na() -> String {
    format!("{:?}", NameState::NotApplicable)
}

fn u() -> String {
    format!("{:?}", NameState::Unknown)
}

// ---- 1. SELECT / JOIN / CTE / subquery -----------------------------------

#[test]
fn select_simple() {
    let s = one("SELECT id, name FROM orders", SqlDialect::MySql);
    assert_eq!(s.action, StatementAction::Select);
    assert!(s.targets.is_empty());
    assert_eq!(tables(&s.sources), vec![(p("appdb"), na(), "orders".to_string())]);
    assert!(!s.has_side_effects);
}

#[test]
fn select_join() {
    let s = one("SELECT o.id, c.name FROM shop.orders o JOIN crm.customers c ON o.cid = c.id", SqlDialect::MySql);
    assert_eq!(s.action, StatementAction::Select);
    assert_eq!(
        tables(&s.sources),
        vec![(p("crm"), na(), "customers".to_string()), (p("shop"), na(), "orders".to_string())]
    );
}

#[test]
fn cte_names_are_not_physical_tables() {
    let s = one(
        "WITH recent AS (SELECT * FROM orders WHERE total > 100) \
         SELECT * FROM recent r JOIN customers c ON r.cid = c.id",
        SqlDialect::Postgres,
    );
    assert_eq!(s.action, StatementAction::Select);
    // `recent` must not appear; `orders` (inside the CTE) must.
    assert_eq!(
        tables(&s.sources),
        vec![(p("appdb"), u(), "customers".to_string()), (p("appdb"), u(), "orders".to_string())]
    );
}

#[test]
fn nested_subqueries_and_exists() {
    let s = one(
        "SELECT * FROM orders o WHERE EXISTS \
         (SELECT 1 FROM payments p WHERE p.oid = o.id AND p.id IN (SELECT pid FROM refunds))",
        SqlDialect::Postgres,
    );
    assert_eq!(
        tables(&s.sources),
        vec![
            (p("appdb"), u(), "orders".to_string()),
            (p("appdb"), u(), "payments".to_string()),
            (p("appdb"), u(), "refunds".to_string()),
        ]
    );
}

#[test]
fn comments_do_not_hide_or_create_tables() {
    let s = one("SELECT /* FROM hidden */ id FROM orders -- FROM also_hidden", SqlDialect::MySql);
    assert_eq!(tables(&s.sources), vec![(p("appdb"), na(), "orders".to_string())]);
}

// ---- 2. UNION -------------------------------------------------------------

#[test]
fn union_both_sides() {
    let s = one("SELECT id FROM a UNION SELECT id FROM b", SqlDialect::MySql);
    assert_eq!(tables(&s.sources), vec![(p("appdb"), na(), "a".to_string()), (p("appdb"), na(), "b".to_string())]);
}

// ---- 3. INSERT VALUES -----------------------------------------------------

#[test]
fn insert_values() {
    let s = one("INSERT INTO archive.orders (id, total) VALUES (1, 100)", SqlDialect::MySql);
    assert_eq!(s.action, StatementAction::Insert);
    assert_eq!(tables(&s.targets), vec![(p("archive"), na(), "orders".to_string())]);
    assert!(s.sources.is_empty());
}

// ---- 4. INSERT SELECT dual action -----------------------------------------

#[test]
fn insert_select_has_both_actions() {
    let s = one("INSERT INTO archive.orders SELECT * FROM crm.orders", SqlDialect::MySql);
    assert_eq!(s.action, StatementAction::Insert);
    assert_eq!(tables(&s.targets), vec![(p("archive"), na(), "orders".to_string())]);
    // Sources carry Select semantics; the gateway will require
    // (archive.orders, Insert) + (crm.orders, Select).
    assert_eq!(tables(&s.sources), vec![(p("crm"), na(), "orders".to_string())]);
}

// ---- 4b. INSERT edge cases ----------------------------------------------------

#[test]
fn insert_on_conflict_walks_subqueries() {
    let s = one(
        "INSERT INTO orders (id) SELECT id FROM staging ON CONFLICT (id) DO UPDATE SET x = (SELECT max_v FROM cfg)",
        SqlDialect::Postgres,
    );
    assert_eq!(s.action, StatementAction::Insert);
    assert_eq!(tables(&s.targets), vec![(p("appdb"), u(), "orders".to_string())]);
    assert_eq!(
        tables(&s.sources),
        vec![(p("appdb"), u(), "cfg".to_string()), (p("appdb"), u(), "staging".to_string())]
    );
}

#[test]
fn insert_set_syntax() {
    let s = one("INSERT INTO orders SET id = 1, total = (SELECT MAX(total) FROM history)", SqlDialect::MySql);
    assert_eq!(s.action, StatementAction::Insert);
    assert_eq!(tables(&s.sources), vec![(p("appdb"), na(), "history".to_string())]);
}

// ---- 5. UPDATE FROM --------------------------------------------------------

#[test]
fn update_with_where() {
    let s = one("UPDATE orders SET status = 'shipped' WHERE id = 1", SqlDialect::MySql);
    assert_eq!(s.action, StatementAction::Update);
    assert_eq!(tables(&s.targets), vec![(p("appdb"), na(), "orders".to_string())]);
    assert_eq!(s.has_where, Some(true));
    assert!(!s.where_trivially_true);
}

#[test]
fn update_from_collects_source_tables() {
    let s = one("UPDATE orders o SET o.status = 'x' FROM audit_log a WHERE o.id = a.oid", SqlDialect::Postgres);
    assert_eq!(s.action, StatementAction::Update);
    assert_eq!(tables(&s.targets), vec![(p("appdb"), u(), "orders".to_string())]);
    // `orders` is the target; only `audit_log` remains as a source.
    assert_eq!(tables(&s.sources), vec![(p("appdb"), u(), "audit_log".to_string())]);
    assert_eq!(s.has_where, Some(true));
}

// ---- 6. DELETE USING -------------------------------------------------------

#[test]
fn delete_using() {
    let s = one("DELETE FROM orders USING audit_log WHERE orders.id = audit_log.oid", SqlDialect::Postgres);
    assert_eq!(s.action, StatementAction::Delete);
    assert_eq!(tables(&s.targets), vec![(p("appdb"), u(), "orders".to_string())]);
    assert_eq!(tables(&s.sources), vec![(p("appdb"), u(), "audit_log".to_string())]);
    assert_eq!(s.has_where, Some(true));
}

// ---- 7. WHERE presence -----------------------------------------------------

#[test]
fn where_presence_matrix() {
    let no_where = one("UPDATE orders SET status = 'x'", SqlDialect::MySql);
    assert_eq!(no_where.has_where, Some(false));
    assert!(!no_where.where_trivially_true);

    let del_no_where = one("DELETE FROM orders", SqlDialect::MySql);
    assert_eq!(del_no_where.has_where, Some(false));

    for taut in ["WHERE TRUE", "WHERE 1 = 1", "WHERE 'a' = 'a'", "WHERE id = id", "WHERE (TRUE)", "WHERE TRUE AND 1=1"]
    {
        let s = one(&format!("UPDATE orders SET status = 'x' {taut}"), SqlDialect::MySql);
        assert_eq!(s.has_where, Some(true), "{taut}");
        assert!(s.where_trivially_true, "{taut}");
    }

    // A restrictive conjunct defeats the tautology.
    let s = one("UPDATE orders SET status = 'x' WHERE 1 = 1 AND id = 5", SqlDialect::MySql);
    assert_eq!(s.has_where, Some(true));
    assert!(!s.where_trivially_true);

    // `NOT (id = 5)` is restrictive: never misclassified as trivially true.
    let s = one("UPDATE orders SET status = 'x' WHERE NOT (id = 5)", SqlDialect::MySql);
    assert!(!s.where_trivially_true);
}

// ---- 8. multi-statement denied ----------------------------------------------

#[test]
fn multi_statement_denied() {
    let err = analyze("SELECT 1; SELECT 2", SqlDialect::MySql).unwrap_err();
    assert_eq!(err, AnalyzeError::MultiStatement { count: 2 });
}

#[test]
fn multi_statement_cannot_hide_drop() {
    // The classic `analyze_sql_references` gap: the DROP was silently
    // swallowed there. Here the whole request is denied.
    let err = analyze("SELECT 1; DROP TABLE orders", SqlDialect::MySql).unwrap_err();
    assert!(matches!(err, AnalyzeError::MultiStatement { .. }), "{err:?}");
}

// ---- 9. DDL / GRANT / REVOKE precisely identified ---------------------------

#[test]
fn ddl_is_identified_not_errored() {
    for sql in [
        "CREATE TABLE t (id INT PRIMARY KEY)",
        "ALTER TABLE t ADD COLUMN x INT",
        "DROP TABLE t",
        "TRUNCATE TABLE t",
        "CREATE INDEX ix ON t (id)",
    ] {
        let s = one(sql, SqlDialect::MySql);
        assert_eq!(s.action, StatementAction::Ddl, "{sql}");
    }
}

#[test]
fn grant_revoke_are_identified() {
    let g = one("GRANT SELECT ON orders TO reader", SqlDialect::MySql);
    assert_eq!(g.action, StatementAction::Grant);
    let r = one("REVOKE SELECT ON orders FROM reader", SqlDialect::MySql);
    assert_eq!(r.action, StatementAction::Grant);
}

// ---- 10. MERGE / CALL / EXEC denied ------------------------------------------

#[test]
fn merge_call_exec_are_identified() {
    let m = one("MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN UPDATE SET x = 1", SqlDialect::Postgres);
    assert_eq!(m.action, StatementAction::Merge);

    let c = one("CALL my_proc()", SqlDialect::MySql);
    assert_eq!(c.action, StatementAction::Procedure);
}

#[test]
fn transaction_control_is_identified() {
    for (sql, dialect) in [("BEGIN", SqlDialect::Postgres), ("COMMIT", SqlDialect::Postgres)] {
        let s = one(sql, dialect);
        assert_eq!(s.action, StatementAction::Transaction, "{sql}");
    }
    let s = one("SET NAMES 'utf8mb4'", SqlDialect::MySql);
    assert_eq!(s.action, StatementAction::Utility);
}

// ---- 11. Oracle unsupported syntax denied -------------------------------------

#[test]
fn oracle_proprietary_syntax_is_denied() {
    // The MODEL clause is Oracle-proprietary and unparseable here: the
    // request must fail (ParseFailed or Unsupported — either is a
    // denial, never Ok with a partial resource list).
    let res = analyze("SELECT * FROM t MODEL DIMENSION BY (id) MEASURES (x) RULES (x[1] = 2)", SqlDialect::Generic);
    assert!(res.is_err(), "oracle MODEL clause must not analyze cleanly");
}

#[test]
fn connect_by_is_walked_completely() {
    // CONNECT BY *is* parseable by sqlparser 0.62; its expressions are
    // walked, so subqueries there cannot hide tables.
    let s = one("SELECT * FROM t CONNECT BY PRIOR id = pid START WITH id = 1", SqlDialect::Generic);
    assert_eq!(s.action, StatementAction::Select);
    assert_eq!(tables(&s.sources), vec![(p("appdb"), u(), "t".to_string())]);
    let s = one("SELECT * FROM t WHERE id IN (SELECT pid FROM u) CONNECT BY PRIOR id = pid", SqlDialect::Generic);
    assert_eq!(tables(&s.sources), vec![(p("appdb"), u(), "t".to_string()), (p("appdb"), u(), "u".to_string())]);
}

// ---- 12. SQL Server three-part names preserved ----------------------------------

#[test]
fn sqlserver_three_part_names() {
    let s = one("SELECT * FROM mydb.dbo.orders", SqlDialect::SqlServer);
    assert_eq!(tables(&s.sources), vec![(p("mydb"), p("dbo"), "orders".to_string())]);
}

#[test]
fn sqlserver_top_and_brackets() {
    let s = one("SELECT TOP 10 * FROM [dbo].[orders]", SqlDialect::SqlServer);
    assert_eq!(tables(&s.sources), vec![(p("appdb"), p("dbo"), "orders".to_string())]);
}

// ---- 13. MySQL / PG dialect differences ------------------------------------------

#[test]
fn mysql_two_part_is_database_table() {
    let s = one("SELECT * FROM mydb.orders", SqlDialect::MySql);
    assert_eq!(tables(&s.sources), vec![(p("mydb"), na(), "orders".to_string())]);
}

#[test]
fn postgres_two_part_is_schema_table() {
    let s = one("SELECT * FROM public.orders", SqlDialect::Postgres);
    // database falls back to the connection default; schema is explicit.
    assert_eq!(tables(&s.sources), vec![(p("appdb"), p("public"), "orders".to_string())]);
}

#[test]
fn quoted_identifiers_keep_case() {
    let s = one("SELECT * FROM `Orders`", SqlDialect::MySql);
    assert_eq!(tables(&s.sources), vec![(p("appdb"), na(), "Orders".to_string())]);
    let s = one(r#"SELECT * FROM "Orders""#, SqlDialect::Postgres);
    // Quoted identifiers keep case; the unqualified schema is Unknown.
    assert_eq!(tables(&s.sources), vec![(p("appdb"), u(), "Orders".to_string())]);
}

#[test]
fn sqlite_has_no_schema_level() {
    let s = one("SELECT * FROM main.orders", SqlDialect::Sqlite);
    // SQLite: two parts are database.table (attached-database name).
    assert_eq!(tables(&s.sources), vec![(p("main"), na(), "orders".to_string())]);
    let s = one("SELECT * FROM temp.orders", SqlDialect::Sqlite);
    assert_eq!(tables(&s.sources), vec![(p("temp"), na(), "orders".to_string())]);
}

#[test]
fn sqlite_bare_table_is_unknown() {
    // temp -> main resolution order is unknowable statically: a
    // `temp.orders` table would shadow `main.orders`. V1 requires
    // explicit qualification; the bare name resolves to Unknown and
    // the policy denies it before RBAC.
    let s = one("SELECT * FROM orders", SqlDialect::Sqlite);
    assert_eq!(s.sources[0].database, NameState::Unknown);
    assert!(s.sources[0].has_unknown_level());
}

// ---- 14. side-effect SELECTs -------------------------------------------------------

#[test]
fn select_into_is_side_effect() {
    let s = one("SELECT * INTO new_orders FROM orders", SqlDialect::SqlServer);
    assert!(s.has_side_effects);
    assert_eq!(tables(&s.targets), vec![(p("appdb"), u(), "new_orders".to_string())]);
    assert_eq!(tables(&s.sources), vec![(p("appdb"), u(), "orders".to_string())]);
}

#[test]
fn locking_reads_are_side_effects() {
    let s = one("SELECT * FROM orders WHERE id = 1 FOR UPDATE", SqlDialect::Postgres);
    assert!(s.has_side_effects);
    // Still a Select action — policy denies via side_effects, and the
    // reason stays precise.
    assert_eq!(s.action, StatementAction::Select);
}

#[test]
fn unknown_functions_are_side_effects() {
    for sql in ["SELECT pg_sleep(1)", "SELECT nextval('order_seq')", "SELECT my_udf(id) FROM orders"] {
        let s = one(sql, SqlDialect::Postgres);
        assert!(s.has_side_effects, "{sql}");
    }
}

#[test]
fn pure_functions_are_fine() {
    let s = one(
        "SELECT COUNT(*), NOW(), COALESCE(name, 'n/a'), SUBSTRING(code, 1, 3), \
         ROW_NUMBER() OVER (PARTITION BY cid ORDER BY id) FROM orders GROUP BY cid",
        SqlDialect::MySql,
    );
    assert!(!s.has_side_effects);
    assert_eq!(tables(&s.sources), vec![(p("appdb"), na(), "orders".to_string())]);
}

// ---- 15. aliases / nesting: no omissions, no false positives -------------------------

#[test]
fn derived_tables_and_aliases() {
    let s = one(
        "SELECT t.id FROM (SELECT id, cid FROM orders WHERE total > 0) t \
         JOIN (SELECT id FROM customers) c ON t.cid = c.id",
        SqlDialect::MySql,
    );
    // MySQL has no schema level: NotApplicable is legitimate here.
    assert_eq!(
        tables(&s.sources),
        vec![(p("appdb"), na(), "customers".to_string()), (p("appdb"), na(), "orders".to_string())]
    );
}

#[test]
fn self_join_alias_does_not_duplicate() {
    let s = one("SELECT a.id, b.id FROM orders a JOIN orders b ON a.pid = b.id", SqlDialect::MySql);
    assert_eq!(tables(&s.sources), vec![(p("appdb"), na(), "orders".to_string())]);
}

#[test]
fn four_part_names_are_unsupported() {
    let res = analyze("SELECT * FROM srv.mydb.dbo.orders", SqlDialect::SqlServer);
    assert!(matches!(res, Err(AnalyzeError::Unsupported { .. })), "{res:?}");
}

// ---- 16. empty resources: complete vs masked --------------------------------------------

#[test]
fn select_1_is_complete_with_empty_resources() {
    // Genuinely no tables: Ok with empty resources is CORRECT here —
    // completeness was proven, not assumed.
    let s = one("SELECT 1", SqlDialect::MySql);
    assert_eq!(s.action, StatementAction::Select);
    assert!(s.sources.is_empty() && s.targets.is_empty());
}

#[test]
fn empty_sql_is_denied() {
    assert_eq!(analyze("   ", SqlDialect::MySql).unwrap_err(), AnalyzeError::EmptySql);
}

#[test]
fn parse_failure_is_denied() {
    let res = analyze("SELECT FROM WHERE", SqlDialect::MySql);
    assert!(matches!(res, Err(AnalyzeError::ParseFailed { .. })), "{res:?}");
}

#[test]
fn exotic_statements_are_unsupported_not_select() {
    // INSTALL / VACUUM parse but are outside the V1 positive list.
    for sql in ["INSTALL foo", "VACUUM orders"] {
        let res = analyze(sql, SqlDialect::Generic);
        assert!(res.is_err(), "{sql} must not analyze cleanly: {res:?}");
    }
}

// ---- 17. unknown actions never default to Select ------------------------------------------

#[test]
fn unknown_statement_is_never_select() {
    // Whatever this parses to, it must not come back as Select.
    for sql in ["VACUUM orders", "ANALYZE orders", "CHECKPOINT"] {
        if let Ok(stmts) = analyze(sql, SqlDialect::Generic) {
            for s in stmts {
                assert_ne!(s.action, StatementAction::Select, "{sql}");
            }
        }
    }
}

// ---- default database handling ---------------------------------------------------------------

#[test]
fn no_default_db_leaves_database_unknown() {
    // Standalone mode with no connection default: the database is
    // Unknown, never guessed; MySQL still has no schema level.
    let s = analyze_no_default_db("SELECT * FROM orders", SqlDialect::MySql).unwrap().into_iter().next().unwrap();
    assert_eq!(tables(&s.sources), vec![(u(), na(), "orders".to_string())]);
}

// ---- security fix: identity resolution --------------------------------------
// Unqualified names on dialects with a real schema level (PG/SQL Server)
// resolve to Unknown, never NotApplicable. Rationale: at the RBAC
// layer a wildcard rule WOULD match an Unknown level while a
// table-level DENY on the real schema would not fire — so the policy
// must deny before RBAC. This test locks the analyzer half of that.

#[test]
fn unqualified_schema_is_unknown_not_not_applicable() {
    for dialect in [SqlDialect::Postgres, SqlDialect::SqlServer, SqlDialect::Generic] {
        let s = one("SELECT * FROM orders", dialect);
        assert_eq!(s.sources[0].schema, NameState::Unknown, "{dialect:?}");
        assert!(s.sources[0].has_unknown_level());
    }
    // MySQL genuinely has no schema level: NotApplicable stays legitimate.
    let s = one("SELECT * FROM orders", SqlDialect::MySql);
    assert_eq!(s.sources[0].schema, NameState::NotApplicable);
    assert!(!s.sources[0].has_unknown_level());
}

#[test]
fn postgres_folds_unquoted_identifiers() {
    // Unquoted -> lower case (the real PG object); quoted stays literal.
    let s = one("SELECT * FROM ORDERS", SqlDialect::Postgres);
    assert_eq!(s.sources[0].table, "orders");
    let s = one(r#"SELECT * FROM "ORDERS""#, SqlDialect::Postgres);
    assert_eq!(s.sources[0].table, "ORDERS");
}

// ---- security fix: function identity -----------------------------------------

#[test]
fn qualified_functions_need_proven_builtin_identity() {
    // pg_catalog.now() is provably the builtin: fine.
    let s = one("SELECT pg_catalog.now()", SqlDialect::Postgres);
    assert!(!s.has_side_effects);
    // A user-schema qualification may shadow a builtin with a UDF: deny.
    let s = one("SELECT myschema.now()", SqlDialect::Postgres);
    assert!(s.has_side_effects);
    let s = one("SELECT public.my_udf(id) FROM public.orders", SqlDialect::Postgres);
    assert!(s.has_side_effects);
}

// ---- security fix: data-modifying CTEs ---------------------------------------

#[test]
fn data_modifying_ctes_are_rejected() {
    // Writes disguised as query structure: never misreported as a pure
    // Select with an empty resource list.
    for sql in [
        "WITH d AS (DELETE FROM t RETURNING *) SELECT * FROM d",
        "WITH i AS (INSERT INTO t SELECT * FROM s RETURNING *) SELECT * FROM i",
        "WITH u AS (UPDATE t SET x = 1 RETURNING *) SELECT * FROM u",
    ] {
        let res = analyze(sql, SqlDialect::Postgres);
        assert!(res.is_err(), "{sql} must be rejected, got {res:?}");
    }
}

// ---- perf smoke: analysis latency baseline ------------------------------------------------------
///
/// Decision 11: baselines for AST latency; security checks are never
/// skipped for performance. These are generous debug-build bounds —
/// they catch pathological regressions, not micro-optimizations.

#[test]
fn analysis_latency_baseline() {
    let queries = [
        ("simple", "SELECT id FROM orders WHERE id = 1", SqlDialect::MySql),
        (
            "join_cte",
            "WITH r AS (SELECT * FROM orders) SELECT * FROM r JOIN customers c ON r.cid = c.id WHERE c.x IN (SELECT y FROM z)",
            SqlDialect::Postgres,
        ),
        ("insert_select", "INSERT INTO a.b SELECT * FROM c.d JOIN e.f ON 1=1", SqlDialect::MySql),
    ];
    for (name, sql, dialect) in queries {
        let start = std::time::Instant::now();
        let _ = analyze(sql, dialect).expect("baseline query must analyze");
        let elapsed = start.elapsed();
        println!("analyze[{name}]: {elapsed:?}");
        assert!(elapsed.as_secs() < 1, "analyze[{name}] took {elapsed:?}, investigate");
    }
}

#[test]
fn pg_requires_pg_catalog_qualification() {
    // V1 (strict): on PostgreSQL only an explicit `pg_catalog.<pure>`
    // call is proven side-effect-free.
    let s = one("SELECT pg_catalog.now()", SqlDialect::Postgres);
    assert!(!s.has_side_effects);
    let s = one("SELECT pg_catalog.count(*) FROM public.orders", SqlDialect::Postgres);
    assert!(!s.has_side_effects);
    // Unqualified: search_path / UDF shadowing / overload ambiguity.
    let s = one("SELECT now()", SqlDialect::Postgres);
    assert!(s.has_side_effects);
    let s = one("SELECT count(*) FROM public.orders", SqlDialect::Postgres);
    assert!(s.has_side_effects);
    // User-schema qualification: proven shadowing risk.
    let s = one("SELECT public.now()", SqlDialect::Postgres);
    assert!(s.has_side_effects);
    let s = one("SELECT myschema.coalesce(a, b) FROM public.t", SqlDialect::Postgres);
    assert!(s.has_side_effects);
}

#[test]
fn pg_function_overload_ambiguity_is_denied_unqualified() {
    // `round` is overloaded in PG (round(numeric), round(numeric,int));
    // an unqualified call cannot prove which implementation runs, and a
    // UDF could shadow the name via search_path.
    let s = one("SELECT round(price) FROM public.t", SqlDialect::Postgres);
    assert!(s.has_side_effects);
    let s = one("SELECT round(price, 2) FROM public.t", SqlDialect::Postgres);
    assert!(s.has_side_effects);
    // Explicit pg_catalog qualification pins the builtin identity.
    let s = one("SELECT pg_catalog.round(price) FROM public.t", SqlDialect::Postgres);
    assert!(!s.has_side_effects);
    // `substr(...)` parses as Expr::Substring (builtin syntax, not a
    // function call); it is pure on all dialects.
    let s = one("SELECT substr(name, 1, 3) FROM public.t", SqlDialect::Postgres);
    assert!(!s.has_side_effects);
}

#[test]
fn non_pg_dialects_keep_unqualified_pure_calls() {
    // MySQL / SQL Server have no search_path equivalent for builtins.
    let s = one("SELECT NOW()", SqlDialect::MySql);
    assert!(!s.has_side_effects);
    let s = one("SELECT now()", SqlDialect::SqlServer);
    assert!(!s.has_side_effects);
    let s = one("SELECT sys.now()", SqlDialect::SqlServer);
    assert!(!s.has_side_effects);
}

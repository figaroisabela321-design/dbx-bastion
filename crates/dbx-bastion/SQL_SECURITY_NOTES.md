# SQL Analysis Notes for DB Bastion (P4/P5 input)

Recorded during TASK-001 from direct inspection of `t8y2/dbx` @ `e013fff`.
Do **not** treat keyword detection, regex table-name extraction, or the MCP
policy gate as a complete bastion security boundary.

## What actually exists in DBX today

| Facility | Location | Verdict for bastion use |
|---|---|---|
| `analyze_sql_references(sql, dialect)` | `crates/dbx-sql-core/src/sql_analysis.rs:148` | **True AST** (`sqlparser` 0.62, `visitor` feature). Returns `SqlReferenceAnalysis { tables, columns, scopes, group_by_violations }`. This is the primary candidate for per-table RBAC and WHERE-clause detection. Must still be evaluated for dialect coverage and edge cases (CTEs, subqueries, multi-statement input) in P4/P5. |
| `classify_sql_risk_for_database` | `crates/dbx-sql-core/src/sql_risk.rs:697` | Parses via `Parser::parse_sql` but output is only 4 coarse buckets (`SqlRisk::{ReadOnly, Write, Ddl, Transaction}`). Too coarse to drive policy alone; usable as a hint at most. |
| `is_write_sql` / `is_write_sql_for_database` | `crates/dbx-sql-core/src/query_execution_sql.rs:421` | **Lexical keyword-prefix whitelist** (`is_write_sql_statement`, ~lines 853–898): strips comments/literals, then checks the first keyword against `READ_SQL_KEYWORDS`. **Not AST.** Must NOT be used for bastion security decisions. |
| `production_safety::{is_production_database, targets_production_database, sql_references_disallowed_database}` | `crates/dbx-core/src/safety/production_safety.rs` | **Regex-based** table/database extraction (`LazyLock<Regex>`: `DML_TARGET_RE`, `DDL_OBJECT_TARGET_RE`, `PRIVILEGE_TARGET_RE`, …). Useful heuristics for the existing single-user product; **not** a sound basis for multi-tenant authorization. |
| `risk_metrics.rs` | `crates/dbx-core/src/safety/risk_metrics.rs` | Prometheus observability metrics (counters/gauges). **Unrelated to SQL risk.** The name is misleading; do not cite it as "SQL risk". |
| `safety_report.rs` | `crates/dbx-core/src/safety/safety_report.rs` | **Dead code**: not declared in `safety/mod.rs`, references a non-existent `crate::sql_risk::ImpactReport`. Not compiled. Ignore. |
| `AstSandbox` | `crates/dbx-sql-schema/src/sql_parser/ast_filter.rs` | AST sandbox filter used by MCP/Agent paths. Worth evaluating in P4/P5 as a complementary guard, but it serves the agent threat model, not the bastion RBAC model. |
| `mcp_policy::ensure_sql` | `crates/dbx-web/src/routes/mcp_policy.rs` | Applied to `execute_query`/`execute_batch` only. `execute_script`, `execute_in_transaction`, `execute_script_with_2pc` bypass it today. This is exactly the bypass class the QueryGateway firewall (P4/P9) must close. |

## Consequences for P4 (QueryGateway) / P5 (Policy engine)

1. Policy decisions must be built on `analyze_sql_references` + direct
   `sqlparser::ast::Statement` matching. Unknown/unparseable SQL fails closed.
2. Multi-statement input: `split_sql_statements_for_database` exists, but V1
   policy is deny-by-default for multi-statement; splitting is not a
   substitute for per-statement authorization.
3. WHERE-clause detection for UPDATE/DELETE must come from the AST
   (`has_where` in `SqlAnalysis`), never from substring search.
4. Statement-kind mapping (`SqlKind`) must be exhaustive over the dialects
   DBX supports (MySQL, Postgres, Oracle, SQL Server, …); `Unknown` maps to
   deny.
5. The gateway firewall must cover **all** execution paths enumerated in the
   TASK-001 report (`execute_sql_statement`, `execute_multi_core`,
   `execute_statements[_in_transaction]`, manual-transaction trio,
   `execute_schema_diff_deploy`), not just `/query/execute`.

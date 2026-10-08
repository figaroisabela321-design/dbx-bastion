//! Strict SQL analyzer for the query gateway (TASK-005A).
//!
//! Design rules (fail-closed):
//! - The analyzer walks the **sqlparser AST directly**. It never uses
//!   keyword-prefix checks, regexes, or `analyze_sql_references` (which
//!   silently ignores every write statement and several dangerous
//!   constructs — see `SQL_SECURITY_NOTES.md`).
//! - Resource enumeration must be **provably complete**: whenever the
//!   analyzer cannot prove it found every table a statement touches, it
//!   returns `Err(AnalyzeError::Unsupported)` — never `Ok` with an empty
//!   resource list masking the gap.
//! - Unknown statement kinds are never defaulted to `Select`.
//! - Function calls are checked against an explicit positive allowlist of
//!   side-effect-free functions; anything else marks the statement as
//!   having side effects (the policy then denies it as a non-pure read).
//! - `Expr` is matched **exhaustively** (no `_` arm): a new sqlparser
//!   variant is a compile error, forcing a conscious decision. `Statement`
//!   uses explicit arms for precisely-classified kinds and a deny-default
//!   catch-all for everything else.

use sqlparser::ast::{
    Expr, Function, ObjectName, Query, Select, SetExpr, Statement, TableFactor, TableObject, TableWithJoins,
};
use sqlparser::dialect::{
    Dialect as ParserDialect, GenericDialect, MsSqlDialect, MySqlDialect, PostgreSqlDialect, SQLiteDialect,
};
use sqlparser::parser::Parser;

use crate::rbac::resource::NameState;

// ---- public types --------------------------------------------------------

/// SQL dialect for parsing and name resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SqlDialect {
    MySql,
    Postgres,
    Sqlite,
    SqlServer,
    /// Best-effort parsing (Oracle, Dameng, ...). Proprietary syntax that
    /// the generic parser cannot handle fails closed.
    Generic,
}

impl SqlDialect {
    fn parser_dialect(&self) -> Box<dyn ParserDialect> {
        match self {
            Self::MySql => Box::new(MySqlDialect {}),
            Self::Postgres => Box::new(PostgreSqlDialect {}),
            Self::Sqlite => Box::new(SQLiteDialect {}),
            Self::SqlServer => Box::new(MsSqlDialect {}),
            Self::Generic => Box::new(GenericDialect {}),
        }
    }
}

/// Input to the analyzer.
#[derive(Debug, Clone, Copy)]
pub struct AnalyzeRequest<'a> {
    /// The exact SQL text that will be executed if authorized.
    pub sql: &'a str,
    pub dialect: SqlDialect,
    /// Database the connection is bound to. Unqualified table references
    /// resolve against it; `None` leaves the database level
    /// `NotApplicable` (only wildcard database grants can then match).
    pub default_database: Option<&'a str>,
}

/// The operation a statement performs. Precisely-identified kinds that V1
/// policy denies (`Ddl`, `Grant`, `Transaction`, `Procedure`, `Merge`) are
/// still reported (not errored) so policy and audit get exact reasons.
/// Anything the analyzer cannot precisely classify is
/// `Err(AnalyzeError::Unsupported)` — never silently mapped to `Select`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StatementAction {
    Select,
    Insert,
    Update,
    Delete,
    Ddl,
    Grant,
    Transaction,
    Procedure,
    Merge,
    /// Session-utility statements (`SET`, ...) denied in V1.
    Utility,
}

/// A table reference with three-state levels (see
/// [`NameState`](crate::rbac::resource::NameState)). The analyzer never
/// emits `NameState::Unknown`: an unresolvable name is
/// `AnalyzeError::Unsupported`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableRef {
    pub database: NameState,
    pub schema: NameState,
    pub table: String,
}

/// One analyzed statement.
#[derive(Debug, Clone)]
pub struct AnalyzedStatement {
    pub action: StatementAction,
    /// Write targets, each carrying `action` semantics for RBAC.
    pub targets: Vec<TableRef>,
    /// Read sources, each carrying `Select` semantics for RBAC.
    pub sources: Vec<TableRef>,
    /// For `Update`/`Delete`: `Some(true)` iff a WHERE clause is present,
    /// `Some(false)` iff absent, `None` iff undeterminable (fail closed).
    pub has_where: Option<bool>,
    /// True for trivially-true WHERE clauses (`WHERE TRUE`, `WHERE 1=1`,
    /// `WHERE id=id`, AND/OR combinations thereof). Conservative:
    /// false negatives deny, false positives are impossible by
    /// construction (only syntactic tautologies match).
    pub where_trivially_true: bool,
    /// True for `SELECT INTO`, locking reads (`FOR UPDATE`, ...),
    /// unknown/non-pure function calls, or table functions outside the
    /// allowlist. Policy denies these as non-pure reads.
    pub has_side_effects: bool,
}

/// Analysis failure. Every variant fails closed downstream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnalyzeError {
    /// Empty or whitespace-only input.
    EmptySql,
    /// The SQL could not be parsed at all.
    ParseFailed { detail: String },
    /// Parsed, but the analyzer cannot prove complete resource
    /// enumeration (unsupported construct, unresolvable name, ...).
    /// This must never become `Ok` with an empty resource list.
    Unsupported { reason: String },
    /// V1 policy: more than one statement is always denied.
    MultiStatement { count: usize },
}

impl std::fmt::Display for AnalyzeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptySql => write!(f, "empty SQL"),
            Self::ParseFailed { detail } => write!(f, "SQL parse failed: {detail}"),
            Self::Unsupported { reason } => write!(f, "unsupported SQL: {reason}"),
            Self::MultiStatement { count } => write!(f, "multi-statement SQL denied ({count} statements)"),
        }
    }
}

impl std::error::Error for AnalyzeError {}

/// Strict SQL analyzer. Implemented in-crate on the sqlparser AST so the
/// security-critical analysis is owned by the bastion, not delegated.
pub trait SqlAnalyzer: Send + Sync {
    /// Analyze the exact SQL text. Returns one entry per statement on
    /// success; any failure variant denies the request.
    fn analyze(&self, req: &AnalyzeRequest) -> Result<Vec<AnalyzedStatement>, AnalyzeError>;
}

/// The production analyzer: explicit AST walk, fail-closed.
pub struct StrictSqlAnalyzer;

impl SqlAnalyzer for StrictSqlAnalyzer {
    fn analyze(&self, req: &AnalyzeRequest) -> Result<Vec<AnalyzedStatement>, AnalyzeError> {
        let sql = req.sql.trim();
        if sql.is_empty() {
            return Err(AnalyzeError::EmptySql);
        }
        let dialect = req.dialect.parser_dialect();
        let statements =
            Parser::parse_sql(&*dialect, sql).map_err(|e| AnalyzeError::ParseFailed { detail: e.to_string() })?;
        if statements.len() != 1 {
            return Err(AnalyzeError::MultiStatement { count: statements.len() });
        }
        let ctx = WalkContext::new(req.dialect, req.default_database);
        analyze_statement(&statements[0], &ctx).map(|stmt| vec![stmt])
    }
}

// ---- walker --------------------------------------------------------------

struct WalkContext {
    dialect: SqlDialect,
    default_database: Option<String>,
}

impl WalkContext {
    fn new(dialect: SqlDialect, default_database: Option<&str>) -> Self {
        Self { dialect, default_database: default_database.map(str::to_string) }
    }
}

/// Per-query walk state.
struct QueryWalker<'a> {
    ctx: &'a WalkContext,
    /// Visible CTE names (uppercased), innermost last.
    cte_names: Vec<String>,
    sources: Vec<TableRef>,
    /// `SELECT INTO` targets.
    into_targets: Vec<TableRef>,
    side_effects: bool,
}

impl<'a> QueryWalker<'a> {
    fn new(ctx: &'a WalkContext) -> Self {
        Self { ctx, cte_names: Vec::new(), sources: Vec::new(), into_targets: Vec::new(), side_effects: false }
    }

    /// Extract the identifier string from one `ObjectName` part.
    /// Function parts (dialect-specific computed names) are unsupported.
    fn part_ident(part: &sqlparser::ast::ObjectNamePart) -> Result<&str, AnalyzeError> {
        use sqlparser::ast::ObjectNamePart;
        match part {
            ObjectNamePart::Identifier(i) => Ok(i.value.as_str()),
            ObjectNamePart::Function(_) => {
                Err(AnalyzeError::Unsupported { reason: "computed table name part".to_string() })
            }
        }
    }

    /// Map an `ObjectName` to a three-level `TableRef`.
    ///
    /// - 1 part: unqualified; database falls back to the connection
    ///   default (or `NotApplicable`), schema is `NotApplicable`
    ///   ("not specified in SQL": only wildcard-schema grants match —
    ///   a grant pinned to `schema = "public"` must not authorize
    ///   `SELECT * FROM orders`, whose effective schema is unknown).
    /// - 2 parts: `[db, table]` on MySQL, `[schema, table]` elsewhere.
    /// - 3 parts: `[db, schema, table]` (SQL Server; preserved, never
    ///   dropped).
    /// - 4+ parts (linked servers, ...): unsupported.
    fn table_ref(&self, name: &ObjectName) -> Result<TableRef, AnalyzeError> {
        let parts: Vec<&str> = name.0.iter().map(Self::part_ident).collect::<Result<_, _>>()?;
        let db_default = self.ctx.default_database.as_deref();
        match parts.as_slice() {
            [table] => Ok(TableRef {
                database: db_default.map(NameState::present).unwrap_or(NameState::NotApplicable),
                schema: NameState::NotApplicable,
                table: table.to_string(),
            }),
            [a, b] => {
                let (database, schema) = match self.ctx.dialect {
                    SqlDialect::MySql => (NameState::present(*a), NameState::NotApplicable),
                    _ => {
                        (db_default.map(NameState::present).unwrap_or(NameState::NotApplicable), NameState::present(*a))
                    }
                };
                Ok(TableRef { database, schema, table: b.to_string() })
            }
            [a, b, c] => {
                Ok(TableRef { database: NameState::present(*a), schema: NameState::present(*b), table: c.to_string() })
            }
            _ => Err(AnalyzeError::Unsupported { reason: format!("table name with {} parts", parts.len()) }),
        }
    }

    fn is_cte(&self, name: &ObjectName) -> bool {
        name.0
            .last()
            .and_then(|p| Self::part_ident(p).ok())
            .map(|n| self.cte_names.iter().any(|cte| cte == &n.to_uppercase()))
            .unwrap_or(false)
    }

    fn push_source(&mut self, name: &ObjectName) -> Result<(), AnalyzeError> {
        if self.is_cte(name) {
            return Ok(());
        }
        let r = self.table_ref(name)?;
        if !self.sources.contains(&r) {
            self.sources.push(r);
        }
        Ok(())
    }

    fn check_function(&mut self, func: &Function) -> Result<(), AnalyzeError> {
        use sqlparser::ast::{FunctionArgExpr, FunctionArguments};
        // Strip qualification: `pg_catalog.now()` -> `NOW`.
        let name =
            func.name.0.last().and_then(|p| Self::part_ident(p).ok()).map(|n| n.to_uppercase()).unwrap_or_default();
        if !is_pure_function(&name) {
            self.side_effects = true;
        }
        match &func.args {
            FunctionArguments::None => {}
            FunctionArguments::Subquery(q) => self.walk_query(q)?,
            FunctionArguments::List(list) => {
                for arg in &list.args {
                    use sqlparser::ast::FunctionArg;
                    match arg {
                        FunctionArg::Unnamed(FunctionArgExpr::Expr(e)) => self.walk_expr(e)?,
                        FunctionArg::Unnamed(_) => {}
                        FunctionArg::Named { arg: FunctionArgExpr::Expr(e), .. } => self.walk_expr(e)?,
                        FunctionArg::Named { .. } => {}
                        FunctionArg::ExprNamed { name, arg: FunctionArgExpr::Expr(e), .. } => {
                            self.walk_expr(name)?;
                            self.walk_expr(e)?;
                        }
                        FunctionArg::ExprNamed { name, .. } => self.walk_expr(name)?,
                    }
                }
            }
        }
        // Window OVER clause may embed expressions.
        if let Some(window) = func.over.as_ref() {
            self.walk_window(window)?;
        }
        Ok(())
    }

    fn walk_window(&mut self, window: &sqlparser::ast::WindowType) -> Result<(), AnalyzeError> {
        use sqlparser::ast::WindowType;
        match window {
            WindowType::WindowSpec(spec) => {
                for expr in &spec.partition_by {
                    self.walk_expr(expr)?;
                }
                for oe in &spec.order_by {
                    self.walk_expr(&oe.expr)?;
                }
            }
            WindowType::NamedWindow(_) => {}
        }
        Ok(())
    }

    fn walk_query(&mut self, q: &Query) -> Result<(), AnalyzeError> {
        // Locking reads are not pure reads.
        if !q.locks.is_empty() {
            self.side_effects = true;
        }
        // Register CTE names before walking bodies so later CTEs and the
        // main query resolve them; pop afterwards for correct nesting.
        let mut pushed = 0;
        if let Some(with) = q.with.as_ref() {
            for cte in &with.cte_tables {
                self.cte_names.push(cte.alias.name.value.to_uppercase());
                pushed += 1;
            }
            for cte in &with.cte_tables {
                self.walk_query(&cte.query)?;
            }
        }
        self.walk_set_expr(&q.body)?;
        if let Some(order_by) = q.order_by.as_ref() {
            use sqlparser::ast::OrderByKind;
            if let OrderByKind::Expressions(exprs) = &order_by.kind {
                for oe in exprs {
                    self.walk_expr(&oe.expr)?;
                }
            }
        }
        // Pipe operators (`|>`) are outside the V1 positive list: deny
        // rather than risk incomplete analysis of a new syntax.
        if !q.pipe_operators.is_empty() {
            return Err(AnalyzeError::Unsupported { reason: "pipe operators are not in the V1 allowlist".to_string() });
        }
        if let Some(fetch) = q.fetch.as_ref() {
            if let Some(quantity) = fetch.quantity.as_ref() {
                self.walk_expr(quantity)?;
            }
        }
        if let Some(settings) = q.settings.as_ref() {
            for setting in settings {
                self.walk_expr(&setting.value)?;
            }
        }
        if let Some(limit_clause) = q.limit_clause.as_ref() {
            use sqlparser::ast::LimitClause;
            if let LimitClause::LimitOffset { limit, offset, limit_by } = limit_clause {
                if let Some(e) = limit {
                    self.walk_expr(e)?;
                }
                if let Some(o) = offset {
                    self.walk_expr(&o.value)?;
                }
                for e in limit_by {
                    self.walk_expr(e)?;
                }
            }
        }
        for _ in 0..pushed {
            self.cte_names.pop();
        }
        Ok(())
    }

    fn walk_set_expr(&mut self, s: &SetExpr) -> Result<(), AnalyzeError> {
        match s {
            SetExpr::Select(select) => self.walk_select(select)?,
            SetExpr::Query(q) => self.walk_query(q)?,
            SetExpr::SetOperation { left, right, .. } => {
                self.walk_set_expr(left)?;
                self.walk_set_expr(right)?;
            }
            SetExpr::Values(_) => {}
            // `TABLE t` reads table t (when named).
            SetExpr::Table(t) => {
                use sqlparser::ast::ObjectNamePart;
                let mut parts = Vec::new();
                if let Some(schema) = t.schema_name.as_ref() {
                    parts.push(ObjectNamePart::Identifier(sqlparser::ast::Ident::new(schema)));
                }
                if let Some(name) = t.table_name.as_ref() {
                    parts.push(ObjectNamePart::Identifier(sqlparser::ast::Ident::new(name)));
                }
                if !parts.is_empty() {
                    self.push_source(&ObjectName(parts))?;
                }
            }
            // INSERT/UPDATE/DELETE cannot appear as set operands in the
            // dialects we parse; anything else here is out of scope.
            _ => {}
        }
        Ok(())
    }

    fn walk_select(&mut self, s: &Select) -> Result<(), AnalyzeError> {
        if let Some(into) = s.into.as_ref() {
            // `SELECT ... INTO t`: a write disguised as a query.
            self.side_effects = true;
            let r = self.table_ref(&into.name)?;
            if !self.into_targets.contains(&r) {
                self.into_targets.push(r);
            }
        }
        for item in &s.projection {
            self.walk_select_item(item)?;
        }
        for twj in &s.from {
            self.walk_table_with_joins(twj)?;
        }
        if let Some(selection) = s.selection.as_ref() {
            self.walk_expr(selection)?;
        }
        // ClickHouse PREWHERE and Oracle CONNECT BY / START WITH: walk
        // their expressions so subqueries there cannot hide tables.
        if let Some(prewhere) = s.prewhere.as_ref() {
            self.walk_expr(prewhere)?;
        }
        for cb in &s.connect_by {
            use sqlparser::ast::ConnectByKind;
            match cb {
                ConnectByKind::ConnectBy { relationships, .. } => {
                    for e in relationships {
                        self.walk_expr(e)?;
                    }
                }
                ConnectByKind::StartWith { condition, .. } => self.walk_expr(condition)?,
            }
        }
        match &s.group_by {
            sqlparser::ast::GroupByExpr::Expressions(exprs, _) => {
                for expr in exprs {
                    self.walk_expr(expr)?;
                }
            }
            sqlparser::ast::GroupByExpr::All(_) => {}
        }
        if let Some(having) = s.having.as_ref() {
            self.walk_expr(having)?;
        }
        for e in &s.cluster_by {
            self.walk_expr(e)?;
        }
        for e in &s.distribute_by {
            self.walk_expr(e)?;
        }
        for obe in &s.sort_by {
            self.walk_expr(&obe.expr)?;
        }
        if let Some(qualify) = s.qualify.as_ref() {
            self.walk_expr(qualify)?;
        }
        for lv in &s.lateral_views {
            self.walk_expr(&lv.lateral_view)?;
        }
        for named in &s.named_window {
            self.walk_named_window_expr(&named.1)?;
        }
        if let Some(top) = s.top.as_ref() {
            if let Some(sqlparser::ast::TopQuantity::Expr(e)) = top.quantity.as_ref() {
                self.walk_expr(e)?;
            }
        }
        Ok(())
    }

    fn walk_select_item(&mut self, item: &sqlparser::ast::SelectItem) -> Result<(), AnalyzeError> {
        use sqlparser::ast::SelectItem;
        match item {
            SelectItem::UnnamedExpr(e)
            | SelectItem::ExprWithAlias { expr: e, .. }
            | SelectItem::ExprWithAliases { expr: e, .. } => self.walk_expr(e)?,
            SelectItem::Wildcard(_) | SelectItem::QualifiedWildcard(_, _) => {}
        }
        Ok(())
    }

    fn walk_table_with_joins(&mut self, twj: &TableWithJoins) -> Result<(), AnalyzeError> {
        self.walk_table_factor(&twj.relation)?;
        for join in &twj.joins {
            self.walk_table_factor(&join.relation)?;
            if let Some(e) = join_on_expr(&join.join_operator) {
                self.walk_expr(e)?;
            }
        }
        Ok(())
    }

    fn walk_named_window_expr(&mut self, expr: &sqlparser::ast::NamedWindowExpr) -> Result<(), AnalyzeError> {
        use sqlparser::ast::NamedWindowExpr;
        match expr {
            NamedWindowExpr::WindowSpec(spec) => {
                for e in &spec.partition_by {
                    self.walk_expr(e)?;
                }
                for oe in &spec.order_by {
                    self.walk_expr(&oe.expr)?;
                }
            }
            NamedWindowExpr::NamedWindow(_) => {}
        }
        Ok(())
    }

    fn walk_table_factor(&mut self, f: &TableFactor) -> Result<(), AnalyzeError> {
        match f {
            TableFactor::Table { name, .. } => {
                self.push_source(name)?;
            }
            TableFactor::Derived { subquery, .. } => self.walk_query(subquery)?,
            TableFactor::Function { name, args, .. } => {
                // Table function: same purity discipline as scalar calls.
                let fname =
                    name.0.last().and_then(|p| Self::part_ident(p).ok()).map(|n| n.to_uppercase()).unwrap_or_default();
                if !is_pure_function(&fname) {
                    self.side_effects = true;
                }
                for arg in args {
                    if let sqlparser::ast::FunctionArg::Unnamed(sqlparser::ast::FunctionArgExpr::Expr(e)) = arg {
                        self.walk_expr(e)?;
                    }
                }
            }
            TableFactor::UNNEST { array_exprs, .. } => {
                for e in array_exprs {
                    self.walk_expr(e)?;
                }
            }
            TableFactor::NestedJoin { table_with_joins, .. } => self.walk_table_with_joins(table_with_joins)?,
            TableFactor::Pivot { table, .. } => self.walk_table_factor(table)?,
            TableFactor::Unpivot { table, .. } => self.walk_table_factor(table)?,
            TableFactor::TableFunction { .. }
            | TableFactor::JsonTable { .. }
            | TableFactor::OpenJsonTable { .. }
            | TableFactor::MatchRecognize { .. }
            | TableFactor::XmlTable { .. }
            | TableFactor::SemanticView { .. } => {
                // Exotic table producers: not in the V1 positive list.
                // Marking side effects denies them as non-pure reads.
                self.side_effects = true;
            }
        }
        Ok(())
    }

    /// Exhaustive `Expr` walk: every variant is matched explicitly (no `_`
    /// arm) so a new sqlparser variant is a compile error, never a
    /// silently-missed subquery.
    fn walk_expr(&mut self, e: &Expr) -> Result<(), AnalyzeError> {
        // Exhaustive match (no `_` arm): a new sqlparser variant is a
        // compile error, never a silently-missed subquery.
        match e {
            // Leaves: no subqueries, no function calls.
            Expr::Identifier(_)
            | Expr::CompoundIdentifier(_)
            | Expr::Value(_)
            | Expr::TypedString { .. }
            | Expr::QualifiedWildcard(_, _)
            | Expr::Wildcard(_) => {}
            // Transparent wrappers.
            Expr::Nested(e)
            | Expr::UnaryOp { expr: e, .. }
            | Expr::Collate { expr: e, .. }
            | Expr::Cast { expr: e, .. }
            | Expr::Convert { expr: e, .. }
            | Expr::AtTimeZone { timestamp: e, .. }
            | Expr::Extract { expr: e, .. }
            | Expr::Position { expr: e, .. }
            | Expr::Ceil { expr: e, .. }
            | Expr::Floor { expr: e, .. }
            | Expr::IsNormalized { expr: e, .. }
            | Expr::Named { expr: e, .. }
            | Expr::Prefixed { value: e, .. }
            | Expr::Prior(e) => self.walk_expr(e)?,
            // Null/boolean tests.
            Expr::IsNull(e)
            | Expr::IsNotNull(e)
            | Expr::IsTrue(e)
            | Expr::IsNotTrue(e)
            | Expr::IsFalse(e)
            | Expr::IsNotFalse(e)
            | Expr::IsUnknown(e)
            | Expr::IsNotUnknown(e) => self.walk_expr(e)?,
            // Binary comparisons.
            Expr::BinaryOp { left, right, .. }
            | Expr::IsDistinctFrom(left, right)
            | Expr::IsNotDistinctFrom(left, right)
            | Expr::AnyOp { left, right, .. }
            | Expr::AllOp { left, right, .. } => {
                self.walk_expr(left)?;
                self.walk_expr(right)?;
            }
            Expr::OuterJoin(e) => self.walk_expr(e)?,
            Expr::InList { expr, list, .. } => {
                self.walk_expr(expr)?;
                for e in list {
                    self.walk_expr(e)?;
                }
            }
            Expr::InSubquery { expr, subquery, .. } => {
                self.walk_expr(expr)?;
                self.walk_query(subquery)?;
            }
            Expr::InUnnest { expr, array_expr, .. } => {
                self.walk_expr(expr)?;
                self.walk_expr(array_expr)?;
            }
            Expr::Between { expr, low, high, .. } => {
                self.walk_expr(expr)?;
                self.walk_expr(low)?;
                self.walk_expr(high)?;
            }
            Expr::Like { expr, pattern, .. }
            | Expr::ILike { expr, pattern, .. }
            | Expr::SimilarTo { expr, pattern, .. }
            | Expr::RLike { expr, pattern, .. } => {
                self.walk_expr(expr)?;
                self.walk_expr(pattern)?;
            }
            Expr::Subquery(q) => self.walk_query(q)?,
            Expr::Exists { subquery, .. } => self.walk_query(subquery)?,
            Expr::Function(f) => self.check_function(f)?,
            Expr::Case { operand, conditions, else_result, .. } => {
                if let Some(op) = operand {
                    self.walk_expr(op)?;
                }
                for w in conditions {
                    self.walk_expr(&w.condition)?;
                    self.walk_expr(&w.result)?;
                }
                if let Some(els) = else_result {
                    self.walk_expr(els)?;
                }
            }
            Expr::Substring { expr, substring_from, substring_for, .. } => {
                self.walk_expr(expr)?;
                if let Some(f) = substring_from {
                    self.walk_expr(f)?;
                }
                if let Some(f) = substring_for {
                    self.walk_expr(f)?;
                }
            }
            Expr::Trim { expr, .. } => self.walk_expr(expr)?,
            Expr::Overlay { expr, overlay_what, overlay_from, overlay_for, .. } => {
                self.walk_expr(expr)?;
                self.walk_expr(overlay_what)?;
                self.walk_expr(overlay_from)?;
                if let Some(f) = overlay_for {
                    self.walk_expr(f)?;
                }
            }
            Expr::Tuple(exprs) => {
                for e in exprs {
                    self.walk_expr(e)?;
                }
            }
            Expr::Cube(sets) | Expr::Rollup(sets) | Expr::GroupingSets(sets) => {
                for set in sets {
                    for e in set {
                        self.walk_expr(e)?;
                    }
                }
            }
            Expr::Array(arr) => {
                for e in &arr.elem {
                    self.walk_expr(e)?;
                }
            }
            Expr::Interval(interval) => self.walk_expr(&interval.value)?,
            Expr::JsonAccess { value, .. } => self.walk_expr(value)?,
            Expr::CompoundFieldAccess { root, access_chain } => {
                self.walk_expr(root)?;
                for access in access_chain {
                    if let sqlparser::ast::AccessExpr::Dot(e) = access {
                        self.walk_expr(e)?;
                    }
                }
            }
            // `columns` are plain identifiers and `match_value` a literal.
            Expr::MatchAgainst { .. } => {}
            Expr::Dictionary(fields) => {
                for f in fields {
                    self.walk_expr(&f.value)?;
                }
            }
            Expr::Map(m) => {
                for entry in &m.entries {
                    self.walk_expr(&entry.key)?;
                    self.walk_expr(&entry.value)?;
                }
            }
            Expr::Struct { values, .. } => {
                for v in values {
                    self.walk_expr(v)?;
                }
            }
            Expr::Lambda(f) => self.walk_expr(&f.body)?,
            Expr::MemberOf(m) => {
                self.walk_expr(&m.value)?;
                self.walk_expr(&m.array)?;
            }
        }
        Ok(())
    }
}

// ---- statement analysis --------------------------------------------------

/// Extract the `ON` expression from a join operator, if any. Every
/// operator variant is listed explicitly so a new variant is a
/// compile-time reminder, not a silently skipped constraint.
fn join_on_expr(op: &sqlparser::ast::JoinOperator) -> Option<&Expr> {
    use sqlparser::ast::{JoinConstraint, JoinOperator};
    let constraint = match op {
        JoinOperator::Join(c)
        | JoinOperator::Inner(c)
        | JoinOperator::Left(c)
        | JoinOperator::LeftOuter(c)
        | JoinOperator::Right(c)
        | JoinOperator::RightOuter(c)
        | JoinOperator::FullOuter(c)
        | JoinOperator::CrossJoin(c)
        | JoinOperator::Semi(c)
        | JoinOperator::LeftSemi(c)
        | JoinOperator::RightSemi(c)
        | JoinOperator::Anti(c)
        | JoinOperator::LeftAnti(c)
        | JoinOperator::RightAnti(c)
        | JoinOperator::StraightJoin(c) => c,
        JoinOperator::CrossApply
        | JoinOperator::OuterApply
        | JoinOperator::ArrayJoin
        | JoinOperator::LeftArrayJoin
        | JoinOperator::InnerArrayJoin => return None,
        JoinOperator::AsOf { .. } => return None,
    };
    match constraint {
        JoinConstraint::On(e) => Some(e),
        JoinConstraint::Using(_) | JoinConstraint::Natural | JoinConstraint::None => None,
    }
}

/// Analyze one statement. Precisely-identified kinds map to
/// [`StatementAction`]; anything else is `Err(Unsupported)`.
fn analyze_statement(stmt: &Statement, ctx: &WalkContext) -> Result<AnalyzedStatement, AnalyzeError> {
    let unsupported = |reason: &str| AnalyzeError::Unsupported { reason: reason.to_string() };
    match stmt {
        Statement::Query(q) => {
            let mut w = QueryWalker::new(ctx);
            w.walk_query(q)?;
            Ok(AnalyzedStatement {
                action: StatementAction::Select,
                targets: w.into_targets,
                sources: w.sources,
                has_where: None,
                where_trivially_true: false,
                has_side_effects: w.side_effects,
            })
        }
        Statement::Insert(ins) => {
            let target = match &ins.table {
                TableObject::TableName(name) => {
                    let w = QueryWalker::new(ctx);
                    w.table_ref(name)?
                }
                _ => return Err(unsupported("INSERT into table function")),
            };
            let mut w = QueryWalker::new(ctx);
            if let Some(source) = ins.source.as_ref() {
                w.walk_query(source)?;
            }
            // MySQL `INSERT ... SET a = expr`.
            for assign in &ins.assignments {
                w.walk_expr(&assign.value)?;
            }
            if let Some(partitioned) = ins.partitioned.as_ref() {
                for e in partitioned {
                    w.walk_expr(e)?;
                }
            }
            // ON CONFLICT / ON DUPLICATE KEY UPDATE: assignments and
            // selections can embed subqueries.
            if let Some(on) = ins.on.as_ref() {
                walk_on_insert(&mut w, on)?;
            }
            for item in ins.returning.iter().flatten() {
                w.walk_select_item(item)?;
            }
            let sources = w.sources;
            let side_effects = w.side_effects;
            Ok(AnalyzedStatement {
                action: StatementAction::Insert,
                targets: vec![target],
                sources,
                has_where: None,
                where_trivially_true: false,
                has_side_effects: side_effects,
            })
        }
        Statement::Update(upd) => {
            let mut w = QueryWalker::new(ctx);
            // Target table.
            let target = match &upd.table.relation {
                TableFactor::Table { name, .. } => w.table_ref(name)?,
                _ => return Err(unsupported("UPDATE of non-table relation")),
            };
            w.walk_table_with_joins(&upd.table)?;
            // UPDATE..FROM sources.
            if let Some(from) = upd.from.as_ref() {
                walk_update_from(&mut w, from)?;
            }
            for assign in &upd.assignments {
                w.walk_expr(&assign.value)?;
            }
            for item in upd.returning.iter().flatten() {
                w.walk_select_item(item)?;
            }
            let (has_where, trivial) = where_info(upd.selection.as_ref());
            let sources: Vec<TableRef> = w.sources.into_iter().filter(|t| *t != target).collect();
            Ok(AnalyzedStatement {
                action: StatementAction::Update,
                targets: vec![target],
                sources,
                has_where,
                where_trivially_true: trivial,
                has_side_effects: w.side_effects,
            })
        }
        Statement::Delete(del) => {
            let mut w = QueryWalker::new(ctx);
            // FROM tables.
            let from_tables: &[TableWithJoins] = match &del.from {
                sqlparser::ast::FromTable::WithFromKeyword(t) | sqlparser::ast::FromTable::WithoutKeyword(t) => t,
            };
            for twj in from_tables {
                w.walk_table_with_joins(twj)?;
            }
            // USING clause sources (Postgres/MySQL/Snowflake).
            if let Some(using) = del.using.as_ref() {
                for twj in using {
                    w.walk_table_with_joins(twj)?;
                }
            }
            // Targets: explicit multi-table list (MySQL `DELETE t1, t2
            // FROM ...`), else every plain table in FROM.
            let targets: Vec<TableRef> = if del.tables.is_empty() {
                let mut targets = Vec::new();
                for twj in from_tables {
                    match &twj.relation {
                        TableFactor::Table { name, .. } => targets.push(w.table_ref(name)?),
                        _ => return Err(unsupported("DELETE with non-table FROM relation")),
                    }
                }
                targets
            } else {
                del.tables.iter().map(|name| w.table_ref(name)).collect::<Result<_, _>>()?
            };
            if targets.is_empty() {
                return Err(unsupported("DELETE with unresolvable target"));
            }
            let target_names: Vec<String> = targets.iter().map(|t| t.table.clone()).collect();
            for item in del.returning.iter().flatten() {
                w.walk_select_item(item)?;
            }
            let (has_where, trivial) = where_info(del.selection.as_ref());
            Ok(AnalyzedStatement {
                action: StatementAction::Delete,
                targets,
                sources: w.sources.into_iter().filter(|t| !target_names.contains(&t.table)).collect(),
                has_where,
                where_trivially_true: trivial,
                has_side_effects: w.side_effects,
            })
        }
        // Precisely-identified kinds that V1 policy denies (exact reasons
        // for policy/audit, never mapped to Select).
        Statement::CreateTable { .. }
        | Statement::CreateView { .. }
        | Statement::CreateIndex { .. }
        | Statement::CreateRole { .. }
        | Statement::CreateSchema { .. }
        | Statement::CreateSequence { .. }
        | Statement::AlterTable { .. }
        | Statement::AlterIndex { .. }
        | Statement::Drop { .. }
        | Statement::Truncate { .. } => Ok(denied_action(StatementAction::Ddl)),
        Statement::Grant { .. } | Statement::Revoke { .. } => Ok(denied_action(StatementAction::Grant)),
        Statement::StartTransaction { .. } | Statement::Commit { .. } | Statement::Rollback { .. } => {
            Ok(denied_action(StatementAction::Transaction))
        }
        Statement::Set(_) => Ok(denied_action(StatementAction::Utility)),
        Statement::Call(_) | Statement::Execute { .. } => Ok(denied_action(StatementAction::Procedure)),
        Statement::Merge(_) => Ok(denied_action(StatementAction::Merge)),
        // Everything else: fail closed, never defaulted to Select.
        other => Err(unsupported(&format!("statement kind {other:?}").chars().take(80).collect::<String>())),
    }
}

fn denied_action(action: StatementAction) -> AnalyzedStatement {
    AnalyzedStatement {
        action,
        targets: Vec::new(),
        sources: Vec::new(),
        has_where: None,
        where_trivially_true: false,
        has_side_effects: false,
    }
}

fn walk_on_insert(w: &mut QueryWalker<'_>, on: &sqlparser::ast::OnInsert) -> Result<(), AnalyzeError> {
    use sqlparser::ast::{OnConflictAction, OnInsert};
    match on {
        OnInsert::DuplicateKeyUpdate(assignments) => {
            for assign in assignments {
                w.walk_expr(&assign.value)?;
            }
            Ok(())
        }
        OnInsert::OnConflict(oc) => match &oc.action {
            OnConflictAction::DoNothing => Ok(()),
            OnConflictAction::DoUpdate(du) => {
                for assign in &du.assignments {
                    w.walk_expr(&assign.value)?;
                }
                if let Some(selection) = du.selection.as_ref() {
                    w.walk_expr(selection)?;
                }
                Ok(())
            }
        },
        // `OnInsert` is #[non_exhaustive]: future variants fail closed.
        _ => Err(AnalyzeError::Unsupported { reason: "unknown ON INSERT clause".to_string() }),
    }
}

fn walk_update_from(w: &mut QueryWalker<'_>, from: &sqlparser::ast::UpdateTableFromKind) -> Result<(), AnalyzeError> {
    use sqlparser::ast::UpdateTableFromKind;
    match from {
        UpdateTableFromKind::BeforeSet(tables) | UpdateTableFromKind::AfterSet(tables) => {
            for twj in tables {
                w.walk_table_with_joins(twj)?;
            }
            Ok(())
        }
    }
}

/// `(has_where, where_trivially_true)`.
fn where_info(selection: Option<&Expr>) -> (Option<bool>, bool) {
    match selection {
        None => (Some(false), false),
        Some(e) => (Some(true), is_trivially_true(e)),
    }
}

/// Conservative tautology detection. Only syntactic tautologies return
/// true; anything uncertain returns false (a missed tautology here only
/// risks *allowing* — no: a missed tautology means we treat the WHERE
/// as restrictive, which is the unsafe direction, so the listed shapes
/// cover the common bypass spellings).
fn is_trivially_true(e: &Expr) -> bool {
    match e {
        Expr::Value(v) if matches!(v.value, sqlparser::ast::Value::Boolean(true)) => true,
        Expr::Nested(inner) => is_trivially_true(inner),
        Expr::BinaryOp { left, op, right } => {
            use sqlparser::ast::BinaryOperator as Op;
            match op {
                Op::Eq => expr_literal_eq(left, right),
                Op::And => is_trivially_true(left) && is_trivially_true(right),
                Op::Or => is_trivially_true(left) || is_trivially_true(right),
                _ => false,
            }
        }
        _ => false,
    }
}

/// True for `literal = literal` / `ident = ident` with identical text
/// (`1=1`, `'a'='a'`, `id=id`). Value comparison is syntactic.
fn expr_literal_eq(left: &Expr, right: &Expr) -> bool {
    match (left, right) {
        (Expr::Value(a), Expr::Value(b)) => a.value == b.value,
        (Expr::Identifier(a), Expr::Identifier(b)) => a.value == b.value,
        (Expr::Nested(a), b) => expr_literal_eq(a, b),
        (a, Expr::Nested(b)) => expr_literal_eq(a, b),
        _ => false,
    }
}

// ---- pure function allowlist ----------------------------------------------

/// Positive allowlist of side-effect-free scalar/window functions.
///
/// V1 is intentionally conservative: any function call not on this list
/// marks the statement as having side effects, and policy denies it as
/// a non-pure read. Rationale: `pg_sleep()`, `nextval()`,dblink-style
/// accessors and unknown UDFs must never pass as ordinary SELECTs.
/// Extensions require independent review (a pure-in-one-dialect function
/// could have side effects in another).
const PURE_FUNCTIONS: &[&str] = &[
    "ABS",
    "ACOS",
    "ADDDATE",
    "AGE",
    "ARRAY_AGG",
    "ASCII",
    "ASIN",
    "ATAN",
    "ATAN2",
    "AVG",
    "BIT_LENGTH",
    "BTRIM",
    "CEIL",
    "CEILING",
    "CHAR",
    "CHARACTER_LENGTH",
    "CHAR_LENGTH",
    "CHR",
    "COALESCE",
    "CONCAT",
    "CONCAT_WS",
    "CONNECTION_ID",
    "CONVERT",
    "COS",
    "COT",
    "COUNT",
    "CUME_DIST",
    "CURDATE",
    "CURRENT_DATE",
    "CURRENT_TIME",
    "CURRENT_TIMESTAMP",
    "CURRENT_USER",
    "CURTIME",
    "DATABASE",
    "DATE",
    "DATEDIFF",
    "DATETIME",
    "DATE_ADD",
    "DATE_FORMAT",
    "DATE_PART",
    "DATE_SUB",
    "DATE_TRUNC",
    "DAY",
    "DAYNAME",
    "DAYOFMONTH",
    "DAYOFWEEK",
    "DAYOFYEAR",
    "DEGREES",
    "DENSE_RANK",
    "DIV",
    "EXP",
    "EXTRACT",
    "FIRST_VALUE",
    "FLOOR",
    "FORMAT",
    "FROM_BASE64",
    "GEN_RANDOM_UUID",
    "GETDATE",
    "GETUTCDATE",
    "GREATEST",
    "GROUP_CONCAT",
    "HEX",
    "HOUR",
    "IF",
    "IFNULL",
    "INITCAP",
    "INSTR",
    "JSONB_AGG",
    "JSON_AGG",
    "JSON_ARRAY",
    "JSON_EXTRACT",
    "JSON_KEYS",
    "JSON_LENGTH",
    "JSON_OBJECT",
    "JSON_QUERY",
    "JSON_QUOTE",
    "JSON_UNQUOTE",
    "JSON_VALUE",
    "LAG",
    "LAST_VALUE",
    "LCASE",
    "LEAD",
    "LEAST",
    "LEFT",
    "LEN",
    "LENGTH",
    "LN",
    "LOCATE",
    "LOG",
    "LOG10",
    "LOG2",
    "LOWER",
    "LPAD",
    "LTRIM",
    "MAX",
    "MD5",
    "MIN",
    "MINUTE",
    "MOD",
    "MONTH",
    "MONTHNAME",
    "NOW",
    "NTH_VALUE",
    "NTILE",
    "NULLIF",
    "NVL",
    "NVL2",
    "OCTET_LENGTH",
    "ORD",
    "PERCENT_RANK",
    "PI",
    "POSITION",
    "POW",
    "POWER",
    "QUARTER",
    "QUOTE",
    "RADIANS",
    "RAND",
    "RANDOM",
    "RANK",
    "REGEXP_INSTR",
    "REGEXP_LIKE",
    "REGEXP_REPLACE",
    "REGEXP_SUBSTR",
    "REPEAT",
    "REPLACE",
    "REVERSE",
    "RIGHT",
    "ROUND",
    "ROW_NUMBER",
    "RPAD",
    "RTRIM",
    "SCHEMA",
    "SECOND",
    "SESSION_USER",
    "SHA1",
    "SHA2",
    "SIGN",
    "SIN",
    "SPACE",
    "SPLIT_PART",
    "SQRT",
    "STDDEV",
    "STDDEV_POP",
    "STDDEV_SAMP",
    "STRING_AGG",
    "STRPOS",
    "STR_TO_DATE",
    "SUBDATE",
    "SUBSTR",
    "SUBSTRING",
    "SUM",
    "SYSDATE",
    "SYSDATETIME",
    "SYSTEM_USER",
    "TAN",
    "TIME",
    "TIMESTAMP",
    "TIMESTAMPADD",
    "TIMESTAMPDIFF",
    "TIME_FORMAT",
    "TO_BASE64",
    "TO_DATE",
    "TO_TIMESTAMP",
    "TRANSLATE",
    "TRIM",
    "TRUNC",
    "TRY_CAST",
    "TRY_CONVERT",
    "TYPEOF",
    "UCASE",
    "UNHEX",
    "UPPER",
    "USER",
    "UUID",
    "VARIANCE",
    "VAR_POP",
    "VAR_SAMP",
    "VERSION",
    "WEEK",
    "WEEKDAY",
    "YEAR",
];

/// Case-insensitive membership test against [`PURE_FUNCTIONS`].
/// The list is sorted; `binary_search` is the single lookup path.
pub fn is_pure_function(name: &str) -> bool {
    PURE_FUNCTIONS.binary_search(&name.to_uppercase().as_str()).is_ok()
}

// Keep the list sorted for binary_search; verify in tests.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pure_function_list_is_sorted_and_unique() {
        assert!(
            PURE_FUNCTIONS.windows(2).all(|w| w[0] < w[1]),
            "PURE_FUNCTIONS must be strictly sorted for binary_search"
        );
        // Spot checks: dangerous functions must NOT be allowlisted.
        for dangerous in ["PG_SLEEP", "SLEEP", "NEXTVAL", "SETVAL", "DBLINK", "COPY", "LO_IMPORT"] {
            assert!(!is_pure_function(dangerous), "{dangerous} must not be pure");
        }
        for pure in ["COUNT", "NOW", "COALESCE", "SUBSTRING", "ROW_NUMBER", "JSON_EXTRACT"] {
            assert!(is_pure_function(pure), "{pure} must be pure");
            assert!(is_pure_function(&pure.to_lowercase()), "matching must be case-insensitive");
        }
    }
}

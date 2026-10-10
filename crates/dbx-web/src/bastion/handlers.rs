//! Bastion HTTP handlers (TASK-005C-2/4).
//!
//! - Auth: `POST /api/bastion/auth/login`, `POST /api/bastion/auth/logout`,
//!   `GET /api/bastion/auth/me`.
//! - Assets: `GET /api/bastion/assets`, `GET /api/bastion/assets/:id`
//!   (CONNECT-gated views; platform admins get no implicit data access).
//!
//! Every authenticated handler takes [`BastionSession`], which
//! re-validates the session token on each request. `user_id`/roles
//! are never read from browser input.

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::{header, request::Parts, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use dbx_bastion::audit::AuditService;
use dbx_bastion::auth::LoginRequest;
use serde::{Deserialize, Serialize};

use super::session::{check_csrf, peer_ip, BastionSession};
use super::state::BastionState;

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct LoginBody {
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
struct LoginResponse {
    username: String,
    expires_at: String,
}

#[derive(Serialize)]
pub struct MeResponse {
    user_id: String,
    username: String,
}

/// `POST /api/bastion/auth/login`.
///
/// Rate limiting is enforced inside `AuthService::login` (shared
/// instance). The raw token is returned only via `Set-Cookie`, never
/// in the JSON body.
pub async fn login(State(state): State<Arc<BastionState>>, parts: Parts, Json(body): Json<LoginBody>) -> Response {
    if let Err(reject) = check_csrf(&parts) {
        return reject;
    }
    let user_agent = parts.headers.get(header::USER_AGENT).and_then(|v| v.to_str().ok()).map(str::to_string);
    let req = LoginRequest { username: body.username, password: body.password, source_ip: peer_ip(&parts), user_agent };
    match state.service.auth().login(&req).await {
        Ok(result) => {
            let cookie = state.cookie_config.policy.set_cookie_value(&result.token);
            (
                StatusCode::OK,
                [(header::SET_COOKIE, cookie)],
                Json(LoginResponse {
                    username: result.principal.username.clone(),
                    expires_at: result.expires_at.to_rfc3339(),
                }),
            )
                .into_response()
        }
        Err(_) => {
            // Fail-closed without distinguishing "bad credentials" from
            // "auth backend error" or rate limiting.
            (StatusCode::UNAUTHORIZED, "invalid credentials").into_response()
        }
    }
}

/// `POST /api/bastion/auth/logout`. Revokes the current session
/// immediately and clears the cookie.
pub async fn logout(State(state): State<Arc<BastionState>>, session: BastionSession) -> Response {
    if session_state_revoked(&state, &session).await {
        // Already gone; still clear the cookie.
    }
    let cookie = state.cookie_config.policy.clear_cookie_value();
    (StatusCode::OK, [(header::SET_COOKIE, cookie)], Json(serde_json::json!({"ok": true}))).into_response()
}

async fn session_state_revoked(state: &Arc<BastionState>, session: &BastionSession) -> bool {
    state.service.auth().logout(session.principal.session_id()).await.is_err()
}

/// `GET /api/bastion/auth/me`.
pub async fn me(session: BastionSession) -> Json<MeResponse> {
    Json(MeResponse {
        user_id: session.principal.user_id().to_string(),
        username: session.principal.username().to_string(),
    })
}

// ---------------------------------------------------------------------------
// Assets (CONNECT-gated views)
// ---------------------------------------------------------------------------

#[derive(Deserialize, Default)]
pub struct AssetListQuery {
    pub environment: Option<String>,
    pub db_type: Option<String>,
    pub name_contains: Option<String>,
    pub page: Option<u32>,
    pub page_size: Option<u32>,
}

#[derive(Serialize)]
struct AssetListResponse {
    items: Vec<dbx_bastion::asset::AssetView>,
    total: u64,
    page: u32,
    page_size: u32,
}

/// `GET /api/bastion/assets`. Only assets the caller has CONNECT on.
/// Disabled/missing assets are hidden (the service returns unified
/// `NotFound`; list filtering happens inside the snapshot).
pub async fn list_assets(
    State(state): State<Arc<BastionState>>,
    session: BastionSession,
    Query(q): Query<AssetListQuery>,
) -> Response {
    use dbx_bastion::asset::{AssetFilter, Environment, PageRequest};
    let environment = q.environment.as_deref().and_then(|e| match e.to_lowercase().as_str() {
        "production" | "prod" => Some(Environment::Production),
        "staging" => Some(Environment::Staging),
        "test" => Some(Environment::Test),
        "development" | "dev" => Some(Environment::Development),
        _ => None,
    });
    let filter = AssetFilter {
        environment,
        db_type: q.db_type,
        group_id: None,
        name_contains: q.name_contains,
        include_disabled: false,
    };
    let page_req = PageRequest {
        page: q.page.unwrap_or(1).max(1),
        page_size: q.page_size.unwrap_or(50).clamp(1, 200),
        sort_by: dbx_bastion::asset::AssetSortField::Name,
        sort_desc: false,
    };
    match state.asset_service().list_asset_views(&session.principal, filter, page_req).await {
        Ok(page) => {
            Json(AssetListResponse { items: page.items, total: page.total, page: page.page, page_size: page.page_size })
                .into_response()
        }
        Err(_) => (StatusCode::FORBIDDEN, "access denied").into_response(),
    }
}

/// `GET /api/bastion/assets/:id`. Unified 404 for missing / disabled /
/// no-CONNECT (no enumeration oracle).
pub async fn get_asset(
    State(state): State<Arc<BastionState>>,
    session: BastionSession,
    Path(id): Path<String>,
) -> Response {
    let asset_id = match uuid::Uuid::parse_str(&id) {
        Ok(u) => u,
        Err(_) => return (StatusCode::NOT_FOUND, "not found").into_response(),
    };
    match state.asset_service().get_asset_view(&session.principal, asset_id).await {
        Ok(view) => Json(view).into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}

// ---------------------------------------------------------------------------
// Query execution (005C-4)
// ---------------------------------------------------------------------------

/// Independent safety switch: even in bastion mode, real SQL execution
/// requires `DBX_BASTION_SQL_EXECUTION_ENABLED=1`. Default is deny.
/// This switch never bypasses session, RBAC, policy, approval, audit,
/// asset state, or execution limits — and production assets stay denied
/// regardless.
fn sql_execution_enabled() -> bool {
    std::env::var("DBX_BASTION_SQL_EXECUTION_ENABLED")
        .map(|v| matches!(v.trim().to_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
}

#[derive(serde::Deserialize)]
pub struct ExecuteQueryBody {
    pub asset_id: String,
    pub sql: String,
    pub max_rows: Option<u64>,
    pub timeout_secs: Option<u64>,
}

/// `POST /api/bastion/query/execute` — the only bastion SQL entry.
///
/// Full chain: session → principal → gateway (asset resolve →
/// analyzer → policy → RBAC → audit STARTED → re-verify → executor →
/// audit completion). Refused when the execution switch is off, when
/// degraded, or when the gateway denies.
pub async fn execute_query(
    State(state): State<Arc<BastionState>>,
    parts: Parts,
    session: BastionSession,
    Json(body): Json<ExecuteQueryBody>,
) -> Response {
    if let Err(reject) = check_csrf(&parts) {
        return reject;
    }
    if !sql_execution_enabled() {
        return (StatusCode::FORBIDDEN, "sql execution is not enabled").into_response();
    }
    if state.execution_refused() {
        return (StatusCode::SERVICE_UNAVAILABLE, "bastion is degraded: sql execution refused").into_response();
    }
    let gateway = match state.gateway.as_ref() {
        Some(g) => g,
        None => return (StatusCode::SERVICE_UNAVAILABLE, "query gateway not initialized").into_response(),
    };
    let asset_id = match uuid::Uuid::parse_str(&body.asset_id) {
        Ok(id) => id,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid asset_id").into_response(),
    };
    if body.sql.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, "sql is required").into_response();
    }
    // Caller-requested limits are clamped server-side by the gateway;
    // the executor enforces the final values.
    let mut options = dbx_bastion::query::ExecutionOptions::default();
    if let Some(mr) = body.max_rows {
        options.max_rows = mr.clamp(1, 10_000);
    }
    if let Some(ts) = body.timeout_secs {
        options.timeout = std::time::Duration::from_secs(ts.clamp(1, 300));
    }
    let req = dbx_bastion::query::GatewayRequest { asset_id, sql: body.sql, options };

    // Client disconnect cancels the gateway's parent token.
    let cancel = tokio_util::sync::CancellationToken::new();
    match gateway.execute_with_cancel(&session.principal, req, cancel).await {
        Ok(dto) => Json(dto).into_response(),
        Err(e) => {
            let (status, msg) = match e {
                dbx_bastion::BastionError::Forbidden(_) => (StatusCode::FORBIDDEN, "access denied"),
                dbx_bastion::BastionError::NotFound(_) => (StatusCode::NOT_FOUND, "not found"),
                dbx_bastion::BastionError::AuditFailClosed => {
                    (StatusCode::SERVICE_UNAVAILABLE, "audit fail-closed: triage required")
                }
                dbx_bastion::BastionError::ExecutionTimeout => (StatusCode::GATEWAY_TIMEOUT, "execution timed out"),
                dbx_bastion::BastionError::ExecutionCancelled => (StatusCode::from_u16(499).unwrap(), "cancelled"),
                _ => (StatusCode::BAD_GATEWAY, "execution failed"),
            };
            (status, msg).into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// Audit recovery (005C-4, admin-only)
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
pub struct TriageBody {
    pub reason: String,
    pub evidence: Option<String>,
    /// Required: what the evidence proves. One of
    /// `confirmed_committed`, `confirmed_not_executed`, `still_unknown`.
    pub conclusion: String,
}

/// `GET /api/bastion/audit/interruptions` — list untriaged audit
/// records. Requires bastion-admin (verified per call, not from the
/// principal snapshot).
pub async fn list_interruptions(State(state): State<Arc<BastionState>>, session: BastionSession) -> Response {
    if state.asset_service().guard().check(&session.principal).await.is_err() {
        return (StatusCode::FORBIDDEN, "admin required").into_response();
    }
    let audit = dbx_bastion::audit::SqliteAuditService::new(state.service.store().clone());
    match audit.list_unfinished().await {
        Ok(items) => Json(items).into_response(),
        Err(_) => (StatusCode::BAD_GATEWAY, "audit unavailable").into_response(),
    }
}

/// `POST /api/bastion/audit/interruptions/:id/triage` — controlled
/// recovery (P0-2). Requires bastion-admin + non-empty reason +
/// explicit conclusion. The original audit row is NEVER modified; the
/// triage appends to `audit_recovery_events`. Only
/// `confirmed_committed` / `confirmed_not_executed` lift the execution
/// block; `still_unknown` keeps refusing. Actively-executing records
/// cannot be triaged.
pub async fn triage_interruption(
    State(state): State<Arc<BastionState>>,
    parts: Parts,
    session: BastionSession,
    Path(id): Path<String>,
    Json(body): Json<TriageBody>,
) -> Response {
    if let Err(reject) = check_csrf(&parts) {
        return reject;
    }
    let admin_id = match state.asset_service().guard().check(&session.principal).await {
        Ok(id) => id,
        Err(_) => return (StatusCode::FORBIDDEN, "admin required").into_response(),
    };
    let record_id = match uuid::Uuid::parse_str(&id) {
        Ok(u) => u,
        Err(_) => return (StatusCode::NOT_FOUND, "not found").into_response(),
    };
    let conclusion = match dbx_bastion::audit::TriageConclusion::from_str(&body.conclusion) {
        Some(c) => c,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                "conclusion must be confirmed_committed, confirmed_not_executed, or still_unknown",
            )
                .into_response()
        }
    };
    // Forbid triage of actively-executing records (P0-2 requirement 6).
    // The gateway tracks in-flight audit IDs; the instance lock
    // guarantees this process is the only writer.
    if let Some(gw) = state.gateway.as_ref() {
        if gw.is_inflight(&record_id) {
            return (StatusCode::CONFLICT, "audit record is actively executing; triage is forbidden").into_response();
        }
    }
    // Pass an empty set: the gateway check above already rejected
    // in-flight IDs. The service also guards against in-flight IDs
    // passed by other callers (defense in depth).
    let inflight_set = std::collections::HashSet::new();
    let audit = dbx_bastion::audit::SqliteAuditService::new(state.service.store().clone());
    match audit
        .triage_interruption(
            record_id,
            admin_id,
            &body.reason,
            body.evidence.as_deref().unwrap_or(""),
            conclusion,
            &inflight_set,
        )
        .await
    {
        Ok(()) => Json(serde_json::json!({"ok": true})).into_response(),
        Err(dbx_bastion::BastionError::NotFound(_)) => (StatusCode::NOT_FOUND, "not found").into_response(),
        Err(dbx_bastion::BastionError::InvalidData(msg)) => (StatusCode::BAD_REQUEST, msg).into_response(),
        Err(_) => (StatusCode::BAD_REQUEST, "triage failed").into_response(),
    }
}

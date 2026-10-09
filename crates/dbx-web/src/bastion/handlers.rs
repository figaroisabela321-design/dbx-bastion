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

//! Bastion HTTP routes (TASK-005C-2).
//!
//! Registered:
//! - `GET /api/bastion/health` — liveness, no auth.
//! - `GET /api/bastion/status` — mode + startup state, no auth.
//! - `POST /api/bastion/auth/login` — username/password → session cookie.
//! - `POST /api/bastion/auth/logout` — revoke session, clear cookie.
//! - `GET /api/bastion/auth/me` — current user (session required).
//! - `GET /api/bastion/assets` — CONNECT-gated asset views.
//! - `GET /api/bastion/assets/:id` — single CONNECT-gated asset view.
//!
//! No query execution route yet (005C-4). The default-deny firewall
//! (`firewall.rs`) mirrors this list; anything not listed does not
//! exist.

use std::sync::Arc;

use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};
use serde::Serialize;

use super::handlers;
use super::state::{BastionState, StartupState};

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    mode: &'static str,
}

#[derive(Serialize)]
struct StatusResponse {
    mode: &'static str,
    startup_state: &'static str,
    execution_refused: bool,
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok", mode: "bastion" })
}

async fn status(State(state): State<Arc<BastionState>>) -> Json<StatusResponse> {
    let startup_state = match state.startup_state {
        StartupState::Ready => "ready",
        StartupState::Degraded => "degraded",
    };
    Json(StatusResponse { mode: "bastion", startup_state, execution_refused: state.execution_refused() })
}

/// Build the bastion API router. This is the **complete** route set for
/// bastion mode: anything not listed here does not exist. The firewall
/// allowlist must be kept in sync (see `firewall::ALLOWLIST`).
pub fn build_bastion_router(state: Arc<BastionState>) -> Router {
    Router::new()
        .route("/api/bastion/health", get(health))
        .route("/api/bastion/status", get(status))
        .route("/api/bastion/auth/login", post(handlers::login))
        .route("/api/bastion/auth/logout", post(handlers::logout))
        .route("/api/bastion/auth/me", get(handlers::me))
        .route("/api/bastion/assets", get(handlers::list_assets))
        .route("/api/bastion/assets/{id}", get(handlers::get_asset))
        .with_state(state)
}

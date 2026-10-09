//! Bastion HTTP routes (TASK-005C-1).
//!
//! 005C-1 registers only:
//! - `GET /api/bastion/health` — liveness, no auth.
//! - `GET /api/bastion/status` — mode + startup state, no auth.
//!
//! No query execution, no auth endpoints, no admin endpoints yet.
//! Those arrive in 005C-2/005C-4 with their authentication and guards.
//! In particular there is deliberately **no** `/api/bastion/query/*`
//! route in this phase.

use std::sync::Arc;

use axum::{extract::State, routing::get, Json, Router};
use serde::Serialize;

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
/// bastion mode in 005C-1: anything not listed here does not exist.
pub fn build_bastion_router(state: Arc<BastionState>) -> Router {
    Router::new().route("/api/bastion/health", get(health)).route("/api/bastion/status", get(status)).with_state(state)
}

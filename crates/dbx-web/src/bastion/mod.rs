//! Bastion mode for dbx-web (TASK-005C).
//!
//! 005C-1 scope: run-mode selection, startup gates, bastion router
//! (health + status only), and the default-deny firewall. No
//! authentication, no query execution, no admin APIs yet — those arrive
//! in 005C-2/005C-4 with their own guards.
//!
//! Design rules:
//! - Bastion and legacy routers are built by separate functions; bastion
//!   mode never registers legacy routes.
//! - `DBX_DISABLE_PASSWORD=1` + bastion mode is a startup failure.
//! - Any bastion initialization failure is a startup failure; the
//!   process never falls back to legacy mode.

pub mod adapters;
pub mod firewall;
pub mod fs_security;
pub mod handlers;
pub mod mode;
pub mod routes;
pub mod session;
pub mod state;

pub use firewall::validate_base_path;
pub use mode::{check_mode_conflict, run_mode_from_env, RunMode};
pub use routes::build_bastion_router;
pub use state::{BastionState, StartupState};

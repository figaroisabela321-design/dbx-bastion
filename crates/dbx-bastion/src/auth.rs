//! Authentication principal.
//!
//! `Principal` is the authenticated identity that flows through the whole
//! bastion pipeline (RBAC -> policy -> approval -> audit). Password
//! verification, session issuance/revocation and login rate limiting are
//! implemented in a later TASK; this module only defines the identity shape.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The authenticated caller of a bastion operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Principal {
    pub user_id: Uuid,
    pub username: String,
    pub display_name: String,
    pub session_id: Uuid,
    /// Role names resolved at authentication time (snapshot, not live).
    pub roles: Vec<String>,
}

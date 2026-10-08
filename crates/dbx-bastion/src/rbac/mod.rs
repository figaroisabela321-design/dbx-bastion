//! Role-based access control: the authorization question of DB Bastion.
//!
//! Scope: `User/Role -> Asset -> Database -> Schema -> Table -> Action`.
//! DENY always overrides ALLOW; anything not explicitly allowed is denied.
//!
//! Architecture:
//! - [`AuthenticatedPrincipal`](crate::auth::AuthenticatedPrincipal) is the
//!   only accepted identity: unforgeable, session-validated.
//! - [`Authorizer`] evaluates batches of [`AuthorizationCheck`] against one
//!   [`snapshot::AuthSnapshot`] built inside a single SQLite read
//!   transaction. Evaluation is a pure function; snapshots are never
//!   cached across requests.
//! - [`grants::GrantService`] is the management plane (grant CRUD, user
//!   groups), restricted to platform administrators.
//! - [`resource`] defines the resource identity contract (no SQL parsing
//!   here — that belongs to the future QueryGateway).
//!
//! Platform administrators have **no** implicit database data permissions:
//! `bastion-admin` lets you manage grants, never query data.

pub mod authorizer;
pub mod grants;
pub mod resource;
pub mod snapshot;

pub use authorizer::{connect_check, AuthorizationCheck, Authorizer, SnapshotAuthorizer};
pub use grants::{AssetScope, GrantService, GrantView, NewGrant};
pub use resource::{NameState, ResourceScope};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Connect,
    Select,
    Insert,
    Update,
    Delete,
    Ddl,
    Execute,
    Export,
    Import,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Connect => "connect",
            Self::Select => "select",
            Self::Insert => "insert",
            Self::Update => "update",
            Self::Delete => "delete",
            Self::Ddl => "ddl",
            Self::Execute => "execute",
            Self::Export => "export",
            Self::Import => "import",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "connect" => Some(Self::Connect),
            "select" => Some(Self::Select),
            "insert" => Some(Self::Insert),
            "update" => Some(Self::Update),
            "delete" => Some(Self::Delete),
            "ddl" => Some(Self::Ddl),
            "execute" => Some(Self::Execute),
            "export" => Some(Self::Export),
            "import" => Some(Self::Import),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Effect {
    Allow,
    Deny,
}

impl Effect {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "allow" => Some(Self::Allow),
            "deny" => Some(Self::Deny),
            _ => None,
        }
    }
}

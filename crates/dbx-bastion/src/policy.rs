//! SQL policy domain types.
//!
//! The policy engine (rule model + evaluation: multi-statement deny,
//! UPDATE/DELETE-without-WHERE deny, production write/DDL approval defaults,
//! ...) is implemented in a later TASK. This module defines the decision
//! shape the engine will produce and the gateway will enforce.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "low" => Some(Self::Low),
            "medium" => Some(Self::Medium),
            "high" => Some(Self::High),
            "critical" => Some(Self::Critical),
            _ => None,
        }
    }
}

/// The outcome of policy evaluation for one statement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecision {
    /// Whether execution may proceed (possibly subject to approval).
    pub allow: bool,
    /// Whether an approval ticket is required before execution.
    pub require_approval: bool,
    pub risk_level: RiskLevel,
    /// Human-readable reasons, surfaced to the operator and the audit trail.
    pub reasons: Vec<String>,
    /// Optional result-size guard applied by the gateway.
    pub max_rows: Option<u64>,
    /// Whether exporting this result set is permitted.
    pub allow_export: bool,
}

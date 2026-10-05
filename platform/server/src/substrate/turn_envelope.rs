//! TurnEnvelope — canonical identity of one Talk/Effect operation across planes.
//!
//! Downstream modules must not independently guess principal or generation;
//! they bind to the envelope minted at accept time.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const TURN_ENVELOPE_SCHEMA: &str = "connector.turn_envelope.v1";

/// Plane that owns the operation (INV: Talk never ToolDispatches).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimePlane {
    Control,
    Talk,
    Effect,
    Evidence,
}

impl RuntimePlane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Control => "control",
            Self::Talk => "talk",
            Self::Effect => "effect",
            Self::Evidence => "evidence",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TurnDeadline {
    /// Absolute wall deadline (unix ms).
    pub deadline_ms: i64,
    /// Soft budget for provider HTTP (ms).
    pub provider_budget_ms: u64,
    /// Soft budget for inject/projection (ms).
    pub prepare_budget_ms: u64,
}

impl TurnDeadline {
    pub fn from_now(provider_budget_ms: u64, prepare_budget_ms: u64) -> Self {
        let now = chrono::Utc::now().timestamp_millis();
        let total = provider_budget_ms.saturating_add(prepare_budget_ms).saturating_add(2_000);
        Self {
            deadline_ms: now + total as i64,
            provider_budget_ms,
            prepare_budget_ms,
        }
    }

    pub fn expired(&self) -> bool {
        chrono::Utc::now().timestamp_millis() >= self.deadline_ms
    }

    pub fn remaining_ms(&self) -> i64 {
        self.deadline_ms - chrono::Utc::now().timestamp_millis()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TurnEnvelope {
    pub schema: String,
    pub plane: RuntimePlane,
    pub tenant_id: String,
    pub principal_id: String,
    pub session_id: String,
    pub turn_id: String,
    pub work_unit_id: String,
    pub snapshot_version: u64,
    pub identity_generation: u64,
    pub broker_generation: u64,
    pub quarantine_generation: u64,
    pub deadline: TurnDeadline,
    pub trace_id: String,
    pub request_hash: String,
}

impl TurnEnvelope {
    pub fn mint_talk(
        tenant_id: impl Into<String>,
        principal_id: impl Into<String>,
        session_id: impl Into<String>,
        snapshot_version: u64,
        identity_generation: u64,
        broker_generation: u64,
        quarantine_generation: u64,
        deadline: TurnDeadline,
        request_body: &str,
    ) -> Self {
        let turn_id = format!("turn:{}", Uuid::new_v4().as_simple());
        let work_unit_id = format!("wu:{}", Uuid::new_v4().as_simple());
        let trace_id = format!("{:x}", Sha256::digest(turn_id.as_bytes()))[..32].to_string();
        let request_hash = format!("{:x}", Sha256::digest(request_body.as_bytes()));
        Self {
            schema: TURN_ENVELOPE_SCHEMA.into(),
            plane: RuntimePlane::Talk,
            tenant_id: tenant_id.into(),
            principal_id: principal_id.into(),
            session_id: session_id.into(),
            turn_id,
            work_unit_id,
            snapshot_version,
            identity_generation,
            broker_generation,
            quarantine_generation,
            deadline,
            trace_id,
            request_hash,
        }
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mint_talk_binds_generations() {
        let d = TurnDeadline::from_now(30_000, 5_000);
        let env = TurnEnvelope::mint_talk(
            "tenant-a",
            "agent-1",
            "sess-1",
            7,
            3,
            9,
            1,
            d,
            "hello",
        );
        assert_eq!(env.plane, RuntimePlane::Talk);
        assert_eq!(env.snapshot_version, 7);
        assert_eq!(env.broker_generation, 9);
        assert!(env.turn_id.starts_with("turn:"));
        assert_eq!(env.request_hash.len(), 64);
    }

    #[test]
    fn deadline_remaining_positive() {
        let d = TurnDeadline::from_now(10_000, 1_000);
        assert!(!d.expired());
        assert!(d.remaining_ms() > 0);
    }
}

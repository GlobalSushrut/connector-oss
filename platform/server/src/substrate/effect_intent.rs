//! Semantic EffectIntent — expected/actual state delta on ActionBinding.
//! Tool/protocol capability checks remain authoritative; intent is audit + verify.
//! Authority fields bind the intent to a compiled snapshot and turn (digest-bound Admit).

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::kernel::action_binding::ActionBinding;

pub const EFFECT_INTENT_SCHEMA: &str = "connector.effect_intent.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StateDelta {
    pub reads: Vec<String>,
    pub writes: Vec<String>,
    pub expected: Value,
    pub actual: Option<Value>,
}

/// Digest-bound authority that Admit/PATE must preserve (INV: no free-floating effects).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct EffectAuthority {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot_version: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub turn_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub order_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal_id: Option<String>,
    /// SHA-256 over (operation|order|snapshot|turn) — HITL / PATE bind to this.
    #[serde(default)]
    pub auth_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EffectIntent {
    pub schema: String,
    pub intent_digest: String,
    pub operation: String,
    pub semantic_verb: String,
    pub delta: StateDelta,
    pub reversibility: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority: Option<EffectAuthority>,
}

impl EffectIntent {
    pub fn from_binding(binding: &ActionBinding, reversibility: &str) -> Self {
        let semantic_verb = classify_verb(&binding.operation, &binding.target.tool_name);
        let delta = StateDelta {
            reads: vec![],
            writes: vec![binding.target.resource.clone()],
            expected: binding.parameters.clone(),
            actual: None,
        };
        let mut intent = Self {
            schema: EFFECT_INTENT_SCHEMA.into(),
            intent_digest: String::new(),
            operation: binding.operation.clone(),
            semantic_verb,
            delta,
            reversibility: reversibility.into(),
            authority: None,
        };
        intent.intent_digest = intent.compute_digest();
        intent
    }

    /// Workbench Admit: bind order payload to snapshot/turn generations.
    pub fn from_workbench_order(
        principal_id: &str,
        session_id: &str,
        order_id: &str,
        operation: &str,
        tool_name: &str,
        parameters: Value,
        snapshot_version: u64,
        turn_id: Option<&str>,
    ) -> Self {
        let semantic_verb = classify_verb(operation, tool_name);
        let delta = StateDelta {
            reads: vec![],
            writes: vec![format!("tool:{tool_name}")],
            expected: parameters,
            actual: None,
        };
        let mut auth = EffectAuthority {
            snapshot_version: Some(snapshot_version),
            turn_id: turn_id.map(str::to_string),
            session_id: Some(session_id.into()),
            order_id: Some(order_id.into()),
            principal_id: Some(principal_id.into()),
            auth_digest: String::new(),
        };
        auth.auth_digest = auth_digest_for(
            principal_id,
            order_id,
            operation,
            snapshot_version,
            turn_id.unwrap_or(""),
        );
        let mut intent = Self {
            schema: EFFECT_INTENT_SCHEMA.into(),
            intent_digest: String::new(),
            operation: operation.into(),
            semantic_verb,
            delta,
            reversibility: "governed".into(),
            authority: Some(auth),
        };
        intent.intent_digest = intent.compute_digest();
        intent
    }

    pub fn compute_digest(&self) -> String {
        let body = json!({
            "operation": self.operation,
            "semantic_verb": self.semantic_verb,
            "delta": self.delta,
            "reversibility": self.reversibility,
            "authority": self.authority,
        });
        let bytes = serde_json::to_vec(&body).unwrap_or_default();
        format!("{:x}", Sha256::digest(&bytes))
    }

    pub fn with_actual(mut self, actual: Value) -> Self {
        self.delta.actual = Some(actual);
        self.intent_digest = self.compute_digest();
        self
    }

    pub fn auth_digest(&self) -> Option<&str> {
        self.authority
            .as_ref()
            .map(|a| a.auth_digest.as_str())
            .filter(|s| !s.is_empty())
    }
}

pub fn auth_digest_for(
    principal_id: &str,
    order_id: &str,
    operation: &str,
    snapshot_version: u64,
    turn_id: &str,
) -> String {
    let raw = format!(
        "effect_auth|{principal_id}|{order_id}|{operation}|{snapshot_version}|{turn_id}"
    );
    format!("{:x}", Sha256::digest(raw.as_bytes()))
}

fn classify_verb(operation: &str, tool: &str) -> String {
    let s = format!("{operation}:{tool}").to_ascii_lowercase();
    if s.contains("read") || s.contains("get") || s.contains("list") || s.contains("observe") {
        "observe".into()
    } else if s.contains("write") || s.contains("put") || s.contains("create") {
        "mutate".into()
    } else if s.contains("delete") || s.contains("destroy") || s.contains("estop") {
        "irreversible".into()
    } else if s.contains("conp") || s.contains("command") {
        "actuate".into()
    } else if s.contains("talk") || s.contains("llm") || s.contains("chat") {
        "propose".into()
    } else if s.contains("admit") || s.contains("workbench") {
        "admit".into()
    } else {
        "effect".into()
    }
}

pub fn attach_to_binding_json(binding: &ActionBinding, intent: &EffectIntent) -> Value {
    let mut v = serde_json::to_value(binding).unwrap_or(Value::Null);
    if let Some(obj) = v.as_object_mut() {
        obj.insert(
            "effect_intent".into(),
            serde_json::to_value(intent).unwrap_or(Value::Null),
        );
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workbench_order_binds_auth_digest() {
        let intent = EffectIntent::from_workbench_order(
            "agent-1",
            "sess-1",
            "ord-9",
            "tool.dispatch",
            "demo.echo",
            json!({"msg": "hi"}),
            3,
            Some("turn:abc"),
        );
        assert!(intent.authority.is_some());
        assert_eq!(
            intent.auth_digest().unwrap(),
            auth_digest_for("agent-1", "ord-9", "tool.dispatch", 3, "turn:abc")
        );
        assert!(!intent.intent_digest.is_empty());
    }
}

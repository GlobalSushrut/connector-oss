//! Developer-composable substrate specs (agents, tools, routes, budgets, …).
//!
//! These are **intent** types for SDK/Gloo/CLS. They never mint grants, embed
//! bearer secrets, or claim effective enforcement posture. Digests pin content
//! into packages and IR.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::digest_hex_str;
use crate::invocation::EffectDescriptor;
use crate::proxy::ProxyHopKind;

pub const TOOL_SPEC_SCHEMA: &str = "connector.tool_spec.v1";
pub const AGENT_SPEC_SCHEMA: &str = "connector.agent_spec.v1";
pub const GRAPH_SPEC_SCHEMA: &str = "connector.graph_spec.v1";
pub const LISTENER_SPEC_SCHEMA: &str = "connector.listener_spec.v1";
pub const ROUTE_SPEC_SCHEMA: &str = "connector.route_spec.v1";
pub const TRANSFORM_SPEC_SCHEMA: &str = "connector.transform_spec.v1";
pub const INFERENCE_SPEC_SCHEMA: &str = "connector.inference_spec.v1";
pub const MEMORY_SPEC_SCHEMA: &str = "connector.memory_spec.v1";
pub const BUDGET_SPEC_SCHEMA: &str = "connector.budget_spec.v1";
pub const GRANT_REQUEST_SCHEMA: &str = "connector.grant_request.v1";
pub const SECRET_REF_SCHEMA: &str = "connector.secret_ref.v1";
pub const SUPERVISION_SPEC_SCHEMA: &str = "connector.supervision_spec.v1";
pub const TARGET_SPEC_SCHEMA: &str = "connector.target_spec.v1";

/// Canonical JSON → content digest for package/IR pinning.
pub fn spec_digest(value: &impl Serialize) -> Result<String, String> {
    let v = serde_json::to_value(value).map_err(|e| e.to_string())?;
    let canonical = canonical_json(&v);
    Ok(format!("spec-sha256-{}", digest_hex_str(&canonical)))
}

fn canonical_json(v: &Value) -> String {
    match v {
        Value::Object(map) => {
            let mut keys: Vec<_> = map.keys().cloned().collect();
            keys.sort();
            let parts: Vec<String> = keys
                .into_iter()
                .filter_map(|k| {
                    let child = map.get(&k)?;
                    Some(format!("\"{}\":{}", k, canonical_json(child)))
                })
                .collect();
            format!("{{{}}}", parts.join(","))
        }
        Value::Array(arr) => {
            let parts: Vec<String> = arr.iter().map(canonical_json).collect();
            format!("[{}]", parts.join(","))
        }
        Value::String(s) => serde_json::to_string(s).unwrap_or_else(|_| "\"\"".into()),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => "null".into(),
    }
}

/// Tool declaration — schema + effect row; not a grant.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ToolSpec {
    pub schema: String,
    pub tool_id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default)]
    pub input_schema: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<Value>,
    pub effect: EffectDescriptor,
    #[serde(default)]
    pub idempotent: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reversibility: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
    #[serde(default)]
    pub streaming: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub isolation: Option<String>,
    #[serde(default)]
    pub credential_imports: Vec<SecretRef>,
}

impl ToolSpec {
    pub fn new(tool_id: impl Into<String>, name: impl Into<String>, effect: EffectDescriptor) -> Self {
        Self {
            schema: TOOL_SPEC_SCHEMA.into(),
            tool_id: tool_id.into(),
            name: name.into(),
            description: None,
            input_schema: Value::Object(Default::default()),
            output_schema: None,
            effect,
            idempotent: false,
            reversibility: None,
            timeout_ms: None,
            streaming: false,
            isolation: None,
            credential_imports: vec![],
        }
    }
}

/// Opaque vault/secret handle — never a raw secret value.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretRef {
    pub schema: String,
    pub handle: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub materialization: Option<String>,
}

impl SecretRef {
    pub fn handle(handle: impl Into<String>) -> Self {
        Self {
            schema: SECRET_REF_SCHEMA.into(),
            handle: handle.into(),
            audience: None,
            destination: None,
            materialization: Some("adapter_only".into()),
        }
    }
}

/// Requested attenuated authority — never a minted grant.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GrantRequest {
    pub schema: String,
    pub resource: String,
    #[serde(default)]
    pub actions: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effect_ceiling: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiry_ms: Option<i64>,
}

impl GrantRequest {
    pub fn new(resource: impl Into<String>, actions: Vec<String>) -> Self {
        Self {
            schema: GRANT_REQUEST_SCHEMA.into(),
            resource: resource.into(),
            actions,
            effect_ceiling: None,
            budget_ref: None,
            expiry_ms: None,
        }
    }
}

/// Provider-neutral agent authoring intent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentSpec {
    pub schema: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_requirements: Option<Value>,
    #[serde(default)]
    pub tools: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<Value>,
    #[serde(default)]
    pub memory_scopes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hitl_policy: Option<String>,
    #[serde(default)]
    pub grant_requests: Vec<GrantRequest>,
}

impl AgentSpec {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            schema: AGENT_SPEC_SCHEMA.into(),
            name: name.into(),
            model_requirements: None,
            tools: vec![],
            output_schema: None,
            memory_scopes: vec![],
            budget_ref: None,
            hitl_policy: None,
            grant_requests: vec![],
        }
    }
}

/// Explicit durable graph (LangGraph-class) declaration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GraphSpec {
    pub schema: String,
    pub name: String,
    #[serde(default)]
    pub state_schema: Value,
    #[serde(default)]
    pub nodes: Vec<GraphNodeSpec>,
    #[serde(default)]
    pub edges: Vec<GraphEdgeSpec>,
    #[serde(default)]
    pub interrupt_before: Vec<String>,
    #[serde(default)]
    pub compensations: Vec<GraphCompensationSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GraphNodeSpec {
    pub id: String,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GraphEdgeSpec {
    pub from: String,
    pub to: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub condition: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GraphCompensationSpec {
    pub node_id: String,
    pub compensate_ref: String,
}

impl GraphSpec {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            schema: GRAPH_SPEC_SCHEMA.into(),
            name: name.into(),
            state_schema: Value::Object(Default::default()),
            nodes: vec![],
            edges: vec![],
            interrupt_before: vec![],
            compensations: vec![],
        }
    }
}

/// Ingress listener intent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListenerSpec {
    pub schema: String,
    pub listener_id: String,
    pub transport: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind_host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<String>,
}

impl ListenerSpec {
    pub fn http(listener_id: impl Into<String>, port: u16) -> Self {
        Self {
            schema: LISTENER_SPEC_SCHEMA.into(),
            listener_id: listener_id.into(),
            transport: "http".into(),
            bind_host: Some("0.0.0.0".into()),
            bind_port: Some(port),
            protocol: Some("http".into()),
            auth: None,
        }
    }
}

/// Route hop chain intent (compiles toward RouteGraph).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RouteSpec {
    pub schema: String,
    pub route_id: String,
    #[serde(default)]
    pub match_predicates: Vec<String>,
    #[serde(default)]
    pub hops: Vec<RouteHopSpec>,
    #[serde(default = "default_max_hops")]
    pub max_hops: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deadline_ms: Option<u64>,
}

fn default_max_hops() -> u32 {
    8
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RouteHopSpec {
    pub hop_id: String,
    pub kind: ProxyHopKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transform_ref: Option<String>,
}

impl RouteSpec {
    pub fn new(route_id: impl Into<String>) -> Self {
        Self {
            schema: ROUTE_SPEC_SCHEMA.into(),
            route_id: route_id.into(),
            match_predicates: vec![],
            hops: vec![],
            max_hops: default_max_hops(),
            deadline_ms: None,
        }
    }
}

/// Request/response transform — schema-validated; no raw secrets.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TransformSpec {
    pub schema: String,
    pub transform_id: String,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_schema: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<Value>,
    #[serde(default)]
    pub redaction_paths: Vec<String>,
}

/// Inference route intent (projection constraints; no credentials).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InferenceSpec {
    pub schema: String,
    pub inference_id: String,
    #[serde(default)]
    pub required_capabilities: Vec<String>,
    #[serde(default)]
    pub fail_closed_on_required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disclosure_policy: Option<String>,
    #[serde(default)]
    pub deny_provider_hosted_effects: bool,
}

impl InferenceSpec {
    pub fn new(inference_id: impl Into<String>) -> Self {
        Self {
            schema: INFERENCE_SPEC_SCHEMA.into(),
            inference_id: inference_id.into(),
            required_capabilities: vec![],
            fail_closed_on_required: true,
            disclosure_policy: None,
            deny_provider_hosted_effects: true,
        }
    }
}

/// Memory / context namespace intent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MemorySpec {
    pub schema: String,
    pub namespace: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visibility: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_packets: Option<u64>,
}

/// Budget ceilings (intent; enforcement is operator/node scoped).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BudgetSpec {
    pub schema: String,
    pub budget_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_calls: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_hops: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_duration_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_cost_micros: Option<u64>,
}

impl BudgetSpec {
    pub fn new(budget_id: impl Into<String>) -> Self {
        Self {
            schema: BUDGET_SPEC_SCHEMA.into(),
            budget_id: budget_id.into(),
            max_tokens: None,
            max_calls: None,
            max_bytes: None,
            max_hops: None,
            max_duration_ms: None,
            max_cost_micros: None,
        }
    }
}

/// Supervision / placement intent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SupervisionSpec {
    pub schema: String,
    pub supervision_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub isolation_grade: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restart_policy: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub concurrency: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health_path: Option<String>,
}

/// Target declaration (canonical connector:// + locators).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TargetSpec {
    pub schema: String,
    pub connector_uri: String,
    #[serde(default)]
    pub locators: Vec<String>,
    #[serde(default)]
    pub interfaces: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adapter_ref: Option<String>,
}

impl TargetSpec {
    pub fn new(connector_uri: impl Into<String>) -> Self {
        Self {
            schema: TARGET_SPEC_SCHEMA.into(),
            connector_uri: connector_uri.into(),
            locators: vec![],
            interfaces: vec![],
            adapter_ref: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::invocation::EffectDescriptor;

    #[test]
    fn tool_spec_digest_stable() {
        let t = ToolSpec::new(
            "write_file",
            "write_file",
            EffectDescriptor {
                effect_class: "fs.write".into(),
                mutates: true,
                disclosure_class: Some("filesystem".into()),
            },
        );
        let a = spec_digest(&t).unwrap();
        let b = spec_digest(&t).unwrap();
        assert_eq!(a, b);
        assert!(a.starts_with("spec-sha256-"));
    }

    #[test]
    fn secret_ref_has_no_value_field() {
        let s = SecretRef::handle("vault:openai");
        let v = serde_json::to_value(&s).unwrap();
        assert!(v.get("value").is_none());
        assert!(v.get("secret").is_none());
        assert_eq!(v["handle"], "vault:openai");
    }
}

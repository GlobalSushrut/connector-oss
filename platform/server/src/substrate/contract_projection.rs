//! Loss-aware `ContractProjection` for recognized inference channels.
//!
//! Projection encodes intelligence/contract/disclosure for a provider adapter.
//! It never carries bearer grants or credentials. Provider translation must
//! return a [`ProjectionLossReport`]; required unsupported features deny
//! before egress.

use connector_native_contract::{
    ContractProjection, InferenceCapabilities, ProjectionLossReport,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::state::{PlatformState, SharedState};
use crate::substrate::native_compat;

pub const FOLDER: &str = "contract_projection_v1";
pub const SCHEMA: &str = "connector.contract_projection.v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectInferenceRequest {
    /// Prefer native intelligence UID when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intelligence_uid: Option<String>,
    /// Legacy agent_pid compatibility.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_pid: Option<String>,
    pub principal_projection: String,
    pub contract_ref: String,
    #[serde(default)]
    pub generation: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mission_ref: Option<String>,
    #[serde(default)]
    pub disclosure_manifest: Vec<String>,
    #[serde(default)]
    pub knowledge_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_scope: Option<String>,
    #[serde(default)]
    pub instruction_blocks: Vec<String>,
    #[serde(default)]
    pub permitted_tool_descriptions: Vec<String>,
    #[serde(default)]
    pub response_constraints: Vec<String>,
    #[serde(default)]
    pub retention_requirements: Vec<String>,
    #[serde(default)]
    pub required_capabilities: Vec<String>,
    #[serde(default)]
    pub provider_capabilities: InferenceCapabilities,
    /// When true, missing required capabilities deny even if downgrade would be soft.
    #[serde(default = "default_true")]
    pub fail_closed_on_required: bool,
    #[serde(default = "default_ttl")]
    pub ttl_ms: i64,
}

fn default_true() -> bool {
    true
}

fn default_ttl() -> i64 {
    3_600_000
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectInferenceResult {
    pub ok: bool,
    pub projection: Option<ContractProjection>,
    pub loss: ProjectionLossReport,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deny_reason: Option<String>,
    pub honesty: String,
}

/// Evaluate capability loss between required feature names and provider caps.
pub fn evaluate_projection_loss(
    projection_digest: &str,
    required: &[String],
    caps: &InferenceCapabilities,
) -> ProjectionLossReport {
    let mut lost = Vec::new();
    let mut required_failures = Vec::new();

    for req in required {
        let key = req.trim().to_ascii_lowercase();
        let supported = match key.as_str() {
            "instruction_precedence" => caps.instruction_precedence,
            "strict_schema" | "strict_schema_support" => caps.strict_schema_support,
            "output_schema" | "output_schema_support" => caps.output_schema_support,
            "confidential_execution" => caps.confidential_execution,
            "hosted_effects" => caps.hosted_effects,
            "streaming" => caps.streaming_semantics.is_some(),
            "tool_calls" => caps.tool_call_mode.is_some(),
            "no_hosted_effects" => !caps.hosted_effects,
            other if other.starts_with("retention:") => {
                let mode = other.trim_start_matches("retention:");
                caps.retention_modes
                    .iter()
                    .any(|m| m.eq_ignore_ascii_case(mode))
            }
            other if other.starts_with("modality:") => {
                let m = other.trim_start_matches("modality:");
                caps.multimodal_types
                    .iter()
                    .any(|t| t.eq_ignore_ascii_case(m))
            }
            _ => false,
        };
        if !supported {
            lost.push(req.clone());
            required_failures.push(req.clone());
        }
    }

    // Hosted effects are always recorded as a loss feature when present —
    // Connector-owned execution prefers denying provider-side tools.
    if caps.hosted_effects {
        lost.push("provider_hosted_effects".into());
    }

    ProjectionLossReport {
        projection_digest: projection_digest.to_string(),
        lost_features: lost,
        required_failures,
        downgrade_allowed: required.is_empty(),
    }
}

fn resolve_intelligence_ref(state: Option<&PlatformState>, req: &ProjectInferenceRequest) -> String {
    if let Some(uid) = req
        .intelligence_uid
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        return uid.to_string();
    }
    if let Some(pid) = req.agent_pid.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        if let Some(st) = state {
            if let Some(m) = native_compat::resolve_by_agent_pid(st, pid) {
                if let Some(uid) = m.intelligence_uid {
                    return uid;
                }
            }
        }
        return format!("intel_compat:{pid}");
    }
    "intel_unknown".into()
}

/// Build a digest-stable projection and evaluate provider loss (no persistence).
pub fn project_inference_ephemeral(req: &ProjectInferenceRequest) -> ProjectInferenceResult {
    project_inference_inner(None, req, false)
}

/// Build a digest-stable projection, evaluate provider loss, and persist when allowed.
pub fn project_inference(
    state: &PlatformState,
    req: &ProjectInferenceRequest,
) -> ProjectInferenceResult {
    project_inference_inner(Some(state), req, true)
}

fn project_inference_inner(
    state: Option<&PlatformState>,
    req: &ProjectInferenceRequest,
    persist: bool,
) -> ProjectInferenceResult {
    let now = chrono::Utc::now().timestamp_millis();
    let intelligence_ref = resolve_intelligence_ref(state, req);
    let mut projection = ContractProjection {
        intelligence_ref,
        generation: req.generation,
        principal_projection: req.principal_projection.clone(),
        mission_ref: req.mission_ref.clone(),
        disclosure_manifest: req.disclosure_manifest.clone(),
        knowledge_refs: req.knowledge_refs.clone(),
        memory_scope: req.memory_scope.clone(),
        instruction_blocks: req.instruction_blocks.clone(),
        permitted_tool_descriptions: req.permitted_tool_descriptions.clone(),
        response_constraints: req.response_constraints.clone(),
        retention_requirements: req.retention_requirements.clone(),
        projection_revision: 1,
        source_digests: vec![
            format!("contract:{}", req.contract_ref),
            format!("schema:{SCHEMA}"),
        ],
        expires_at_ms: now.saturating_add(req.ttl_ms.max(60_000)),
        projection_digest: String::new(),
    };
    projection.projection_digest = projection.compute_digest();

    let mut loss = evaluate_projection_loss(
        &projection.projection_digest,
        &req.required_capabilities,
        &req.provider_capabilities,
    );

    // Required no_hosted_effects: if provider hosts effects, fail.
    let wants_no_hosted = req
        .required_capabilities
        .iter()
        .any(|c| c.eq_ignore_ascii_case("no_hosted_effects"));
    if wants_no_hosted && req.provider_capabilities.hosted_effects {
        loss.required_failures.push("no_hosted_effects".into());
        if !loss
            .lost_features
            .iter()
            .any(|f| f == "provider_hosted_effects")
        {
            loss.lost_features.push("provider_hosted_effects".into());
        }
    }

    let deny = req.fail_closed_on_required && !loss.required_failures.is_empty();
    if !deny && persist {
        if let Some(st) = state {
            if let Ok(mut es) = st.engine_store.lock() {
                let _ = es.folder_put(
                    FOLDER,
                    &projection.projection_digest,
                    &json!({
                        "schema": SCHEMA,
                        "projection": projection,
                        "loss": loss,
                        "at_ms": now,
                    }),
                );
            }
        }
    }

    ProjectInferenceResult {
        ok: !deny,
        projection: if deny { None } else { Some(projection) },
        loss,
        deny_reason: if deny {
            Some("required_projection_capability_unavailable".into())
        } else {
            None
        },
        honesty: "ContractProjection proves encoding intent only — not model obedience. Credentials and grants are never embedded.".into(),
    }
}

pub async fn http_project(
    axum::extract::State(state): axum::extract::State<SharedState>,
    axum::Json(req): axum::Json<ProjectInferenceRequest>,
) -> axum::Json<Value> {
    let result = project_inference(state.as_ref(), &req);
    axum::Json(json!({
        "ok": result.ok,
        "schema": SCHEMA,
        "projection": result.projection,
        "loss": result.loss,
        "deny_reason": result.deny_reason,
        "honesty": result.honesty,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loss_reports_missing_strict_schema() {
        let caps = InferenceCapabilities::default();
        let loss = evaluate_projection_loss(
            "digest",
            &["strict_schema".into()],
            &caps,
        );
        assert!(loss.required_failures.iter().any(|f| f == "strict_schema"));
        assert!(!loss.downgrade_allowed);
    }

    #[test]
    fn hosted_effects_denied_when_required_absent() {
        let req = ProjectInferenceRequest {
            intelligence_uid: Some("intel_1".into()),
            agent_pid: None,
            principal_projection: "prin:x".into(),
            contract_ref: "dev-agent-v1".into(),
            generation: 1,
            mission_ref: None,
            disclosure_manifest: vec![],
            knowledge_refs: vec![],
            memory_scope: None,
            instruction_blocks: vec!["stay in role".into()],
            permitted_tool_descriptions: vec![],
            response_constraints: vec![],
            retention_requirements: vec![],
            required_capabilities: vec!["no_hosted_effects".into()],
            provider_capabilities: InferenceCapabilities {
                hosted_effects: true,
                ..Default::default()
            },
            fail_closed_on_required: true,
            ttl_ms: 60_000,
        };
        let result = project_inference_ephemeral(&req);
        assert!(!result.ok);
        assert!(result.projection.is_none());
        assert_eq!(
            result.deny_reason.as_deref(),
            Some("required_projection_capability_unavailable")
        );
    }

    #[test]
    fn successful_projection_has_stable_digest() {
        let caps = InferenceCapabilities {
            instruction_precedence: true,
            strict_schema_support: true,
            ..Default::default()
        };
        let req = ProjectInferenceRequest {
            intelligence_uid: Some("intel_abc".into()),
            agent_pid: None,
            principal_projection: "prin:y".into(),
            contract_ref: "c1".into(),
            generation: 3,
            mission_ref: None,
            disclosure_manifest: vec!["public".into()],
            knowledge_refs: vec![],
            memory_scope: Some("mem:1".into()),
            instruction_blocks: vec![],
            permitted_tool_descriptions: vec![],
            response_constraints: vec![],
            retention_requirements: vec![],
            required_capabilities: vec!["instruction_precedence".into(), "strict_schema".into()],
            provider_capabilities: caps,
            fail_closed_on_required: true,
            ttl_ms: 60_000,
        };
        let result = project_inference_ephemeral(&req);
        assert!(result.ok);
        let p = result.projection.expect("projection");
        assert!(p.digest_matches());
        assert!(!p.projection_digest.is_empty());
        let v = serde_json::to_value(&p).unwrap();
        let s = v.to_string().to_ascii_lowercase();
        assert!(!s.contains("api_key"));
        assert!(!s.contains("\"grant\""));
        assert!(!s.contains("bearer"));
    }
}

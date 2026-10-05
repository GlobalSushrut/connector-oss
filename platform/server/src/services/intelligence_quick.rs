//! POST /intelligence/apply — k8s-like 5-minute agent create (membrane-ready).

use axum::{extract::State, http::HeaderMap, Json};
use serde_json::{json, Value};

use crate::kernel::agent_principal::ContractPatchV2;
use crate::kernel::intelligence_spec::{
    self, IntelligenceClass, IntelligenceSpecV1, KnowledgeSeedV1,
};
use crate::services::agent_identity::{self, AgentSetupBody};
use crate::services::agents::{self, caller, RegisterAgentRequest};
use crate::services::memory;
use crate::state::SharedState;

/// GET /intelligence/spec-schema — operator template (parameters→skills→knowledge→limits→portals→rules).
pub async fn get_spec_schema() -> Json<Value> {
    Json(json!({
        "ok": true,
        "schema": intelligence_spec::SPEC_SCHEMA,
        "summary": "Declare an Intelligence like a k8s object, then apply once. ~5 minutes to a membrane-ready agent.",
        "flow": [
            "parameters (name, purpose, class, model, namespace)",
            "skills (bounded typed capabilities — not markdown)",
            "knowledge (1 line or long docs → /k primary dataset)",
            "limitations (caps, deny, network, HITL, forensic)",
            "portals (real-world access: machines, APIs, IoT, cluster)",
            "rules (ask/block/note boundaries)",
            "ACS + NS FS + light_ns isolation (created on apply — top-level, not plugin settings)",
        ],
        "classes": ["app", "robotics", "iot", "cybernetic", "service", "custom"],
        "example": intelligence_spec::openapi_schema_hint(),
        "apply": "POST /api/v1/intelligence/apply",
        "cpkg": {
            "role": "Optional later: ship custom runtime logic as .cpkg that calls these APIs as the agent_pid",
            "not_required_for_5min": true,
        },
        "military_ready": {
            "harden": true,
            "means": "HITL≥tool, forensic≥standard, network_default=deny, ambient_shell denied, activate on apply",
        },
    }))
}

/// POST /intelligence/apply — create + charter + knowledge + activate in one shot.
pub async fn apply_intelligence(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(spec): Json<IntelligenceSpecV1>,
) -> Json<Value> {
    let (_uid, role) = match caller(&headers) {
        Some(c) => c,
        None => return Json(json!({"ok": false, "error": "auth_required", "status": 401})),
    };
    if role.rank() < 3 {
        return Json(json!({"ok": false, "error": "developer_required", "status": 403}));
    }

    if spec.kind != "Intelligence" && !spec.kind.is_empty() {
        return Json(json!({
            "ok": false,
            "error": "kind_must_be_Intelligence",
            "got": spec.kind,
        }));
    }
    if spec.metadata.name.trim().is_empty() {
        return Json(json!({"ok": false, "error": "metadata.name_required"}));
    }
    if spec.spec.purpose.trim().is_empty() {
        return Json(json!({"ok": false, "error": "spec.purpose_required"}));
    }

    let class = IntelligenceClass::parse(spec.spec.class.as_deref().unwrap_or("app"));
    let name = spec.metadata.name.trim().to_string();
    let purpose = spec.spec.purpose.trim().to_string();
    let kb_id = format!("kb:{}", name.to_lowercase().replace([' ', '_'], "-"));

    let tags = {
        let mut t = spec.spec.parameters.tags.clone();
        t.push(format!("class:{}", class.as_str()));
        t.push("intelligence_spec_v1".into());
        t
    };

    // 1) Register
    let reg = agents::register_agent(
        State(state.clone()),
        headers.clone(),
        Json(RegisterAgentRequest {
            name: name.clone(),
            namespace: spec.spec.parameters.namespace.clone(),
            role: spec
                .spec
                .parameters
                .role
                .clone()
                .or_else(|| Some("reader".into())),
            model: spec.spec.parameters.model.clone(),
            instructions: spec.spec.parameters.instructions.clone(),
            token_budget: spec.spec.parameters.token_budget,
            tags: Some(tags),
            hipaa: spec
                .spec
                .limitations
                .forensic
                .as_deref()
                .map(|f| f.eq_ignore_ascii_case("hipaa"))
                .unwrap_or(false),
            parent_pid: None,
            purpose: Some(purpose.clone()),
            geo_id: None,
            master_agent_id: None,
            knowledge_base_id: Some(kb_id.clone()),
        }),
    )
    .await;
    let reg_v = reg.0;
    if reg_v.get("error").is_some() {
        let cap = reg_v.get("code").and_then(|x| x.as_str()) == Some("PLAYGROUND_AGENT_CAP");
        let existing = reg_v
            .get("existing_pid")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        // Playground is one Demo per session. Do not rename/reuse it as a successful create.
        return Json(json!({
            "ok": false,
            "stage": "register",
            "error": reg_v.get("error"),
            "code": if cap { json!("PLAYGROUND_AGENT_CAP") } else { reg_v.get("code").cloned().unwrap_or(Value::Null) },
            "existing_pid": if existing.is_empty() { Value::Null } else { json!(existing) },
            "hint": if cap {
                json!("This trial allows one agent. Open the Demo already in this session — Isolate / Govern / Stop / Prove need no LLM key.")
            } else {
                reg_v.get("hint").cloned().unwrap_or(Value::Null)
            },
            "detail": reg_v,
        }));
    }
    let pid = match reg_v.get("pid").and_then(|v| v.as_str()) {
        Some(p) => p.to_string(),
        None => {
            return Json(
                json!({"ok": false, "stage": "register", "error": "missing_pid", "detail": reg_v}),
            );
        }
    };
    let kernel_pid = reg_v
        .get("kernel_pid")
        .and_then(|v| v.as_str())
        .unwrap_or(pid.as_str())
        .to_string();

    let outcome = match apply_spec_to_agent(
        &state,
        &headers,
        &pid,
        &kernel_pid,
        &name,
        &purpose,
        &kb_id,
        &class,
        &spec,
    )
    .await
    {
        Ok(o) => o,
        Err(e) => return Json(e),
    };

    Json(json!({
        "ok": true,
        "schema": intelligence_spec::SPEC_SCHEMA,
        "pid": pid,
        "name": name,
        "class": class.as_str(),
        "purpose": purpose,
        "harden": spec.spec.harden,
        "charter": {
            "capabilities": outcome.caps,
            "denied_operations": outcome.denied,
            "network_default": outcome.network_default,
            "hitl": outcome.hitl,
            "forensic": outcome.forensic,
        },
        "skills_bound": spec.spec.skills.len(),
        "portals": spec.spec.portals.len(),
        "rules": spec.spec.rules.len(),
        "knowledge_ingested": outcome.knowledge_ingested,
        "knowledge_errors": outcome.knowledge_errors,
        "knowledge_namespace": outcome.ns,
        "nsfs": outcome.nsfs,
        "acs": format!("GET /api/v1/runtime/acs/{pid}"),
        "cage": format!("GET /api/v1/runtime/cage/{pid}"),
        "isolation": format!("GET /api/v1/runtime/isolation/{pid}"),
        "density": crate::kernel::isolation_tiers::light_isolation_profile(),
        "activation": outcome.activation,
        "next": [
            format!("Talk: POST /api/v1/agents/{pid}/completions"),
            format!("Skills: GET /api/v1/agents/{pid}/skills"),
            format!("Portals: GET /api/v1/intelligence/{pid}/pack"),
            "Control UI: Start → Talk → Pause → Kill",
            "Optional .cpkg later for custom runtime logic",
        ],
        "honesty": "5-minute create still goes through DockLock charter membrane — not a prompt-only bot",
    }))
}

struct ApplySpecOutcome {
    caps: Vec<String>,
    denied: Vec<String>,
    network_default: String,
    hitl: String,
    forensic: String,
    knowledge_ingested: u64,
    knowledge_errors: Vec<Value>,
    ns: String,
    nsfs: Value,
    activation: Value,
}

async fn apply_spec_to_agent(
    state: &SharedState,
    headers: &HeaderMap,
    pid: &str,
    kernel_pid: &str,
    name: &str,
    purpose: &str,
    kb_id: &str,
    class: &IntelligenceClass,
    spec: &IntelligenceSpecV1,
) -> Result<ApplySpecOutcome, Value> {
    let caps = intelligence_spec::resolve_capabilities(&spec.spec);
    let denied = intelligence_spec::resolve_denied(&spec.spec);
    let network_default = spec
        .spec
        .limitations
        .network_default
        .clone()
        .unwrap_or_else(|| {
            if spec.spec.harden {
                "deny".into()
            } else {
                "deny".into()
            }
        });
    let patch = ContractPatchV2 {
        purpose: Some(vec![purpose.to_string()]),
        capabilities: Some(caps.clone()),
        denied_operations: Some(denied.clone()),
        filesystem_read: if spec.spec.limitations.filesystem_read.is_empty() {
            None
        } else {
            Some(spec.spec.limitations.filesystem_read.clone())
        },
        filesystem_write: if spec.spec.limitations.filesystem_write.is_empty() {
            None
        } else {
            Some(spec.spec.limitations.filesystem_write.clone())
        },
        network_allow: Some(spec.spec.limitations.network_allow.clone()),
        network_default: Some(network_default.clone()),
        receipt_required: Some(true),
    };
    if let Err(e) = crate::kernel::agent_principal::update_contract(state.as_ref(), pid, patch) {
        return Err(json!({"ok": false, "stage": "contract", "error": e, "pid": pid}));
    }

    let hitl = spec.spec.limitations.hitl.clone().unwrap_or_else(|| {
        if spec.spec.harden {
            "tool".into()
        } else {
            "none".into()
        }
    });
    let forensic = spec.spec.limitations.forensic.clone().unwrap_or_else(|| {
        if spec.spec.harden {
            "standard".into()
        } else {
            "off".into()
        }
    });

    let use_case = json!({
        "schema": "connector.intelligence.use_case.v1",
        "class": class.as_str(),
        "summary": purpose,
        "skills_count": spec.spec.skills.len(),
        "portals_count": spec.spec.portals.len(),
        "rules_count": spec.spec.rules.len(),
        "harden": spec.spec.harden,
    });

    let setup = agent_identity::post_agent_setup(
        State(state.clone()),
        headers.clone(),
        axum::extract::Path(pid.to_string()),
        Json(AgentSetupBody {
            name: Some(name.to_string()),
            acume: Some(purpose.to_string()),
            memory_profile: None,
            knowledge_base_id: Some(kb_id.to_string()),
            use_case_def: Some(use_case),
            contract_ref: None,
            hitl_policy: Some(hitl.clone()),
            forensic_profile: Some(forensic.clone()),
            philosophy_digest: None,
            common_spaces: None,
            setup_complete: Some(true),
            skills: Some(spec.spec.skills.clone()),
            portals: Some(spec.spec.portals.clone()),
            rules: Some(spec.spec.rules.clone()),
            knowledge: Some(spec.spec.knowledge.clone()),
        }),
    )
    .await;
    let setup_v = setup.0;
    if setup_v.get("ok") == Some(&Value::Bool(false)) {
        return Err(json!({"ok": false, "stage": "setup", "detail": setup_v, "pid": pid}));
    }

    if let Err(e) = intelligence_spec::persist_bound_pack(
        state.as_ref(),
        pid,
        &spec.spec.skills,
        &spec.spec.portals,
        &spec.spec.rules,
        spec,
    ) {
        return Err(json!({"ok": false, "stage": "persist_pack", "error": e, "pid": pid}));
    }

    let nsfs = crate::kernel::nsfs::ensure_tree(pid).unwrap_or_else(|e| {
        json!({"ok": false, "error": e, "honesty": "NS FS mkdir failed — isolation still charter/DockLock"})
    });

    let mut knowledge_ingested = 0u64;
    let mut knowledge_errors = Vec::new();
    let ns = format!(
        "k/{}",
        crate::kernel::agent_identity_envelope::normalize_kb_path_segment(kb_id)
    );
    for (i, seed) in spec.spec.knowledge.iter().enumerate() {
        let body = seed.body();
        if body.trim().is_empty() {
            continue;
        }
        let title = seed.title.clone().unwrap_or_else(|| format!("seed-{i}"));
        let text = if title.is_empty() {
            body
        } else {
            format!("# {title}\n\n{body}")
        };
        let ingest = memory::knowledge_ingest(
            State(state.clone()),
            Json(json!({
                "namespace": ns,
                "agent_pid": kernel_pid,
                "records": [{
                    "text": text,
                    "role": "system",
                    "tags": seed.tags,
                    "dedupe_key": format!("ispec:{pid}:{i}"),
                }],
                "source": { "kind": "intelligence_spec", "title": title },
            })),
        )
        .await;
        let iv = ingest.0;
        if iv.get("ok") == Some(&Value::Bool(false)) || iv.get("error").is_some() {
            knowledge_errors.push(iv);
        } else {
            knowledge_ingested += 1;
        }
    }

    let mut activation = Value::Null;
    if spec.spec.activate {
        let act = agent_identity::post_agent_activate(
            State(state.clone()),
            headers.clone(),
            axum::extract::Path(pid.to_string()),
        )
        .await;
        activation = act.0;
        if activation.get("ok") == Some(&Value::Bool(false)) {
            return Err(json!({
                "ok": false,
                "stage": "activate",
                "detail": activation,
                "pid": pid,
                "knowledge_ingested": knowledge_ingested,
            }));
        }
    }

    Ok(ApplySpecOutcome {
        caps,
        denied,
        network_default,
        hitl,
        forensic,
        knowledge_ingested,
        knowledge_errors,
        ns,
        nsfs,
        activation,
    })
}

/// GET /intelligence/:pid/pack — bound skills + portals + rules for an agent.
pub async fn get_intelligence_pack(
    State(state): State<SharedState>,
    headers: HeaderMap,
    axum::extract::Path(pid): axum::extract::Path<String>,
) -> Json<Value> {
    if caller(&headers).is_none() {
        return Json(json!({"ok": false, "error": "auth_required"}));
    }
    let spec = intelligence_spec::load_spec_doc(state.as_ref(), &pid);
    Json(json!({
        "ok": true,
        "pid": pid,
        "name": spec
            .as_ref()
            .and_then(|s| s.pointer("/metadata/name"))
            .and_then(|x| x.as_str()),
        "class": spec
            .as_ref()
            .and_then(|s| s.pointer("/spec/class"))
            .and_then(|x| x.as_str()),
        "purpose": spec
            .as_ref()
            .and_then(|s| s.pointer("/spec/purpose"))
            .and_then(|x| x.as_str()),
        "harden": spec
            .as_ref()
            .and_then(|s| s.pointer("/spec/harden"))
            .and_then(|x| x.as_bool()),
        "skills": intelligence_spec::load_bound_skills(state.as_ref(), &pid),
        "portals": intelligence_spec::load_portals(state.as_ref(), &pid),
        "rules": intelligence_spec::load_rules(state.as_ref(), &pid),
        "nsfs": crate::kernel::nsfs::snapshot(&pid),
        "acs": format!("GET /api/v1/runtime/acs/{pid}"),
        "cage": format!("GET /api/v1/runtime/cage/{pid}"),
        "honesty": "Bounded skills are typed capabilities — not markdown files. ACS/NS FS/isolation are top-level. Outer world is an address cage; same machine ≠ host identity.",
    }))
}

#[allow(dead_code)]
fn _seed_type_check(s: &KnowledgeSeedV1) -> String {
    s.body()
}

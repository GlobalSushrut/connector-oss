//! IIA runtime HTTP surface — `/runtime/self`, N4, QPR, delegate, provenance.

use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::intelligence_admission::{self, N4CognizeRequest, N4HelloRequest};
use crate::kernel::{agent_principal, continuity, forensics};
use crate::quanta_polar::{self, QprIntentRequest};
use crate::state::SharedState;

#[derive(Debug, Deserialize)]
pub struct AgentPidQuery {
    pub agent_pid: String,
}

fn auth_agent_access(headers: &HeaderMap, agent_pid: &str) -> Result<(), Json<serde_json::Value>> {
    if crate::auth::extract_claims(headers).is_some() {
        return Ok(());
    }
    if crate::kernel::agent_identity_envelope::agent_self_access(headers, agent_pid) {
        return Ok(());
    }
    Err(Json(
        json!({"error": "Authentication required", "status": 401}),
    ))
}

/// GET /api/v1/runtime/self?agent_pid=
pub async fn get_runtime_self(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Query(q): Query<AgentPidQuery>,
) -> Json<serde_json::Value> {
    if let Err(e) = auth_agent_access(&headers, &q.agent_pid) {
        return e;
    }
    match agent_principal::runtime_self_envelope(state.as_ref(), &q.agent_pid) {
        Some(base) => {
            let identity = crate::kernel::agent_identity_envelope::build_identity_envelope(
                state.as_ref(),
                &q.agent_pid,
            );
            let who = identity
                .as_ref()
                .and_then(|e| e.who_am_i_authoritative.clone())
                .or(base.who_am_i_authoritative.clone());
            let hash = base
                .foundation_block
                .as_ref()
                .map(|f| f.agent_intelligence_hash.clone());
            let foundation = base.foundation_block.clone();
            let forensic_records = crate::kernel::agent_identity_envelope::list_forensic_universal(
                state.as_ref(),
                &q.agent_pid,
            );
            let mark =
                crate::kernel::matrix_host_egress::intelligence_egress_mark_hex(&q.agent_pid);
            Json(json!({
                "ok": true,
                "self": base,
                "identity_envelope": identity,
                "who_am_i_authoritative": who,
                "agent_intelligence_hash": hash,
                "foundation_block": foundation,
                "forensic_universal_schema": connector_trust::FORENSIC_UNIVERSAL_SCHEMA,
                "forensic_universal_records": forensic_records.len(),
                "principal_id": base.principal.principal_id,
                "intelligence_mark": mark,
                "continuity_state": format!("{:?}", base.continuity.state),
                "iia_v2": true,
            }))
        }
        None => Json(json!({
            "ok": false,
            "error": "principal_not_found",
            "message": "Agent registered before IIA — re-register or migrate",
        })),
    }
}

/// GET /api/v1/runtime/contract?agent_pid=
pub async fn get_runtime_contract(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Query(q): Query<AgentPidQuery>,
) -> Json<serde_json::Value> {
    if let Err(e) = auth_agent_access(&headers, &q.agent_pid) {
        return e;
    }
    match agent_principal::load_contract(state.as_ref(), &q.agent_pid) {
        Some(c) => Json(json!({"ok": true, "contract": c})),
        None => Json(json!({"ok": false, "error": "contract_not_found"})),
    }
}

/// GET /api/v1/runtime/hardware
pub async fn get_runtime_hardware(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> Json<serde_json::Value> {
    if crate::auth::extract_claims(&headers).is_none() {
        return Json(json!({"error": "Authentication required", "status": 401}));
    }
    let erm = continuity::mint_execution_reality_manifest(state.as_ref());
    Json(json!({"ok": true, "execution_reality": erm}))
}

/// GET /api/v1/runtime/permissions?agent_pid=
pub async fn get_runtime_permissions(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Query(q): Query<AgentPidQuery>,
) -> Json<serde_json::Value> {
    if let Err(e) = auth_agent_access(&headers, &q.agent_pid) {
        return e;
    }
    let contract = agent_principal::load_contract(state.as_ref(), &q.agent_pid);
    let continuity = agent_principal::load_continuity(state.as_ref(), &q.agent_pid);
    Json(json!({
        "ok": true,
        "capabilities": contract.as_ref().map(|c| &c.capabilities),
        "denied_operations": contract.as_ref().map(|c| &c.denied_operations),
        "continuity": continuity,
        "qpr_enforce": quanta_polar::qpr_enforce_enabled(),
    }))
}

/// GET /api/v1/runtime/provenance?agent_pid=
pub async fn get_runtime_provenance(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Query(q): Query<AgentPidQuery>,
) -> Json<serde_json::Value> {
    if let Err(e) = auth_agent_access(&headers, &q.agent_pid) {
        return e;
    }
    let receipts = forensics::export_receipt_chain(state.as_ref(), &q.agent_pid);
    let four_id = forensics::four_id_linkage(state.as_ref(), &q.agent_pid);
    Json(json!({
        "ok": true,
        "receipt_count": receipts.len(),
        "receipts": receipts,
        "four_id": four_id,
    }))
}

/// POST /api/v1/n4/hello
pub async fn post_n4_hello(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<N4HelloRequest>,
) -> Json<serde_json::Value> {
    if let Err(e) = auth_agent_access(&headers, &req.agent_pid) {
        return e;
    }
    match intelligence_admission::n4_handshake(state.as_ref(), &req) {
        Ok(profile) => Json(json!({"ok": true, "profile": profile})),
        Err(e) => Json(e),
    }
}

/// POST /api/v1/n4/qualify — alias: re-run handshake with observed fields.
pub async fn post_n4_qualify(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<N4HelloRequest>,
) -> Json<serde_json::Value> {
    post_n4_hello(State(state), headers, Json(req)).await
}

/// POST /api/v1/n4/cognize
pub async fn post_n4_cognize(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<N4CognizeRequest>,
) -> Json<serde_json::Value> {
    if let Err(e) = auth_agent_access(&headers, &req.agent_pid) {
        return e;
    }
    match intelligence_admission::n4_cognize(state.as_ref(), &req) {
        Ok(cpo) => Json(json!({
            "ok": true,
            "cpo": cpo,
            "non_authoritative": true,
            "message": "CPO is not execution authority — POST /qpr/intent next",
        })),
        Err(e) => Json(e),
    }
}

/// POST /api/v1/qpr/intent
pub async fn post_qpr_intent(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<QprIntentRequest>,
) -> Json<serde_json::Value> {
    if let Err(e) = auth_agent_access(&headers, &req.agent_pid) {
        return e;
    }
    match quanta_polar::polarize_cpo(state.as_ref(), &req) {
        Ok(q) => {
            let _ = forensics::append_receipt(
                state.as_ref(),
                forensics::AppendReceiptParams {
                    agent_pid: req.agent_pid.clone(),
                    cpo_id: Some(req.cpo_id),
                    quantum_id: Some(q.quantum_id.clone()),
                    docklock_profile_id: None,
                    effect_digest: q.nonce.clone(),
                },
            );
            Json(json!({"ok": true, "execution_quantum": q}))
        }
        Err(e) => Json(e),
    }
}

#[derive(Debug, Deserialize)]
pub struct DelegateRequest {
    pub from_agent_pid: String,
    pub to_agent_pid: String,
    pub scope: Vec<String>,
    pub ttl_secs: i64,
    #[serde(default)]
    pub parent_grant_id: Option<String>,
    #[serde(default)]
    pub address: Option<String>,
}

/// POST /api/v1/runtime/delegate
pub async fn post_runtime_delegate(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<DelegateRequest>,
) -> Json<serde_json::Value> {
    if let Err(e) = auth_agent_access(&headers, &req.from_agent_pid) {
        return e;
    }
    let from = agent_principal::load_principal(state.as_ref(), &req.from_agent_pid);
    let to = agent_principal::load_principal(state.as_ref(), &req.to_agent_pid);
    if from.is_none() || to.is_none() {
        return Json(json!({"ok": false, "error": "principal_not_found", "executed": false, "admits": false}));
    }
    let (Some(parent_grant_id), Some(address)) = (req.parent_grant_id.as_deref().map(str::trim).filter(|item| !item.is_empty()), req.address.as_deref().map(str::trim).filter(|item| !item.is_empty())) else {
        return Json(json!({
            "ok": false,
            "error": "parent_grant_required",
            "executed": false,
            "admits": false,
            "honesty": "Delegation without a parent GrantRef is not stored.",
        }));
    };
    let grant = crate::kernel::world_gateway::WorldGrantV1 {
        agent_pid: req.to_agent_pid.clone(),
        address: address.to_string(),
        address_type: "delegation".into(),
        access: req.scope.clone(),
        effect: "ask".into(),
        layer: "cone".into(),
        app_allow: Vec::new(),
        cone_ask: Vec::new(),
        justification: None,
        params: json!({}),
        note: Some("attenuated delegation".into()),
    };
    let (grant_ref, revision) = match crate::substrate::authority_repo::mint_world_grant(
        state.as_ref(),
        &grant,
        None,
        Some(parent_grant_id),
    ) {
        Ok(minted) => minted,
        Err(error) => {
            return Json(json!({"ok": false, "error": error, "executed": false, "admits": false}));
        }
    };
    let expires = chrono::Utc::now().timestamp_millis() + req.ttl_secs * 1000;
    let delegation = json!({
        "from_agent_pid": req.from_agent_pid,
        "to_agent_pid": req.to_agent_pid,
        "scope": req.scope,
        "expires_at_ms": expires,
        "grant_id": grant_ref.grant_id,
        "authority_revision": revision,
        "effect": "ask",
        "executed": false,
        "admits": false,
    });
    let mut es = state.engine_store.lock().unwrap();
    let key = format!("{}:{}", req.from_agent_pid, req.to_agent_pid);
    let _ = es.folder_put("iia_delegation_v2", &key, &delegation);
    Json(json!({"ok": true, "delegation": delegation}))
}

/// POST /api/v1/runtime/continuity/evaluate?agent_pid=
pub async fn post_continuity_evaluate(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Query(q): Query<AgentPidQuery>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    if let Err(e) = auth_agent_access(&headers, &q.agent_pid) {
        return e;
    }
    let rh = body
        .get("runtime_hash")
        .and_then(|v| v.as_str())
        .unwrap_or("tampered");
    let mr = body
        .get("model_ref")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let record = continuity::evaluate_continuity(&state, &q.agent_pid, rh, mr);
    Json(json!({"ok": true, "continuity": record}))
}

/// GET /api/v1/runtime/export?agent_pid= — evidence export (honest signing_tier).
pub async fn get_runtime_export(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Query(q): Query<AgentPidQuery>,
) -> Json<serde_json::Value> {
    if let Err(e) = auth_agent_access(&headers, &q.agent_pid) {
        return e;
    }
    let envelope = agent_principal::runtime_self_envelope(state.as_ref(), &q.agent_pid);
    let receipts = forensics::export_receipt_chain(state.as_ref(), &q.agent_pid);
    let erm = continuity::mint_execution_reality_manifest(state.as_ref());
    // Never stamp court here — derive from forensic package rules (B26).
    let (signing_tier, package_ok, honesty) = match crate::kernel::forensic_package::build_package(
        state.as_ref(),
        &q.agent_pid,
        None,
        None,
    ) {
        Ok(pkg) => {
            let tier = pkg
                .pointer("/manifest/signing_tier")
                .and_then(|v| v.as_str())
                .unwrap_or("hmac_lab")
                .to_string();
            let honesty = pkg.get("manifest").and_then(|m| m.get("honesty")).cloned();
            (tier, true, honesty)
        }
        Err(e) => (
            "hmac_lab".into(),
            false,
            Some(json!({
                "hmac_not_court_grade": true,
                "package_error": e,
                "honesty": "Export does not claim court without a valid forensic package.",
            })),
        ),
    };
    Json(json!({
        "ok": true,
        "signing_tier": signing_tier,
        "package_resolved": package_ok,
        "self": envelope,
        "receipts": receipts,
        "execution_reality": erm,
        "honesty": honesty,
        "verify_hint": "connectorctl iia verify-export --file export.json",
        "forensic_package_hint": format!("GET /api/v1/forensics/package?agent_pid={}", q.agent_pid),
    }))
}

/// GET /api/v1/runtime/matrix?agent_pid= — CDMI isolation posture (hardware-capable nodes).
pub async fn get_runtime_matrix(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Query(q): Query<AgentPidQuery>,
) -> Json<serde_json::Value> {
    if let Err(e) = auth_agent_access(&headers, &q.agent_pid) {
        return e;
    }
    Json(json!({
        "ok": true,
        "matrix": crate::kernel::matrix_isolation::status_for_agent(state.as_ref(), &q.agent_pid),
    }))
}

/// GET /api/v1/runtime/effect-exclusivity/status — effect mediator posture.
pub async fn get_effect_exclusivity_status(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> Json<serde_json::Value> {
    if crate::auth::extract_claims(&headers).is_none() {
        return Json(json!({"error": "Authentication required", "status": 401}));
    }
    Json(json!({
        "ok": true,
        "effect_exclusivity": crate::substrate::effect_exclusivity::effect_exclusivity_status(state.as_ref()),
    }))
}

#[derive(Debug, Deserialize)]
pub struct EffectExclusivityProbeRequest {
    pub agent_pid: String,
    pub bypass_kind: String,
}

/// POST /api/v1/runtime/effect-exclusivity/probe — adversarial alternate-path probe.
pub async fn post_effect_exclusivity_probe(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<EffectExclusivityProbeRequest>,
) -> Json<serde_json::Value> {
    if let Err(e) = auth_agent_access(&headers, &req.agent_pid) {
        return e;
    }
    match crate::substrate::effect_exclusivity::probe_effect_bypass(
        state.as_ref(),
        &req.agent_pid,
        &req.bypass_kind,
    ) {
        Ok(v) => Json(v),
        Err(e) => Json(e),
    }
}

#[derive(Debug, Deserialize)]
pub struct ZtHandshakeEstablishRequest {
    pub agent_pid: String,
    pub bridge_id: String,
    pub tool_name: String,
    #[serde(default)]
    pub manifest_hash: Option<String>,
}

/// POST /api/v1/runtime/zt-handshake/establish — node-signed genesis block.
pub async fn post_zt_handshake_establish(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<ZtHandshakeEstablishRequest>,
) -> Json<serde_json::Value> {
    if let Err(e) = auth_agent_access(&headers, &req.agent_pid) {
        return e;
    }
    match crate::kernel::zt_handshake::establish(
        state.as_ref(),
        &req.agent_pid,
        &req.bridge_id,
        &req.tool_name,
        req.manifest_hash.as_deref(),
    ) {
        Ok(hs) => Json(json!({
            "ok": true,
            "handshake": hs,
            "llm_holds_session_key": false,
            "honesty": "Genesis is node-signed. The LLM cannot establish or forge this handshake.",
        })),
        Err(e) => Json(e),
    }
}

/// GET /api/v1/runtime/microvm-tools/status — tools-in-microVM posture.
pub async fn get_microvm_tools_status(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> Json<serde_json::Value> {
    if crate::auth::extract_claims(&headers).is_none() {
        return Json(json!({"error": "Authentication required", "status": 401}));
    }
    Json(json!({
        "ok": true,
        "microvm_tool_plane": crate::substrate::microvm_tool_plane::status(state.as_ref()),
        "agentic_context": crate::substrate::agentic_context::status(),
    }))
}

#[derive(Debug, Deserialize)]
pub struct MicrovmToolInvokeRequest {
    pub agent_pid: String,
    pub bridge_id: String,
    pub tool_name: String,
    #[serde(default)]
    pub input: serde_json::Value,
}

/// POST /api/v1/runtime/microvm-tools/invoke — force local I/O into microVM.
pub async fn post_microvm_tools_invoke(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<MicrovmToolInvokeRequest>,
) -> Json<serde_json::Value> {
    if let Err(e) = auth_agent_access(&headers, &req.agent_pid) {
        return e;
    }
    match crate::services::tools::dispatch_mcp_tool(
        &state,
        &req.bridge_id,
        &req.tool_name,
        &req.agent_pid,
        &req.input,
        "microvm-tools-invoke".into(),
        crate::services::tools::ToolMissionOpts {
            mission_id: None,
            idempotency_key: None,
        },
    )
    .await
    {
        Ok(v) => Json(v),
        Err(e) => Json(e),
    }
}

/// GET /api/v1/runtime/probabilistic-llm/status — LLM distrust / quarantine posture.
pub async fn get_probabilistic_llm_status(
    headers: HeaderMap,
) -> Json<serde_json::Value> {
    if crate::auth::extract_claims(&headers).is_none() {
        return Json(json!({"error": "Authentication required", "status": 401}));
    }
    Json(json!({
        "ok": true,
        "probabilistic_llm": crate::substrate::probabilistic_llm::status(),
    }))
}

/// GET /api/v1/runtime/zt-handshake/status
pub async fn get_zt_handshake_status(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> Json<serde_json::Value> {
    if crate::auth::extract_claims(&headers).is_none() {
        return Json(json!({"error": "Authentication required", "status": 401}));
    }
    Json(json!({
        "ok": true,
        "zt_handshake": crate::kernel::zt_handshake::status(state.as_ref(), None),
    }))
}

#[derive(Debug, Deserialize)]
pub struct ZtHandshakeProbeRequest {
    pub agent_pid: String,
    pub bypass_kind: String,
}

/// POST /api/v1/runtime/zt-handshake/probe
pub async fn post_zt_handshake_probe(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<ZtHandshakeProbeRequest>,
) -> Json<serde_json::Value> {
    if let Err(e) = auth_agent_access(&headers, &req.agent_pid) {
        return e;
    }
    match crate::kernel::zt_handshake::probe_bypass(state.as_ref(), &req.agent_pid, &req.bypass_kind)
    {
        Ok(v) => Json(v),
        Err(e) => Json(e),
    }
}

#[derive(Debug, Deserialize)]
pub struct ZtHandshakeRevokeRequest {
    pub agent_pid: String,
    pub bridge_id: String,
    pub tool_name: String,
}

/// POST /api/v1/runtime/zt-handshake/revoke
pub async fn post_zt_handshake_revoke(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<ZtHandshakeRevokeRequest>,
) -> Json<serde_json::Value> {
    if let Err(e) = auth_agent_access(&headers, &req.agent_pid) {
        return e;
    }
    match crate::kernel::zt_handshake::revoke(
        state.as_ref(),
        &req.agent_pid,
        &req.bridge_id,
        &req.tool_name,
    ) {
        Ok(v) => Json(v),
        Err(e) => Json(e),
    }
}

/// GET /api/v1/runtime/docklock/status — Ring-1 kernel honesty.
pub async fn get_docklock_status(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> Json<serde_json::Value> {
    if crate::auth::extract_claims(&headers).is_none() {
        return Json(json!({"error": "Authentication required", "status": 401}));
    }
    Json(json!({
        "ok": true,
        "docklock": crate::kernel::docklock::status_snapshot(state.as_ref()),
    }))
}

#[derive(Debug, Deserialize)]
pub struct DocklockProbeRequest {
    pub agent_pid: String,
    #[serde(default = "default_bypass_kind")]
    pub bypass_kind: String,
}

fn default_bypass_kind() -> String {
    "shell".into()
}

/// POST /api/v1/runtime/docklock/probe — adversarial bypass (must deny without quantum).
pub async fn post_docklock_probe(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<DocklockProbeRequest>,
) -> Json<serde_json::Value> {
    if let Err(e) = auth_agent_access(&headers, &req.agent_pid) {
        return e;
    }
    match crate::kernel::docklock::probe_bypass_denied(
        state.as_ref(),
        &req.agent_pid,
        &req.bypass_kind,
    ) {
        Ok(v) => Json(v),
        Err(e) => Json(e),
    }
}

/// GET /api/v1/runtime/fleet/charter — DI-4 fleet charter drift (intelligence digests, not PIDs).
pub async fn get_fleet_charter(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> Json<serde_json::Value> {
    if crate::auth::extract_claims(&headers).is_none() {
        return Json(json!({"error": "Authentication required", "status": 401}));
    }

    use std::collections::{BTreeMap, BTreeSet};

    let mut pids: BTreeSet<String> = BTreeSet::new();
    {
        let es = state.engine_store.lock().unwrap();
        for k in es
            .folder_keys(agent_principal::IIA_CONTRACT_FOLDER, None)
            .unwrap_or_default()
        {
            pids.insert(k);
        }
        for k in es
            .folder_keys(agent_principal::IIA_PRINCIPAL_FOLDER, None)
            .unwrap_or_default()
        {
            pids.insert(k);
        }
        for k in es
            .folder_keys(
                crate::kernel::agent_identity_envelope::ACTIVATION_FOLDER,
                None,
            )
            .unwrap_or_default()
        {
            pids.insert(k);
        }
    }
    {
        let k = state.kernel.lock().unwrap();
        for pid in k.agents().keys() {
            pids.insert(pid.clone());
        }
    }

    let mut digest_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut rows: Vec<serde_json::Value> = Vec::new();

    for api_pid in &pids {
        let principal = agent_principal::load_principal(state.as_ref(), api_pid);
        let contract = agent_principal::load_contract(state.as_ref(), api_pid);
        let setup = crate::kernel::agent_identity_envelope::load_setup(state.as_ref(), api_pid);
        let activation =
            crate::kernel::agent_identity_envelope::load_activation(state.as_ref(), api_pid);
        let continuity = agent_principal::load_continuity(state.as_ref(), api_pid);
        let matrix = crate::kernel::matrix_isolation::status_for_agent(state.as_ref(), api_pid);
        let mark = crate::kernel::matrix_host_egress::intelligence_egress_mark_hex(api_pid);

        let contract_digest = contract
            .as_ref()
            .map(|c| c.contract_digest_sha256.clone())
            .unwrap_or_default();
        if !contract_digest.is_empty() {
            *digest_counts.entry(contract_digest.clone()).or_insert(0) += 1;
        }

        let purpose: Vec<String> = contract
            .as_ref()
            .map(|c| c.purpose.iter().take(4).cloned().collect())
            .unwrap_or_default();
        let caps: Vec<String> = contract
            .as_ref()
            .map(|c| c.capabilities.iter().take(8).cloned().collect())
            .unwrap_or_default();

        rows.push(json!({
            "agent_pid": api_pid,
            "principal_id": principal.as_ref().map(|p| &p.principal_id),
            "intelligence_id": principal.as_ref().map(|p| &p.intelligence_id),
            "contract_present": contract.is_some(),
            "contract_digest_sha256": if contract_digest.is_empty() { Value::Null } else { json!(contract_digest) },
            "contract_version": contract.as_ref().map(|c| c.contract_version),
            "purpose": purpose,
            "capabilities": caps,
            "network_default": contract.as_ref().map(|c| &c.network_default),
            "hitl_policy": setup.as_ref().map(|s| format!("{:?}", s.hitl_policy).to_ascii_lowercase()),
            "forensic_profile": setup.as_ref().map(|s| format!("{:?}", s.forensic_profile).to_ascii_lowercase()),
            "activation_state": activation.as_ref().map(|a| format!("{:?}", a.state).to_ascii_lowercase()),
            "setup_spec_digest_sha256": activation.as_ref().map(|a| &a.setup_spec_digest_sha256),
            "activated": activation
                .as_ref()
                .map(|a| a.state == connector_trust::ActivationStateV2::Active)
                .unwrap_or(false),
            "continuity_state": continuity.as_ref().map(|c| format!("{:?}", c.state)),
            "continuity_broken": continuity
                .as_ref()
                .map(|c| c.state == connector_trust::ContinuityStateV2::Broken)
                .unwrap_or(false),
            "intelligence_mark": mark,
            "egress_isolated": matrix
                .get("egress_isolated")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
        }));
    }

    let mode_digest = digest_counts
        .iter()
        .max_by_key(|(_, n)| *n)
        .map(|(d, _)| d.clone());
    let mode_count = mode_digest
        .as_ref()
        .and_then(|d| digest_counts.get(d).copied())
        .unwrap_or(0);

    let mut drifted = 0usize;
    let mut missing_contract = 0usize;
    let mut broken = 0usize;
    let mut active = 0usize;
    for row in &mut rows {
        let digest = row
            .get("contract_digest_sha256")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let has_contract = row
            .get("contract_present")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if !has_contract {
            missing_contract += 1;
        }
        if row
            .get("continuity_broken")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            broken += 1;
        }
        if row
            .get("activated")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            active += 1;
        }
        let charter_drift = match (&mode_digest, digest.is_empty()) {
            (Some(mode), false) => digest != mode.as_str() && mode_count > 1,
            _ => false,
        };
        if charter_drift {
            drifted += 1;
        }
        if let Some(obj) = row.as_object_mut() {
            obj.insert("charter_drift".into(), json!(charter_drift));
            obj.insert(
                "drift_reason".into(),
                if !has_contract {
                    json!("missing_contract")
                } else if charter_drift {
                    json!("digest_diverges_from_fleet_mode")
                } else {
                    Value::Null
                },
            );
        }
    }

    Json(json!({
        "ok": true,
        "schema": "connector.fleet.charter.v1",
        "agent_count": rows.len(),
        "active_count": active,
        "missing_contract_count": missing_contract,
        "charter_drift_count": drifted,
        "continuity_broken_count": broken,
        "mode_contract_digest_sha256": mode_digest,
        "mode_digest_agent_count": mode_count,
        "distinct_contract_digests": digest_counts.len(),
        "agents": rows,
        "hint": "Charter digests that diverge from the fleet mode are flagged (intelligence plane, not OS PID).",
    }))
}

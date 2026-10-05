//! CNKTROS native invocation kernel.
//!
//! Routes `InvocationEnvelope` through ActionBinding / EffectIntent / PATE when
//! semantic confidence and agent binding allow it. Lower-confidence mutation
//! paths are denied without calling PATE (monotonic uncertainty / honesty).

use connector_engine::engine_store::EngineStore;
use connector_native_contract::{
    digest_hex_str, new_uid, BudgetSpec, CanonicalAction, EdgeReceipt, EffectDescriptor,
    EnforcementPosture, InvocationEnvelope, InvocationMode, InvocationOrigin, ObservedIdentity,
    PackagePin, SemanticConfidence, SemanticProvenance, SurfaceRef, TargetState,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::state::SharedState;
use crate::kernel::mission_journal::{self, BeginOutcome, StepKind};
use crate::substrate::authority_repo;
use crate::substrate::channel_surface::{
    self, commit_edge_receipt_store, INVOCATION_FOLDER, SURFACE_FOLDER,
};
use crate::substrate::flow_lease::{self, ConstrainedLeaseRequest};
use crate::substrate::native_compat;
use crate::substrate::pate::{self, AugmentedTaskUnit, TaskVerdict};

fn default_true() -> bool {
    true
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// Extended native invocation request (superset of `BuildInvocationRequest`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeInvokeRequest {
    pub origin: InvocationOrigin,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub surface_uid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel_uid: Option<String>,
    pub effect: EffectDescriptor,
    pub contract_ref: String,
    #[serde(default)]
    pub authority_ref: String,
    #[serde(default)]
    pub lifecycle_mode: InvocationMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enforcement_posture: Option<EnforcementPosture>,
    // ── Native kernel extensions ──
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_pid: Option<String>,
    /// Defaults to `"native"` when absent/empty at call time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bridge_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parameters: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    /// Mint a flow lease on allow / allow_narrow (default true).
    #[serde(default = "default_true")]
    pub mint_flow_lease: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_protocol: Option<String>,
    /// Tenant partition for authority revision binding (default `"default"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// Optional durable operation (mission) to accept-before-effect.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mission_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    /// Signed AppPackageV2 pin — required for mutating effects outside lab.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package: Option<PackagePin>,
    /// Optional authoring budget ceilings (narrows trajectory / latency / hop caps).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget: Option<BudgetSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeInvokeResult {
    pub envelope: InvocationEnvelope,
    pub receipt: EdgeReceipt,
    pub pate_verdict: String,
    pub action_digest: Option<String>,
    pub flow_id: Option<String>,
    pub meta: Value,
}

/// Intermediate admission outcome before persistence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionOutcome {
    pub pate_verdict: &'static str,
    pub execution_state: &'static str,
    pub honesty: &'static str,
    pub action_digest: Option<String>,
    pub atu_task_id: Option<String>,
    pub call_pate: bool,
}

/// True when confidence is high enough for semantic PATE/ActionBinding admission.
pub fn confidence_allows_pate(confidence: SemanticConfidence) -> bool {
    confidence.rank() >= SemanticConfidence::AdapterVerified.rank()
}

/// Hard pre-filter: deny mutations below AdapterVerified without calling PATE.
///
/// - TransportOnly + mutates → deny
/// - ProtocolObserved + mutates → deny (monotonic uncertainty; tool_name does not upgrade)
pub fn hard_prefilter(confidence: SemanticConfidence, mutates: bool) -> Option<AdmissionOutcome> {
    if mutates && !confidence_allows_pate(confidence) {
        let honesty = if matches!(confidence, SemanticConfidence::TransportOnly) {
            "deny-by-default: transport_only/unknown surfaces cannot mutate until resolved"
        } else {
            "deny-by-default: mutations require AdapterVerified+ semantics; ProtocolObserved is insufficient (monotonic uncertainty)"
        };
        return Some(AdmissionOutcome {
            pate_verdict: "deny",
            execution_state: "denied",
            honesty,
            action_digest: None,
            atu_task_id: None,
            call_pate: false,
        });
    }
    None
}

fn map_atu_to_outcome(atu: &AugmentedTaskUnit) -> AdmissionOutcome {
    let (pate_verdict, execution_state, honesty) = match atu.verdict {
        TaskVerdict::Proceed => (
            "allow",
            "admitted",
            "PATE Proceed — ActionBinding admitted tool",
        ),
        TaskVerdict::AskHitl => (
            "ask",
            "awaiting_hitl",
            "PATE AskHitl — HITL required before effect",
        ),
        TaskVerdict::DeferRedo => (
            "ask",
            "defer_redo",
            "PATE DeferRedo — replan / retry after epoch refresh",
        ),
        TaskVerdict::Quarantine => (
            "deny",
            "quarantined",
            "PATE Quarantine — effect blocked",
        ),
        TaskVerdict::Block => ("deny", "denied", "PATE Block — policy deny"),
    };
    AdmissionOutcome {
        pate_verdict,
        execution_state,
        honesty,
        action_digest: Some(atu.action_digest.clone()),
        atu_task_id: Some(atu.task_id.clone()),
        call_pate: true,
    }
}

fn resolve_agent_pid(state: &SharedState, req: &NativeInvokeRequest) -> Option<String> {
    if let Some(pid) = req
        .agent_pid
        .as_ref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        return Some(pid.to_string());
    }
    if let Some(m) =
        native_compat::resolve_by_intelligence_uid(state.as_ref(), &req.origin.intelligence_uid)
    {
        if !m.agent_pid.trim().is_empty() {
            return Some(m.agent_pid);
        }
    }
    if !req.origin.workload_uid.trim().is_empty() {
        if let Some(m) =
            native_compat::resolve_by_workload_uid(state.as_ref(), &req.origin.workload_uid)
        {
            if !m.agent_pid.trim().is_empty() {
                return Some(m.agent_pid);
            }
        }
    }
    None
}

fn build_canonical_action(req: &NativeInvokeRequest) -> Option<CanonicalAction> {
    let tool = req
        .tool_name
        .as_ref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())?;
    let params_digest = req.parameters.as_ref().map(|p| digest_hex_str(&p.to_string()));
    Some(CanonicalAction {
        verb: tool.to_string(),
        resource: req.resource.clone(),
        params_digest,
    })
}

fn decide_without_pate(
    confidence: SemanticConfidence,
    mutates: bool,
    has_agent: bool,
    has_tool: bool,
) -> AdmissionOutcome {
    let _ = (has_agent, has_tool);
    if matches!(confidence, SemanticConfidence::TransportOnly) && !mutates {
        return AdmissionOutcome {
            pate_verdict: "allow_narrow",
            execution_state: "admitted_narrow",
            honesty: "transport_only read/observe allowed narrowly; not full PATE admission",
            action_digest: None,
            atu_task_id: None,
            call_pate: false,
        };
    }

    if matches!(confidence, SemanticConfidence::NativeVerified) && !mutates && !has_tool {
        return AdmissionOutcome {
            pate_verdict: "recorded_no_effect",
            execution_state: "recorded",
            honesty:
                "NativeVerified recording without tool — no effect admission; envelope+receipt only",
            action_digest: None,
            atu_task_id: None,
            call_pate: false,
        };
    }

    let (pate_verdict, execution_state) = if mutates {
        ("pate_unavailable", "denied")
    } else {
        ("pate_unavailable", "ask")
    };
    AdmissionOutcome {
        pate_verdict,
        execution_state,
        honesty: "native kernel requires agent binding + tool for semantic PATE admission",
        action_digest: None,
        atu_task_id: None,
        call_pate: false,
    }
}

fn load_surface(
    es: &dyn EngineStore,
    surface_uid: Option<&str>,
) -> Result<(Option<SurfaceRef>, SemanticConfidence, SemanticProvenance), String> {
    if let Some(sid) = surface_uid.filter(|s| !s.trim().is_empty()) {
        let s: SurfaceRef = channel_surface::get_json(es, SURFACE_FOLDER, sid)
            .ok_or_else(|| "surface_not_found".to_string())?;
        let conf = s.confidence;
        let prov = s.provenance.clone();
        Ok((Some(s), conf, prov))
    } else {
        Ok((
            None,
            SemanticConfidence::TransportOnly,
            SemanticProvenance::KernelObservation,
        ))
    }
}

fn should_mint_lease(verdict: &str) -> bool {
    matches!(verdict, "allow" | "allow_narrow")
}

fn mint_lease_if_requested(
    state: &SharedState,
    req: &NativeInvokeRequest,
    outcome: &AdmissionOutcome,
    invocation_id: &str,
    enforcement_posture: EnforcementPosture,
    authority_revision: u64,
) -> Option<String> {
    if !req.mint_flow_lease || !should_mint_lease(outcome.pate_verdict) {
        return None;
    }
    let principal = if !req.origin.principal.trim().is_empty() {
        req.origin.principal.as_str()
    } else {
        req.origin.intelligence_uid.as_str()
    };
    let operation = req
        .tool_name
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or("native.invoke");

    let has_dest = req.destination_host.is_some()
        || req.destination_port.is_some()
        || req.destination_protocol.is_some();
    let has_identity = !req.origin.workload_uid.is_empty()
        || !req.origin.intelligence_uid.is_empty()
        || req.channel_uid.is_some();

    if has_dest || has_identity {
        let constrained = ConstrainedLeaseRequest {
            principal_id: principal.to_string(),
            tenant_id: req.tenant_id.clone(),
            operation: operation.to_string(),
            admission_ticket_id: invocation_id.to_string(),
            workload_uid: Some(req.origin.workload_uid.clone()).filter(|s| !s.is_empty()),
            intelligence_uid: Some(req.origin.intelligence_uid.clone()).filter(|s| !s.is_empty()),
            channel_uid: req.channel_uid.clone(),
            destination_host: req.destination_host.clone(),
            destination_ip_cidr: None,
            destination_port: req.destination_port,
            destination_protocol: req.destination_protocol.clone(),
            action_digest: outcome.action_digest.clone(),
            authority_revision: Some(authority_revision),
            enforcement_posture: Some(
                serde_json::to_value(enforcement_posture)
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_string))
                    .unwrap_or_else(|| "advisory".into()),
            ),
        };
        if let Some(fid) = flow_lease::mint_constrained_lease(state.as_ref(), constrained) {
            return Some(fid);
        }
    }

    flow_lease::mint_on_admission_pass(
        state.as_ref(),
        principal,
        req.tenant_id.as_deref(),
        operation,
        invocation_id,
    )
}

fn admit_decision(
    state: &SharedState,
    req: &NativeInvokeRequest,
    confidence: SemanticConfidence,
    mutates: bool,
    agent_pid: Option<&str>,
    tool_name: Option<&str>,
    bridge_id: &str,
) -> (AdmissionOutcome, Option<String>, Option<AugmentedTaskUnit>) {
    if let Some(denied) = hard_prefilter(confidence, mutates) {
        return (denied, None, None);
    }

    if let (Some(pid), Some(tool)) = (agent_pid, tool_name) {
        if confidence_allows_pate(confidence) {
            let params = req.parameters.clone().unwrap_or(Value::Null);
            return match pate::admit_tool(state, pid, bridge_id, tool, &params, None) {
                Ok(atu) => (map_atu_to_outcome(&atu), None, Some(atu)),
                Err(e) => (
                    AdmissionOutcome {
                        pate_verdict: "deny",
                        execution_state: "denied",
                        honesty: "PATE/ActionBinding denied tool admission",
                        action_digest: None,
                        atu_task_id: None,
                        call_pate: true,
                    },
                    Some(e.human_readable),
                    None,
                ),
            };
        }
    }

    (
        decide_without_pate(
            confidence,
            mutates,
            agent_pid.is_some(),
            tool_name.is_some(),
        ),
        None,
        None,
    )
}

/// Admit / record a native invocation through the CNKTROS kernel path.
pub fn invoke(state: &SharedState, req: NativeInvokeRequest) -> Result<NativeInvokeResult, String> {
    let t0 = std::time::Instant::now();
    let mut phases_ms = serde_json::Map::new();
    let mut store_writes: u32 = 0;

    // Mandatory .cpkg gate for mutating effects (lab/dev may unpackaged with honesty).
    if req.effect.mutates {
        crate::substrate::package_gate::require_package_for_consequential_effect(req.package.as_ref())?;
    }

    let (surface, confidence, provenance) = {
        let es = state
            .engine_store
            .lock()
            .map_err(|_| "engine_store_lock".to_string())?;
        load_surface(es.as_ref(), req.surface_uid.as_deref())?
    };
    phases_ms.insert("load_surface".into(), json!(t0.elapsed().as_millis() as u64));

    let action = build_canonical_action(&req);
    let mutates = req.effect.mutates;
    let agent_pid = resolve_agent_pid(state, &req);
    let tool_name = req
        .tool_name
        .as_ref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    let bridge_id = req
        .bridge_id
        .as_ref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .unwrap_or("native")
        .to_string();

    // Trajectory budget: fail closed when exhausted before consequential admit.
    if mutates {
        let mission = req
            .mission_id
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or("native_default");
        let pid = agent_pid
            .as_deref()
            .unwrap_or(req.origin.intelligence_uid.as_str());
        let mut tb = crate::substrate::trajectory_budget::load_or_create(state.as_ref(), mission, pid);
        if let Some(ref b) = req.budget {
            tb.apply_budget_spec(b);
        }
        if tb.exhausted {
            return Err(format!(
                "trajectory_budget_exhausted: effects={}/{} commitments={}/{}",
                tb.effect_count, tb.max_effects, tb.commitments, tb.max_commitments
            ));
        }
        // Persist narrowed ceilings so subsequent invokes share them.
        if req.budget.is_some() {
            crate::substrate::trajectory_budget::save(state.as_ref(), &tb);
        }
    }

    // Per-request duration ceiling from BudgetSpec (before heavy admit).
    if let Some(max_ms) = req.budget.as_ref().and_then(|b| b.max_duration_ms) {
        // Stored for end-of-invoke check alongside CONNECTOR_NATIVE_MAX_LATENCY_MS.
        phases_ms.insert("budget_max_duration_ms".into(), json!(max_ms));
    }

    // Durable accept-before-effect when mission_id + idempotency_key are bound.
    let mut journal_step_id: Option<String> = None;
    if let (Some(mid), Some(ikey)) = (
        req.mission_id.as_deref().filter(|s| !s.trim().is_empty()),
        req.idempotency_key
            .as_deref()
            .filter(|s| !s.trim().is_empty()),
    ) {
        let pid = agent_pid
            .clone()
            .unwrap_or_else(|| req.origin.intelligence_uid.clone());
        let input = json!({
            "tool_name": tool_name,
            "resource": req.resource,
            "effect": req.effect,
            "contract_ref": req.contract_ref,
        });
        match mission_journal::begin_step_detailed(
            state.as_ref(),
            mid,
            &pid,
            StepKind::Tool,
            ikey,
            &input,
            Some(json!({"channel": "native_invoker"})),
        ) {
            Ok((step, BeginOutcome::ExistingCompleted)) => {
                return Ok(NativeInvokeResult {
                    envelope: InvocationEnvelope {
                        invocation_id: step.step_id.clone(),
                        origin: req.origin.clone(),
                        target: TargetState::Unresolved {
                            observed_peer: ObservedIdentity {
                                kind: "replay".into(),
                                value: "existing_completed".into(),
                            },
                        },
                        semantic_provenance: provenance.clone(),
                        semantic_confidence: confidence,
                        action: action.clone(),
                        effect: req.effect.clone(),
                        contract_ref: req.contract_ref.clone(),
                        contract_revision: 1,
                        authority_ref: "authority:replay".into(),
                        authority_revision: 0,
                        channel_ref: req.channel_uid.clone(),
                        surface_ref: req.surface_uid.clone(),
                        lifecycle_mode: req.lifecycle_mode,
                        deadline_ms: None,
                    },
                    receipt: EdgeReceipt {
                        operation_id: step.step_id.clone(),
                        intelligence_uid: req.origin.intelligence_uid.clone(),
                        workload_uid: req.origin.workload_uid.clone(),
                        software_uid: req.origin.software_uid.clone(),
                        channel_uid: req.channel_uid.clone(),
                        surface_uid: req.surface_uid.clone(),
                        semantic_confidence: confidence,
                        semantic_provenance: provenance.clone(),
                        enforcement_posture: req
                            .enforcement_posture
                            .unwrap_or(EnforcementPosture::Advisory),
                        target_ref: None,
                        observed_locators: vec![],
                        action_digest: None,
                        effect_digest: None,
                        projection_digest: None,
                        projection_loss_digest: None,
                        contract_ref: req.contract_ref.clone(),
                        contract_revision: 1,
                        grant_ref: String::new(),
                        authority_revision: 0,
                        pate_verdict: "allow".into(),
                        execution_state: "replayed".into(),
                        evidence_refs: vec![format!("mission_step:{}", step.step_id)],
                        issued_at_ms: now_ms(),
                    },
                    pate_verdict: "allow".into(),
                    action_digest: None,
                    flow_id: None,
                    meta: json!({
                        "honesty": "idempotent replay — completed step not re-fired",
                        "begin_outcome": "existing_completed",
                        "mission_id": mid,
                    }),
                });
            }
            Ok((step, BeginOutcome::ExistingInFlight)) => {
                journal_step_id = Some(step.step_id);
            }
            Ok((step, BeginOutcome::New)) => {
                journal_step_id = Some(step.step_id);
            }
            Err(e) => return Err(e),
        }
    }

    let t_admit = std::time::Instant::now();
    let (outcome, deny_detail, admitted) = admit_decision(
        state,
        &req,
        confidence,
        mutates,
        agent_pid.as_deref(),
        tool_name.as_deref(),
        &bridge_id,
    );
    phases_ms.insert("admit".into(), json!(t_admit.elapsed().as_millis() as u64));

    let enforcement_posture = req
        .enforcement_posture
        .unwrap_or(EnforcementPosture::Advisory);

    let target = if let Some(ref s) = surface {
        TargetState::Surface {
            surface_uid: s.surface_uid.clone(),
        }
    } else {
        TargetState::Unresolved {
            observed_peer: ObservedIdentity {
                kind: "unknown".into(),
                value: "unspecified".into(),
            },
        }
    };

    let invocation_id = new_uid("inv_");
    let auth_bind = authority_repo::bind_for_invocation(
        state.as_ref(),
        req.tenant_id.as_deref(),
        agent_pid.as_deref(),
        req.resource.as_deref(),
    );
    let authority_ref = if req.authority_ref.is_empty() {
        if auth_bind.root_id.is_empty() {
            "authority:native_kernel".into()
        } else {
            format!("authority:{}", auth_bind.root_id)
        }
    } else {
        req.authority_ref.clone()
    };
    let grant_ref_id = if auth_bind.grant_ref.is_empty() {
        authority_ref.clone()
    } else {
        auth_bind.grant_ref.clone()
    };

    let envelope = InvocationEnvelope {
        invocation_id: invocation_id.clone(),
        origin: req.origin.clone(),
        target,
        semantic_provenance: provenance.clone(),
        semantic_confidence: confidence,
        action,
        effect: req.effect.clone(),
        contract_ref: req.contract_ref.clone(),
        contract_revision: 1,
        authority_ref: authority_ref.clone(),
        authority_revision: auth_bind.authority_revision,
        channel_ref: req.channel_uid.clone(),
        surface_ref: req.surface_uid.clone(),
        lifecycle_mode: req.lifecycle_mode,
        deadline_ms: None,
    };

    let flow_id = mint_lease_if_requested(
        state,
        &req,
        &outcome,
        &invocation_id,
        enforcement_posture,
        auth_bind.authority_revision,
    );

    let mut evidence_refs = vec![format!("invocation:{invocation_id}")];
    if let Some(ref tid) = outcome.atu_task_id {
        evidence_refs.push(format!("pate:{tid}"));
    }
    if let Some(ref fid) = flow_id {
        evidence_refs.push(format!("flow_lease:{fid}"));
    }
    if !auth_bind.grant_ref.is_empty() {
        evidence_refs.push(format!("grant:{}", auth_bind.grant_ref));
    }
    evidence_refs.push(format!(
        "authority_revision:{}",
        auth_bind.authority_revision
    ));

    let receipt = EdgeReceipt {
        operation_id: journal_step_id
            .clone()
            .unwrap_or_else(|| invocation_id.clone()),
        intelligence_uid: req.origin.intelligence_uid.clone(),
        workload_uid: req.origin.workload_uid.clone(),
        software_uid: req.origin.software_uid.clone(),
        channel_uid: req.channel_uid.clone(),
        surface_uid: req.surface_uid.clone(),
        semantic_confidence: confidence,
        semantic_provenance: provenance,
        enforcement_posture,
        target_ref: None,
        observed_locators: surface
            .as_ref()
            .map(|s| {
                s.locators
                    .iter()
                    .filter_map(|l| l.digest.clone())
                    .collect()
            })
            .unwrap_or_default(),
        action_digest: outcome.action_digest.clone(),
        effect_digest: Some(digest_hex_str(&format!(
            "{}|{}",
            req.effect.effect_class, req.effect.mutates
        ))),
        projection_digest: None,
        projection_loss_digest: None,
        contract_ref: req.contract_ref.clone(),
        contract_revision: 1,
        grant_ref: grant_ref_id,
        authority_revision: auth_bind.authority_revision,
        pate_verdict: outcome.pate_verdict.into(),
        execution_state: outcome.execution_state.into(),
        evidence_refs,
        issued_at_ms: now_ms(),
    };

    if let (Some(mid), Some(sid)) = (
        req.mission_id.as_deref(),
        journal_step_id.as_deref(),
    ) {
        if matches!(
            outcome.pate_verdict,
            "allow" | "allow_narrow" | "recorded_no_effect"
        ) {
            let _ = mission_journal::complete_step(
                state.as_ref(),
                mid,
                sid,
                serde_json::to_value(&receipt).unwrap_or(json!({})),
            );
        } else if matches!(outcome.pate_verdict, "ask") {
            let _ = mission_journal::mark_waiting_hitl(
                state.as_ref(),
                mid,
                sid,
                &format!("native:{invocation_id}"),
            );
        } else if matches!(outcome.pate_verdict, "deny" | "pate_unavailable") {
            let _ = mission_journal::fail_step(
                state.as_ref(),
                mid,
                sid,
                deny_detail
                    .clone()
                    .unwrap_or_else(|| outcome.pate_verdict.to_string()),
            );
        }
    }

    {
        let t_persist = std::time::Instant::now();
        let mut es = state
            .engine_store
            .lock()
            .map_err(|_| "engine_store_lock".to_string())?;
        channel_surface::put_json(es.as_mut(), INVOCATION_FOLDER, &invocation_id, &envelope)?;
        store_writes = store_writes.saturating_add(1);
        commit_edge_receipt_store(es.as_mut(), &receipt)?;
        store_writes = store_writes.saturating_add(2); // receipt + evidence_graph dual-write
        phases_ms.insert("persist".into(), json!(t_persist.elapsed().as_millis() as u64));
    }

    if let Some(atu) = admitted.as_ref() {
        if pate::host_admission_allows_execution(atu.verdict) {
            let _ = pate::run_admitted_effect(state, atu, |_| {
                Ok(json!({
                    "observed": false,
                    "execution": "recorded_no_external_effect",
                }))
            });
        }
    }

    let max_writes = std::env::var("CONNECTOR_NATIVE_MAX_STORE_WRITES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(16u32);
    if store_writes > max_writes {
        return Err(format!(
            "write_amplification_exceeded:{store_writes}>{max_writes}"
        ));
    }

    let total_ms = t0.elapsed().as_millis() as u64;
    let mut max_latency_ms = std::env::var("CONNECTOR_NATIVE_MAX_LATENCY_MS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(30_000u64);
    if let Some(budget_ms) = req.budget.as_ref().and_then(|b| b.max_duration_ms) {
        max_latency_ms = max_latency_ms.min(budget_ms);
    }
    if total_ms > max_latency_ms {
        return Err(format!(
            "latency_budget_exceeded:{total_ms}>{max_latency_ms}"
        ));
    }

    // Record trajectory for successful mutating admits.
    if mutates
        && matches!(
            outcome.pate_verdict,
            "allow" | "allow_narrow" | "recorded_no_effect"
        )
    {
        let mission = req
            .mission_id
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or("native_default");
        let pid = agent_pid
            .as_deref()
            .unwrap_or(req.origin.intelligence_uid.as_str());
        let mut tb =
            crate::substrate::trajectory_budget::load_or_create(state.as_ref(), mission, pid);
        let blast = if mutates { 0.35 } else { 0.05 };
        tb.record_effect(blast, 0.0, 256, true);
        crate::substrate::trajectory_budget::save(state.as_ref(), &tb);
    }

    phases_ms.insert("total".into(), json!(total_ms));

    let mut meta = json!({
        "honesty": outcome.honesty,
        "pate_note": "native_invoker — ActionBinding/PATE when AdapterVerified+ with agent+tool",
        "agent_pid": agent_pid,
        "bridge_id": bridge_id,
        "call_pate": outcome.call_pate,
        "confidence_rank": confidence.rank(),
        "authority_revision": auth_bind.authority_revision,
        "authority_root": auth_bind.root_id,
        "grant_ref": auth_bind.grant_ref,
        "tenant_id": auth_bind.tenant_id,
        "mission_id": req.mission_id,
        "journal_step_id": journal_step_id,
        "phases_ms": phases_ms,
        "store_writes": store_writes,
        "max_store_writes": max_writes,
        "max_latency_ms": max_latency_ms,
        "budget_id": req.budget.as_ref().map(|b| b.budget_id.clone()),
    });
    if let Some(detail) = deny_detail {
        if let Some(o) = meta.as_object_mut() {
            o.insert("deny_detail".into(), json!(detail));
        }
    }

    Ok(NativeInvokeResult {
        envelope,
        receipt,
        pate_verdict: outcome.pate_verdict.to_string(),
        action_digest: outcome.action_digest,
        flow_id,
        meta,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_only_mutate_denies_without_pate() {
        let o = hard_prefilter(SemanticConfidence::TransportOnly, true).expect("deny");
        assert_eq!(o.pate_verdict, "deny");
        assert!(!o.call_pate);
        assert_eq!(o.execution_state, "denied");
    }

    #[test]
    fn protocol_observed_mutate_denies_without_pate() {
        let o = hard_prefilter(SemanticConfidence::ProtocolObserved, true).expect("deny");
        assert_eq!(o.pate_verdict, "deny");
        assert!(!o.call_pate);
    }

    #[test]
    fn adapter_verified_mutate_passes_prefilter() {
        assert!(hard_prefilter(SemanticConfidence::AdapterVerified, true).is_none());
        assert!(hard_prefilter(SemanticConfidence::NativeVerified, true).is_none());
    }

    #[test]
    fn adapter_verified_mutate_without_agent_is_pate_unavailable() {
        let o = decide_without_pate(SemanticConfidence::AdapterVerified, true, false, false);
        assert_eq!(o.pate_verdict, "pate_unavailable");
        assert_eq!(o.execution_state, "denied");
        assert!(!o.call_pate);
    }

    #[test]
    fn transport_only_non_mutate_allow_narrow() {
        let o = decide_without_pate(SemanticConfidence::TransportOnly, false, false, false);
        assert_eq!(o.pate_verdict, "allow_narrow");
        assert_eq!(o.execution_state, "admitted_narrow");
    }

    #[test]
    fn confidence_rank_gate() {
        assert!(!confidence_allows_pate(SemanticConfidence::TransportOnly));
        assert!(!confidence_allows_pate(SemanticConfidence::ProtocolObserved));
        assert!(confidence_allows_pate(SemanticConfidence::AdapterVerified));
        assert!(confidence_allows_pate(SemanticConfidence::NativeVerified));
        assert!(
            SemanticConfidence::AdapterVerified.rank()
                > SemanticConfidence::ProtocolObserved.rank()
        );
    }

    #[test]
    fn native_verified_no_tool_recorded_no_effect() {
        let o = decide_without_pate(SemanticConfidence::NativeVerified, false, true, false);
        assert_eq!(o.pate_verdict, "recorded_no_effect");
    }
}

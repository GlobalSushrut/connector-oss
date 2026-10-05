//! Admission Gate — Central pre-execution security enforcement for ALL agent actions.
//!
//! Every agent execution path (LLM, memory, tools, pipelines, MCP protocol) MUST call
//! `admission::check()` before performing any action. The gate is the single enforcement
//! point for quarantine, firewall, injection detection, budget, and audit.
//!
//! Design: See `platform/docs/arch/ADMISSION_GATE.md`
//!
//! Properties:
//! - **Deny-by-default**: If the gate returns `Err`, the action MUST NOT execute.
//! - **Quarantine on security violation**: Injection / guard deny → agent paused + HITL.
//! - **Audit on every decision**: Every PASS and DENY writes to engine_store audit log.
//! - **Idempotent**: Same request → same result.
//! - **< 200µs overhead**: Negligible vs LLM latency.
//!
//! ## Control planes (see `platform/docs/arch/CONNECTOR_KERNEL_CONTROLS.md`)
//!
//! 1. **Per-agent quarantine** — `agent_meta.quarantined` / `paused` blocks *all* ops (Step 1).
//! 2. **Per-operation / scoped deny** — enforced in plugins or AAPI policies (not this gate alone).
//! 3. **Host kernel attachment** — when `CONNECTOR_KERNEL_ENFORCE=1`, egress-capable ops require an
//!    **active** host profile (`kernel_host`, Step 1.5) until `connector-kerneld` is wired.

use crate::error::{ConnectorError, DenialReason};
use crate::license;
use crate::services::kernel_host;
use crate::state::SharedState;
use connector_engine::engine_store::EngineAuditEntry;
use connector_engine::guard_pipeline::GuardRequest;
use connector_engine::semantic_injection::SemanticInjectionDetector;
use vac_core::guard::GuardDecision;
use vac_core::namespace_types::SecurityLevel;

// ═══════════════════════════════════════════════════════════════════════════
// Admission Request — what callers provide to the gate
// ═══════════════════════════════════════════════════════════════════════════

/// The operation an agent is attempting.
#[derive(Debug, Clone)]
#[allow(dead_code)] // PipelineStep + McpCall wired in Phase 5
pub enum AdmissionOp {
    /// LLM chat completion (POST /v1/chat/completions)
    LlmChat,
    /// Memory write (POST /memory/write)
    MemoryWrite,
    /// Memory read / recall (GET /memory/recall/*) — governed under effect exclusivity.
    MemoryRead { namespace: String },
    /// Tool dispatch (POST /tools/mcp/invoke)
    ToolDispatch { tool_id: String },
    /// Multi-agent pipeline step
    PipelineStep { pipeline_id: String, step: usize },
    /// MCP protocol call_tool
    McpCall { tool_name: String },
    /// CONP machine command / e-stop (POST /protocol/conp/command|estop)
    ConpCommand {
        capability_id: String,
        entity_id: String,
    },
}

impl AdmissionOp {
    /// Machine-readable operation name for audit logs.
    pub fn slug(&self) -> &str {
        match self {
            AdmissionOp::LlmChat => "llm.chat",
            AdmissionOp::MemoryWrite => "memory.write",
            AdmissionOp::MemoryRead { .. } => "memory.read",
            AdmissionOp::ToolDispatch { .. } => "tool.dispatch",
            AdmissionOp::PipelineStep { .. } => "pipeline.step",
            AdmissionOp::McpCall { .. } => "mcp.call",
            AdmissionOp::ConpCommand { .. } => "conp.command",
        }
    }

    /// Resource identifier for the ConnectorError body.
    pub fn resource(&self) -> String {
        match self {
            AdmissionOp::LlmChat => "llm.chat".into(),
            AdmissionOp::MemoryWrite => "memory.write".into(),
            AdmissionOp::MemoryRead { namespace } => format!("memory.read:{namespace}"),
            AdmissionOp::ToolDispatch { tool_id } => format!("tool:{}", tool_id),
            AdmissionOp::PipelineStep { pipeline_id, step } => {
                format!("pipeline:{}:step:{}", pipeline_id, step)
            }
            AdmissionOp::McpCall { tool_name } => format!("mcp:{}", tool_name),
            AdmissionOp::ConpCommand {
                capability_id,
                entity_id,
            } => format!("conp:{capability_id}:{entity_id}"),
        }
    }
}

/// Network-adjacent operations that require a host kernel attachment when `CONNECTOR_KERNEL_ENFORCE=1`.
pub fn admission_op_requires_kernel_host_attestation(op: &AdmissionOp) -> bool {
    matches!(
        op,
        AdmissionOp::LlmChat
            | AdmissionOp::ToolDispatch { .. }
            | AdmissionOp::McpCall { .. }
            | AdmissionOp::PipelineStep { .. }
            | AdmissionOp::MemoryRead { .. }
            | AdmissionOp::ConpCommand { .. }
    )
}

fn env_flag_true(name: &str) -> bool {
    matches!(
        std::env::var(name)
            .ok()
            .as_deref()
            .map(|s| s.trim().to_ascii_lowercase())
            .as_deref(),
        Some("1") | Some("true") | Some("yes") | Some("on")
    )
}

/// B5: enforce HitlPolicyV2 from setup when `CONNECTOR_IIA_HITL_ENFORCE=1`.
pub fn hitl_policy_enforce_enabled() -> bool {
    env_flag_true("CONNECTOR_IIA_HITL_ENFORCE")
}

/// Returns deny message if setup HITL policy blocks this operation class.
fn hitl_policy_denial(
    state: &crate::state::PlatformState,
    req: &AdmissionRequest<'_>,
) -> Option<String> {
    use connector_trust::HitlPolicyV2;
    let setup = crate::kernel::agent_identity_envelope::load_setup(state, req.agent_pid)?;
    let blocks = match (&setup.hitl_policy, &req.operation) {
        (HitlPolicyV2::None, _) => false,
        (HitlPolicyV2::Tool, AdmissionOp::ToolDispatch { .. }) => true,
        (HitlPolicyV2::Tool, AdmissionOp::ConpCommand { .. }) => true,
        (HitlPolicyV2::Egress, AdmissionOp::McpCall { .. }) => true,
        (
            HitlPolicyV2::AllMaterial,
            AdmissionOp::ToolDispatch { .. }
            | AdmissionOp::McpCall { .. }
            | AdmissionOp::MemoryWrite
            | AdmissionOp::MemoryRead { .. }
            | AdmissionOp::PipelineStep { .. }
            | AdmissionOp::ConpCommand { .. },
        ) => true,
        (HitlPolicyV2::Export, _) => {
            // Export path is primarily forensics/WC — block tool egress as proxy.
            matches!(
                req.operation,
                AdmissionOp::McpCall { .. }
                    | AdmissionOp::ToolDispatch { .. }
                    | AdmissionOp::ConpCommand { .. }
            )
        }
        _ => false,
    };
    if !blocks {
        return None;
    }
    let _ = crate::services::agents::hitl_submit(
        req.agent_pid,
        req.operation.slug(),
        &format!(
            "HITL policy {:?} requires approval before {}",
            setup.hitl_policy,
            req.operation.resource()
        ),
    );
    Some(format!(
        "HITL policy '{:?}' requires human approval before {}",
        setup.hitl_policy,
        req.operation.slug()
    ))
}

/// What callers provide to the Admission Gate.
pub struct AdmissionRequest<'a> {
    /// The agent performing the action.
    pub agent_pid: &'a str,
    /// Namespace the action targets.
    pub namespace: &'a str,
    /// What the agent is trying to do.
    pub operation: AdmissionOp,
    /// Content to inspect (prompt text, memory content, tool params).
    /// If None, content-based checks (injection, guard L3) are skipped.
    pub content: Option<&'a str>,
    /// Execution quantum from `X-Connector-Execution-Quantum` (Ring-1 / QPR).
    pub execution_quantum_id: Option<&'a str>,
}

// ═══════════════════════════════════════════════════════════════════════════
// Admission Ticket — returned on PASS
// ═══════════════════════════════════════════════════════════════════════════

/// Proof that the Admission Gate approved this action. Callers may include
/// the `ticket_id` in response metadata for audit correlation.
#[derive(Debug, Clone)]
pub struct AdmissionTicket {
    /// Unique ticket ID (for audit correlation).
    pub ticket_id: String,
    /// Injection score observed (0.0 if no content).
    pub injection_score: f64,
    /// Audit CID for this decision (for proof surface).
    pub audit_cid: Option<String>,
    /// Host policy revision from `kernel_host` (Phase A stub / future `connector-kerneld`).
    pub kernel_policy_revision: Option<u64>,
    /// `active` / `pending` / `failed`, or `None` when kernel enforcement is off or not applicable.
    pub kernel_host_apply_state: Option<String>,
}

impl AdmissionTicket {
    /// Lift into the shared v2 trust contract (additive; no behavior change).
    pub fn to_v2(&self) -> connector_trust::AdmissionTicketV2 {
        connector_trust::AdmissionTicketV2::from_legacy_fields(
            self.ticket_id.clone(),
            self.injection_score,
            self.audit_cid.clone(),
            self.kernel_policy_revision,
            self.kernel_host_apply_state.clone(),
        )
    }
}

/// Run admission and return the shared v2 ticket shape.
pub fn check_v2(
    state: &SharedState,
    req: &AdmissionRequest,
) -> Result<connector_trust::AdmissionTicketV2, ConnectorError> {
    check(state, req).map(|t| t.to_v2())
}

// ═══════════════════════════════════════════════════════════════════════════
// Core gate — the ONLY function that decides pass/deny
// ═══════════════════════════════════════════════════════════════════════════

/// Run the Admission Gate. Returns `Ok(AdmissionTicket)` on pass, `Err(ConnectorError)` on deny.
///
/// **Every agent execution path MUST call this before performing any action.**
///
/// Steps (short-circuit on first deny):
///   1. Quarantine check — is the agent paused/quarantined?
///   1.25 License — if `CONNECTOR_LICENSE_ENFORCE=1`, deny all ops when `valid_until` has passed
///   1.5 Host kernel — if `CONNECTOR_KERNEL_ENFORCE=1`, egress-capable ops require active attachment
///   1.6 Graph Firewall — relation-graph dynamic rules + agentic control breaker
///   2. Guard Pipeline (5 layers) — MAC, Policy, Content, CircuitBreaker, Audit
///   3. Injection score — heuristic check on content
///   4. Audit write — record the decision (pass or deny)
///   5. On security deny: quarantine agent + HITL submit
pub fn check(
    state: &SharedState,
    req: &AdmissionRequest,
) -> Result<AdmissionTicket, ConnectorError> {
    let now_ms = chrono::Utc::now().timestamp_millis();
    let ticket_id = format!("adm_{}", uuid::Uuid::new_v4().simple());

    // ── Step 1: Quarantine check ─────────────────────────────────────────
    // If the agent is quarantined, block EVERYTHING. No exceptions.
    {
        let es = state.engine_store.lock().unwrap();
        if let Some(meta) = es.folder_get("agent_meta", req.agent_pid).ok().flatten() {
            // Check quarantined flag (set by admission gate on security violation)
            let quarantined = meta
                .get("quarantined")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if quarantined {
                let reason = meta
                    .get("quarantine_reason")
                    .and_then(|v| v.as_str())
                    .unwrap_or("security violation");
                let hitl_id = meta.get("quarantine_hitl_id").and_then(|v| v.as_str());

                // Audit: record the blocked attempt during quarantine
                drop(es);
                let audit_cid =
                    audit_decision(state, req, &ticket_id, "blocked_quarantined", now_ms, None);

                return Err(
                    ConnectorError::agent_quarantined(req.agent_pid, reason, hitl_id)
                        .with_denied_resource(req.operation.resource())
                        .with_audit_cid(audit_cid),
                );
            }

            // CDMI matrix egress isolation — continuity break / tamper response.
            let egress_isolated = meta
                .get("egress_isolated")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if egress_isolated {
                let reason = meta
                    .get("matrix_isolation_reason")
                    .and_then(|v| v.as_str())
                    .unwrap_or("matrix egress isolation");
                drop(es);
                let audit_cid = audit_decision(
                    state,
                    req,
                    &ticket_id,
                    "blocked_matrix_egress",
                    now_ms,
                    None,
                );
                return Err(ConnectorError::new(
                    DenialReason::PolicyDenied,
                    &format!("Matrix egress isolation active: {reason}"),
                )
                .with_denied_resource(req.operation.resource())
                .with_agent_scope(req.agent_pid)
                .with_audit_cid(audit_cid));
            }

            // Also check legacy `paused` flag
            let paused = meta
                .get("paused")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if paused {
                drop(es);
                let audit_cid =
                    audit_decision(state, req, &ticket_id, "blocked_paused", now_ms, None);

                return Err(ConnectorError::agent_quarantined(
                    req.agent_pid,
                    "Agent is paused by operator",
                    None,
                )
                .with_denied_resource(req.operation.resource())
                .with_agent_scope(req.namespace)
                .with_audit_cid(audit_cid));
            }
        }
    }

    // ── Step 1.2 Agent namespace isolation (P10.10) ───────────────────────
    let write_ns = matches!(req.operation, AdmissionOp::MemoryWrite);
    if !crate::kernel::agent_identity_envelope::agent_may_access_namespace(
        state.as_ref(),
        req.agent_pid,
        req.namespace,
        write_ns,
    ) {
        use sha2::{Digest, Sha256};
        let leaf = hex::encode(Sha256::digest(
            format!("ns_deny|{}|{}", req.agent_pid, req.namespace).as_bytes(),
        ));
        let _ = crate::kernel::forensic_rollups::record_event(
            state.as_ref(),
            crate::kernel::forensic_rollups::RollupEvent {
                agent_pid: req.agent_pid,
                event_kind: "admission.namespace_isolation",
                leaf_digest: leaf,
                universal_envelope_id: None,
                namespace: Some(req.namespace),
                cross_agent_denied: true,
                admission_deny: true,
                continuity_break: false,
                quarantine: false,
                egress_isolated: false,
                cpo_id: None,
                quantum_id: None,
                docklock_profile_id: None,
                intelligence_receipt_id: None,
                witnessctl_session_id: None,
                tracetramp_trace_id: None,
                fni_flow_id: None,
                moment_id: None,
            },
        );
        let audit_cid = audit_decision(
            state,
            req,
            &ticket_id,
            "blocked_namespace_isolation",
            now_ms,
            Some("cross-agent namespace denied without grant"),
        );
        return Err(
            ConnectorError::new(
                DenialReason::PolicyDenied,
                format!(
                    "Namespace '{}' is not in agent '{}' scope — no cross-agent /m/ access without common-space grant",
                    req.namespace, req.agent_pid
                ),
            )
            .with_denied_resource(req.operation.resource())
            .with_agent_scope(req.namespace)
            .with_audit_cid(audit_cid),
        );
    }

    // ── Step 1.22 HITL policy (B5) — CONNECTOR_IIA_HITL_ENFORCE=1 ─────────
    if hitl_policy_enforce_enabled() {
        if let Some(deny) = hitl_policy_denial(state.as_ref(), req) {
            let audit_cid = audit_decision(
                state,
                req,
                &ticket_id,
                "blocked_hitl_policy",
                now_ms,
                Some(&deny),
            );
            return Err(
                ConnectorError::new(DenialReason::PolicyDenied, deny)
                    .with_denied_resource(req.operation.resource())
                    .with_agent_scope(req.agent_pid)
                    .with_hint("Approve via POST /agents/:pid/hitl/:id/approve or set X-Connector-Hitl-Approved: 1 after human review")
                    .with_audit_cid(audit_cid),
            );
        }
    }

    // ── Step 1.25 License time validity (CONNECTOR_LICENSE_ENFORCE=1) ─────────────────
    if license::license_enforce_enabled()
        && !state.license.is_time_valid(chrono::Utc::now().timestamp())
    {
        let audit_cid = audit_decision(
            state,
            req,
            &ticket_id,
            "blocked_license_invalid",
            now_ms,
            Some("CONNECTOR_LICENSE_ENFORCE=1: license outside valid_until window"),
        );
        return Err(
            ConnectorError::new(
                DenialReason::LicenseInvalid,
                "Platform license is not active (outside valid_until). Renew the license or unset CONNECTOR_LICENSE_ENFORCE for non-production evaluation.",
            )
            .with_denied_resource(req.operation.resource())
            .with_agent_scope(req.namespace)
            .with_audit_cid(audit_cid),
        );
    }

    // ── Step 1.5 Host kernel attachment (Connector Phase A — checklist §10.1 / §10.4) ──
    if kernel_host::kernel_enforce_enabled()
        && admission_op_requires_kernel_host_attestation(&req.operation)
    {
        let mut kh = state.kernel_host.lock().unwrap();
        let apply_state = kh
            .agent_attachment(req.agent_pid)
            .as_ref()
            .map(|a| a.host_apply_state);
        let host_ready = apply_state.map(|s| s.is_host_ready()).unwrap_or(false);
        // B32: Simulated attach must never satisfy enforce (even if fail-closed=0 in lab,
        // productionish modes still deny Simulated).
        let simulated = matches!(apply_state, Some(kernel_host::HostApplyState::Simulated));
        if !host_ready {
            kh.record_admission_deny();
            drop(kh);
            state.metrics.kernel_host_admission_denied_total.inc();
            state
                .metrics
                .admission_rejected_total
                .get_or_create(&crate::state::ReasonLabels {
                    reason: if simulated {
                        "kernel_host_simulated".to_string()
                    } else {
                        "kernel_host_not_ready".to_string()
                    },
                })
                .inc();

            let deny_simulated = simulated
                || kernel_host::kernel_fail_closed()
                || crate::connector_profile::is_productionish_env();
            if deny_simulated {
                let audit_cid = audit_decision(
                    state,
                    req,
                    &ticket_id,
                    if simulated {
                        "blocked_kernel_host_simulated"
                    } else {
                        "blocked_kernel_host"
                    },
                    now_ms,
                    Some(if simulated {
                        "CONNECTOR_KERNEL_ENFORCE=1 rejects Simulated attach — need real kerneld Active"
                    } else {
                        "CONNECTOR_KERNEL_ENFORCE=1 requires active host attachment"
                    }),
                );
                return Err(
                    ConnectorError::new(
                        DenialReason::KernelHostNotReady,
                        if simulated {
                            "Host kernel attach is Simulated (no BPF/nft). Real connector-kerneld confirm required before Active."
                        } else {
                            "Host kernel enforcement is enabled but this agent has no active attachment. \
                             Create a profile (POST /api/v1/kernel/profiles) then attach (POST /api/v1/kernel/agents/:pid/attach)."
                        },
                    )
                    .with_denied_resource(req.operation.resource())
                    .with_agent_scope(req.namespace)
                    .with_audit_cid(audit_cid),
                );
            }

            let _ = audit_decision(
                state,
                req,
                &ticket_id,
                "kernel_host_degraded_allow",
                now_ms,
                Some("CONNECTOR_KERNEL_FAIL_CLOSED=0: allowing without active host attachment (audit only)"),
            );
        }
    }

    // ── Step 1.6 Graph Firewall — relation-graph dynamic rules + agentic breaker ──
    let graph_verdict = crate::substrate::graph_firewall::evaluate(state, req, now_ms);
    if !graph_verdict.allowed {
        let reason = graph_verdict
            .deny_reason
            .clone()
            .unwrap_or_else(|| "graph firewall denied".into());
        let is_security = graph_verdict.breaker_tripped
            || graph_verdict
                .rules_fired
                .iter()
                .any(|r| r.action == "deny" || r.action == "block");
        if is_security {
            quarantine_agent(state, req.agent_pid, &reason);
        }
        state
            .metrics
            .admission_rejected_total
            .get_or_create(&crate::state::ReasonLabels {
                reason: "graph_firewall_denied".to_string(),
            })
            .inc();
        let audit_cid = audit_decision(
            state,
            req,
            &ticket_id,
            "blocked_graph_firewall",
            now_ms,
            Some(&reason),
        );
        return Err(ConnectorError::new(
            DenialReason::PolicyDenied,
            format!("Graph firewall denied: {}", reason),
        )
        .with_denied_resource(req.operation.resource())
        .with_agent_scope(req.namespace)
        .with_audit_cid(audit_cid));
    }
    let graph_has_grant = graph_verdict.has_namespace_grant;

    // ── Step 2: Guard Pipeline (5 layers) ────────────────────────────────
    // Run the full GuardPipeline: MAC → Policy → Content → CircuitBreaker → Audit+HITL.
    // This is the SAME pipeline used by POST /firewall/inspect, but now it ENFORCES.
    {
        // Resolve agent clearance from metadata (default: Standard)
        let agent_clearance = {
            let es = state.engine_store.lock().unwrap();
            es.folder_get("agent_meta", req.agent_pid)
                .ok()
                .flatten()
                .and_then(|m| m.get("clearance").and_then(|v| v.as_u64()))
                .map(|c| match c {
                    0 => SecurityLevel::Public,
                    1 => SecurityLevel::ToolIO,
                    3 => SecurityLevel::Protected,
                    4 => SecurityLevel::Control,
                    5 => SecurityLevel::Kernel,
                    _ => SecurityLevel::Standard,
                })
                .unwrap_or(SecurityLevel::Standard)
        };

        // Normalize namespace so MAC resolves correctly.
        // Unknown prefixes (gateway/, demo3/, tools/) → map to valid namespace type.
        let guard_namespace = normalize_namespace(req.namespace, &req.operation);

        let is_owner = agent_owns_guard_namespace(state.as_ref(), req.agent_pid, &guard_namespace);

        let guard_req = GuardRequest {
            request_id: ticket_id.clone(),
            agent_pid: req.agent_pid.to_string(),
            agent_clearance,
            operation: req.operation.slug().to_string(),
            namespace: guard_namespace,
            content: req.content.map(|s| s.to_string()),
            content_type: Some("input".into()),
            is_owner, // B30: real ownership — grants cover cross-namespace
            has_grant: graph_has_grant,
            has_integrity_grant: false,
            has_write_down_grant: false,
            is_read: matches!(
                req.operation,
                AdmissionOp::LlmChat | AdmissionOp::MemoryRead { .. }
            ),
            is_write: matches!(
                req.operation,
                AdmissionOp::MemoryWrite
                    | AdmissionOp::ToolDispatch { .. }
                    | AdmissionOp::McpCall { .. }
                    | AdmissionOp::PipelineStep { .. }
                    | AdmissionOp::ConpCommand { .. }
            ),
            is_kernel: false,
            timestamp_ms: now_ms,
        };

        let chain = {
            let mut guard = state.guard.lock().unwrap();
            guard.evaluate(&guard_req)
        };

        if let GuardDecision::Deny { reason } = &chain.final_decision {
            // Security deny → quarantine + HITL + audit
            let is_security = is_security_denial(&reason);
            if is_security {
                quarantine_agent(state, req.agent_pid, &reason);
            }
            crate::substrate::graph_firewall::record_guard_denial(
                state,
                req.agent_pid,
                reason,
                now_ms,
            );

            let audit_cid = audit_decision(
                state,
                req,
                &ticket_id,
                "blocked_guard",
                now_ms,
                Some(&reason),
            );

            return Err(ConnectorError::new(
                DenialReason::PolicyDenied,
                format!("Guard pipeline denied: {}", reason),
            )
            .with_denied_resource(req.operation.resource())
            .with_agent_scope(req.namespace)
            .with_audit_cid(audit_cid));
        }
    }

    // ── Step 3: Injection score (heuristic) ──────────────────────────────
    // Defense in depth: even if GuardPipeline L3 passed, run the heuristic.
    let injection_score = if let Some(content) = req.content {
        let score = {
            let mut detector = SemanticInjectionDetector::new();
            let result = detector.analyze(content, req.agent_pid);
            result.score
        };

        if score >= 0.75 {
            // Security violation → quarantine + HITL + audit
            quarantine_agent(
                state,
                req.agent_pid,
                &format!("Injection detected (score={:.2})", score),
            );
            crate::substrate::graph_firewall::record_injection_denial(state, req.agent_pid, now_ms);

            let audit_cid = audit_decision(
                state,
                req,
                &ticket_id,
                "blocked_injection",
                now_ms,
                Some(&format!("score={:.2}", score)),
            );

            // Metrics
            state
                .metrics
                .injections_by_agent
                .get_or_create(&crate::state::AgentLabels {
                    agent_pid: req.agent_pid.to_string(),
                })
                .inc();
            state
                .metrics
                .admission_rejected_total
                .get_or_create(&crate::state::ReasonLabels {
                    reason: "injection_detected".to_string(),
                })
                .inc();

            return Err(ConnectorError::injection_detected(score)
                .with_denied_resource(req.operation.resource())
                .with_agent_scope(req.namespace)
                .with_audit_cid(audit_cid));
        }

        score
    } else {
        0.0
    };

    // ── Step 4: All passed — audit PASS ──────────────────────────────────
    let pass_audit_cid = audit_decision(state, req, &ticket_id, "allowed", now_ms, None);

    let (kernel_policy_revision, kernel_host_apply_state) = {
        let kh = state.kernel_host.lock().unwrap();
        kh.agent_attachment(req.agent_pid)
            .map(|a| {
                (
                    Some(a.policy_revision),
                    Some(a.host_apply_state.as_str().to_string()),
                )
            })
            .unwrap_or((None, None))
    };

    crate::substrate::causal::record_admission_envelope(
        state,
        req.agent_pid,
        None,
        req.agent_pid,
        None,
        req.operation.slug(),
        &req.operation.resource(),
        &ticket_id,
        kernel_policy_revision,
    );

    let _flow_lease = if crate::kernel::docklock::ring1_enforce_enabled() {
        None
    } else {
        crate::substrate::flow_lease::mint_on_admission_pass(
            state.as_ref(),
            req.agent_pid,
            None,
            req.operation.slug(),
            &ticket_id,
        )
    };

    crate::kernel::docklock::enforce_ring1(
        state.as_ref(),
        req.agent_pid,
        req.operation.slug(),
        crate::kernel::ring1_context::resolve_quantum_id(req.execution_quantum_id).as_deref(),
    )?;

    Ok(AdmissionTicket {
        ticket_id,
        injection_score,
        audit_cid: Some(pass_audit_cid),
        kernel_policy_revision,
        kernel_host_apply_state,
    })
}

// ═══════════════════════════════════════════════════════════════════════════
// Quarantine — isolate agent + create HITL request
// ═══════════════════════════════════════════════════════════════════════════

/// Operator-initiated quarantine — blocks all admission + lifecycle execution paths.
pub fn operator_quarantine_agent(state: &SharedState, agent_pid: &str, reason: &str, by: &str) {
    quarantine_agent(state, agent_pid, &format!("operator:{by}: {reason}"));
    let (kernel_pid, _) = crate::services::agents::resolve_kernel_pid(state, agent_pid);
    crate::services::intelligence_authority::kernel_suspend_if_present(
        state,
        &kernel_pid,
        reason,
    );
}

/// Quarantine an agent: set quarantined=true in agent_meta, create HITL request.
///
/// After this call, ALL subsequent `admission::check()` calls for this agent
/// will return HTTP 403 AgentQuarantined until a human approves via HITL.
fn quarantine_agent(state: &SharedState, agent_pid: &str, reason: &str) {
    let now = chrono::Utc::now().to_rfc3339();

    // Create HITL request for human review
    let hitl_id = crate::services::agents::hitl_submit_with_state(
        agent_pid,
        "unquarantine",
        &format!(
            "Agent quarantined: {}. Review and approve to resume, or deny to terminate.",
            reason
        ),
        Some(state),
    );

    tracing::warn!(
        agent_pid = %agent_pid,
        reason = %reason,
        hitl_request_id = %hitl_id,
        "ADMISSION GATE: Agent quarantined — all actions blocked until HITL approval"
    );

    // Persist quarantine state
    let mut es = state.engine_store.lock().unwrap();
    let existing = es
        .folder_get("agent_meta", agent_pid)
        .ok()
        .flatten()
        .unwrap_or_else(|| serde_json::json!({"pid": agent_pid}));
    let mut meta = existing.as_object().cloned().unwrap_or_default();
    meta.insert("quarantined".into(), serde_json::json!(true));
    meta.insert("quarantine_reason".into(), serde_json::json!(reason));
    meta.insert("quarantined_at".into(), serde_json::json!(now));
    meta.insert("quarantine_hitl_id".into(), serde_json::json!(hitl_id));
    meta.insert("paused".into(), serde_json::json!(true)); // also set legacy paused flag
    meta.insert("paused_by".into(), serde_json::json!("admission_gate"));
    meta.insert("paused_at".into(), serde_json::json!(now));
    let _ = es.folder_put("agent_meta", agent_pid, &serde_json::Value::Object(meta));
    drop(es);

    // Void LLM broker tokens — shared model retains no usable agent authority.
    crate::substrate::llm_context_broker::invalidate_agent(
        state,
        agent_pid,
        &format!("quarantine:{reason}"),
    );

    // IAC L1: bump per-agent epoch so in-flight ATUs / Talk bindings become stale.
    let new_epoch = state.cells.bump_epoch(agent_pid);
    tracing::info!(
        agent_pid = %agent_pid,
        epoch = new_epoch,
        "IAC: epoch bumped on quarantine"
    );

    let (kernel_pid, _) = crate::services::agents::resolve_kernel_pid(state, agent_pid);
    crate::services::intelligence_authority::kernel_suspend_if_present(state, &kernel_pid, reason);
}

/// CDMI matrix isolation — quarantine + egress cut (continuity break / hardware tamper).
pub fn matrix_security_isolate(state: &SharedState, agent_pid: &str, reason: &str) {
    quarantine_agent(state, agent_pid, reason);
    let now = chrono::Utc::now().to_rfc3339();
    let mut es = state.engine_store.lock().unwrap();
    let existing = es
        .folder_get("agent_meta", agent_pid)
        .ok()
        .flatten()
        .unwrap_or_else(|| serde_json::json!({"pid": agent_pid}));
    let mut meta = existing.as_object().cloned().unwrap_or_default();
    meta.insert("egress_isolated".into(), serde_json::json!(true));
    meta.insert("matrix_isolation_reason".into(), serde_json::json!(reason));
    meta.insert("matrix_isolated_at".into(), serde_json::json!(now));
    meta.insert("cdmi_posture".into(), serde_json::json!("egress_isolated"));
    let _ = es.folder_put("agent_meta", agent_pid, &serde_json::Value::Object(meta));
}

/// Unquarantine an agent. Called by HITL approve flow in agents.rs.
pub fn unquarantine_agent(state: &SharedState, agent_pid: &str, approved_by: &str) {
    let now = chrono::Utc::now().to_rfc3339();

    tracing::info!(
        agent_pid = %agent_pid,
        approved_by = %approved_by,
        "ADMISSION GATE: Agent unquarantined — resuming normal operations"
    );

    let mut es = state.engine_store.lock().unwrap();
    let existing = es
        .folder_get("agent_meta", agent_pid)
        .ok()
        .flatten()
        .unwrap_or_else(|| serde_json::json!({"pid": agent_pid}));
    let mut meta = existing.as_object().cloned().unwrap_or_default();
    meta.insert("quarantined".into(), serde_json::json!(false));
    meta.insert("unquarantined_at".into(), serde_json::json!(now));
    meta.insert("unquarantined_by".into(), serde_json::json!(approved_by));
    meta.insert("paused".into(), serde_json::json!(false));
    // B31: clear matrix/egress isolation so admission is not still blocked.
    meta.insert("egress_isolated".into(), serde_json::json!(false));
    meta.insert("cdmi_posture".into(), serde_json::json!("nominal"));
    meta.remove("matrix_isolation_reason");
    meta.remove("matrix_isolated_at");
    meta.insert("host_egress_cut_applied".into(), serde_json::json!(false));
    let _ = es.folder_put("agent_meta", agent_pid, &serde_json::Value::Object(meta));
    drop(es);

    crate::substrate::spend_cease::clear_post_cease_retries(state.as_ref(), agent_pid);

    let _ = crate::kernel::matrix_host_egress::clear_matrix_host_egress_cut(agent_pid);

    // B31: demote Broken continuity to Unknown so Ring-1 is not stuck; next eval re-verifies.
    let api_pid = crate::kernel::agent_principal::api_pid_from_kernel(state.as_ref(), agent_pid)
        .unwrap_or_else(|| agent_pid.to_string());
    if let Some(mut cont) =
        crate::kernel::agent_principal::load_continuity(state.as_ref(), &api_pid)
    {
        if matches!(cont.state, connector_trust::ContinuityStateV2::Broken) {
            cont.state = connector_trust::ContinuityStateV2::Unknown;
            cont.break_reason = Some("cleared_on_unquarantine_pending_reeval".into());
            cont.evaluated_at_ms = chrono::Utc::now().timestamp_millis();
            if let Ok(mut es) = state.engine_store.lock() {
                let _ = es.folder_put(
                    crate::kernel::agent_principal::IIA_CONTINUITY_FOLDER,
                    &api_pid,
                    &serde_json::to_value(&cont).unwrap_or_default(),
                );
            }
        }
    }

    // Reset circuit breakers so the agent isn't penalized by prior failures
    {
        let mut gp = state.guard.lock().unwrap();
        gp.circuit_breakers.reset(agent_pid);
    }
    crate::substrate::graph_firewall::reset_agentic_breaker(state, agent_pid);

    // Prior LLM context stays void — must mint a fresh broker token on next talk.
    crate::substrate::llm_context_broker::invalidate_agent(
        state,
        agent_pid,
        &format!("unquarantine:{approved_by}"),
    );
    // Human approval resume: new epoch + open sandbox → normal HTTP 200 path.
    let resume = crate::substrate::llm_agent_sandbox::resume_after_human_approval(
        state,
        agent_pid,
        approved_by,
    );

    // Audit the unquarantine
    let mut es = state.engine_store.lock().unwrap();
    let _ = es.append_audit(&EngineAuditEntry {
        timestamp: chrono::Utc::now().timestamp_millis(),
        category: "admission_gate".to_string(),
        agent_pid: Some(agent_pid.to_string()),
        action: "agent.unquarantined".to_string(),
        resource: None,
        verdict: Some("approved".to_string()),
        details: Some(serde_json::json!({
            "approved_by": approved_by,
            "unquarantined_at": now,
            "egress_cleared": true,
            "llm_context_broker_reseed_required": true,
            "llm_sealed_brain_new_epoch_only": true,
            "http_resume": 200,
            "broker_resume": resume,
        })),
        severity: "warn".to_string(),
    });
}

/// B30: whether the agent owns the (normalized) guard namespace.
fn agent_owns_guard_namespace(
    state: &crate::state::PlatformState,
    agent_pid: &str,
    guard_namespace: &str,
) -> bool {
    use vac_core::namespace_types::NamespaceValidator;

    let api_pid = crate::kernel::agent_principal::api_pid_from_kernel(state, agent_pid)
        .unwrap_or_else(|| agent_pid.to_string());
    let setup = crate::kernel::agent_identity_envelope::load_setup(state, &api_pid);
    let agent_owner = setup
        .as_ref()
        .map(|s| {
            s.namespace
                .trim_start_matches('/')
                .split('/')
                .nth(1)
                .unwrap_or(api_pid.as_str())
                .to_string()
        })
        .unwrap_or_else(|| api_pid.clone());
    let Some(owner) = NamespaceValidator::extract_owner(guard_namespace) else {
        return false;
    };
    owner == agent_owner
        || owner == api_pid
        || setup.as_ref().map(|s| owner == s.name).unwrap_or(false)
}

// ═══════════════════════════════════════════════════════════════════════════
// Audit — record every admission decision
// ═══════════════════════════════════════════════════════════════════════════

/// Write an audit entry for every admission decision (pass or deny).
/// Returns the audit CID (ticket_id serves as stable CID for this decision).
fn audit_decision(
    state: &SharedState,
    req: &AdmissionRequest,
    ticket_id: &str,
    verdict: &str,
    timestamp: i64,
    detail: Option<&str>,
) -> String {
    let entry = EngineAuditEntry {
        timestamp,
        category: "admission_gate".to_string(),
        agent_pid: Some(req.agent_pid.to_string()),
        action: format!("admission.{}", req.operation.slug()),
        resource: Some(req.operation.resource()),
        verdict: Some(verdict.to_string()),
        details: Some(serde_json::json!({
            "ticket_id": ticket_id,
            "namespace": req.namespace,
            "operation": req.operation.slug(),
            "detail": detail.unwrap_or(""),
        })),
        severity: if verdict == "allowed" {
            "info".to_string()
        } else {
            "warn".to_string()
        },
    };

    let mut es = state.engine_store.lock().unwrap();
    let _ = es.append_audit(&entry);
    ticket_id.to_string()
}

// ═══════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════

/// Normalize a namespace to a valid prefix so the guard pipeline's MAC layer
/// resolves the correct security level instead of defaulting to Kernel.
///
/// Gateway uses `gateway/{pid}` or `demo3/{pid}` — these don't match any known
/// prefix, so MAC defaults to Kernel(5) and blocks Standard(2) agents.
///
/// Mapping:
/// - `gateway/*`, `demo*/*` → `m/{rest}` (Memory, Standard level)
/// - `tools/*`              → `t/{rest}` (Tool, ToolIO level)
/// - Already valid (`m/`, `k/`, `t/`, etc.) → pass through
fn normalize_namespace(ns: &str, op: &AdmissionOp) -> String {
    let trimmed = ns.trim_start_matches('/');

    // Already a valid namespace prefix — pass through
    let valid_prefixes = ["m/", "k/", "v/", "x/", "c/", "a/", "t/", "s/", "p/"];
    for p in &valid_prefixes {
        if trimmed.starts_with(p) || trimmed == &p[..1] {
            return ns.to_string();
        }
    }

    // Map based on operation type
    match op {
        AdmissionOp::LlmChat => format!("m/{}", trimmed),
        AdmissionOp::MemoryWrite | AdmissionOp::MemoryRead { .. } => format!("m/{}", trimmed),
        AdmissionOp::ToolDispatch { .. } => format!("t/{}", trimmed),
        AdmissionOp::McpCall { .. } => format!("t/{}", trimmed),
        AdmissionOp::PipelineStep { .. } => format!("m/{}", trimmed),
        AdmissionOp::ConpCommand { .. } => format!("c/{}", trimmed),
    }
}

/// Determine if a guard denial reason indicates a security violation
/// (should trigger quarantine) vs a policy/config issue (should not).
fn is_security_denial(reason: &str) -> bool {
    let security_keywords = [
        "injection",
        "Injection",
        "semantic",
        "Semantic",
        "pii",
        "PII",
        "exfiltration",
        "boundary",
        "Boundary",
        "circuit breaker OPEN",
        "malicious",
        "adversarial",
        "toxicity",
        "toxic",
    ];
    security_keywords.iter().any(|kw| reason.contains(kw))
}

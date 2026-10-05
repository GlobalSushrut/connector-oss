//! Agent identity envelope — setup, activation, namespace isolation, forensic universal record (P10.10).

use connector_trust::{
    canonical_digest_json, ActivationStateV2, AgentActivationProfileV2, AgentCapabilityManifestV2,
    AgentIdentityEnvelopeV2, AgentKnowledgeSummaryV2, AgentKnotSummaryV2, AgentMemorySummaryV2,
    AgentNamespaceScopeV2, AgentSetupSpecV2, COGNITIVE_MEMORY_TYPES, ForensicPostureV2,
    ForensicProfileV2, ForensicUniversalEnvelopeV2, FORENSIC_UNIVERSAL_SCHEMA, HitlPolicyV2,
    HitlPostureV2, MemoryProfileV2, NamespaceGrantV2, NAMESPACE_PREFIX_TYPES,
    AGENT_IDENTITY_SCHEMA, SigningTierV2,
};
use sha2::{Digest, Sha256};
use vac_core::namespace_types::NamespaceValidator;

use crate::kernel::{agent_principal, forensics};
use crate::state::PlatformState;

pub const SETUP_FOLDER: &str = "agent_setup_spec_v2";
pub const ACTIVATION_FOLDER: &str = "agent_activation_profile_v2";
pub const GRANT_FOLDER: &str = "namespace_grant_v2";
pub const FORENSIC_UNIVERSAL_FOLDER: &str = "forensic_universal_envelope_v2";
pub const FORENSIC_UNIVERSAL_INDEX: &str = "forensic_universal_envelope_index_v2";

pub fn setup_gate_enabled() -> bool {
    std::env::var("CONNECTOR_AGENT_SETUP_GATE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn digest_json<T: serde::Serialize>(v: &T) -> String {
    canonical_digest_json(v).unwrap_or_else(|_| {
        hex::encode(Sha256::digest(serde_json::to_vec(v).unwrap_or_default()))
    })
}

pub fn default_memory_profile() -> MemoryProfileV2 {
    MemoryProfileV2 {
        default_memory_type: "working".into(),
        quota_tier: "standard".into(),
        enabled_types: COGNITIVE_MEMORY_TYPES.iter().map(|s| s.to_string()).collect(),
    }
}

pub fn normalize_kb_path_segment(kb_id: &str) -> String {
    kb_id
        .trim()
        .trim_start_matches("/k/")
        .trim_start_matches("kb:")
        .to_string()
}

pub fn mint_default_setup(
    api_pid: &str,
    name: &str,
    namespace: &str,
    acume: &str,
    knowledge_base_id: Option<&str>,
    contract_ref: &str,
) -> AgentSetupSpecV2 {
    let kb_id = knowledge_base_id
        .map(str::to_string)
        .unwrap_or_else(|| format!("kb:{}", acume.to_lowercase().replace('_', "-")));
    let kb_path = normalize_kb_path_segment(&kb_id);
    let now = chrono::Utc::now().timestamp_millis();
    AgentSetupSpecV2 {
        schema: AGENT_IDENTITY_SCHEMA.into(),
        agent_pid: api_pid.to_string(),
        name: name.to_string(),
        acume: acume.to_string(),
        namespace: namespace.to_string(),
        memory_profile: default_memory_profile(),
        knowledge_base_id: kb_id.clone(),
        knowledge_base_address: format!("/k/{kb_path}"),
        use_case_def: None,
        contract_ref: contract_ref.to_string(),
        // General-purpose defaults: no HITL stall on MCP; forensic off until operator charters
        // Soc2/HIPAA/Court. Operators tighten via Charter Studio / setup POST.
        hitl_policy: HitlPolicyV2::None,
        forensic_profile: ForensicProfileV2::Off,
        philosophy_digest: Some(hex::encode(Sha256::digest(acume.as_bytes()))),
        common_spaces: vec![],
        configured_at_ms: now,
        setup_complete: true,
    }
}

/// B14: when setup gate is on, register must not look "pre-configured".
pub fn mint_draft_setup(
    api_pid: &str,
    name: &str,
    namespace: &str,
    acume: &str,
    knowledge_base_id: Option<&str>,
    contract_ref: &str,
) -> AgentSetupSpecV2 {
    let mut spec = mint_default_setup(api_pid, name, namespace, acume, knowledge_base_id, contract_ref);
    spec.hitl_policy = HitlPolicyV2::None;
    spec.forensic_profile = ForensicProfileV2::Off;
    spec.setup_complete = false;
    spec.philosophy_digest = None;
    spec
}

pub fn save_setup(state: &PlatformState, spec: &AgentSetupSpecV2) -> Result<(), String> {
    let mut es = state.engine_store.lock().map_err(|e| format!("{e:?}"))?;
    es.folder_put(SETUP_FOLDER, &spec.agent_pid, &serde_json::to_value(spec).unwrap())
        .map_err(|e| format!("{e:?}"))?;
    for grant in &spec.common_spaces {
        let _ = es.folder_put(GRANT_FOLDER, &grant.grant_id, &serde_json::to_value(grant).unwrap());
    }
    Ok(())
}

pub fn load_setup(state: &PlatformState, api_pid: &str) -> Option<AgentSetupSpecV2> {
    let es = state.engine_store.lock().ok()?;
    let v = es.folder_get(SETUP_FOLDER, api_pid).ok().flatten()?;
    serde_json::from_value(v).ok()
}

fn grant_lists_pid(list: &[String], pid: &str) -> bool {
    let agent_ref = format!("agent:{pid}");
    list.iter()
        .any(|a| a == pid || a == &agent_ref || a == "*" || a == "any")
}

/// True when `from` and `to` share a NamespaceGrantV2 (either side's setup).
pub fn agents_share_grant(
    state: &PlatformState,
    from_pid: &str,
    to_pid: &str,
    namespace: Option<&str>,
) -> bool {
    if from_pid == to_pid {
        return true;
    }
    let path_ok = |path: &str| match namespace {
        None => true,
        Some(ns) if ns.is_empty() => true,
        Some(ns) => path == ns || path.starts_with(ns) || ns.starts_with(path),
    };
    for owner in [from_pid, to_pid] {
        let Some(setup) = load_setup(state, owner) else {
            continue;
        };
        for g in &setup.common_spaces {
            if !path_ok(&g.path) {
                continue;
            }
            let other = if owner == from_pid { to_pid } else { from_pid };
            if grant_lists_pid(&g.readable_by, other) || grant_lists_pid(&g.writable_by, other) {
                return true;
            }
        }
    }
    false
}

/// DI-4 — inter-intelligence fabric only under grants when hardening is on.
pub fn require_inter_intelligence_grant(
    state: &PlatformState,
    from_pid: &str,
    to_pid: &str,
    namespace: Option<&str>,
) -> Result<(), String> {
    if from_pid.is_empty() || to_pid.is_empty() {
        return Err("grant_required: from_pid and to_pid required".into());
    }
    if from_pid == to_pid {
        return Ok(());
    }
    if crate::kernel::share_portal::agents_have_portal(state, from_pid, to_pid, namespace) {
        return Ok(());
    }
    if agents_share_grant(state, from_pid, to_pid, namespace) {
        return Ok(());
    }
    Err(format!(
        "share_contract_required: {from_pid} and {to_pid} are isolated by default. \
         Human+root must file a sharing contract (what, where, how much, why) → shared portal. \
         POST /api/v1/intelligence/share-contract"
    ))
}

pub fn load_activation(state: &PlatformState, api_pid: &str) -> Option<AgentActivationProfileV2> {
    let es = state.engine_store.lock().ok()?;
    let v = es.folder_get(ACTIVATION_FOLDER, api_pid).ok().flatten()?;
    serde_json::from_value(v).ok()
}

pub fn save_activation(state: &PlatformState, profile: &AgentActivationProfileV2) -> Result<(), String> {
    let mut es = state.engine_store.lock().map_err(|e| format!("{e:?}"))?;
    es.folder_put(ACTIVATION_FOLDER, &profile.agent_pid, &serde_json::to_value(profile).unwrap())
        .map_err(|e| format!("{e:?}"))
}

pub fn build_namespace_scope(
    api_pid: &str,
    namespace: &str,
    setup: &AgentSetupSpecV2,
) -> AgentNamespaceScopeV2 {
    let owner = namespace.trim_start_matches('/').split('/').nth(1).unwrap_or(api_pid);
    let private_memory = if namespace.starts_with('/') {
        namespace.to_string()
    } else {
        format!("/{namespace}")
    };
    let private_control = format!("/a/{owner}");
    let mut readable = vec![
        private_memory.clone(),
        private_control.clone(),
        setup.knowledge_base_address.clone(),
    ];
    let mut writable = vec![private_memory.clone(), private_control.clone()];
    for grant in &setup.common_spaces {
        let agent_ref = format!("agent:{api_pid}");
        if grant.readable_by.iter().any(|a| a == &agent_ref || a == api_pid) {
            readable.push(grant.path.clone());
        }
        if grant.writable_by.iter().any(|a| a == &agent_ref || a == api_pid) {
            writable.push(grant.path.clone());
        }
    }
    readable.sort();
    readable.dedup();
    writable.sort();
    writable.dedup();
    AgentNamespaceScopeV2 {
        private_memory,
        private_control,
        knowledge_base: setup.knowledge_base_address.clone(),
        readable_paths: readable,
        writable_paths: writable,
        common_spaces: setup.common_spaces.clone(),
        isolation_enforced: true,
    }
}

pub fn build_capability_manifest(setup: &AgentSetupSpecV2) -> AgentCapabilityManifestV2 {
    let now = chrono::Utc::now().timestamp_millis();
    let mut memory_types = std::collections::BTreeMap::new();
    for t in COGNITIVE_MEMORY_TYPES {
        let on = setup
            .memory_profile
            .enabled_types
            .iter()
            .any(|e| e.eq_ignore_ascii_case(t));
        memory_types.insert((*t).to_string(), on);
    }
    let mut namespace_prefixes = std::collections::BTreeMap::new();
    for p in NAMESPACE_PREFIX_TYPES {
        let on = matches!(*p, "memory" | "agent" | "knowledge" | "tool" | "public");
        namespace_prefixes.insert((*p).to_string(), on);
    }
    let forensic_on = !matches!(setup.forensic_profile, ForensicProfileV2::Off);
    AgentCapabilityManifestV2 {
        schema: AGENT_IDENTITY_SCHEMA.into(),
        memory_types,
        namespace_prefixes,
        thinking: true,
        knowledge_rag: true,
        knot_graph: true,
        forensic_iia: forensic_on,
        forensic_tracetramp: forensic_on,
        forensic_witnessctl: forensic_on,
        hitl: !matches!(setup.hitl_policy, HitlPolicyV2::None),
        activated_at_ms: now,
    }
}

pub fn build_memory_summary(state: &PlatformState, namespace: &str) -> AgentMemorySummaryV2 {
    let kernel = state.kernel.lock().unwrap();
    let packets = kernel.packets_in_namespace(namespace);
    let mut counts = std::collections::BTreeMap::new();
    for t in COGNITIVE_MEMORY_TYPES {
        counts.insert((*t).to_string(), 0);
    }
    let mut last_ms: Option<i64> = None;
    for pkt in &packets {
        let mt = format!("{:?}", pkt.memory_type).to_lowercase();
        *counts.entry(mt).or_insert(0) += 1;
        let ts = pkt.index.ts;
        last_ms = Some(last_ms.map(|l| l.max(ts)).unwrap_or(ts));
    }
    AgentMemorySummaryV2 {
        counts_by_type: counts,
        total_packets: packets.len() as u64,
        namespace: namespace.to_string(),
        last_packet_at_ms: last_ms,
    }
}

pub fn build_knowledge_summary(state: &PlatformState, setup: &AgentSetupSpecV2) -> AgentKnowledgeSummaryV2 {
    let kb_ns = setup
        .knowledge_base_address
        .trim_start_matches('/')
        .to_string();
    let kernel = state.kernel.lock().unwrap();
    let packets = kernel.packets_in_namespace(&kb_ns);
    let last_ms = packets.iter().map(|p| p.index.ts).max();
    AgentKnowledgeSummaryV2 {
        knowledge_base_id: setup.knowledge_base_id.clone(),
        knowledge_base_address: setup.knowledge_base_address.clone(),
        packet_count: packets.len() as u64,
        last_ingest_at_ms: last_ms,
    }
}

pub fn build_knot_summary(state: &PlatformState, api_pid: &str, namespace: &str) -> AgentKnotSummaryV2 {
    let owner = namespace.trim_start_matches('/').split('/').nth(1).unwrap_or(api_pid);
    let entity_key = format!("m:{owner}");
    let knot = state.knot.lock().unwrap();
    let node_count = knot
        .nodes()
        .keys()
        .filter(|k| k.contains(&entity_key) || k.contains(api_pid))
        .count() as u64;
    AgentKnotSummaryV2 {
        node_count,
        edge_count: knot.edge_count() as u64,
        agent_entity_key: entity_key,
    }
}

fn hitl_posture(state: &PlatformState, api_pid: &str, policy: HitlPolicyV2) -> HitlPostureV2 {
    let es = state.engine_store.lock().unwrap();
    let meta = es.folder_get("agent_meta", api_pid).ok().flatten();
    let quarantined = meta
        .as_ref()
        .and_then(|m| m.get("quarantined"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    drop(es);
    let pending_count = crate::services::agents::hitl_pending_count(api_pid);
    HitlPostureV2 {
        policy,
        pending_count,
        quarantined,
    }
}

fn forensic_posture(state: &PlatformState, api_pid: &str, profile: ForensicProfileV2) -> ForensicPostureV2 {
    let es = state.engine_store.lock().ok();
    let idx = es
        .and_then(|es| es.folder_get(FORENSIC_UNIVERSAL_INDEX, api_pid).ok().flatten());
    let count = idx
        .as_ref()
        .and_then(|v| v.get("count"))
        .and_then(|c| c.as_u64())
        .unwrap_or(0);
    let last_id = idx
        .and_then(|v| v.get("last_id").and_then(|x| x.as_str().map(str::to_string)));
    let wc_session = load_activation(state, api_pid).and_then(|a| a.witnessctl_session_hint);
    ForensicPostureV2 {
        profile,
        compliance_frameworks: profile.compliance_frameworks(),
        universal_envelope_count: count,
        last_envelope_id: last_id,
        witnessctl_session_id: wc_session,
    }
}

pub fn render_who_am_i(envelope: &AgentIdentityEnvelopeV2, acume: &str, agent_name: &str) -> String {
    let base = &envelope.base;
    let foundation = base.foundation_block.as_ref();
    let caps = base.contract.capabilities.join(", ");
    let denied = base.contract.denied_operations.join(", ");
    let mem_counts: String = envelope
        .memory_summary
        .counts_by_type
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(", ");
    let readable = envelope.namespace_scope.readable_paths.join(", ");
    let frameworks = envelope.forensic_posture.compliance_frameworks.join(", ");
    format!(
        "I am a Connector Agent — my identity is kernel-authoritative, not my LLM weights.\n\
        === IDENTITY ===\n\
        AgentID (principal): {pid}\n\
        IntelligenceID: {iid}\n\
        Agent Intelligence Hash: {hash}\n\
        Name: {name}\n\
        Acume/Purpose: {acume}\n\
        Activation: {act_state:?}\n\
        === MEMORY (VAC — 7 cognitive types) ===\n\
        Private namespace: {priv_ns}\n\
        Memory packets: {total} ({mem_counts})\n\
        P99 anchor: {p99}\n\
        === KNOWLEDGE ===\n\
        Knowledge base: {kb_addr} (id: {kb_id}, packets: {kb_cnt})\n\
        === KNOT (entity graph) ===\n\
        Nodes: {knot_nodes}, Edges: {knot_edges}, entity_key: {knot_key}\n\
        === CONTRACT & EXECUTION ===\n\
        Capabilities: {caps}\n\
        Denied operations: {denied}\n\
        Execution rules digest: {exec_digest}\n\
        HITL policy: {hitl:?}\n\
        === NAMESPACE SCOPE (isolation enforced) ===\n\
        Readable: {readable}\n\
        I cannot access another agent's /m/ or /a/ unless a common-space grant exists.\n\
        === FORENSIC & COMPLIANCE ===\n\
        Forensic profile: {forensic:?}\n\
        Compliance frameworks (WitnessCtl-ready): {frameworks}\n\
        Universal envelope records: {env_cnt}\n\
        === CAPABILITIES ACTIVE ===\n\
        Thinking: {think}, Knowledge RAG: {rag}, Knot: {knot}, Forensic IIA: {f_iia}\n\
        === GENERAL USE ===\n\
        I help with any task the operator asks that is allowed by my capabilities and not in denied operations.\n\
        Purpose/acume describes my role identity; it is not a ban on other work inside the contract.\n\
        When asked who I am, I answer ONLY from this kernel block.",
        pid = base.principal.principal_id,
        iid = foundation.map(|f| f.intelligence_id.as_str()).unwrap_or("unknown"),
        hash = foundation.map(|f| f.agent_intelligence_hash.as_str()).unwrap_or("unknown"),
        name = agent_name,
        acume = acume,
        act_state = envelope.activation.state,
        priv_ns = envelope.namespace_scope.private_memory,
        total = envelope.memory_summary.total_packets,
        mem_counts = mem_counts,
        p99 = foundation.map(|f| f.p99_memory_id.as_str()).unwrap_or("unknown"),
        kb_addr = envelope.knowledge_summary.knowledge_base_address,
        kb_id = envelope.knowledge_summary.knowledge_base_id,
        kb_cnt = envelope.knowledge_summary.packet_count,
        knot_nodes = envelope.knot_summary.node_count,
        knot_edges = envelope.knot_summary.edge_count,
        knot_key = envelope.knot_summary.agent_entity_key,
        caps = caps,
        denied = denied,
        exec_digest = envelope.execution_rules_digest,
        hitl = envelope.hitl_posture.policy,
        readable = readable,
        forensic = envelope.forensic_posture.profile,
        frameworks = frameworks,
        env_cnt = envelope.forensic_posture.universal_envelope_count,
        think = envelope.capability_manifest.thinking,
        rag = envelope.capability_manifest.knowledge_rag,
        knot = envelope.capability_manifest.knot_graph,
        f_iia = envelope.capability_manifest.forensic_iia,
    )
}

pub fn build_identity_envelope(state: &PlatformState, api_pid: &str) -> Option<AgentIdentityEnvelopeV2> {
    let base = agent_principal::runtime_self_envelope(state, api_pid)?;
    let setup = load_setup(state, api_pid)?;
    let activation = load_activation(state, api_pid).unwrap_or_else(|| {
        let manifest = build_capability_manifest(&setup);
        AgentActivationProfileV2 {
            schema: AGENT_IDENTITY_SCHEMA.into(),
            agent_pid: api_pid.to_string(),
            state: ActivationStateV2::Registered,
            setup_spec_digest_sha256: digest_json(&setup),
            capability_manifest: manifest,
            witnessctl_session_hint: None,
            activation_receipt_id: None,
            activated_at_ms: None,
        }
    });
    let namespace = setup.namespace.clone();
    let memory_summary = build_memory_summary(state, &namespace);
    let knowledge_summary = build_knowledge_summary(state, &setup);
    let knot_summary = build_knot_summary(state, api_pid, &namespace);
    let namespace_scope = build_namespace_scope(api_pid, &namespace, &setup);
    let hitl = hitl_posture(state, api_pid, setup.hitl_policy);
    let forensic = forensic_posture(state, api_pid, setup.forensic_profile);
    let execution_rules_digest = digest_json(&(
        &base.contract.contract_digest_sha256,
        &base.contract.denied_operations,
        &namespace_scope.readable_paths,
    ));
    let mut envelope = AgentIdentityEnvelopeV2 {
        schema: AGENT_IDENTITY_SCHEMA.into(),
        base,
        activation,
        capability_manifest: build_capability_manifest(&setup),
        memory_summary,
        knowledge_summary,
        knot_summary,
        namespace_scope,
        hitl_posture: hitl,
        forensic_posture: forensic,
        execution_rules_digest,
        who_am_i_authoritative: None,
    };
    envelope.who_am_i_authoritative = Some(render_who_am_i(&envelope, &setup.acume, &setup.name));
    envelope.base.who_am_i_authoritative = envelope.who_am_i_authoritative.clone();
    Some(envelope)
}

pub fn who_am_i_authoritative(state: &PlatformState, api_pid: &str) -> Option<String> {
    build_identity_envelope(state, api_pid).and_then(|e| e.who_am_i_authoritative)
}

fn normalize_ns(ns: &str) -> String {
    let trimmed = ns.trim().trim_start_matches('/');
    if trimmed.is_empty() {
        return String::new();
    }
    format!("/{trimmed}")
}

fn path_allowed(paths: &[String], target: &str) -> bool {
    let t = normalize_ns(target);
    paths.iter().any(|p| {
        let pn = normalize_ns(p);
        t == pn || t.starts_with(&format!("{pn}/"))
    })
}

/// Namespace isolation — agent may only touch its own `/m/`/`/a/` plus granted/common paths.
pub fn agent_may_access_namespace(
    state: &PlatformState,
    agent_pid: &str,
    target_ns: &str,
    write: bool,
) -> bool {
    let api_pid = agent_principal::api_pid_from_kernel(state, agent_pid)
        .unwrap_or_else(|| agent_pid.to_string());
    // Talk / gateway namespace: `gateway/{pid}` and remapped `m/gateway/{pid}` are in-scope
    // for that agent (forced-pid Talk path).
    if talk_gateway_ns_allowed(&api_pid, agent_pid, target_ns) {
        return true;
    }
    let setup = match load_setup(state, &api_pid) {
        Some(s) => s,
        None => {
            return owns_private_ns(agent_pid, &api_pid, target_ns)
                || crate::kernel::share_portal::agent_may_use_portal(
                    state, agent_pid, target_ns, write,
                );
        }
    };
    let scope = build_namespace_scope(&api_pid, &setup.namespace, &setup);
    let paths = if write {
        &scope.writable_paths
    } else {
        &scope.readable_paths
    };
    if path_allowed(paths, target_ns) {
        return true;
    }
    if crate::kernel::share_portal::agent_may_use_portal(state, &api_pid, target_ns, write)
        || crate::kernel::share_portal::agent_may_use_portal(state, agent_pid, target_ns, write)
    {
        return true;
    }
    // Deny cross-agent private paths (including /p — not public).
    if let Some(owner) = NamespaceValidator::extract_owner(target_ns) {
        let agent_owner = setup
            .namespace
            .trim_start_matches('/')
            .split('/')
            .nth(1)
            .unwrap_or(api_pid.as_str());
        if owner != agent_owner && owner != api_pid && owner != setup.name {
            return false;
        }
    }
    false
}

fn talk_gateway_ns_allowed(api_pid: &str, kernel_pid: &str, target_ns: &str) -> bool {
    let t = normalize_ns(target_ns);
    for id in [api_pid, kernel_pid] {
        let id = id.trim();
        if id.is_empty() {
            continue;
        }
        if t == format!("gateway/{id}")
            || t == format!("m/gateway/{id}")
            || t.starts_with(&format!("gateway/{id}/"))
            || t.starts_with(&format!("m/gateway/{id}/"))
        {
            return true;
        }
    }
    false
}

fn owns_private_ns(kernel_pid: &str, api_pid: &str, target_ns: &str) -> bool {
    let t = normalize_ns(target_ns);
    let ids = [kernel_pid, api_pid];
    ids.iter().any(|id| {
        let id = id.trim();
        !id.is_empty()
            && (t.contains(&format!("/{id}"))
                || t.contains(&format!("/{id}/"))
                || t.ends_with(id)
                || t.contains(&format!("nsfs/{id}")))
    })
}

pub fn apply_namespace_grants_to_kernel(state: &PlatformState, api_pid: &str) -> Result<(), String> {
    let setup = load_setup(state, api_pid).ok_or("setup_not_found")?;
    let kernel_pid = {
        let es = state.engine_store.lock().map_err(|e| format!("{e:?}"))?;
        es.folder_get("agent_meta", api_pid)
            .ok()
            .flatten()
            .and_then(|m| m.get("kernel_pid").and_then(|v| v.as_str().map(str::to_string)))
            .ok_or("kernel_pid_not_found")?
    };
    let scope = build_namespace_scope(api_pid, &setup.namespace, &setup);
    let own_ns = setup.namespace.trim_start_matches('/').to_string();
    let mut k = state.kernel.lock().map_err(|e| format!("{e:?}"))?;
    for path in &scope.readable_paths {
        let ns = path.trim_start_matches('/').to_string();
        if ns == own_ns {
            continue;
        }
        let write = scope.writable_paths.iter().any(|w| {
            let wn = w.trim_start_matches('/');
            wn == ns || ns.starts_with(&format!("{wn}/"))
        });
        let result = k.dispatch(vac_core::kernel::SyscallRequest {
            agent_pid: kernel_pid.clone(),
            operation: vac_core::types::MemoryKernelOp::AccessGrant,
            payload: vac_core::kernel::SyscallPayload::AccessGrant {
                target_namespace: ns,
                grantee_pid: kernel_pid.clone(),
                read: true,
                write,
                expires_at: None,
            },
            reason: Some(format!("agent_identity activate grant for {api_pid}")),
            vakya_id: None,
            trace_parent: None,
            trace_state: None,
            api_version: None,
        });
        if result.outcome != vac_core::types::OpOutcome::Success {
            tracing::warn!(
                "AccessGrant partial on activate for {}: {:?}",
                api_pid,
                result.outcome
            );
        }
    }
    Ok(())
}

pub fn validate_setup(spec: &AgentSetupSpecV2) -> Result<(), String> {
    if spec.name.trim().is_empty() {
        return Err("name required".into());
    }
    if spec.acume.trim().is_empty() {
        return Err("acume required".into());
    }
    if spec.knowledge_base_id.trim().is_empty() {
        return Err("knowledge_base_id required".into());
    }
    if spec.contract_ref.trim().is_empty() {
        return Err("contract_ref required".into());
    }
    Ok(())
}

pub fn activate_agent(state: &PlatformState, api_pid: &str) -> Result<AgentActivationProfileV2, String> {
    let mut setup = load_setup(state, api_pid).ok_or("setup_not_found — POST /agents/:pid/setup first")?;
    validate_setup(&setup)?;
    // B14: draft bootstrap is not activate-ready — operator must POST /setup first.
    if setup_gate_enabled() && !setup.setup_complete {
        return Err(
            "setup_incomplete — POST /agents/:pid/setup with HITL/forensic choices before activate"
                .into(),
        );
    }
    setup.setup_complete = true;
    save_setup(state, &setup)?;

    apply_namespace_grants_to_kernel(state, api_pid)?;

    // B10: bind persistent DockLock profile from contract (not a decorative string).
    let docklock_profile_id =
        crate::kernel::docklock::bind_docklock_profile_at_activate(state, api_pid)?;

    let manifest = build_capability_manifest(&setup);
    let receipt = forensics::append_receipt(
        state,
        forensics::AppendReceiptParams {
            agent_pid: api_pid.to_string(),
            cpo_id: None,
            quantum_id: None,
            docklock_profile_id: Some(docklock_profile_id.clone()),
            effect_digest: format!("activate|{}", digest_json(&manifest)),
        },
    );

    // B16: align WC session frameworks with forensic_profile (open when required + configured).
    let wc_align = crate::kernel::witnessctl_align::align_on_activate(
        state,
        api_pid,
        setup.forensic_profile,
    );
    let wc_hint = wc_align.session_id.clone().unwrap_or_else(|| {
        format!("wc:agent:{}", &api_pid[..api_pid.len().min(24)])
    });
    let profile = AgentActivationProfileV2 {
        schema: AGENT_IDENTITY_SCHEMA.into(),
        agent_pid: api_pid.to_string(),
        state: ActivationStateV2::Active,
        setup_spec_digest_sha256: digest_json(&setup),
        capability_manifest: manifest,
        witnessctl_session_hint: Some(wc_hint),
        activation_receipt_id: Some(receipt.receipt_id.clone()),
        activated_at_ms: Some(chrono::Utc::now().timestamp_millis()),
    };
    save_activation(state, &profile)?;

    let activation_digest = digest_json(&profile);
    let _ = crate::kernel::compliance_contract::bind_at_activate(
        state,
        api_pid,
        &activation_digest,
        // Prefer real WC session id; hint string only when open did not succeed.
        wc_align.session_id.clone().or_else(|| profile.witnessctl_session_hint.clone()),
    );

    if let Some(envelope) = build_identity_envelope(state, api_pid) {
        record_forensic_universal(
            state,
            api_pid,
            "activate",
            Some(&receipt.receipt_id),
            Some("agent activation — capability manifest + compliance contract bound"),
            &envelope,
            &profile,
        );
    }

    Ok(profile)
}

pub fn record_forensic_universal(
    state: &PlatformState,
    api_pid: &str,
    event_kind: &str,
    intelligence_receipt_id: Option<&str>,
    effect_summary: Option<&str>,
    envelope: &AgentIdentityEnvelopeV2,
    activation: &AgentActivationProfileV2,
) -> ForensicUniversalEnvelopeV2 {
    let principal = &envelope.base.principal;
    let four_id = forensics::four_id_linkage(state, api_pid).unwrap_or(connector_trust::FourIdLinkageV2 {
        agent_id: principal.principal_id.clone(),
        intelligence_id: principal.intelligence_id.clone().unwrap_or_default(),
        runtime_id: principal.runtime_hash.clone().unwrap_or_default(),
        machine_id: std::env::var("CONNECTOR_CELL_ID").unwrap_or_else(|_| "local".into()),
    });
    let setup = load_setup(state, api_pid);
    let forensic_profile = setup
        .as_ref()
        .map(|s| s.forensic_profile)
        .unwrap_or(ForensicProfileV2::Standard);
    let frameworks = forensic_profile.compliance_frameworks();
    let record = ForensicUniversalEnvelopeV2 {
        schema: FORENSIC_UNIVERSAL_SCHEMA.into(),
        envelope_id: format!("fue_{}", uuid::Uuid::new_v4()),
        event_kind: event_kind.to_string(),
        agent_pid: api_pid.to_string(),
        principal_id: principal.principal_id.clone(),
        intelligence_id: principal.intelligence_id.clone().unwrap_or_default(),
        four_id,
        identity_envelope_digest_sha256: digest_json(envelope),
        activation_profile_digest_sha256: digest_json(activation),
        forensic_profile,
        compliance_frameworks: frameworks,
        witnessctl_session_id: activation.witnessctl_session_hint.clone(),
        intelligence_receipt_id: intelligence_receipt_id.map(str::to_string),
        effect_summary: effect_summary.map(str::to_string),
        issued_at_ms: chrono::Utc::now().timestamp_millis(),
        // B26: universal envelopes are unsigned here — do not claim court.
        signing_tier: SigningTierV2::HmacLab,
    };

    {
        let mut es = state.engine_store.lock().unwrap();
        let _ = es.folder_put(
            FORENSIC_UNIVERSAL_FOLDER,
            &record.envelope_id,
            &serde_json::to_value(&record).unwrap(),
        );
        let prev_count = es
            .folder_get(FORENSIC_UNIVERSAL_INDEX, api_pid)
            .ok()
            .flatten()
            .and_then(|v| v.get("count").and_then(|c| c.as_u64()))
            .unwrap_or(0);
        let _ = es.folder_put(
            FORENSIC_UNIVERSAL_INDEX,
            api_pid,
            &serde_json::json!({
                "count": prev_count + 1,
                "last_id": record.envelope_id,
                "last_kind": event_kind,
            }),
        );
    }

    let leaf = hex::encode(Sha256::digest(
        format!(
            "{}|{}|{}",
            record.envelope_id, event_kind, record.identity_envelope_digest_sha256
        )
        .as_bytes(),
    ));
    let _ = crate::kernel::forensic_rollups::record_event(
        state,
        crate::kernel::forensic_rollups::RollupEvent {
            agent_pid: api_pid,
            event_kind,
            leaf_digest: leaf,
            universal_envelope_id: Some(record.envelope_id.clone()),
            namespace: Some(&envelope.namespace_scope.private_memory),
            cross_agent_denied: false,
            admission_deny: false,
            continuity_break: false,
            quarantine: envelope.hitl_posture.quarantined,
            egress_isolated: false,
            cpo_id: None,
            quantum_id: None,
            docklock_profile_id: None,
            intelligence_receipt_id: intelligence_receipt_id.map(str::to_string),
            witnessctl_session_id: record.witnessctl_session_id.clone(),
            tracetramp_trace_id: None,
            fni_flow_id: None,
            moment_id: None,
        },
    );

    record
}

pub fn list_forensic_universal(state: &PlatformState, api_pid: &str) -> Vec<ForensicUniversalEnvelopeV2> {
    let es = state.engine_store.lock().unwrap();
    let keys = es
        .folder_keys(FORENSIC_UNIVERSAL_FOLDER, None)
        .unwrap_or_default();
    keys.into_iter()
        .filter_map(|k| {
            let v = es.folder_get(FORENSIC_UNIVERSAL_FOLDER, &k).ok().flatten()?;
            let r: ForensicUniversalEnvelopeV2 = serde_json::from_value(v).ok()?;
            if r.agent_pid == api_pid {
                Some(r)
            } else {
                None
            }
        })
        .collect()
}

pub fn bootstrap_agent_identity(
    state: &PlatformState,
    api_pid: &str,
    name: &str,
    namespace: &str,
    acume: &str,
    knowledge_base_id: Option<&str>,
) -> Result<(), String> {
    let contract_ref = agent_principal::load_contract(state, api_pid)
        .map(|c| c.contract_digest_sha256)
        .unwrap_or_else(|| "iia:default".into());
    // B14: gate on → draft setup (incomplete / no silent Soc2+Egress claim).
    let spec = if setup_gate_enabled() {
        mint_draft_setup(api_pid, name, namespace, acume, knowledge_base_id, &contract_ref)
    } else {
        mint_default_setup(api_pid, name, namespace, acume, knowledge_base_id, &contract_ref)
    };
    save_setup(state, &spec)?;
    if setup_gate_enabled() {
        return Ok(());
    }
    activate_agent(state, api_pid)?;
    Ok(())
}

/// Hosted trial: complete setup and activate so Talk is not stuck on agent_not_activated.
pub fn force_activate_playground(state: &PlatformState, api_pid: &str) -> Result<(), String> {
    if let Some(act) = load_activation(state, api_pid) {
        if matches!(act.state, ActivationStateV2::Active) {
            return Ok(());
        }
    }
    let contract_ref = agent_principal::load_contract(state, api_pid)
        .map(|c| c.contract_digest_sha256)
        .unwrap_or_else(|| "iia:default".into());
    let spec = if let Some(existing) = load_setup(state, api_pid) {
        if validate_setup(&existing).is_ok() {
            let mut ready = existing;
            ready.setup_complete = true;
            ready
        } else {
            mint_default_setup(
                api_pid,
                &existing.name,
                &existing.namespace,
                if existing.acume.trim().is_empty() {
                    "playground:demo"
                } else {
                    existing.acume.as_str()
                },
                Some(existing.knowledge_base_id.as_str()),
                &contract_ref,
            )
        }
    } else {
        mint_default_setup(
            api_pid,
            "Demo",
            "m/demo",
            "playground:demo",
            None,
            &contract_ref,
        )
    };
    save_setup(state, &spec)?;
    activate_agent(state, api_pid)?;
    Ok(())
}

/// Agent may read its own identity when `X-Connector-Agent-Pid` matches (kernel truth path).
pub fn agent_self_access(headers: &axum::http::HeaderMap, api_pid: &str) -> bool {
    headers
        .get("x-connector-agent-pid")
        .and_then(|v| v.to_str().ok())
        .map(|h| h == api_pid)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespace_scope_includes_private_memory() {
        let setup = mint_default_setup(
            "agent_a",
            "finance",
            "m/finance",
            "FINANCE_AGENT_ACUME",
            None,
            "contract:abc",
        );
        let scope = build_namespace_scope("agent_a", "m/finance", &setup);
        assert!(scope.readable_paths.iter().any(|p| p.contains("m/finance")));
        assert!(scope.isolation_enforced);
    }

    #[test]
    fn kb_path_strips_prefix() {
        assert_eq!(
            normalize_kb_path_segment("kb:finance-corp"),
            "finance-corp"
        );
        assert_eq!(
            normalize_kb_path_segment("/k/finance-corp"),
            "finance-corp"
        );
    }

    #[test]
    fn draft_setup_is_incomplete_and_unconfigured() {
        let d = mint_draft_setup("a1", "n", "m/n", "ACUME", None, "c");
        assert!(!d.setup_complete);
        assert!(matches!(d.hitl_policy, HitlPolicyV2::None));
        assert!(matches!(d.forensic_profile, ForensicProfileV2::Off));
        let full = mint_default_setup("a1", "n", "m/n", "ACUME", None, "c");
        assert!(full.setup_complete);
        assert!(matches!(full.hitl_policy, HitlPolicyV2::None));
        assert!(matches!(full.forensic_profile, ForensicProfileV2::Off));
    }
}

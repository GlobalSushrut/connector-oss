//! **Graph Firewall v1** — relation-graph dynamic rules + unified agentic control breaker.
//!
//! Top enforcement layer for agentic systems: evaluates namespace grants, Knot relation edges,
//! parent/child agent topology, and persisted dynamic rules **before** the static guard pipeline.
//!
//! ```text
//! Relation graph (grants + knot edges + agent tree)
//!        ↓
//! Dynamic rules (engine_store + built-ins)
//!        ↓
//! AgenticControlBreaker (unified trip state)
//!        ↓
//! admission::check → GuardPipeline → injection
//! ```

use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{HashMap, HashSet};
use vac_core::types::MemoryKernelOp;

use crate::services::admission::{AdmissionOp, AdmissionRequest};
use crate::state::SharedState;

pub const SCHEMA: &str = "graph_firewall.v1";

/// Relations that hard-block cross-intelligence effects when present in Knot.
const BLOCKED_KNOT_RELATIONS: &[&str] = &[
    "contradicts",
    "distrust",
    "blocked",
    "revoked",
    "deny",
];

/// Built-in dynamic rules always evaluated (relation-graph semantics).
const BUILTIN_RULES: &[(&str, &str)] = &[
    (
        "namespace_write_grant",
        "Memory write requires writable namespace, own namespace, or AccessGrant edge",
    ),
    (
        "k_graph_grant",
        "Writes under k/* require explicit grant edge unless agent is system",
    ),
    (
        "tool_allowlist",
        "Tool dispatch requires tool in agent allowed_tools or grant",
    ),
    (
        "parent_quarantine_cascade",
        "Child agents blocked when parent is quarantined",
    ),
    (
        "knot_distrust_edge",
        "Knot distrust/contradicts edge to target blocks cross-namespace effects",
    ),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BreakerState {
    Closed,
    Open,
    HalfOpen,
}

impl BreakerState {
    pub fn as_str(self) -> &'static str {
        match self {
            BreakerState::Closed => "closed",
            BreakerState::Open => "open",
            BreakerState::HalfOpen => "half_open",
        }
    }
}

/// Unified per-agent control breaker (graph + guard + cost + anomaly).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AgenticBreakerState {
    pub graph_denials: u32,
    pub guard_denials: u32,
    pub injection_denials: u32,
    pub cost_trips: u32,
    pub anomaly_score: f64,
    pub state: String,
    pub consecutive_denials: u32,
    pub last_trip_ms: i64,
    pub last_success_ms: i64,
    pub trip_reason: Option<String>,
}

impl AgenticBreakerState {
    fn breaker_state(&self) -> BreakerState {
        match self.state.as_str() {
            "open" => BreakerState::Open,
            "half_open" => BreakerState::HalfOpen,
            _ => BreakerState::Closed,
        }
    }

    fn set_state(&mut self, s: BreakerState) {
        self.state = s.as_str().to_string();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantEdge {
    pub grantor_pid: String,
    pub target_namespace: String,
    pub read: bool,
    pub write: bool,
}

#[derive(Debug, Clone)]
pub struct RelationGraphContext {
    pub agent_pid: String,
    pub agent_namespace: String,
    pub readable_namespaces: Vec<String>,
    pub writable_namespaces: Vec<String>,
    pub allowed_tools: Vec<String>,
    pub parent_pid: Option<String>,
    pub child_pids: Vec<String>,
    pub parent_quarantined: bool,
    pub grant_edges: Vec<GrantEdge>,
    pub knot_blocked_targets: HashSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleFire {
    pub rule_id: String,
    pub action: String,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct GraphFirewallVerdict {
    pub allowed: bool,
    pub deny_reason: Option<String>,
    pub rules_fired: Vec<RuleFire>,
    pub has_namespace_grant: bool,
    pub breaker_tripped: bool,
    pub anomaly_score: f64,
}

pub fn failure_threshold() -> u32 {
    std::env::var("CONNECTOR_GRAPH_BREAKER_THRESHOLD")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&n| n > 0)
        .unwrap_or(5)
}

pub fn breaker_reset_ms() -> i64 {
    std::env::var("CONNECTOR_GRAPH_BREAKER_RESET_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&n| n > 0)
        .unwrap_or(60_000)
}

pub fn graph_firewall_enabled() -> bool {
    !matches!(
        std::env::var("CONNECTOR_GRAPH_FIREWALL").ok().as_deref(),
        Some("0") | Some("false") | Some("off")
    )
}

fn normalize_ns(ns: &str) -> String {
    let n = ns.trim();
    if n.starts_with('/') {
        n.to_string()
    } else {
        format!("/{n}")
    }
}

fn ns_allowed(target: &str, allowed: &[String]) -> bool {
    let t = normalize_ns(target);
    allowed.iter().any(|a| {
        let a = normalize_ns(a);
        t == a || t.starts_with(&format!("{a}/"))
    })
}

fn is_shared_knowledge_ns(ns: &str) -> bool {
    let n = normalize_ns(ns);
    n.starts_with("/k/") || n == "/k"
}

fn is_system_agent(pid: &str) -> bool {
    pid == "system" || pid.starts_with("system:") || pid.starts_with("pid:system")
}

/// Build relation graph context from kernel + knot + engine_store.
pub fn build_relation_graph(state: &SharedState, agent_pid: &str) -> RelationGraphContext {
    let (
        agent_namespace,
        readable_namespaces,
        writable_namespaces,
        allowed_tools,
        parent_pid,
        child_pids,
        grant_edges,
    ) = {
        let k = state.kernel.lock().unwrap();
        let acb = k.get_agent(agent_pid);
        let agent_namespace = acb
            .map(|a| a.namespace.clone())
            .unwrap_or_else(|| format!("m/{agent_pid}"));
        let readable_namespaces = acb
            .map(|a| a.readable_namespaces.clone())
            .unwrap_or_default();
        let writable_namespaces = acb
            .map(|a| a.writable_namespaces.clone())
            .unwrap_or_default();
        let allowed_tools = acb.map(|a| a.allowed_tools.clone()).unwrap_or_default();
        let parent_pid = acb.and_then(|a| a.parent_pid.clone());
        let child_pids = acb.map(|a| a.child_pids.clone()).unwrap_or_default();

        let mut grant_edges = Vec::new();
        for (pid, acb) in k.agents() {
            for ns in &acb.readable_namespaces {
                grant_edges.push(GrantEdge {
                    grantor_pid: pid.clone(),
                    target_namespace: ns.clone(),
                    read: true,
                    write: false,
                });
            }
            for ns in &acb.writable_namespaces {
                grant_edges.push(GrantEdge {
                    grantor_pid: pid.clone(),
                    target_namespace: ns.clone(),
                    read: true,
                    write: true,
                });
            }
        }

        for entry in k.audit_log().iter().rev().take(800) {
            if entry.operation != MemoryKernelOp::AccessGrant {
                continue;
            }
            if entry.agent_pid != agent_pid {
                continue;
            }
            if let Some(ref target) = entry.target {
                grant_edges.push(GrantEdge {
                    grantor_pid: agent_pid.to_string(),
                    target_namespace: target.clone(),
                    read: true,
                    write: true,
                });
            }
        }

        (
            agent_namespace,
            readable_namespaces,
            writable_namespaces,
            allowed_tools,
            parent_pid,
            child_pids,
            grant_edges,
        )
    };

    let parent_quarantined = parent_pid.as_ref().map_or(false, |pp| {
        let es = state.engine_store.lock().unwrap();
        es.folder_get("agent_meta", pp)
            .ok()
            .flatten()
            .and_then(|m| m.get("quarantined").and_then(|v| v.as_bool()))
            .unwrap_or(false)
    });

    let knot_blocked_targets = {
        let knot = state.knot.lock().unwrap();
        let agent_key = agent_pid
            .strip_prefix("pid:")
            .unwrap_or(agent_pid)
            .to_string();
        let mut blocked = HashSet::new();
        for edge in knot.edges_from(&agent_key) {
            if BLOCKED_KNOT_RELATIONS
                .iter()
                .any(|r| edge.relation.eq_ignore_ascii_case(r))
            {
                blocked.insert(edge.to.clone());
            }
        }
        for edge in knot.edges_to(&agent_key) {
            if BLOCKED_KNOT_RELATIONS
                .iter()
                .any(|r| edge.relation.eq_ignore_ascii_case(r))
            {
                blocked.insert(edge.from.clone());
            }
        }
        blocked
    };

    RelationGraphContext {
        agent_pid: agent_pid.to_string(),
        agent_namespace,
        readable_namespaces,
        writable_namespaces,
        allowed_tools,
        parent_pid,
        child_pids,
        parent_quarantined,
        grant_edges,
        knot_blocked_targets,
    }
}

fn has_grant_for(ctx: &RelationGraphContext, target_ns: &str, write: bool) -> bool {
    if is_system_agent(&ctx.agent_pid) {
        return true;
    }
    let t = normalize_ns(target_ns);
    if ns_allowed(&t, &[ctx.agent_namespace.clone()]) {
        return true;
    }
    if write {
        if ns_allowed(&t, &ctx.writable_namespaces) {
            return true;
        }
    } else if ns_allowed(&t, &ctx.readable_namespaces) {
        return true;
    }
    ctx.grant_edges.iter().any(|g| {
        let matches_ns = {
            let gn = normalize_ns(&g.target_namespace);
            t == gn || t.starts_with(&format!("{gn}/"))
        };
        matches_ns && g.grantor_pid == ctx.agent_pid && (!write || g.write)
    })
}

#[derive(Debug, Deserialize)]
struct PersistedRule {
    rule_id: String,
    #[serde(default)]
    operation: Option<String>,
    #[serde(default)]
    namespace_prefix: Option<String>,
    #[serde(default)]
    action: String,
    #[serde(default)]
    reason: Option<String>,
}

fn load_dynamic_rules(state: &SharedState) -> Vec<PersistedRule> {
    let es = state.engine_store.lock().unwrap();
    let keys = es
        .folder_keys("graph_firewall_rules", None)
        .unwrap_or_default();
    keys.into_iter()
        .filter_map(|k| es.folder_get("graph_firewall_rules", &k).ok().flatten())
        .filter_map(|v| serde_json::from_value(v).ok())
        .collect()
}

fn target_entity_from_ns(ns: &str) -> String {
    ns.trim_start_matches('/')
        .split('/')
        .next()
        .unwrap_or(ns)
        .to_string()
}

/// Evaluate relation-graph rules + agentic breaker. Called from admission Step 1.6.
pub fn evaluate(
    state: &SharedState,
    req: &AdmissionRequest<'_>,
    now_ms: i64,
) -> GraphFirewallVerdict {
    if !graph_firewall_enabled() {
        return GraphFirewallVerdict {
            allowed: true,
            deny_reason: None,
            rules_fired: vec![],
            has_namespace_grant: true,
            breaker_tripped: false,
            anomaly_score: 0.0,
        };
    }

    let ctx = build_relation_graph(state, req.agent_pid);
    let mut rules_fired = Vec::new();
    let mut breaker = load_breaker(state, req.agent_pid);

    // ── Unified breaker gate ─────────────────────────────────────────────
    if let Some(deny) = breaker_should_deny(&mut breaker, now_ms) {
        persist_breaker(state, req.agent_pid, &breaker);
        return GraphFirewallVerdict {
            allowed: false,
            deny_reason: Some(deny),
            rules_fired: vec![RuleFire {
                rule_id: "agentic_breaker_open".into(),
                action: "deny".into(),
                detail: breaker.trip_reason.clone().unwrap_or_default(),
            }],
            has_namespace_grant: false,
            breaker_tripped: true,
            anomaly_score: breaker.anomaly_score,
        };
    }

    let target_ns = normalize_ns(req.namespace);
    let has_grant = has_grant_for(&ctx, &target_ns, !matches!(req.operation, AdmissionOp::LlmChat));

    // ── R1: Parent quarantine cascade ───────────────────────────────────
    if ctx.parent_quarantined {
        rules_fired.push(RuleFire {
            rule_id: "parent_quarantine_cascade".into(),
            action: "deny".into(),
            detail: format!("parent {} is quarantined", ctx.parent_pid.as_deref().unwrap_or("?")),
        });
        return deny_verdict(
            state,
            req.agent_pid,
            &mut breaker,
            "parent agent quarantined — child blocked",
            rules_fired,
            has_grant,
            now_ms,
        );
    }

    // ── R2: Knot distrust edge ──────────────────────────────────────────
    let entity = target_entity_from_ns(&target_ns);
    if ctx.knot_blocked_targets.contains(&entity) {
        rules_fired.push(RuleFire {
            rule_id: "knot_distrust_edge".into(),
            action: "deny".into(),
            detail: format!("knot blocked relation to entity '{entity}'"),
        });
        return deny_verdict(
            state,
            req.agent_pid,
            &mut breaker,
            &format!("relation graph blocks target '{entity}'"),
            rules_fired,
            has_grant,
            now_ms,
        );
    }

    // ── R3: Namespace write grant (memory + shared k/*) ─────────────────
    match &req.operation {
        AdmissionOp::MemoryRead { namespace } => {
            let read_ns = normalize_ns(namespace);
            if !has_grant_for(&ctx, &read_ns, false) && !ns_allowed(&read_ns, &ctx.readable_namespaces) {
                if !is_system_agent(&ctx.agent_pid) {
                    rules_fired.push(RuleFire {
                        rule_id: "namespace_read_grant".into(),
                        action: "deny".into(),
                        detail: format!("no read grant for namespace {read_ns}"),
                    });
                    return deny_verdict(
                        state,
                        req.agent_pid,
                        &mut breaker,
                        &format!("graph firewall: no read grant for namespace {read_ns}"),
                        rules_fired,
                        false,
                        now_ms,
                    );
                }
            }
        }
        AdmissionOp::MemoryWrite => {
            if !has_grant_for(&ctx, &target_ns, true) {
                rules_fired.push(RuleFire {
                    rule_id: "namespace_write_grant".into(),
                    action: "deny".into(),
                    detail: format!("no write grant for namespace {target_ns}"),
                });
                return deny_verdict(
                    state,
                    req.agent_pid,
                    &mut breaker,
                    &format!("graph firewall: no write grant for namespace {target_ns}"),
                    rules_fired,
                    false,
                    now_ms,
                );
            }
            if is_shared_knowledge_ns(&target_ns) && !is_system_agent(&ctx.agent_pid) {
                let k_grant = ctx.grant_edges.iter().any(|g| {
                    g.grantor_pid == ctx.agent_pid
                        && (normalize_ns(&g.target_namespace).starts_with("/k/")
                            || normalize_ns(&g.target_namespace) == "/k")
                }) || ns_allowed(&target_ns, &ctx.writable_namespaces);
                if !k_grant {
                    rules_fired.push(RuleFire {
                        rule_id: "k_graph_grant".into(),
                        action: "deny".into(),
                        detail: "no grant edge for shared knowledge namespace".into(),
                    });
                    return deny_verdict(
                        state,
                        req.agent_pid,
                        &mut breaker,
                        "graph firewall: k/* write requires explicit grant edge",
                        rules_fired,
                        false,
                        now_ms,
                    );
                }
            }
        }
        AdmissionOp::ToolDispatch { tool_id } | AdmissionOp::McpCall { tool_name: tool_id } => {
            let tool = if matches!(req.operation, AdmissionOp::McpCall { .. }) {
                tool_id.as_str()
            } else {
                tool_id.as_str()
            };
            let tool_ok = ctx.allowed_tools.is_empty()
                || ctx.allowed_tools.iter().any(|t| {
                    t == tool || (t.ends_with('*') && tool.starts_with(t.trim_end_matches('*')))
                })
                || is_system_agent(&ctx.agent_pid);
            if !tool_ok {
                rules_fired.push(RuleFire {
                    rule_id: "tool_allowlist".into(),
                    action: "deny".into(),
                    detail: format!("tool '{tool}' not in allowed_tools graph"),
                });
                return deny_verdict(
                    state,
                    req.agent_pid,
                    &mut breaker,
                    &format!("graph firewall: tool '{tool}' not allowed for agent"),
                    rules_fired,
                    has_grant,
                    now_ms,
                );
            }
        }
        AdmissionOp::ConpCommand { capability_id, .. } => {
            let cap = capability_id.as_str();
            let tool_ok = ctx.allowed_tools.is_empty()
                || ctx.allowed_tools.iter().any(|t| {
                    t == cap
                        || t == &format!("conp:{cap}")
                        || (t.ends_with('*') && cap.starts_with(t.trim_end_matches('*')))
                })
                || is_system_agent(&ctx.agent_pid);
            if !tool_ok {
                rules_fired.push(RuleFire {
                    rule_id: "conp_capability_allowlist".into(),
                    action: "deny".into(),
                    detail: format!("CONP capability '{cap}' not in allowed_tools graph"),
                });
                return deny_verdict(
                    state,
                    req.agent_pid,
                    &mut breaker,
                    &format!("graph firewall: CONP '{cap}' not allowed for agent"),
                    rules_fired,
                    has_grant,
                    now_ms,
                );
            }
        }
        _ => {}
    }

    // ── R4: Persisted dynamic rules ─────────────────────────────────────
    for rule in load_dynamic_rules(state) {
        if let Some(ref op) = rule.operation {
            if op != req.operation.slug() && op != "*" {
                continue;
            }
        }
        if let Some(ref prefix) = rule.namespace_prefix {
            if !target_ns.starts_with(&normalize_ns(prefix)) {
                continue;
            }
        }
        let action = rule.action.to_ascii_lowercase();
        if action == "deny" || action == "block" {
            rules_fired.push(RuleFire {
                rule_id: rule.rule_id.clone(),
                action: action.clone(),
                detail: rule
                    .reason
                    .clone()
                    .unwrap_or_else(|| "dynamic rule matched".into()),
            });
            return deny_verdict(
                state,
                req.agent_pid,
                &mut breaker,
                &rules_fired
                    .last()
                    .map(|r| r.detail.clone())
                    .unwrap_or_else(|| "dynamic graph rule denied".into()),
                rules_fired,
                has_grant,
                now_ms,
            );
        }
    }

    // ── Pass — reset consecutive denials, record success ─────────────────
    breaker.consecutive_denials = 0;
    breaker.last_success_ms = now_ms;
    if breaker.breaker_state() == BreakerState::HalfOpen {
        breaker.set_state(BreakerState::Closed);
        breaker.trip_reason = None;
    }
    breaker.anomaly_score = (breaker.anomaly_score * 0.9).max(0.0);
    persist_breaker(state, req.agent_pid, &breaker);

    GraphFirewallVerdict {
        allowed: true,
        deny_reason: None,
        rules_fired,
        has_namespace_grant: has_grant,
        breaker_tripped: false,
        anomaly_score: breaker.anomaly_score,
    }
}

fn deny_verdict(
    state: &SharedState,
    agent_pid: &str,
    breaker: &mut AgenticBreakerState,
    reason: &str,
    rules_fired: Vec<RuleFire>,
    has_grant: bool,
    now_ms: i64,
) -> GraphFirewallVerdict {
    record_graph_denial(breaker, reason, now_ms);
    persist_breaker(state, agent_pid, breaker);
    GraphFirewallVerdict {
        allowed: false,
        deny_reason: Some(reason.to_string()),
        rules_fired,
        has_namespace_grant: has_grant,
        breaker_tripped: breaker.breaker_state() == BreakerState::Open,
        anomaly_score: breaker.anomaly_score,
    }
}

fn breaker_should_deny(breaker: &mut AgenticBreakerState, now_ms: i64) -> Option<String> {
    match breaker.breaker_state() {
        BreakerState::Closed => None,
        BreakerState::Open => {
            if now_ms - breaker.last_trip_ms >= breaker_reset_ms() {
                breaker.set_state(BreakerState::HalfOpen);
                breaker.consecutive_denials = 0;
                None
            } else {
                Some(
                    breaker
                        .trip_reason
                        .clone()
                        .unwrap_or_else(|| "agentic control breaker OPEN".into()),
                )
            }
        }
        BreakerState::HalfOpen => None,
    }
}

pub fn record_graph_denial(breaker: &mut AgenticBreakerState, reason: &str, now_ms: i64) {
    breaker.graph_denials = breaker.graph_denials.saturating_add(1);
    breaker.consecutive_denials = breaker.consecutive_denials.saturating_add(1);
    breaker.anomaly_score = (breaker.anomaly_score + 0.15).min(1.0);
    if breaker.consecutive_denials >= failure_threshold() {
        breaker.set_state(BreakerState::Open);
        breaker.last_trip_ms = now_ms;
        breaker.trip_reason = Some(format!(
            "agentic breaker tripped after {} denials: {}",
            breaker.consecutive_denials, reason
        ));
    }
}

/// Called from admission when guard or injection denies.
pub fn record_guard_denial(state: &SharedState, agent_pid: &str, reason: &str, now_ms: i64) {
    let mut breaker = load_breaker(state, agent_pid);
    breaker.guard_denials = breaker.guard_denials.saturating_add(1);
    record_graph_denial(&mut breaker, reason, now_ms);
    persist_breaker(state, agent_pid, &breaker);
}

pub fn record_injection_denial(state: &SharedState, agent_pid: &str, now_ms: i64) {
    let mut breaker = load_breaker(state, agent_pid);
    breaker.injection_denials = breaker.injection_denials.saturating_add(1);
    breaker.anomaly_score = (breaker.anomaly_score + 0.35).min(1.0);
    record_graph_denial(&mut breaker, "injection detected", now_ms);
    persist_breaker(state, agent_pid, &breaker);
}

pub fn record_cost_trip(state: &SharedState, agent_pid: &str, now_ms: i64) {
    let mut breaker = load_breaker(state, agent_pid);
    breaker.cost_trips = breaker.cost_trips.saturating_add(1);
    record_graph_denial(&mut breaker, "cost circuit breaker", now_ms);
    persist_breaker(state, agent_pid, &breaker);
}

pub fn reset_agentic_breaker(state: &SharedState, agent_pid: &str) {
    let mut es = state.engine_store.lock().unwrap();
    let _ = es.folder_delete("agentic_breakers", agent_pid);
}

pub fn load_breaker(state: &SharedState, agent_pid: &str) -> AgenticBreakerState {
    let es = state.engine_store.lock().unwrap();
    es.folder_get("agentic_breakers", agent_pid)
        .ok()
        .flatten()
        .and_then(|v| serde_json::from_value(v).ok())
        .unwrap_or_default()
}

pub fn persist_breaker(state: &SharedState, agent_pid: &str, breaker: &AgenticBreakerState) {
    let mut es = state.engine_store.lock().unwrap();
    let _ = es.folder_put(
        "agentic_breakers",
        agent_pid,
        &serde_json::to_value(breaker).unwrap_or(json!({})),
    );
}

pub fn intelligence_standard_json() -> serde_json::Value {
    json!({
        "schema": SCHEMA,
        "principle": "Relation graph (grants + knot edges + agent tree) drives dynamic firewall rules; unified agentic breaker trips before guard pipeline on cascade failure.",
        "layers": {
            "graph_firewall": "Step 1.6 admission — relation-graph dynamic rules",
            "guard_pipeline": "Step 2 — MAC, policy, content, circuit breaker, HITL",
            "injection": "Step 3 — semantic injection heuristic",
        },
        "relation_graph_sources": [
            "kernel AgentControlBlock readable/writable namespaces",
            "kernel AccessGrant audit edges",
            "Knot entity edges (contradicts/distrust/blocked/revoked/deny)",
            "parent/child agent topology + quarantine cascade",
            "engine_store graph_firewall_rules/* (operator dynamic rules)",
        ],
        "builtin_rules": BUILTIN_RULES.iter().map(|(id, desc)| json!({"id": id, "description": desc})).collect::<Vec<_>>(),
        "breaker": {
            "threshold": failure_threshold(),
            "reset_ms": breaker_reset_ms(),
            "state_folder": "agentic_breakers",
        },
        "not_this": [
            "Static regex-only firewall without graph context",
            "Host nftables/eBPF (see CONNECTOR_OS_AGENTIC_ENTROPY_FIREWALL_RESEARCH.md Phase A)",
            "Monitor alert-rules (ops telemetry, not action firewall)",
        ],
    })
}

pub fn fleet_status(state: &SharedState) -> serde_json::Value {
    let es = state.engine_store.lock().unwrap();
    let keys = es.folder_keys("agentic_breakers", None).unwrap_or_default();
    let mut open = 0usize;
    let mut half_open = 0usize;
    let agents: Vec<serde_json::Value> = keys
        .iter()
        .filter_map(|k| {
            let b: AgenticBreakerState = es
                .folder_get("agentic_breakers", k)
                .ok()
                .flatten()
                .and_then(|v| serde_json::from_value(v).ok())?;
            match b.breaker_state() {
                BreakerState::Open => open += 1,
                BreakerState::HalfOpen => half_open += 1,
                BreakerState::Closed => {}
            }
            Some(json!({
                "agent_pid": k,
                "state": b.state,
                "graph_denials": b.graph_denials,
                "guard_denials": b.guard_denials,
                "injection_denials": b.injection_denials,
                "cost_trips": b.cost_trips,
                "anomaly_score": b.anomaly_score,
                "trip_reason": b.trip_reason,
            }))
        })
        .collect();

    let dynamic_rules = es.folder_keys("graph_firewall_rules", None).unwrap_or_default().len();

    let (agent_count, grant_audit_count) = {
        let k = state.kernel.lock().unwrap();
        let grants = k
            .audit_log()
            .iter()
            .filter(|e| e.operation == MemoryKernelOp::AccessGrant)
            .count();
        (k.agent_count(), grants)
    };

    json!({
        "ok": true,
        "schema": SCHEMA,
        "enabled": graph_firewall_enabled(),
        "agents_tracked": agents.len(),
        "breakers_open": open,
        "breakers_half_open": half_open,
        "kernel_agents": agent_count,
        "grant_audit_edges": grant_audit_count,
        "dynamic_rules_loaded": dynamic_rules,
        "agents": agents,
    })
}

pub fn agent_status(state: &SharedState, agent_pid: &str) -> serde_json::Value {
    let breaker = load_breaker(state, agent_pid);
    let ctx = build_relation_graph(state, agent_pid);
    let guard_cb = {
        let guard = state.guard.lock().unwrap();
        format!("{:?}", guard.circuit_breakers.get_state(agent_pid))
    };

    json!({
        "ok": true,
        "schema": SCHEMA,
        "agent_pid": agent_pid,
        "agentic_breaker": breaker,
        "guard_circuit": guard_cb,
        "relation_graph": {
            "namespace": ctx.agent_namespace,
            "readable_count": ctx.readable_namespaces.len(),
            "writable_count": ctx.writable_namespaces.len(),
            "grant_edges": ctx.grant_edges.len(),
            "knot_blocked_targets": ctx.knot_blocked_targets.len(),
            "parent_pid": ctx.parent_pid,
            "parent_quarantined": ctx.parent_quarantined,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn has_grant_own_namespace() {
        let ctx = RelationGraphContext {
            agent_pid: "pid:a".into(),
            agent_namespace: "/m/agent-a".into(),
            readable_namespaces: vec![],
            writable_namespaces: vec![],
            allowed_tools: vec![],
            parent_pid: None,
            child_pids: vec![],
            parent_quarantined: false,
            grant_edges: vec![],
            knot_blocked_targets: HashSet::new(),
        };
        assert!(has_grant_for(&ctx, "/m/agent-a", true));
    }

    #[test]
    fn blocked_knot_relation_set() {
        assert!(BLOCKED_KNOT_RELATIONS.contains(&"contradicts"));
    }

    #[test]
    fn breaker_trips_after_threshold() {
        let mut b = AgenticBreakerState::default();
        let now = 1_000_000_i64;
        for _ in 0..failure_threshold() {
            record_graph_denial(&mut b, "test", now);
        }
        assert_eq!(b.breaker_state(), BreakerState::Open);
    }

    #[test]
    fn standard_json_has_layers() {
        let v = intelligence_standard_json();
        assert!(v.get("layers").is_some());
        assert_eq!(v.get("schema").and_then(|s| s.as_str()), Some(SCHEMA));
    }

    #[test]
    fn graph_firewall_enabled_by_default() {
        std::env::remove_var("CONNECTOR_GRAPH_FIREWALL");
        assert!(graph_firewall_enabled());
    }
}

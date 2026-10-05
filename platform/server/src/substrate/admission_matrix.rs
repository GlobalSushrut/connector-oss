//! Declared admission coverage for mutating effect paths (operator honesty surface).

use serde_json::{json, Value};

/// Critical effect handlers that must call `admission::check` or `admission_gate::*`.
pub const CRITICAL_HANDLERS: &[(&str, &str)] = &[
    ("gateway.rs", "pate::admit_talk"),
    ("anthropic_gateway.rs", "pate::admit_talk"),
    ("memory.rs", "governed_effect::evaluate_effect"),
    ("memory2.rs", "admission_gate::"),
    ("tools.rs", "pate::admit_tool"),
    ("object_fabric.rs", "governed_effect::evaluate_effect"),
    ("multiagent.rs", "admission_gate::"),
    ("protocols.rs", "admission_gate::"),
    ("experiments.rs", "admission_gate::"),
    ("assets.rs", "admission_gate::"),
    ("debug.rs", "admission_gate::"),
    ("agents.rs", "intelligence_authority::require_lifecycle_transition"),
    ("admission.rs", "pub fn check"),
    ("workload_profile.rs", "assert_start_allowed"),
    ("harden_posture.rs", "assert_harden_ready_for_start"),
];

/// Routes with admission wired (documentation + CI anchor).
pub const WIRED_EFFECT_ROUTES: &[(&str, &str, &str)] = &[
    ("POST", "/agents/:pid/start", "agents::start_agent + intelligence_authority"),
    ("POST", "/agents/:pid/pause", "agents::pause_agent + intelligence_authority"),
    ("POST", "/agents/:pid/resume", "agents::resume_agent + intelligence_authority"),
    ("POST", "/agents/:pid/quarantine", "agents::quarantine_agent_endpoint"),
    ("POST", "/agents/:pid/unquarantine", "agents::unquarantine_agent_endpoint + HITL"),
    ("POST", "/agents/:pid/signal", "agents::send_agent_signal + intelligence_authority"),
    ("POST", "/v1/chat/completions", "gateway::chat_completions"),
    ("POST", "/memory/write", "memory::write_memory"),
    ("POST", "/memory/knowledge/ingest", "memory::knowledge_ingest"),
    ("POST", "/memory/graph/entity", "memory2::add_graph_entity"),
    ("POST", "/memory/graph/edge", "memory2::add_graph_edge"),
    ("POST", "/memory/knowledge/compile", "memory2::knowledge_compile"),
    ("POST", "/memory/graph/seed", "memory2::load_knowledge_seed"),
    ("POST", "/memory/sessions", "memory2::create_session"),
    ("POST", "/agents/:pid/memory/import", "memory2::agent_memory_import"),
    ("POST", "/agents/:pid/memory/purge", "memory2::agent_memory_purge"),
    ("POST", "/agents/:pid/memory/compact", "memory2::agent_memory_compact"),
    ("POST", "/tools/mcp/register", "tools::mcp_register"),
    ("POST", "/tools/mcp/invoke", "tools::dispatch_mcp_tool_core"),
    ("PUT/POST", "/memory/objects", "object_fabric::*"),
    ("POST", "/memory/objects/multipart/complete", "object_fabric::multipart_complete"),
    ("POST", "/multiagent/pipeline", "multiagent::run_pipeline"),
    ("POST", "/multiagent/grant", "multiagent::grant_access"),
    ("POST", "/multiagent/revoke", "multiagent::revoke_access"),
    ("POST", "/multiagent/pipelines/:pipeline_id/approve-step/:step", "multiagent::approve_step"),
    ("POST", "/memory/optimize-context/:agent_pid", "memory::optimize_context"),
    ("POST", "/memory/consolidate/:agent_pid", "memory::consolidate"),
    ("POST", "/memory/tier/change", "memory::tier_change"),
    ("POST", "/assets/containers/:id/upload", "assets::upload_asset"),
    ("POST", "/assets/ingest", "assets::ingest_assets"),
    ("POST", "/protocols/mcp/discover", "protocols::mcp_discover"),
    ("POST", "/protocols/mcp/call", "protocols::mcp_call_tool"),
    ("POST", "/protocols/mcp/handle", "protocols::mcp_handle"),
    ("POST", "/experiments/:experiment_id/run", "experiments::run_experiment"),
    ("POST", "/debug/agents/:agent_pid/restore", "debug::agent_restore"),
    ("GET", "/debug/agents/:agent_pid/snapshot", "debug::agent_snapshot"),
    ("GET", "/runtime/security-profile", "workload_profile::get_profile"),
    ("POST", "/runtime/security-profile", "workload_profile::set_profile"),
    ("GET", "/node/contract", "node_contract::get_node_contract"),
];

pub fn admission_matrix_json() -> Value {
    json!({
        "schema": "admission_matrix.v1",
        "critical_handlers": CRITICAL_HANDLERS.iter().map(|(f, gate)| {
            json!({ "file": f, "gate_pattern": gate })
        }).collect::<Vec<_>>(),
        "wired_effect_routes": WIRED_EFFECT_ROUTES.iter().map(|(method, path, handler)| {
            json!({ "method": method, "path": path, "handler": handler })
        }).collect::<Vec<_>>(),
        "wired_count": WIRED_EFFECT_ROUTES.len(),
        "inventory_wired_routes": WIRED_EFFECT_ROUTES.len(),
        "inventory_script": "scripts/audit-route-admission-inventory.py",
        "inventory_note": "Full route inventory: docs/architecture/route-security-inventory.json",
        "human_doc": "docs/architecture/admission-matrix.md",
        "workload_profile": "substrate::workload_profile",
        "node_contract": "substrate::node_contract",
        "inventory_complete": true,
        "agentgateway": "TARGET",
        "spine": "closed",
        "honesty": "Operator API mutating methods and plugin-cage mutations close one PATE task or are refused before execution. Declared non-effects admit nothing. Ask stays open and the handler does not run. production_ready stays live evidence. effect_mediated stays per effect. agentgateway ext-auth denies forwarding. This is not Connector Ready.",
        "production_standard": {
            "claim": "each Connector-managed external effect traverses one PATE task or is refused before execution",
            "inventory_complete": true,
            "production_ready": false,
            "effect_mediated": "per_effect",
            "connector_ready": false,
            "agentgateway": "TARGET"
        },
        "not_effects": [
            {"method": "PUT", "path": "/agents/:pid/character", "admits": false},
            {"method": "POST", "path": "/agents/:pid/directives", "admits": false},
            {"method": "POST", "path": "/agents/:pid/aliases", "admits": false},
            {"method": "DELETE", "path": "/tools/mcp/bridges/:bridge_id", "admits": false}
        ],
        "outside_spine": [
            "agentgateway forwarding"
        ],
        "spine_closed_routes": [
            "memory write",
            "memory optimize",
            "memory tier change",
            "memory consolidate",
            "memory share",
            "memory purge",
            "memory compact",
            "memory import",
            "memory session create",
            "memory session close",
            "graph entity",
            "graph edge",
            "knowledge seed",
            "knowledge compile",
            "knowledge ingest",
            "asset upload",
            "asset ingest",
            "agent start",
            "agent pause",
            "agent resume",
            "agent quarantine",
            "agent unquarantine",
            "agent signal",
            "agent cease",
            "agent terminate",
            "agent terminate all",
            "debug restore",
            "object fabric json put",
            "object fabric byte put",
            "object fabric multipart complete",
            "MCP dispatch including an early return",
            "MCP register",
            "MCP discover",
            "MCP handle tools/call",
            "MCP protocol call",
            "multiagent grant",
            "multiagent revoke",
            "multiagent pipeline",
            "multiagent approve step",
            "experiment run",
            "memory packet pin",
            "memory packet unpin",
            "security profile set",
            "chat completions",
            "chat completions stream",
            "anthropic messages",
            "agent update",
            "agent budget reset",
            "agent budget update",
            "agent clearance",
            "agent register",
            "runtime policy update",
            "runtime mode set",
            "node activation",
            "isolation runtime set",
            "pilot create",
            "pilot revoke",
            "pilot extend",
            "pilot scope update",
            "agent setup",
            "agent activate",
            "llm providers set",
            "llm routing rules set",
            "llm overrides set",
            "llm guardrails set",
            "llm privacy tags set",
            "llm link",
            "prompt create",
            "prompt version add",
            "prompt version approve",
            "prompt version activate",
            "prompt rollback activate",
            "prompt retire",
            "webhook register",
            "webhook update",
            "webhook retire",
            "plugin lifecycle",
            "workspace file save",
            "workspace file remove",
            "workspace git commit",
            "workspace git push",
            "notification cancel",
            "workbench session create",
            "chat thread create",
            "plugin settings",
            "webhook retry enqueue",
            "devguard session start",
            "devguard session end",
            "api key create",
            "knowledge boundary put",
            "knowledge boundary harden",
            "team create",
            "team member add",
            "team role update",
            "team action log",
            "dal turn",
            "playground session end",
            "analytics event",
            "package register",
            "package install",
            "package bind",
            "package lifecycle",
            "rollup policy put",
            "rollup aging pass",
            "rollup scheduled pass",
            "rollup rehydrate",
            "rollup fade lock",
            "agent kill",
            "operator stop",
            "agent freeze",
            "agent thaw",
            "devguard token revoke",
            "notification scan",
            "council mint",
            "council floor",
            "council member add",
            "council close",
            "agent reset",
            "trust level",
            "reflection",
            "agent migrate",
            "hitl create",
            "hitl approve",
            "hitl deny",
            "mission create",
            "mission resume",
            "mission step",
            "mission complete",
            "mission cancel",
            "agent task assign",
            "alert rule create",
            "alert rule update",
            "alert rule retire",
            "slo create",
            "experiment create",
            "dataset create",
            "experiment promote",
            "history archive",
            "tool approve",
            "tool deny",
            "action record",
            "work proof",
            "pipeline definition",
            "pipeline artifact",
            "gate policy",
            "kecs health sweep",
            "agent notice",
            "breaker configure",
            "event handler",
            "channel open",
            "channel send",
            "cgroup register",
            "world root",
            "world address",
            "world grant",
            "world grant revoke",
            "decision record",
            "decision record v2",
            "decision bundle",
            "browser page"
        ],
        "target": "100% mutating external-effect paths gated before dispatch",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn critical_handlers_contain_admission_gate() {
        for (file, needle) in CRITICAL_HANDLERS {
            let root = env!("CARGO_MANIFEST_DIR");
            let path = [format!("{root}/src/services/{file}"), format!("{root}/src/substrate/{file}")]
                .into_iter()
                .find(|candidate| std::path::Path::new(candidate).is_file())
                .unwrap_or_else(|| panic!("{file} is not under src/services or src/substrate"));
            let content = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("read {path}: {e}"));
            assert!(
                content.contains(needle),
                "{file} must contain `{needle}` for admission gate"
            );
        }
    }

    #[test]
    fn wired_route_count_meets_minimum() {
        assert!(
            WIRED_EFFECT_ROUTES.len() >= 16,
            "admission wired routes should cover core effect paths"
        );
    }

    #[test]
    fn wired_routes_declared_in_route_inventory() {
        let inv_path = format!(
            "{}/../../docs/architecture/route-security-inventory.json",
            env!("CARGO_MANIFEST_DIR")
        );
        let raw = std::fs::read_to_string(&inv_path)
            .unwrap_or_else(|e| panic!("read inventory {inv_path}: {e}"));
        let doc: serde_json::Value =
            serde_json::from_str(&raw).expect("route-security-inventory.json must parse");

        let routes = doc
            .get("routes")
            .and_then(|v| v.as_array())
            .expect("routes array");

        for (method_spec, path, _handler) in WIRED_EFFECT_ROUTES {
            let methods: Vec<&str> = method_spec.split('/').collect();
            let mut found = false;
            for r in routes {
                if r.get("path").and_then(|p| p.as_str()) != Some(path) {
                    continue;
                }
                let route_methods: Vec<&str> = r
                    .get("methods")
                    .and_then(|m| m.as_array())
                    .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
                    .unwrap_or_default();
                if methods.iter().any(|m| route_methods.contains(m)) {
                    assert_eq!(
                        r.get("admission_operation").and_then(|v| v.as_str()),
                        Some("required"),
                        "inventory admission for {method_spec} {path}"
                    );
                    found = true;
                    break;
                }
            }
            assert!(found, "inventory missing wired route {method_spec} {path}");
        }
    }
}

//! Per-deployment plugin enablement (`CONNECTOR_PLUGINS_ENABLED`).
//!
//! One operator UI can ship everywhere; this matrix hides API routes and drives the hub so teams
//! only see plugins that are actually part of their bundle (e.g. DevGuard-only, TraceTramp-only).

use std::collections::HashSet;
use std::sync::OnceLock;

/// Stable ids for first-party connector plugins (gated routes + hub cards).
pub const KNOWN_PLUGINS: &[&str] = &["devguard", "tracetramp", "witnessctl"];

static ENABLED_CACHE: OnceLock<HashSet<String>> = OnceLock::new();

fn parse_enabled_list(raw: &str) -> HashSet<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("all") || trimmed == "*" {
        return KNOWN_PLUGINS.iter().map(|s| (*s).to_string()).collect();
    }
    let mut set = HashSet::new();
    for part in trimmed.split(',') {
        let p = part.trim().to_ascii_lowercase();
        if p.is_empty() {
            continue;
        }
        if KNOWN_PLUGINS.contains(&p.as_str()) {
            set.insert(p);
        } else {
            tracing::warn!(
                plugin_id = %p,
                "CONNECTOR_PLUGINS_ENABLED: unknown plugin id ignored (expected devguard, tracetramp, witnessctl)"
            );
        }
    }
    if set.is_empty() {
        tracing::warn!(
            "CONNECTOR_PLUGINS_ENABLED produced no valid ids; enabling all known plugins"
        );
        return KNOWN_PLUGINS.iter().map(|s| (*s).to_string()).collect();
    }
    set
}

fn load_enabled_from_env() -> HashSet<String> {
    parse_enabled_list(&std::env::var("CONNECTOR_PLUGINS_ENABLED").unwrap_or_default())
}

/// Plugin ids enabled for this process (comma list from env, or all if unset).
pub fn enabled_plugin_ids() -> &'static HashSet<String> {
    ENABLED_CACHE.get_or_init(load_enabled_from_env)
}

pub fn is_plugin_enabled(id: &str) -> bool {
    enabled_plugin_ids().contains(id)
}

pub fn is_gated_plugin_segment(seg: &str) -> bool {
    KNOWN_PLUGINS.contains(&seg)
}

#[derive(Clone, Copy, serde::Serialize)]
pub struct WorkflowCatalogEntry {
    pub id: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub required_plugins: &'static [&'static str],
}

/// Built-in workflow presets and which plugins they assume at runtime.
/// Custom workflows can be added later; entries with unmet `required_plugins` are omitted from
/// `workflows_for_deployment`.
pub const WORKFLOW_CATALOG: &[WorkflowCatalogEntry] = &[
    WorkflowCatalogEntry {
        id: "wf-governed-chat",
        title: "Governed chat",
        description: "LLM traffic through TraceTramp gateway with trace + policy hooks.",
        required_plugins: &["tracetramp"],
    },
    WorkflowCatalogEntry {
        id: "wf-approval-loop",
        title: "Human approval loop",
        description: "Queue risky tool calls for operator approve/reject in TraceTramp.",
        required_plugins: &["tracetramp"],
    },
    WorkflowCatalogEntry {
        id: "wf-evidence-export",
        title: "Evidence export",
        description: "Session compliance map and custody-friendly exports via WitnessCtl.",
        required_plugins: &["witnessctl"],
    },
    WorkflowCatalogEntry {
        id: "wf-hitl-compliance",
        title: "HITL compliance review",
        description: "WitnessCtl HITL queue plus management proxy.",
        required_plugins: &["witnessctl"],
    },
    WorkflowCatalogEntry {
        id: "wf-workspace-cage",
        title: "Workspace cage",
        description: "DevGuard policy + local profile for IDE and agent tool boundaries.",
        required_plugins: &["devguard"],
    },
    WorkflowCatalogEntry {
        id: "wf-trace-plus-witness",
        title: "Trace + witness bundle",
        description: "TraceTramp decisions mirrored into WitnessCtl evidence plane.",
        required_plugins: &["tracetramp", "witnessctl"],
    },
    WorkflowCatalogEntry {
        id: "wf-guard-plus-trace",
        title: "DevGuard + TraceTramp",
        description: "Workspace governance with gateway-traced model and tool calls.",
        required_plugins: &["devguard", "tracetramp"],
    },
    WorkflowCatalogEntry {
        id: "wf-full-stack-governance",
        title: "Full governance stack",
        description: "DevGuard, TraceTramp, and WitnessCtl together for maximum coverage.",
        required_plugins: &["devguard", "tracetramp", "witnessctl"],
    },
];

pub fn workflow_catalog() -> &'static [WorkflowCatalogEntry] {
    WORKFLOW_CATALOG
}

pub fn workflows_for_deployment() -> Vec<serde_json::Value> {
    WORKFLOW_CATALOG
        .iter()
        .filter(|w| w.required_plugins.iter().all(|p| is_plugin_enabled(p)))
        .map(|w| serde_json::to_value(w).unwrap_or(serde_json::Value::Null))
        .filter(|v| !v.is_null())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_subset_and_all() {
        let a = parse_enabled_list("devguard");
        assert_eq!(a.len(), 1);
        assert!(a.contains("devguard"));

        let b = parse_enabled_list("tracetramp, witnessctl");
        assert_eq!(b.len(), 2);

        let c = parse_enabled_list("ALL");
        assert_eq!(c.len(), KNOWN_PLUGINS.len());

        let d = parse_enabled_list("");
        assert_eq!(d.len(), KNOWN_PLUGINS.len());
    }

    #[test]
    fn workflow_filter_respects_matrix() {
        let tt_only = parse_enabled_list("tracetramp");
        let wf_ok =
            |w: &WorkflowCatalogEntry| w.required_plugins.iter().all(|p| tt_only.contains(*p));
        let available: Vec<_> = workflow_catalog().iter().filter(|w| wf_ok(w)).collect();
        assert!(available.iter().any(|w| w.id == "wf-governed-chat"));
        assert!(!available.iter().any(|w| w.id == "wf-evidence-export"));
    }
}

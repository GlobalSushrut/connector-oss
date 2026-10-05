//! E8 — Named escape hatches (env bypass flags) surfaced on posture / audit.
//!
//! Soft-fail and break-glass must never be invisible. Every hatch is listed with
//! whether it is currently active.

use serde_json::{json, Value};

fn env_on(key: &str) -> bool {
    std::env::var(key)
        .map(|v| {
            let t = v.trim().to_ascii_lowercase();
            matches!(t.as_str(), "1" | "true" | "yes" | "on")
        })
        .unwrap_or(false)
}

/// Canonical inventory of Connector escape / soft-fail / break-glass env flags.
pub fn inventory() -> Vec<Value> {
    let entries: &[(&str, &str, &str)] = &[
        (
            "CONNECTOR_DEV_AUTH_BYPASS",
            "auth",
            "Skip auth for lab break-glass",
        ),
        (
            "CONNECTOR_ALLOW_IN_PROCESS_EFFECTS",
            "effect",
            "Allow in-process effects outside cage",
        ),
        (
            "CONNECTOR_ALLOW_SUBPROCESS_ISOLATION",
            "isolation",
            "Permit subprocess isolation instead of microVM",
        ),
        (
            "CONNECTOR_ALLOW_ISOLATION_DOWNGRADE",
            "isolation",
            "Downgrade isolation tier at runtime",
        ),
        (
            "CONNECTOR_ALLOW_GUEST_EGRESS",
            "egress",
            "Permit guest egress when membrane would cut",
        ),
        (
            "CONNECTOR_HOST_MCP_BROKER",
            "tools",
            "Host MCP broker bypass path",
        ),
        (
            "CONNECTOR_LLM_STUB",
            "llm",
            "Stub LLM responses (no provider spend)",
        ),
        (
            "CONNECTOR_LLM_STUB_ALLOW_IN_PROD",
            "llm",
            "Keep LLM stub under production hardening",
        ),
        (
            "CONNECTOR_KERNEL_EGRESS_DEGRADED",
            "egress",
            "Operate without kerneld fail-closed helper",
        ),
        (
            "CONNECTOR_KERNEL_ENFORCE",
            "kernel",
            "When 0 under harden: kernel gates soft",
        ),
        (
            "CONNECTOR_DISTRIBUTED_ALLOW_INSECURE_TLS",
            "tls",
            "Allow insecure TLS for distributed peers (lab)",
        ),
        (
            "CONNECTOR_CAPS_ALLOW_MOCK",
            "caps",
            "Mock capability runners",
        ),
        (
            "CONNECTOR_PLAYGROUND",
            "profile",
            "Playground session / LAB mode",
        ),
        (
            "CONNECTOR_ARC_GOVERNOR",
            "arc",
            "ARC Agency Governor façade (Phase B+; off = no behavior change)",
        ),
        (
            "CONNECTOR_ARC_HARDEN",
            "arc",
            "ARC Soft→Harden: require CONNECTOR_ARC_GOVERNOR=1 or deny effects (B4)",
        ),
        (
            "CONNECTOR_ARC_LEASE",
            "arc",
            "Require ConsequenceLease at wired sinks (Phase C+)",
        ),
        (
            "CONNECTOR_ARC_IFC",
            "arc",
            "ARC three-algebra IFC gate (Phase D+)",
        ),
        (
            "CONNECTOR_ARC_AVSOCK",
            "arc",
            "A-VSOCK framed agency IPC (Phase F+; not the security boundary)",
        ),
        (
            "CONNECTOR_ARC_SCHEDULER",
            "arc",
            "Agency ScheduleHint only — never Admit",
        ),
        (
            "CONNECTOR_ARC_MEMORY",
            "arc",
            "ARC memory class ABI — Secret tokenize + Evidence append-only (Phase H)",
        ),
        (
            "CONNECTOR_ARC_DURABLE",
            "arc",
            "Persist WorldlineCommit — JSONL Soft or COPG redb when STORE=copg",
        ),
        (
            "CONNECTOR_ARC_STORE",
            "arc",
            "ARC durable backend: jsonl (Soft) | copg (redb graph + SQL-ish)",
        ),
    ];
    entries
        .iter()
        .map(|(key, class, detail)| {
            json!({
                "env": key,
                "class": class,
                "detail": detail,
                "active": env_on(key),
            })
        })
        .collect()
}

pub fn posture_json() -> Value {
    let hatches = inventory();
    let active: Vec<&str> = hatches
        .iter()
        .filter(|h| h.get("active").and_then(|v| v.as_bool()) == Some(true))
        .filter_map(|h| h.get("env").and_then(|v| v.as_str()))
        .collect();
    json!({
        "schema": "connector.escape_hatches.v1",
        "hatches": hatches,
        "active_count": active.len(),
        "active": active,
        "honesty": "Active escape hatches imply LAB or break-glass — never silent production membrane",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inventory_nonempty_and_named() {
        let inv = inventory();
        assert!(inv.len() >= 8);
        assert!(inv.iter().any(|h| h.get("env").and_then(|v| v.as_str())
            == Some("CONNECTOR_DEV_AUTH_BYPASS")));
    }
}

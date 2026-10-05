//! Expometer — one operator snapshot: authority (cease/quarantine/block) +
//! world exposure + LLM behavior. Built so BankOps / Talk demos have a place
//! to *see* whether admit is live or dead.

use serde_json::{json, Value};

use crate::state::SharedState;
use crate::substrate::llm_context_broker;
use crate::substrate::spend_cease;

/// Aggregate live authority + exposure for one agent.
pub fn snapshot(state: &SharedState, agent_pid: &str) -> Value {
    let pid = agent_pid.trim();
    if pid.is_empty() {
        return json!({ "ok": false, "error": "agent_pid_required", "status": 400 });
    }

    let burn = spend_cease::burn_meter(state, pid);
    let ceased = burn
        .get("latest_cease")
        .map(|x| !x.is_null())
        .unwrap_or(false);
    let inflight = burn
        .get("inflight_count")
        .and_then(|x| x.as_u64())
        .unwrap_or(0);
    let gen = burn
        .get("generation_id")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();

    let control = crate::services::intelligence_authority::load_agent_control(state, pid);
    let grants = crate::kernel::world_gateway::list_grants(state.as_ref(), Some(pid));
    let grant_summaries: Vec<Value> = grants
        .iter()
        .take(24)
        .map(|g| {
            json!({
                "address": g.get("address").cloned().unwrap_or(Value::Null),
                "effect": g.get("effect").cloned().unwrap_or(Value::Null),
                "access": g.get("access").cloned().unwrap_or(Value::Null),
                "address_type": g.get("address_type").cloned().unwrap_or(Value::Null),
            })
        })
        .collect();

    let isolation = crate::kernel::isolation_tiers::isolation_for_agent(state.as_ref(), pid);
    let broker = llm_context_broker::status();
    let live_gen = llm_context_broker::current_generation(state, pid);

    let llm_stub = std::env::var("CONNECTOR_LLM_STUB")
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false);

    // Tenant-linked router (if any) — redacted. Empty headers: playground
    // resolves tenant from agent_meta.
    let headers = axum::http::HeaderMap::new();
    let linked = crate::services::settings_llms::talk_llm_wired(state, &headers, pid);

    let mut flags = Vec::new();
    if control.quarantined {
        flags.push("QUARANTINED");
    }
    if ceased {
        flags.push("CEASED");
    }
    if control.paused {
        flags.push("PAUSED");
    }
    if control.egress_isolated {
        flags.push("EGRESS_CUT");
    }
    if blocked_post_cease_retries(state, pid) {
        flags.push("POST_CEASE_RETRY");
    }

    let admit = if control.quarantined {
        "REFUSED_QUARANTINE"
    } else if ceased {
        "REFUSED_GENERATION_FENCED"
    } else if control.paused {
        "REFUSED_PAUSED"
    } else {
        "LIVE"
    };

    let verdict = if control.quarantined {
        "quarantined"
    } else if ceased {
        "ceased"
    } else if control.paused {
        "paused"
    } else if control.egress_isolated {
        "egress_isolated"
    } else {
        "active"
    };

    json!({
        "ok": true,
        "schema": "connector.expometer.v1",
        "agent_pid": pid,
        "verdict": verdict,
        "flags": flags,
        "authority": {
            "admit": admit,
            "ceased": ceased,
            "quarantined": control.quarantined,
            "paused": control.paused,
            "egress_isolated": control.egress_isolated,
            "quarantine_reason": control.quarantine_reason,
            "quarantine_hitl_id": control.quarantine_hitl_id,
            "generation_id": gen,
            "broker_generation": live_gen,
            "latest_cease": burn.get("latest_cease").cloned().unwrap_or(Value::Null),
            "inflight_llm": inflight,
            "honesty": "Admit is law. After Cease/quarantine, new hops through this fence refuse — cancel tax may remain on already-started provider work.",
        },
        "spend": burn.get("burn").cloned().unwrap_or(Value::Null),
        "spend_hint": burn.get("hint").cloned().unwrap_or(Value::Null),
        "world": {
            "grant_count": grants.len(),
            "grants": grant_summaries,
            "honesty": "World grants = addresses this agent may touch after Admit. Empty ≠ no tools if MCP lane minted separately.",
        },
        "llm": {
            "mode": if linked { "linked_router" } else if llm_stub { "simulation_stub" } else { "unlinked" },
            "stub_env": llm_stub,
            "linked_router": linked,
            "broker": broker,
            "inflight_count": inflight,
            "honesty": "simulation_stub = CONNECTOR_LLM_STUB canned replies until a tenant links a key.",
        },
        "isolation": isolation,
        "updated_at_ms": chrono::Utc::now().timestamp_millis(),
    })
}

fn blocked_post_cease_retries(state: &SharedState, agent_pid: &str) -> bool {
    let Ok(es) = state.engine_store.lock() else {
        return false;
    };
    es.folder_get("spend_cease_retries_v1", agent_pid)
        .ok()
        .flatten()
        .and_then(|v| v.get("count").and_then(|c| c.as_u64()))
        .map(|n| n > 0)
        .unwrap_or(false)
}

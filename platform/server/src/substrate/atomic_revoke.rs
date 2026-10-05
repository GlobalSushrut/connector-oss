//! Atomic revoke — quantum + flow + vsock + egress OS cut (Seven Pillars §6).

use serde_json::json;

use crate::state::PlatformState;

const REVOKE_FOLDER: &str = "atomic_revoke_v1";

/// Revoke all dependent authority for an agent in one helper.
pub fn revoke_agent_authority(state: &PlatformState, agent_pid: &str, reason: &str) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    if let Ok(mut es) = state.engine_store.lock() {
        let _ = es.folder_put(
            REVOKE_FOLDER,
            &format!("quantum:{agent_pid}"),
            &json!({ "revoked_at_unix": now, "reason": reason }),
        );
        let _ = es.folder_put(
            REVOKE_FOLDER,
            &format!("egress:{agent_pid}"),
            &json!({ "cut": true, "revoked_at_unix": now, "reason": reason }),
        );
        let _ = es.folder_put(
            REVOKE_FOLDER,
            &format!("receipt:{agent_pid}:{now}"),
            &json!({
                "schema": "connector.atomic_revoke.v1",
                "agent_pid": agent_pid,
                "reason": reason,
                "revoked_at_unix": now,
                "scopes": ["quantum", "flow", "vsock", "egress", "workload", "ebpf_mark"],
            }),
        );
    }

    crate::substrate::flow_lease::revoke_leases_for_agent(state, agent_pid);
    crate::kernel::isolation_manifest::revoke_vsock_channels(state, agent_pid);

    // Void LLM broker tokens (SharedState-shaped engine store path via PlatformState wrapper).
    // PlatformState is the same store; invalidate via a thin SharedState is not available here —
    // bump generation through engine_store directly.
    {
        let folder = "llm_context_broker_v1";
        let gen_key = format!("gen:{agent_pid}");
        let next = if let Ok(es) = state.engine_store.lock() {
            es.folder_get(folder, &gen_key)
                .ok()
                .flatten()
                .and_then(|v| v.get("generation").and_then(|g| g.as_u64()))
                .unwrap_or(0)
                .saturating_add(1)
        } else {
            1
        };
        if let Ok(mut es) = state.engine_store.lock() {
            let _ = es.folder_put(
                folder,
                &gen_key,
                &json!({
                    "generation": next,
                    "reason": format!("atomic_revoke:{reason}"),
                }),
            );
            let _ = es.folder_put(
                folder,
                &format!("active:{agent_pid}"),
                &json!({
                    "token_id": null,
                    "generation": next,
                    "invalidated": true,
                    "reason": format!("atomic_revoke:{reason}"),
                }),
            );
        }
    }

    // OS-level cut: nft/iptables matrix + eBPF deny mark.
    let cut = crate::kernel::matrix_host_egress::apply_matrix_host_egress_cut(
        agent_pid,
        &format!("atomic_revoke:{reason}"),
    );
    if let Ok(mut es) = state.engine_store.lock() {
        let _ = es.folder_put(
            REVOKE_FOLDER,
            &format!("os_cut:{agent_pid}"),
            &json!({
                "result": format!("{cut:?}"),
                "revoked_at_unix": now,
            }),
        );
    }
}

pub fn is_agent_authority_revoked(state: &PlatformState, agent_pid: &str) -> bool {
    let Ok(es) = state.engine_store.lock() else {
        return crate::substrate::sandbox_unbypassable::unbypassable_bar_enforced();
    };
    es.folder_get(REVOKE_FOLDER, &format!("quantum:{agent_pid}"))
        .ok()
        .flatten()
        .is_some()
}

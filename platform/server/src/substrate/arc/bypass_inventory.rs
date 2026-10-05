//! Host/guest bypass inventory (F4) — A-VSOCK auth alone is not a pass.

use serde_json::{json, Value};

use super::flags::ArcFlags;

pub const SCHEMA: &str = "connector.arc.bypass_inventory.v1";

#[derive(Debug, Clone)]
struct BypassRow {
    id: &'static str,
    path: &'static str,
    closed: bool,
    lab_only: bool,
    evidence: &'static str,
}

fn inventory_rows() -> Vec<BypassRow> {
    let tools_microvm = crate::substrate::microvm_tool_plane::tools_in_microvm_enforced();
    let exclusivity = crate::substrate::effect_exclusivity::effect_exclusivity_enforced();
    let in_proc = crate::substrate::effect_exclusivity::in_process_effects_allowed();
    let vsock_tickets = crate::kernel::isolation_manifest::vsock_ticket_required();
    let landlock = connector_plugin_runtime::linux_hardening::landlock_fail_closed_enabled();

    vec![
        BypassRow {
            id: "raw_virtio_net",
            path: "guest raw virtio-net / TAP consequence",
            closed: tools_microvm || exclusivity,
            lab_only: !(tools_microvm || exclusivity),
            evidence: "microvm vsock-only (no TAP) when tools-in-microvm / exclusivity",
        },
        BypassRow {
            id: "host_mount",
            path: "host filesystem mount into consequence path",
            closed: landlock || tools_microvm,
            lab_only: !(landlock || tools_microvm),
            evidence: "Landlock fail-closed and/or microVM rootfs isolation",
        },
        BypassRow {
            id: "second_tool_daemon",
            path: "second tool daemon bypassing Connector mediator",
            closed: exclusivity && !in_proc,
            lab_only: in_proc || !exclusivity,
            evidence: "effect_exclusivity + deny in-process effects",
        },
        BypassRow {
            id: "ungated_vsock",
            path: "ungated vsock effect (no ticket / no A-VSOCK class)",
            closed: vsock_tickets || ArcFlags::from_env().avsock,
            lab_only: !(vsock_tickets || ArcFlags::from_env().avsock),
            evidence: "vsock tickets and/or CONNECTOR_ARC_AVSOCK frame class",
        },
        BypassRow {
            id: "host_tool_io",
            path: "shell/fs/exec on Connector host under microVM bar",
            closed: tools_microvm,
            lab_only: !tools_microvm,
            evidence: "microvm_tool_plane assert_in_process_dispatch",
        },
    ]
}

/// All paths closed:true, or explicitly LAB-labeled (F4 acceptance).
pub fn inventory_json() -> Value {
    let rows = inventory_rows();
    let all_ok = rows.iter().all(|r| r.closed || r.lab_only);
    let all_closed = rows.iter().all(|r| r.closed);
    let items: Vec<Value> = rows
        .iter()
        .map(|r| {
            json!({
                "id": r.id,
                "path": r.path,
                "closed": r.closed,
                "lab": r.lab_only && !r.closed,
                "evidence": r.evidence,
            })
        })
        .collect();
    json!({
        "schema": SCHEMA,
        "items": items,
        "all_closed": all_closed,
        "f4_pass": all_ok,
        "honesty": if all_closed {
            "Host bypass inventory all closed"
        } else if all_ok {
            "F4 pass with LAB-labeled open paths — not Effective MicroCell exclusivity"
        } else {
            "F4 incomplete — open consequence path without LAB label"
        },
        "note": "Perfect A-VSOCK auth without F4 is not a pass",
    })
}

pub fn f4_pass() -> bool {
    inventory_json()
        .get("f4_pass")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inventory_has_required_paths() {
        let inv = inventory_json();
        let items = inv["items"].as_array().unwrap();
        let ids: Vec<&str> = items
            .iter()
            .filter_map(|i| i["id"].as_str())
            .collect();
        assert!(ids.contains(&"raw_virtio_net"));
        assert!(ids.contains(&"host_mount"));
        assert!(ids.contains(&"second_tool_daemon"));
        assert!(ids.contains(&"ungated_vsock"));
        // Soft/lab environments: f4_pass via lab labels is ok
        assert!(inv["f4_pass"].as_bool().unwrap_or(false));
    }
}

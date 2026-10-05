//! Egress + kerneld operator surface (I-21 partial).

use axum::extract::State;
use axum::Json;
use serde_json::{json, Value};

use crate::{operator::honesty::operator_envelope, services::kernel_host, state::SharedState};

/// `GET /api/v1/runtime/egress/status`
pub async fn get_egress_status(State(state): State<SharedState>) -> Json<Value> {
    let kernel_enforce = kernel_host::kernel_enforce_enabled();
    let host_snap = state
        .kernel_host
        .lock()
        .ok()
        .map(|h| h.snapshot_json())
        .unwrap_or(Value::Null);
    let kerneld_agent = std::env::var("CONNECTOR_KERNELD_AGENT_PID").ok();
    let kerneld_url = std::env::var("CONNECTOR_PLATFORM_URL")
        .or_else(|_| std::env::var("CONNECTOR_TEST_URL"))
        .unwrap_or_else(|_| "http://127.0.0.1:9735".into());
    let flow_lease = crate::substrate::flow_lease::lease_snapshot(state.as_ref());
    // Deny-path stub probe (no flow_id) — surfaces honesty when enforce is on.
    let deny_probe = crate::substrate::flow_lease::require_active_flow_lease(state.as_ref(), None)
        .err()
        .unwrap_or_else(|| {
            json!({
                "ok": true,
                "enforce": crate::substrate::flow_lease::enforce_display(),
                "note": "enforce off — deny stub not engaged",
            })
        });
    let destination_probe = crate::substrate::flow_lease::require_matching_destination_lease(
        state.as_ref(),
        Some("example.invalid"),
        None,
        Some(443),
        Some("tcp"),
    )
    .err()
    .unwrap_or_else(|| {
        json!({
            "ok": true,
            "note": "matching destination lease present or enforce off",
        })
    });
    Json(operator_envelope(json!({
        "schema": "runtime_egress_status.v1",
        "kernel_host_enforce": kernel_enforce,
        "kernel_host_snapshot": host_snap,
        "kerneld": {
            "binary": "connector-kerneld",
            "agent_pid_env": kerneld_agent,
            "platform_url": kerneld_url,
            "watch_hint": "connector-kerneld watch --agent <pid> --output /etc/systemd/system/connector-agent.service.d/egress.conf",
            "fail_closed_note": "Production should run kerneld watch + systemd IPAddressAllow= drop-ins",
            "honesty": "Kerneld still uses lease count for IPAddressDeny=any; destination matching is enforced in userspace proxy_plane / flow_lease",
        },
        "flow_lease_enforcement": crate::substrate::flow_lease::flow_lease_enforcement_enabled(),
        "flow_lease_enforce": crate::substrate::flow_lease::enforce_display(),
        "flow_lease": flow_lease,
        "flow_lease_deny_probe": deny_probe,
        "flow_lease_destination_probe": destination_probe,
        "proxy_plane": "substrate::proxy_plane — embedded route graph; Envoy deferred",
        "flow_lease_note": "Per-connect FNI/ticket map; enforce via CONNECTOR_FLOW_LEASE_ENFORCE (or KERNEL_ENFORCE) when map enabled",
        "microvm_egress_enforce": crate::services::phase5_operator_env::microvm_egress_enforce_label(),
        "docker_lab_egress_enforce": crate::services::phase5_operator_env::docker_lab_egress_enforce_label(),
        "l7_egress_proxy": crate::substrate::egress_policy::l7_egress_status(),
    })))
}

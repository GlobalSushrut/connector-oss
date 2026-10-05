//! Phase 1.8 — `GET /api/v1/health`: kernel monitor snapshot + first-party plugin reachability.

use axum::{extract::State, Json};
use serde_json::{json, Value};

use crate::state::SharedState;

fn devguard_configured() -> bool {
    crate::services::plugin_upstream_probe::devguard_management_url().is_some()
}

fn witnessctl_configured() -> bool {
    crate::services::plugin_upstream_probe::witnessctl_management_url().is_some()
}

fn plugin_status(id: &str, enabled: bool, configured: bool, upstream: Option<bool>) -> Value {
    let status = if !enabled {
        "disabled"
    } else if !configured {
        "unconfigured"
    } else if let Some(ok) = upstream {
        if ok {
            "ok"
        } else {
            "unreachable"
        }
    } else {
        "unknown"
    };
    json!({
        "id": id,
        "enabled_in_deployment": enabled,
        "configured": configured,
        "upstream_reachable": upstream,
        "status": status,
    })
}

fn rank_kernel(s: &str) -> u8 {
    match s {
        "critical" => 3,
        "degraded" => 2,
        "healthy" => 1,
        "production_ready" => 0,
        _ => 1,
    }
}

fn rank_plugin(enabled: bool, st: &str) -> u8 {
    if !enabled {
        return 0;
    }
    match st {
        "unreachable" => 3,
        "unconfigured" => 2,
        "unknown" => 1,
        "ok" => 0,
        "disabled" => 0,
        _ => 1,
    }
}

fn overall_label(kernel_status: &str, plugins: &[(bool, &str)]) -> &'static str {
    let mut r = rank_kernel(kernel_status);
    for (en, st) in plugins {
        r = r.max(rank_plugin(*en, st));
    }
    match r {
        0 | 1 => "ok",
        2 => "degraded",
        _ => "critical",
    }
}

/// Async rollup used by health checks and `.cpkg` install rollback (Phase 4.5).
pub async fn unified_overall_status(state: &SharedState) -> &'static str {
    let kernel = crate::services::monitor::kernel_health_snapshot(state);
    let kernel_status = kernel
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    let en_tt = crate::services::plugin_matrix::is_plugin_enabled("tracetramp");
    let en_wc = crate::services::plugin_matrix::is_plugin_enabled("witnessctl");
    let en_dg = crate::services::plugin_matrix::is_plugin_enabled("devguard");

    let tt_cfg = crate::services::tracetramp_proxy::tracetramp_management_plane_configured();
    let wc_cfg = witnessctl_configured();
    let dg_cfg = devguard_configured();

    let (tt_up, wc_up, dg_up) = tokio::join!(
        crate::services::tracetramp_proxy::tracetramp_upstream_reachable(),
        crate::services::plugin_upstream_probe::witnessctl_upstream_reachable(),
        crate::services::plugin_upstream_probe::devguard_upstream_reachable(),
    );

    let tracetramp = plugin_status("tracetramp", en_tt, tt_cfg, tt_up);
    let witnessctl = plugin_status("witnessctl", en_wc, wc_cfg, wc_up);
    let devguard = plugin_status("devguard", en_dg, dg_cfg, dg_up);

    let tt_st = tracetramp["status"].as_str().unwrap_or("unknown");
    let wc_st = witnessctl["status"].as_str().unwrap_or("unknown");
    let dg_st = devguard["status"].as_str().unwrap_or("unknown");

    overall_label(
        kernel_status,
        &[(en_tt, tt_st), (en_wc, wc_st), (en_dg, dg_st)],
    )
}

/// `GET /api/v1/health` — public rollup (same auth bypass list as `/health`).
pub async fn get_unified_health(State(state): State<SharedState>) -> Json<Value> {
    let kernel = crate::services::monitor::kernel_health_snapshot(&state);
    let kernel_status = kernel
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    let en_tt = crate::services::plugin_matrix::is_plugin_enabled("tracetramp");
    let en_wc = crate::services::plugin_matrix::is_plugin_enabled("witnessctl");
    let en_dg = crate::services::plugin_matrix::is_plugin_enabled("devguard");

    let tt_cfg = crate::services::tracetramp_proxy::tracetramp_management_plane_configured();
    let wc_cfg = witnessctl_configured();
    let dg_cfg = devguard_configured();

    let (tt_up, wc_up, dg_up) = tokio::join!(
        crate::services::tracetramp_proxy::tracetramp_upstream_reachable(),
        crate::services::plugin_upstream_probe::witnessctl_upstream_reachable(),
        crate::services::plugin_upstream_probe::devguard_upstream_reachable(),
    );

    let tracetramp = plugin_status("tracetramp", en_tt, tt_cfg, tt_up);
    let witnessctl = plugin_status("witnessctl", en_wc, wc_cfg, wc_up);
    let devguard = plugin_status("devguard", en_dg, dg_cfg, dg_up);

    let tt_st = tracetramp["status"].as_str().unwrap_or("unknown");
    let wc_st = witnessctl["status"].as_str().unwrap_or("unknown");
    let dg_st = devguard["status"].as_str().unwrap_or("unknown");

    let overall = overall_label(
        kernel_status,
        &[(en_tt, tt_st), (en_wc, wc_st), (en_dg, dg_st)],
    );

    Json(json!({
        "ok": true,
        "overall": {
            "status": overall,
            "kernel_status": kernel_status,
            "hint": "overall.status is max(kernel, enabled plugins). Disabled plugins are ignored."
        },
        "kernel": kernel,
        "plugins": {
            "tracetramp": tracetramp,
            "witnessctl": witnessctl,
            "devguard": devguard,
        },
        "links": {
            "kernel_detail": "/api/v1/monitor/health",
            "deployment_matrix": "/api/v1/plugins/status",
            "liveness": "/health"
        }
    }))
}

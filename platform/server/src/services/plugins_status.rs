//! Aggregate plugin status for `GET /api/v1/plugins/status` (dashboard hub + connectorctl).

use axum::{extract::State, Json};
use serde_json::json;

use crate::state::SharedState;

fn status_badge(installed: bool, enabled: bool, upstream_reachable: Option<bool>) -> &'static str {
    if !installed {
        return "not_installed";
    }
    if !enabled {
        return "disabled";
    }
    match upstream_reachable {
        Some(true) => "healthy",
        Some(false) => "degraded",
        None => "enabled",
    }
}

#[cfg(test)]
mod honesty_tests {
    use super::status_badge;

    #[test]
    fn local_profile_alone_cannot_make_status_badge_healthy() {
        // DG-08: without upstream reachability, badge stays "enabled", never "healthy".
        assert_eq!(status_badge(true, true, None), "enabled");
        assert_eq!(status_badge(true, true, Some(true)), "healthy");
        assert_eq!(status_badge(true, true, Some(false)), "degraded");
    }
}

fn lifecycle_actions(installed: bool, enabled: bool) -> Vec<&'static str> {
    if !installed {
        return vec!["install"];
    }
    let mut out = vec!["update", "uninstall"];
    if enabled {
        out.push("disable");
    } else {
        out.push("enable");
    }
    out
}

fn witnessctl_management_configured() -> bool {
    crate::services::plugin_upstream_probe::witnessctl_management_url().is_some()
}

fn devguard_management_configured() -> bool {
    crate::services::plugin_upstream_probe::devguard_management_url().is_some()
}

fn witnessctl_management_url_explicit() -> bool {
    std::env::var("CONNECTOR_WITNESSCTL_MANAGEMENT_URL")
        .or_else(|_| std::env::var("WITNESSCTL_MANAGEMENT_URL"))
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false)
}

fn devguard_management_url_explicit() -> bool {
    std::env::var("CONNECTOR_DEVGUARD_MANAGEMENT_URL")
        .or_else(|_| std::env::var("DEVGUARD_MANAGEMENT_URL"))
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false)
}

fn devguard_local_profile_saved(state: &SharedState) -> bool {
    let es = state.engine_store.lock().unwrap();
    es.folder_get("devguard_local_profile", "singleton")
        .ok()
        .flatten()
        .is_some()
}

fn phase5_hints(state: &SharedState, plugin_matrix_id: &str) -> serde_json::Value {
    serde_json::json!({
        "tier_scheduler": state.plugin_tier_scheduler.hint_json(plugin_matrix_id),
        "crash_recovery": state.plugin_crash_recovery.hint_json(plugin_matrix_id),
    })
}

/// Node-wide Phase 5 operator hints (same host env + persisted isolation runtime). Not secret.
fn phase5_operator_summary(state: &SharedState) -> serde_json::Value {
    let rt = *state.isolation_runtime.read().unwrap();
    json!({
        "isolation_runtime": rt.as_str(),
        "tier_idle_suspend_policy_after_ms": state.plugin_tier_scheduler.idle_suspend_policy_after_ms(),
        "docker_lab_egress": crate::services::phase5_operator_env::docker_lab_egress_mode_label(),
        "docker_lab_egress_enforce": crate::services::phase5_operator_env::docker_lab_egress_enforce_label(),
        "connectorctl_plugin_run_backend": crate::services::phase5_operator_env::connectorctl_plugin_run_backend_label(),
        "microvm_vendor_assets_configured": crate::services::phase5_operator_env::microvm_vendor_assets_configured(),
        "microvm_vm_agent_guest_path": crate::services::phase5_operator_env::microvm_vm_agent_guest_path_label(),
        "microvm_wsl_distro": crate::services::phase5_operator_env::microvm_wsl_distro_label(),
        "microvm_wsl_state_dir": crate::services::phase5_operator_env::microvm_wsl_state_dir_label(),
        "microvm_egress_mode": crate::services::phase5_operator_env::microvm_egress_mode_label(),
        "microvm_egress_enforce": crate::services::phase5_operator_env::microvm_egress_enforce_label(),
        "microvm_egress_enforce_required": crate::services::phase5_operator_env::microvm_egress_enforce_required_label(),
        "microvm_guest_iface": crate::services::phase5_operator_env::microvm_guest_iface_label(),
        "plugin_subprocess_cgroup_parent": crate::services::phase5_operator_env::plugin_subprocess_cgroup_parent_label(),
        "plugin_subprocess_cgroup_pids_max": crate::services::phase5_operator_env::plugin_subprocess_cgroup_pids_max_label(),
        "plugin_subprocess_cpu_weight": crate::services::phase5_operator_env::plugin_subprocess_cpu_weight_label(),
        "plugin_subprocess_memory_high_bytes": crate::services::phase5_operator_env::plugin_subprocess_memory_high_bytes_label(),
        "plugin_subprocess_memory_swap_max_bytes": crate::services::phase5_operator_env::plugin_subprocess_memory_swap_max_bytes_label(),
        "supervisor_node_crash_plugin_id": crate::services::phase5_operator_env::supervisor_node_crash_plugin_id_label(),
        "microvm_tier_state_file": crate::services::phase5_operator_env::microvm_tier_state_file_operator_label(),
        "microvm_tier_state_sync": crate::services::phase5_operator_env::microvm_tier_state_sync_operator_label(),
        "plugin_tier_cgroup_scan": crate::services::phase5_operator_env::plugin_tier_cgroup_scan_label(),
        "plugin_tier_cgroup_idle_demote": crate::services::phase5_operator_env::plugin_tier_cgroup_idle_demote_label(),
        "plugin_subprocess_seccomp": crate::services::phase5_operator_env::plugin_subprocess_seccomp_label(),
        "plugin_subprocess_seccomp_intent": crate::services::phase5_operator_env::plugin_subprocess_seccomp_intent_label_from_raw(
            &std::env::var("CONNECTOR_PLUGIN_SUBPROCESS_SECCOMP_INTENT").unwrap_or_default()
        ),
        "plugin_subprocess_seccomp_resolution": crate::services::phase5_operator_env::plugin_subprocess_seccomp_resolution(),
        "connect_connector_env": crate::services::phase5_operator_env::connect_connector_env_label(),
        "connect_env_production_like": crate::services::phase5_operator_env::connect_env_production_like(),
        "connect_dev_mode_truthy": crate::services::phase5_operator_env::connect_dev_mode_truthy(),
        "connect_production_reject_dev_mode_truthy": crate::services::phase5_operator_env::connect_production_reject_dev_mode_truthy(),
        "production_dev_mode_hygiene": crate::services::phase5_operator_env::production_dev_mode_hygiene_level(),
        "hint": "Persisted isolation_runtime is kernel policy; CONNECTOR_* vars apply to connectorctl + connector-plugin-runtime on this host (see GET /api/v1/runtime/isolation).",
    })
}

fn phase5_operator_with_warnings(state: &SharedState) -> serde_json::Value {
    let mut p5 = phase5_operator_summary(state);
    let warnings =
        crate::services::phase5_operator_env::phase5_preflight_warnings_from_operator(&p5);
    let warning_count = warnings.len();
    let warning_level =
        crate::services::phase5_operator_env::phase5_preflight_warning_level_from_warnings(
            &warnings,
        );
    let process_line = crate::phase5_operator_display::process_env_operator_display_line(&p5);
    if let Some(obj) = p5.as_object_mut() {
        obj.insert("preflight_warnings".into(), json!(warnings));
        obj.insert("preflight_warning_count".into(), json!(warning_count));
        obj.insert("preflight_warning_level".into(), json!(warning_level));
        if let Some(ref l) = process_line {
            obj.insert("process_env_operator_display_line".into(), json!(l));
        }
    }
    p5
}

/// `GET /api/v1/kernel/plugin-tier-scheduler` — aggregate tier scheduler state (all plugins).
pub async fn get_kernel_tier_scheduler(
    State(state): State<SharedState>,
) -> Json<serde_json::Value> {
    let sched = &state.plugin_tier_scheduler;
    let idle_ms = sched.idle_suspend_policy_after_ms();
    let util = sched.utilization_summary_json();
    let mv_sync = crate::services::phase5_operator_env::microvm_tier_state_sync_operator_label();
    Json(json!({
        "ok": true,
        "idle_suspend_policy_after_ms": idle_ms,
        "tier_idle_suspend_policy_ms_for_guest": idle_ms,
        "microvm_tier_state_sync": mv_sync,
        "utilization": util,
        "hint": "Aggregate tier scheduler snapshot across all tracked plugins. CLI: connectorctl tier show"
    }))
}

/// `GET /api/v1/plugins/service-map` — plugin dependency graph edges for the interactive UI.
pub async fn get_plugins_service_map(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let en_tt = crate::services::plugin_matrix::is_plugin_enabled("tracetramp");
    let en_dg = crate::services::plugin_matrix::is_plugin_enabled("devguard");
    let en_wc = crate::services::plugin_matrix::is_plugin_enabled("witnessctl");
    let cage = |slug: &str| crate::internal_dns::plugin_cage_hostname(slug);
    Json(json!({
        "ok": true,
        "schema": "plugins.service_map.v1",
        "cage_uri_stability": "docs/architecture/cage-uri-stability.md",
        "nodes": [
            {"id": "connector-platform", "kind": "core", "label": "Connector Platform", "status": "healthy"},
            {
                "id": "devguard",
                "kind": "plugin",
                "label": "DevGuard",
                "enabled": en_dg,
                "cage_host": cage("devguard"),
                "public_path": "/plugin/devguard",
                "stable_uri": true
            },
            {
                "id": "tracetramp",
                "kind": "plugin",
                "label": "TraceTramp",
                "enabled": en_tt,
                "cage_host": cage("tracetramp"),
                "public_path": "/plugin/tracetramp",
                "stable_uri": true
            },
            {
                "id": "witnessctl",
                "kind": "plugin",
                "label": "WitnessCtl",
                "enabled": en_wc,
                "cage_host": cage("witnessctl"),
                "public_path": "/plugin/witnessctl",
                "stable_uri": true
            },
            {"id": "kernel",             "kind": "kernel", "label": "Kernel",        "status": "healthy"},
            {"id": "policy-engine",      "kind": "kernel", "label": "Policy Engine", "status": "healthy"},
            {"id": "audit-chain",        "kind": "kernel", "label": "Audit Chain",   "status": "healthy"},
        ],
        "edges": [
            {"from": "connector-platform", "to": "kernel",        "kind": "depends"},
            {"from": "connector-platform", "to": "policy-engine", "kind": "depends"},
            {"from": "connector-platform", "to": "audit-chain",   "kind": "depends"},
            {"from": "devguard",           "to": "connector-platform", "kind": "plugin"},
            {"from": "tracetramp",         "to": "connector-platform", "kind": "plugin"},
            {"from": "witnessctl",         "to": "connector-platform", "kind": "plugin"},
            {"from": "devguard",           "to": "policy-engine",      "kind": "governed"},
            {"from": "devguard",           "to": "audit-chain",        "kind": "governed"},
        ],
        "honesty": "cage_host and public_path stay stable across isolation backend swap; see cage-uri-stability.md",
    }))
}

/// `GET /api/v1/plugins/status` — non-secret summary of which plugin control planes are wired.
pub async fn get_plugins_status(State(state): State<SharedState>) -> Json<serde_json::Value> {
    // Rehydrate UI-saved configure overlays after process restart.
    for id in ["tracetramp", "witnessctl", "devguard"] {
        crate::services::plugin_configure::hydrate_overlay_from_store(&state, id);
    }
    let tt = crate::services::tracetramp_proxy::tracetramp_management_plane_configured();
    let tt_url = crate::services::tracetramp_proxy::tracetramp_management_url_explicit();
    let tt_upstream = if tt {
        crate::services::tracetramp_proxy::tracetramp_upstream_reachable().await
    } else {
        None
    };

    let wc_cfg = witnessctl_management_configured();
    let wc_api = crate::services::witnessctl_proxy::witnessctl_api_proxy_configured();
    let wc_health = crate::services::witnessctl_proxy::witnessctl_health_proxy_configured();
    let dg_cfg = devguard_management_configured();
    let wc_upstream = if wc_cfg {
        crate::services::plugin_upstream_probe::witnessctl_upstream_reachable().await
    } else {
        None
    };
    let dg_upstream = if dg_cfg {
        crate::services::plugin_upstream_probe::devguard_upstream_reachable().await
    } else {
        None
    };
    let dg_local_saved = devguard_local_profile_saved(&state);

    let wc_host = crate::services::plugin_upstream_probe::witnessctl_management_url()
        .as_deref()
        .map(crate::services::plugin_upstream_probe::management_display_host);
    let dg_host = crate::services::plugin_upstream_probe::devguard_management_url()
        .as_deref()
        .map(crate::services::plugin_upstream_probe::management_display_host);

    let en_tt = crate::services::plugin_matrix::is_plugin_enabled("tracetramp");
    let en_dg = crate::services::plugin_matrix::is_plugin_enabled("devguard");
    let en_wc = crate::services::plugin_matrix::is_plugin_enabled("witnessctl");

    let cage_tt = crate::internal_dns::plugin_cage_hostname("tracetramp");
    let cage_dg = crate::internal_dns::plugin_cage_hostname("devguard");
    let cage_wc = crate::internal_dns::plugin_cage_hostname("witnessctl");
    let dns_tt = crate::internal_dns::resolve(&cage_tt).is_some();
    let dns_dg = crate::internal_dns::resolve(&cage_dg).is_some();
    let dns_wc = crate::internal_dns::resolve(&cage_wc).is_some();

    let enabled_ids: Vec<_> = crate::services::plugin_matrix::KNOWN_PLUGINS
        .iter()
        .filter(|id| crate::services::plugin_matrix::is_plugin_enabled(id))
        .copied()
        .collect();

    let workflows = crate::services::plugin_matrix::workflows_for_deployment();
    let lf_tt =
        crate::services::plugin_lifecycle::load_plugin_lifecycle_state(&state, "tracetramp");
    let lf_dg = crate::services::plugin_lifecycle::load_plugin_lifecycle_state(&state, "devguard");
    let lf_wc =
        crate::services::plugin_lifecycle::load_plugin_lifecycle_state(&state, "witnessctl");
    // Playground DevGuard is in-process (no sidecar). That is a measured product
    // path — not the local-profile shortcut DG-08 forbids.
    let dg_health = if dg_upstream.is_some() {
        dg_upstream
    } else if crate::services::playground::is_playground_mode()
        && en_dg
        && lf_dg.installed
        && lf_dg.enabled
    {
        Some(true)
    } else {
        dg_upstream
    };

    Json(json!({
        "ok": true,
        "deployment": {
            "enabled_plugin_ids": enabled_ids,
            "env_var": "CONNECTOR_PLUGINS_ENABLED",
            "hint": "Comma-separated subset: devguard, tracetramp, witnessctl. Empty, \"all\", or \"*\" keeps all plugins enabled (default). Unknown ids are ignored.",
            "cage_tld": crate::internal_dns::cage_tld(),
            "hint_cage": "Internal DNS registers <slug>.<cage_tld> for enabled plugins. Public reverse proxy: GET/POST /plugin/<slug>/… (same auth as /api/v1). Configure TLD via connector.yaml connector.cage_tld or CONNECTOR_CAGE_TLD."
        },
        "workflows": {
            "available_in_deployment": workflows,
            "hint": "Each preset lists required_plugins; only workflows whose requirements are met appear here. Custom workflows can extend the same contract later."
        },
        "phase_5_operator": phase5_operator_with_warnings(&state),
        "plugins": {
            "tracetramp": {
                "id": "tracetramp",
                "enabled_in_deployment": en_tt,
                "phase_5": phase5_hints(&state, "tracetramp"),
                "status_badge": status_badge(lf_tt.installed, lf_tt.enabled, tt_upstream),
                "lifecycle": lf_tt,
                "actions": lifecycle_actions(lf_tt.installed, lf_tt.enabled),
                "cage_host": cage_tt,
                "cage_internal_dns_registered": dns_tt,
                "public_plugin_proxy_prefix": "/plugin/tracetramp",
                "dashboard_path": "/plugins/tracetramp",
                "configured": tt,
                "management_url_explicit": tt_url,
                "default_base": crate::services::tracetramp_proxy::default_tt_base(),
                "upstream_reachable": tt_upstream,
                "hint": "This flag is for the connector-platform process only: set CONNECTOR_TRACETRAMP_ADMIN_TOKEN (same value as TraceTramp TRACETRAMP_ADMIN_TOKEN) and optionally CONNECTOR_TRACETRAMP_MANAGEMENT_URL. TraceTramp and Connector OSS can be healthy inside Docker while the hub still shows “check config” until the platform has these variables."
            },
            "devguard": {
                "id": "devguard",
                "enabled_in_deployment": en_dg,
                "phase_5": phase5_hints(&state, "devguard"),
                "status_badge": status_badge(lf_dg.installed, lf_dg.enabled, dg_health),
                "lifecycle": lf_dg,
                "actions": lifecycle_actions(lf_dg.installed, lf_dg.enabled),
                "cage_host": cage_dg,
                "cage_internal_dns_registered": dns_dg,
                "public_plugin_proxy_prefix": "/plugin/devguard",
                "dashboard_path": "/plugins/devguard",
                "ui_embedded": true,
                "management_proxy_configured": dg_cfg,
                "local_profile_saved": dg_local_saved,
                "extension_status_path": "/plugins/devguard/extension/status",
                "management_url_explicit": devguard_management_url_explicit(),
                "management_display_host": dg_host,
                "upstream_reachable": dg_upstream,
                "healthy_via_local_profile": false,
                "hint": "Playground DevGuard is in-process (POST /devguard/connect). Set CONNECTOR_DEVGUARD_MANAGEMENT_URL only for an external sidecar. A saved local-profile does not make DevGuard healthy by itself."
            },
            "witnessctl": {
                "id": "witnessctl",
                "enabled_in_deployment": en_wc,
                "phase_5": phase5_hints(&state, "witnessctl"),
                "status_badge": status_badge(lf_wc.installed, lf_wc.enabled, wc_upstream),
                "lifecycle": lf_wc,
                "actions": lifecycle_actions(lf_wc.installed, lf_wc.enabled),
                "cage_host": cage_wc,
                "cage_internal_dns_registered": dns_wc,
                "public_plugin_proxy_prefix": "/plugin/witnessctl",
                "dashboard_path": "/plugins/witnessctl",
                "ui_embedded": true,
                "management_proxy_configured": wc_cfg,
                "health_proxy_configured": wc_health,
                "api_proxy_configured": wc_api,
                "management_url_explicit": witnessctl_management_url_explicit(),
                "management_display_host": wc_host,
                "upstream_reachable": wc_upstream,
                "sessions_proxy_path": "/plugins/witnessctl/sessions",
                "hint": "Set CONNECTOR_WITNESSCTL_MANAGEMENT_URL and CONNECTOR_WITNESSCTL_ADMIN_TOKEN (or WITNESSCTL_*). Dashboard uses GET /api/v1/plugins/witnessctl/health and .../sessions (server-side proxy)."
            }
        }
    }))
}

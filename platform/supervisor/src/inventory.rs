//! Phase **5.10.6** — documented supervisee **patterns** for `connectorctl` / kernel integration.
//! Extend this list when new long-running AGOS entrypoints ship; keep **`ProcessSpec`** fields consistent.

use serde_json::{json, Value};

/// Machine-readable inventory (also served at **`GET /api/v1/kernel/supervisor/inventory`**).
pub fn supervisee_inventory() -> Value {
    json!({
        "ok": true,
        "phase": "5.10.6",
        "profiles": [
            {
                "id": "node_connector_platform",
                "entrypoint": "connectorctl start",
                "uses_process_group": true,
                "plugin_crash_plugin_id": "optional via CONNECTOR_SUPERVISOR_NODE_CRASH_PLUGIN_ID (non-empty manifest-style id → POST …/plugin-crash-recovery/record on each non-success exit, including between coded-exit retries)",
                "restart_on_code_failure": "CONNECTOR_SUPERVISOR_RESTART_MAX / _BASE_MS / _CAP_MS",
                "summary": "Background connector-platform child; optional coded-exit respawns via RestartOnCodeFailure::from_node_supervisor_env."
            },
            {
                "id": "node_connector_platform_foreground",
                "entrypoint": "connectorctl start --foreground",
                "uses_process_group": false,
                "plugin_crash_plugin_id": false,
                "restart_on_code_failure": "none (single blocking child; no supervisor thread)",
                "summary": "Foreground debug boot — std::process::Command::status on the node binary; no connector-supervisor process group or CONNECTOR_SUPERVISOR_RESTART_* loop."
            },
            {
                "id": "plugin_run_dev",
                "entrypoint": "connectorctl plugin run --dev",
                "uses_process_group": true,
                "plugin_crash_plugin_id": true,
                "restart_on_code_failure": "CLI --retry-max / --retry-base-ms (spawn loop)",
                "execution_modes": [
                    {
                        "runtime": "subprocess",
                        "crash_hook": "ProcessSpec.plugin_crash_plugin_id on non-success exit",
                        "retry_control": "CLI retry loop",
                    },
                    {
                        "runtime": "docker_lab",
                        "crash_hook": "connectorctl notifies record_failure when docker run fails",
                        "retry_control": "CLI retry loop",
                    },
                    {
                        "runtime": "microvm",
                        "crash_hook": "connectorctl notifies record_failure on spawn/run failure",
                        "retry_control": "CLI retry loop",
                    },
                    {
                        "runtime": "wasm",
                        "crash_hook": "connectorctl notifies record_failure on spawn failure or non-zero wasm exit_code in receipt",
                        "retry_control": "CLI retry loop",
                    }
                ],
                "summary": "Foreground dev runs; crash failures are reported for subprocess/docker_lab/microvm/wasm paths, with optional CLI retries."
            }
        ],
        "extensibility": "New supervisees: set plugin_crash_plugin_id when failures should POST …/plugin-crash-recovery/record; background node may use CONNECTOR_SUPERVISOR_NODE_CRASH_PLUGIN_ID; use restart_on_code_failure only for background coded-exit retry (not signals)."
    })
}

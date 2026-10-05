//! Connector OS supervisor — process groups, health probes, log fan-in, restart backoff, graceful shutdown.
//!
//! Intended for `connectorctl` / kernel integration (Phase 1.1). On Unix, children call `setpgid(0, 0)` so
//! the whole tree can be signalled with `kill(-pgid, SIGTERM)`.
//!
//! Phase **5.10.2:** set [`ProcessSpec::plugin_crash_plugin_id`] to a `vendor/slug` id; on non-success exit,
//! the supervisor POSTs `…/plugin-crash-recovery/record` to `CONNECTOR_API_URL` (best-effort).
//!
//! Phase **5.10.4 (node):** `connectorctl start` background mode sets [`ProcessSpec::restart_on_code_failure`] via
//! [`RestartOnCodeFailure::from_node_supervisor_env`] (same env vars; [`Backoff`] between respawns after **non-zero exit codes**;
//! signal exits are not retried). See also [`run_process_spec_with_restart`].
//!
//! **Supervisee inventory (Phase 5.10.6):** `supervisee_inventory()` documents background **`connectorctl start`**
//! (supervisor + restart), **`connectorctl start --foreground`** (no supervisor / no restart loop), and
//! **`connectorctl plugin run --dev`**. Callers today: (1) background **connector-platform** via
//! [`run_process_spec_with_restart`] with optional [`RestartOnCodeFailure`] and optional
//! [`ProcessSpec::plugin_crash_plugin_id`] from **`CONNECTOR_SUPERVISOR_NODE_CRASH_PLUGIN_ID`**, and (2) foreground **`plugin run --dev`** via [`ProcessGroup::spawn_many`]
//! plus CLI-driven tier-admit / quarantine / retry loop, with [`ProcessSpec::plugin_crash_plugin_id`] set for kernel
//! crash record on non-success exit, or **`CONNECTOR_PLUGIN_RUN_BACKEND=docker_lab`** via `connector-plugin-runtime`
//! with [`notify_plugin_crash_on_exit`] on each failed `docker run`, or **`wasm`** on spawn failure / non-zero guest **`exit_code`**. **`connectorctl status`** (human + `--json`) best-effort **`GET /api/v1/plugins/status`** → **`phase_5_operator`** summary line / field. New long-running AGOS entrypoints should reuse the same fields consistently.

mod backoff;
mod health;
pub mod inventory;
mod kernel_crash_notify;
mod log_fanin;
mod process_group;
mod shutdown;

pub use backoff::Backoff;
pub use inventory::supervisee_inventory;
pub use health::{HealthEvent, HttpHealthProbe, ProbeError, TcpHealthProbe};
pub use kernel_crash_notify::notify_plugin_crash_on_exit;
pub use log_fanin::LinePrefixWriter;
pub use process_group::{
    run_process_spec_with_restart, ProcessGroup, ProcessGroupConfig, ProcessSpec, RestartOnCodeFailure,
    SpawnedProcess,
};
pub use shutdown::{ShutdownCoordinator, ShutdownPhase};

#[cfg(test)]
mod integration_tests {
    use super::*;
    use std::path::PathBuf;

    #[tokio::test]
    async fn spawn_sh_true_joins() {
        let (program, args): (PathBuf, Vec<String>) = if cfg!(windows) {
            (
                PathBuf::from("cmd"),
                vec!["/C".into(), "echo hi && exit 0".into()],
            )
        } else {
            (
                PathBuf::from("sh"),
                vec!["-c".into(), "echo hi && exit 0".into()],
            )
        };
        let spec = ProcessSpec {
            name: "noop".into(),
            program,
            args,
            cwd: None,
            inherit_parent_env: true,
            env: vec![],
            forward_logs: true,
            plugin_crash_plugin_id: None,
            restart_on_code_failure: None,
        };
        let g = ProcessGroup::spawn_many(vec![spec]).await.expect("spawn");
        let st = g.join_all().await.expect("wait");
        assert_eq!(st.len(), 1);
        assert!(st[0].success());
    }
}

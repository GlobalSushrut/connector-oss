use serde::{Deserialize, Serialize};

/// Keep strings aligned with `connector-platform` `runtime_control::IsolationRuntime`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IsolationRuntime {
    /// Legacy / in-tree name — same backend as [`Subprocess`](Self::Subprocess).
    Internal,
    Subprocess,
    DockerLab,
    Microvm,
    /// Wasmtime + WASI preview1 (Phase **5.6**).
    Wasm,
}

#[derive(Debug, Clone)]
pub struct SpawnRequest {
    pub plugin_id: String,
    pub program: std::path::PathBuf,
    pub args: Vec<String>,
    pub cwd: Option<std::path::PathBuf>,
    pub env: Vec<(String, String)>,
    /// `network.outbound:host:port` capability strings from the active manifest (Phase 5.7).
    /// Used by Docker lab when `CONNECTOR_DOCKER_LAB_EGRESS=allowlist_strict` (empty → `--network none`).
    pub egress_allowlist: Vec<String>,
    /// Docker lab: host directory mounted read-only at `/connector-plugin` (`program` must be under this path).
    pub workspace_host_mount: Option<std::path::PathBuf>,
    /// Docker lab: `true` = `docker run -d` (default); `false` = blocking run, exit status from container (e.g. `connectorctl`).
    pub docker_run_detached: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpawnReceipt {
    pub backend: String,
    pub plugin_id: String,
    pub detail: serde_json::Value,
}

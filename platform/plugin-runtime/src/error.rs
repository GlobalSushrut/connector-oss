use thiserror::Error;

#[derive(Debug, Error)]
pub enum PluginRuntimeError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("spawn failed: {0}")]
    Spawn(String),
    #[error("docker_lab: {0}")]
    DockerLab(String),
    #[error("microvm: {0}")]
    Microvm(String),
    /// WSL2 bridge failure: `code` is a stable machine label from the launcher or host shim.
    #[error("microvm wsl [{code}]: {detail}")]
    MicrovmWsl { code: String, detail: String },
    #[error("wasm: {0}")]
    Wasm(String),
}

use thiserror::Error;

#[derive(Debug, Error)]
pub enum MicrovmError {
    #[error("microvm host not configured: {0}")]
    HostNotConfigured(String),
    #[error("invalid vm config: {0}")]
    InvalidConfig(String),
    #[error("io: {0}")]
    Io(String),
    #[error("firecracker process failed: {0}")]
    Process(String),
    #[error("firecracker api error: {0}")]
    Api(String),
    #[error("unsupported host: {0}")]
    UnsupportedHost(String),
}

//! AGOS **plugin handshake** (Phase 1.4): kernel (or launcher) delivers bootstrap JSON once; the
//! process maps it into the legacy env vars that existing plugins already read (`Config::from_env`,
//! `ConnectorClient::new`, etc.).
//!
//! Delivery mechanisms (first match wins):
//! 1. **`CONNECTOR_AGOS_HANDSHAKE_FD`** (Unix only) — read one JSON document from that file
//!    descriptor, then the fd is closed with the `File`.
//! 2. **`CONNECTOR_AGOS_HANDSHAKE`** — path to a UTF‑8 JSON file.
//!
//! If neither is set, [`apply_from_env`] is a no-op.

use serde::Deserialize;
use std::io::Read;

pub const ENV_HANDSHAKE_PATH: &str = "CONNECTOR_AGOS_HANDSHAKE";
pub const ENV_HANDSHAKE_FD: &str = "CONNECTOR_AGOS_HANDSHAKE_FD";

#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    #[error("unsupported handshake schema_version {0} (only 1 is supported)")]
    UnsupportedSchemaVersion(u32),
    #[error("handshake JSON missing required `connector` object")]
    MissingConnector,
    #[error("invalid CONNECTOR_AGOS_HANDSHAKE_FD `{0}`")]
    InvalidFd(String),
    #[error("CONNECTOR_AGOS_HANDSHAKE_FD is only supported on Unix targets")]
    FdUnsupported,
    #[error("read handshake file: {0}")]
    Io(#[from] std::io::Error),
    #[error("parse handshake JSON: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Deserialize)]
struct AgosHandshakeV1 {
    schema_version: u32,
    #[serde(default)]
    connector: Option<ConnectorBlock>,
}

#[derive(Debug, Deserialize)]
struct ConnectorBlock {
    base_url: String,
    #[serde(default)]
    api_key: Option<String>,
}

/// Load handshake from [`ENV_HANDSHAKE_FD`] or [`ENV_HANDSHAKE_PATH`] and `set_var` the
/// cross-plugin Connector env aliases. Safe to call from every plugin `main` before config/CLI.
pub fn apply_from_env() -> Result<(), HandshakeError> {
    let Some(raw) = read_raw_payload()? else {
        return Ok(());
    };
    let doc: AgosHandshakeV1 = serde_json::from_str(raw.trim())?;
    if doc.schema_version != 1 {
        return Err(HandshakeError::UnsupportedSchemaVersion(doc.schema_version));
    }
    let Some(connector) = doc.connector else {
        return Err(HandshakeError::MissingConnector);
    };
    let base = connector.base_url.trim();
    if base.is_empty() {
        return Err(HandshakeError::MissingConnector);
    }
    std::env::set_var("TRACETRAMP_CONNECTOR_BASE_URL", base);
    std::env::set_var("CONNECTOR_BASE_URL", base);
    std::env::set_var("CONNECTOR_URL", base);
    if let Some(ref key) = connector.api_key {
        let k = key.trim();
        if !k.is_empty() {
            std::env::set_var("TRACETRAMP_CONNECTOR_API_KEY", k);
            std::env::set_var("CONNECTOR_API_KEY", k);
            std::env::set_var("CONNECTOR_KEY", k);
            std::env::set_var("CONNECTOR_ACCESS_KEY", k);
        }
    }
    Ok(())
}

fn read_raw_payload() -> Result<Option<String>, HandshakeError> {
    if let Ok(fd_s) = std::env::var(ENV_HANDSHAKE_FD) {
        let fd_s = fd_s.trim();
        if !fd_s.is_empty() {
            #[cfg(unix)]
            {
                let fd: std::os::fd::RawFd = fd_s
                    .parse()
                    .map_err(|_| HandshakeError::InvalidFd(fd_s.to_string()))?;
                return Ok(Some(read_fd_to_string(fd)?));
            }
            #[cfg(not(unix))]
            {
                return Err(HandshakeError::FdUnsupported);
            }
        }
    }

    if let Ok(path) = std::env::var(ENV_HANDSHAKE_PATH) {
        let path = path.trim();
        if path.is_empty() {
            return Ok(None);
        }
        return Ok(Some(std::fs::read_to_string(path)?));
    }

    Ok(None)
}

#[cfg(unix)]
fn read_fd_to_string(fd: std::os::fd::RawFd) -> Result<String, HandshakeError> {
    use std::os::fd::FromRawFd;
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    let mut buf = String::new();
    file.read_to_string(&mut buf)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_from_path_sets_connector_env() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!("agos-handshake-test-{nanos}.json"));
        std::fs::write(
            &p,
            r#"{"schema_version":1,"connector":{"base_url":"http://cage:9091","api_key":"k"}}"#,
        )
        .expect("write");
        std::env::set_var(ENV_HANDSHAKE_PATH, p.to_str().unwrap());
        std::env::remove_var(ENV_HANDSHAKE_FD);
        apply_from_env().expect("apply");
        assert_eq!(
            std::env::var("CONNECTOR_BASE_URL").unwrap(),
            "http://cage:9091"
        );
        assert_eq!(std::env::var("CONNECTOR_API_KEY").unwrap(), "k");
        assert_eq!(std::env::var("TRACETRAMP_CONNECTOR_BASE_URL").unwrap(), "http://cage:9091");
        std::env::remove_var(ENV_HANDSHAKE_PATH);
        std::env::remove_var("CONNECTOR_BASE_URL");
        std::env::remove_var("CONNECTOR_API_KEY");
        std::env::remove_var("CONNECTOR_KEY");
        std::env::remove_var("CONNECTOR_URL");
        std::env::remove_var("CONNECTOR_ACCESS_KEY");
        std::env::remove_var("TRACETRAMP_CONNECTOR_BASE_URL");
        std::env::remove_var("TRACETRAMP_CONNECTOR_API_KEY");
        let _ = std::fs::remove_file(&p);
    }
}

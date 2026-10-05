//! Cell SPIFFE-ish identity constants (P8.3).
//!
//! Product URI shape for a cell (not a full SPIFFE SVID issuance stack):
//! `spiffe://{trust_domain}/cell/{cell_id}`
//!
//! See `docs/architecture/cell-spiffe-identity.md`.

/// Documented URI template for local / peer cell identity.
pub const CELL_SPIFFE_URI_TEMPLATE: &str = "spiffe://{trust_domain}/cell/{cell_id}";

/// Default trust domain when `CONNECTOR_FEDERATION_TRUST_DOMAIN` / `CONNECTOR_TRUST_DOMAIN` unset.
pub const DEFAULT_TRUST_DOMAIN: &str = "connector.local";

/// Resolve trust domain label for SPIFFE-ish cell URIs.
pub fn trust_domain() -> String {
    std::env::var("CONNECTOR_FEDERATION_TRUST_DOMAIN")
        .or_else(|_| std::env::var("CONNECTOR_TRUST_DOMAIN"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_TRUST_DOMAIN.into())
}

/// Build `spiffe://{trust_domain}/cell/{cell_id}` for the local (or named) cell.
pub fn cell_spiffe_id(trust_domain: &str, cell_id: &str) -> String {
    let td = trust_domain.trim();
    let td = if td.is_empty() {
        DEFAULT_TRUST_DOMAIN
    } else {
        td
    };
    let cid = cell_id.trim();
    let cid = if cid.is_empty() { "cell_local" } else { cid };
    format!("spiffe://{td}/cell/{cid}")
}

/// Whether `spire-agent` is installed. Does not fetch an SVID.
pub fn spire_agent_present() -> bool {
    spire_agent_bin().is_some()
}

/// Ask SPIRE for an X.509 SVID id. Connector does not issue SVIDs.
/// `spiffe_id` is set only when `spire-agent api fetch x509` exits 0 and prints `spiffe://`.
pub fn fetch_spire_x509() -> SpireFetch {
    let socket = std::env::var("SPIFFE_ENDPOINT_SOCKET")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let Some(socket) = socket else {
        return SpireFetch {
            spiffe_id: None,
            detail: "SPIFFE_ENDPOINT_SOCKET unset. Cell URI is not a SPIRE SVID.".into(),
        };
    };
    let bin = spire_agent_bin();
    let Some(bin) = bin else {
        return SpireFetch {
            spiffe_id: None,
            detail: "not_installed: spire-agent. Set CONNECTOR_SPIRE_AGENT_BIN or place spire-agent on PATH.".into(),
        };
    };
    match run_spire(&bin, &spire_socket_path(&socket)) {
        Ok((code, stdout, stderr)) if code == 0 => {
            if let Some(id) = parse_spiffe_id(&stdout) {
                SpireFetch {
                    spiffe_id: Some(id),
                    detail: "spire-agent api fetch x509 exited 0".into(),
                }
            } else {
                SpireFetch {
                    spiffe_id: None,
                    detail: format!("spire-agent exited 0 but no spiffe:// id was in stdout: {}", clip(&stdout)),
                }
            }
        }
        Ok((code, _, stderr)) => SpireFetch {
            spiffe_id: None,
            detail: format!("spire-agent exited {code}: {}", clip(&stderr)),
        },
        Err(e) => SpireFetch {
            spiffe_id: None,
            detail: e,
        },
    }
}

#[derive(Debug, Clone)]
pub struct SpireFetch {
    pub spiffe_id: Option<String>,
    pub detail: String,
}

/// `SPIFFE_ENDPOINT_SOCKET` is a URI (`unix:///run/...`). The CLI wants the path.
pub fn spire_socket_path(raw: &str) -> String {
    raw.trim()
        .strip_prefix("unix://")
        .unwrap_or(raw.trim())
        .to_string()
}

pub fn parse_spiffe_id(stdout: &str) -> Option<String> {
    for line in stdout.lines() {
        let Some(rest) = line.trim().strip_prefix("SPIFFE ID:") else {
            continue;
        };
        let id = rest.trim();
        if id.starts_with("spiffe://") && !id.chars().any(char::is_whitespace) {
            return Some(id.to_string());
        }
    }
    None
}

fn spire_agent_bin() -> Option<std::path::PathBuf> {
    if let Ok(explicit) = std::env::var("CONNECTOR_SPIRE_AGENT_BIN") {
        let p = std::path::PathBuf::from(explicit.trim());
        if p.is_file() {
            return Some(p);
        }
    }
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join("spire-agent");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn run_spire(bin: &std::path::Path, socket: &str) -> Result<(i32, String, String), String> {
    let mut child = std::process::Command::new(bin)
        .args(["api", "fetch", "x509", "-socketPath", socket])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    let start = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(5);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut stdout = String::new();
                let mut stderr = String::new();
                if let Some(mut p) = child.stdout.take() {
                    let _ = std::io::Read::read_to_string(&mut p, &mut stdout);
                }
                if let Some(mut p) = child.stderr.take() {
                    let _ = std::io::Read::read_to_string(&mut p, &mut stderr);
                }
                return Ok((status.code().unwrap_or(-1), stdout, stderr));
            }
            Ok(None) if start.elapsed() > timeout => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("spire-agent timed out after 5s".into());
            }
            Ok(None) => std::thread::sleep(std::time::Duration::from_millis(50)),
            Err(e) => return Err(e.to_string()),
        }
    }
}

fn clip(s: &str) -> String {
    let t = s.trim();
    if t.chars().count() > 240 {
        let end = t.char_indices().nth(240).map(|(i, _)| i).unwrap_or(t.len());
        format!("{}…", &t[..end])
    } else {
        t.to_string()
    }
}

/// Local cell SPIFFE-ish id from env (`CONNECTOR_CELL_ID`, trust domain env).
pub fn local_cell_spiffe_id() -> String {
    let cell_id = std::env::var("CONNECTOR_CELL_ID")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "cell_local".into());
    cell_spiffe_id(&trust_domain(), &cell_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cell_spiffe_uri_shape() {
        assert_eq!(
            cell_spiffe_id("example.org", "cell-a"),
            "spiffe://example.org/cell/cell-a"
        );
        assert!(CELL_SPIFFE_URI_TEMPLATE.contains("{trust_domain}"));
        assert!(CELL_SPIFFE_URI_TEMPLATE.contains("{cell_id}"));
    }

    #[test]
    fn parse_spire_workload_api_line() {
        let stdout = "Received 1 svid after 3ms\n\nSPIFFE ID:\t\tspiffe://example.org/ns/default/sa/default\nSVID Valid After:\t2026-01-01\n";
        assert_eq!(
            parse_spiffe_id(stdout).as_deref(),
            Some("spiffe://example.org/ns/default/sa/default")
        );
        assert!(parse_spiffe_id("SPIFFE ID: not-an-id\n").is_none());
    }

    #[test]
    fn unix_socket_uri_becomes_a_filesystem_path() {
        assert_eq!(
            spire_socket_path("unix:///run/spire/agent/sockets/api.sock"),
            "/run/spire/agent/sockets/api.sock"
        );
        assert_eq!(spire_socket_path("/tmp/agent.sock"), "/tmp/agent.sock");
    }
}

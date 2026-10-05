//! Firecracker **guest-initiated** vsock: the host listens on `{uds_path}_{PORT}` (see Firecracker `docs/vsock.md`).
//! `connector-vm-agent` in the guest connects to **host CID 2** + the same port and sends JSON heartbeats;
//! the host may reply with one JSON line **`{"kind":"tier_signal","thermal_tier":"cold"|"warm"}`** (Phase 5.4.3).

use std::path::{Path, PathBuf};

/// Default guest→host vsock port for `connector-vm-agent` heartbeats (host AF_UNIX `{uds_path}_{port}`).
pub fn agent_vsock_port() -> u32 {
    const DEFAULT: u32 = 1024;
    std::env::var("CONNECTOR_MICROVM_AGENT_VSOCK_PORT")
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .filter(|&p| p > 0 && p < 65536)
        .unwrap_or(DEFAULT)
}

pub fn guest_listen_uds_path(base: &Path, port: u32) -> PathBuf {
    PathBuf::from(format!("{}_{port}", base.display()))
}

fn vsock_ticket_required() -> bool {
    matches!(
        std::env::var("CONNECTOR_VSOCK_TICKET_REQUIRE")
            .ok()
            .as_deref()
            .map(|s| s.trim().to_ascii_lowercase())
            .as_deref(),
        Some("1") | Some("true") | Some("yes") | Some("on")
    )
}

pub fn tier_signal_replies_enabled() -> bool {
    matches!(
        std::env::var("CONNECTOR_MICROVM_VSOCK_TIER_SIGNAL")
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "1" | "true" | "yes" | "on"
    )
}

#[cfg(target_os = "linux")]
pub fn spawn_guest_initiated_vsock_listener(
    listen_path: PathBuf,
    plugin_id: String,
    tier_state_path: Option<PathBuf>,
    tier_reply_enabled: bool,
    first_sample_tx: std::sync::mpsc::Sender<String>,
    expected_ticket: Option<String>,
    require_ticket: bool,
) -> Result<(), crate::error::PluginRuntimeError> {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread;

    if listen_path.exists() {
        let _ = std::fs::remove_file(&listen_path);
    }
    let listener = UnixListener::bind(&listen_path).map_err(|e| {
        crate::error::PluginRuntimeError::Microvm(format!(
            "bind vsock agent listen {}: {}",
            listen_path.display(),
            e
        ))
    })?;
    let _ = listener.set_nonblocking(false);
    let first_sent = AtomicBool::new(false);
    thread::spawn(move || loop {
        let Ok((stream, _)) = listener.accept() else {
            continue;
        };
        let mut line = String::new();
        let mut stream = {
            let mut reader = BufReader::new(stream);
            if reader.read_line(&mut line).is_err() {
                continue;
            }
            reader.into_inner()
        };
        let trimmed = line.trim().to_string();
        if require_ticket {
            let ok = match expected_ticket.as_deref() {
                Some(exp) if !exp.is_empty() => ticket_matches(exp, &trimmed),
                _ => false,
            };
            if !ok {
                let _ = writeln!(
                    stream,
                    "{}",
                    serde_json::json!({
                        "kind": "error",
                        "error": "vsock_ticket_rejected",
                    })
                );
                continue;
            }
        }
        if !first_sent.swap(true, Ordering::SeqCst) {
            let _ = first_sample_tx.send(trimmed);
        }
        if tier_reply_enabled {
            let tier = read_tier_for_plugin(tier_state_path.as_deref(), &plugin_id);
            let body = serde_json::json!({"kind":"tier_signal","thermal_tier": tier});
            let _ = writeln!(stream, "{}", body);
            let _ = stream.flush();
        }
    });
    Ok(())
}

fn ticket_matches(expect: &str, line: &str) -> bool {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
        if let Some(t) = v.get("vsock_ticket").and_then(|x| x.as_str()) {
            return t == expect;
        }
    }
    line.trim() == expect
}

#[cfg(target_os = "linux")]
fn read_tier_for_plugin(tier_state_path: Option<&Path>, plugin_id: &str) -> &'static str {
    let Some(path) = tier_state_path else {
        return "warm";
    };
    let Ok(raw) = std::fs::read_to_string(path) else {
        return "warm";
    };
    let s = raw.trim();
    if s.is_empty() {
        return "warm";
    }
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(s) {
        if let Some(t) = v.get(plugin_id).and_then(|x| x.as_str()) {
            if t.eq_ignore_ascii_case("cold") {
                return "cold";
            }
        }
        if let Some(t) = v.get("thermal_tier").and_then(|x| x.as_str()) {
            if t.eq_ignore_ascii_case("cold") {
                return "cold";
            }
        }
    }
    if s.eq_ignore_ascii_case("cold") {
        "cold"
    } else {
        "warm"
    }
}

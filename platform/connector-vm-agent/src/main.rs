use std::io::Write;
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Serialize)]
struct VmAgentHeartbeat<'a> {
    kind: &'a str,
    ts_unix_ms: u128,
    pid: u32,
}

#[derive(Debug, Default, Clone, Deserialize)]
struct CondoHeartbeatConfig {
    condo_id: String,
    guest_id: String,
    vm_id: String,
    target_pool: String,
    heartbeat_url: String,
    heartbeat_token: String,
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

fn parse_cmdline_kv(key: &str) -> Option<String> {
    let raw = std::fs::read_to_string("/proc/cmdline").ok()?;
    for part in raw.split_whitespace() {
        let Some((k, v)) = part.split_once('=') else {
            continue;
        };
        if k == key {
            return Some(v.to_string());
        }
    }
    None
}

fn condo_hb_cfg() -> CondoHeartbeatConfig {
    let condo_id = std::env::var("CONNECTOR_CONDO_ID")
        .ok()
        .or_else(|| parse_cmdline_kv("connector.condo_id"))
        .unwrap_or_default();
    let guest_id = std::env::var("CONNECTOR_CONDO_GUEST_ID")
        .ok()
        .or_else(|| parse_cmdline_kv("connector.condo_guest_id"))
        .unwrap_or_default();
    let vm_id = std::env::var("CONNECTOR_VM_ID")
        .ok()
        .or_else(|| parse_cmdline_kv("connector.vm_id"))
        .unwrap_or_default();
    let target_pool = std::env::var("CONNECTOR_CONDO_TARGET_POOL")
        .ok()
        .or_else(|| parse_cmdline_kv("connector.condo_target_pool"))
        .unwrap_or_default();
    let heartbeat_url = std::env::var("CONNECTOR_CONDO_GUEST_HEARTBEAT_URL")
        .ok()
        .or_else(|| parse_cmdline_kv("connector.condo_heartbeat_url"))
        .or_else(|| {
            std::env::var("CONNECTOR_API_URL")
                .ok()
                .or_else(|| parse_cmdline_kv("connector.api_url"))
                .map(|base| {
                    format!(
                        "{}/api/v1/kernel/plugin-condos/guest-heartbeat",
                        base.trim_end_matches('/')
                    )
                })
        })
        .unwrap_or_default();
    let heartbeat_token = std::env::var("CONNECTOR_CONDO_GUEST_HEARTBEAT_TOKEN")
        .ok()
        .or_else(|| parse_cmdline_kv("connector.condo_heartbeat_token"))
        .or_else(|| {
            std::env::var("CONNECTOR_API_KEY")
                .ok()
                .or_else(|| parse_cmdline_kv("connector.api_key"))
        })
        .unwrap_or_default();
    CondoHeartbeatConfig {
        condo_id,
        guest_id,
        vm_id,
        target_pool,
        heartbeat_url,
        heartbeat_token,
    }
}

fn maybe_post_condo_heartbeat(cfg: &CondoHeartbeatConfig) -> Result<(), String> {
    if cfg.condo_id.trim().is_empty() || cfg.heartbeat_url.trim().is_empty() {
        return Ok(());
    }
    let url = cfg.heartbeat_url.trim().to_string();
    let payload = json!({
        "condo_id": cfg.condo_id,
        "guest_id": if cfg.guest_id.is_empty() { serde_json::Value::Null } else { json!(cfg.guest_id) },
        "vm_id": if cfg.vm_id.is_empty() { serde_json::Value::Null } else { json!(cfg.vm_id) },
        "target_pool": if cfg.target_pool.is_empty() { serde_json::Value::Null } else { json!(cfg.target_pool) },
        "status": "healthy",
    });
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .map_err(|e| e.to_string())?;
    let mut req = client.post(url).json(&payload);
    if !cfg.heartbeat_token.trim().is_empty() {
        req = req.header("Authorization", format!("Bearer {}", cfg.heartbeat_token.trim()));
    }
    let res = req.send().map_err(|e| e.to_string())?;
    if !res.status().is_success() {
        return Err(format!("http {}", res.status()));
    }
    Ok(())
}

/// Static guest ULA from kernel cmdline (set by `connector-plugin-runtime` when microVM egress uses IPv6 caps).
fn maybe_apply_microvm_guest_ipv6() {
    let Some(addr) = parse_cmdline_kv("connector.microvm_guest_ipv6") else {
        return;
    };
    let addr = addr.trim();
    if addr.is_empty() || !addr.contains(':') {
        return;
    }
    let cidr = format!("{addr}/64");
    let dev = parse_cmdline_kv("connector.microvm_guest_iface")
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "eth0".into());
    let dev = dev.trim();
    for bin in ["/sbin/ip", "/bin/ip", "ip"] {
        if std::process::Command::new(bin)
            .args(["-6", "addr", "add", &cidr, "dev", dev])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            return;
        }
    }
}

fn log_tier_idle_suspend_guest_hint() {
    let ms = parse_cmdline_kv("connector.plugin_idle_suspend_after_ms")
        .and_then(|s| s.trim().parse::<u128>().ok())
        .unwrap_or(0);
    if ms > 0 {
        eprintln!(
            "[connector-vm-agent] tier_idle_suspend_policy_ms={ms} (kernel policy on cmdline; optional host tier_signal over vsock when /dev/vsock exists)"
        );
    }
}

fn vsock_agent_port() -> u32 {
    parse_cmdline_kv("connector.vsock_agent_port")
        .and_then(|s| s.trim().parse::<u32>().ok())
        .filter(|&p| p > 0 && p < 65536)
        .unwrap_or(1024)
}

fn handle_tier_signal_reply(reply: &str) {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(reply) else {
        return;
    };
    if v.get("kind").and_then(|x| x.as_str()) != Some("tier_signal") {
        return;
    }
    if v.get("thermal_tier").and_then(|x| x.as_str()) != Some("cold") {
        return;
    }
    eprintln!("[connector-vm-agent] host tier_signal=thermal_tier:cold");
    let action = std::env::var("CONNECTOR_VM_AGENT_TIER_COLD_ACTION")
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    if action == "poweroff" {
        let _ = std::process::Command::new("/sbin/poweroff").status();
    }
}

#[cfg(target_os = "linux")]
fn send_heartbeat_via_vsock(port: u32, line: &str) -> Result<Option<String>, std::io::Error> {
    use std::io::{BufRead, BufReader, Write};
    use vsock::VsockStream;
    /// Firecracker host CID (see Firecracker `docs/vsock.md`).
    const VMADDR_CID_HOST: u32 = 2;
    let mut stream = VsockStream::connect_with_cid_port(VMADDR_CID_HOST, port).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::Other, format!("vsock connect: {e}"))
    })?;
    stream.write_all(line.as_bytes())?;
    stream.write_all(b"\n")?;
    stream.flush()?;
    stream
        .set_read_timeout(Some(Duration::from_millis(200)))
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("vsock read timeout: {e}")))?;
    let mut reader = BufReader::new(stream);
    let mut reply = String::new();
    let n = reader.read_line(&mut reply)?;
    Ok((n > 0 && !reply.trim().is_empty()).then_some(reply))
}

#[cfg(unix)]
fn send_heartbeat_via_unix_socket(path: &str, line: &str) -> std::io::Result<()> {
    let mut stream = UnixStream::connect(path)?;
    stream.write_all(line.as_bytes())?;
    stream.write_all(b"\n")?;
    stream.flush()?;
    Ok(())
}

fn main() {
    maybe_apply_microvm_guest_ipv6();
    log_tier_idle_suspend_guest_hint();
    let vsock_path = std::env::var("CONNECTOR_VM_AGENT_VSOCK_PATH")
        .ok()
        .or_else(|| {
            std::env::args()
                .find(|a| a.starts_with("--vsock-path="))
                .map(|a| a.trim_start_matches("--vsock-path=").to_string())
        })
        .unwrap_or_else(|| "/run/connector-vm-agent.sock".to_string());
    let agent_port = vsock_agent_port();
    let condo_cfg = condo_hb_cfg();

    eprintln!(
        "[connector-vm-agent] starting pid={} vsock_path={} vsock_agent_port={}",
        std::process::id(),
        vsock_path,
        agent_port
    );
    loop {
        let hb = VmAgentHeartbeat {
            kind: "heartbeat",
            ts_unix_ms: now_ms(),
            pid: std::process::id(),
        };
        let line = serde_json::to_string(&hb).unwrap_or_else(|_| "{\"kind\":\"heartbeat\"}".to_string());
        #[cfg(target_os = "linux")]
        {
            if std::path::Path::new("/dev/vsock").exists() {
                match send_heartbeat_via_vsock(agent_port, &line) {
                    Ok(Some(reply)) => handle_tier_signal_reply(&reply),
                    Ok(None) => {}
                    Err(e) => eprintln!("[connector-vm-agent] vsock heartbeat failed: {e}"),
                }
            } else if let Err(e) = send_heartbeat_via_unix_socket(&vsock_path, &line) {
                eprintln!("[connector-vm-agent] heartbeat transport unavailable: {e}");
            }
        }
        #[cfg(all(unix, not(target_os = "linux")))]
        {
            if let Err(e) = send_heartbeat_via_unix_socket(&vsock_path, &line) {
                eprintln!("[connector-vm-agent] heartbeat transport unavailable: {e}");
            }
        }
        #[cfg(not(unix))]
        {
            let _ = (&vsock_path, &line, agent_port);
            eprintln!("[connector-vm-agent] heartbeat transport unavailable (non-unix host build)");
        }
        if let Err(e) = maybe_post_condo_heartbeat(&condo_cfg) {
            eprintln!("[connector-vm-agent] condo heartbeat post failed: {}", e);
        }
        std::thread::sleep(Duration::from_secs(2));
    }
}

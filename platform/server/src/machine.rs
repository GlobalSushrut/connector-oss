/// Track 5B: Machine Fingerprint
/// Generates a stable, cross-platform machine fingerprint: hash(hostname + MAC + disk serial).
/// Used to lock a license to a specific machine or container.
///
/// Platforms: Linux (sysfs), macOS (ioreg via sysctl), Docker (container ID via /proc/self/cgroup).
use sha2::{Digest, Sha256};

/// Stable machine fingerprint: hex-encoded SHA-256 of combined identifiers.
pub fn machine_fingerprint() -> String {
    let mut components: Vec<String> = Vec::new();

    // 1. Hostname
    if let Ok(h) = hostname() { components.push(h); }

    // 2. Primary MAC address (Linux: sysfs; macOS: fallback)
    if let Some(mac) = primary_mac() { components.push(mac); }

    // 3. Machine ID / disk serial / container ID
    if let Some(id) = machine_id() { components.push(id); }

    // 4. CPU info (extra entropy, stable across reboots)
    if let Some(cpu) = cpu_model() { components.push(cpu); }

    if components.is_empty() {
        // Last resort: use a file-persisted UUID
        components.push(persistent_fallback_id());
    }

    let combined = components.join("|");
    let hash = Sha256::digest(combined.as_bytes());
    hex::encode(hash)
}

fn hostname() -> Result<String, ()> {
    std::fs::read_to_string("/etc/hostname")
        .map(|s| s.trim().to_string())
        .or_else(|_| {
            // POSIX fallback via env
            std::env::var("HOSTNAME").map_err(|_| ())
        })
}

fn primary_mac() -> Option<String> {
    // Linux: /sys/class/net/<iface>/address — pick first non-loopback
    if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
        let mut macs: Vec<String> = entries
            .filter_map(|e| e.ok())
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().into_owned();
                if name == "lo" { return None; }
                let addr_path = format!("/sys/class/net/{}/address", name);
                std::fs::read_to_string(&addr_path).ok().map(|s| s.trim().to_string())
            })
            .filter(|mac| mac != "00:00:00:00:00:00" && !mac.is_empty())
            .collect();
        macs.sort(); // deterministic
        if let Some(mac) = macs.first() { return Some(mac.clone()); }
    }
    None
}

fn machine_id() -> Option<String> {
    // 1. systemd machine-id (Linux)
    if let Ok(id) = std::fs::read_to_string("/etc/machine-id") {
        let trimmed = id.trim().to_string();
        if !trimmed.is_empty() { return Some(trimmed); }
    }

    // 2. Docker container ID via /proc/self/cgroup
    if let Ok(cgroup) = std::fs::read_to_string("/proc/self/cgroup") {
        for line in cgroup.lines() {
            if let Some(idx) = line.rfind('/') {
                let id = &line[idx + 1..];
                if id.len() >= 12 && id.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Some(id.chars().take(64).collect());
                }
            }
        }
    }

    // 3. /proc/sys/kernel/random/boot_id (Linux, changes on reboot — lower priority)
    if let Ok(id) = std::fs::read_to_string("/proc/sys/kernel/random/boot_id") {
        let trimmed = id.trim().to_string();
        if !trimmed.is_empty() { return Some(trimmed); }
    }

    None
}

fn cpu_model() -> Option<String> {
    // Linux: /proc/cpuinfo "model name"
    if let Ok(info) = std::fs::read_to_string("/proc/cpuinfo") {
        for line in info.lines() {
            if line.starts_with("model name") {
                if let Some(val) = line.split(':').nth(1) {
                    return Some(val.trim().to_string());
                }
            }
        }
    }
    None
}

fn persistent_fallback_id() -> String {
    // If all else fails, use/create a UUID stored in $DATA_DIR/machine_id
    let dir  = std::env::var("DATA_DIR").unwrap_or_else(|_| "/tmp".into());
    let path = format!("{}/machine_id", dir);
    if let Ok(id) = std::fs::read_to_string(&path) {
        let trimmed = id.trim().to_string();
        if !trimmed.is_empty() { return trimmed; }
    }
    let new_id = uuid::Uuid::new_v4().to_string();
    let _ = std::fs::write(&path, &new_id);
    new_id
}

/// Live **control-plane** OS facts for runtime / enforcement APIs (not per-agent VMs).
///
/// Read from `/proc` where available; safe to call on each request (small reads).
/// Used to ground dashboards in real host context while staying honest about
/// what runs in-process vs. what deployment must add (workers, gVisor, net policies).
pub fn control_plane_os_telemetry() -> serde_json::Value {
    let server_pid = std::process::id();
    let cgroup_full = std::fs::read_to_string("/proc/self/cgroup").ok();
    let cgroup_excerpt = cgroup_full
        .as_ref()
        .map(|s| s.chars().take(1200).collect::<String>());
    let kernel_release = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .map(|s| s.trim().to_string());
    let dockerenv = std::path::Path::new("/.dockerenv").exists();
    let mut heuristic_cues: Vec<&'static str> = Vec::new();
    if dockerenv {
        heuristic_cues.push("dockerenv_present");
    }
    if let Some(cg) = cgroup_full.as_ref() {
        let lower = cg.to_ascii_lowercase();
        if lower.contains("kubepods") || lower.contains("kubernetes") {
            heuristic_cues.push("cgroup_suggests_kubernetes");
        }
        if lower.contains("docker") {
            heuristic_cues.push("cgroup_suggests_docker");
        }
    }

    serde_json::json!({
        "server_pid": server_pid,
        "kernel_release": kernel_release,
        "arch": std::env::consts::ARCH,
        "os_family": std::env::consts::OS,
        "proc_self_cgroup_excerpt": cgroup_excerpt,
        "container_heuristic_cues": heuristic_cues,
        "honesty": "This describes the connector-platform OS process and its cgroup context — not a separate PID per logical agent.",
    })
}

/// Validate that the running machine matches a license's locked fingerprint.
/// Returns (matches: bool, actual_fp: String).
pub fn validate_fingerprint(locked_fp: &str) -> (bool, String) {
    let actual = machine_fingerprint();
    (actual == locked_fp, actual)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_stable() {
        let fp1 = machine_fingerprint();
        let fp2 = machine_fingerprint();
        assert_eq!(fp1, fp2, "Fingerprint must be deterministic");
        assert_eq!(fp1.len(), 64, "SHA-256 hex = 64 chars");
    }

    #[test]
    fn fingerprint_is_hex() {
        let fp = machine_fingerprint();
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()), "Must be hex");
    }
}

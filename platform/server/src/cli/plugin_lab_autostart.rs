//! First-party plugin lab stack autostart for `connectorctl start` (T1 — one green start).
//!
//! When enabled, brings up `lab/docker-compose.premium-lab.yml` + `lab/docker-compose.platform-local.yml`
//! for Postgres/Redis and enabled plugins (TraceTramp, WitnessCtl). DevGuard is host-run only.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

const PREMIUM_LAB: &str = "lab/docker-compose.premium-lab.yml";
const PLATFORM_LOCAL: &str = "lab/docker-compose.platform-local.yml";

/// Whether `connectorctl start` should run the Docker lab stack after the node is ready.
pub fn lab_auto_start_enabled() -> bool {
    match std::env::var("CONNECTOR_PLUGIN_LAB_AUTO_START") {
        Ok(v) => {
            let t = v.trim().to_ascii_lowercase();
            !(t == "0" || t == "false" || t == "no" || t == "off")
        }
        Err(_) => {
            // Default on for dev-oriented presets unless explicitly production.
            let env = std::env::var("CONNECTOR_ENV")
                .unwrap_or_default()
                .to_ascii_lowercase();
            !matches!(env.as_str(), "production" | "prod")
                && std::env::var("CONNECTOR_AIRGAP")
                    .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                    .unwrap_or(false)
                    == false
        }
    }
}

/// Repo root containing `lab/docker-compose.premium-lab.yml`.
pub fn resolve_repo_root(manifest_path: &Option<String>) -> Option<PathBuf> {
    if let Ok(root) = std::env::var("CONNECTOR_REPO_ROOT") {
        let p = PathBuf::from(root.trim());
        if p.join(PREMIUM_LAB).is_file() {
            return Some(p);
        }
    }
    if let Some(m) = manifest_path {
        let p = Path::new(m);
        if let Some(root) = p.parent().and_then(|x| x.parent()).and_then(|x| x.parent()) {
            if root.join(PREMIUM_LAB).is_file() {
                return Some(root.to_path_buf());
            }
        }
    }
    for candidate in [
        "lab/docker-compose.premium-lab.yml",
        "../lab/docker-compose.premium-lab.yml",
        "../../lab/docker-compose.premium-lab.yml",
    ] {
        if Path::new(candidate).is_file() {
            return Path::new(candidate)
                .parent()
                .and_then(|p| p.parent())
                .map(|p| p.to_path_buf());
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        for base in cwd.ancestors().take(6) {
            if base.join(PREMIUM_LAB).is_file() {
                return Some(base.to_path_buf());
            }
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        for base in exe.ancestors().take(10) {
            let lab = base.join(PREMIUM_LAB);
            if lab.is_file() {
                return Some(base.to_path_buf());
            }
        }
    }
    None
}

fn curl_ok(url: &str) -> bool {
    Command::new("curl")
        .args(["-sf", "--max-time", "3", url])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn wait_http_ok(url: &str, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if curl_ok(url) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(750));
    }
    false
}

/// After compose `up`, wait for management planes (host-mapped ports).
pub fn wait_for_plugin_management_ready(plugin_ids: &[String], timeout: Duration) -> Vec<(String, bool)> {
    let mut out = Vec::new();
    if plugin_ids.iter().any(|id| id == "tracetramp") {
        let base = std::env::var("CONNECTOR_TRACETRAMP_MANAGEMENT_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:19742".into());
        let url = format!("{}/health", base.trim_end_matches('/'));
        out.push(("tracetramp".into(), wait_http_ok(&url, timeout)));
    }
    if plugin_ids.iter().any(|id| id == "witnessctl") {
        let base = std::env::var("CONNECTOR_WITNESSCTL_MANAGEMENT_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:17443".into());
        let url = format!("{}/health", base.trim_end_matches('/'));
        out.push(("witnessctl".into(), wait_http_ok(&url, timeout)));
    }
    out
}

fn docker_compose_bin() -> Option<String> {
    if Command::new("docker")
        .args(["compose", "version"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        return Some("docker compose".to_string());
    }
    if Command::new("docker-compose")
        .arg("version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        return Some("docker-compose".to_string());
    }
    None
}

/// Plugin ids enabled for this deployment (`CONNECTOR_PLUGINS_ENABLED` or all known).
pub fn enabled_first_party_plugin_ids() -> Vec<String> {
    let raw = std::env::var("CONNECTOR_PLUGINS_ENABLED").unwrap_or_default();
    let ids: Vec<String> = raw
        .split(',')
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    if ids.is_empty() {
        return vec![
            "tracetramp".into(),
            "witnessctl".into(),
            "devguard".into(),
        ];
    }
    ids
}

/// Compose service names to start for the given plugin ids.
pub fn compose_services_for_plugins(plugin_ids: &[String]) -> Vec<&'static str> {
    let mut out = Vec::new();
    let needs_db = plugin_ids
        .iter()
        .any(|id| id == "tracetramp" || id == "witnessctl");
    if needs_db {
        out.push("postgres");
        out.push("redis");
    }
    if plugin_ids.iter().any(|id| id == "tracetramp") {
        out.push("tracetramp");
    }
    if plugin_ids.iter().any(|id| id == "witnessctl") {
        out.push("witnessctl");
    }
    out
}

fn platform_base_url_for_compose() -> String {
    let port = std::env::var("CONNECTOR_PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .or_else(|| {
            std::env::var("CONNECTOR_HOST")
                .ok()
                .and_then(|h| h.rsplit(':').next().and_then(|p| p.parse().ok()))
        })
        .unwrap_or(9091);
    format!("http://host.docker.internal:{port}")
}

/// Start lab compose services. Returns human-readable summary.
pub fn start_lab_stack(repo_root: &Path, plugin_ids: &[String], quiet: bool) -> Result<String, String> {
    let compose_bin = docker_compose_bin()
        .ok_or_else(|| "docker compose not found (install Docker to autostart TraceTramp/WitnessCtl)".to_string())?;

    let services = compose_services_for_plugins(plugin_ids);
    if services.is_empty() {
        return Ok("no compose services for enabled plugins".into());
    }

    let premium = repo_root.join(PREMIUM_LAB);
    let overlay = repo_root.join(PLATFORM_LOCAL);
    if !premium.is_file() {
        return Err(format!("missing {}", premium.display()));
    }
    if !overlay.is_file() {
        return Err(format!("missing {}", overlay.display()));
    }

    let env_file = repo_root.join("advanced-lab/.env");
    if !env_file.is_file() {
        let example = repo_root.join("advanced-lab/.env.example");
        if example.is_file() {
            let _ = std::fs::copy(&example, &env_file);
        }
    }
    let mut cmd = if compose_bin == "docker compose" {
        let mut c = Command::new("docker");
        c.arg("compose");
        c
    } else {
        Command::new("docker-compose")
    };

    if env_file.is_file() {
        cmd.arg("--env-file").arg(&env_file);
    }
    cmd.current_dir(repo_root)
        .arg("-f")
        .arg(&premium)
        .arg("-f")
        .arg(&overlay)
        .arg("up")
        .arg("-d")
        .arg("--build")
        .env(
            "CONNECTOR_PLATFORM_BASE_URL",
            platform_base_url_for_compose(),
        );

    for svc in &services {
        cmd.arg(svc);
    }

    if !quiet {
        eprintln!(
            "  → plugin lab: {} …",
            services.join(", ")
        );
    }

    let out = cmd
        .output()
        .map_err(|e| format!("docker compose up: {e}"))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let stdout = String::from_utf8_lossy(&out.stdout);
        return Err(format!(
            "plugin lab compose failed (exit {}): {}{}",
            out.status.code().unwrap_or(-1),
            stderr,
            stdout
        ));
    }

    let mut notes = vec![format!("started: {}", services.join(", "))];

    let wait_secs = std::env::var("CONNECTOR_PLUGIN_LAB_HEALTH_WAIT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(120);
    let ready = wait_for_plugin_management_ready(plugin_ids, Duration::from_secs(wait_secs));
    for (id, ok) in &ready {
        notes.push(format!(
            "{}: {}",
            id,
            if *ok { "management healthy" } else { "management timeout (check docker logs)" }
        ));
    }
    if plugin_ids.iter().any(|id| id == "devguard") {
        notes.push("devguard: host-only — enable via dashboard Apps (no compose service)".into());
    }
    Ok(notes.join(" · "))
}

/// Default `connectorctl plugin run` backend when `CONNECTOR_PLUGIN_RUN_BACKEND` is unset.
pub fn default_plugin_run_backend() -> &'static str {
    let env = std::env::var("CONNECTOR_ENV")
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    if matches!(env.as_str(), "production" | "prod" | "pilots" | "pilot") {
        "microvm"
    } else {
        "subprocess"
    }
}

/// Apply management-plane env defaults on the connectorctl process (inherited by supervised child).
pub fn apply_local_plugin_wiring_env() {
    let set = |key: &str, val: &str| {
        if std::env::var_os(key).is_none() {
            std::env::set_var(key, val);
        }
    };
    set(
        "CONNECTOR_TRACETRAMP_MANAGEMENT_URL",
        "http://127.0.0.1:19742",
    );
    set(
        "CONNECTOR_TRACETRAMP_ADMIN_TOKEN",
        "lab_tracetramp_admin_token_change_me",
    );
    set(
        "CONNECTOR_WITNESSCTL_MANAGEMENT_URL",
        "http://127.0.0.1:17443",
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compose_services_include_db_for_tracetramp() {
        let s = compose_services_for_plugins(&["tracetramp".into()]);
        assert!(s.contains(&"postgres"));
        assert!(s.contains(&"tracetramp"));
    }

    #[test]
    fn auto_start_off_when_env_zero() {
        std::env::set_var("CONNECTOR_PLUGIN_LAB_AUTO_START", "0");
        assert!(!lab_auto_start_enabled());
        std::env::remove_var("CONNECTOR_PLUGIN_LAB_AUTO_START");
    }
}

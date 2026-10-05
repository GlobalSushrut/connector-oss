//! Landlock child executor — every world address runs outside connector-platform.
//!
//! The platform process does not dial agent world sockets when this path is on.
//! Children get DockLock Landlock + dest pin (`CONNECTOR_PORE_DEST`) + matrix mark.
//! LLM completions use the Connector system pore; the child cannot execute tools.

use serde_json::{json, Value};
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::time::Duration;

use crate::kernel::{address_cage, docklock, nsfs, pore_table};
use crate::pore_worker::{dest_spec, parse_url_host_port, PoreJob, JOB_SCHEMA};
use crate::state::PlatformState;

pub const TLS_READ_PATHS: &str =
    "/etc/ssl:/etc/ssl/certs:/etc/ca-certificates:/etc/pki:/etc/resolv.conf:/etc/hosts:/etc/nsswitch.conf:/etc/gai.conf";

fn env_flag(name: &str) -> bool {
    matches!(
        std::env::var(name)
            .ok()
            .as_deref()
            .map(|s| s.trim().to_ascii_lowercase())
            .as_deref(),
        Some("1") | Some("true") | Some("yes") | Some("on")
    )
}

/// Density path: Landlock child per address. On with exclusivity / Ring-1 / explicit flag.
pub fn enforced() -> bool {
    if env_flag("CONNECTOR_ALLOW_IN_PROCESS_EFFECTS") {
        return false;
    }
    env_flag("CONNECTOR_LANDLOCK_CHILD")
        || env_flag("CONNECTOR_LLM_CAGE")
        || crate::substrate::effect_exclusivity::effect_exclusivity_enforced()
        || crate::kernel::docklock::ring1_enforce_enabled()
}

pub fn llm_cage_enforced() -> bool {
    env_flag("CONNECTOR_LLM_CAGE")
        || enforced()
        || crate::kernel::llm_vendor_cut::engaged()
}

pub fn posture() -> Value {
    let landlock = connector_plugin_runtime::linux_hardening::landlock_posture_snapshot();
    json!({
        "schema": "connector.landlock.child.v1",
        "enforced": enforced(),
        "llm_cage": llm_cage_enforced(),
        "pore_table": pore_table::posture(),
        "vendor_cut": crate::kernel::llm_vendor_cut::engaged(),
        "landlock": landlock,
        "binary": pore_bin().display().to_string(),
        "honesty": "Parent never claims restrict_self; child pre_exec applies Landlock. Tool-connected sessions DROP direct vendor HTTPS except this cage mark.",
    })
}

pub fn execute_job(
    state: &PlatformState,
    agent_pid: &str,
    address: &str,
    job: PoreJob,
) -> Result<Value, String> {
    if !job.dest_host.trim().is_empty() {
        assert_not_agent_vendor(agent_pid, &job.dest_host)?;
    }
    let row = if job.dest_host.trim().is_empty() {
        pore_table::get(state, agent_pid, address)
            .ok_or_else(|| format!("pore_missing:{agent_pid}::{address}"))?
    } else {
        pore_table::ensure_for_dial(
            state,
            agent_pid,
            address,
            &job.dest_host,
            job.dest_port,
        )?
    };
    spawn_child(state, agent_pid, &row, &job)
}

fn assert_not_agent_vendor(agent_pid: &str, host: &str) -> Result<(), String> {
    crate::kernel::llm_vendor_cut::deny_agent_vendor_dial(agent_pid, host)
}

pub fn http_fetch(
    state: &PlatformState,
    agent_pid: &str,
    address: &str,
    url: &str,
    method: &str,
    headers: Value,
    body: Option<Value>,
    timeout_ms: u64,
) -> Result<Value, String> {
    let (host, port) = parse_url_host_port(url)?;
    let job = PoreJob {
        schema: JOB_SCHEMA.into(),
        kind: "http_fetch".into(),
        dest_host: host,
        dest_port: port,
        url: Some(url.into()),
        method: Some(method.into()),
        headers,
        body,
        tcp_payload: None,
        timeout_ms: Some(timeout_ms),
    };
    execute_job(state, agent_pid, address, job)
}

pub fn tcp_send(
    state: &PlatformState,
    agent_pid: &str,
    address: &str,
    host: &str,
    port: u16,
    payload: Value,
) -> Result<Value, String> {
    let job = PoreJob {
        schema: JOB_SCHEMA.into(),
        kind: "tcp_send".into(),
        dest_host: host.into(),
        dest_port: port,
        url: None,
        method: None,
        headers: json!({}),
        body: Some(payload),
        tcp_payload: None,
        timeout_ms: Some(8_000),
    };
    execute_job(state, agent_pid, address, job)
}

/// Provider HTTP from a dest-pinned LLM cage. Keys never enter agent NSFS.
pub fn llm_complete(
    state: &PlatformState,
    base_url: &str,
    provider: &str,
    api_key: &str,
    model: &str,
    messages: &Value,
    max_tokens: u32,
    temperature: f32,
) -> Result<Value, String> {
    let (host, port) = parse_url_host_port(base_url)?;
    let _ = pore_table::upsert_llm_provider(state, base_url);
    let (url, headers, body) = if provider.eq_ignore_ascii_case("gemini") {
        let mut sys = None;
        let mut contents = Vec::new();
        if let Some(arr) = messages.as_array() {
            for m in arr {
                let role = m.get("role").and_then(|v| v.as_str()).unwrap_or("user");
                let content = m
                    .get("content")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                if role == "system" {
                    sys = Some(json!({"parts": [{"text": content}]}));
                } else {
                    contents.push(json!({
                        "role": if role == "assistant" { "model" } else { "user" },
                        "parts": [{"text": content}],
                    }));
                }
            }
        }
        (
            format!(
                "{}/models/{}:generateContent",
                base_url.trim_end_matches('/'),
                model
            ),
            json!({
                "x-goog-api-key": api_key,
                "content-type": "application/json",
            }),
            json!({
                "contents": contents,
                "systemInstruction": sys,
                "generationConfig": {
                    "maxOutputTokens": max_tokens,
                    "temperature": temperature,
                }
            }),
        )
    } else if provider.eq_ignore_ascii_case("anthropic") {
        let mut sys = None;
        let mut um = Vec::new();
        if let Some(arr) = messages.as_array() {
            for m in arr {
                let role = m.get("role").and_then(|v| v.as_str()).unwrap_or("");
                let content = m.get("content").cloned().unwrap_or(json!(""));
                if role == "system" {
                    sys = content.as_str().map(|s| s.to_string());
                } else {
                    um.push(json!({"role": role, "content": content}));
                }
            }
        }
        (
            format!("{}/messages", base_url.trim_end_matches('/')),
            json!({
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            }),
            json!({
                "model": model,
                "messages": um,
                "max_tokens": max_tokens,
                "system": sys,
            }),
        )
    } else {
        (
            format!("{}/chat/completions", base_url.trim_end_matches('/')),
            json!({
                "Authorization": format!("Bearer {api_key}"),
                "content-type": "application/json",
            }),
            json!({
                "model": model,
                "messages": messages,
                "max_tokens": max_tokens,
                "temperature": temperature,
            }),
        )
    };
    let job = PoreJob {
        schema: JOB_SCHEMA.into(),
        kind: "llm_complete".into(),
        dest_host: host,
        dest_port: port,
        url: Some(url),
        method: Some("POST".into()),
        headers,
        body: Some(body),
        tcp_payload: None,
        timeout_ms: Some(60_000),
    };
    execute_job(
        state,
        pore_table::LLM_SYSTEM_AGENT,
        pore_table::LLM_PROVIDER_ADDR,
        job,
    )
}

fn spawn_child(
    state: &PlatformState,
    agent_pid: &str,
    row: &pore_table::PoreRow,
    job: &PoreJob,
) -> Result<Value, String> {
    let bin = pore_bin();
    if !bin.exists() {
        return Err(format!(
            "pore_binary_missing: {} — set CONNECTOR_PORE_BIN",
            bin.display()
        ));
    }
    let mut env = docklock::cage_env_for_intelligence("pore", "pore", agent_pid);
    address_cage::strip_host_identity_env(&mut env);
    address_cage::apply_nsfs_landlock_defaults(agent_pid, &mut env);
    // Network pores need CA/DNS; never the platform data dir or host HOME.
    let mut read = TLS_READ_PATHS.to_string();
    if let Ok(root) = nsfs::nsfs_root(agent_pid) {
        let root = root.canonicalize().unwrap_or(root);
        read = format!("{read}:{}", root.display());
    }
    set_env(&mut env, "CONNECTOR_DOCKLOCK_FS_READ", &read);
    set_env(&mut env, "CONNECTOR_DOCKLOCK_FS_WRITE", "");
    set_env(
        &mut env,
        "CONNECTOR_PLUGIN_SUBPROCESS_SECCOMP_INTENT",
        &row.seccomp_intent,
    );
    set_env(&mut env, "CONNECTOR_DOCKLOCK_LANDLOCK", "1");
    set_env(
        &mut env,
        "CONNECTOR_PORE_DEST",
        &dest_spec(&job.dest_host, job.dest_port),
    );
    set_env(&mut env, "CONNECTOR_PORE_WORKER", "1");
    let allow_vendor = agent_pid.trim() == pore_table::LLM_SYSTEM_AGENT;
    set_env(
        &mut env,
        "CONNECTOR_PORE_ALLOW_VENDOR",
        if allow_vendor { "1" } else { "0" },
    );
    // Never leak platform data / LLM keys via env (job JSON carries provider key only).
    env.retain(|(k, _)| {
        k != "CONNECTOR_DATA_DIR"
            && k != "CONNECTOR_LLM_API_KEY"
            && k != "HOME"
            && k != "USER"
            && k != "CONNECTOR_KERNEL_ROOT_PASS"
    });

    let mut cmd = Command::new(&bin);
    cmd.arg("--pore-worker");
    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    cmd.env_clear();
    for (k, v) in &env {
        cmd.env(k, v);
    }
    // Keep a minimal PATH for the dynamic linker / NSS.
    cmd.env("PATH", "/usr/bin:/bin");
    cmd.env("LANG", "C");

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        unsafe {
            cmd.pre_exec(|| connector_plugin_runtime::linux_hardening::apply_linux_hardening_env());
        }
    }

    let mut child = cmd.spawn().map_err(|e| format!("pore_spawn:{e}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        let payload = serde_json::to_vec(job).map_err(|e| e.to_string())?;
        stdin
            .write_all(&payload)
            .map_err(|e| format!("pore_stdin:{e}"))?;
    }
    let timeout = Duration::from_millis(job.timeout_ms.unwrap_or(15_000) + 2_000);
    let output = wait_with_timeout(child, timeout)?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let parsed: Value = serde_json::from_str(stdout.trim())
        .or_else(|_| serde_json::from_str(stderr.trim()))
        .unwrap_or_else(|_| {
            json!({
                "ok": false,
                "error": "pore_child_output",
                "stdout": stdout.chars().take(800).collect::<String>(),
                "stderr": stderr.chars().take(800).collect::<String>(),
                "exit": output.status.code(),
            })
        });
    if parsed.get("ok").and_then(|v| v.as_bool()) != Some(true) {
        return Err(parsed
            .get("message")
            .or_else(|| parsed.get("error"))
            .and_then(|v| v.as_str())
            .unwrap_or("pore_child_failed")
            .to_string());
    }
    let _ = state;
    Ok(parsed)
}

fn wait_with_timeout(child: std::process::Child, timeout: Duration) -> Result<Output, String> {
    let pid = child.id();
    let handle = std::thread::spawn(move || child.wait_with_output());
    let start = std::time::Instant::now();
    loop {
        if handle.is_finished() {
            return handle
                .join()
                .map_err(|_| "pore_join".to_string())?
                .map_err(|e| format!("pore_wait:{e}"));
        }
        if start.elapsed() > timeout {
            #[cfg(unix)]
            unsafe {
                libc::kill(pid as i32, libc::SIGKILL);
            }
            #[cfg(not(unix))]
            {
                let _ = pid;
            }
            let _ = handle.join();
            return Err("pore_child_timeout".into());
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn set_env(env: &mut Vec<(String, String)>, key: &str, val: &str) {
    if let Some((_, v)) = env.iter_mut().find(|(k, _)| k == key) {
        *v = val.into();
    } else {
        env.push((key.into(), val.into()));
    }
}

fn pore_bin() -> PathBuf {
    if let Ok(p) = std::env::var("CONNECTOR_PORE_BIN") {
        let t = p.trim();
        if !t.is_empty() {
            return PathBuf::from(t);
        }
    }
    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("connector-platform"));
    if exe
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .contains("connector-platform")
    {
        return exe;
    }
    exe.with_file_name("connector-platform")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dest_spec_stable() {
        assert_eq!(dest_spec("API.OpenAI.com", 443), "api.openai.com:443");
    }
}

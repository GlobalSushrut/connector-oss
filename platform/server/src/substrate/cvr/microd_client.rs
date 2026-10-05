//! Client for connector-microd Unix socket (Phase D).
//!
//! When microd is READY, VMM ops prefer the privileged supervisor.
//! In-process MicrovmHost remains the fallback for lab/dev.

use serde_json::{json, Value};
use std::path::PathBuf;

use connector_microvm::FirecrackerVmConfig;

fn sock_path() -> PathBuf {
    std::env::var("CONNECTOR_MICROD_SOCK")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/run/connector/microd.sock"))
}

fn ready_path() -> PathBuf {
    std::env::var("CONNECTOR_MICROD_READY_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/run/connector/microd.ready"))
}

/// True when the Unix socket exists (daemon likely up).
pub fn microd_socket_present() -> bool {
    sock_path().exists()
}

/// Read ready file written by microd prepare/serve.
pub fn ready_file_json() -> Option<Value> {
    let p = ready_path();
    let raw = std::fs::read_to_string(p).ok()?;
    serde_json::from_str(&raw).ok()
}

pub fn microd_verified_ready() -> bool {
    ready_file_json()
        .and_then(|v| v.get("verified").and_then(|x| x.as_bool()))
        .unwrap_or(false)
}

#[cfg(unix)]
fn call(req: Value) -> Result<Value, String> {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    let path = sock_path();
    if !path.exists() {
        return Err("microd_socket_missing".into());
    }
    let mut stream = UnixStream::connect(&path).map_err(|e| format!("connect: {e}"))?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));
    let mut line = req.to_string();
    line.push('\n');
    stream
        .write_all(line.as_bytes())
        .map_err(|e| format!("write: {e}"))?;
    let mut reader = BufReader::new(stream);
    let mut resp = String::new();
    reader
        .read_line(&mut resp)
        .map_err(|e| format!("read: {e}"))?;
    serde_json::from_str(resp.trim()).map_err(|e| format!("parse: {e}"))
}

#[cfg(not(unix))]
fn call(_req: Value) -> Result<Value, String> {
    Err("microd_requires_unix".into())
}

pub fn status() -> Value {
    match call(json!({"op": "status"})) {
        Ok(v) => v,
        Err(e) => json!({
            "ok": false,
            "error": e,
            "ready_file": ready_file_json(),
            "socket": sock_path().display().to_string(),
            "socket_present": microd_socket_present(),
        }),
    }
}

pub fn start_vm(cfg: &FirecrackerVmConfig, use_jailer: bool) -> Result<Value, String> {
    let resp = call(json!({
        "op": "start",
        "cfg": cfg,
        "use_jailer": use_jailer,
    }))?;
    if resp.get("ok").and_then(|v| v.as_bool()) == Some(true) {
        Ok(resp.get("result").cloned().unwrap_or(resp))
    } else {
        Err(resp
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("microd_start_failed")
            .to_string())
    }
}

pub fn pause(api_socket_path: &str) -> Result<Value, String> {
    let resp = call(json!({
        "op": "pause",
        "api_socket_path": api_socket_path,
    }))?;
    if resp.get("ok").and_then(|v| v.as_bool()) == Some(true) {
        Ok(resp.get("result").cloned().unwrap_or(resp))
    } else {
        Err(resp
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("microd_pause_failed")
            .to_string())
    }
}

pub fn resume(api_socket_path: &str) -> Result<Value, String> {
    let resp = call(json!({
        "op": "resume",
        "api_socket_path": api_socket_path,
    }))?;
    if resp.get("ok").and_then(|v| v.as_bool()) == Some(true) {
        Ok(resp.get("result").cloned().unwrap_or(resp))
    } else {
        Err(resp
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("microd_resume_failed")
            .to_string())
    }
}

pub fn stop(api_socket_path: &str, pid: Option<u32>) -> Result<Value, String> {
    let resp = call(json!({
        "op": "stop",
        "api_socket_path": api_socket_path,
        "pid": pid,
    }))?;
    if resp.get("ok").and_then(|v| v.as_bool()) == Some(true) {
        Ok(resp.get("result").cloned().unwrap_or(resp))
    } else {
        Err(resp
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("microd_stop_failed")
            .to_string())
    }
}

pub fn warm_ensure(n: Option<usize>) -> Result<Value, String> {
    let mut req = json!({"op": "warm_ensure"});
    if let Some(n) = n {
        req["n"] = json!(n);
    }
    let resp = call(req)?;
    if resp.get("ok").and_then(|v| v.as_bool()) == Some(true) {
        Ok(resp)
    } else {
        Err(resp
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("microd_warm_ensure_failed")
            .to_string())
    }
}

pub fn posture_json() -> Value {
    let ready = ready_file_json();
    json!({
        "schema": "connector.cvr.microd_client.v1",
        "socket": sock_path().display().to_string(),
        "socket_present": microd_socket_present(),
        "ready_file": ready_path().display().to_string(),
        "ready": ready,
        "prefer_microd": microd_socket_present(),
        "verified": microd_verified_ready(),
        "honesty": "When microd socket is present, Firecracker ops go through privileged supervisor; else in-process MicrovmHost fallback (lab). Live RPC: GET /cvr/microd",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_sock_path() {
        assert!(sock_path().to_string_lossy().contains("microd"));
    }
}

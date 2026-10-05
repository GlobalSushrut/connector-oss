//! Landlock pore worker — dest-pinned world dials, no tool execution.
//!
//! Spawned as `connector-platform --pore-worker` after `pre_exec` Landlock/seccomp.
//! Default DROP: the only allowed TCP/HTTP destination is `CONNECTOR_PORE_DEST`.
//! The model never runs here; this process cannot dispatch tools.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

pub const JOB_SCHEMA: &str = "connector.pore.job.v1";
pub const RESULT_SCHEMA: &str = "connector.pore.result.v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoreJob {
    pub schema: String,
    pub kind: String,
    pub dest_host: String,
    pub dest_port: u16,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub headers: Value,
    #[serde(default)]
    pub body: Option<Value>,
    #[serde(default)]
    pub tcp_payload: Option<String>,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

/// Child entry. Must not boot the platform.
pub fn run() -> i32 {
    let dest = std::env::var("CONNECTOR_PORE_DEST").unwrap_or_default();
    let mut buf = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut buf) {
        emit_err("stdin", &e.to_string());
        return 2;
    }
    let job: PoreJob = match serde_json::from_str(&buf) {
        Ok(j) => j,
        Err(e) => {
            emit_err("job_decode", &e.to_string());
            return 2;
        }
    };
    match execute_job(&dest, &job) {
        Ok(v) => {
            println!("{}", v);
            0
        }
        Err(e) => {
            emit_err("pore_denied", &e);
            3
        }
    }
}

pub fn dest_spec(host: &str, port: u16) -> String {
    format!("{}:{}", host.trim().to_ascii_lowercase(), port)
}

/// Userspace iptables: destination must match the pore row exactly.
pub fn dest_allowed(pinned: &str, host: &str, port: u16) -> bool {
    let want = dest_spec(host, port);
    pinned.trim().eq_ignore_ascii_case(&want)
}

fn execute_job(pinned: &str, job: &PoreJob) -> Result<String, String> {
    if job.schema != JOB_SCHEMA {
        return Err("pore_job_schema".into());
    }
    if !dest_allowed(pinned, &job.dest_host, job.dest_port) {
        return Err(format!(
            "pore_dest_mismatch: pinned={pinned} got={}:{}",
            job.dest_host, job.dest_port
        ));
    }
    if crate::substrate::egress_policy::is_direct_llm_provider_host(&job.dest_host) {
        let allow = std::env::var("CONNECTOR_PORE_ALLOW_VENDOR")
            .ok()
            .map(|s| s.trim() == "1")
            .unwrap_or(false);
        if !allow {
            return Err(format!(
                "vendor_exclusive: {} is Connector LLM cage only — tool cannot talk to the vendor directly",
                job.dest_host
            ));
        }
    }
    if let Some(url) = job.url.as_deref() {
        let (uh, up) = parse_url_host_port(url)?;
        if !dest_allowed(pinned, &uh, up) {
            return Err(format!("pore_url_dest_mismatch: {url}"));
        }
    }
    let timeout = Duration::from_millis(job.timeout_ms.unwrap_or(15_000).max(500));
    match job.kind.as_str() {
        "probe" => Ok(json!({
            "schema": RESULT_SCHEMA,
            "ok": true,
            "kind": "probe",
            "dest": dest_spec(&job.dest_host, job.dest_port),
            "landlock_env": std::env::var("CONNECTOR_DOCKLOCK_LANDLOCK").ok(),
            "seccomp_intent": std::env::var("CONNECTOR_PLUGIN_SUBPROCESS_SECCOMP_INTENT").ok(),
            "tool_execution": false,
            "honesty": "Pore worker has no tool dispatcher — LLM cannot bypass via this child",
        })
        .to_string()),
        "tcp_send" => tcp_send(job, timeout),
        "http_fetch" | "llm_complete" => http_fetch(job, timeout),
        other => Err(format!("unknown_pore_kind:{other}")),
    }
}

fn tcp_send(job: &PoreJob, timeout: Duration) -> Result<String, String> {
    let addr = format!("{}:{}", job.dest_host.trim(), job.dest_port);
    let mut stream = TcpStream::connect(&addr).map_err(|e| format!("tcp_connect:{e}"))?;
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));
    let mut payload = job.tcp_payload.clone().unwrap_or_default().into_bytes();
    if payload.is_empty() {
        if let Some(body) = &job.body {
            payload = serde_json::to_vec(body).unwrap_or_default();
            payload.push(b'\n');
        }
    }
    stream
        .write_all(&payload)
        .map_err(|e| format!("tcp_write:{e}"))?;
    let mut buf = vec![0u8; 8192];
    let n = stream.read(&mut buf).unwrap_or(0);
    Ok(json!({
        "schema": RESULT_SCHEMA,
        "ok": true,
        "kind": "tcp_send",
        "bytes_written": payload.len(),
        "ack_raw": String::from_utf8_lossy(&buf[..n]),
        "tool_execution": false,
    })
    .to_string())
}

fn http_fetch(job: &PoreJob, timeout: Duration) -> Result<String, String> {
    let url = job
        .url
        .as_deref()
        .ok_or_else(|| "pore_url_required".to_string())?;
    let method = job
        .method
        .as_deref()
        .unwrap_or("GET")
        .to_ascii_uppercase();
    let client = reqwest::blocking::Client::builder()
        .timeout(timeout)
        .connect_timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| e.to_string())?;
    let mut req = match method.as_str() {
        "POST" => client.post(url),
        "PUT" => client.put(url),
        "PATCH" => client.patch(url),
        "DELETE" => client.delete(url),
        _ => client.get(url),
    };
    if let Some(obj) = job.headers.as_object() {
        for (k, v) in obj {
            if let Some(s) = v.as_str() {
                req = req.header(k, s);
            }
        }
    }
    if let Some(body) = &job.body {
        req = req.json(body);
    }
    let resp = req.send().map_err(|e| format!("http:{e}"))?;
    let status = resp.status().as_u16();
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let location = resp
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let text = resp.text().unwrap_or_default();
    let parsed: Value = serde_json::from_str(&text).unwrap_or(Value::String(text.clone()));
    Ok(json!({
        "schema": RESULT_SCHEMA,
        "ok": (200..300).contains(&status),
        "kind": job.kind,
        "status": status,
        "content_type": content_type,
        "location": location,
        "body": parsed,
        "tool_execution": false,
        "honesty": "HTTP completed inside dest-pinned Landlock child — no tool dispatch",
    })
    .to_string())
}

pub fn parse_url_host_port(url: &str) -> Result<(String, u16), String> {
    let s = url.trim();
    if s.starts_with("http://") || s.starts_with("https://") {
        return parse_http_url_host_port(s);
    }
    parse_hostport(s)
}

fn parse_http_url_host_port(s: &str) -> Result<(String, u16), String> {
    let https = s.starts_with("https://");
    let rest = s
        .strip_prefix("https://")
        .or_else(|| s.strip_prefix("http://"))
        .ok_or_else(|| "pore_url_not_http".to_string())?;
    parse_authority(
        rest.split('/').next().unwrap_or(rest),
        if https { 443 } else { 80 },
    )
}

fn parse_hostport(s: &str) -> Result<(String, u16), String> {
    let rest = s
        .split("://")
        .nth(1)
        .unwrap_or(s)
        .split('/')
        .next()
        .unwrap_or(s);
    parse_authority(rest, 443)
}

fn parse_authority(rest: &str, default: u16) -> Result<(String, u16), String> {
    let authority = rest.split('?').next().unwrap_or(rest);
    let hostport = authority.rsplit('@').next().unwrap_or(authority).trim();
    if let Some(inner) = hostport.strip_prefix('[') {
        let (host, after) = inner
            .split_once(']')
            .ok_or_else(|| "pore_url_bad_ipv6".to_string())?;
        let port = after
            .strip_prefix(':')
            .and_then(|p| p.parse().ok())
            .unwrap_or(default);
        return Ok((host.to_ascii_lowercase(), port));
    }
    if let Some((h, p)) = hostport.rsplit_once(':') {
        if p.chars().all(|c| c.is_ascii_digit()) {
            return Ok((h.to_ascii_lowercase(), p.parse().unwrap_or(default)));
        }
    }
    Ok((hostport.to_ascii_lowercase(), default))
}

fn emit_err(code: &str, msg: &str) {
    let v = json!({
        "schema": RESULT_SCHEMA,
        "ok": false,
        "error": code,
        "message": msg,
        "tool_execution": false,
    });
    eprintln!("{v}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dest_pin_is_exact() {
        assert!(dest_allowed("api.anthropic.com:443", "api.anthropic.com", 443));
        assert!(!dest_allowed("api.anthropic.com:443", "evil.example", 443));
        assert!(!dest_allowed("api.anthropic.com:443", "api.anthropic.com", 80));
    }

    #[test]
    fn url_host_must_match_pin() {
        let (h, p) = parse_url_host_port("https://api.openai.com/v1/chat/completions").unwrap();
        assert_eq!(h, "api.openai.com");
        assert_eq!(p, 443);
        assert!(!dest_allowed("api.openai.com:443", "127.0.0.1", 443));
    }

    #[test]
    fn vendor_dest_denied_without_allow_flag() {
        let prev = std::env::var("CONNECTOR_PORE_ALLOW_VENDOR").ok();
        std::env::remove_var("CONNECTOR_PORE_ALLOW_VENDOR");
        let job = PoreJob {
            schema: JOB_SCHEMA.into(),
            kind: "probe".into(),
            dest_host: "api.anthropic.com".into(),
            dest_port: 443,
            url: None,
            method: None,
            headers: json!({}),
            body: None,
            tcp_payload: None,
            timeout_ms: Some(500),
        };
        let err = execute_job("api.anthropic.com:443", &job).unwrap_err();
        assert!(err.contains("vendor_exclusive"), "{err}");
        std::env::set_var("CONNECTOR_PORE_ALLOW_VENDOR", "1");
        let ok = execute_job("api.anthropic.com:443", &job).unwrap();
        assert!(ok.contains("\"ok\":true") || ok.contains("\"ok\": true"));
        match prev {
            Some(v) => std::env::set_var("CONNECTOR_PORE_ALLOW_VENDOR", v),
            None => std::env::remove_var("CONNECTOR_PORE_ALLOW_VENDOR"),
        }
    }
}

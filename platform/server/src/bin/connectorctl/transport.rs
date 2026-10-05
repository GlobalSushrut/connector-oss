//! HTTP/host transport — no silent fallbacks, no automatic `dev-token`.

use crate::output::{ExitCode, GlobalOpts};
use serde_json::Value;
use std::time::Duration;

#[derive(Debug)]
pub enum TransportError {
    Network(String),
    Http { status: u16, body: String },
    Auth,
    Decode(String),
}

impl TransportError {
    pub fn exit_code(&self) -> ExitCode {
        match self {
            Self::Auth => ExitCode::Auth,
            Self::Http { status, .. } if *status == 401 || *status == 403 => ExitCode::Auth,
            Self::Http { status, .. } if *status == 404 => ExitCode::Unavailable,
            Self::Http { status, .. } if *status == 409 || *status == 422 => ExitCode::Refused,
            Self::Network(_) => ExitCode::Unavailable,
            _ => ExitCode::Failure,
        }
    }

    pub fn message(&self) -> String {
        match self {
            Self::Network(e) => format!("node unreachable: {e}"),
            Self::Http { status, body } => {
                let snippet = body.chars().take(200).collect::<String>();
                format!("HTTP {status}: {snippet}")
            }
            Self::Auth => "authentication/authorization failed".into(),
            Self::Decode(e) => format!("response decode failed: {e}"),
        }
    }
}

pub struct Client<'a> {
    opts: &'a GlobalOpts,
    http: reqwest::blocking::Client,
}

impl<'a> Client<'a> {
    pub fn new(opts: &'a GlobalOpts) -> Result<Self, String> {
        let http = reqwest::blocking::Client::builder()
            .timeout(opts.timeout)
            .connect_timeout(Duration::from_secs(5))
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Self { opts, http })
    }

    pub fn url(&self, path: &str) -> String {
        if path.starts_with("http://") || path.starts_with("https://") {
            return path.to_string();
        }
        format!("{}{}", self.opts.endpoint, path)
    }

    pub fn get_json(&self, path: &str) -> Result<Value, TransportError> {
        self.request_json(reqwest::Method::GET, path, None)
    }

    pub fn post_json(&self, path: &str, body: Value) -> Result<Value, TransportError> {
        self.request_json(reqwest::Method::POST, path, Some(body))
    }

    pub fn patch_json(&self, path: &str, body: Value) -> Result<Value, TransportError> {
        self.request_json(reqwest::Method::PATCH, path, Some(body))
    }

    pub fn delete_json(&self, path: &str) -> Result<Value, TransportError> {
        self.request_json(reqwest::Method::DELETE, path, None)
    }

    fn request_json(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<Value, TransportError> {
        let url = self.url(path);
        let mut req = self.http.request(method, &url);
        if let Some(key) = &self.opts.api_key {
            req = req.header("Authorization", format!("Bearer {key}"));
        }
        if let Some(b) = body {
            req = req.json(&b);
        }
        let resp = req.send().map_err(|e| TransportError::Network(e.to_string()))?;
        let status = resp.status().as_u16();
        let text = resp.text().unwrap_or_default();
        if status == 401 || status == 403 {
            return Err(TransportError::Auth);
        }
        if !(200..300).contains(&status) {
            return Err(TransportError::Http { status, body: text });
        }
        if text.trim().is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_str(&text).map_err(|e| TransportError::Decode(e.to_string()))
    }
}

/// Probe liveness without inventing success from unrelated endpoints.
pub fn probe_health(opts: &GlobalOpts) -> Result<(String, Value), TransportError> {
    let client = Client::new(opts).map_err(TransportError::Network)?;
    for path in ["/healthz", "/health"] {
        match client.get_json(path) {
            Ok(v) => return Ok((path.to_string(), v)),
            Err(TransportError::Http { status: 404, .. }) => continue,
            Err(e) => return Err(e),
        }
    }
    Err(TransportError::Http {
        status: 404,
        body: "neither /healthz nor /health available".into(),
    })
}

pub fn systemctl(args: &[&str]) -> Result<std::process::Output, String> {
    std::process::Command::new("systemctl")
        .args(args)
        .output()
        .map_err(|e| format!("systemctl failed: {e}"))
}

pub fn journalctl(unit: &str, lines: u32, follow: bool) -> Result<i32, String> {
    let mut cmd = std::process::Command::new("journalctl");
    cmd.args(["-u", unit, "-n", &lines.to_string(), "--no-pager"]);
    if follow {
        cmd.arg("-f");
    }
    let status = cmd.status().map_err(|e| format!("journalctl failed: {e}"))?;
    Ok(status.code().unwrap_or(1))
}

pub fn prefer_unit() -> &'static str {
    if systemctl(&["cat", "connector-platform"])
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        "connector-platform"
    } else if systemctl(&["cat", "connector-node"])
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        "connector-node"
    } else {
        "connector-platform"
    }
}

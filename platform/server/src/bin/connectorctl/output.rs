//! Shared flags, exit codes, and versioned result envelopes.

use serde_json::{json, Value};
use std::io::IsTerminal;
use std::time::Duration;

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitCode {
    Success = 0,
    Usage = 2,
    Unavailable = 3,
    Auth = 4,
    Refused = 5,
    Degraded = 6,
    Failure = 7,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputMode {
    Human,
    Json,
}

#[derive(Debug, Clone)]
pub struct GlobalOpts {
    pub endpoint: String,
    pub api_key: Option<String>,
    pub timeout: Duration,
    pub output: OutputMode,
    pub no_color: bool,
    pub yes: bool,
}

impl GlobalOpts {
    pub fn parse(args: &[String]) -> Result<(Self, Vec<String>), String> {
        let mut endpoint = std::env::var("CONNECTOR_API_URL")
            .or_else(|_| std::env::var("CONNECTOR_URL"))
            .unwrap_or_else(|_| "http://127.0.0.1:9091".into());
        let mut api_key = load_api_key();
        let mut timeout = Duration::from_secs(
            std::env::var("CONNECTOR_TIMEOUT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(15),
        );
        let mut output = if std::env::var("CONNECTOR_OUTPUT")
            .map(|v| v.eq_ignore_ascii_case("json"))
            .unwrap_or(false)
        {
            OutputMode::Json
        } else {
            OutputMode::Human
        };
        let mut no_color = std::env::var("NO_COLOR").is_ok() || !std::io::stdout().is_terminal();
        let mut yes = false;
        let mut rest = Vec::new();
        let mut i = 0;
        while i < args.len() {
            match args[i].as_str() {
                "--endpoint" | "--url" => {
                    endpoint = args
                        .get(i + 1)
                        .ok_or("usage: --endpoint requires a URL")?
                        .clone();
                    i += 2;
                }
                "--api-key-file" => {
                    let path = args
                        .get(i + 1)
                        .ok_or("usage: --api-key-file requires a path")?;
                    let raw = std::fs::read_to_string(path)
                        .map_err(|e| format!("read api-key-file {path}: {e}"))?;
                    api_key = Some(raw.trim().to_string());
                    i += 2;
                }
                "--timeout" => {
                    let secs: u64 = args
                        .get(i + 1)
                        .ok_or("usage: --timeout requires seconds")?
                        .parse()
                        .map_err(|_| "usage: --timeout must be an integer (seconds)".to_string())?;
                    timeout = Duration::from_secs(secs.max(1));
                    i += 2;
                }
                "--output" => {
                    let mode = args
                        .get(i + 1)
                        .ok_or("usage: --output requires human|json")?;
                    output = match mode.as_str() {
                        "json" => OutputMode::Json,
                        "human" => OutputMode::Human,
                        other => return Err(format!("usage: unknown --output {other}")),
                    };
                    i += 2;
                }
                "--json" => {
                    output = OutputMode::Json;
                    i += 1;
                }
                "--no-color" => {
                    no_color = true;
                    i += 1;
                }
                "--yes" | "-y" => {
                    yes = true;
                    i += 1;
                }
                "--help" | "-h" if rest.is_empty() => {
                    rest.push("help".into());
                    i += 1;
                }
                "--version" | "-V" if rest.is_empty() => {
                    rest.push("version".into());
                    i += 1;
                }
                arg if arg.starts_with('-') => {
                    return Err(format!("usage: unknown global flag {arg}"));
                }
                arg => {
                    rest.push(arg.to_string());
                    i += 1;
                }
            }
        }
        Ok((
            Self {
                endpoint: endpoint.trim_end_matches('/').to_string(),
                api_key,
                timeout,
                output,
                no_color,
                yes,
            },
            rest,
        ))
    }

    pub fn is_tty(&self) -> bool {
        !self.no_color && std::io::stdout().is_terminal()
    }
}

fn load_api_key() -> Option<String> {
    if let Ok(path) = std::env::var("CONNECTOR_API_KEY_FILE") {
        if let Ok(raw) = std::fs::read_to_string(&path) {
            let t = raw.trim();
            if !t.is_empty() {
                return Some(t.to_string());
            }
        }
    }
    std::env::var("CONNECTOR_API_KEY")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

#[derive(Debug, Clone)]
pub struct Provenance {
    pub kind: &'static str,
    pub method: Option<&'static str>,
    pub route: Option<String>,
    pub detail: Option<String>,
}

impl Provenance {
    pub fn api(method: &'static str, route: impl Into<String>) -> Self {
        Self {
            kind: "node_api",
            method: Some(method),
            route: Some(route.into()),
            detail: None,
        }
    }

    pub fn host(detail: impl Into<String>) -> Self {
        Self {
            kind: "host",
            method: None,
            route: None,
            detail: Some(detail.into()),
        }
    }
}

pub struct CmdResult {
    pub ok: bool,
    pub command: String,
    pub exit: ExitCode,
    pub source: Provenance,
    pub data: Value,
    pub warnings: Vec<String>,
    pub error: Option<String>,
}

impl CmdResult {
    pub fn emit(self, opts: &GlobalOpts) -> ExitCode {
        match opts.output {
            OutputMode::Json => {
                let envelope = json!({
                    "schema": "connector.ctl.result.v1",
                    "ok": self.ok,
                    "command": self.command,
                    "source": {
                        "kind": self.source.kind,
                        "method": self.source.method,
                        "route": self.source.route,
                        "detail": self.source.detail,
                        "observed_at": chrono::Utc::now().to_rfc3339(),
                    },
                    "data": self.data,
                    "warnings": self.warnings,
                    "error": self.error,
                });
                println!("{}", serde_json::to_string_pretty(&envelope).unwrap_or_else(|_| "{}".into()));
            }
            OutputMode::Human => {
                if let Some(err) = &self.error {
                    eprintln!("{err}");
                }
                for w in &self.warnings {
                    eprintln!("warning: {w}");
                }
                print_human(&self);
            }
        }
        self.exit
    }
}

fn print_human(r: &CmdResult) {
    if let Some(obj) = r.data.as_object() {
        if let Some(lines) = obj.get("_human").and_then(|v| v.as_array()) {
            for line in lines {
                if let Some(s) = line.as_str() {
                    println!("{s}");
                }
            }
            return;
        }
    }
    if r.ok {
        if r.data.is_null() {
            println!("ok");
        } else {
            println!("{}", serde_json::to_string_pretty(&r.data).unwrap_or_else(|_| r.data.to_string()));
        }
    }
}

pub fn human_lines(lines: Vec<String>) -> Value {
    json!({ "_human": lines })
}

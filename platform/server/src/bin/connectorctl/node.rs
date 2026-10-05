//! `connectorctl node` — lifecycle and diagnosis.

use crate::output::{
    CmdResult, ExitCode, GlobalOpts, Provenance, human_lines,
};
use crate::transport::{self, Client};
use serde_json::{json, Value};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

pub fn run(opts: &GlobalOpts, args: &[String]) -> Result<ExitCode, String> {
    let verb = args.first().map(|s| s.as_str()).unwrap_or("status");
    let rest = if args.is_empty() { &[][..] } else { &args[1..] };
    match verb {
        "status" => status(opts),
        "health" => health(opts),
        "doctor" => doctor(opts),
        "logs" => logs(opts, rest),
        "start" => start(opts, rest),
        "stop" => stop(opts),
        "restart" => {
            let _ = stop(opts)?;
            std::thread::sleep(Duration::from_millis(500));
            start(opts, rest)
        }
        "support-bundle" => support_bundle(opts, rest),
        "config" => config(opts, rest),
        _ => Err(format!(
            "usage: connectorctl node <start|stop|restart|status|health|doctor|logs|support-bundle|config>"
        )),
    }
}

fn status(opts: &GlobalOpts) -> Result<ExitCode, String> {
    let client = Client::new(opts)?;
    let mut warnings = vec![];
    let mut data = json!({});

    match transport::probe_health(opts) {
        Ok((route, v)) => {
            data["health"] = v;
            data["health_route"] = json!(route);
        }
        Err(e) => {
            return Ok(CmdResult {
                ok: false,
                command: "node status".into(),
                exit: e.exit_code(),
                source: Provenance::api("GET", "/healthz"),
                data: json!({}),
                warnings,
                error: Some(e.message()),
            }
            .emit(opts));
        }
    }

    match client.get_json("/readyz") {
        Ok(v) => data["ready"] = v,
        Err(e) => warnings.push(format!("readyz: {}", e.message())),
    }
    match client.get_json("/api/v1/monitor/health") {
        Ok(v) => data["monitor"] = v,
        Err(e) => warnings.push(format!("monitor/health: {}", e.message())),
    }

    let unit = transport::prefer_unit();
    if let Ok(out) = transport::systemctl(&["is-active", unit]) {
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        data["systemd_unit"] = json!(unit);
        data["systemd_active"] = json!(s);
    }

    let healthy = data
        .pointer("/health")
        .map(|h| {
            h.get("status")
                .and_then(|s| s.as_str())
                .map(|s| s.eq_ignore_ascii_case("ok") || s.eq_ignore_ascii_case("healthy"))
                .unwrap_or(h.get("ok").and_then(|v| v.as_bool()).unwrap_or(true))
        })
        .unwrap_or(false);

    let lines = vec![
        format!(
            "node: {} | unit={} active={}",
            if healthy { "up" } else { "degraded" },
            data.get("systemd_unit").and_then(|v| v.as_str()).unwrap_or("n/a"),
            data.get("systemd_active").and_then(|v| v.as_str()).unwrap_or("n/a")
        ),
        format!(
            "health_route: {}",
            data.get("health_route").and_then(|v| v.as_str()).unwrap_or("?")
        ),
    ];

    Ok(CmdResult {
        ok: healthy && warnings.is_empty(),
        command: "node status".into(),
        exit: if healthy {
            if warnings.is_empty() {
                ExitCode::Success
            } else {
                ExitCode::Degraded
            }
        } else {
            ExitCode::Failure
        },
        source: Provenance::api("GET", "/healthz+/readyz+/api/v1/monitor/health"),
        data: merge_human(data, lines, opts),
        warnings,
        error: None,
    }
    .emit(opts))
}

fn health(opts: &GlobalOpts) -> Result<ExitCode, String> {
    match transport::probe_health(opts) {
        Ok((route, v)) => {
            let ok = v
                .get("status")
                .and_then(|s| s.as_str())
                .map(|s| s.eq_ignore_ascii_case("ok") || s.eq_ignore_ascii_case("healthy"))
                .or_else(|| v.get("ok").and_then(|b| b.as_bool()))
                .unwrap_or(true);
            Ok(CmdResult {
                ok,
                command: "node health".into(),
                exit: if ok {
                    ExitCode::Success
                } else {
                    ExitCode::Failure
                },
                source: Provenance::api("GET", route.clone()),
                data: merge_human(
                    json!({ "route": route, "body": v }),
                    vec![if ok {
                        "HEALTHY".into()
                    } else {
                        "UNHEALTHY".into()
                    }],
                    opts,
                ),
                warnings: vec![],
                error: None,
            }
            .emit(opts))
        }
        Err(e) => Ok(CmdResult {
            ok: false,
            command: "node health".into(),
            exit: e.exit_code(),
            source: Provenance::api("GET", "/healthz"),
            data: json!({}),
            warnings: vec![],
            error: Some(e.message()),
        }
        .emit(opts)),
    }
}

fn doctor(opts: &GlobalOpts) -> Result<ExitCode, String> {
    let client = Client::new(opts)?;
    let mut warnings = vec![];
    let mut data = json!({
        "ui_mount": std::env::var("CONNECTOR_UI_DIR").unwrap_or_else(|_| "(unset — embed or search path)".into()),
        "endpoint": opts.endpoint,
    });

    let mut ok = true;
    match transport::probe_health(opts) {
        Ok((route, v)) => {
            data["health_route"] = json!(route);
            data["health"] = v;
        }
        Err(e) => {
            ok = false;
            warnings.push(e.message());
        }
    }
    for (key, path) in [
        ("ready", "/readyz"),
        ("version", "/version"),
        ("monitor", "/api/v1/monitor/health"),
        ("substrate", "/api/v1/substrate/status"),
        ("runtime_mode", "/api/v1/runtime/mode"),
    ] {
        match client.get_json(path) {
            Ok(v) => data[key] = v,
            Err(e) => {
                warnings.push(format!("{path}: {}", e.message()));
                data[key] = Value::Null;
            }
        }
    }

    let unit = transport::prefer_unit();
    data["systemd_unit"] = json!(unit);
    if let Ok(out) = transport::systemctl(&["is-active", unit]) {
        data["systemd_active"] = json!(String::from_utf8_lossy(&out.stdout).trim());
    }

    let lines = vec![
        format!(
            "doctor: {} | endpoint={}",
            if ok && warnings.is_empty() {
                "ok"
            } else if ok {
                "degraded"
            } else {
                "fail"
            },
            opts.endpoint
        ),
        format!(
            "systemd: {}={}",
            unit,
            data.get("systemd_active").and_then(|v| v.as_str()).unwrap_or("unknown")
        ),
        format!(
            "sources: health={} monitor={} substrate={}",
            if data.get("health").map(|v| !v.is_null()).unwrap_or(false) {
                "ok"
            } else {
                "missing"
            },
            if data.get("monitor").map(|v| !v.is_null()).unwrap_or(false) {
                "ok"
            } else {
                "missing"
            },
            if data.get("substrate").map(|v| !v.is_null()).unwrap_or(false) {
                "ok"
            } else {
                "missing"
            }
        ),
    ];

    Ok(CmdResult {
        ok: ok && warnings.is_empty(),
        command: "node doctor".into(),
        exit: if !ok {
            ExitCode::Failure
        } else if warnings.is_empty() {
            ExitCode::Success
        } else {
            ExitCode::Degraded
        },
        source: Provenance::api("GET", "doctor probe set"),
        data: merge_human(data, lines, opts),
        warnings,
        error: None,
    }
    .emit(opts))
}

fn logs(opts: &GlobalOpts, args: &[String]) -> Result<ExitCode, String> {
    let follow = args.iter().any(|a| a == "-f" || a == "--follow");
    let lines = args
        .iter()
        .position(|a| a == "-n" || a == "--lines")
        .and_then(|i| args.get(i + 1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(50u32);
    let unit = transport::prefer_unit();
    if opts.output == crate::output::OutputMode::Json && follow {
        return Err("usage: --output json cannot combine with --follow".into());
    }
    if follow || opts.output == crate::output::OutputMode::Human {
        let code = transport::journalctl(unit, lines, follow)?;
        return Ok(if code == 0 {
            ExitCode::Success
        } else {
            ExitCode::Failure
        });
    }
    let out = Command::new("journalctl")
        .args(["-u", unit, "-n", &lines.to_string(), "--no-pager"])
        .output()
        .map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&out.stdout);
    let log_lines: Vec<String> = text.lines().map(|s| s.to_string()).collect();
    Ok(CmdResult {
        ok: out.status.success(),
        command: "node logs".into(),
        exit: if out.status.success() {
            ExitCode::Success
        } else {
            ExitCode::Failure
        },
        source: Provenance::host(format!("journalctl -u {unit}")),
        data: json!({ "unit": unit, "lines": log_lines }),
        warnings: vec![],
        error: None,
    }
    .emit(opts))
}

fn start(opts: &GlobalOpts, args: &[String]) -> Result<ExitCode, String> {
    let foreground = args.iter().any(|a| a == "--foreground" || a == "-f");
    let unit = transport::prefer_unit();

    if !foreground {
        if let Ok(out) = transport::systemctl(&["start", unit]) {
            if out.status.success() {
                let _ = wait_health(opts, Duration::from_secs(60));
                return Ok(CmdResult {
                    ok: true,
                    command: "node start".into(),
                    exit: ExitCode::Success,
                    source: Provenance::host(format!("systemctl start {unit}")),
                    data: merge_human(
                        json!({ "method": "systemd", "unit": unit }),
                        vec![
                            format!("started via systemd ({unit})"),
                            format!("dashboard: {}/", opts.endpoint),
                        ],
                        opts,
                    ),
                    warnings: vec![],
                    error: None,
                }
                .emit(opts));
            }
        }
    }

    let bin = find_platform_binary()?;
    if foreground {
        let status = Command::new(&bin)
            .envs(std::env::vars())
            .status()
            .map_err(|e| e.to_string())?;
        return Ok(if status.success() {
            ExitCode::Success
        } else {
            ExitCode::Failure
        });
    }

    let child = Command::new(&bin)
        .envs(std::env::vars())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("spawn {bin}: {e}"))?;
    let pid = child.id();
    let _ = wait_health(opts, Duration::from_secs(60));
    Ok(CmdResult {
        ok: true,
        command: "node start".into(),
        exit: ExitCode::Success,
        source: Provenance::host(format!("spawn {bin}")),
        data: merge_human(
            json!({ "method": "spawn", "binary": bin, "pid": pid }),
            vec![
                format!("started {bin} pid={pid}"),
                format!("dashboard: {}/", opts.endpoint),
            ],
            opts,
        ),
        warnings: vec![],
        error: None,
    }
    .emit(opts))
}

fn stop(opts: &GlobalOpts) -> Result<ExitCode, String> {
    let unit = transport::prefer_unit();
    if let Ok(out) = transport::systemctl(&["stop", unit]) {
        if out.status.success() {
            return Ok(CmdResult {
                ok: true,
                command: "node stop".into(),
                exit: ExitCode::Success,
                source: Provenance::host(format!("systemctl stop {unit}")),
                data: merge_human(
                    json!({ "method": "systemd", "unit": unit }),
                    vec![format!("stopped {unit}")],
                    opts,
                ),
                warnings: vec![],
                error: None,
            }
            .emit(opts));
        }
    }
    // Local pid file fallback
    let data_dir = std::env::var("CONNECTOR_DATA_DIR").unwrap_or_else(|_| "./data".into());
    let pid_path = format!("{data_dir}/connector.pid");
    if let Ok(pid_s) = std::fs::read_to_string(&pid_path) {
        if let Ok(pid) = pid_s.trim().parse::<i32>() {
            let _ = Command::new("kill").args(["-TERM", &pid.to_string()]).status();
            let _ = std::fs::remove_file(&pid_path);
            return Ok(CmdResult {
                ok: true,
                command: "node stop".into(),
                exit: ExitCode::Success,
                source: Provenance::host(format!("kill -TERM {pid}")),
                data: merge_human(
                    json!({ "method": "signal", "pid": pid }),
                    vec![format!("signaled pid {pid}")],
                    opts,
                ),
                warnings: vec![],
                error: None,
            }
            .emit(opts));
        }
    }
    Ok(CmdResult {
        ok: false,
        command: "node stop".into(),
        exit: ExitCode::Unavailable,
        source: Provenance::host("systemd/pid"),
        data: json!({}),
        warnings: vec![],
        error: Some("could not stop node (no systemd unit active and no pid file)".into()),
    }
    .emit(opts))
}

fn support_bundle(opts: &GlobalOpts, args: &[String]) -> Result<ExitCode, String> {
    let mut out_path = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--out" | "-o" => {
                out_path = args.get(i + 1).cloned();
                i += 2;
            }
            other if other.starts_with('-') => {
                return Err(format!("usage: unknown flag {other}"));
            }
            _ => i += 1,
        }
    }
    let client = Client::new(opts)?;
    match client.get_json("/api/v1/support/bundle") {
        Ok(v) => {
            if v.get("ok").and_then(|b| b.as_bool()) == Some(false) {
                let err = v
                    .get("error")
                    .and_then(|e| e.as_str())
                    .unwrap_or("support bundle refused")
                    .to_string();
                return Ok(CmdResult {
                    ok: false,
                    command: "node support-bundle".into(),
                    exit: ExitCode::Auth,
                    source: Provenance::api("GET", "/api/v1/support/bundle"),
                    data: v,
                    warnings: vec![],
                    error: Some(err),
                }
                .emit(opts));
            }
            if let Some(path) = out_path {
                let pretty = serde_json::to_string_pretty(&v).map_err(|e| e.to_string())?;
                std::fs::write(&path, &pretty).map_err(|e| format!("write {path}: {e}"))?;
                return Ok(CmdResult {
                    ok: true,
                    command: "node support-bundle".into(),
                    exit: ExitCode::Success,
                    source: Provenance::api("GET", "/api/v1/support/bundle"),
                    data: merge_human(
                        json!({ "path": path }),
                        vec![format!("wrote redacted support bundle → {path}")],
                        opts,
                    ),
                    warnings: vec![],
                    error: None,
                }
                .emit(opts));
            }
            Ok(CmdResult {
                ok: true,
                command: "node support-bundle".into(),
                exit: ExitCode::Success,
                source: Provenance::api("GET", "/api/v1/support/bundle"),
                data: v,
                warnings: vec![],
                error: None,
            }
            .emit(opts))
        }
        Err(e) => Ok(CmdResult {
            ok: false,
            command: "node support-bundle".into(),
            exit: e.exit_code(),
            source: Provenance::api("GET", "/api/v1/support/bundle"),
            data: json!({}),
            warnings: vec![],
            error: Some(e.message()),
        }
        .emit(opts)),
    }
}

fn config(opts: &GlobalOpts, args: &[String]) -> Result<ExitCode, String> {
    let sub = args.first().map(|s| s.as_str()).unwrap_or("show");
    match sub {
        "show" => {
            let path = std::env::var("CONNECTOR_CONFIG_FILE")
                .unwrap_or_else(|_| "/etc/connector/connector.yaml".into());
            let mut data = json!({
                "CONNECTOR_CONFIG_FILE": path,
                "CONNECTOR_DATA_DIR": std::env::var("CONNECTOR_DATA_DIR").ok(),
                "CONNECTOR_UI_DIR": std::env::var("CONNECTOR_UI_DIR").ok(),
                "CONNECTOR_ENV": std::env::var("CONNECTOR_ENV").ok(),
                "endpoint": opts.endpoint,
            });
            if Path::new(&path).is_file() {
                let raw = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
                data["config_bytes"] = json!(raw.len());
                data["config_present"] = json!(true);
            } else {
                data["config_present"] = json!(false);
            }
            // Prefer live runtime mode when node is up
            let mut warnings = vec![];
            if let Ok(c) = Client::new(opts) {
                match c.get_json("/api/v1/runtime/mode") {
                    Ok(v) => data["runtime_mode"] = v,
                    Err(e) => warnings.push(e.message()),
                }
            }
            Ok(CmdResult {
                ok: true,
                command: "node config show".into(),
                exit: ExitCode::Success,
                source: Provenance::host("env + optional GET /api/v1/runtime/mode"),
                data,
                warnings,
                error: None,
            }
            .emit(opts))
        }
        "validate" => Ok(CmdResult {
            ok: false,
            command: "node config validate".into(),
            exit: ExitCode::Unavailable,
            source: Provenance::host("command registry"),
            data: json!({}),
            warnings: vec![],
            error: Some(
                "config validate unavailable: no GET /api/v1/config/validate route is registered"
                    .into(),
            ),
        }
        .emit(opts)),
        _ => Err("usage: connectorctl node config <show|validate>".into()),
    }
}

fn wait_health(opts: &GlobalOpts, timeout: Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if transport::probe_health(opts).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    false
}

fn find_platform_binary() -> Result<String, String> {
    if let Ok(p) = std::env::var("CONNECTOR_PLATFORM_BIN") {
        if Path::new(&p).is_file() {
            return Ok(p);
        }
    }
    for c in [
        "/usr/local/bin/connector-platform",
        "/usr/bin/connector-platform",
        "./connector-platform",
        "./target/release/connector-platform",
        "./platform/server/target/release/connector-platform",
    ] {
        if Path::new(c).is_file() {
            return Ok(c.into());
        }
    }
    if let Ok(path) = std::env::var("PATH") {
        for dir in path.split(':') {
            let p = format!("{dir}/connector-platform");
            if Path::new(&p).is_file() {
                return Ok(p);
            }
        }
    }
    Err("connector-platform binary not found on PATH or known install locations".into())
}

fn merge_human(mut data: Value, lines: Vec<String>, opts: &GlobalOpts) -> Value {
    if opts.output == crate::output::OutputMode::Human {
        if let Some(obj) = data.as_object_mut() {
            obj.insert("_human".into(), json!(lines));
        } else {
            return human_lines(lines);
        }
    }
    data
}

//! `connectorctl access` — mode, activation, pilots, license.

use crate::output::{CmdResult, ExitCode, GlobalOpts, Provenance};
use crate::transport::Client;
use serde_json::json;

pub fn run(opts: &GlobalOpts, args: &[String]) -> Result<ExitCode, String> {
    let verb = args.first().map(|s| s.as_str()).unwrap_or("status");
    let rest = if args.is_empty() { &[][..] } else { &args[1..] };
    match verb {
        "status" => status(opts),
        "mode" => mode(opts, rest),
        "activate" => activate(opts, rest),
        "pilot" => pilot(opts, rest),
        "license" => license(opts, rest),
        _ => Err(
            "usage: connectorctl access <status|mode|activate|pilot|license>".into(),
        ),
    }
}

fn status(opts: &GlobalOpts) -> Result<ExitCode, String> {
    let client = Client::new(opts)?;
    let mut data = json!({});
    let mut warnings = vec![];
    for (key, route) in [
        ("mode", "/api/v1/runtime/mode"),
        ("activation", "/api/v1/runtime/activation"),
        ("license", "/api/v1/license/status"),
    ] {
        match client.get_json(route) {
            Ok(v) => data[key] = v,
            Err(e) => {
                warnings.push(format!("{route}: {}", e.message()));
                data[key] = json!(null);
            }
        }
    }
    Ok(CmdResult {
        ok: warnings.is_empty(),
        command: "access status".into(),
        exit: if warnings.is_empty() {
            ExitCode::Success
        } else {
            ExitCode::Degraded
        },
        source: Provenance::api("GET", "runtime+license status set"),
        data,
        warnings,
        error: None,
    }
    .emit(opts))
}

fn mode(opts: &GlobalOpts, args: &[String]) -> Result<ExitCode, String> {
    let client = Client::new(opts)?;
    if args.is_empty() {
        return get(opts, "access mode", "/api/v1/runtime/mode");
    }
    let mode = args[0].as_str();
    if !matches!(mode, "dev" | "pilots" | "production" | "local") {
        return Err("usage: connectorctl access mode [dev|pilots|production|local]".into());
    }
    match client.post_json("/api/v1/runtime/mode", json!({ "mode": mode })) {
        Ok(v) => Ok(CmdResult {
            ok: true,
            command: "access mode".into(),
            exit: ExitCode::Success,
            source: Provenance::api("POST", "/api/v1/runtime/mode"),
            data: v,
            warnings: vec![],
            error: None,
        }
        .emit(opts)),
        Err(e) => Ok(fail(opts, "access mode", "/api/v1/runtime/mode", e)),
    }
}

fn activate(opts: &GlobalOpts, args: &[String]) -> Result<ExitCode, String> {
    let client = Client::new(opts)?;
    if args.is_empty() {
        return get(opts, "access activate", "/api/v1/runtime/activation");
    }
    let body = json!({ "mode": args[0] });
    match client.post_json("/api/v1/runtime/activation", body) {
        Ok(v) => Ok(CmdResult {
            ok: true,
            command: "access activate".into(),
            exit: ExitCode::Success,
            source: Provenance::api("POST", "/api/v1/runtime/activation"),
            data: v,
            warnings: vec![],
            error: None,
        }
        .emit(opts)),
        Err(e) => Ok(fail(
            opts,
            "access activate",
            "/api/v1/runtime/activation",
            e,
        )),
    }
}

fn pilot(opts: &GlobalOpts, args: &[String]) -> Result<ExitCode, String> {
    let sub = args.first().map(|s| s.as_str()).unwrap_or("list");
    match sub {
        "list" => get(opts, "access pilot list", "/api/v1/admin/pilots"),
        _ => Err("usage: connectorctl access pilot list".into()),
    }
}

fn license(opts: &GlobalOpts, args: &[String]) -> Result<ExitCode, String> {
    let sub = args.first().map(|s| s.as_str()).unwrap_or("status");
    match sub {
        "status" => get(opts, "access license status", "/api/v1/license/status"),
        "tiers" => get(opts, "access license tiers", "/api/v1/license/tiers"),
        _ => Err("usage: connectorctl access license <status|tiers>".into()),
    }
}

fn get(opts: &GlobalOpts, command: &str, route: &str) -> Result<ExitCode, String> {
    let client = Client::new(opts)?;
    match client.get_json(route) {
        Ok(v) => Ok(CmdResult {
            ok: true,
            command: command.into(),
            exit: ExitCode::Success,
            source: Provenance::api("GET", route),
            data: v,
            warnings: vec![],
            error: None,
        }
        .emit(opts)),
        Err(e) => Ok(fail(opts, command, route, e)),
    }
}

fn fail(
    opts: &GlobalOpts,
    cmd: &str,
    route: &str,
    e: crate::transport::TransportError,
) -> ExitCode {
    CmdResult {
        ok: false,
        command: cmd.into(),
        exit: e.exit_code(),
        source: Provenance::api("GET/POST", route),
        data: json!({}),
        warnings: vec![],
        error: Some(e.message()),
    }
    .emit(opts)
}

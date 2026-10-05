//! `connectorctl substrate` — proven ARC/SVF/DAL/rollup/worldline surfaces.

use crate::output::{CmdResult, ExitCode, GlobalOpts, Provenance};
use crate::transport::Client;
use serde_json::json;

pub fn run(opts: &GlobalOpts, args: &[String]) -> Result<ExitCode, String> {
    let verb = args.first().map(|s| s.as_str()).unwrap_or("status");
    let rest = if args.is_empty() { &[][..] } else { &args[1..] };
    match verb {
        "status" => get(opts, "substrate status", "/api/v1/substrate/status"),
        "arc" => sub_get(opts, rest, "arc", "/api/v1/arc/posture"),
        "svf" => sub_get(opts, rest, "svf", "/api/v1/svf/posture"),
        "dal" => sub_get(opts, rest, "dal", "/api/v1/dal/posture"),
        "rollup" => sub_get(opts, rest, "rollup", "/api/v1/rollup/posture"),
        "worldline" => worldline(opts, rest),
        _ => Err(
            "usage: connectorctl substrate <status|arc|svf|dal|rollup|worldline>".into(),
        ),
    }
}

fn sub_get(
    opts: &GlobalOpts,
    args: &[String],
    name: &str,
    posture_route: &str,
) -> Result<ExitCode, String> {
    let sub = args.first().map(|s| s.as_str()).unwrap_or("posture");
    if sub != "posture" {
        return Err(format!(
            "usage: connectorctl substrate {name} posture  (additional verbs not yet registered)"
        ));
    }
    get(opts, &format!("substrate {name} posture"), posture_route)
}

fn worldline(opts: &GlobalOpts, args: &[String]) -> Result<ExitCode, String> {
    let sub = args.first().map(|s| s.as_str()).unwrap_or("");
    if sub != "export" {
        return Err("usage: connectorctl substrate worldline export --agent <pid>".into());
    }
    let agent = args
        .iter()
        .position(|a| a == "--agent")
        .and_then(|i| args.get(i + 1))
        .ok_or("usage: --agent <pid> required")?;
    get(
        opts,
        "substrate worldline export",
        &format!("/api/v1/proof/export/{agent}"),
    )
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
        Err(e) => Ok(CmdResult {
            ok: false,
            command: command.into(),
            exit: e.exit_code(),
            source: Provenance::api("GET", route),
            data: json!({}),
            warnings: vec![],
            error: Some(e.message()),
        }
        .emit(opts)),
    }
}

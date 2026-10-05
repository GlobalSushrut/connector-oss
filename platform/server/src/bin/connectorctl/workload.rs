//! `connectorctl workload` — agents and deploy.

use crate::output::{CmdResult, ExitCode, GlobalOpts, Provenance, human_lines};
use crate::transport::Client;
use serde_json::{json, Value};
use std::path::Path;

pub fn run(opts: &GlobalOpts, args: &[String]) -> Result<ExitCode, String> {
    let verb = args.first().map(|s| s.as_str()).unwrap_or("list");
    let rest = if args.is_empty() { &[][..] } else { &args[1..] };
    match verb {
        "list" => list(opts),
        "show" => show(opts, rest),
        "inspect" => show(opts, rest),
        "logs" => logs(opts, rest),
        "start" => agent_post(opts, rest, "start"),
        "stop" => agent_post(opts, rest, "kill"),
        "deploy" => deploy(opts, rest),
        _ => Err(
            "usage: connectorctl workload <list|show|inspect|logs|start|stop|deploy>".into(),
        ),
    }
}

fn list(opts: &GlobalOpts) -> Result<ExitCode, String> {
    let client = Client::new(opts)?;
    match client.get_json("/api/v1/agents") {
        Ok(v) => {
            let lines = summarize_agents(&v);
            Ok(CmdResult {
                ok: true,
                command: "workload list".into(),
                exit: ExitCode::Success,
                source: Provenance::api("GET", "/api/v1/agents"),
                data: merge_human(v, lines, opts),
                warnings: vec![],
                error: None,
            }
            .emit(opts))
        }
        Err(e) => Ok(fail(opts, "workload list", "/api/v1/agents", e)),
    }
}

fn show(opts: &GlobalOpts, args: &[String]) -> Result<ExitCode, String> {
    let pid = args
        .first()
        .ok_or("usage: connectorctl workload show <pid>")?;
    let route = format!("/api/v1/agents/{pid}");
    let client = Client::new(opts)?;
    match client.get_json(&route) {
        Ok(v) => Ok(CmdResult {
            ok: true,
            command: "workload show".into(),
            exit: ExitCode::Success,
            source: Provenance::api("GET", route),
            data: v,
            warnings: vec![],
            error: None,
        }
        .emit(opts)),
        Err(e) => Ok(fail(opts, "workload show", &format!("/api/v1/agents/{pid}"), e)),
    }
}

fn logs(opts: &GlobalOpts, args: &[String]) -> Result<ExitCode, String> {
    let pid = args
        .first()
        .ok_or("usage: connectorctl workload logs <pid>")?;
    let route = format!("/api/v1/agents/{pid}/logs");
    let client = Client::new(opts)?;
    match client.get_json(&route) {
        Ok(v) => Ok(CmdResult {
            ok: true,
            command: "workload logs".into(),
            exit: ExitCode::Success,
            source: Provenance::api("GET", route),
            data: v,
            warnings: vec![],
            error: None,
        }
        .emit(opts)),
        Err(e) => Ok(fail(opts, "workload logs", &format!("/api/v1/agents/{pid}/logs"), e)),
    }
}

fn agent_post(opts: &GlobalOpts, args: &[String], action: &str) -> Result<ExitCode, String> {
    let pid = args
        .first()
        .ok_or_else(|| format!("usage: connectorctl workload {action} <pid>"))?;
    let route = format!("/api/v1/agents/{pid}/{action}");
    let client = Client::new(opts)?;
    match client.post_json(&route, json!({})) {
        Ok(v) => Ok(CmdResult {
            ok: true,
            command: format!("workload {action}"),
            exit: ExitCode::Success,
            source: Provenance::api("POST", route),
            data: v,
            warnings: vec![],
            error: None,
        }
        .emit(opts)),
        Err(e) => Ok(fail(
            opts,
            &format!("workload {action}"),
            &format!("/api/v1/agents/{pid}/{action}"),
            e,
        )),
    }
}

fn deploy(opts: &GlobalOpts, args: &[String]) -> Result<ExitCode, String> {
    let path = args
        .first()
        .ok_or("usage: connectorctl workload deploy <manifest.yaml>")?;
    if !Path::new(path).is_file() {
        return Err(format!("manifest not found: {path}"));
    }
    let body_text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let client = Client::new(opts)?;
    // Prefer JSON body if file is JSON; otherwise send as YAML text field
    let body = if path.ends_with(".json") {
        serde_json::from_str(&body_text).map_err(|e| format!("json parse: {e}"))?
    } else {
        json!({ "manifest_yaml": body_text, "path": path })
    };
    match client.post_json("/api/v1/deploy", body) {
        Ok(v) => Ok(CmdResult {
            ok: true,
            command: "workload deploy".into(),
            exit: ExitCode::Success,
            source: Provenance::api("POST", "/api/v1/deploy"),
            data: v,
            warnings: vec![],
            error: None,
        }
        .emit(opts)),
        Err(e) => Ok(fail(opts, "workload deploy", "/api/v1/deploy", e)),
    }
}

fn summarize_agents(v: &Value) -> Vec<String> {
    let mut lines = vec![];
    let agents = v
        .get("agents")
        .and_then(|a| a.as_array())
        .or_else(|| v.as_array());
    match agents {
        Some(arr) => {
            lines.push(format!("agents: {}", arr.len()));
            for a in arr.iter().take(50) {
                let id = a
                    .get("pid")
                    .or_else(|| a.get("id"))
                    .or_else(|| a.get("name"))
                    .and_then(|x| x.as_str())
                    .unwrap_or("?");
                let state = a
                    .get("state")
                    .or_else(|| a.get("status"))
                    .and_then(|x| x.as_str())
                    .unwrap_or("?");
                lines.push(format!("  {id}  {state}"));
            }
        }
        None => lines.push("agents: (response shape unknown — see --output json)".into()),
    }
    lines
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

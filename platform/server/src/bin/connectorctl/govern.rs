//! `connectorctl govern` — policy, compliance, cost, metrics, events.

use crate::output::{CmdResult, ExitCode, GlobalOpts, Provenance};
use crate::transport::Client;
use serde_json::json;

pub fn run(opts: &GlobalOpts, args: &[String]) -> Result<ExitCode, String> {
    let verb = args.first().map(|s| s.as_str()).unwrap_or("");
    let rest = if args.is_empty() { &[][..] } else { &args[1..] };
    match verb {
        "policy" => get(opts, "govern policy", "/api/v1/runtime/policy"),
        "metrics" => get(opts, "govern metrics", "/api/v1/monitor/health"),
        "events" => get(opts, "govern events", "/api/v1/monitor/signals"),
        "compliance" => compliance(opts, rest),
        "cost" => cost(opts, rest),
        "aipsprt" => aipsprt(opts, rest),
        "spend" => spend(opts, rest),
        "backends" => get(opts, "govern backends", "/api/v1/runtime/backends"),
        "deploy-verify" => deploy_verify(opts, rest),
        "ecosystem" => get(opts, "govern ecosystem", "/api/v1/runtime/ecosystem"),
        "cease-proof" => {
            let pid = rest
                .first()
                .ok_or("usage: connectorctl govern cease-proof <agent-pid>")?;
            get(
                opts,
                "govern cease-proof",
                &format!("/api/v1/runtime/cease-proof/{pid}"),
            )
        }
        "explain" => {
            let id = rest
                .first()
                .ok_or("usage: connectorctl govern explain <receipt-id>")?;
            get(
                opts,
                "govern explain",
                &format!("/api/v1/runtime/explain/{id}"),
            )
        }
        _ => Err(
            "usage: connectorctl govern <policy|compliance|cost|metrics|events|aipsprt|spend|backends|deploy-verify|ecosystem|explain|cease-proof>"
                .into(),
        ),
    }
}

fn deploy_verify(opts: &GlobalOpts, args: &[String]) -> Result<ExitCode, String> {
    let profile = args.first().map(String::as_str).unwrap_or("linux-kvm");
    if !matches!(profile, "linux-kvm" | "kubernetes") {
        return Err(
            "usage: connectorctl govern deploy-verify [linux-kvm|kubernetes]".into(),
        );
    }
    let route = format!("/api/v1/runtime/deploy-verify?profile={profile}");
    let client = Client::new(opts)?;
    match client.get_json(&route) {
        Ok(value) => {
            let ready = value
                .get("operational_ready")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            Ok(CmdResult {
                ok: ready,
                command: "govern deploy-verify".into(),
                exit: if ready {
                    ExitCode::Success
                } else {
                    ExitCode::Refused
                },
                source: Provenance::api("GET", &route),
                data: value,
                warnings: vec![],
                error: if ready {
                    None
                } else {
                    Some("seven_backend_operational_evidence_incomplete".into())
                },
            }
            .emit(opts))
        }
        Err(error) => Ok(CmdResult {
            ok: false,
            command: "govern deploy-verify".into(),
            exit: error.exit_code(),
            source: Provenance::api("GET", &route),
            data: json!({}),
            warnings: vec![],
            error: Some(error.message()),
        }
        .emit(opts)),
    }
}

fn compliance(opts: &GlobalOpts, args: &[String]) -> Result<ExitCode, String> {
    let sub = args.first().map(|s| s.as_str()).unwrap_or("scorecard");
    match sub {
        "scorecard" => get(opts, "govern compliance scorecard", "/api/v1/compliance/scorecard"),
        "findings" => get(opts, "govern compliance findings", "/api/v1/compliance/findings"),
        "frameworks" => get(opts, "govern compliance frameworks", "/api/v1/compliance/frameworks"),
        other => Err(format!(
            "usage: connectorctl govern compliance <scorecard|findings|frameworks> (got {other})"
        )),
    }
}

fn cost(opts: &GlobalOpts, args: &[String]) -> Result<ExitCode, String> {
    let pid = args
        .first()
        .ok_or("usage: connectorctl govern cost <pid>")?;
    get(opts, "govern cost", &format!("/api/v1/agents/{pid}/cost"))
}

fn aipsprt(opts: &GlobalOpts, args: &[String]) -> Result<ExitCode, String> {
    let sub = args.first().map(|s| s.as_str()).unwrap_or("");
    match sub {
        "schema" => get(opts, "govern aipsprt schema", "/api/v1/aipsprt/schema"),
        "get" => {
            let id = args
                .get(1)
                .ok_or("usage: connectorctl govern aipsprt get <passport_id>")?;
            get(opts, "govern aipsprt get", &format!("/api/v1/aipsprt/{id}"))
        }
        "index-digest" => {
            let dig = args
                .get(1)
                .ok_or("usage: connectorctl govern aipsprt index-digest <sha256hex>")?;
            get(
                opts,
                "govern aipsprt index-digest",
                &format!("/api/v1/aipsprt/index/digest/{dig}"),
            )
        }
        "c2pa-map" => {
            let id = args
                .get(1)
                .ok_or("usage: connectorctl govern aipsprt c2pa-map <passport_id>")?;
            get(
                opts,
                "govern aipsprt c2pa-map",
                &format!("/api/v1/aipsprt/{id}/c2pa-map"),
            )
        }
        "verify" => {
            let path = args
                .get(1)
                .ok_or("usage: connectorctl govern aipsprt verify <passport.json>")?;
            let raw = std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
            let passport: serde_json::Value =
                serde_json::from_str(&raw).map_err(|e| format!("json: {e}"))?;
            post(
                opts,
                "govern aipsprt verify",
                "/api/v1/aipsprt/verify",
                json!({ "passport": passport }),
            )
        }
        _ => Err(
            "usage: connectorctl govern aipsprt <schema|get <id>|index-digest <hex>|c2pa-map <id>|verify <file.json>>"
                .into(),
        ),
    }
}

fn spend(opts: &GlobalOpts, args: &[String]) -> Result<ExitCode, String> {
    let sub = args.first().map(|s| s.as_str()).unwrap_or("");
    match sub {
        "ceiling" => {
            let pid = args
                .get(1)
                .ok_or("usage: connectorctl govern spend ceiling <pid>")?;
            get(
                opts,
                "govern spend ceiling",
                &format!("/api/v1/spend/ceiling/{pid}"),
            )
        }
        "burn" => {
            let pid = args
                .get(1)
                .ok_or("usage: connectorctl govern spend burn <pid>")?;
            get(
                opts,
                "govern spend burn",
                &format!("/api/v1/spend/burn/{pid}"),
            )
        }
        "cease-latest" => {
            let pid = args
                .get(1)
                .ok_or("usage: connectorctl govern spend cease-latest <pid>")?;
            get(
                opts,
                "govern spend cease-latest",
                &format!("/api/v1/spend/cease/latest/{pid}"),
            )
        }
        "cease" => {
            let pid = args
                .get(1)
                .ok_or("usage: connectorctl govern spend cease <pid>")?;
            post(
                opts,
                "govern spend cease",
                &format!("/api/v1/agents/{pid}/cease"),
                json!({}),
            )
        }
        _ => Err(
            "usage: connectorctl govern spend <ceiling|burn|cease-latest|cease> <pid>".into(),
        ),
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

fn post(opts: &GlobalOpts, command: &str, route: &str, body: serde_json::Value) -> Result<ExitCode, String> {
    let client = Client::new(opts)?;
    match client.post_json(route, body) {
        Ok(v) => Ok(CmdResult {
            ok: true,
            command: command.into(),
            exit: ExitCode::Success,
            source: Provenance::api("POST", route),
            data: v,
            warnings: vec![],
            error: None,
        }
        .emit(opts)),
        Err(e) => Ok(CmdResult {
            ok: false,
            command: command.into(),
            exit: e.exit_code(),
            source: Provenance::api("POST", route),
            data: json!({}),
            warnings: vec![],
            error: Some(e.message()),
        }
        .emit(opts)),
    }
}

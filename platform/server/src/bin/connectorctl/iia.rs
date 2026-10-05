//! `connectorctl iia` — protocol-plane smoke against a live node.
//!
//! This is not a two-agent join demo. It cites real `/api/v1/protocol/conp/*`
//! and `/api/v1/cnp/*` routes. `--conp` exercises grant persist + actuation.

use crate::output::{CmdResult, ExitCode, GlobalOpts, Provenance};
use crate::transport::{self, Client};
use serde_json::{json, Value};

pub fn run(opts: &GlobalOpts, args: &[String]) -> Result<ExitCode, String> {
    let verb = args.first().map(|s| s.as_str()).unwrap_or("");
    match verb {
        "smoke" => smoke(opts, &args[1..]),
        _ => Err("usage: connectorctl iia smoke [--conp]".into()),
    }
}

fn smoke(opts: &GlobalOpts, args: &[String]) -> Result<ExitCode, String> {
    let conp = args.iter().any(|a| a == "--conp");
    let client = Client::new(opts)?;
    let mut checks = Vec::new();
    let mut warnings = Vec::new();

    match transport::probe_health(opts) {
        Ok((path, v)) => checks.push(json!({"name": "healthz", "ok": true, "path": path, "body": v})),
        Err(e) => {
            return Ok(fail(
                opts,
                "iia smoke",
                "/healthz",
                e.message(),
                json!({ "checks": checks }),
            ));
        }
    }

    let info = match client.get_json("/api/v1/protocol/conp/info") {
        Ok(v) => v,
        Err(e) => {
            return Ok(fail(
                opts,
                "iia smoke",
                "/api/v1/protocol/conp/info",
                e.message(),
                json!({ "checks": checks }),
            ));
        }
    };
    let type_count = info
        .get("message_type_count")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let cap_count = info
        .get("capability_count")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    if type_count != 30 {
        return Ok(fail(
            opts,
            "iia smoke",
            "/api/v1/protocol/conp/info",
            format!("expected 30 CONP MessageTypes, got {type_count}"),
            json!({ "checks": checks, "info": info }),
        ));
    }
    checks.push(json!({
        "name": "conp_info",
        "ok": true,
        "message_type_count": type_count,
        "capability_count": cap_count,
    }));

    let overview = match client.get_json("/api/v1/cnp/overview") {
        Ok(v) => v,
        Err(e) => {
            return Ok(fail(
                opts,
                "iia smoke",
                "/api/v1/cnp/overview",
                e.message(),
                json!({ "checks": checks }),
            ));
        }
    };
    checks.push(json!({
        "name": "cnp_overview",
        "ok": overview.get("ok").and_then(|v| v.as_bool()).unwrap_or(false),
        "mtls_product": overview.pointer("/data/mtls/mutual_auth_product"),
    }));

    if let Ok(posture) = client.get_json("/api/v1/runtime/intelligence-posture") {
        let sil = posture
            .pointer("/native_protocol/conp/sil_certified")
            .and_then(|v| v.as_bool());
        if sil == Some(true) {
            return Ok(fail(
                opts,
                "iia smoke",
                "/api/v1/runtime/intelligence-posture",
                "sil_certified claimed true — CONP taxonomy is not a SIL bus".into(),
                json!({ "checks": checks, "posture": posture }),
            ));
        }
        checks.push(json!({
            "name": "intelligence_posture",
            "ok": true,
            "sil_certified": sil,
        }));
    } else {
        warnings.push("GET /api/v1/runtime/intelligence-posture unavailable".into());
    }

    if conp {
        match smoke_conp(&client) {
            Ok(v) => checks.push(v),
            Err(e) => {
                return Ok(fail(
                    opts,
                    "iia smoke --conp",
                    "/api/v1/protocol/conp/message",
                    e,
                    json!({ "checks": checks }),
                ));
            }
        }
    }

    Ok(CmdResult {
        ok: true,
        command: if conp {
            "iia smoke --conp".into()
        } else {
            "iia smoke".into()
        },
        exit: ExitCode::Success,
        source: Provenance::api("GET", "/api/v1/protocol/conp/info"),
        data: json!({
            "schema": "connector.iia.smoke.v1",
            "conp": conp,
            "checks": checks,
            "honesty": "Protocol-plane smoke (CONP catalog + CNP overview). Not two-agent IIA join, SIL, ROS, or Envoy execute.",
        }),
        warnings,
        error: None,
    }
    .emit(opts))
}

fn smoke_conp(client: &Client<'_>) -> Result<Value, String> {
    let grant_body = json!({
        "agent_pid": "iia-smoke-agent",
        "capability_id": "machine.move_axis",
        "entity_id": "machine:smoke-arm",
        "message_type": "CapabilityGrant",
        "parameters": { "smoke": true },
    });
    let grant = client
        .post_json("/api/v1/protocol/conp/message", grant_body)
        .map_err(|e| e.message())?;
    if grant.get("ok") != Some(&json!(true)) {
        return Err(format!("CapabilityGrant refused: {grant}"));
    }
    let grant_id = grant
        .pointer("/stored/grant_id")
        .or_else(|| grant.pointer("/ack/stored/grant_id"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("CapabilityGrant did not persist grant_id: {grant}"))?
        .to_string();
    let status = grant
        .pointer("/stored/status")
        .or_else(|| grant.pointer("/ack/stored/status"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if status != "active" && status != "delegated" {
        return Err(format!("expected stored status active, got {status}"));
    }

    let revoke = client
        .post_json(
            "/api/v1/protocol/conp/message",
            json!({
                "agent_pid": "iia-smoke-agent",
                "capability_id": "machine.move_axis",
                "entity_id": "machine:smoke-arm",
                "message_type": "CapabilityRevoke",
                "grant_id": grant_id,
                "parameters": {},
            }),
        )
        .map_err(|e| e.message())?;
    if revoke.get("ok") != Some(&json!(true)) {
        return Err(format!("CapabilityRevoke refused: {revoke}"));
    }
    let revoked = revoke
        .pointer("/stored/status")
        .or_else(|| revoke.pointer("/ack/stored/status"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if revoked != "revoked" {
        return Err(format!("expected revoked status, got {revoked} in {revoke}"));
    }

    let actuation = client
        .post_json(
            "/api/v1/cnp/actuation",
            json!({
                "from_agent": "iia-smoke-agent",
                "to_agent": "local",
                "command": "emergency_stop",
                "parameters": {},
            }),
        )
        .map_err(|e| e.message())?;
    if actuation.get("ok") != Some(&json!(true)) {
        return Err(format!("CNP actuation refused: {actuation}"));
    }

    let mut command = json!(null);
    if std::env::var("CONNECTOR_CONP_LAB_ECHO")
        .map(|v| {
            let t = v.trim().to_ascii_lowercase();
            matches!(t.as_str(), "1" | "true" | "yes" | "on")
        })
        .unwrap_or(false)
    {
        let ack = client
            .post_json(
                "/api/v1/protocol/conp/command",
                json!({
                    "agent_pid": "iia-smoke-agent",
                    "capability_id": "machine.move_axis",
                    "entity_id": "machine:smoke-arm",
                    "message_type": "Command",
                    "parameters": { "axis": "X", "target_mm": 1.0 },
                    "lab_echo_hal": true,
                }),
            )
            .map_err(|e| e.message())?;
        if ack.get("ok") != Some(&json!(true)) {
            return Err(format!("lab echo CONP command refused: {ack}"));
        }
        command = ack;
    }

    Ok(json!({
        "name": "conp_mutating",
        "ok": true,
        "grant_id": grant_id,
        "revoke_status": revoked,
        "actuation_message_id": actuation.get("message_id"),
        "lab_echo_command": command,
    }))
}

fn fail(
    opts: &GlobalOpts,
    command: &str,
    route: &str,
    error: String,
    data: Value,
) -> ExitCode {
    CmdResult {
        ok: false,
        command: command.into(),
        exit: ExitCode::Failure,
        source: Provenance::api("GET", route),
        data,
        warnings: vec![],
        error: Some(error),
    }
    .emit(opts)
}

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
        "up" => up(opts),
        "status" => status(opts),
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
            "usage: connectorctl govern <up|status|policy|compliance|cost|metrics|events|aipsprt|spend|backends|deploy-verify|ecosystem|explain|cease-proof>"
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

const OPERATOR_ROLES: &[(&str, &str)] = &[
    ("iam", "sign-in"),
    ("spire", "workload"),
    ("openshell", "boundary"),
    ("opa", "policy"),
    ("firecracker", "isolation"),
    ("otel", "trace"),
    ("cosign", "supply"),
    ("traffic", "traffic"),
    ("brain", "recall"),
    ("broker", "model"),
    ("orchestrate", "flow"),
];

pub(crate) fn operator_state(state: &str) -> &'static str {
    match state {
        "followed" => "up",
        "supervised" => "not following this task",
        _ => "down",
    }
}

fn status(opts: &GlobalOpts) -> Result<ExitCode, String> {
    let client = Client::new(opts)?;
    let route = "/api/v1/reports/system";
    let report = match client.get_json(route) {
        Ok(value) => value,
        Err(err) => {
            return Ok(CmdResult {
                ok: false,
                command: "govern status".into(),
                exit: err.exit_code(),
                source: Provenance::api("GET", route),
                data: json!({}),
                warnings: vec![],
                error: Some(err.message()),
            }
            .emit(opts));
        }
    };
    let fingers = report
        .pointer("/body/fingers")
        .and_then(|value| value.as_array())
        .cloned()
        .unwrap_or_default();
    let mut roles = Vec::new();
    let mut lines = Vec::new();
    for (id, role) in OPERATOR_ROLES {
        let state = fingers
            .iter()
            .find(|row| row.get("id").and_then(|value| value.as_str()) == Some(*id))
            .and_then(|row| row.get("state").and_then(|value| value.as_str()))
            .unwrap_or("absent");
        let operator = operator_state(state);
        lines.push(format!("{role}: {operator}"));
        roles.push(json!({
            "role": role,
            "reading": state,
            "operator": operator,
        }));
    }
    Ok(CmdResult {
        ok: true,
        command: "govern status".into(),
        exit: ExitCode::Success,
        source: Provenance::api("GET", route),
        data: json!({
            "_human": lines,
            "roles": roles,
            "acceptance_passed": false,
            "seven_backend": false,
        }),
        warnings: vec![],
        error: None,
    }
    .emit(opts))
}

fn up(opts: &GlobalOpts) -> Result<ExitCode, String> {
    let oss = oss_boot_dir()?;
    let seven = run_boot(&oss.join("boot-backends.sh"));
    let intel = run_boot(&oss.join("boot-intelligence.sh"));
    let seven_up = seven.0 == 0;
    let intel_up = intel.0 == 0;
    let mut lines = vec![
        format!(
            "sign-in, workload, boundary, policy, isolation, trace, supply, traffic: {}",
            if seven_up { "started" } else { "down" }
        ),
        format!(
            "recall, model, flow: {}",
            if intel_up { "started" } else { "down" }
        ),
        "This command does not run deploy-verify.".into(),
    ];
    let mut warnings = Vec::new();
    if !seven_up && !seven.1.is_empty() {
        warnings.push(seven.1);
    }
    if !intel_up && !intel.1.is_empty() {
        warnings.push(intel.1);
    }
    Ok(CmdResult {
        ok: seven_up && intel_up,
        command: "govern up".into(),
        exit: if seven_up && intel_up {
            ExitCode::Success
        } else {
            ExitCode::Degraded
        },
        source: Provenance::host("oss boot scripts"),
        data: json!({
            "_human": lines,
            "sign_in_through_traffic_exit": seven.0,
            "recall_model_flow_exit": intel.0,
            "platform_started": false,
            "acceptance_passed": false,
        }),
        warnings,
        error: None,
    }
    .emit(opts))
}

fn oss_boot_dir() -> Result<std::path::PathBuf, String> {
    if let Ok(root) = std::env::var("CONNECTOR_REPO_ROOT") {
        let oss = std::path::PathBuf::from(root).join("oss");
        if boot_scripts_present(&oss) {
            return Ok(oss);
        }
    }
    let mut dir = std::env::current_dir().map_err(|err| err.to_string())?;
    loop {
        let oss = dir.join("oss");
        if boot_scripts_present(&oss) {
            return Ok(oss);
        }
        if !dir.pop() {
            break;
        }
    }
    Err("finger boot scripts are not in this tree".into())
}

fn boot_scripts_present(oss: &std::path::Path) -> bool {
    oss.join("boot-backends.sh").is_file() && oss.join("boot-intelligence.sh").is_file()
}

fn run_boot(script: &std::path::Path) -> (i32, String) {
    match std::process::Command::new("bash")
        .arg(script)
        .stdin(std::process::Stdio::null())
        .output()
    {
        Ok(output) => (
            output.status.code().unwrap_or(1),
            safe_boot_note(&output.stdout, &output.stderr),
        ),
        Err(err) => (127, safe_boot_note(err.to_string().as_bytes(), b"")),
    }
}

fn safe_boot_note(stdout: &[u8], stderr: &[u8]) -> String {
    let mut text = String::from_utf8_lossy(stderr).into_owned();
    if !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }
    text.push_str(&String::from_utf8_lossy(stdout));
    for line in text.lines().rev() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let lower = trimmed.to_ascii_lowercase();
        if lower.contains("password")
            || lower.contains("secret")
            || lower.contains("token")
            || lower.contains("api_key")
            || lower.contains("bearer")
            || lower.contains("docker ")
            || lower.contains("curl ")
        {
            continue;
        }
        return trimmed.chars().take(180).collect();
    }
    String::new()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operator_rows_use_the_report_reading() {
        assert_eq!(operator_state("followed"), "up");
        assert_eq!(operator_state("supervised"), "not following this task");
        assert_eq!(operator_state("absent"), "down");
        assert_eq!(operator_state("ready"), "down");
        assert_eq!(OPERATOR_ROLES.len(), 11);
        assert_eq!(OPERATOR_ROLES[0].1, "sign-in");
        assert_eq!(OPERATOR_ROLES[10].1, "flow");
    }

    #[test]
    fn boot_notes_drop_vendor_commands_and_secrets() {
        let note = safe_boot_note(
            b"docker pull example\npassword=hidden\n[not ready] sign-in\n",
            b"",
        );
        assert_eq!(note, "[not ready] sign-in");
        assert!(safe_boot_note(b"curl -s http://example\n", b"").is_empty());
    }
}

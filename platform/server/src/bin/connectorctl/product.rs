//! `connectorctl product` — install, supervise, and report the Linux/KVM stack.
//!
//! Applying a spec configures Keycloak, SPIRE, OpenShell, Firecracker, the
//! OpenTelemetry Collector, and cosign. It does not mark them READY. The
//! board is READY only when the process is up and `govern deploy-verify`
//! has evidence for that backend.

use crate::output::{human_lines, CmdResult, ExitCode, GlobalOpts, Provenance};
use crate::product_eval::{
    classify_surface, compatibility, decide_install, demo_steps, env_flag_on, evaluate,
    parse_spec, parse_task_args, policy_from_explain, providers,
    recovery_action, recovery_semantics, render_spire_agent, render_spire_server, response_text,
    score_outcomes, surface_contract_patch, task_blockers, task_execution_complete, task_stage,
    upgrade_decision, DeploymentSpec, EvidenceFacts, HostFacts, InstallDecision, OutcomeFacts,
    ServiceFacts, SurfaceKind, SCHEMA, OUTCOMES_SCHEMA,
};
use crate::transport::Client;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const UNITS: &[&str] = &[
    "connector-spire-server",
    "connector-spire-agent",
    "connector-microd",
];

pub fn run(opts: &GlobalOpts, args: &[String]) -> Result<ExitCode, String> {
    let verb = args.first().map(String::as_str).unwrap_or("");
    let rest = if args.is_empty() { &[][..] } else { &args[1..] };
    match verb {
        "install" => install(opts, rest),
        "start" => lifecycle(opts, "start"),
        "stop" => lifecycle(opts, "stop"),
        "restart" => lifecycle(opts, "restart"),
        "upgrade" => upgrade(opts, rest),
        "rollback" => rollback(opts),
        "status" => status(opts),
        "diagnose" => diagnose(opts),
        "uninstall" => uninstall(opts, rest),
        "reconcile" => reconcile(opts),
        "demo" => demo(opts, rest),
        "task" => task(opts, rest),
        "providers" => static_json(opts, "product providers", providers()),
        "compatibility" => static_json(opts, "product compatibility", compatibility()),
        _ => Err(
            "usage: connectorctl product <install <spec.json>|start|stop|restart|upgrade <spec.json>|rollback|status|diagnose|uninstall [purge]|reconcile|demo governed-agent|task --model <llm> --surface <path|sandbox|dedicated> --purpose <sentence>|providers|compatibility>"
                .into(),
        ),
    }
}

fn install(opts: &GlobalOpts, args: &[String]) -> Result<ExitCode, String> {
    let spec_path = args
        .first()
        .ok_or("usage: connectorctl product install <spec.json> [--yes applies as root]")?;
    let (decision, spec) = load_decision(spec_path)?;
    match decision {
        InstallDecision::Refuse { blockers } => refused(
            opts,
            "product install",
            "install_refused",
            blockers,
            "host prerequisites or the deployment spec",
        ),
        InstallDecision::Plan { steps } => {
            if !opts.yes {
                let mut lines = vec![
                    "dry run; nothing was changed".into(),
                    "pass --yes as root to apply. Apply still does not mark READY.".into(),
                    String::new(),
                ];
                lines.extend(steps.iter().map(|step| format!("plan: {step}")));
                return Ok(CmdResult {
                    ok: true,
                    command: "product install".into(),
                    exit: ExitCode::Success,
                    source: Provenance::host("deployment spec plus host prerequisites"),
                    data: json!({
                        "schema": SCHEMA,
                        "applied": false,
                        "production_ready": false,
                        "steps": steps,
                        "_human": lines,
                    }),
                    warnings: vec![],
                    error: None,
                }
                .emit(opts));
            }
            if !is_root() {
                return refused(
                    opts,
                    "product install",
                    "root_required",
                    vec!["product install --yes must run as root".into()],
                    "installer uid",
                );
            }
            let spec = spec.expect("plan only exists for a valid spec");
            apply(opts, spec_path, &spec, &steps)
        }
    }
}

fn apply(
    opts: &GlobalOpts,
    spec_path: &str,
    spec: &DeploymentSpec,
    steps: &[&str],
) -> Result<ExitCode, String> {
    let state = state_dir();
    let stack = stack_dir()?;
    fs::create_dir_all(&state).map_err(|e| format!("create {}: {e}", state.display()))?;
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).ok();
    let mut completed = Vec::new();
    for step in steps {
        if let Err(error) = apply_step(step, spec, &state, &stack) {
            let _ = write_desired(&state, spec_path);
            return Ok(CmdResult {
                ok: false,
                command: "product install".into(),
                exit: ExitCode::Failure,
                source: Provenance::host("linux-kvm product installer"),
                data: json!({
                    "schema": SCHEMA,
                    "applied": false,
                    "production_ready": false,
                    "completed": completed,
                    "failed_step": step,
                }),
                warnings: vec![],
                error: Some(format!("{step}: {error}")),
            }
            .emit(opts));
        }
        completed.push(*step);
        if *step == "run-deploy-verify" {
            break;
        }
    }
    let _ = write_desired(&state, spec_path);
    status_after(opts, "product install")
}

fn apply_step(step: &str, spec: &DeploymentSpec, state: &Path, stack: &Path) -> Result<(), String> {
    match step {
        "verify-pinned-artifacts" => verify_pins(spec),
        "install-pinned-artifacts" => install_artifacts(spec, stack),
        "render-spire-config" => {
            let text = render_spire_server(&spec.trust_domain)?;
            write_private(&state.join("spire-server.conf"), text.as_bytes(), 0o640)?;
            install_file(
                &state.join("spire-server.conf"),
                Path::new("/etc/connector/seven-backends/spire/server.conf"),
                0o640,
            )
        }
        "write-secret-files" => {
            ensure_secret(&spec.admin_password_file)?;
            ensure_secret(&spec.db_password_file)?;
            ensure_secret(&spec.sso_client_secret_file)
        }
        "write-compose-env" => write_compose_env(spec, &state.join("images.env")),
        "start-keycloak-and-collector" => run_cmd("bash", [stack.join("up.sh"), state.join("images.env")]),
        "bootstrap-keycloak-realm" => {
            run_cmd("bash", [stack.join("bootstrap-keycloak.sh"), state.join("images.env")])
        }
        "start-spire" => {
            systemctl(&["daemon-reload"])?;
            systemctl(&["enable", "--now", "connector-spire-server"])
        }
        "register-spire-agent" => register_spire_agent(spec, state),
        "write-microd-env" => write_microd_env(spec),
        "start-microd" => systemctl(&["enable", "--now", "connector-microd"]),
        "write-connector-env" => write_connector_env(spec),
        "enable-reconcile-timer" => enable_reconcile(stack),
        "run-deploy-verify" => Ok(()),
        other => Err(format!("unknown install step {other}")),
    }
}

fn verify_pins(spec: &DeploymentSpec) -> Result<(), String> {
    verify_sha(&spec.kernel_path, &spec.kernel_sha256)?;
    verify_sha(&spec.rootfs_path, &spec.rootfs_sha256)?;
    for (path, sha) in &spec.artifact_pins {
        verify_sha(path, sha)?;
    }
    Ok(())
}

fn verify_sha(path: &str, expected: &str) -> Result<(), String> {
    let actual = sha256_file(path)?;
    if !actual.eq_ignore_ascii_case(expected) {
        return Err(format!("SHA-256 mismatch for {path}"));
    }
    Ok(())
}

fn install_artifacts(spec: &DeploymentSpec, stack: &Path) -> Result<(), String> {
    let names = [
        ("OPENSHELL_PACKAGE", "OPENSHELL_PACKAGE_SHA256"),
        ("SPIRE_SERVER_BIN", "SPIRE_SERVER_SHA256"),
        ("SPIRE_AGENT_BIN", "SPIRE_AGENT_SHA256"),
        ("FIRECRACKER_BIN", "FIRECRACKER_SHA256"),
        ("JAILER_BIN", "JAILER_SHA256"),
        ("COSIGN_BIN", "COSIGN_SHA256"),
        ("CONNECTOR_MICROD_BIN", "CONNECTOR_MICROD_SHA256"),
    ];
    let mut cmd = Command::new("bash");
    cmd.arg(stack.join("install-host-upstreams.sh"));
    for ((path_key, sha_key), (path, sha)) in names.iter().zip(spec.artifact_pins.iter()) {
        cmd.env(path_key, path);
        cmd.env(sha_key, sha);
    }
    let status = cmd.status().map_err(|e| format!("install-host-upstreams: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("install-host-upstreams exited {status}"))
    }
}

fn register_spire_agent(spec: &DeploymentSpec, state: &Path) -> Result<(), String> {
    let output = Command::new("spire-server")
        .args([
            "token",
            "generate",
            "-spiffeID",
            &format!("spiffe://{}/agent", spec.trust_domain),
            "-socketPath",
            "/run/spire/server/private/api.sock",
        ])
        .output()
        .map_err(|e| format!("spire-server token generate: {e}"))?;
    if !output.status.success() {
        return Err("spire-server token generate failed; agent was not registered".into());
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let token = text
        .lines()
        .find_map(|line| line.trim().strip_prefix("Token:").map(str::trim))
        .ok_or("spire-server did not print a Token line")?;
    let agent = render_spire_agent(&spec.trust_domain, token)?;
    write_private(&state.join("spire-agent.conf"), agent.as_bytes(), 0o640)?;
    install_file(
        &state.join("spire-agent.conf"),
        Path::new("/etc/connector/seven-backends/spire/agent.conf"),
        0o640,
    )?;
    systemctl(&["enable", "--now", "connector-spire-agent"])
}

fn write_compose_env(spec: &DeploymentSpec, path: &Path) -> Result<(), String> {
    let admin = read_secret(&spec.admin_password_file)?;
    let db = read_secret(&spec.db_password_file)?;
    let client = read_secret(&spec.sso_client_secret_file)?;
    let body = format!(
        "POSTGRES_IMAGE={}\nKEYCLOAK_IMAGE={}\nOTEL_COLLECTOR_IMAGE={}\nKEYCLOAK_DB_PASSWORD={db}\nKEYCLOAK_ADMIN={}\nKEYCLOAK_ADMIN_PASSWORD={admin}\nKEYCLOAK_HOSTNAME={}\nKEYCLOAK_HTTPS_PORT=8443\nKEYCLOAK_TLS_DIR={}\nOTEL_UPSTREAM_ENDPOINT={}\nCONNECTOR_SSO_CLIENT_ID=connector-platform\nCONNECTOR_SSO_CLIENT_SECRET={client}\nCONNECTOR_SSO_REDIRECT_URI={}\n",
        spec.postgres_image,
        spec.keycloak_image,
        spec.otel_image,
        spec.admin_user,
        spec.hostname,
        spec.tls_dir,
        spec.otel_upstream,
        spec.redirect_uri,
    );
    write_private(path, body.as_bytes(), 0o600)
}

fn write_microd_env(spec: &DeploymentSpec) -> Result<(), String> {
    verify_sha(&spec.kernel_path, &spec.kernel_sha256)?;
    verify_sha(&spec.rootfs_path, &spec.rootfs_sha256)?;
    let body = format!(
        "CONNECTOR_MICROVM_KERNEL={}\nCONNECTOR_MICROVM_ROOTFS={}\nCONNECTOR_MICROD_SOCK=/run/connector/microd.sock\nCONNECTOR_MICROD_READY_FILE=/run/connector/microd.ready\nCONNECTOR_MICROD_WARM_POOL=0\n",
        spec.kernel_path, spec.rootfs_path
    );
    fs::create_dir_all("/etc/connector").map_err(|e| e.to_string())?;
    write_private(Path::new("/etc/connector/microd.env"), body.as_bytes(), 0o640)
}

fn write_connector_env(spec: &DeploymentSpec) -> Result<(), String> {
    let client = read_secret(&spec.sso_client_secret_file)?;
    let host = &spec.hostname;
    let body = format!(
        "CONNECTOR_SSO_CLIENT_ID=connector-platform\nCONNECTOR_SSO_CLIENT_SECRET={client}\nCONNECTOR_SSO_ISSUER=https://{host}/realms/connector\nCONNECTOR_SSO_DISCOVERY_URL=https://{host}/realms/connector/.well-known/openid-configuration\nCONNECTOR_SSO_AUTHORIZATION_URL=https://{host}/realms/connector/protocol/openid-connect/auth\nCONNECTOR_SSO_TOKEN_URL=https://{host}/realms/connector/protocol/openid-connect/token\nCONNECTOR_SSO_USERINFO_URL=https://{host}/realms/connector/protocol/openid-connect/userinfo\nCONNECTOR_SSO_JWKS_URL=https://{host}/realms/connector/protocol/openid-connect/certs\nSPIFFE_ENDPOINT_SOCKET=unix:///run/spire/agent/sockets/api.sock\nOTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4317\n"
    );
    fs::create_dir_all("/etc/connector").map_err(|e| e.to_string())?;
    write_private(
        Path::new("/etc/connector/connector-platform.env"),
        body.as_bytes(),
        0o600,
    )
}

fn enable_reconcile(stack: &Path) -> Result<(), String> {
    install_file(
        &stack.join("systemd/connector-product-reconcile.service"),
        Path::new("/etc/systemd/system/connector-product-reconcile.service"),
        0o644,
    )?;
    install_file(
        &stack.join("systemd/connector-product-reconcile.timer"),
        Path::new("/etc/systemd/system/connector-product-reconcile.timer"),
        0o644,
    )?;
    systemctl(&["daemon-reload"])?;
    systemctl(&["enable", "--now", "connector-product-reconcile.timer"])
}

fn upgrade(opts: &GlobalOpts, args: &[String]) -> Result<ExitCode, String> {
    let spec_path = args
        .first()
        .ok_or("usage: connectorctl product upgrade <spec.json>")?;
    if !opts.yes {
        return refused(
            opts,
            "product upgrade",
            "confirmation_required",
            vec!["pass --yes to upgrade. The previous spec is kept for rollback.".into()],
            "upgrade confirmation",
        );
    }
    let previous = read_json(&state_dir().join("desired.json"))?;
    let previous_profile = previous
        .get("profile")
        .and_then(Value::as_str)
        .unwrap_or("");
    let next: Value = read_json(Path::new(spec_path))?;
    let next_profile = next.get("profile").and_then(Value::as_str).unwrap_or("");
    let schema = next
        .pointer("/compatibility/openshell_policy_schema")
        .and_then(Value::as_u64)
        .unwrap_or(1) as u32;
    if let Err(error) = upgrade_decision(previous_profile, next_profile, schema) {
        return refused(
            opts,
            "product upgrade",
            "upgrade_refused",
            vec![error],
            "compatibility matrix",
        );
    }
    let state = state_dir();
    fs::copy(state.join("desired.json"), state.join("desired.previous.json"))
        .map_err(|e| format!("save previous spec: {e}"))?;
    install(opts, args)
}

fn rollback(opts: &GlobalOpts) -> Result<ExitCode, String> {
    if !opts.yes {
        return refused(
            opts,
            "product rollback",
            "confirmation_required",
            vec!["pass --yes to restore desired.previous.json and apply it".into()],
            "rollback confirmation",
        );
    }
    let previous = state_dir().join("desired.previous.json");
    if !previous.is_file() {
        return refused(
            opts,
            "product rollback",
            "no_previous_spec",
            vec!["no desired.previous.json; nothing was rolled back".into()],
            "deployment state",
        );
    }
    install(opts, &[previous.display().to_string()])
}

fn lifecycle(opts: &GlobalOpts, verb: &str) -> Result<ExitCode, String> {
    if !opts.yes {
        return refused(
            opts,
            &format!("product {verb}"),
            "confirmation_required",
            vec![format!("pass --yes to {verb} the Linux/KVM units")],
            "lifecycle confirmation",
        );
    }
    if !is_root() {
        return refused(
            opts,
            &format!("product {verb}"),
            "root_required",
            vec![format!("product {verb} must run as root")],
            "lifecycle uid",
        );
    }
    let action = match verb {
        "restart" => "restart",
        "stop" => "stop",
        "start" => "start",
        _ => return Err("usage: product start|stop|restart".into()),
    };
    for unit in UNITS {
        systemctl(&[action, unit])?;
    }
    let stack = stack_dir()?;
    let env = state_dir().join("images.env");
    let compose_arg = if verb == "stop" { "stop" } else { "up" };
    let mut args = vec![
        "compose".to_string(),
        "--env-file".into(),
        env.display().to_string(),
        "-f".into(),
        stack.join("compose.yaml").display().to_string(),
        compose_arg.into(),
    ];
    if compose_arg == "up" {
        args.push("-d".into());
    }
    run_cmd("docker", args)?;
    status_after(opts, &format!("product {verb}"))
}

fn uninstall(opts: &GlobalOpts, args: &[String]) -> Result<ExitCode, String> {
    let purge = args.first().map(String::as_str) == Some("purge");
    if !opts.yes {
        return refused(
            opts,
            "product uninstall",
            "confirmation_required",
            vec!["pass --yes to stop units. Add 'purge' to remove volumes and deployment state.".into()],
            "uninstall confirmation",
        );
    }
    if !is_root() {
        return refused(
            opts,
            "product uninstall",
            "root_required",
            vec!["product uninstall must run as root".into()],
            "uninstall uid",
        );
    }
    let _ = systemctl(&["disable", "--now", "connector-product-reconcile.timer"]);
    for unit in UNITS {
        let _ = systemctl(&["disable", "--now", unit]);
    }
    if let Ok(stack) = stack_dir() {
        let env_file = state_dir().join("images.env");
        let compose_file = stack.join("compose.yaml");
        let env_arg = env_file.display().to_string();
        let file_arg = compose_file.display().to_string();
        let mut cmd = Command::new("docker");
        cmd.args(["compose", "--env-file", &env_arg, "-f", &file_arg]);
        if purge {
            cmd.args(["down", "-v"]);
        } else {
            cmd.arg("stop");
        }
        let _ = cmd.status();
        if purge {
            let _ = fs::remove_dir_all(state_dir());
        }
    }
    Ok(CmdResult {
        ok: true,
        command: "product uninstall".into(),
        exit: ExitCode::Success,
        source: Provenance::host("systemd and compose"),
        data: human_lines(vec![
            format!(
                "units stopped{}",
                if purge {
                    "; volumes and deployment state removed"
                } else {
                    "; deployment state kept"
                }
            ),
            "CONNECTOR NOT PRODUCTION READY".into(),
        ]),
        warnings: vec![],
        error: None,
    }
    .emit(opts))
}

fn status(opts: &GlobalOpts) -> Result<ExitCode, String> {
    status_after(opts, "product status")
}

fn status_after(opts: &GlobalOpts, command: &str) -> Result<ExitCode, String> {
    let report = evaluate(&probe_host(), &probe_services(opts), &probe_evidence(opts));
    let lines = crate::product_eval::report_lines(&report);
    let ready = report.production_ready;
    Ok(CmdResult {
        ok: ready,
        command: command.into(),
        exit: if ready {
            ExitCode::Success
        } else {
            ExitCode::Refused
        },
        source: Provenance::host("live processes plus deploy-verify evidence"),
        data: json!({
            "schema": SCHEMA,
            "production_ready": ready,
            "satisfied": report.satisfied,
            "required": 7,
            "blockers": report.blockers,
            "_human": lines,
        }),
        warnings: vec![],
        error: if ready {
            None
        } else {
            Some("connector_not_production_ready".into())
        },
    }
    .emit(opts))
}

fn diagnose(opts: &GlobalOpts) -> Result<ExitCode, String> {
    let report = evaluate(&probe_host(), &probe_services(opts), &probe_evidence(opts));
    let mut lines = crate::product_eval::report_lines(&report);
    lines.push("recovery: restart a dead unit at most 3 times, then leave the row NOT READY".into());
    lines.push("logs: journalctl -u connector-spire-server -u connector-spire-agent -u connector-microd -n 80 --no-pager".into());
    lines.push("verdict: connectorctl govern deploy-verify linux-kvm".into());
    Ok(CmdResult {
        ok: false,
        command: "product diagnose".into(),
        exit: if report.production_ready {
            ExitCode::Success
        } else {
            ExitCode::Refused
        },
        source: Provenance::host("product board and recovery rules"),
        data: json!({
            "schema": SCHEMA,
            "report_blockers": report.blockers,
            "recovery": recovery_semantics(),
            "_human": lines,
        }),
        warnings: vec![],
        error: if report.production_ready {
            None
        } else {
            Some("connector_not_production_ready".into())
        },
    }
    .emit(opts))
}

fn reconcile(opts: &GlobalOpts) -> Result<ExitCode, String> {
    let state = state_dir();
    if !state.join("desired.json").is_file() {
        return refused(
            opts,
            "product reconcile",
            "no_desired_state",
            vec!["no desired.json; run product install before reconcile".into()],
            "deployment state",
        );
    }
    let mut attempts = read_attempts(&state.join("observed.json"));
    if is_root() {
        for unit in UNITS {
            let active = unit_active(unit);
            let prior = attempts.get(*unit).copied().unwrap_or(0);
            match recovery_action(active, prior) {
                "restart" => {
                    let _ = systemctl(&["restart", unit]);
                    attempts.insert((*unit).to_string(), prior + 1);
                }
                "none" => {
                    attempts.insert((*unit).to_string(), 0);
                }
                _ => {}
            }
        }
    }
    let report = evaluate(&probe_host(), &probe_services(opts), &probe_evidence(opts));
    let observed = json!({
        "schema": "connector.product_observed.v1",
        "production_ready": report.production_ready,
        "satisfied": report.satisfied,
        "required": 7,
        "restart_attempts": attempts,
        "blockers": report.blockers,
    });
    let _ = fs::create_dir_all(&state);
    let _ = write_private(&state.join("observed.json"), observed.to_string().as_bytes(), 0o640);
    Ok(CmdResult {
        ok: true,
        command: "product reconcile".into(),
        exit: ExitCode::Success,
        source: Provenance::host("desired state versus live units"),
        data: observed,
        warnings: vec![],
        error: None,
    }
    .emit(opts))
}

fn demo(opts: &GlobalOpts, args: &[String]) -> Result<ExitCode, String> {
    if args.first().map(String::as_str) != Some("governed-agent") {
        return Err("usage: connectorctl product demo governed-agent".into());
    }
    let report = evaluate(&probe_host(), &probe_services(opts), &probe_evidence(opts));
    let steps = demo_steps(report.production_ready);
    let complete = steps.iter().all(|step| step["status"] == "present");
    let mut lines = vec![
        "governed-agent spine".into(),
        String::new(),
    ];
    for step in &steps {
        lines.push(format!(
            "{:<24} {}",
            step["step"].as_str().unwrap_or("?"),
            step["status"].as_str().unwrap_or("?")
        ));
    }
    if !complete {
        lines.push(String::new());
        lines.push("spine incomplete; no agent was registered and no model was called".into());
    }
    Ok(CmdResult {
        ok: complete,
        command: "product demo governed-agent".into(),
        exit: if complete {
            ExitCode::Success
        } else {
            ExitCode::Refused
        },
        source: Provenance::host("deploy-verify plus the scripted spine"),
        data: json!({
            "schema": "connector.product_demo.v1",
            "production_ready": report.production_ready,
            "steps": steps,
            "_human": lines,
        }),
        warnings: vec![],
        error: if complete {
            None
        } else {
            Some("governed_agent_spine_incomplete".into())
        },
    }
    .emit(opts))
}

fn task(opts: &GlobalOpts, args: &[String]) -> Result<ExitCode, String> {
    let request = match parse_task_args(args) {
        Ok(request) => request,
        Err(error) if error == "purpose_required" => {
            return refused(
                opts,
                "product task",
                "purpose_required",
                vec!["Name the job this agent is for. Empty or general-purpose is not a charter.".into()],
                "task purpose",
            );
        }
        Err(error) => return Err(error),
    };
    let client = Client::new(opts).map_err(|e| e.to_string())?;
    let verify = match client.get_json("/api/v1/runtime/deploy-verify?profile=linux-kvm") {
        Ok(value) => value,
        Err(error) => {
            return refused(
                opts,
                "product task",
                "deploy_verify_unavailable",
                vec![error.message()],
                "GET /api/v1/runtime/deploy-verify",
            );
        }
    };
    let operational = verify.get("operational_ready").and_then(Value::as_bool) == Some(true);
    let mut blockers = task_blockers(
        env_flag_on(std::env::var("CONNECTOR_AUGMENTED_ENV").ok().as_deref()),
        env_flag_on(std::env::var("CONNECTOR_PLAYGROUND").ok().as_deref()),
        opts.api_key.as_deref() == Some("dev-token"),
        operational,
    );
    if !operational {
        if let Some(rows) = verify.get("blockers").and_then(Value::as_array) {
            for row in rows {
                blockers.push(row.to_string());
            }
        }
    }
    if !blockers.is_empty() {
        return refused(opts, "product task", "augmented_task_refused", blockers, "augmented gate");
    }

    let surface = classify_surface(&request.surface)?;
    let (pid, registered) = match bind_builtin(&client, &request) {
        Ok(bound) => bound,
        Err(error) => {
            return refused(
                opts,
                "product task",
                "agent_bind_failed",
                vec![error],
                "POST /api/v1/agents",
            );
        }
    };
    let bound = client.post_json(
        "/api/v1/product/tasks",
        json!({
            "pid": pid,
            "model": request.model,
            "purpose": request.purpose,
            "surface": request.surface,
            "surface_kind": match surface {
                SurfaceKind::Workspace => "workspace",
                SurfaceKind::Sandbox => "sandbox",
                SurfaceKind::Dedicated => "dedicated",
            },
            "contract": surface_contract_patch(&request.purpose, &request.surface, surface),
        }),
    );
    let model_update = bound.as_ref().ok().and_then(|body| body.get("model")).cloned();
    let contract_patch = bound.as_ref().map(|body| body.clone()).unwrap_or_else(|error| {
        json!({"ok": false, "detail": error.message()})
    });
    if model_update.as_ref().and_then(Value::as_str) != Some(request.model.as_str()) {
        return refused(
            opts,
            "product task",
            "model_not_confirmed",
            vec![format!("stored model did not match {}", request.model)],
            "POST /api/v1/product/tasks",
        );
    }
    let _ = client.post_json(
        &format!("/api/v1/agents/{pid}/setup"),
        json!({"acume": request.purpose, "setup_complete": true}),
    );
    let _ = client.post_json(&format!("/api/v1/agents/{pid}/activate"), json!({}));
    let contract = client
        .get_json(&format!("/api/v1/agents/{pid}/contract"))
        .unwrap_or(Value::Null);
    let grants = client
        .get_json(&format!("/api/v1/agents/{pid}/grants"))
        .unwrap_or(Value::Null);
    let ceiling = client
        .get_json(&format!("/api/v1/spend/ceiling/{pid}"))
        .unwrap_or(json!({"ceiling": null}));

    let mut talk = json!({"status": "skipped", "detail": "pass --talk to consult the brain. This command does not invent model text."});
    let mut journal_id = None;
    if request.talk {
        match consult(&client, &pid, &request.model, &request.purpose) {
            Ok(turn) => {
                journal_id = response_text(&turn, &["/hitl_request_id", "/session/hitl_request_id", "/journal_id"]);
                talk = turn;
            }
            Err(error) => {
                talk = json!({"status": "absent", "detail": error});
            }
        }
    }

    let mut microcell_id = None;
    let mut promote = json!({"status": "skipped"});
    if surface == SurfaceKind::Dedicated {
        match client.post_json(
            &format!("/api/v1/agents/{pid}/isolation/promote"),
            json!({"target": "dedicated"}),
        ) {
            Ok(body) => {
                microcell_id = response_text(&body, &["/execution_body/microcell_id", "/microcell_id"]);
                promote = body;
            }
            Err(error) => {
                promote = json!({"status": "absent", "detail": error.message()});
            }
        }
    }

    let mut proof = json!({});
    let mut cease_body = json!({});
    if request.cease {
        cease_body = client
            .post_json(&format!("/api/v1/agents/{pid}/cease"), json!({}))
            .unwrap_or_else(|error| json!({"ok": false, "detail": error.message()}));
        proof = client
            .get_json(&format!("/api/v1/runtime/cease-proof/{pid}"))
            .unwrap_or(json!({}));
    }
    let receipt_id = response_text(&cease_body, &["/spend_cease/receipt_id", "/receipt_id"])
        .or_else(|| response_text(&registered, &["/handshake_proof_receipt_id"]));
    let explain = match receipt_id.as_deref() {
        Some(id) => client
            .get_json(&format!("/api/v1/runtime/explain/{id}"))
            .unwrap_or(json!({"schema": "connector.explain.v1", "found": false, "receipt_id": id})),
        None => json!({"schema": "connector.explain.v1", "found": false}),
    };
    let policy = {
        let from_explain = policy_from_explain(&explain);
        if from_explain.get("pushed").and_then(Value::as_bool) == Some(true) {
            from_explain
        } else {
            find_policy(&cease_body)
        }
    };
    let services = probe_services(opts);
    let facts = OutcomeFacts {
        explain: &explain,
        cease_proof: &proof,
        deploy_verify: &verify,
        services: &services,
        ceiling: &ceiling,
        policy: &policy,
        task_agent_pid: &pid,
        journal_id: journal_id.as_deref(),
        microcell_id: microcell_id.as_deref(),
    };
    let score = score_outcomes(&facts);
    let stage = task_stage(&score, &explain);
    let complete = task_execution_complete(stage);
    let mut lines = vec![
        format!("augmented agent {pid}"),
        format!("stage {stage}"),
        format!("brain {}", request.model),
        format!("surface {}", request.surface),
        format!("purpose {}", request.purpose),
        String::new(),
    ];
    if let Some(rows) = score.get("outcomes").and_then(Value::as_array) {
        for row in rows {
            lines.push(format!(
                "{:<16} {}",
                row.get("id").and_then(Value::as_str).unwrap_or("?"),
                row.get("status").and_then(Value::as_str).unwrap_or("absent")
            ));
        }
    }
    lines.push(String::new());
    if let Some(rows) = score.get("backends").and_then(Value::as_array) {
        for row in rows {
            lines.push(format!(
                "{:<16} {}  admits false",
                row.get("id").and_then(Value::as_str).unwrap_or("?"),
                row.get("status").and_then(Value::as_str).unwrap_or("absent")
            ));
        }
    }
    if !complete {
        lines.push(String::new());
        lines.push("configured is not executed. Success needs an admitted effect that was observed.".into());
    }
    Ok(CmdResult {
        ok: complete,
        command: "product task".into(),
        exit: if complete { ExitCode::Success } else { ExitCode::Refused },
        source: Provenance::host("existing agent, contract, spend, explain, and deploy-verify routes"),
        data: json!({
            "schema": OUTCOMES_SCHEMA,
            "stage": stage,
            "pid": pid,
            "model_update": model_update.unwrap_or(Value::Null),
            "contract_patch": contract_patch,
            "model_ref": request.model,
            "surface": request.surface,
            "purpose": request.purpose,
            "registered": registered,
            "contract": contract,
            "grants": grants,
            "talk": talk,
            "promote": promote,
            "score": score,
            "_human": lines,
        }),
        warnings: vec![],
        error: if complete { None } else { Some(format!("augmented_task_{stage}")) },
    }
    .emit(opts))
}

fn bind_builtin(client: &Client, request: &crate::product_eval::TaskRequest) -> Result<(String, Value), String> {
    if let Some(pid) = &request.pid {
        let body = client
            .get_json(&format!("/api/v1/agents/{pid}"))
            .map_err(|e| e.message())?;
        return Ok((pid.clone(), body));
    }
    let created = client.post_json(
        "/api/v1/agents",
        json!({
            "name": "connector-builtin",
            "purpose": request.purpose,
            "model": request.model,
            "namespace": "m/connector-builtin",
        }),
    );
    match created {
        Ok(body) => {
            if let Some(pid) = body.get("pid").and_then(Value::as_str) {
                return Ok((pid.to_string(), body));
            }
            Err(body.to_string())
        }
        Err(error) => {
            let listed = client.get_json("/api/v1/agents").map_err(|e| e.message())?;
            if let Some(pid) = reuse_builtin(&listed) {
                return Ok((pid, json!({"reused": true})));
            }
            Err(error.message())
        }
    }
}

fn reuse_builtin(list: &Value) -> Option<String> {
    let rows = list
        .as_array()
        .or_else(|| list.get("agents").and_then(Value::as_array))?;
    rows.iter().find_map(|row| {
        let name = row.get("name").and_then(Value::as_str).unwrap_or("");
        let purpose = row.get("purpose").and_then(Value::as_str).unwrap_or("");
        if name == "connector-builtin" || purpose == "connector-builtin" {
            row.get("pid").and_then(Value::as_str).map(|s| s.to_string())
        } else {
            None
        }
    })
}

fn consult(client: &Client, pid: &str, model: &str, purpose: &str) -> Result<Value, String> {
    let session = client
        .post_json(
            &format!("/api/v1/agents/{pid}/workbench/sessions"),
            json!({"title": "augmented", "goal": purpose}),
        )
        .map_err(|e| e.message())?;
    let sid = first_string(&session, &["session_id", "sid", "id"])
        .ok_or_else(|| "workbench session did not return an id".to_string())?;
    client
        .post_json(
            &format!("/api/v1/agents/{pid}/workbench/sessions/{sid}/turn"),
            json!({"message": purpose, "model": model}),
        )
        .map_err(|e| e.message())
}

fn first_string(value: &Value, keys: &[&str]) -> Option<String> {
    let mut layers = vec![value];
    for nest in ["data", "session", "latest", "receipt"] {
        if let Some(child) = value.get(nest) {
            layers.push(child);
        }
    }
    for layer in layers {
        for key in keys {
            if let Some(text) = layer.get(*key).and_then(Value::as_str) {
                if !text.is_empty() {
                    return Some(text.to_string());
                }
            }
        }
    }
    None
}

fn find_policy(value: &Value) -> Value {
    if value.get("openshell_ready").is_some() {
        return value.clone();
    }
    match value {
        Value::Object(map) => {
            for child in map.values() {
                let found = find_policy(child);
                if found.get("openshell_ready").is_some() {
                    return found;
                }
            }
        }
        Value::Array(items) => {
            for child in items {
                let found = find_policy(child);
                if found.get("openshell_ready").is_some() {
                    return found;
                }
            }
        }
        _ => {}
    }
    json!({})
}

fn static_json(opts: &GlobalOpts, command: &str, data: Value) -> Result<ExitCode, String> {
    Ok(CmdResult {
        ok: true,
        command: command.into(),
        exit: ExitCode::Success,
        source: Provenance::host("product contract"),
        data,
        warnings: vec![],
        error: None,
    }
    .emit(opts))
}

fn load_decision(spec_path: &str) -> Result<(InstallDecision, Option<DeploymentSpec>), String> {
    let raw = fs::read_to_string(spec_path).map_err(|e| format!("read {spec_path}: {e}"))?;
    let value: Value = serde_json::from_str(&raw).map_err(|e| format!("spec json: {e}"))?;
    let parsed = parse_spec(&value, &state_dir().display().to_string());
    let decision = decide_install(&parsed, &probe_host());
    let spec = parsed.ok();
    Ok((decision, spec))
}

fn ensure_kvm_device() {
    if std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
        .is_ok()
    {
        return;
    }
    let cpu = fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    let module = if cpu.split_whitespace().any(|flag| flag == "svm") {
        "kvm_amd"
    } else if cpu.split_whitespace().any(|flag| flag == "vmx") {
        "kvm_intel"
    } else {
        return;
    };
    let _ = Command::new("modprobe").arg("kvm").status();
    let _ = Command::new("modprobe").arg(module).status();
}

fn probe_host() -> HostFacts {
    ensure_kvm_device();
    HostFacts {
        kvm_usable: File::options()
            .read(true)
            .write(true)
            .open("/dev/kvm")
            .is_ok(),
        systemd: Command::new("systemctl")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false),
        compose: Command::new("docker")
            .args(["compose", "version"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
            || Command::new("podman")
                .args(["compose", "version"])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false),
        cgroup_v2: Path::new("/sys/fs/cgroup/cgroup.controllers").is_file(),
    }
}

fn probe_services(opts: &GlobalOpts) -> ServiceFacts {
    let connector = Client::new(opts)
        .and_then(|client| client.get_json("/healthz").map(|_| ()).map_err(|e| e.message()))
        .is_ok();
    let compose_text = compose_ps();
    ServiceFacts {
        connector,
        keycloak: compose_text.contains("keycloak") || keycloak_realm_up(),
        spire: (unit_active("connector-spire-server") && unit_active("connector-spire-agent"))
            || (process_running("spire-server") && process_running("spire-agent")),
        openshell: tcp_open(17670),
        microd: unit_active("connector-microd") || microd_ready_file(),
        otel: timed_ok("curl", &["--fail", "--silent", "--show-error", "http://127.0.0.1:13133/"]),
        cosign: cosign_binary_runs(),
    }
}

fn probe_evidence(opts: &GlobalOpts) -> EvidenceFacts {
    Client::new(opts)
        .ok()
        .and_then(|client| client.get_json("/api/v1/runtime/deploy-verify?profile=linux-kvm").ok())
        .map(|value| EvidenceFacts::from_deploy_verify(&value))
        .unwrap_or_default()
}

fn compose_ps() -> String {
    let env = state_dir().join("images.env");
    let Ok(stack) = stack_dir() else {
        return String::new();
    };
    let env_arg = env.display().to_string();
    let file_arg = stack.join("compose.yaml").display().to_string();
    let output = Command::new("docker")
        .args([
            "compose",
            "--env-file",
            &env_arg,
            "-f",
            &file_arg,
            "ps",
            "--status",
            "running",
        ])
        .output();
    output
        .ok()
        .filter(|out| out.status.success())
        .map(|out| String::from_utf8_lossy(&out.stdout).to_string())
        .unwrap_or_default()
}

fn read_attempts(path: &Path) -> std::collections::BTreeMap<String, u32> {
    let mut map = std::collections::BTreeMap::new();
    let Ok(value) = read_json(path) else {
        return map;
    };
    let Some(obj) = value.get("restart_attempts").and_then(Value::as_object) else {
        return map;
    };
    for (key, raw) in obj {
        if let Some(n) = raw.as_u64() {
            map.insert(key.clone(), n as u32);
        }
    }
    map
}

fn write_desired(state: &Path, spec_path: &str) -> Result<(), String> {
    let raw = fs::read_to_string(spec_path).map_err(|e| e.to_string())?;
    write_private(&state.join("desired.json"), raw.as_bytes(), 0o640)
}

fn state_dir() -> PathBuf {
    std::env::var("CONNECTOR_PRODUCT_STATE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/var/lib/connector/deployment"))
}

fn stack_dir() -> Result<PathBuf, String> {
    if let Ok(path) = std::env::var("CONNECTOR_LINUX_STACK") {
        return Ok(PathBuf::from(path));
    }
    for candidate in [
        "/usr/share/connector/seven-backends/linux",
        "platform/deploy/seven-backends/linux",
    ] {
        if Path::new(candidate).join("up.sh").is_file() {
            return Ok(PathBuf::from(candidate));
        }
    }
    Err("set CONNECTOR_LINUX_STACK to the seven-backends/linux directory".into())
}

fn is_root() -> bool {
    fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|text| {
            text.lines().find_map(|line| {
                let rest = line.strip_prefix("Uid:")?;
                Some(rest.split_whitespace().next() == Some("0"))
            })
        })
        .unwrap_or(false)
}

fn unit_active(unit: &str) -> bool {
    Command::new("systemctl")
        .args(["is-active", "--quiet", unit])
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn timed_ok(program: &str, args: &[&str]) -> bool {
    Command::new("timeout")
        .arg("5")
        .arg(program)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn process_running(name: &str) -> bool {
    Command::new("pgrep")
        .args(["-x", name])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn tcp_open(port: u16) -> bool {
    std::net::TcpStream::connect_timeout(
        &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
        std::time::Duration::from_millis(400),
    )
    .is_ok()
}

fn keycloak_realm_up() -> bool {
    for url in [
        "https://127.0.0.1:8443/realms/connector/.well-known/openid-configuration",
        "https://127.0.0.1:18443/realms/connector/.well-known/openid-configuration",
    ] {
        if timed_ok(
            "curl",
            &["--fail", "--silent", "--show-error", "--insecure", url],
        ) {
            return true;
        }
    }
    false
}

fn microd_ready_file() -> bool {
    let sock = std::env::var("CONNECTOR_MICROD_SOCK")
        .unwrap_or_else(|_| "/run/connector/microd.sock".into());
    let ready = std::env::var("CONNECTOR_MICROD_READY_FILE")
        .unwrap_or_else(|_| "/run/connector/microd.ready".into());
    Path::new(&sock).exists() && Path::new(&ready).is_file()
}

fn cosign_binary_runs() -> bool {
    if let Ok(bin) = std::env::var("CONNECTOR_COSIGN_BIN") {
        let bin = bin.trim();
        if !bin.is_empty() && Path::new(bin).is_file() && timed_ok(bin, &["version"]) {
            return true;
        }
    }
    timed_ok("cosign", &["version"])
}

fn systemctl(args: &[&str]) -> Result<(), String> {
    let status = Command::new("systemctl")
        .args(args)
        .status()
        .map_err(|e| format!("systemctl: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("systemctl {} exited {status}", args.join(" ")))
    }
}

fn run_cmd<I, S>(program: &str, args: I) -> Result<(), String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr> + std::fmt::Debug,
{
    let args: Vec<S> = args.into_iter().collect();
    let status = Command::new(program)
        .args(&args)
        .status()
        .map_err(|e| format!("{program}: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{program} {args:?} exited {status}"))
    }
}

fn ensure_secret(path: &str) -> Result<(), String> {
    let file = Path::new(path);
    if file.is_file() {
        return Ok(());
    }
    if let Some(parent) = file.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).ok();
    }
    let mut bytes = [0u8; 32];
    File::open("/dev/urandom")
        .and_then(|mut src| src.read_exact(&mut bytes))
        .map_err(|e| format!("read randomness: {e}"))?;
    write_private(file, format!("{}\n", hex::encode(bytes)).as_bytes(), 0o600)
}

fn read_secret(path: &str) -> Result<String, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("read secret file: {e}"))?;
    let text = text.trim();
    if text.is_empty() || text.chars().any(|ch| ch.is_whitespace()) {
        return Err(format!("secret file {path} is empty or contains whitespace"));
    }
    Ok(text.to_string())
}

fn sha256_file(path: &str) -> Result<String, String> {
    let mut file = File::open(path).map_err(|e| format!("open {path}: {e}"))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = file.read(&mut buf).map_err(|e| format!("read {path}: {e}"))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn write_private(path: &Path, bytes: &[u8], mode: u32) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    let mut file = File::create(path).map_err(|e| format!("create {}: {e}", path.display()))?;
    file.write_all(bytes).map_err(|e| format!("write {}: {e}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).ok();
    Ok(())
}

fn install_file(from: &Path, to: &Path, mode: u32) -> Result<(), String> {
    if let Some(parent) = to.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    fs::copy(from, to).map_err(|e| format!("copy {} -> {}: {e}", from.display(), to.display()))?;
    fs::set_permissions(to, fs::Permissions::from_mode(mode)).ok();
    Ok(())
}

fn read_json(path: &Path) -> Result<Value, String> {
    let raw = fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    serde_json::from_str(&raw).map_err(|e| format!("json {}: {e}", path.display()))
}

fn refused(
    opts: &GlobalOpts,
    command: &str,
    error: &str,
    blockers: Vec<String>,
    source: &str,
) -> Result<ExitCode, String> {
    let mut lines = vec!["CONNECTOR NOT PRODUCTION READY".into(), String::new(), "Blocker:".into()];
    lines.extend(blockers.iter().cloned());
    Ok(CmdResult {
        ok: false,
        command: command.into(),
        exit: ExitCode::Refused,
        source: Provenance::host(source),
        data: json!({
            "schema": SCHEMA,
            "production_ready": false,
            "blockers": blockers,
            "_human": lines,
        }),
        warnings: vec![],
        error: Some(error.into()),
    }
    .emit(opts))
}

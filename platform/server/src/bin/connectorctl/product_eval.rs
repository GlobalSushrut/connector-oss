//! Product decisions for the Linux/KVM deployment.
//!
//! These functions do not talk to a backend and do not mark a deployment
//! ready. `connectorctl product` prints their result. Readiness still requires
//! live processes and the operational evidence from `govern deploy-verify`.

use serde_json::{json, Value};

pub const SCHEMA: &str = "connector.product.v1";
pub const PROFILE: &str = "linux-kvm";
pub const POLICY_SCHEMA: u32 = 1;
pub const RESTART_BUDGET: u32 = 3;
pub const EVIDENCE_REQUIRED: u32 = 7;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostFacts {
    pub kvm_usable: bool,
    pub systemd: bool,
    pub compose: bool,
    pub cgroup_v2: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceFacts {
    pub connector: bool,
    pub keycloak: bool,
    pub spire: bool,
    pub openshell: bool,
    pub microd: bool,
    pub otel: bool,
    pub cosign: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EvidenceFacts {
    pub iam: bool,
    pub spire: bool,
    pub openshell: bool,
    pub opa: bool,
    pub firecracker: bool,
    pub otel: bool,
    pub cosign: bool,
}

impl EvidenceFacts {
    pub fn from_deploy_verify(value: &Value) -> Self {
        let mut facts = Self::default();
        let Some(rows) = value.get("backends").and_then(Value::as_array) else {
            return facts;
        };
        for row in rows {
            let id = row.get("id").and_then(Value::as_str).unwrap_or("");
            let ready = row.get("ready").and_then(Value::as_bool) == Some(true);
            match id {
                "iam" => facts.iam = ready,
                "spire" => facts.spire = ready,
                "openshell" => facts.openshell = ready,
                "opa" => facts.opa = ready,
                "firecracker" => facts.firecracker = ready,
                "otel" => facts.otel = ready,
                "cosign" => facts.cosign = ready,
                _ => {}
            }
        }
        facts
    }

    pub fn satisfied(&self) -> u32 {
        [
            self.iam,
            self.spire,
            self.openshell,
            self.opa,
            self.firecracker,
            self.otel,
            self.cosign,
        ]
        .into_iter()
        .filter(|ready| *ready)
        .count() as u32
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoardRow {
    pub label: &'static str,
    pub ready: bool,
    pub action: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductReport {
    pub rows: Vec<BoardRow>,
    pub satisfied: u32,
    pub production_ready: bool,
    pub blockers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeploymentSpec {
    pub profile: String,
    pub trust_domain: String,
    pub postgres_image: String,
    pub keycloak_image: String,
    pub otel_image: String,
    pub admin_password_file: String,
    pub db_password_file: String,
    pub sso_client_secret_file: String,
    pub artifact_pins: Vec<(String, String)>,
    pub policy_schema: u32,
    pub kernel_path: String,
    pub kernel_sha256: String,
    pub rootfs_path: String,
    pub rootfs_sha256: String,
    pub hostname: String,
    pub tls_dir: String,
    pub otel_upstream: String,
    pub redirect_uri: String,
    pub admin_user: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallDecision {
    Refuse { blockers: Vec<String> },
    Plan { steps: Vec<&'static str> },
}

pub fn providers() -> Value {
    json!({
        "schema": "connector.product_providers.v1",
        "ownership": "Connector configures and supervises certified implementations. It does not fork them and it does not let them admit.",
        "providers": [
            {"contract": "IdentityProvider", "implementation": "Keycloak", "connector_does": "OIDC authorization-code + PKCE S256 and JWKS ID-token verification", "connector_does_not": "become the directory or mint PATE Allow"},
            {"contract": "WorkloadIdentityProvider", "implementation": "SPIRE", "connector_does": "fetch an X.509 SVID from the Workload API", "connector_does_not": "issue SVIDs"},
            {"contract": "PolicyProvider", "implementation": "OpenShell with OPA/Rego", "connector_does": "compile AgentContractV2 and call openshell policy set --wait", "connector_does_not": "run opa eval or mint Allow"},
            {"contract": "IsolationProvider", "implementation": "Firecracker + jailer via connector-microd", "connector_does": "create, start, pause, and stop a MicroCell", "connector_does_not": "treat the sandbox id as the agent"},
            {"contract": "TelemetryProvider", "implementation": "OpenTelemetry Collector", "connector_does": "export OTLP and count a batch the collector accepted", "connector_does_not": "treat a configured endpoint as evidence"},
            {"contract": "ArtifactVerifier", "implementation": "Sigstore cosign", "connector_does": "cosign verify-blob of the configured manifest", "connector_does_not": "accept a missing signature as verified"}
        ]
    })
}

pub fn compatibility() -> Value {
    json!({
        "schema": "connector.product_compatibility.v1",
        "product_profile": PROFILE,
        "connector": env!("CARGO_PKG_VERSION"),
        "supported": {
            "iam": "oidc-pkce-s256",
            "workload_identity": "spire-workload-api-x509",
            "policy": "openshell-policy-schema-1",
            "isolation": "firecracker-via-connector-microd",
            "telemetry": "otlp-grpc",
            "artifact": "cosign-verify-blob"
        },
        "refused": ["kubernetes as the one-command production install", "unpinned image tags", "inline secrets", "opa eval inside Connector"],
        "honesty": "A supported contract is not a tested certification range for every upstream release. The deployment spec pins digests. deploy-verify is still required."
    })
}

pub fn recovery_semantics() -> Value {
    json!({
        "schema": "connector.product_recovery.v1",
        "restart_budget": RESTART_BUDGET,
        "cases": [
            {"failure": "SPIRE server or agent exits", "action": "restart the unit up to the budget, then stop and leave Workload identity NOT READY until a new SVID fetch succeeds"},
            {"failure": "SVID rotates", "action": "the next explain fetches again. A stale SPIFFE ID is not reused. Admission does not proceed on a missing fetch."},
            {"failure": "Keycloak unavailable", "action": "operator login fails closed. IAM stays NOT READY until a new JWKS-verified ID token is recorded."},
            {"failure": "OpenTelemetry collector stops accepting batches", "action": "Telemetry becomes NOT READY on the next reconcile. A previous export does not keep the row READY."},
            {"failure": "OpenShell policy set fails halfway", "action": "no success evidence is written. Policy enforcement stays NOT READY. PATE is unchanged."},
            {"failure": "Firecracker or microd exits", "action": "restart microd up to the budget. Isolation stays NOT READY until the create/start, pause, and stop sequence exists again."},
            {"failure": "cosign verify-blob fails", "action": "Artifact verification stays NOT READY. Connector does not install or upgrade from that manifest."},
            {"failure": "every backend is down", "action": "reconcile restarts only units named in the desired spec, then reports NOT PRODUCTION READY. It does not admit and it does not call a model."}
        ]
    })
}

pub fn evaluate(host: &HostFacts, services: &ServiceFacts, evidence: &EvidenceFacts) -> ProductReport {
    let policy_evidence = evidence.openshell && evidence.opa;
    let isolation_evidence = evidence.firecracker && host.kvm_usable && services.microd;
    let rows = vec![
        row(
            "Connector",
            services.connector,
            "start connector-platform and confirm /healthz",
        ),
        row(
            "IAM",
            services.keycloak && evidence.iam,
            if !services.keycloak {
                "start Keycloak, then complete one JWKS-verified OIDC login"
            } else {
                "complete one JWKS-verified OIDC login; a local JWT is not enough"
            },
        ),
        row(
            "Workload identity",
            services.spire && evidence.spire,
            if !services.spire {
                "start connector-spire-server and connector-spire-agent"
            } else {
                "SPIRE Workload API has not returned a spiffe:// SVID"
            },
        ),
        row(
            "Policy enforcement",
            services.openshell && policy_evidence,
            if !services.openshell {
                "OpenShell gateway is not reachable"
            } else {
                "no successful openshell policy set --wait evidence"
            },
        ),
        row(
            "Isolation",
            isolation_evidence,
            if !host.kvm_usable {
                "Firecracker isolation requires KVM."
            } else if !services.microd {
                "start connector-microd with a measured kernel and rootfs"
            } else {
                "Firecracker create/start, pause, and stop have not been recorded on one MicroCell"
            },
        ),
        row(
            "Telemetry",
            services.otel && evidence.otel,
            if !services.otel {
                "start the OpenTelemetry Collector"
            } else {
                "the collector has not accepted an OTLP batch"
            },
        ),
        row(
            "Artifact verification",
            services.cosign && evidence.cosign,
            if !services.cosign {
                "install the digest-pinned cosign binary"
            } else {
                "cosign verify-blob has not succeeded"
            },
        ),
    ];
    let production_ready = evidence.satisfied() == EVIDENCE_REQUIRED
        && services.connector
        && services.keycloak
        && services.spire
        && services.openshell
        && services.microd
        && services.otel
        && services.cosign
        && host.kvm_usable
        && host.systemd
        && host.compose
        && host.cgroup_v2;
    let mut rows = rows;
    rows.push(row(
        "Governed execution",
        production_ready,
        "production ready requires all seven evidence rows and the live processes above",
    ));
    let blockers = rows
        .iter()
        .filter(|row| !row.ready)
        .map(|row| format!("{}: {}", row.label, row.action))
        .collect();
    ProductReport {
        satisfied: evidence.satisfied(),
        production_ready,
        blockers,
        rows,
    }
}

fn row(label: &'static str, ready: bool, action: &'static str) -> BoardRow {
    BoardRow {
        label,
        ready,
        action,
    }
}

pub fn report_lines(report: &ProductReport) -> Vec<String> {
    let mut lines = Vec::new();
    for row in &report.rows {
        lines.push(format!(
            "{:<24} {}",
            row.label,
            if row.ready { "READY" } else { "NOT READY" }
        ));
    }
    lines.push(String::new());
    lines.push(format!(
        "{}/{} evidence requirements satisfied",
        report.satisfied, EVIDENCE_REQUIRED
    ));
    lines.push(String::new());
    if report.production_ready {
        lines.push("CONNECTOR READY".into());
    } else {
        lines.push("CONNECTOR NOT PRODUCTION READY".into());
        lines.push(String::new());
        lines.push("Blocker:".into());
        for blocker in &report.blockers {
            lines.push(blocker.clone());
        }
    }
    lines.push(String::new());
    lines.push(
        "READY means the process is up and operational evidence exists. A previous success does not keep a dead service READY."
            .into(),
    );
    lines
}

pub fn parse_spec(value: &Value, state_dir: &str) -> Result<DeploymentSpec, Vec<String>> {
    let mut blockers = Vec::new();
    let profile = value
        .get("profile")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if profile != PROFILE {
        blockers.push(format!(
            "product install supports profile {PROFILE} only (got '{profile}')"
        ));
    }
    let trust_domain = value
        .get("trust_domain")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if let Err(error) = validate_trust_domain(&trust_domain) {
        blockers.push(error);
    }
    let policy_schema = value
        .pointer("/compatibility/openshell_policy_schema")
        .and_then(Value::as_u64)
        .unwrap_or(POLICY_SCHEMA as u64) as u32;
    if policy_schema != POLICY_SCHEMA {
        blockers.push(format!(
            "OpenShell policy schema {policy_schema} is not supported; Connector compiles schema {POLICY_SCHEMA}"
        ));
    }
    let postgres_image = pinned_image(value, "/images/postgres", &mut blockers);
    let keycloak_image = pinned_image(value, "/images/keycloak", &mut blockers);
    let otel_image = pinned_image(value, "/images/otel_collector", &mut blockers);
    let (admin_password_file, db_password_file, sso_client_secret_file) =
        secret_files(value, state_dir, &mut blockers);
    let artifact_pins = artifact_pins(value, &mut blockers);
    let kernel_path = required_abs(value, "/firecracker/kernel_path", &mut blockers);
    let kernel_sha256 = required_sha256(value, "/firecracker/kernel_sha256", &mut blockers);
    let rootfs_path = required_abs(value, "/firecracker/rootfs_path", &mut blockers);
    let rootfs_sha256 = required_sha256(value, "/firecracker/rootfs_sha256", &mut blockers);
    let hostname = required_token(value, "/keycloak/hostname", &mut blockers);
    let tls_dir = required_abs(value, "/keycloak/tls_dir", &mut blockers);
    let otel_upstream = required_token(value, "/otel/upstream_endpoint", &mut blockers);
    let redirect_uri = required_token(value, "/keycloak/redirect_uri", &mut blockers);
    let admin_user = required_token(value, "/keycloak/admin_user", &mut blockers);
    if blockers.is_empty() {
        Ok(DeploymentSpec {
            profile,
            trust_domain,
            postgres_image,
            keycloak_image,
            otel_image,
            admin_password_file,
            db_password_file,
            sso_client_secret_file,
            artifact_pins,
            policy_schema,
            kernel_path,
            kernel_sha256,
            rootfs_path,
            rootfs_sha256,
            hostname,
            tls_dir,
            otel_upstream,
            redirect_uri,
            admin_user,
        })
    } else {
        Err(blockers)
    }
}

pub fn decide_install(spec: &Result<DeploymentSpec, Vec<String>>, host: &HostFacts) -> InstallDecision {
    let mut blockers = Vec::new();
    if let Err(errors) = spec {
        blockers.extend(errors.clone());
    }
    if !host.kvm_usable {
        blockers.push("Firecracker isolation requires KVM.".into());
    }
    if !host.systemd {
        blockers.push("systemd is required to own SPIRE, microd, and the reconcile timer".into());
    }
    if !host.compose {
        blockers.push("docker compose or podman compose is required for Keycloak and the collector".into());
    }
    if !host.cgroup_v2 {
        blockers.push("cgroup v2 is required".into());
    }
    if !blockers.is_empty() {
        return InstallDecision::Refuse { blockers };
    }
    InstallDecision::Plan {
        steps: vec![
            "verify-pinned-artifacts",
            "install-pinned-artifacts",
            "render-spire-config",
            "write-secret-files",
            "write-compose-env",
            "start-keycloak-and-collector",
            "bootstrap-keycloak-realm",
            "start-spire",
            "register-spire-agent",
            "write-microd-env",
            "start-microd",
            "write-connector-env",
            "enable-reconcile-timer",
            "run-deploy-verify",
        ],
    }
}

pub fn upgrade_decision(previous_profile: &str, next_profile: &str, policy_schema: u32) -> Result<(), String> {
    if previous_profile != PROFILE || next_profile != PROFILE {
        return Err(format!(
            "upgrade stays on {PROFILE}; refusing '{previous_profile}' -> '{next_profile}'"
        ));
    }
    if policy_schema != POLICY_SCHEMA {
        return Err(format!(
            "upgrade refuses OpenShell policy schema {policy_schema}"
        ));
    }
    Ok(())
}

pub fn recovery_action(active: bool, attempts: u32) -> &'static str {
    if active {
        "none"
    } else if attempts < RESTART_BUDGET {
        "restart"
    } else {
        "budget_exhausted"
    }
}

pub fn validate_trust_domain(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 253
        || !value
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '.' || ch == '-')
        || value.starts_with('.')
        || value.ends_with('.')
        || value.contains("..")
    {
        return Err(format!(
            "trust_domain must be a DNS name without whitespace (got '{value}')"
        ));
    }
    Ok(())
}

pub fn render_spire_server(trust_domain: &str) -> Result<String, String> {
    validate_trust_domain(trust_domain)?;
    Ok(format!(
        r#"server {{
    bind_address = "127.0.0.1"
    bind_port = "8081"
    trust_domain = "{trust_domain}"
    data_dir = "/var/lib/spire/server"
    log_level = "INFO"
    socket_path = "/run/spire/server/private/api.sock"
    ca_ttl = "24h"
    default_x509_svid_ttl = "1h"
}}

plugins {{
    DataStore "sql" {{
        plugin_data {{
            database_type = "sqlite3"
            connection_string = "/var/lib/spire/server/datastore.sqlite3"
        }}
    }}
    KeyManager "disk" {{
        plugin_data {{
            keys_path = "/var/lib/spire/server/keys.json"
        }}
    }}
    NodeAttestor "join_token" {{
        plugin_data {{}}
    }}
}}
"#
    ))
}

pub fn render_spire_agent(trust_domain: &str, join_token: &str) -> Result<String, String> {
    validate_trust_domain(trust_domain)?;
    if join_token.is_empty()
        || !join_token
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
    {
        return Err("SPIRE join token is empty or contains whitespace".into());
    }
    Ok(format!(
        r#"agent {{
    data_dir = "/var/lib/spire/agent"
    log_level = "INFO"
    trust_domain = "{trust_domain}"
    server_address = "127.0.0.1"
    server_port = "8081"
    socket_path = "/run/spire/agent/sockets/api.sock"
    insecure_bootstrap = true
    join_token = "{join_token}"
}}

plugins {{
    NodeAttestor "join_token" {{
        plugin_data {{}}
    }}
    KeyManager "memory" {{
        plugin_data {{}}
    }}
    WorkloadAttestor "unix" {{
        plugin_data {{}}
    }}
}}
"#
    ))
}

pub fn demo_steps(production_ready: bool) -> Vec<Value> {
    let gate = if production_ready { "call" } else { "not_run" };
    let later = if production_ready { "target" } else { "not_run" };
    vec![
        json!({"step": "deploy-verify", "status": if production_ready { "present" } else { "refused" }}),
        json!({"step": "register-intelligence", "status": gate, "route": "POST /api/v1/agents"}),
        json!({"step": "compile-contract", "status": later, "reason": "compile_contract is in-process; this command does not pretend a contract was pushed"}),
        json!({"step": "create-grant", "status": later, "reason": "grant creation stays on the gateway API the operator already has"}),
        json!({"step": "openshell-policy", "status": later, "reason": "policy set evidence is required before this step can be present"}),
        json!({"step": "microcell-exec", "status": later, "reason": "scripted execution inside a MicroCell is still target"}),
        json!({"step": "otel-evidence", "status": if production_ready { "present" } else { "not_run" }, "reason": "counted only by deploy-verify"}),
        json!({"step": "cosign", "status": if production_ready { "present" } else { "not_run" }, "reason": "counted only by deploy-verify"}),
        json!({"step": "cease", "status": gate, "route": "POST /api/v1/agents/:pid/cease"}),
        json!({"step": "cease-proof", "status": gate, "route": "GET /api/v1/runtime/cease-proof/:pid"}),
        json!({"step": "explain", "status": later, "reason": "explain runs when a receipt id exists; this command does not invent one"}),
    ]
}

fn pinned_image(value: &Value, pointer: &str, blockers: &mut Vec<String>) -> String {
    let image = value.pointer(pointer).and_then(Value::as_str).unwrap_or("");
    if !image_is_pinned(image) {
        blockers.push(format!("{pointer} must be an immutable image reference containing @sha256:<64 hex>"));
    }
    image.to_string()
}

fn image_is_pinned(image: &str) -> bool {
    let Some((_, digest)) = image.rsplit_once("@sha256:") else {
        return false;
    };
    digest.len() == 64 && digest.chars().all(|ch| ch.is_ascii_hexdigit())
}

fn secret_files(value: &Value, state_dir: &str, blockers: &mut Vec<String>) -> (String, String, String) {
    let names = [
        "keycloak_admin_password",
        "keycloak_db_password",
        "sso_client_secret",
    ];
    let mut out = Vec::new();
    for name in names {
        let text = value
            .pointer(&format!("/secrets/{name}"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let Some(path) = text.strip_prefix("file:") else {
            blockers.push(format!(
                "secret {name} must be file:<absolute path under the state dir>, not an inline value"
            ));
            out.push(String::new());
            continue;
        };
        if !path.starts_with(state_dir) || path.contains('\n') || path.contains("..") {
            blockers.push(format!("secret {name} must live under {state_dir}"));
            out.push(String::new());
            continue;
        }
        out.push(path.to_string());
    }
    (
        out.first().cloned().unwrap_or_default(),
        out.get(1).cloned().unwrap_or_default(),
        out.get(2).cloned().unwrap_or_default(),
    )
}

fn artifact_pins(value: &Value, blockers: &mut Vec<String>) -> Vec<(String, String)> {
    let Some(artifacts) = value.get("artifacts").and_then(Value::as_object) else {
        blockers.push("artifacts with digest pins are required; Connector does not download latest".into());
        return Vec::new();
    };
    let names = [
        "openshell_package",
        "spire_server",
        "spire_agent",
        "firecracker",
        "jailer",
        "cosign",
        "connector_microd",
    ];
    let mut pins = Vec::new();
    for name in names {
        let path = artifacts
            .get(name)
            .and_then(|v| v.get("path"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let sha = artifacts
            .get(name)
            .and_then(|v| v.get("sha256"))
            .and_then(Value::as_str)
            .unwrap_or("");
        if !path.starts_with('/') || path.contains('\n') || path.contains("..") {
            blockers.push(format!("artifact {name} path must be absolute"));
        }
        if sha.len() != 64 || !sha.chars().all(|ch| ch.is_ascii_hexdigit()) {
            blockers.push(format!("artifact {name} sha256 must be 64 hex characters"));
        }
        pins.push((path.to_string(), sha.to_string()));
    }
    pins
}

fn required_abs(value: &Value, pointer: &str, blockers: &mut Vec<String>) -> String {
    let text = value.pointer(pointer).and_then(Value::as_str).unwrap_or("");
    if !text.starts_with('/') || text.contains('\n') || text.contains("..") {
        blockers.push(format!("{pointer} must be an absolute path"));
    }
    text.to_string()
}

fn required_sha256(value: &Value, pointer: &str, blockers: &mut Vec<String>) -> String {
    let text = value.pointer(pointer).and_then(Value::as_str).unwrap_or("");
    if text.len() != 64 || !text.chars().all(|ch| ch.is_ascii_hexdigit()) {
        blockers.push(format!("{pointer} must be 64 hex characters"));
    }
    text.to_string()
}

fn required_token(value: &Value, pointer: &str, blockers: &mut Vec<String>) -> String {
    let text = value.pointer(pointer).and_then(Value::as_str).unwrap_or("");
    if text.is_empty() || text.chars().any(|ch| ch.is_whitespace()) {
        blockers.push(format!("{pointer} must be a single token"));
    }
    text.to_string()
}

pub const OUTCOMES_SCHEMA: &str = "connector.product_outcomes.v1";

/// Inputs already fetched from the node. The scorer does not call a backend and does not mint Allow.
pub struct OutcomeFacts<'a> {
    pub explain: &'a Value,
    pub cease_proof: &'a Value,
    pub deploy_verify: &'a Value,
    pub services: &'a ServiceFacts,
    pub ceiling: &'a Value,
    pub policy: &'a Value,
    pub task_agent_pid: &'a str,
    pub journal_id: Option<&'a str>,
    pub microcell_id: Option<&'a str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskRequest {
    pub model: String,
    pub surface: String,
    pub purpose: String,
    pub pid: Option<String>,
    pub cease: bool,
    pub talk: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SurfaceKind {
    Workspace,
    Sandbox,
    Dedicated,
}

pub fn parse_task_args(args: &[String]) -> Result<TaskRequest, String> {
    let mut model = String::new();
    let mut surface = String::new();
    let mut purpose = String::new();
    let mut pid = None;
    let mut cease = false;
    let mut talk = false;
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        let next = || -> Result<String, String> {
            args.get(i + 1)
                .cloned()
                .filter(|v| !v.starts_with("--"))
                .ok_or_else(|| format!("{arg} needs a value"))
        };
        match arg {
            "--model" => {
                model = next()?;
                i += 2;
            }
            "--surface" => {
                surface = next()?;
                i += 2;
            }
            "--purpose" => {
                purpose = next()?;
                i += 2;
            }
            "--pid" => {
                pid = Some(next()?);
                i += 2;
            }
            "--cease" => {
                cease = true;
                i += 1;
            }
            "--talk" => {
                talk = true;
                i += 1;
            }
            other => return Err(format!("unknown task argument {other}")),
        }
    }
    if model.trim().is_empty() || surface.trim().is_empty() || purpose.trim().is_empty() {
        return Err(
            "usage: connectorctl product task --model <llm> --surface <workspace|sandbox|dedicated> --purpose <sentence> [--pid <agent>] [--cease] [--talk]"
                .into(),
        );
    }
    let purpose = purpose.trim().to_string();
    if purpose.eq_ignore_ascii_case("general-purpose") {
        return Err("purpose_required".into());
    }
    classify_surface(&surface)?;
    Ok(TaskRequest {
        model: model.trim().to_string(),
        surface: surface.trim().to_string(),
        purpose,
        pid,
        cease,
        talk,
    })
}

pub fn classify_surface(surface: &str) -> Result<SurfaceKind, String> {
    let surface = surface.trim();
    if surface.is_empty() || surface.chars().any(|ch| ch.is_whitespace()) {
        return Err("surface must be one token: a workspace path, a sandbox name, or dedicated".into());
    }
    if matches!(
        surface,
        "dedicated" | "microcell" | "dedicated-microvm"
    ) {
        return Ok(SurfaceKind::Dedicated);
    }
    if surface.starts_with('/') {
        return Ok(SurfaceKind::Workspace);
    }
    Ok(SurfaceKind::Sandbox)
}

pub fn task_blockers(
    augmented: bool,
    playground: bool,
    dev_token: bool,
    operational_ready: bool,
) -> Vec<String> {
    let mut blockers = Vec::new();
    if !augmented {
        blockers.push("CONNECTOR_AUGMENTED_ENV=1 is required. Playground and lab are not this task.".into());
    }
    if playground {
        blockers.push("CONNECTOR_PLAYGROUND is on. The augmented task refuses playground.".into());
    }
    if dev_token {
        blockers.push("dev-token is refused. The operator is the Keycloak subject on the verified session.".into());
    }
    if !operational_ready {
        blockers.push("deploy-verify linux-kvm is not operationally ready.".into());
    }
    blockers
}

pub fn env_flag_on(value: Option<&str>) -> bool {
    matches!(
        value.map(str::trim),
        Some("1" | "true" | "TRUE" | "yes" | "on")
    )
}

/// Twelve outcomes plus seven backends. Status is present, absent, or partial. Never pass.
pub fn score_outcomes(facts: &OutcomeFacts<'_>) -> Value {
    let explain = facts.explain;
    let evidence = EvidenceFacts::from_deploy_verify(facts.deploy_verify);
    let intelligence = link_text(explain, "intelligence");
    let operator_sub = explain
        .pointer("/identities/operator/value/sub")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    let workload = explain.pointer("/identities/workload");
    let workload_status = workload.and_then(|v| v.get("status")).and_then(Value::as_str);
    let workload_id = workload.and_then(|v| v.get("value")).and_then(Value::as_str).unwrap_or("");
    let fetched_spiffe = workload_status == Some("present") && valid_fetched_spiffe(workload_id);
    let court = explain.pointer("/identities/binding/value/court");
    let authorizes_false = court
        .and_then(|v| v.pointer("/body/authorizes"))
        .and_then(Value::as_bool)
        == Some(false);
    let court_present = fetched_spiffe && authorizes_false && operator_sub.is_some() && intelligence.is_some();
    let verdict = chain_value(explain, "pate")
        .and_then(|v| v.get("verdict").or_else(|| v.get("decision")))
        .and_then(Value::as_str)
        .unwrap_or("");
    let policy_for_agent = policy_matches_agent(facts.policy, facts.task_agent_pid);
    let push_ok = policy_for_agent
        && facts.policy.get("openshell_ready").and_then(Value::as_bool) == Some(true)
        && facts.policy.get("pushed").and_then(Value::as_bool) == Some(true);
    let ceiling_present = facts.ceiling.get("ceiling").is_some()
        && !facts.ceiling.get("ceiling").unwrap().is_null()
        && facts
            .ceiling
            .pointer("/ceiling/max_usd")
            .is_some();
    let live_generation = response_text(
        facts.ceiling,
        &["/ceiling/generation_id", "/generation_id"],
    );
    let stale_refused = proof_step_status(facts.cease_proof, "admit_refuses_stale_generation") == "present";
    let proof_status = facts
        .cease_proof
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("");
    let proof_honest = matches!(proof_status, "PARTIAL" | "TARGET" | "partial" | "target");
    let receipt_present = explain.get("found").and_then(Value::as_bool) == Some(true);
    let processes_up = facts.services.connector
        && facts.services.keycloak
        && facts.services.spire
        && facts.services.openshell
        && facts.services.microd
        && facts.services.otel
        && facts.services.cosign;
    let operational = facts
        .deploy_verify
        .get("operational_ready")
        .and_then(Value::as_bool)
        == Some(true);
    let trace_ok = effect_trace_ok(chain_value(explain, "otel_trace"));
    let microcell = facts.microcell_id.filter(|id| !id.is_empty());

    let outcomes = vec![
        outcome(
            "agent",
            if intelligence.is_some() { "present" } else { "absent" },
            "Intelligence id from the explain file. The model, the login, and the cell are not this id.",
        ),
        outcome(
            "contract",
            if chain_present(explain, "contract") { "present" } else { "absent" },
            "Contract digest on the explain chain.",
        ),
        outcome(
            "authority",
            if chain_present(explain, "authority") { "present" } else { "absent" },
            "WorldGrant on the explain chain, or absent.",
        ),
        outcome(
            "admission",
            if chain_present(explain, "pate") && !verdict.is_empty() { "present" } else { "absent" },
            "PATE verdict for this step. Backends do not admit.",
        ),
        outcome(
            "human",
            if verdict == "ask_hitl" {
                if facts.journal_id.is_some_and(|id| !id.is_empty()) { "present" } else { "absent" }
            } else if verdict.is_empty() {
                "absent"
            } else {
                "partial"
            },
            "Present when ask_hitl has a mission-journal id. Partial when the verdict did not ask a person.",
        ),
        outcome(
            "budget",
            if ceiling_present { "present" } else { "absent" },
            "Spend ceiling for this generation, including max_usd.",
        ),
        outcome(
            "generation",
            if stale_refused { "present" } else if live_generation.is_some() { "partial" } else { "absent" },
            "Present after cease when the old generation would be denied. Partial while the generation is still live.",
        ),
        outcome(
            "socket",
            if push_ok { "present" } else { "absent" },
            "OpenShell policy set stored for this agent with openshell_ready and pushed.",
        ),
        outcome(
            "body",
            if microcell.is_some() && evidence.firecracker && facts.services.microd { "present" } else { "absent" },
            "One MicroCell id for this agent. The cell is not the agent.",
        ),
        outcome(
            "stop",
            if receipt_present && proof_honest { "present" } else { "absent" },
            "Cease receipt exists and cease-proof is PARTIAL or TARGET. PASS is not a status here.",
        ),
        outcome(
            "file",
            if receipt_present && court_present {
                "present"
            } else if receipt_present {
                "partial"
            } else {
                "absent"
            },
            "Explain file. Court is present only when the three fetched ids are signed with authorizes false.",
        ),
        outcome(
            "machine",
            if operational && processes_up { "present" } else { "absent" },
            "Deploy-verify is operationally ready and every required process is up.",
        ),
    ];
    let file_court = if court_present { "present" } else { "absent" };
    let mut outcomes = outcomes;
    if let Some(file) = outcomes.iter_mut().find(|row| row.get("id").and_then(Value::as_str) == Some("file")) {
        if let Some(obj) = file.as_object_mut() {
            obj.insert("court".to_string(), json!(file_court));
        }
    }

    let backends = vec![
        backend(
            "keycloak",
            if evidence.iam && operator_sub.is_some() { "present" } else { "absent" },
            "iam oidc_jwks_token_verified and explain operator sub",
            &["agent", "human", "file"],
        ),
        backend(
            "spire",
            if evidence.spire && fetched_spiffe { "present" } else { "absent" },
            "fetched spiffe:// id. A cell URI does not count.",
            &["agent", "file"],
        ),
        backend(
            "openshell",
            if push_ok { "present" } else { "absent" },
            "policy set --wait stored for this agent",
            &["contract", "socket", "stop"],
        ),
        backend(
            "opa",
            if push_ok { "present" } else { "absent" },
            "Ready only because that OpenShell push succeeded. Connector does not run opa eval.",
            &["admission", "socket"],
        ),
        backend(
            "firecracker",
            if evidence.firecracker && facts.services.microd && microcell.is_some() { "present" } else { "absent" },
            "create, pause, and stop evidence plus one cell for this agent",
            &["body", "stop"],
        ),
        backend(
            "otel",
            if evidence.otel && trace_ok { "present" } else { "absent" },
            "exporter-accepted batch and a non-zero effect trace",
            &["file", "machine"],
        ),
        backend(
            "cosign",
            if evidence.cosign { "present" } else { "absent" },
            "verify-blob exit 0. This does not create the court signature and it does not admit.",
            &["body", "file"],
        ),
    ];

    json!({
        "schema": OUTCOMES_SCHEMA,
        "augmented": "critical work with a spend ceiling, a narrow surface, and a person when the step asks",
        "outcomes": outcomes,
        "backends": backends,
        "honesty": "present, absent, or partial. PASS is not used. Every backend admits false. A missing row stays absent.",
    })
}

pub fn outcomes_setup_complete(report: &Value) -> bool {
    row_status(report, "outcomes", "agent") == "present"
        && row_status(report, "outcomes", "contract") == "present"
        && row_status(report, "outcomes", "machine") == "present"
}

/// Setup is not execution. Success requires an admitted effect that was observed.
pub fn task_stage(report: &Value, explain: &Value) -> &'static str {
    let agent = row_status(report, "outcomes", "agent") == "present";
    let contract = row_status(report, "outcomes", "contract") == "present";
    let admission = row_status(report, "outcomes", "admission") == "present";
    let effect = chain_present(explain, "observed_effect");
    let reconstructed = explain.get("found").and_then(Value::as_bool) == Some(true)
        && row_status(report, "outcomes", "file") != "absent";
    let ceased = row_status(report, "outcomes", "stop") == "present";
    if !agent || !contract {
        return "incomplete";
    }
    if ceased && reconstructed {
        return "ceased";
    }
    if reconstructed && effect {
        return "reconstructed";
    }
    if admission && effect {
        return "executed";
    }
    if admission {
        return "admitted";
    }
    "configured"
}

pub fn task_execution_complete(stage: &str) -> bool {
    matches!(stage, "executed" | "reconstructed" | "ceased")
}

pub fn response_text(value: &Value, pointers: &[&str]) -> Option<String> {
    pointers.iter().find_map(|pointer| {
        value
            .pointer(pointer)
            .and_then(Value::as_str)
            .filter(|text| !text.is_empty())
            .map(|text| text.to_string())
    })
}

pub fn surface_contract_patch(purpose: &str, surface: &str, kind: SurfaceKind) -> Value {
    let mut patch = json!({
        "purpose": [purpose],
        "denied_operations": ["modify_contract", "ambient_shell"],
        "network_default": "deny",
        "receipt_required": true,
        "network_allow": [],
    });
    match kind {
        SurfaceKind::Workspace => {
            patch["filesystem_read"] = json!([surface]);
            patch["filesystem_write"] = json!([surface]);
        }
        SurfaceKind::Sandbox => {
            patch["filesystem_read"] = json!([]);
            patch["filesystem_write"] = json!([]);
            patch["purpose"] = json!([purpose, format!("openshell-sandbox:{surface}")]);
        }
        SurfaceKind::Dedicated => {
            patch["filesystem_read"] = json!([]);
            patch["filesystem_write"] = json!([]);
            patch["purpose"] = json!([purpose, "execution-body:dedicated-microcell"]);
        }
    }
    patch
}

/// Policy evidence comes from the stored fan-out explain already reconstructed.
pub fn policy_from_explain(explain: &Value) -> Value {
    let Some(fanout) = chain_value(explain, "runtime") else {
        return json!({});
    };
    let pushed = fanout.pointer("/openshell/push/pushed").and_then(Value::as_bool) == Some(true);
    let ready = fanout.pointer("/openshell/push/ready").and_then(Value::as_bool) == Some(true);
    json!({
        "agent_pid": fanout.get("agent_pid").cloned().unwrap_or(Value::Null),
        "openshell_ready": ready,
        "pushed": pushed,
    })
}

fn outcome(id: &str, status: &str, detail: &str) -> Value {
    json!({
        "id": id,
        "kind": "outcome",
        "status": honest_status(status),
        "detail": detail,
    })
}

fn backend(id: &str, status: &str, detail: &str, strengthens: &[&str]) -> Value {
    json!({
        "id": id,
        "kind": "backend",
        "status": honest_status(status),
        "detail": detail,
        "admits": false,
        "strengthens": strengthens,
    })
}

fn honest_status(status: &str) -> &'static str {
    match status {
        "present" => "present",
        "partial" => "partial",
        _ => "absent",
    }
}

fn row_status(report: &Value, list: &str, id: &str) -> &'static str {
    report
        .get(list)
        .and_then(Value::as_array)
        .and_then(|rows| {
            rows.iter().find(|row| row.get("id").and_then(Value::as_str) == Some(id))
        })
        .and_then(|row| row.get("status"))
        .and_then(Value::as_str)
        .map(honest_status)
        .unwrap_or("absent")
}

fn chain_step<'a>(explain: &'a Value, name: &str) -> Option<&'a Value> {
    explain
        .get("chain")
        .and_then(Value::as_array)
        .and_then(|steps| {
            steps
                .iter()
                .find(|step| step.get("step").and_then(Value::as_str) == Some(name))
        })
}

fn chain_present(explain: &Value, name: &str) -> bool {
    chain_step(explain, name).and_then(|step| step.get("status")).and_then(Value::as_str) == Some("present")
        && chain_step(explain, name).and_then(|step| step.get("value")).is_some_and(|v| !v.is_null())
}

fn chain_value<'a>(explain: &'a Value, name: &str) -> Option<&'a Value> {
    if chain_present(explain, name) {
        chain_step(explain, name).and_then(|step| step.get("value"))
    } else {
        None
    }
}

fn link_text(explain: &Value, name: &str) -> Option<String> {
    let link = explain.pointer(&format!("/identities/{name}"))?;
    if link.get("status").and_then(Value::as_str) != Some("present") {
        return None;
    }
    link.get("value")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

fn valid_fetched_spiffe(id: &str) -> bool {
    id.starts_with("spiffe://") && !id.chars().any(|ch| ch.is_whitespace()) && id.len() > "spiffe://".len()
}

fn policy_matches_agent(policy: &Value, task_agent_pid: &str) -> bool {
    match policy.get("agent_pid").and_then(Value::as_str) {
        Some(pid) if !task_agent_pid.is_empty() && pid != task_agent_pid => false,
        _ => true,
    }
}

fn proof_step_status<'a>(proof: &'a Value, name: &str) -> &'a str {
    proof
        .get("steps")
        .and_then(Value::as_array)
        .and_then(|steps| {
            steps.iter().find(|step| step.get("step").and_then(Value::as_str) == Some(name))
        })
        .and_then(|step| step.get("status"))
        .and_then(Value::as_str)
        .unwrap_or("absent")
}

fn effect_trace_ok(value: Option<&Value>) -> bool {
    let Some(value) = value else {
        return false;
    };
    let id = value
        .get("trace_id")
        .or_else(|| value.get("traceparent"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let hex = id.split('-').nth(1).unwrap_or(id);
    !hex.is_empty() && hex.chars().any(|ch| ch != '0') && hex.chars().all(|ch| ch.is_ascii_hexdigit() || ch == '-')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host_ok() -> HostFacts {
        HostFacts {
            kvm_usable: true,
            systemd: true,
            compose: true,
            cgroup_v2: true,
        }
    }

    fn services_up() -> ServiceFacts {
        ServiceFacts {
            connector: true,
            keycloak: true,
            spire: true,
            openshell: true,
            microd: true,
            otel: true,
            cosign: true,
        }
    }

    fn evidence_all() -> EvidenceFacts {
        EvidenceFacts {
            iam: true,
            spire: true,
            openshell: true,
            opa: true,
            firecracker: true,
            otel: true,
            cosign: true,
        }
    }

    fn valid_spec_json() -> Value {
        json!({
            "schema": "connector.deployment.v1",
            "profile": "linux-kvm",
            "trust_domain": "connector.local",
            "compatibility": {"openshell_policy_schema": 1},
            "images": {
                "postgres": format!("postgres@sha256:{}", "ab".repeat(32)),
                "keycloak": format!("quay.io/keycloak/keycloak@sha256:{}", "cd".repeat(32)),
                "otel_collector": format!("otel/opentelemetry-collector-contrib@sha256:{}", "ef".repeat(32))
            },
            "secrets": {
                "keycloak_admin_password": "file:/var/lib/connector/deployment/secrets/keycloak-admin",
                "keycloak_db_password": "file:/var/lib/connector/deployment/secrets/keycloak-db",
                "sso_client_secret": "file:/var/lib/connector/deployment/secrets/sso-client"
            },
            "artifacts": {
                "openshell_package": {"path": "/var/lib/connector/artifacts/openshell.deb", "sha256": "11".repeat(32)},
                "spire_server": {"path": "/var/lib/connector/artifacts/spire-server", "sha256": "22".repeat(32)},
                "spire_agent": {"path": "/var/lib/connector/artifacts/spire-agent", "sha256": "33".repeat(32)},
                "firecracker": {"path": "/var/lib/connector/artifacts/firecracker", "sha256": "44".repeat(32)},
                "jailer": {"path": "/var/lib/connector/artifacts/jailer", "sha256": "55".repeat(32)},
                "cosign": {"path": "/var/lib/connector/artifacts/cosign", "sha256": "66".repeat(32)},
                "connector_microd": {"path": "/var/lib/connector/artifacts/connector-microd", "sha256": "77".repeat(32)}
            },
            "firecracker": {
                "kernel_path": "/var/lib/connector/microvm/kernels/vmlinux",
                "kernel_sha256": "88".repeat(32),
                "rootfs_path": "/var/lib/connector/microvm/images/rootfs.ext4",
                "rootfs_sha256": "99".repeat(32)
            },
            "keycloak": {
                "hostname": "id.example",
                "tls_dir": "/var/lib/connector/deployment/tls",
                "redirect_uri": "https://connector.example/api/v1/auth/sso/callback",
                "admin_user": "admin"
            },
            "otel": {"upstream_endpoint": "127.0.0.1:4317"}
        })
    }

    #[test]
    fn missing_kvm_blocks_install_and_names_the_blocker() {
        let spec = parse_spec(&valid_spec_json(), "/var/lib/connector/deployment").unwrap();
        let mut host = host_ok();
        host.kvm_usable = false;
        match decide_install(&Ok(spec), &host) {
            InstallDecision::Refuse { blockers } => {
                assert!(blockers.iter().any(|b| b == "Firecracker isolation requires KVM."));
            }
            InstallDecision::Plan { .. } => panic!("kvm miss must refuse"),
        }
    }

    #[test]
    fn inline_secret_and_unpinned_image_are_refused() {
        let mut raw = valid_spec_json();
        raw["secrets"]["keycloak_admin_password"] = json!("hunter2");
        raw["images"]["postgres"] = json!("postgres:latest");
        let errors = parse_spec(&raw, "/var/lib/connector/deployment").unwrap_err();
        assert!(errors.iter().any(|e| e.contains("inline")));
        assert!(errors.iter().any(|e| e.contains("@sha256:")));
    }

    #[test]
    fn kubernetes_is_not_the_product_install_path() {
        let mut raw = valid_spec_json();
        raw["profile"] = json!("kubernetes");
        let errors = parse_spec(&raw, "/var/lib/connector/deployment").unwrap_err();
        assert!(errors.iter().any(|e| e.contains("linux-kvm")));
    }

    #[test]
    fn evidence_without_a_live_process_is_not_ready() {
        let mut services = services_up();
        services.otel = false;
        let report = evaluate(&host_ok(), &services, &evidence_all());
        assert!(!report.production_ready);
        assert_eq!(report.satisfied, 7);
        let telemetry = report.rows.iter().find(|row| row.label == "Telemetry").unwrap();
        assert!(!telemetry.ready);
        assert!(telemetry.action.contains("Collector"));
    }

    #[test]
    fn all_seven_evidence_and_processes_report_ready() {
        let report = evaluate(&host_ok(), &services_up(), &evidence_all());
        assert!(report.production_ready);
        assert_eq!(report.satisfied, 7);
        let lines = report_lines(&report);
        assert!(lines.iter().any(|line| line == "CONNECTOR READY"));
    }

    #[test]
    fn kvm_blocker_is_the_isolation_action() {
        let mut host = host_ok();
        host.kvm_usable = false;
        let report = evaluate(&host, &services_up(), &evidence_all());
        assert!(!report.production_ready);
        let lines = report_lines(&report);
        assert!(lines.iter().any(|line| line.contains("CONNECTOR NOT PRODUCTION READY")));
        assert!(lines.iter().any(|line| line.contains("Firecracker isolation requires KVM.")));
    }

    #[test]
    fn restart_budget_stops_after_three() {
        assert_eq!(recovery_action(false, 0), "restart");
        assert_eq!(recovery_action(false, 2), "restart");
        assert_eq!(recovery_action(false, 3), "budget_exhausted");
        assert_eq!(recovery_action(true, 3), "none");
    }

    #[test]
    fn upgrade_refuses_a_different_profile_or_policy_schema() {
        assert!(upgrade_decision("linux-kvm", "linux-kvm", 1).is_ok());
        assert!(upgrade_decision("linux-kvm", "kubernetes", 1).is_err());
        assert!(upgrade_decision("linux-kvm", "linux-kvm", 2).is_err());
    }

    #[test]
    fn demo_does_not_run_when_production_is_not_ready() {
        let steps = demo_steps(false);
        assert!(steps.iter().all(|step| step["status"] != "call"));
        assert_eq!(steps[0]["status"], "refused");
    }

    #[test]
    fn trust_domain_and_join_token_reject_whitespace() {
        assert!(validate_trust_domain("connector.local").is_ok());
        assert!(validate_trust_domain("bad domain").is_err());
        assert!(render_spire_server("connector.local\nserver {").is_err());
        assert!(render_spire_agent("connector.local", "token with space").is_err());
        let agent = render_spire_agent("connector.local", "join_token").unwrap();
        assert!(agent.contains("socket_path = \"/run/spire/agent/sockets/api.sock\""));
        assert!(agent.contains("insecure_bootstrap = true"));
        assert!(agent.contains("join_token = \"join_token\""));
        assert!(!agent.contains("plugin_data {\n            join_token"));
    }

    #[test]
    fn providers_do_not_admit() {
        let text = providers().to_string();
        assert!(text.contains("does not"));
        assert!(text.contains("mint PATE Allow") || text.contains("mint Allow"));
        assert!(!compatibility()["refused"].to_string().is_empty());
    }

    fn all_services() -> ServiceFacts {
        ServiceFacts {
            connector: true,
            keycloak: true,
            spire: true,
            openshell: true,
            microd: true,
            otel: true,
            cosign: true,
        }
    }

    fn ready_verify() -> Value {
        json!({
            "operational_ready": true,
            "backends": [
                {"id": "iam", "ready": true},
                {"id": "spire", "ready": true, "detail": "spiffe://connector.local/connector"},
                {"id": "openshell", "ready": true},
                {"id": "opa", "ready": true},
                {"id": "firecracker", "ready": true},
                {"id": "otel", "ready": true},
                {"id": "cosign", "ready": true}
            ]
        })
    }

    fn explain_fixture(spiffe: &str, workload_status: &str, court: bool) -> Value {
        let binding = if court {
            json!({
                "status": "present",
                "value": {"court": {"body": {"authorizes": false}}}
            })
        } else {
            json!({"status": "absent"})
        };
        json!({
            "schema": "connector.explain.v1",
            "found": true,
            "identities": {
                "operator": {"status": "present", "value": {"sub": "operator-1", "jti": "jti-1", "role": "operator"}},
                "intelligence": {"status": "present", "value": "intel-1"},
                "workload": {"status": workload_status, "value": spiffe},
                "binding": binding
            },
            "chain": [
                {"step": "contract", "status": "present", "value": "digest"},
                {"step": "authority", "status": "present", "value": {"grant": "g1"}},
                {"step": "pate", "status": "present", "value": {"verdict": "proceed"}},
                {"step": "otel_trace", "status": "present", "value": {"trace_id": "abc123"}}
            ]
        })
    }

    fn facts<'a>(
        explain: &'a Value,
        proof: &'a Value,
        verify: &'a Value,
        services: &'a ServiceFacts,
        ceiling: &'a Value,
        policy: &'a Value,
        journal: Option<&'a str>,
        cell: Option<&'a str>,
    ) -> OutcomeFacts<'a> {
        OutcomeFacts {
            explain,
            cease_proof: proof,
            deploy_verify: verify,
            services,
            ceiling,
            policy,
            task_agent_pid: "agent-1",
            journal_id: journal,
            microcell_id: cell,
        }
    }

    #[test]
    fn outcomes_are_twelve_plus_seven_and_never_pass() {
        let explain = explain_fixture("spiffe://connector.local/connector", "present", true);
        let proof = json!({"status": "PARTIAL", "steps": [{"step": "admit_refuses_stale_generation", "status": "present"}]});
        let verify = ready_verify();
        let services = all_services();
        let ceiling = json!({"generation_id": "gen-1", "ceiling": {"max_usd": 5}});
        let policy = json!({"agent_pid": "agent-1", "openshell_ready": true, "pushed": true});
        let report = score_outcomes(&facts(&explain, &proof, &verify, &services, &ceiling, &policy, None, Some("mc-1")));
        let outcomes = report["outcomes"].as_array().unwrap();
        let backends = report["backends"].as_array().unwrap();
        assert_eq!(outcomes.len(), 12);
        assert_eq!(backends.len(), 7);
        for row in outcomes.iter().chain(backends.iter()) {
            let status = row["status"].as_str().unwrap();
            assert!(matches!(status, "present" | "absent" | "partial"), "{status}");
            assert_ne!(status.to_ascii_lowercase(), "pass");
        }
        for row in backends {
            assert_eq!(row["admits"], false);
        }
        assert_eq!(report["outcomes"][4]["id"], "human");
        assert_eq!(report["outcomes"][4]["status"], "partial");
        assert!(outcomes_setup_complete(&report));
    }

    #[test]
    fn court_stays_absent_without_a_fetched_spiffe_id() {
        let services = all_services();
        let verify = ready_verify();
        let ceiling = json!({});
        let policy = json!({});
        let proof = json!({});
        for (spiffe, status) in [("cell://local/agent", "partial"), ("", "absent")] {
            let explain = explain_fixture(spiffe, status, false);
            let report = score_outcomes(&facts(&explain, &proof, &verify, &services, &ceiling, &policy, None, None));
            let file = report["outcomes"].as_array().unwrap().iter().find(|row| row["id"] == "file").unwrap();
            assert_eq!(file["court"], "absent");
            let spire = report["backends"].as_array().unwrap().iter().find(|row| row["id"] == "spire").unwrap();
            assert_eq!(spire["status"], "absent");
        }
    }

    #[test]
    fn policy_for_another_agent_does_not_count() {
        let explain = explain_fixture("spiffe://connector.local/connector", "present", true);
        let proof = json!({});
        let verify = ready_verify();
        let services = all_services();
        let ceiling = json!({});
        let policy = json!({"agent_pid": "other-agent", "openshell_ready": true, "pushed": true});
        let report = score_outcomes(&facts(&explain, &proof, &verify, &services, &ceiling, &policy, None, Some("mc-1")));
        let socket = report["outcomes"].as_array().unwrap().iter().find(|row| row["id"] == "socket").unwrap();
        let opa = report["backends"].as_array().unwrap().iter().find(|row| row["id"] == "opa").unwrap();
        assert_eq!(socket["status"], "absent");
        assert_eq!(opa["status"], "absent");
    }

    #[test]
    fn machine_is_absent_when_a_process_is_down() {
        let explain = json!({"found": false});
        let proof = json!({});
        let verify = ready_verify();
        let mut services = services_up();
        services.microd = false;
        let ceiling = json!({});
        let policy = json!({});
        let report = score_outcomes(&facts(&explain, &proof, &verify, &services, &ceiling, &policy, None, None));
        let machine = report["outcomes"].as_array().unwrap().iter().find(|row| row["id"] == "machine").unwrap();
        assert_eq!(machine["status"], "absent");
    }

    #[test]
    fn cease_proof_pass_does_not_become_a_stop() {
        let explain = explain_fixture("spiffe://connector.local/connector", "present", false);
        let proof = json!({"status": "PASS", "steps": [{"step": "admit_refuses_stale_generation", "status": "present"}]});
        let verify = ready_verify();
        let services = all_services();
        let ceiling = json!({"generation_id": "gen-2", "ceiling": {"max_usd": 5}});
        let policy = json!({});
        let report = score_outcomes(&facts(&explain, &proof, &verify, &services, &ceiling, &policy, None, None));
        let stop = report["outcomes"].as_array().unwrap().iter().find(|row| row["id"] == "stop").unwrap();
        assert_eq!(stop["status"], "absent");
        let blob = report.to_string().to_ascii_lowercase();
        assert!(!blob.contains("\"status\":\"pass\""));
        let cosign = report["backends"].as_array().unwrap().iter().find(|row| row["id"] == "cosign").unwrap();
        let file = report["outcomes"].as_array().unwrap().iter().find(|row| row["id"] == "file").unwrap();
        assert_eq!(cosign["status"], "present");
        assert_eq!(file["court"], "absent");
        let agent = report["outcomes"].as_array().unwrap().iter().find(|row| row["id"] == "agent").unwrap();
        let keycloak = report["backends"].as_array().unwrap().iter().find(|row| row["id"] == "keycloak").unwrap();
        assert_eq!(keycloak["status"], "present");
        assert_eq!(agent["status"], "present");
    }

    #[test]
    fn keycloak_evidence_does_not_invent_an_intelligence() {
        let explain = json!({
            "found": false,
            "identities": {"operator": {"status": "present", "value": {"sub": "operator-1"}}}
        });
        let proof = json!({});
        let verify = ready_verify();
        let services = all_services();
        let ceiling = json!({});
        let policy = json!({});
        let report = score_outcomes(&facts(&explain, &proof, &verify, &services, &ceiling, &policy, None, None));
        let agent = report["outcomes"].as_array().unwrap().iter().find(|row| row["id"] == "agent").unwrap();
        let keycloak = report["backends"].as_array().unwrap().iter().find(|row| row["id"] == "keycloak").unwrap();
        assert_eq!(agent["status"], "absent");
        assert_eq!(keycloak["status"], "present");
    }

    #[test]
    fn task_args_refuse_a_blank_purpose_and_a_dev_token_gate() {
        assert!(parse_task_args(&["--model".into(), "grok".into(), "--surface".into(), "dedicated".into(), "--purpose".into(), "general-purpose".into()]).is_err());
        let task = parse_task_args(&[
            "--model".into(), "grok".into(),
            "--surface".into(), "/var/job".into(),
            "--purpose".into(), "rotate one credential".into(),
            "--cease".into(),
        ]).unwrap();
        assert_eq!(task.model, "grok");
        assert_eq!(classify_surface(&task.surface).unwrap(), SurfaceKind::Workspace);
        assert!(task.cease);
        assert!(!task.talk);
        let blockers = task_blockers(false, true, true, false);
        assert_eq!(blockers.len(), 4);
        assert!(task_blockers(true, false, false, true).is_empty());
    }

    #[test]
    fn task_reads_nested_server_fields_and_refuses_setup_only_success() {
        let cease = json!({"ok": true, "spend_cease": {"receipt_id": "cease_1"}});
        let promote = json!({"ok": true, "execution_body": {"microcell_id": "mc-1"}});
        let ceiling = json!({"ok": true, "ceiling": {"generation_id": "gen-9", "max_usd": 5.0}});
        let turn = json!({"session_id": "sess-1", "hitl_request_id": "hitl-1"});
        assert_eq!(response_text(&cease, &["/spend_cease/receipt_id"]).as_deref(), Some("cease_1"));
        assert_eq!(response_text(&promote, &["/execution_body/microcell_id"]).as_deref(), Some("mc-1"));
        assert_eq!(response_text(&ceiling, &["/ceiling/generation_id"]).as_deref(), Some("gen-9"));
        assert_eq!(response_text(&turn, &["/hitl_request_id"]).as_deref(), Some("hitl-1"));

        let patch = surface_contract_patch("rotate one credential", "/etc/app", SurfaceKind::Workspace);
        assert_eq!(patch["filesystem_write"][0], "/etc/app");
        assert_eq!(patch["network_default"], "deny");
        assert!(patch["denied_operations"].as_array().unwrap().iter().any(|v| v == "ambient_shell"));

        let explain = explain_fixture("spiffe://connector.local/connector", "present", true);
        let proof = json!({});
        let verify = ready_verify();
        let services = all_services();
        let policy = json!({});
        let report = score_outcomes(&facts(&explain, &proof, &verify, &services, &ceiling, &policy, None, Some("mc-1")));
        assert!(outcomes_setup_complete(&report));
        assert_eq!(task_stage(&report, &explain), "admitted");
        assert!(!task_execution_complete(task_stage(&report, &explain)));

        let mut executed = explain.clone();
        executed["chain"].as_array_mut().unwrap().push(json!({"step": "observed_effect", "status": "present", "value": "digest"}));
        assert_eq!(task_stage(&report, &executed), "reconstructed");
        assert!(task_execution_complete("reconstructed"));
    }

    #[test]
    fn openshell_policy_comes_from_the_explain_fanout() {
        let explain = json!({
            "found": true,
            "chain": [{
                "step": "runtime",
                "status": "present",
                "value": {
                    "agent_pid": "agent-1",
                    "openshell": {"push": {"pushed": true, "ready": true}}
                }
            }]
        });
        let policy = policy_from_explain(&explain);
        assert_eq!(policy["agent_pid"], "agent-1");
        assert_eq!(policy["pushed"], true);
        assert_eq!(policy["openshell_ready"], true);
    }
}

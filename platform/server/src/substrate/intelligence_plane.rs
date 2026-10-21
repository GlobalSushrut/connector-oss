//! Internal intelligence plane.
//!
//! The operator calls Connector. Connector calls three pinned processes:
//! memory and agent state, the model broker, and the workflow runner.
//! This plane is not one of the seven backends. A pin file is not supervision.
//! Dispatch does not mint a PATE verdict. A 2xx body is hashed into a kernel mempacket.

use std::time::Duration;

use axum::extract::State;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::state::{PlatformState, SharedState};
use crate::substrate::spend_cease::generation_is_live;

const LETTA_PIN: &str = include_str!("../../../deploy/intelligence-backends/linux/letta.pin");
const LITELLM_PIN: &str =
    include_str!("../../../deploy/intelligence-backends/linux/litellm.pin");
const LANGFLOW_PIN: &str =
    include_str!("../../../deploy/intelligence-backends/linux/langflow.pin");

pub const SCHEMA: &str = "connector.intelligence_plane.v1";

struct Backend {
    id: &'static str,
    role: &'static str,
    upstream: &'static str,
    pin: &'static str,
    image_env: &'static str,
    url_env: &'static str,
    token_env: &'static str,
    default_url: &'static str,
    connector_calls: &'static str,
}

const BACKENDS: &[Backend] = &[
    Backend {
        id: "brain",
        role: "memory and agent state",
        upstream: "Letta",
        pin: LETTA_PIN,
        image_env: "CONNECTOR_INTELLIGENCE_BRAIN_IMAGE",
        url_env: "CONNECTOR_INTELLIGENCE_BRAIN_URL",
        token_env: "CONNECTOR_INTELLIGENCE_BRAIN_TOKEN",
        default_url: "http://127.0.0.1:18283",
        connector_calls: "Connector forwards an admitted call to the pinned Letta process on the loopback port.",
    },
    Backend {
        id: "broker",
        role: "model broker",
        upstream: "LiteLLM",
        pin: LITELLM_PIN,
        image_env: "CONNECTOR_INTELLIGENCE_BROKER_IMAGE",
        url_env: "CONNECTOR_INTELLIGENCE_BROKER_URL",
        token_env: "CONNECTOR_INTELLIGENCE_BROKER_TOKEN",
        default_url: "http://127.0.0.1:14011",
        connector_calls: "Connector forwards an admitted model call to the pinned LiteLLM process on the loopback port.",
    },
    Backend {
        id: "orchestrate",
        role: "workflow",
        upstream: "Langflow",
        pin: LANGFLOW_PIN,
        image_env: "CONNECTOR_INTELLIGENCE_ORCHESTRATE_IMAGE",
        url_env: "CONNECTOR_INTELLIGENCE_ORCHESTRATE_URL",
        token_env: "CONNECTOR_INTELLIGENCE_ORCHESTRATE_TOKEN",
        default_url: "http://127.0.0.1:17860",
        connector_calls: "Connector forwards an admitted workflow call to the pinned Langflow process on the loopback port.",
    },
];

pub fn pinned_reference(pin_file: &str) -> &str {
    pin_file
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with('#'))
        .unwrap_or("")
}

pub fn pinned_digest_verified(reference: &str) -> bool {
    let Some(digest) = reference.rsplit_once("@sha256:") else {
        return false;
    };
    let hex = digest.1;
    hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit()) && reference.contains('/')
}

fn backend(id: &str) -> Option<&'static Backend> {
    BACKENDS.iter().find(|row| row.id == id)
}

fn base_url(row: &Backend) -> String {
    std::env::var(row.url_env)
        .ok()
        .map(|value| value.trim().trim_end_matches('/').to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| row.default_url.to_string())
}

pub fn loopback_base(base: &str) -> bool {
    let Some(rest) = base.strip_prefix("http://") else {
        return false;
    };
    if rest.contains('@') || rest.contains('\\') {
        return false;
    }
    let hostport = rest.split('/').next().unwrap_or("");
    let host = hostport.split(':').next().unwrap_or("");
    (host == "127.0.0.1" || host == "localhost") && !hostport.is_empty()
}

fn docker_ancestor_running(reference: &str) -> bool {
    let Ok(output) = std::process::Command::new("docker")
        .args([
            "ps",
            "--filter",
            &format!("ancestor={reference}"),
            "--format",
            "{{.ID}}",
        ])
        .output()
    else {
        return false;
    };
    output.status.success()
        && output
            .stdout
            .split(|b| *b == b'\n')
            .any(|line| !line.is_empty())
}

pub fn process_ready(id: &str) -> bool {
    let Some(row) = backend(id) else {
        return false;
    };
    let reference = pinned_reference(row.pin);
    pinned_digest_verified(reference) && docker_ancestor_running(reference)
}

/// Loopback OpenAI-compatible URL for the model router. None unless the pinned broker is up.
pub fn broker_loopback() -> Option<String> {
    if !process_ready("broker") {
        return None;
    }
    let row = backend("broker")?;
    let base = base_url(row);
    if !loopback_base(&base) {
        return None;
    }
    Some(format!("{}/v1", base.trim_end_matches('/')))
}

pub fn path_allowed(role: &str, path: &str) -> bool {
    let path = path.split('?').next().unwrap_or(path);
    if !path.starts_with('/') || path.contains("..") || path.contains('\\') {
        return false;
    }
    let prefixes: &[&str] = match role {
        "brain" => &[
            "/v1/agents",
            "/v1/blocks",
            "/v1/memory",
            "/v1/health",
            "/health",
        ],
        "broker" => &[
            "/v1/chat/completions",
            "/v1/models",
            "/v1/embeddings",
            "/health",
        ],
        "orchestrate" => &["/api/v1/run", "/api/v1/flows", "/api/v1/version", "/health"],
        _ => return false,
    };
    prefixes.iter().any(|prefix| {
        path == *prefix || path.starts_with(&format!("{prefix}/"))
    })
}

/// None means the call may be proxied. Dispatch still does not mint Proceed.
pub fn dispatch_denial(
    role: &str,
    method: &str,
    path: &str,
    base_url: &str,
    supervised: bool,
    has_task: bool,
    verdict: &str,
    observed: bool,
    generation_live: bool,
) -> Option<&'static str> {
    if backend(role).is_none() {
        return Some("role_unknown");
    }
    if method != "GET" && method != "POST" {
        return Some("method_not_allowed");
    }
    if !path_allowed(role, path) {
        return Some("path_not_allowed");
    }
    if !loopback_base(base_url) {
        return Some("intelligence_url_not_loopback");
    }
    if !has_task {
        return Some("pate_task_required");
    }
    if !supervised {
        return Some("intelligence_not_supervised");
    }
    if !generation_live {
        return Some("stale_generation");
    }
    if !verdict.eq_ignore_ascii_case("proceed") || observed {
        return Some("pate_not_open_proceed");
    }
    None
}

fn row_json(row: &Backend) -> Value {
    let reference = pinned_reference(row.pin);
    let digest_ok = pinned_digest_verified(reference);
    let ready = digest_ok && docker_ancestor_running(reference);
    let configured = std::env::var(row.image_env).unwrap_or_default();
    json!({
        "id": row.id,
        "role": row.role,
        "upstream": row.upstream,
        "operator_runs_it": false,
        "present": digest_ok,
        "ready": ready,
        "status": if ready { "partial" } else { "TARGET" },
        "seven_backend": false,
        "pinned_reference": reference,
        "configured_image_matches_pin": !configured.is_empty() && configured == reference,
        "loopback": base_url(row),
        "connector_calls": row.connector_calls,
    })
}

pub fn status() -> Value {
    let rows: Vec<Value> = BACKENDS.iter().map(row_json).collect();
    let running = rows
        .iter()
        .filter(|row| row.get("ready").and_then(|v| v.as_bool()).unwrap_or(false))
        .count();
    let ready = running == rows.len() && !rows.is_empty();
    json!({
        "schema": SCHEMA,
        "operator": "Call Connector. These three tools are internal backends. Do not operate them yourself.",
        "operator_runs_it": false,
        "installed": ready,
        "ready": ready,
        "status": if running == 0 { "TARGET" } else { "partial" },
        "seven_backend": false,
        "production_eligible": false,
        "acceptance_passed": false,
        "inventory_complete": true,
        "backends": rows,
        "honesty": "present means the pin is a digest. ready means docker shows that pinned image as a running ancestor. A pin file is not a running process. This plane is not one of the seven backends. The acceptance suite has not passed. Dispatch requires an existing unobserved PATE Proceed and does not write kernel memory.",
    })
}

pub async fn get_status() -> Json<Value> {
    Json(status())
}

#[derive(Debug, Deserialize)]
pub struct DispatchBody {
    pub role: String,
    #[serde(default)]
    pub pate_task_id: Option<String>,
    #[serde(default)]
    pub method: Option<String>,
    pub path: String,
    #[serde(default)]
    pub body: Option<Value>,
}

/// POST /api/v1/runtime/intelligence/dispatch
/// The caller names a role. Connector selects the pinned process.
pub async fn post_dispatch(
    State(state): State<SharedState>,
    Json(body): Json<DispatchBody>,
) -> Json<Value> {
    Json(dispatch(state.as_ref(), body).await)
}

pub async fn dispatch(state: &PlatformState, body: DispatchBody) -> Value {
    let admitted = match admit(state, &body) {
        Ok(admitted) => admitted,
        Err(denied) => return denied,
    };
    let mut value = proxy(admitted.row, &admitted.method, &admitted.path, body.body.as_ref()).await;
    remember_success(state, &admitted.agent_pid, &mut value);
    value
}

/// Recall may call the brain only through the closed dispatch.
pub async fn recall_if_admitted(state: &PlatformState, agent_pid: &str) -> Option<String> {
    if !process_ready("brain") {
        return None;
    }
    let task_id = latest_task_id(state, agent_pid)?;
    prepare_role(state, &task_id, agent_pid, "brain");
    let value = dispatch(
        state,
        DispatchBody {
            role: "brain".into(),
            pate_task_id: Some(task_id),
            method: Some("GET".into()),
            path: "/v1/memory".into(),
            body: None,
        },
    )
    .await;
    value
        .get("mempacket_cid")
        .and_then(|cid| cid.as_str())
        .filter(|cid| !cid.is_empty())
        .map(str::to_string)
}

/// One workflow id on the capability runs after the tool envelope exists.
pub fn run_named_flow(state: &PlatformState, agent_pid: &str, task_id: &str) -> Option<String> {
    if task_id.trim().is_empty() || !process_ready("orchestrate") {
        return None;
    }
    let address = prepare_role(state, task_id, agent_pid, "orchestrate")?;
    let flow_id = address.strip_prefix("flow:")?;
    let body = DispatchBody {
        role: "orchestrate".into(),
        pate_task_id: Some(task_id.to_string()),
        method: Some("POST".into()),
        path: format!("/api/v1/run/{flow_id}"),
        body: Some(json!({})),
    };
    let admitted = match admit(state, &body) {
        Ok(admitted) => admitted,
        Err(_) => return None,
    };
    let mut value = proxy_blocking(admitted.row, &admitted.method, &admitted.path, body.body.as_ref());
    remember_success(state, &admitted.agent_pid, &mut value);
    value
        .get("mempacket_cid")
        .and_then(|cid| cid.as_str())
        .filter(|cid| !cid.is_empty())
        .map(str::to_string)
}

/// Cite an existing grant and stamp the envelope and packet DNA for that address.
/// Returns the address. Does not issue a capability and does not mint PATE.
fn prepare_role(
    state: &PlatformState,
    task_id: &str,
    agent_pid: &str,
    role: &str,
) -> Option<String> {
    let (token, address) = grant_for_task(state, task_id, agent_pid, role)?;
    cite_grant(state, task_id, &token);
    stamp_address(state, agent_pid, role, &address);
    Some(address)
}

fn grant_for_task(
    state: &PlatformState,
    task_id: &str,
    agent_pid: &str,
    role: &str,
) -> Option<(String, String)> {
    if let Some(token) = task_aapi_ref(state, task_id) {
        let resources = task_resources(state, task_id).ok()?;
        let address = role_address(role, agent_pid, &resources)?;
        if resources.iter().any(|resource| resource == &address)
            || state
                .aapi
                .lock()
                .ok()
                .is_some_and(|engine| engine.capability_covers(&token, &address))
        {
            return Some((token, address));
        }
        return None;
    }
    let engine = state.aapi.lock().ok()?;
    let mut grants = engine.grants_for_subject(agent_pid);
    grants.extend(engine.grants_for_subject(&format!("agent:{agent_pid}")));
    drop(engine);
    for (token, resources) in grants {
        let Some(address) = role_address(role, agent_pid, &resources) else {
            continue;
        };
        if resources.iter().any(|resource| resource == &address) {
            return Some((token, address));
        }
        if state
            .aapi
            .lock()
            .ok()
            .is_some_and(|engine| engine.capability_covers(&token, &address))
        {
            return Some((token, address));
        }
    }
    None
}

fn cite_grant(state: &PlatformState, task_id: &str, token: &str) {
    let Ok(mut store) = state.engine_store.lock() else {
        return;
    };
    let Ok(Some(mut record)) = store.folder_get(crate::substrate::pate::ATU_FOLDER, task_id) else {
        return;
    };
    let cited = record
        .pointer("/spine/aapi_ref")
        .and_then(|value| value.as_str())
        .unwrap_or("")
        .trim();
    if !cited.is_empty() {
        return;
    }
    let Some(spine) = record.pointer_mut("/spine").and_then(|value| value.as_object_mut()) else {
        return;
    };
    spine.insert("aapi_ref".into(), json!(token));
    let _ = store.folder_put(crate::substrate::pate::ATU_FOLDER, task_id, &record);
}

fn stamp_address(state: &PlatformState, agent_pid: &str, role: &str, address: &str) {
    if verified_envelope(state, agent_pid, address) && packet_dna_logged(state, agent_pid, address) {
        return;
    }
    let operation = match role {
        "brain" => "memory.recall",
        "broker" => "llm.chat",
        "orchestrate" => "flow.run",
        _ => "intelligence.dispatch",
    };
    let binding = crate::kernel::action_binding::ActionBinding::new(
        agent_pid,
        operation,
        address,
        address,
        json!({}),
        None,
        "1",
        None,
    );
    let envelope = crate::substrate::effect_envelope_bus::mint_for_tool(
        state,
        &binding,
        None,
        None,
        None,
        None,
        120,
    );
    if crate::substrate::effect_envelope_bus::verify_envelope(&envelope).is_err() {
        return;
    }
    let payload = json!({ "address": address, "operation": operation });
    let _ = crate::substrate::packet_dna::mint_require_and_log(
        state,
        agent_pid,
        operation,
        address,
        &json!({}),
        &payload,
    );
}

struct Admitted<'a> {
    row: &'a Backend,
    method: String,
    path: String,
    agent_pid: String,
}

fn admit<'a>(state: &PlatformState, body: &DispatchBody) -> Result<Admitted<'a>, Value> {
    let role = body.role.trim();
    let method = body
        .method
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("POST")
        .to_ascii_uppercase();
    let path = body.path.trim();
    let Some(row) = backend(role) else {
        return Err(deny(role, "role_unknown"));
    };
    let base = base_url(row);
    let task_id = body
        .pate_task_id
        .as_deref()
        .map(str::trim)
        .filter(|id| !id.is_empty());
    let (verdict, observed, generation_live, agent_pid) = match task_id {
        None => (String::new(), false, false, String::new()),
        Some(task_id) => match recorded_proceed(state, task_id) {
            Ok(view) => view,
            Err(reason) => return Err(deny(role, reason)),
        },
    };
    if let Some(reason) = dispatch_denial(
        role,
        &method,
        path,
        &base,
        process_ready(role),
        task_id.is_some(),
        &verdict,
        observed,
        generation_live,
    ) {
        return Err(deny(role, reason));
    }
    let Some(task_id) = task_id else {
        return Err(deny(role, "pate_task_required"));
    };
    if let Some(reason) = task_support_denial(state, task_id, role, &agent_pid) {
        return Err(deny(role, reason));
    }
    Ok(Admitted {
        row,
        method,
        path: path.to_string(),
        agent_pid,
    })
}

fn deny(role: &str, reason: &str) -> Value {
    json!({
        "ok": false,
        "forward": false,
        "role": role,
        "reason": reason,
        "seven_backend": false,
        "acceptance_passed": false,
        "honesty": "Connector did not call the internal process.",
    })
}

fn recorded_proceed(
    state: &PlatformState,
    task_id: &str,
) -> Result<(String, bool, bool, String), &'static str> {
    let Ok(store) = state.engine_store.lock() else {
        return Err("store_unavailable");
    };
    let Some(record) = store
        .folder_get(crate::substrate::pate::ATU_FOLDER, task_id)
        .ok()
        .flatten()
    else {
        return Err("pate_task_absent");
    };
    let verdict = record
        .get("verdict")
        .and_then(|value| value.as_str())
        .unwrap_or("absent")
        .to_string();
    let observed = record
        .pointer("/spine/observed")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let agent_pid = record
        .get("agent_pid")
        .and_then(|value| value.as_str())
        .unwrap_or("")
        .to_string();
    let recorded_generation = record
        .pointer("/spine/generation_id")
        .and_then(|value| value.as_str())
        .map(|value| value.to_string())
        .or_else(|| {
            record
                .get("broker_epoch")
                .and_then(|value| value.as_u64())
                .map(|epoch| epoch.to_string())
        });
    let live = store
        .folder_get(
            crate::substrate::llm_context_broker::FOLDER,
            &format!("gen:{agent_pid}"),
        )
        .ok()
        .flatten()
        .and_then(|value| value.get("generation").and_then(|generation| generation.as_u64()))
        .unwrap_or(0);
    let generation_live = recorded_generation
        .as_deref()
        .is_some_and(|generation| generation_is_live(generation, live));
    Ok((verdict, observed, generation_live, agent_pid))
}

/// The address a capability must already name. Orchestrate takes the one `flow:` resource.
pub fn role_address(role: &str, agent_pid: &str, resources: &[String]) -> Option<String> {
    match role {
        "brain" => Some(format!("memory:{agent_pid}")),
        "broker" => Some(format!("llm:{agent_pid}")),
        "orchestrate" => one_workflow(resources),
        _ => None,
    }
}

fn one_workflow(resources: &[String]) -> Option<String> {
    let mut ids = resources.iter().filter_map(|resource| {
        let id = resource.strip_prefix("flow:")?;
        if id.is_empty() || id.contains('*') || id.contains('/') {
            return None;
        }
        Some(id)
    });
    let id = ids.next()?;
    if ids.next().is_some() {
        return None;
    }
    Some(format!("flow:{id}"))
}

pub fn missing_support(capability: bool, envelope: bool, dna: bool) -> Option<&'static str> {
    if !capability {
        return Some("capability_required");
    }
    if !envelope {
        return Some("effect_envelope_required");
    }
    if !dna {
        return Some("packet_dna_required");
    }
    None
}

fn task_support_denial(
    state: &PlatformState,
    task_id: &str,
    role: &str,
    agent_pid: &str,
) -> Option<&'static str> {
    if agent_pid.trim().is_empty() {
        return Some("capability_required");
    }
    let resources = match task_resources(state, task_id) {
        Ok(resources) => resources,
        Err(reason) => return Some(reason),
    };
    let Some(address) = role_address(role, agent_pid, &resources) else {
        return Some("capability_required");
    };
    let capability = resources.iter().any(|resource| resource == &address)
        || task_capability_covers(state, task_id, &address);
    let envelope = verified_envelope(state, agent_pid, &address);
    let dna = packet_dna_logged(state, agent_pid, &address);
    missing_support(capability, envelope, dna)
}

fn task_capability_covers(state: &PlatformState, task_id: &str, address: &str) -> bool {
    let Some(token) = task_aapi_ref(state, task_id) else {
        return false;
    };
    state
        .aapi
        .lock()
        .ok()
        .is_some_and(|engine| engine.capability_covers(&token, address))
}

fn task_resources(state: &PlatformState, task_id: &str) -> Result<Vec<String>, &'static str> {
    let Some(token) = task_aapi_ref(state, task_id) else {
        return Err("capability_required");
    };
    state
        .aapi
        .lock()
        .ok()
        .and_then(|engine| engine.capability_resources(&token))
        .ok_or("capability_required")
}

fn task_aapi_ref(state: &PlatformState, task_id: &str) -> Option<String> {
    let store = state.engine_store.lock().ok()?;
    let record = store
        .folder_get(crate::substrate::pate::ATU_FOLDER, task_id)
        .ok()
        .flatten()?;
    record
        .pointer("/spine/aapi_ref")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn verified_envelope(state: &PlatformState, agent_pid: &str, address: &str) -> bool {
    let Ok(store) = state.engine_store.lock() else {
        return false;
    };
    let Ok(keys) = store.folder_keys("effect_envelope_v1", None) else {
        return false;
    };
    for key in keys.into_iter().take(256) {
        let Ok(Some(value)) = store.folder_get("effect_envelope_v1", &key) else {
            continue;
        };
        let Ok(envelope) = serde_json::from_value::<connector_trust::EffectEnvelopeV1>(value) else {
            continue;
        };
        if envelope.agent_pid == agent_pid
            && envelope.address == address
            && crate::substrate::effect_envelope_bus::verify_envelope(&envelope).is_ok()
        {
            return true;
        }
    }
    false
}

fn packet_dna_logged(state: &PlatformState, agent_pid: &str, address: &str) -> bool {
    let Ok(store) = state.engine_store.lock() else {
        return false;
    };
    let prefix = format!("{agent_pid}:");
    let Ok(keys) = store.folder_keys("packet_dna_log", Some(&prefix)) else {
        return false;
    };
    for key in keys.into_iter().take(256) {
        let Ok(Some(row)) = store.folder_get("packet_dna_log", &key) else {
            continue;
        };
        let digest = row
            .get("effect_digest")
            .and_then(|value| value.as_str())
            .unwrap_or("");
        let row_agent = row
            .get("agent_pid")
            .and_then(|value| value.as_str())
            .unwrap_or("");
        let row_address = row.get("address").and_then(|value| value.as_str()).unwrap_or("");
        if row_agent == agent_pid && row_address == address && !digest.is_empty() {
            return true;
        }
    }
    false
}

fn latest_task_id(state: &PlatformState, agent_pid: &str) -> Option<String> {
    let store = state.engine_store.lock().ok()?;
    let record = store
        .folder_get(
            crate::substrate::pate::ATU_FOLDER,
            &format!("latest:{agent_pid}"),
        )
        .ok()
        .flatten()?;
    record
        .get("task_id")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

async fn proxy(row: &Backend, method: &str, path: &str, body: Option<&Value>) -> Value {
    let base = base_url(row);
    let url = format!("{}{path}", base.trim_end_matches('/'));
    let client = match reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .build()
    {
        Ok(client) => client,
        Err(_) => return deny(row.id, "upstream_client_unavailable"),
    };
    let mut request = match method {
        "GET" => client.get(&url),
        "POST" => client.post(&url).json(&body.cloned().unwrap_or_else(|| json!({}))),
        _ => return deny(row.id, "method_not_allowed"),
    };
    if let Ok(token) = std::env::var(row.token_env) {
        let token = token.trim();
        if !token.is_empty() {
            request = request.bearer_auth(token);
        }
    }
    match request.send().await {
        Ok(response) => {
            let status = response.status().as_u16();
            let text = response.text().await.unwrap_or_default();
            upstream_value(row.id, status, &text)
        }
        Err(_) => deny(row.id, "upstream_unreachable"),
    }
}

fn proxy_blocking(row: &Backend, method: &str, path: &str, body: Option<&Value>) -> Value {
    let base = base_url(row);
    let url = format!("{}{path}", base.trim_end_matches('/'));
    let client = match reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(5))
        .build()
    {
        Ok(client) => client,
        Err(_) => return deny(row.id, "upstream_client_unavailable"),
    };
    let request = match method {
        "GET" => client.get(&url),
        "POST" => client.post(&url).json(&body.cloned().unwrap_or_else(|| json!({}))),
        _ => return deny(row.id, "method_not_allowed"),
    };
    let request = attach_token(row, request);
    match request.send() {
        Ok(response) => upstream_value(row.id, response.status().as_u16(), &response.text().unwrap_or_default()),
        Err(_) => deny(row.id, "upstream_unreachable"),
    }
}

fn attach_token(
    row: &Backend,
    request: reqwest::blocking::RequestBuilder,
) -> reqwest::blocking::RequestBuilder {
    if let Ok(token) = std::env::var(row.token_env) {
        let token = token.trim();
        if !token.is_empty() {
            return request.bearer_auth(token);
        }
    }
    request
}

fn upstream_value(role: &str, status: u16, text: &str) -> Value {
    let (payload, truncated) = clip(text);
    json!({
        "ok": (200..300).contains(&status),
        "forward": true,
        "role": role,
        "upstream_status": status,
        "body": payload,
        "body_sha256": sha256_hex(text.as_bytes()),
        "truncated": truncated,
        "seven_backend": false,
        "acceptance_passed": false,
        "honesty": "Connector forwarded this admitted call to the supervised loopback process. The acceptance suite has not passed.",
    })
}

fn remember_success(state: &PlatformState, agent_pid: &str, value: &mut Value) {
    if value.get("ok").and_then(|ok| ok.as_bool()) != Some(true) {
        return;
    }
    let Some(hash) = value.get("body_sha256").and_then(|hash| hash.as_str()) else {
        return;
    };
    match write_mempacket(state, agent_pid, hash) {
        Ok(cid) => {
            value["mempacket_cid"] = json!(cid);
            if let Some(role) = value.get("role").and_then(|role| role.as_str()) {
                note_followed(state, agent_pid, role, &cid);
            }
        }
        Err(reason) => {
            value["mempacket_cid"] = Value::Null;
            value["mempacket_error"] = json!(reason);
        }
    }
}

fn write_mempacket(state: &PlatformState, agent_pid: &str, hash: &str) -> Result<String, String> {
    use vac_core::cid::compute_cid;
    use vac_core::types::{MemoryKernelOp, MemoryType, OpOutcome, PacketType, Source, SourceKind};
    use vac_core::{MemPacket, SyscallPayload, SyscallRequest};

    let body = serde_json::Value::String(hash.to_string());
    let payload_cid = compute_cid(&body).map_err(|err| err.to_string())?;
    let writer = kernel_writer(state, agent_pid);
    let mut packet = MemPacket::new(
        PacketType::Action,
        body,
        payload_cid,
        writer.clone(),
        "intelligence-dispatch".to_string(),
        Source {
            kind: SourceKind::Tool,
            principal_id: writer.clone(),
        },
        chrono::Utc::now().timestamp_millis(),
    );
    packet.memory_type = MemoryType::Episodic;
    let mut kernel = state.kernel.lock().map_err(|err| err.to_string())?;
    let result = kernel.dispatch(SyscallRequest {
        agent_pid: writer,
        operation: MemoryKernelOp::MemWrite,
        payload: SyscallPayload::MemWrite { packet },
        reason: Some("intelligence_dispatch_body_hash".into()),
        vakya_id: None,
        trace_parent: None,
        trace_state: None,
        api_version: None,
    });
    if result.outcome != OpOutcome::Success {
        return Err(format!("memwrite_dispatch_failed: {:?}", result.outcome));
    }
    match result.value {
        vac_core::SyscallValue::Cid(cid) => Ok(cid.to_string()),
        _ => Ok(hash.to_string()),
    }
}

fn note_followed(state: &PlatformState, agent_pid: &str, role: &str, cid: &str) {
    let Ok(mut store) = state.engine_store.lock() else {
        return;
    };
    let _ = store.folder_put(
        "intelligence_dispatch_v1",
        &format!("latest:{agent_pid}:{role}"),
        &json!({
            "agent_pid": agent_pid,
            "role": role,
            "mempacket_cid": cid,
            "followed": true,
        }),
    );
}

pub fn role_followed(state: &PlatformState, agent_pid: &str, role: &str) -> bool {
    let Ok(store) = state.engine_store.lock() else {
        return false;
    };
    store
        .folder_get(
            "intelligence_dispatch_v1",
            &format!("latest:{agent_pid}:{role}"),
        )
        .ok()
        .flatten()
        .and_then(|row| row.get("followed").and_then(|value| value.as_bool()))
        .unwrap_or(false)
}

fn kernel_writer(state: &PlatformState, agent_pid: &str) -> String {
    let Ok(store) = state.engine_store.lock() else {
        return agent_pid.to_string();
    };
    store
        .folder_get("agent_meta", agent_pid)
        .ok()
        .flatten()
        .and_then(|row| row.get("kernel_pid").and_then(|value| value.as_str()).map(str::to_string))
        .filter(|pid| !pid.trim().is_empty())
        .unwrap_or_else(|| agent_pid.to_string())
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(bytes))
}

fn clip(text: &str) -> (String, bool) {
    const LIMIT: usize = 8192;
    if text.len() <= LIMIT {
        (text.to_string(), false)
    } else {
        let mut end = LIMIT;
        while !text.is_char_boundary(end) && end > 0 {
            end -= 1;
        }
        (text[..end].to_string(), true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plane_is_not_a_seventh_backend() {
        let body = status();
        assert_eq!(body["seven_backend"], false);
        assert_eq!(body["operator_runs_it"], false);
        assert_eq!(body["production_eligible"], false);
        assert_eq!(body["acceptance_passed"], false);
        assert_eq!(body["inventory_complete"], true);
        let rows = body["backends"].as_array().unwrap();
        assert_eq!(rows.len(), 3);
        let ids: Vec<&str> = rows
            .iter()
            .filter_map(|row| row["id"].as_str())
            .collect();
        assert_eq!(ids, ["brain", "broker", "orchestrate"]);
        let running = rows
            .iter()
            .filter(|row| row["ready"] == true)
            .count();
        assert_eq!(body["ready"], running == 3);
        assert_eq!(
            body["status"],
            if running == 0 { "TARGET" } else { "partial" }
        );
        for row in rows {
            assert_eq!(row["operator_runs_it"], false);
            assert_eq!(row["seven_backend"], false);
            let reference = row["pinned_reference"].as_str().unwrap();
            assert!(pinned_digest_verified(reference));
            assert_eq!(row["ready"], process_ready(row["id"].as_str().unwrap()));
        }
        assert!(pinned_reference(LETTA_PIN).ends_with(
            "@sha256:894208298df11849fbf6d7677375d81ef7263c5ba18d733db5db30b09cfd8665"
        ));
        assert!(pinned_reference(LITELLM_PIN).ends_with(
            "@sha256:b959a1816fa454a14d2842242d0fa1cd0d39f96fc94d3a1f4e1de4e48e2398c6"
        ));
        assert!(pinned_reference(LANGFLOW_PIN).ends_with(
            "@sha256:25e13252fc3701ca16e2b9a6cf2d3edd720aafbbc297a701ec0b7a15a3287792"
        ));
        assert!(!body.to_string().contains("CONNECTOR READY"));
        assert_eq!(
            missing_support(false, true, true),
            Some("capability_required")
        );
        assert_eq!(
            missing_support(true, false, true),
            Some("effect_envelope_required")
        );
        assert_eq!(
            missing_support(true, true, false),
            Some("packet_dna_required")
        );
        assert_eq!(missing_support(true, true, true), None);
        assert_eq!(
            role_address("brain", "agent_a", &[]).as_deref(),
            Some("memory:agent_a")
        );
        assert_eq!(
            role_address("broker", "agent_a", &[]).as_deref(),
            Some("llm:agent_a")
        );
        assert_eq!(
            role_address(
                "orchestrate",
                "agent_a",
                &["flow:one-workflow".into(), "memory:agent_a".into()]
            )
            .as_deref(),
            Some("flow:one-workflow")
        );
        assert!(role_address(
            "orchestrate",
            "agent_a",
            &["flow:one".into(), "flow:two".into()]
        )
        .is_none());
        let seven = crate::substrate::cvr::backends::assemble(
            &[],
            &json!({"present": false, "verified": false, "reason": "not_installed"}),
        );
        assert_eq!(seven["backends"].as_array().unwrap().len(), 7);
    }

    #[test]
    fn dispatch_stays_closed_without_a_live_proceed() {
        assert_eq!(
            dispatch_denial(
                "brain",
                "POST",
                "/v1/agents",
                "http://127.0.0.1:18283",
                true,
                false,
                "proceed",
                false,
                true,
            ),
            Some("pate_task_required")
        );
        assert_eq!(
            dispatch_denial(
                "broker",
                "POST",
                "/v1/chat/completions",
                "http://127.0.0.1:14011",
                false,
                true,
                "proceed",
                false,
                true,
            ),
            Some("intelligence_not_supervised")
        );
        assert_eq!(
            dispatch_denial(
                "orchestrate",
                "POST",
                "/api/v1/run/flow",
                "http://127.0.0.1:17860",
                true,
                true,
                "proceed",
                true,
                true,
            ),
            Some("pate_not_open_proceed")
        );
        assert_eq!(
            dispatch_denial(
                "broker",
                "POST",
                "/v1/chat/completions",
                "http://127.0.0.1:14011",
                true,
                true,
                "proceed",
                false,
                false,
            ),
            Some("stale_generation")
        );
        assert!(dispatch_denial(
            "brain",
            "POST",
            "/v1/agents/agent/messages",
            "http://127.0.0.1:18283",
            true,
            true,
            "Proceed",
            false,
            true,
        )
        .is_none());
        assert_eq!(
            dispatch_denial(
                "brain",
                "POST",
                "/v1/admin",
                "http://127.0.0.1:18283",
                true,
                true,
                "proceed",
                false,
                true,
            ),
            Some("path_not_allowed")
        );
        assert_eq!(
            dispatch_denial(
                "broker",
                "DELETE",
                "/v1/models",
                "http://127.0.0.1:14011",
                true,
                true,
                "proceed",
                false,
                true,
            ),
            Some("method_not_allowed")
        );
        assert_eq!(
            dispatch_denial(
                "broker",
                "POST",
                "/v1/chat/completions",
                "http://10.0.0.8:4000",
                true,
                true,
                "proceed",
                false,
                true,
            ),
            Some("intelligence_url_not_loopback")
        );
        assert!(!loopback_base("http://user@127.0.0.1:14011"));
        assert!(!pinned_digest_verified("letta/letta:0.34.11"));
        assert!(!path_allowed("brain", "/v1/agents/../../etc/passwd"));
    }
}

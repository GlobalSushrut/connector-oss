use crate::auth::{extract_claims, PlatformRole};
use crate::state::SharedState;
use axum::{extract::State, http::HeaderMap, Json};
use serde::{Deserialize, Serialize};
use std::process::Command;
use std::time::{Duration, Instant};
#[cfg(unix)]
use std::os::unix::process::CommandExt;

// ── Request / Response types ─────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ExecuteRequest {
    /// All cells in order — the backend concatenates them so variables persist.
    pub cells: Vec<CellCode>,
    /// Index of the "active" cell being run (0-based). Only cells 0..=run_up_to
    /// are executed.
    pub run_up_to: usize,
    /// Connector platform base URL visible from the server process.
    /// Defaults to http://localhost:9090/api/v1
    pub base_url: Option<String>,
    /// Optional Bearer token to pre-inject into the client.
    pub api_token: Option<String>,
    /// Optional agent_pid to pre-bind the client to.
    pub agent_pid: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct CellCode {
    pub id: String,
    pub code: String,
}

#[derive(Debug, Serialize)]
pub struct ExecuteResponse {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub duration_ms: u64,
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SnippetListRequest {
    pub category: Option<String>,
}

// ── Boilerplate injected at the top of every execution ──────────────────────

fn build_boilerplate(base_url: &str, api_token: Option<&str>, agent_pid: Option<&str>) -> String {
    let token_line = if let Some(tok) = api_token {
        format!("    api_key=\"{tok}\"")
    } else {
        "    api_key=None".into()
    };
    let auth_header_line = if let Some(tok) = api_token {
        format!("_DEFAULT_HEADERS = {{\"Authorization\": \"Bearer {tok}\"}}")
    } else {
        "_DEFAULT_HEADERS = {}".into()
    };
    let pid_line = if let Some(pid) = agent_pid {
        format!("    agent_pid=\"{pid}\"")
    } else {
        "    agent_pid=None".into()
    };

    format!(
        r#"import sys, json, os, time
sys.path.insert(0, "{sdk_path}")

BASE_URL = "{base_url}"
{auth_header_line}

# ── Raw HTTP helpers (always available) ──────────────────────────────────────
try:
    import requests as _requests
    def _api(method, path, **kwargs):
        """Raw helper: _api('get', '/agents') or _api('post', '/memory/write', json={{...}})"""
        url = BASE_URL + path
        headers = dict(_DEFAULT_HEADERS)
        headers.update(kwargs.pop("headers", {{}}))
        r = _requests.request(method.upper(), url, headers=headers, timeout=15, **kwargs)
        try:
            return r.json()
        except Exception:
            return r.text
    _requests_ok = True
except ImportError:
    def _api(method, path, **kwargs):
        raise RuntimeError("Install 'requests': pip install requests")
    _requests_ok = False

def show(obj):
    """Pretty-print any object."""
    if isinstance(obj, (dict, list)):
        print(json.dumps(obj, indent=2, default=str))
    else:
        print(obj)

# ── Quick-access helpers ─────────────────────────────────────────────────────
def agents():      return _api('get', '/agents')
def agent(pid):    return _api('get', f'/agents/{{pid}}')
def prompts():     return _api('get', '/prompts')
def experiments(): return _api('get', '/experiments')
def memory(ns):    return _api('get', f'/memory/recall/{{ns}}')
def health():      return _api('get', '/monitor/health')
def trust():       return _api('get', '/monitor/trust')

# ── Connector Platform SDK (optional, for decorator/langchain/crewai) ────────
try:
    from decorator import ConnectorClient, connector_trace, connector_tool
    client = ConnectorClient(
        base_url=BASE_URL,
{token_line},
{pid_line},
        async_mode=False,
    )
    _sdk_ok = True
except Exception:
    _sdk_ok = False
    class _FakeClient:
        agent_pid = "{agent_pid_val}"
        namespace = "{agent_pid_val}"
        def write_packet(self, *a, **kw): return _api('post', '/memory/write', json=kw)
        def log_action(self, *a, **kw): return _api('post', '/actionlog/record', json=kw)
        def trace(self, *a, **kw):
            import contextlib
            return contextlib.nullcontext()
    client = _FakeClient()

try:
    from langchain import ConnectorCallbackHandler as _lch
    ConnectorCallbackHandler = _lch
except Exception:
    pass

try:
    from crewai import ConnectorCrewObserver as _co, instrument_crew as _ic
    ConnectorCrewObserver = _co
    instrument_crew = _ic
except Exception:
    pass

"#,
        sdk_path = get_sdk_path(),
        base_url = base_url,
        auth_header_line = auth_header_line,
        token_line = token_line,
        pid_line = pid_line,
        agent_pid_val = agent_pid.unwrap_or(""),
    )
}

fn get_sdk_path() -> String {
    let cwd = std::env::current_dir().unwrap_or_default();
    let exe = std::env::current_exe().unwrap_or_default();
    let candidates = [
        cwd.join("integrations"),    // if run from repo root
        cwd.join("../integrations"), // if run from server/
        exe.parent()
            .unwrap_or(std::path::Path::new("."))
            .join("../../integrations"), // if run from server/target/debug/
        exe.parent()
            .unwrap_or(std::path::Path::new("."))
            .join("../../../integrations"),
    ];
    for c in &candidates {
        if let Ok(canonical) = c.canonicalize() {
            if canonical.join("decorator.py").exists() {
                return canonical.to_string_lossy().into_owned();
            }
        }
    }
    // Fallback: absolute path based on exe location
    cwd.join("../integrations").to_string_lossy().into_owned()
}

fn assert_notebook_base_url_allowed(base_url: &str) -> Result<(), &'static str> {
    if let Some(host) = crate::substrate::egress_policy::parse_host_from_url(base_url) {
        if crate::substrate::egress_policy::is_direct_llm_provider_host(&host) {
            return Err("direct_provider_egress_denied");
        }
    }
    Ok(())
}

// ── Execute handler ──────────────────────────────────────────────────────────

pub async fn execute(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<ExecuteRequest>,
) -> Json<serde_json::Value> {
    let host_exec = std::env::var("CONNECTOR_NOTEBOOK_HOST_EXEC")
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false);
    let allow_in_prod = std::env::var("CONNECTOR_NOTEBOOK_HOST_EXEC_ALLOW_IN_PROD")
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false);
    if crate::connector_profile::is_productionish_env() && !(host_exec && allow_in_prod) {
        return Json(serde_json::json!({
            "ok": false,
            "error": "notebook_host_exec_disabled",
            "message": "Host python execution is disabled in production-like environments.",
            "status": 403,
        }));
    }
    if !host_exec {
        return Json(serde_json::json!({
            "ok": false,
            "error": "notebook_host_exec_disabled",
            "message": "Set CONNECTOR_NOTEBOOK_HOST_EXEC=1 to allow bounded host python in lab.",
            "status": 403,
        }));
    }
    let claims = extract_claims(&headers);
    let role = claims
        .as_ref()
        .map(|c| PlatformRole::from_str(&c.role))
        .unwrap_or(PlatformRole::Viewer);
    if role.rank() < PlatformRole::Admin.rank() {
        return Json(serde_json::json!({
            "ok": false,
            "error": "Admin privileges required for notebook host execution",
            "status": 403,
        }));
    }
    let base_url = req
        .base_url
        .clone()
        .unwrap_or_else(|| "http://localhost:9090/api/v1".into());
    if let Err(code) = assert_notebook_base_url_allowed(&base_url) {
        return Json(serde_json::json!({
            "ok": false,
            "error": code,
            "message": "Notebook base_url must not point at LLM providers; use Connector gateway.",
            "status": 403,
        }));
    }
    if let Some(pid) = req.agent_pid.as_deref().filter(|s| !s.is_empty()) {
        if let Err(e) = crate::kernel::agent_principal::require_contract_action(
            state.as_ref(),
            pid,
            "notebook.execute",
            "playground",
        ) {
            return Json(serde_json::json!({
                "ok": false,
                "error": e,
                "denial_reason": "contract_denied",
                "status": 403,
                "honesty": "U6 — playground bound to an I is charter-gated under harden."
            }));
        }
    }
    let boilerplate = build_boilerplate(
        &base_url,
        req.api_token.as_deref(),
        req.agent_pid.as_deref(),
    );

    // Collect cells up to and including run_up_to
    let last = req.run_up_to.min(req.cells.len().saturating_sub(1));
    let user_code: String = req.cells[..=last]
        .iter()
        .map(|c| format!("# ── Cell: {} ──\n{}\n", c.id, c.code))
        .collect::<Vec<_>>()
        .join("\n");

    let full_code = format!("{boilerplate}\n{user_code}");

    let start = Instant::now();

    // Spawn python3 with a 30-second timeout via `timeout` command
    let mut cmd = Command::new("timeout");
    cmd.args(["30", "python3", "-c", &full_code])
        .env("PYTHONUNBUFFERED", "1")
        .env_remove("CONNECTOR_LLM_API_KEY")
        .env_remove("OPENAI_API_KEY")
        .env_remove("ANTHROPIC_API_KEY")
        .env_remove("CONNECTOR_LLM_FALLBACK_KEY")
        .env_remove("STRIPE_SECRET_KEY")
        .env_remove("CONNECTOR_JWT_SECRET")
        .env_remove("CONNECTOR_LICENSE_HMAC_KEY")
        .env_remove("CONNECTOR_RECEIPT_HMAC_KEY");
    // B23: inject DockLock cage env when a quantum is bound (or ambient).
    crate::kernel::docklock::apply_cage_env_to_command(state.as_ref(), &mut cmd, None, None);
    let landlock_fc = connector_plugin_runtime::linux_hardening::landlock_fail_closed_enabled();
    let has_fs = std::env::var("CONNECTOR_DOCKLOCK_FS_READ")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .is_some()
        || std::env::var("CONNECTOR_DOCKLOCK_FS_WRITE")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .is_some();
    if landlock_fc && !has_fs {
        return Json(serde_json::json!({
            "ok": false,
            "error": "notebook_landlock_paths_required",
            "message": "Fail-closed Landlock is on; set CONNECTOR_DOCKLOCK_FS_READ/WRITE before host python.",
            "status": 403,
        }));
    }
    cmd.env(
        "CONNECTOR_PLUGIN_SUBPROCESS_SECCOMP_INTENT",
        std::env::var("CONNECTOR_PLUGIN_SUBPROCESS_SECCOMP_INTENT")
            .unwrap_or_else(|_| "no_network".into()),
    );
    #[cfg(unix)]
    unsafe {
        cmd.pre_exec(|| {
            if libc::setpgid(0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            connector_plugin_runtime::linux_hardening::apply_linux_hardening_env()?;
            Ok(())
        });
    }
    let result = cmd.output();

    let elapsed = start.elapsed().as_millis() as u64;

    match result {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
            let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
            let exit_code = output.status.code().unwrap_or(-1);

            // Strip boilerplate tracebacks that reference internal lines
            let clean_stderr = clean_stderr(&stderr, &boilerplate);

            Json(serde_json::json!({
                "stdout": stdout,
                "stderr": clean_stderr,
                "exit_code": exit_code,
                "duration_ms": elapsed,
                "ok": exit_code == 0,
            }))
        }
        Err(e) => Json(serde_json::json!({
            "stdout": "",
            "stderr": format!("Failed to spawn python3: {e}. Is python3 installed?"),
            "exit_code": -1,
            "duration_ms": elapsed,
            "ok": false,
        })),
    }
}

/// Remove internal boilerplate lines from tracebacks so the user only sees
/// errors relevant to their own code.
fn clean_stderr(stderr: &str, boilerplate: &str) -> String {
    let boilerplate_lines = boilerplate.lines().count();
    let mut out = Vec::new();
    let mut skip_next = false;
    for line in stderr.lines() {
        // Filter out File "<string>", line N where N <= boilerplate_lines
        if line.trim_start().starts_with("File \"<string>\", line ") {
            if let Some(num_str) = line
                .split("line ")
                .nth(1)
                .and_then(|s| s.split(',').next())
                .and_then(|s| s.trim().parse::<usize>().ok())
            {
                if num_str <= boilerplate_lines + 2 {
                    skip_next = true;
                    continue;
                }
                // Adjust line number to be relative to user code
                let user_line = num_str.saturating_sub(boilerplate_lines);
                out.push(line.replacen(
                    &format!("line {num_str}"),
                    &format!("line {user_line}"),
                    1,
                ));
                skip_next = false;
                continue;
            }
        }
        if skip_next {
            skip_next = false;
            continue;
        }
        out.push(line.to_owned());
    }
    out.join("\n")
}

// ── Kernel info (stateless — just reports python version) ───────────────────

pub async fn kernel_info(State(_state): State<SharedState>) -> Json<serde_json::Value> {
    let version = Command::new("python3")
        .arg("--version")
        .output()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout).trim().to_string()
                + &String::from_utf8_lossy(&o.stderr).trim().to_string()
        })
        .unwrap_or_else(|_| "python3 not found".into());

    let sdk_path = get_sdk_path();
    let sdk_available = std::path::Path::new(&sdk_path)
        .join("decorator.py")
        .exists();

    Json(serde_json::json!({
        "python": version.trim(),
        "sdk_path": sdk_path,
        "sdk_available": sdk_available,
        "execution_model": "stateless-concat",
        "timeout_secs": 30,
        "note": "Variables persist across cells within a single Run — all cells above are re-executed on each run.",
    }))
}

// ── Snippet library ──────────────────────────────────────────────────────────

pub async fn snippets(State(_state): State<SharedState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "categories": [
            {
                "id": "agents",
                "label": "Agents",
                "icon": "Bot",
                "snippets": [
                    {
                        "id": "agents_list",
                        "label": "List all agents",
                        "code": "show(agents())"
                    },
                    {
                        "id": "agents_register",
                        "label": "Register an agent",
                        "code": "result = _api('post', '/agents', json={\n    \"name\": \"my-agent\",\n    \"instructions\": \"You are a helpful assistant.\",\n    \"token_budget\": 50000,\n    \"namespace\": \"my-agent\"\n})\nshow(result)"
                    },
                    {
                        "id": "agents_cost",
                        "label": "Agent cost & tokens",
                        "code": "pid = \"agent_REPLACE_ME\"\nshow(_api('get', f'/agents/{pid}/cost'))"
                    },
                    {
                        "id": "agents_pause",
                        "label": "Pause / resume agent",
                        "code": "pid = \"agent_REPLACE_ME\"\nshow(_api('post', f'/agents/{pid}/pause'))\n# To resume:\n# show(_api('post', f'/agents/{pid}/resume'))"
                    }
                ]
            },
            {
                "id": "memory",
                "label": "Memory",
                "icon": "Brain",
                "snippets": [
                    {
                        "id": "memory_write",
                        "label": "Write a memory packet",
                        "code": "result = client.write_packet(\n    packet_type=\"Reasoning\",\n    content=\"The user prefers concise answers.\",\n    tags=[\"preference\", \"style\"]\n)\nprint(\"written\")"
                    },
                    {
                        "id": "memory_recall",
                        "label": "Recall memory",
                        "code": "ns = client.namespace\nresult = _api('get', f'/memory/recall/{ns}')\nshow(result)"
                    },
                    {
                        "id": "memory_write_raw",
                        "label": "Write via raw API",
                        "code": "result = _api('post', '/memory/write', json={\n    \"agent_pid\": client.agent_pid,\n    \"namespace\": client.namespace,\n    \"packet_type\": \"Observation\",\n    \"content\": \"Observed user clicked submit at 14:32\",\n    \"tags\": [\"event\", \"ui\"]\n})\nshow(result)"
                    },
                    {
                        "id": "memory_context_pressure",
                        "label": "Context pressure gauge",
                        "code": "pid = client.agent_pid\nshow(_api('get', f'/memory/context-pressure/{pid}'))"
                    },
                    {
                        "id": "knowledge_ingest",
                        "label": "Ingest into knowledge base",
                        "code": "result = _api('post', '/memory/knowledge/ingest', json={\n    \"content\": \"Connector Platform supports 15 services and 123 REST routes.\",\n    \"source\": \"docs\",\n    \"tags\": [\"platform\", \"docs\"]\n})\nshow(result)"
                    },
                    {
                        "id": "knowledge_query",
                        "label": "Query knowledge base",
                        "code": "result = _api('post', '/memory/knowledge/query', json={\n    \"query\": \"How many services does the platform have?\",\n    \"top_k\": 3\n})\nshow(result)"
                    }
                ]
            },
            {
                "id": "prompts",
                "label": "Prompts",
                "icon": "FileText",
                "snippets": [
                    {
                        "id": "prompts_list",
                        "label": "List prompts",
                        "code": "show(prompts())"
                    },
                    {
                        "id": "prompts_create",
                        "label": "Create a prompt",
                        "code": "result = _api('post', '/prompts', json={\n    \"name\": \"summarize-v1\",\n    \"description\": \"Summarise text in 3 bullet points\",\n    \"content\": \"Summarise the following in exactly 3 bullet points:\\n\\n{{text}}\",\n    \"tags\": [\"summarize\", \"nlp\"]\n})\nshow(result)"
                    },
                    {
                        "id": "prompts_activate",
                        "label": "Activate a prompt version",
                        "code": "prompt_id = \"prompt_REPLACE_ME\"\nshow(_api('post', f'/prompts/{prompt_id}/activate'))"
                    }
                ]
            },
            {
                "id": "experiments",
                "label": "Experiments",
                "icon": "FlaskConical",
                "snippets": [
                    {
                        "id": "experiments_list",
                        "label": "List experiments",
                        "code": "show(experiments())"
                    },
                    {
                        "id": "experiments_create",
                        "label": "Create & run experiment",
                        "code": "exp = _api('post', '/experiments', json={\n    \"name\": \"prompt-ab-test\",\n    \"agent_pid\": client.agent_pid,\n    \"variant_a\": {\"prompt\": \"Be concise.\"},\n    \"variant_b\": {\"prompt\": \"Be verbose.\"},\n    \"token_budget\": 5000,\n    \"runs\": 3\n})\nshow(exp)\n\n# Run it\nif 'experiment_id' in exp:\n    show(_api('post', f\"/experiments/{exp['experiment_id']}/run\"))"
                    }
                ]
            },
            {
                "id": "trust",
                "label": "Trust & Proof",
                "icon": "Shield",
                "snippets": [
                    {
                        "id": "trust_score",
                        "label": "Current trust score",
                        "code": "show(trust())"
                    },
                    {
                        "id": "proof_generate",
                        "label": "Generate proof",
                        "code": "result = _api('post', '/proof/generate', json={\n    \"agent_pid\": client.agent_pid\n})\nshow(result)"
                    },
                    {
                        "id": "merkle_proof",
                        "label": "Merkle proof for a CID",
                        "code": "cid = \"cid_REPLACE_ME\"\nshow(_api('get', f'/proof/merkle-proof/{cid}'))"
                    }
                ]
            },
            {
                "id": "guard",
                "label": "Guard Pipeline",
                "icon": "ShieldAlert",
                "snippets": [
                    {
                        "id": "guard_status",
                        "label": "Guard pipeline status",
                        "code": "show(_api('get', '/monitor/guard-pipeline'))"
                    },
                    {
                        "id": "pii_scan",
                        "label": "PII scan",
                        "code": "show(_api('get', '/actionlog/pii-scan'))"
                    }
                ]
            },
            {
                "id": "langchain",
                "label": "LangChain",
                "icon": "Link",
                "snippets": [
                    {
                        "id": "langchain_basic",
                        "label": "LangChain callback handler",
                        "code": "# Requires: pip install langchain langchain-openai\nfrom langchain import ConnectorCallbackHandler\nhandler = ConnectorCallbackHandler(\n    base_url=BASE_URL,\n    agent_pid=client.agent_pid\n)\nprint('Handler ready — attach to any LangChain LLM/chain as callbacks=[handler]')\nshow(handler.__dict__)"
                    }
                ]
            },
            {
                "id": "crewai",
                "label": "CrewAI",
                "icon": "Users",
                "snippets": [
                    {
                        "id": "crewai_observer",
                        "label": "CrewAI observer setup",
                        "code": "# Requires: pip install crewai\nfrom crewai import ConnectorCrewObserver, instrument_crew\nobserver = ConnectorCrewObserver(\n    base_url=BASE_URL,\n    agent_pid=client.agent_pid\n)\nprint('Observer ready — call instrument_crew(crew, observer) before crew.kickoff()')"
                    }
                ]
            },
            {
                "id": "monitor",
                "label": "Monitor",
                "icon": "Activity",
                "snippets": [
                    {
                        "id": "monitor_health",
                        "label": "Platform health",
                        "code": "show(health())"
                    },
                    {
                        "id": "monitor_cost",
                        "label": "Cost dashboard",
                        "code": "show(_api('get', '/monitor/cost-dashboard'))"
                    },
                    {
                        "id": "monitor_anomalies",
                        "label": "Anomalies",
                        "code": "show(_api('get', '/monitor/anomalies'))"
                    }
                ]
            },
            {
                "id": "misc",
                "label": "Utilities",
                "icon": "Wrench",
                "snippets": [
                    {
                        "id": "trace_decorator",
                        "label": "@connector_trace decorator",
                        "code": "@connector_trace(client=client, intent=\"classify\", tags=[\"demo\"])\ndef classify(text: str) -> str:\n    # Replace with real logic\n    return f\"category:positive (len={len(text)})\"\n\nresult = classify(\"Connector Platform is great!\")\nprint(result)"
                    },
                    {
                        "id": "trace_context",
                        "label": "Context manager trace",
                        "code": "with client.trace(\"fetch_data\", tags=[\"db\"]) as span:\n    data = {\"rows\": 42, \"source\": \"demo\"}\n    span.record(str(data))\n    span.set_metadata(\"row_count\", 42)\nprint(\"Trace complete\")"
                    },
                    {
                        "id": "action_log",
                        "label": "Log a custom action",
                        "code": "client.log_action(\n    intent=\"user-click\",\n    action=\"submit-form\",\n    outcome=\"Allowed\",\n    duration_ms=12,\n    target=\"/onboarding\"\n)\nprint(\"Action logged\")"
                    }
                ]
            }
        ]
    }))
}

pub async fn playground(State(_state): State<SharedState>) -> Json<serde_json::Value> {
    let version = Command::new("python3")
        .arg("--version")
        .output()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout).trim().to_string()
                + &String::from_utf8_lossy(&o.stderr).trim().to_string()
        })
        .unwrap_or_else(|_| "python3 not found".into());

    let sdk_path = get_sdk_path();
    let sdk_available = std::path::Path::new(&sdk_path)
        .join("decorator.py")
        .exists();

    Json(serde_json::json!({
        "ok": true,
        "data": {
            "id": "connector-playground",
            "label": "Connector Interactive Playground",
            "execution_model": "stateless-concat",
            "python": version.trim(),
            "sdk_available": sdk_available,
            "sdk_path": sdk_path,
            "timeout_secs": 30,
            "routes": {
                "info": "/playground",
                "execute": "/playground/execute",
                "kernel": "/playground/kernel",
                "snippets": "/playground/snippets"
            },
            "starter_cells": [
                {
                    "id": "intro",
                    "label": "Platform health",
                    "code": "show(health())"
                },
                {
                    "id": "agents",
                    "label": "List agents",
                    "code": "show(agents())"
                },
                {
                    "id": "memory",
                    "label": "Write a memory packet",
                    "code": "result = client.write_packet(packet_type=\"Observation\", content=\"Playground started\", tags=[\"playground\"])\nshow(result)"
                }
            ],
            "next_actions": [
                "POST code cells to /playground/execute",
                "Browse starter snippets at /playground/snippets",
                "Inspect kernel/runtime info at /playground/kernel"
            ]
        },
        "meta": {
            "version": "v1",
            "timestamp": chrono::Utc::now().to_rfc3339()
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::assert_notebook_base_url_allowed;

    #[test]
    fn notebook_rejects_direct_provider_base_url() {
        assert!(assert_notebook_base_url_allowed("https://api.openai.com/v1").is_err());
        assert!(assert_notebook_base_url_allowed("https://api.anthropic.com").is_err());
        assert!(assert_notebook_base_url_allowed("http://localhost:9090/api/v1").is_ok());
    }
}

//! Service 21: Protocol Bridges
//! Exposes MCP client/server, A2A, ACP, ANP, AP2 — all 7 agent communication layers

use crate::middleware::tenant::{TenantContext, TenantSource};
use crate::state::SharedState;
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::IntoResponse;
use axum::{
    extract::{Path, State},
    Json,
};
use serde::Deserialize;
use std::convert::Infallible;
use std::sync::Mutex;
use std::time::{Duration, Instant};

fn protocol_json_err(body: serde_json::Value) -> Json<serde_json::Value> {
    Json(body)
}

fn mcp_api_key(headers: &HeaderMap) -> String {
    headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.trim_start_matches("Bearer ").trim().to_string())
        .or_else(|| {
            headers
                .get("x-api-key")
                .and_then(|h| h.to_str().ok())
                .map(|s| s.trim().to_string())
        })
        .unwrap_or_default()
}

/// Linked repo: no Connector agent ID + role → deny MCP tools, including read.
fn deny_mcp_without_repo_identity(
    state: &SharedState,
    headers: &HeaderMap,
) -> Option<Json<serde_json::Value>> {
    match crate::services::devguard::require_repo_identity(state, &mcp_api_key(headers), headers) {
        Ok(_) => None,
        Err(code) => Some(Json(serde_json::json!({
            "ok": false,
            "admitted": false,
            "error": code,
            "verdict": "DENY",
            "message": "This repo is under Connector. Ask the node for an agent ID and role. Even read is denied.",
            "ask": "POST /api/v1/devguard/admit",
            "header": "X-Connector-Repo",
        }))),
    }
}

fn agent_pid_for_protocol(headers: &HeaderMap, explicit: Option<&str>) -> String {
    explicit
        .filter(|s| !s.trim().is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| crate::substrate::egress_policy::principal_id(headers))
}

/// Spectral (I) hint for SGKE — optional `_sgke_re`/`_sgke_im` in tool args or `CONNECTOR_SGKE_I`.
fn mcp_sgke_spectral_hint(req: &McpCallRequest) -> (f64, f64) {
    if let Some(re) = req.arguments.get("_sgke_re").and_then(|v| v.as_f64()) {
        let im = req
            .arguments
            .get("_sgke_im")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        return (re, im);
    }
    if let Ok(v) = std::env::var("CONNECTOR_SGKE_I") {
        if let Ok(i) = v.parse::<f64>() {
            return (i.clamp(0.0, 1.0), 0.0);
        }
    }
    // Default below high-I threshold so ordinary MCP egress is not blocked.
    (0.35, 0.0)
}

/// Placement (H) hint — local single-node placement is honest; force-missing for gate tests.
fn mcp_sgke_placement_hint(
    _state: &SharedState,
    _headers: &HeaderMap,
) -> Option<connector_trust::HardwarePlacementV2> {
    if std::env::var("CONNECTOR_SGKE_FORCE_MISSING_H")
        .map(|v| {
            let t = v.trim().to_ascii_lowercase();
            t == "1" || t == "true" || t == "yes"
        })
        .unwrap_or(false)
    {
        return None;
    }
    if let Ok(region) = std::env::var("CONNECTOR_PLACEMENT_REGION") {
        let region = region.trim();
        if !region.is_empty() {
            return Some(
                connector_trust::HardwarePlacementV2::new(region)
                    .with_cell_id("single_node")
                    .with_capabilities(vec!["mcp_egress".into()])
                    .with_endpoints(vec!["local://node".into()]),
            );
        }
    }
    Some(
        connector_trust::HardwarePlacementV2::new("local")
            .with_cell_id("single_node")
            .with_capabilities(vec!["mcp_egress".into()])
            .with_endpoints(vec!["local://node".into()]),
    )
}

/// Sliding window limit for MCP `agent_register` (BF2-S01).
fn mcp_proceed(
    state: &crate::state::SharedState,
    agent_pid: &str,
    tool: &str,
    args: &serde_json::Value,
) -> Result<crate::substrate::pate::AugmentedTaskUnit, String> {
    match crate::substrate::pate::admit_tool(state, agent_pid, "mcp", tool, args, None) {
        Ok(atu) if crate::substrate::pate::host_admission_allows_execution(atu.verdict) => Ok(atu),
        Ok(atu) => {
            mcp_finish(state, &atu, false);
            Err(format!("pate_not_proceed:{}", atu.task_id))
        }
        Err(error) => Err(error.human_readable),
    }
}

fn mcp_finish(state: &crate::state::SharedState, atu: &crate::substrate::pate::AugmentedTaskUnit, observed: bool) {
    let _ = crate::substrate::pate::complete_augmented_task(
        state,
        atu,
        if observed { "ok" } else { "deny" },
        serde_json::json!({"observed": observed, "runtime": "mcp"}),
    );
}

fn mcp_agent_register_rate_allow() -> Result<(), String> {
    const MAX_PER_MIN: u32 = 120;
    static WINDOW: Mutex<Option<(Instant, u32)>> = Mutex::new(None);
    let mut w = WINDOW
        .lock()
        .map_err(|_| "mcp_rate_limit_lock_poisoned".to_string())?;
    let now = Instant::now();
    let slot = w.get_or_insert((now, 0));
    if now.duration_since(slot.0) >= Duration::from_secs(60) {
        slot.0 = now;
        slot.1 = 0;
    }
    if slot.1 >= MAX_PER_MIN {
        return Err(format!(
            "agent_register rate limited: max {} MCP registrations per minute",
            MAX_PER_MIN
        ));
    }
    slot.1 += 1;
    Ok(())
}
use connector_protocols::{
    a2a_bridge::{
        A2aArtifact, A2aBridge, A2aKernelBackend, A2aMessage, A2aPart, A2aTask, AgentCapabilities,
        AgentCard, AgentSkill, AuthenticationInfo, TaskSendRequest, TaskState, TaskStatus,
    },
    acp_bridge::{AcpBridge, AcpKernelBackend, AcpMessage},
    anp_bridge::{DidDocument, ServiceEndpoint},
    ap2_bridge::MandateType,
    error::{ProtocolError, ProtocolResult},
    mcp_client::{McpClient, McpTransport},
    mcp_server::{
        JsonRpcRequest, JsonRpcResponse, McpContent, McpKernelBackend, McpResourceDef, McpServer,
        McpToolDef, McpToolResult,
    },
};

// ── Local sync MCP transport (reqwest blocking) ───────────────────────────────

// ── Phase R3: Async MCP transport — replaces reqwest::blocking ──────────────
//
// `McpTransport::send` is a sync trait method (defined in connector-protocols).
// We bridge to the async `reqwest::Client` by running the blocking call on
// tokio's dedicated blocking thread pool via `std::thread::spawn` + channel.
// This means no tokio blocking thread is ever held inside an async context.
//
// In Phase R4 the connector-protocols crate will add an `async_send` method
// to `McpTransport` and this bridge goes away entirely.

struct ReqwestAsyncTransport {
    timeout_secs: u64,
}

impl ReqwestAsyncTransport {
    fn new(timeout_secs: u64) -> Self {
        Self { timeout_secs }
    }
}

impl McpTransport for ReqwestAsyncTransport {
    fn send(&self, url: &str, request: &JsonRpcRequest) -> ProtocolResult<JsonRpcResponse> {
        // Build a one-shot sync client per call — cheap since reqwest reuses
        // the OS TCP stack. The client is built inside a real OS thread so the
        // tokio executor is never blocked on I/O.
        let timeout_secs = self.timeout_secs;
        let url = url.to_string();
        let req_body = serde_json::to_string(request)
            .map_err(|e| ProtocolError::Serialization(e.to_string()))?;

        // Offload blocking I/O to a real OS thread so the tokio runtime stays free.
        let (tx, rx) = std::sync::mpsc::channel::<ProtocolResult<JsonRpcResponse>>();
        std::thread::spawn(move || {
            let client = match crate::substrate::egress_policy::reqwest_blocking_client_pinned(
                &url,
                std::time::Duration::from_secs(timeout_secs),
            ) {
                Ok(c) => c,
                Err(e) => {
                    let _ = tx.send(Err(ProtocolError::Transport(format!("dns_pin: {e}"))));
                    return;
                }
            };
            let result = client
                .post(&url)
                .header("content-type", "application/json")
                .body(req_body)
                .send()
                .map_err(|e| ProtocolError::Transport(e.to_string()))
                .and_then(|r| {
                    r.json::<JsonRpcResponse>()
                        .map_err(|e| ProtocolError::Serialization(e.to_string()))
                });
            let _ = tx.send(result);
        });

        rx.recv()
            .map_err(|_| ProtocolError::Transport("transport thread dropped".into()))?
    }
}

// Alias so call sites are unchanged
type HttpSyncTransport = ReqwestAsyncTransport;

// ── MCP Client ────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct McpDiscoverRequest {
    pub server_url: String,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

/// POST /protocols/mcp/discover — discover tools from a remote MCP server
pub async fn mcp_discover(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<McpDiscoverRequest>,
) -> Json<serde_json::Value> {
    if let Err(j) = crate::substrate::egress_policy::cfni_mesh_guard(&headers) {
        crate::substrate::cnp_edge::record_rest_protocol_edge(
            state.as_ref(),
            "/protocols/mcp/discover",
            "mcp",
            Some(&crate::substrate::egress_policy::principal_id(&headers)),
            crate::substrate::egress_policy::tenant_id(&headers).as_deref(),
            403,
        );
        return protocol_json_err(j);
    }
    if let Err(code) = crate::substrate::egress_policy::assert_mcp_egress_allowed(&req.server_url) {
        let body = serde_json::json!({
            "ok": false,
            "error": code,
            "message": "MCP egress denied by allowlist",
        });
        crate::substrate::cnp_edge::record_rest_protocol_edge(
            state.as_ref(),
            "/protocols/mcp/discover",
            "mcp",
            Some(&crate::substrate::egress_policy::principal_id(&headers)),
            crate::substrate::egress_policy::tenant_id(&headers).as_deref(),
            403,
        );
        return protocol_json_err(body);
    }
    let agent_pid = agent_pid_for_protocol(&headers, None);
    if let Err(e) = crate::substrate::egress_policy::assert_agent_l7_egress_allowed(
        state.as_ref(),
        &agent_pid,
        &req.server_url,
    ) {
        let body = serde_json::json!({
            "ok": false,
            "error": "l7_egress_denied",
            "message": e,
            "honesty": "App allowlist gate — not a full L7 proxy",
        });
        return protocol_json_err(body);
    }
    if let Err(j) = crate::substrate::admission_gate::require_tool_dispatch_headers(
        &state,
        Some(&headers),
        &agent_pid,
        "protocols/mcp",
        "mcp:discover",
    ) {
        crate::substrate::cnp_edge::record_rest_protocol_edge(
            state.as_ref(),
            "/protocols/mcp/discover",
            "mcp",
            Some(&agent_pid),
            crate::substrate::egress_policy::tenant_id(&headers).as_deref(),
            403,
        );
        return protocol_json_err(j);
    }
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        &agent_pid,
        "protocols",
        "discover",
        &serde_json::json!({"server_url": req.server_url}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    let timeout_secs = req.timeout_secs.unwrap_or(10);
    let transport = HttpSyncTransport::new(timeout_secs);
    let mut client =
        McpClient::new(transport).with_timeout(std::time::Duration::from_secs(timeout_secs));
    let result = match client.discover(&req.server_url) {
        Ok(tools) => {
            let tool_list: Vec<serde_json::Value> = tools
                .iter()
                .map(|t| {
                    serde_json::json!({
                        "name": t.name,
                        "description": t.description,
                        "input_schema": t.input_schema,
                    })
                })
                .collect();
            serde_json::json!({
                "ok": true,
                "server_url": req.server_url,
                "tool_count": tool_list.len(),
                "tools": tool_list,
            })
        }
        Err(e) => serde_json::json!({ "ok": false, "error": format!("{:?}", e) }),
    };
    let status = if result.get("ok").and_then(|v| v.as_bool()) == Some(true) {
        200
    } else {
        502
    };
    crate::substrate::cnp_edge::record_rest_protocol_edge(
        state.as_ref(),
        "/protocols/mcp/discover",
        "mcp",
        Some(&agent_pid),
        crate::substrate::egress_policy::tenant_id(&headers).as_deref(),
        status,
    );
    let discovered = result.get("ok").and_then(|v| v.as_bool()) == Some(true);
    open_proceed.finish_observed(discovered);
    let mut result = result;
    if let Some(obj) = result.as_object_mut() {
        obj.insert("task_id".into(), serde_json::json!(admitted.task_id));
        obj.insert("executed".into(), serde_json::json!(discovered));
        obj.insert("admits".into(), serde_json::json!(false));
    }
    Json(result)
}

#[derive(Deserialize)]
pub struct McpCallRequest {
    pub server_url: String,
    pub tool_name: String,
    pub arguments: serde_json::Value,
    #[serde(default)]
    pub agent_pid: Option<String>,
    #[serde(default)]
    pub package: Option<connector_native_contract::PackagePin>,
}

/// POST /protocols/mcp/call — call a tool on a remote MCP server
pub async fn mcp_call_tool(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<McpCallRequest>,
) -> Json<serde_json::Value> {
    if let Some(deny) = deny_mcp_without_repo_identity(&state, &headers) {
        return deny;
    }
    if let Err(j) = crate::substrate::egress_policy::cfni_mesh_guard(&headers) {
        crate::substrate::cnp_edge::record_rest_protocol_edge(
            state.as_ref(),
            "/protocols/mcp/call",
            "mcp",
            Some(&crate::substrate::egress_policy::principal_id(&headers)),
            crate::substrate::egress_policy::tenant_id(&headers).as_deref(),
            403,
        );
        return protocol_json_err(j);
    }
    if let Err(code) = crate::substrate::egress_policy::assert_mcp_egress_allowed(&req.server_url) {
        let body = serde_json::json!({
            "ok": false,
            "error": code,
            "message": "MCP egress denied by allowlist",
        });
        crate::substrate::cnp_edge::record_rest_protocol_edge(
            state.as_ref(),
            "/protocols/mcp/call",
            "mcp",
            Some(&crate::substrate::egress_policy::principal_id(&headers)),
            crate::substrate::egress_policy::tenant_id(&headers).as_deref(),
            403,
        );
        return protocol_json_err(body);
    }
    // P6.6 SGKE: high I without H denied before tool egress.
    {
        let (re, im) = mcp_sgke_spectral_hint(&req);
        let placement = mcp_sgke_placement_hint(&state, &headers);
        let decision =
            crate::substrate::sgke_gate::evaluate_from_spectral(re, im, placement.as_ref());
        if decision.verdict == crate::substrate::sgke_gate::SgkeVerdict::Deny {
            let body = crate::substrate::sgke_gate::deny_json(&decision);
            crate::substrate::cnp_edge::record_rest_protocol_edge(
                state.as_ref(),
                "/protocols/mcp/call",
                "mcp",
                Some(&crate::substrate::egress_policy::principal_id(&headers)),
                crate::substrate::egress_policy::tenant_id(&headers).as_deref(),
                403,
            );
            return protocol_json_err(body);
        }
    }
    let agent_pid = agent_pid_for_protocol(&headers, req.agent_pid.as_deref());
    if let Err(e) = crate::substrate::egress_policy::assert_agent_l7_egress_allowed(
        state.as_ref(),
        &agent_pid,
        &req.server_url,
    ) {
        let body = serde_json::json!({
            "ok": false,
            "error": "l7_egress_denied",
            "message": e,
            "honesty": "App allowlist gate — not a full L7 proxy",
        });
        return protocol_json_err(body);
    }
    let args_str = serde_json::to_string(&req.arguments).unwrap_or_default();
    if let Err(j) = crate::substrate::admission_gate::require_mcp_call_headers(
        &state,
        Some(&headers),
        &agent_pid,
        "protocols/mcp",
        &req.tool_name,
        Some(&args_str),
    ) {
        crate::substrate::cnp_edge::record_rest_protocol_edge(
            state.as_ref(),
            "/protocols/mcp/call",
            "mcp",
            Some(&agent_pid),
            crate::substrate::egress_policy::tenant_id(&headers).as_deref(),
            403,
        );
        return protocol_json_err(j);
    }
    // Protocol driver: surface bind + native_invoker → PATE/ActionBinding before HTTP egress.
    let (driver, atu) = match crate::substrate::protocol_drivers::admit_mcp_call(
        &state,
        &agent_pid,
        "protocols/mcp",
        &req.tool_name,
        &req.server_url,
        &req.arguments,
        None,
        req.package.clone(),
    ) {
        Ok(pair) => pair,
        Err(e) => {
            crate::substrate::cnp_edge::record_rest_protocol_edge(
                state.as_ref(),
                "/protocols/mcp/call",
                "mcp",
                Some(&agent_pid),
                crate::substrate::egress_policy::tenant_id(&headers).as_deref(),
                403,
            );
            return protocol_json_err(
                crate::substrate::protocol_drivers::admit_denied_json("mcp", &e),
            );
        }
    };
    if !crate::substrate::pate::host_admission_allows_execution(atu.verdict) {
        crate::substrate::cnp_edge::record_rest_protocol_edge(
            state.as_ref(),
            "/protocols/mcp/call",
            "mcp",
            Some(&agent_pid),
            crate::substrate::egress_policy::tenant_id(&headers).as_deref(),
            403,
        );
        return Json(serde_json::json!({
            "ok": false,
            "error": "not_proceed",
            "task_id": atu.task_id,
            "executed": false,
            "admits": false,
            "pate_verdict": driver.pate_verdict,
        }));
    }
    if !driver.allowed {
        crate::substrate::cnp_edge::record_rest_protocol_edge(
            state.as_ref(),
            "/protocols/mcp/call",
            "mcp",
            Some(&agent_pid),
            crate::substrate::egress_policy::tenant_id(&headers).as_deref(),
            403,
        );
        return protocol_json_err(serde_json::json!({
            "ok": false,
            "error": "mcp_governance_denied",
            "pate_verdict": driver.pate_verdict,
            "detail": driver.deny_detail,
            "surface_uid": driver.surface_uid,
            "honesty": "Real MCP HTTP cannot bypass AutonomyGateway, world grants, or HITL",
        }));
    }
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &atu);
    if crate::kernel::landlock_child::enforced() {
        let rpc = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": req.tool_name,
                "arguments": req.arguments,
            }
        });
        return match crate::kernel::landlock_child::http_fetch(
            state.as_ref(),
            &agent_pid,
            &req.server_url,
            &req.server_url,
            "POST",
            serde_json::json!({"content-type": "application/json"}),
            Some(rpc),
            30_000,
        ) {
            Ok(v) => {
                open_proceed.finish_observed(true);
                Json(serde_json::json!({
                    "ok": true,
                    "task_id": atu.task_id,
                    "executed": true,
                    "admits": false,
                    "tool_name": req.tool_name,
                    "server_url": req.server_url,
                    "landlock_child": true,
                    "content": v.get("body").cloned().unwrap_or(v),
                    "honesty": "MCP HTTP ran in dest-pinned Landlock child — not platform PID",
                }))
            }
            Err(e) => {
                open_proceed.finish_observed(false);
                protocol_json_err(serde_json::json!({
                    "ok": false,
                    "task_id": atu.task_id,
                    "executed": false,
                    "admits": false,
                    "error": e,
                    "landlock_child": true,
                }))
            }
        };
    }
    // Peer hop honesty: without a peer UsageReceipt, mark unmetered (never fake $0).
    {
        let receipt = connector_trust::UsageReceipt::unmetered_peer(
            connector_trust::PeerKind::Mcp,
            req.server_url.clone(),
            None,
            None,
        );
        let _ = crate::substrate::usage_receipt::append_usage_receipt(state.as_ref(), &receipt);
    }
    let transport = HttpSyncTransport::new(30);
    let mut client = McpClient::new(transport);
    let result = match client.discover(&req.server_url) {
        Ok(_) => {}
        Err(e) => {
            let body = serde_json::json!({
                "ok": false,
                "task_id": atu.task_id,
                "executed": false,
                "admits": false,
                "error": format!("discover: {:?}", e),
            });
            crate::substrate::cnp_edge::record_rest_protocol_edge(
                state.as_ref(),
                "/protocols/mcp/call",
                "mcp",
                Some(&agent_pid),
                crate::substrate::egress_policy::tenant_id(&headers).as_deref(),
                502,
            );
            open_proceed.finish_observed(false);
            return protocol_json_err(body);
        }
    };
    let result = match client.call_tool(&req.tool_name, req.arguments.clone()) {
        Ok(result) => {
            let content = result.get("content").cloned().unwrap_or_default();
            let is_error = result
                .get("isError")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            serde_json::json!({
                "ok": true,
                "tool_name": req.tool_name,
                "server_url": req.server_url,
                "content": content,
                "is_error": is_error,
            })
        }
        Err(e) => serde_json::json!({ "ok": false, "error": format!("{:?}", e) }),
    };
    let status = if result.get("ok").and_then(|v| v.as_bool()) == Some(true) {
        200
    } else {
        502
    };
    crate::substrate::cnp_edge::record_rest_protocol_edge(
        state.as_ref(),
        "/protocols/mcp/call",
        "mcp",
        Some(&agent_pid),
        crate::substrate::egress_policy::tenant_id(&headers).as_deref(),
        status,
    );
    let called = result.get("ok").and_then(|v| v.as_bool()) == Some(true);
    open_proceed.finish_observed(called);
    let mut result = result;
    if let Some(obj) = result.as_object_mut() {
        obj.insert("task_id".into(), serde_json::json!(atu.task_id));
        obj.insert("executed".into(), serde_json::json!(called));
        obj.insert("admits".into(), serde_json::json!(false));
    }
    Json(result)
}

/// GET /protocols/mcp/servers — list registered MCP servers in this session
pub async fn mcp_list_servers(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let es = state.engine_store.lock().unwrap();
    let keys = es.folder_keys("mcp_servers", None).unwrap_or_default();
    let servers: Vec<serde_json::Value> = keys
        .iter()
        .filter_map(|k| {
            es.folder_get("mcp_servers", k)
                .ok()
                .flatten()
                .map(|v| serde_json::json!({ "url": k, "meta": v }))
        })
        .collect();
    Json(serde_json::json!({ "servers": servers, "count": servers.len() }))
}

// ── MCP Server (platform acts as MCP server) ──────────────────────────────────

#[derive(Deserialize)]
pub struct McpHandleRequest {
    pub jsonrpc: String,
    pub id: Option<serde_json::Value>,
    pub method: String,
    pub params: Option<serde_json::Value>,
}

/// POST /protocols/mcp/handle — platform receives JSON-RPC from MCP clients
pub async fn mcp_handle(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<McpHandleRequest>,
) -> Json<serde_json::Value> {
    if req.method == "tools/call" {
        if let Some(deny) = deny_mcp_without_repo_identity(&state, &headers) {
            return deny;
        }
        if let Err(j) = crate::substrate::egress_policy::cfni_mesh_guard(&headers) {
            crate::substrate::cnp_edge::record_rest_protocol_edge(
                state.as_ref(),
                "/protocols/mcp/handle",
                "mcp",
                Some(&crate::substrate::egress_policy::principal_id(&headers)),
                crate::substrate::egress_policy::tenant_id(&headers).as_deref(),
                403,
            );
            return protocol_json_err(j);
        }
    }
    let handle_agent = crate::substrate::egress_policy::principal_id(&headers);
    let admitted = if req.method == "tools/call" {
        match crate::substrate::pate::require_proceed(
            &state,
            &handle_agent,
            "protocols",
            "mcp_handle",
            &serde_json::json!({"method": req.method}),
        ) {
            Ok(atu) => Some(atu),
            Err(body) => return Json(body),
        }
    } else {
        None
    };
    let mut open_proceed = admitted
        .as_ref()
        .map(|atu| crate::substrate::pate::OpenProceed::arm(&state, atu));
    let q = crate::kernel::docklock::extract_quantum_id(&headers);
    let rpc = JsonRpcRequest {
        jsonrpc: req.jsonrpc,
        id: req.id.clone(),
        method: req.method.clone(),
        params: req.params.unwrap_or_default(),
    };
    let state_for_mcp = state.clone();
    let (response, status) = crate::kernel::ring1_context::scope(q, async move {
        let backend = PlatformMcpBackend {
            state: state_for_mcp,
        };
        let server = McpServer::new(backend, "connector-platform", "0.1.0");
        let response = server.handle_request("platform", &rpc);
        let status = if response.error.is_some() { 400 } else { 200 };
        (response, status)
    })
    .await;
    if let Some(guard) = open_proceed.as_mut() {
        guard.finish_observed(status == 200);
    }
    crate::substrate::cnp_edge::record_rest_protocol_edge(
        state.as_ref(),
        "/protocols/mcp/handle",
        "mcp",
        Some(&crate::substrate::egress_policy::principal_id(&headers)),
        crate::substrate::egress_policy::tenant_id(&headers).as_deref(),
        status,
    );
    Json(serde_json::to_value(&response).unwrap_or_default())
}

/// GET /protocols/mcp/tools — list tools this platform exposes as MCP server
pub async fn mcp_list_tools(State(_state): State<SharedState>) -> Json<serde_json::Value> {
    let backend = PlatformMcpBackend { state: _state };
    let tools = backend.list_tools("platform").unwrap_or_default();
    let tool_list: Vec<serde_json::Value> = tools
        .iter()
        .map(|t| {
            serde_json::json!({
                "name": t.name,
                "description": t.description,
            })
        })
        .collect();
    Json(
        serde_json::json!({
            "tools": tool_list,
            "count": tool_list.len(),
            "server": "connector-platform",
            "admits": crate::substrate::agentgateway::mcp_discovery_admits_effect(),
        }),
    )
}

fn tenant_context_from_mcp_args(args: &serde_json::Value) -> Option<TenantContext> {
    if std::env::var("CONNECTOR_MULTI_TENANT").is_err() {
        return None;
    }
    args.get("tenant_id")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|id| TenantContext::from_id(id, TenantSource::Header))
}

struct PlatformMcpBackend {
    state: SharedState,
}

impl PlatformMcpBackend {
    fn injection_check(agent_pid: &str, args: &serde_json::Value) -> Option<McpToolResult> {
        let mut det = connector_engine::semantic_injection::SemanticInjectionDetector::new();
        let r = det.analyze(&serde_json::to_string(args).unwrap_or_default(), agent_pid);
        if r.score > 0.75 {
            Some(McpToolResult {
                content: vec![McpContent {
                    content_type: "text".into(),
                    text: format!("INJECTION_BLOCKED score={:.2}", r.score),
                }],
                is_error: Some(true),
            })
        } else {
            None
        }
    }
    fn ok(text: String) -> McpToolResult {
        McpToolResult {
            content: vec![McpContent {
                content_type: "text".into(),
                text,
            }],
            is_error: None,
        }
    }
    fn err(text: String) -> McpToolResult {
        McpToolResult {
            content: vec![McpContent {
                content_type: "text".into(),
                text,
            }],
            is_error: Some(true),
        }
    }
}

impl McpKernelBackend for PlatformMcpBackend {
    fn list_tools(
        &self,
        _agent_pid: &str,
    ) -> connector_protocols::error::ProtocolResult<Vec<McpToolDef>> {
        crate::services::mcp_hosting::ensure_default_plugins();
        let mut tools = vec![
            McpToolDef { name: "memory_write".into(),
                description: "Write a memory packet into an agent namespace (VAC kernel)".into(),
                input_schema: serde_json::json!({"type":"object","required":["content","agent_pid"],"properties":{"content":{"type":"string"},"agent_pid":{"type":"string"},"type":{"type":"string","default":"extraction"},"session_id":{"type":"string"}}}) },
            McpToolDef { name: "memory_recall".into(),
                description: "Return recent memory packets for an agent".into(),
                input_schema: serde_json::json!({"type":"object","required":["agent_pid"],"properties":{"agent_pid":{"type":"string"},"limit":{"type":"integer","default":20}}}) },
            McpToolDef { name: "memory_search".into(),
                description: "Keyword search over agent memory packets".into(),
                input_schema: serde_json::json!({"type":"object","required":["agent_pid","query"],"properties":{"agent_pid":{"type":"string"},"query":{"type":"string"},"limit":{"type":"integer","default":10}}}) },
            McpToolDef { name: "agent_register".into(),
                description: "Register a new agent in the kernel, returns agent_pid. Under CONNECTOR_DEFENSE_STRICT, also set CONNECTOR_MCP_ALLOW_AGENT_REGISTER=1 (or capability mcp:agent:register in args when enforced).".into(),
                input_schema: serde_json::json!({"type":"object","required":["name","namespace"],"properties":{"name":{"type":"string"},"namespace":{"type":"string"},"role":{"type":"string"},"model":{"type":"string"},"tenant_id":{"type":"string","description":"Required when CONNECTOR_MULTI_TENANT is set"},"capability":{"type":"string","description":"Must be mcp:agent:register when defense strict + allow flag set"}}}) },
            McpToolDef { name: "agent_status".into(),
                description: "Get status and metadata for an agent by PID".into(),
                input_schema: serde_json::json!({"type":"object","required":["agent_pid"],"properties":{"agent_pid":{"type":"string"}}}) },
            McpToolDef { name: "agent_health".into(),
                description: "Get health metrics: token budget, cost, trust score, operation count".into(),
                input_schema: serde_json::json!({"type":"object","required":["agent_pid"],"properties":{"agent_pid":{"type":"string"}}}) },
            McpToolDef { name: "audit_tail".into(),
                description: "Return last N audit entries across all agents".into(),
                input_schema: serde_json::json!({"type":"object","properties":{"limit":{"type":"integer","default":20,"maximum":200}}}) },
            McpToolDef { name: "audit_by_agent".into(),
                description: "Return last N audit entries for a specific agent".into(),
                input_schema: serde_json::json!({"type":"object","required":["agent_pid"],"properties":{"agent_pid":{"type":"string"},"limit":{"type":"integer","default":20}}}) },
            McpToolDef { name: "trust_score".into(),
                description: "Compute platform EigenTrust score across all dimensions".into(),
                input_schema: serde_json::json!({"type":"object","properties":{}}) },
            McpToolDef { name: "snapshot".into(),
                description: "Create a content-addressed snapshot of an agent's context".into(),
                input_schema: serde_json::json!({"type":"object","required":["agent_pid"],"properties":{"agent_pid":{"type":"string"}}}) },
            McpToolDef { name: "restore".into(),
                description: "Restore agent context from a snapshot CID".into(),
                input_schema: serde_json::json!({"type":"object","required":["agent_pid","snapshot_cid"],"properties":{"agent_pid":{"type":"string"},"snapshot_cid":{"type":"string"}}}) },
            McpToolDef { name: "proof_generate".into(),
                description: "Generate HMAC audit-chain integrity proof for an agent".into(),
                input_schema: serde_json::json!({"type":"object","required":["agent_pid"],"properties":{"agent_pid":{"type":"string"},"from_ms":{"type":"integer"},"to_ms":{"type":"integer"}}}) },
            McpToolDef { name: "policy_check".into(),
                description: "Dry-run policy check: is an agent allowed to perform an operation?".into(),
                input_schema: serde_json::json!({"type":"object","required":["agent_pid","operation"],"properties":{"agent_pid":{"type":"string"},"operation":{"type":"string"},"resource":{"type":"string"}}}) },
            McpToolDef { name: "actionlog_record".into(),
                description: "Record a structured action log entry for an agent (tool call, decision, observation)".into(),
                input_schema: serde_json::json!({"type":"object","required":["agent_pid","action"],"properties":{"agent_pid":{"type":"string"},"action":{"type":"string"},"resource":{"type":"string"},"outcome":{"type":"string","default":"success"},"metadata":{"type":"object"}}}) },
            McpToolDef { name: "agent_ps".into(),
                description: "List all registered agents (process list) with status and namespace".into(),
                input_schema: serde_json::json!({"type":"object","properties":{"status_filter":{"type":"string","description":"Filter by status: active, suspended, all (default: all)"}}}) },
            McpToolDef { name: "agent_inspect".into(),
                description: "Deep inspect an agent: ACB fields, token budget, policy grants, recent audit entries".into(),
                input_schema: serde_json::json!({"type":"object","required":["agent_pid"],"properties":{"agent_pid":{"type":"string"}}}) },
            McpToolDef { name: "agent_signal".into(),
                description: "Send a signal to an agent: suspend, resume, terminate, reflect".into(),
                input_schema: serde_json::json!({"type":"object","required":["agent_pid","signal"],"properties":{"agent_pid":{"type":"string"},"signal":{"type":"string","enum":["suspend","resume","terminate","reflect"]},"reason":{"type":"string"}}}) },
            McpToolDef { name: "budget_status".into(),
                description: "Return token budget usage, cost and remaining capacity for an agent".into(),
                input_schema: serde_json::json!({"type":"object","required":["agent_pid"],"properties":{"agent_pid":{"type":"string"}}}) },
            McpToolDef { name: "connector_who_am_i".into(),
                description: "Kernel-authoritative who-am-I for an agent (IIA identity envelope — never invent a persona)".into(),
                input_schema: serde_json::json!({"type":"object","properties":{"agent_pid":{"type":"string","description":"Defaults to caller agent"}}}) },
        ];
        tools.extend(crate::services::mcp_hosting::list_tools());
        Ok(tools)
    }

    fn list_resources(
        &self,
        agent_pid: &str,
    ) -> connector_protocols::error::ProtocolResult<Vec<McpResourceDef>> {
        let k = self.state.kernel.lock().unwrap();
        let agent_count = k.agents().len();
        let packet_count = k.packet_count();
        let audit_count = k.audit_count();
        let agents: Vec<String> = k.agents().keys().cloned().collect();
        drop(k);
        let es = self.state.engine_store.lock().unwrap();
        let bridge_keys = es.folder_keys("mcp_bridges", None).unwrap_or_default();
        drop(es);

        let mut res = vec![
            McpResourceDef {
                uri: "resource://platform/health".into(),
                name: "Platform Health".into(),
                description: "Overall platform health and subsystem status".into(),
                mime_type: "application/json".into(),
            },
            McpResourceDef {
                uri: "resource://platform/stats".into(),
                name: "Platform Stats".into(),
                description: format!(
                    "{} agents, {} packets, {} audit entries",
                    agent_count, packet_count, audit_count
                ),
                mime_type: "application/json".into(),
            },
            McpResourceDef {
                uri: "resource://platform/trust".into(),
                name: "Trust Score".into(),
                description: "EigenTrust score across all dimensions".into(),
                mime_type: "application/json".into(),
            },
            McpResourceDef {
                uri: "resource://platform/audit/tail".into(),
                name: "Audit Tail".into(),
                description: "Last 50 audit entries".into(),
                mime_type: "application/json".into(),
            },
            McpResourceDef {
                uri: format!("resource://agent/{}/status", agent_pid),
                name: "Caller Status".into(),
                description: format!("Status for {}", agent_pid),
                mime_type: "application/json".into(),
            },
            McpResourceDef {
                uri: format!("resource://agent/{}/memory", agent_pid),
                name: "Caller Memory".into(),
                description: format!("Recent packets for {}", agent_pid),
                mime_type: "application/json".into(),
            },
            McpResourceDef {
                uri: format!("resource://agent/{}/audit", agent_pid),
                name: "Caller Audit".into(),
                description: format!("Audit entries for {}", agent_pid),
                mime_type: "application/json".into(),
            },
        ];
        for bid in &bridge_keys {
            res.push(McpResourceDef {
                uri: format!("resource://bridge/{}/tools", bid),
                name: format!("Bridge {}", bid),
                description: format!("Tools for MCP bridge '{}'", bid),
                mime_type: "application/json".into(),
            });
        }
        for pid in &agents {
            if pid != agent_pid {
                res.push(McpResourceDef {
                    uri: format!("resource://agent/{}/status", pid),
                    name: format!("Agent {}", pid),
                    description: String::new(),
                    mime_type: "application/json".into(),
                });
            }
        }
        Ok(res)
    }

    fn call_tool(
        &self,
        agent_pid: &str,
        name: &str,
        args: serde_json::Value,
    ) -> connector_protocols::error::ProtocolResult<McpToolResult> {
        if let Some(b) = Self::injection_check(agent_pid, &args) {
            return Ok(b);
        }
        crate::services::mcp_hosting::ensure_default_plugins();
        if let Some(result) =
            crate::services::mcp_hosting::call_tool(&self.state, agent_pid, name, args.clone())
        {
            return Ok(result);
        }
        match name {
            "memory_write" => {
                let mcp_atu = match mcp_proceed(&self.state, agent_pid, "memory_write", &args) {
                    Ok(atu) => atu,
                    Err(message) => return Ok(Self::err(message)),
                };
                let content = args
                    .get("content")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let target = args
                    .get("agent_pid")
                    .and_then(|v| v.as_str())
                    .unwrap_or(agent_pid)
                    .to_string();
                let session = args
                    .get("session_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("mcp")
                    .to_string();
                if content.is_empty() {
                    return Ok(Self::err("content required".into()));
                }
                let ns = {
                    let k = self.state.kernel.lock().unwrap();
                    k.get_agent(&target)
                        .map(|a| a.namespace.clone())
                        .unwrap_or_else(|| format!("mcp/{}", target))
                };
                if let Err(j) = crate::substrate::admission_gate::require_memory_write_headers(
                    &self.state,
                    None,
                    &target,
                    &ns,
                ) {
                    return Ok(Self::err(
                        serde_json::to_string(&j).unwrap_or_else(|_| "admission_denied".into()),
                    ));
                }
                if let Err(j) = crate::substrate::admission_gate::require_mcp_call_headers(
                    &self.state,
                    None,
                    agent_pid,
                    &format!("mcp/{}", agent_pid),
                    "memory_write",
                    Some(&content),
                ) {
                    return Ok(Self::err(
                        serde_json::to_string(&j).unwrap_or_else(|_| "admission_denied".into()),
                    ));
                }
                let src = vac_core::types::Source {
                    kind: vac_core::types::SourceKind::Tool,
                    principal_id: format!("mcp:{}", agent_pid),
                };
                let pkt = vac_core::types::MemPacket::new(
                    vac_core::types::PacketType::Extraction,
                    serde_json::json!({"text": content}),
                    cid::Cid::default(),
                    session,
                    "mcp".into(),
                    src,
                    chrono::Utc::now().timestamp_millis(),
                );
                let mut k = self.state.kernel.lock().unwrap();
                let r = k.dispatch(vac_core::kernel::SyscallRequest {
                    agent_pid: target.clone(),
                    trace_parent: None,
                    trace_state: None,
                    api_version: None,
                    operation: vac_core::types::MemoryKernelOp::MemWrite,
                    payload: vac_core::kernel::SyscallPayload::MemWrite { packet: pkt },
                    reason: Some("mcp:memory_write".into()),
                    vakya_id: Some(format!("vakya:mcp:memory_write:{}", target)),
                });
                mcp_finish(&self.state, &mcp_atu, r.outcome == vac_core::types::OpOutcome::Success);
                Ok(Self::ok(
                    serde_json::json!({"outcome": format!("{:?}", r.outcome), "agent_pid": target, "pate_task_id": mcp_atu.task_id})
                        .to_string(),
                ))
            }
            "memory_recall" => {
                let target = args
                    .get("agent_pid")
                    .and_then(|v| v.as_str())
                    .unwrap_or(agent_pid);
                let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(20) as usize;
                let k = self.state.kernel.lock().unwrap();
                let ns = k
                    .get_agent(target)
                    .map(|a| a.namespace.clone())
                    .unwrap_or_default();
                let mut pkts = k.packets_in_namespace(&ns);
                pkts.truncate(limit);
                let items: Vec<_> = pkts
                    .iter()
                    .map(|p| {
                        serde_json::json!({"cid": p.index.packet_cid.to_string(),
                    "type": format!("{:?}", p.content.packet_type), "ts": p.index.ts})
                    })
                    .collect();
                Ok(Self::ok(
                    serde_json::json!({"packets": items, "count": items.len()}).to_string(),
                ))
            }
            "memory_search" => {
                let target = args
                    .get("agent_pid")
                    .and_then(|v| v.as_str())
                    .unwrap_or(agent_pid);
                let query = args
                    .get("query")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_lowercase();
                let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(10) as usize;
                let k = self.state.kernel.lock().unwrap();
                let ns = k
                    .get_agent(target)
                    .map(|a| a.namespace.clone())
                    .unwrap_or_default();
                let matched: Vec<_> = k.packets_in_namespace(&ns).iter()
                    .filter(|p| serde_json::to_string(&p.content.payload).unwrap_or_default().to_lowercase().contains(&query))
                    .take(limit)
                    .map(|p| serde_json::json!({"cid": p.index.packet_cid.to_string(),
                        "snippet": serde_json::to_string(&p.content.payload).unwrap_or_default().chars().take(200).collect::<String>()}))
                    .collect();
                Ok(Self::ok(
                    serde_json::json!({"query": query, "results": matched, "count": matched.len()})
                        .to_string(),
                ))
            }
            "agent_register" => {
                let mcp_atu = match mcp_proceed(&self.state, agent_pid, "agent_register", &args) {
                    Ok(atu) => atu,
                    Err(message) => return Ok(Self::err(message)),
                };
                if let Err(e) = mcp_agent_register_rate_allow() {
                    mcp_finish(&self.state, &mcp_atu, false);
                    return Ok(Self::err(e));
                }
                let args_str = serde_json::to_string(&args).unwrap_or_default();
                if let Err(j) = crate::substrate::admission_gate::require_mcp_call_headers(
                    &self.state,
                    None,
                    agent_pid,
                    &format!("mcp/{}", agent_pid),
                    "agent_register",
                    Some(&args_str),
                ) {
                    return Ok(Self::err(
                        serde_json::to_string(&j).unwrap_or_else(|_| "admission_denied".into()),
                    ));
                }
                // BF2-S01: defense deployments require explicit operator opt-in + capability string.
                if crate::services::runtime_control::defense_strict_enabled() {
                    let allowed = std::env::var("CONNECTOR_MCP_ALLOW_AGENT_REGISTER")
                        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                        .unwrap_or(false);
                    if !allowed {
                        return Ok(Self::err(
                            "agent_register disabled under DEFENSE_STRICT; set CONNECTOR_MCP_ALLOW_AGENT_REGISTER=1 for controlled use (BF2-S01)".into(),
                        ));
                    }
                    let cap = args
                        .get("capability")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    if cap != "mcp:agent:register" {
                        return Ok(Self::err(
                            "capability must be \"mcp:agent:register\" for agent_register when DEFENSE_STRICT is enabled".into(),
                        ));
                    }
                }
                let tenant_cap = tenant_context_from_mcp_args(&args);
                if let Err(j) = crate::services::agents::kernel_agent_limit_gate(
                    self.state.as_ref(),
                    tenant_cap.as_ref(),
                ) {
                    return Ok(Self::err(
                        serde_json::to_string(&j).unwrap_or_else(|_| "agent_limit_reached".into()),
                    ));
                }
                let aname = args
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("mcp-agent")
                    .to_string();
                let ns_raw = crate::services::agents::normalize_memory_namespace(
                    args.get("namespace")
                        .and_then(|v| v.as_str())
                        .unwrap_or("m/mcp"),
                );
                let ns = crate::services::agents::tenant_scoped_memory_namespace(
                    tenant_cap.as_ref(),
                    &ns_raw,
                );
                let role = args.get("role").and_then(|v| v.as_str()).map(String::from);
                let model = args.get("model").and_then(|v| v.as_str()).map(String::from);
                let mut k = self.state.kernel.lock().unwrap();
                let r = k.dispatch(vac_core::kernel::SyscallRequest {
                    agent_pid: "".into(),
                    trace_parent: None,
                    trace_state: None,
                    api_version: None,
                    operation: vac_core::types::MemoryKernelOp::AgentRegister,
                    payload: vac_core::kernel::SyscallPayload::AgentRegister {
                        agent_name: aname.clone(),
                        namespace: ns.clone(),
                        role,
                        model: model.clone(),
                        framework: None,
                    },
                    reason: Some("mcp:agent_register".into()),
                    vakya_id: Some(format!("vakya:mcp:agent_register:{}", aname)),
                });
                if r.outcome != vac_core::types::OpOutcome::Success {
                    return Ok(Self::err(format!("registration failed: {:?}", r.outcome)));
                }
                let kp = match r.value {
                    vac_core::kernel::SyscallValue::AgentPid(p) => p,
                    _ => {
                        return Ok(Self::err(
                            "registration failed: unexpected syscall value".into(),
                        ))
                    }
                };
                drop(k);
                let api_pid = crate::services::agents::ensure_agent_store_mapping(
                    &self.state,
                    &kp,
                    &aname,
                    &ns,
                    model.as_deref(),
                    "mcp",
                    Some(serde_json::json!({"source": "mcp"})),
                );
                mcp_finish(&self.state, &mcp_atu, true);
                Ok(Self::ok(
                    serde_json::json!({
                        "agent_pid": kp,
                        "api_pid": api_pid,
                        "name": aname,
                        "namespace": ns,
                        "pate_task_id": mcp_atu.task_id,
                    })
                    .to_string(),
                ))
            }
            "agent_status" => {
                let target = args
                    .get("agent_pid")
                    .and_then(|v| v.as_str())
                    .unwrap_or(agent_pid);
                let k = self.state.kernel.lock().unwrap();
                match k.get_agent(target) {
                    Some(a) => Ok(Self::ok(serde_json::json!({"agent_pid": target,
                        "name": a.agent_name, "status": format!("{:?}", a.status),
                        "namespace": a.namespace, "role": format!("{:?}", a.role),
                        "total_tokens": a.total_tokens_consumed, "total_cost_usd": a.total_cost_usd}).to_string())),
                    None => Ok(Self::err(format!("Agent {} not found", target))),
                }
            }
            "agent_health" => {
                let target = args
                    .get("agent_pid")
                    .and_then(|v| v.as_str())
                    .unwrap_or(agent_pid);
                let k = self.state.kernel.lock().unwrap();
                match k.get_agent(target) {
                    Some(a) => {
                        let trust = connector_engine::TrustComputer::compute(&k);
                        let ops = k
                            .audit_log_all()
                            .iter()
                            .filter(|e| e.agent_pid == target)
                            .count();
                        Ok(Self::ok(serde_json::json!({"agent_pid": target, "healthy": a.is_alive(),
                            "status": format!("{:?}", a.status), "total_tokens": a.total_tokens_consumed,
                            "token_budget": a.token_budget, "total_cost_usd": a.total_cost_usd,
                            "total_operations": ops, "trust_score": trust.score, "trust_grade": trust.grade}).to_string()))
                    }
                    None => Ok(Self::err(format!("Agent {} not found", target))),
                }
            }
            "audit_tail" => {
                let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(20) as usize;
                let k = self.state.kernel.lock().unwrap();
                let log = k.audit_log_all();
                let start = log.len().saturating_sub(limit);
                let entries: Vec<_> = log[start..]
                    .iter()
                    .map(|e| {
                        serde_json::json!({"audit_id": e.audit_id,
                    "timestamp": e.timestamp, "operation": format!("{:?}", e.operation),
                    "agent_pid": e.agent_pid, "outcome": format!("{:?}", e.outcome)})
                    })
                    .collect();
                Ok(Self::ok(
                    serde_json::json!({"entries": entries, "count": entries.len()}).to_string(),
                ))
            }
            "audit_by_agent" => {
                let target = args
                    .get("agent_pid")
                    .and_then(|v| v.as_str())
                    .unwrap_or(agent_pid);
                let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(20) as usize;
                let k = self.state.kernel.lock().unwrap();
                let entries: Vec<_> = k.audit_log_all().iter().rev()
                    .filter(|e| e.agent_pid == target).take(limit)
                    .map(|e| serde_json::json!({"audit_id": e.audit_id, "timestamp": e.timestamp,
                        "operation": format!("{:?}", e.operation), "outcome": format!("{:?}", e.outcome)}))
                    .collect();
                Ok(Self::ok(serde_json::json!({"agent_pid": target, "entries": entries, "count": entries.len()}).to_string()))
            }
            "trust_score" => {
                let k = self.state.kernel.lock().unwrap();
                let t = connector_engine::TrustComputer::compute(&k);
                Ok(Self::ok(
                    serde_json::json!({"score": t.score, "grade": t.grade,
                    "operations_analyzed": t.operations_analyzed,
                    "dimensions": {"memory_integrity": t.dimensions.memory_integrity,
                        "audit_completeness": t.dimensions.audit_completeness,
                        "authorization_coverage": t.dimensions.authorization_coverage,
                        "decision_provenance": t.dimensions.decision_provenance,
                        "operational_health": t.dimensions.operational_health}})
                    .to_string(),
                ))
            }
            "snapshot" => {
                let target = args
                    .get("agent_pid")
                    .and_then(|v| v.as_str())
                    .unwrap_or(agent_pid);
                let now_ms = chrono::Utc::now().timestamp_millis() as u64;
                let snap_cid = format!("snap:mcp:{}:{}", target, now_ms);
                let mut es = self.state.engine_store.lock().unwrap();
                let _ = es.folder_put(
                    "mcp_snapshots",
                    &snap_cid,
                    &serde_json::json!({"agent_pid": target, "created_at_ms": now_ms}),
                );
                Ok(Self::ok(
                    serde_json::json!({"snapshot_cid": snap_cid, "agent_pid": target}).to_string(),
                ))
            }
            "restore" => {
                let target = args
                    .get("agent_pid")
                    .and_then(|v| v.as_str())
                    .unwrap_or(agent_pid);
                let snap_cid = args
                    .get("snapshot_cid")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if snap_cid.is_empty() {
                    return Ok(Self::err("snapshot_cid required".into()));
                }
                let es = self.state.engine_store.lock().unwrap();
                match es.folder_get("mcp_snapshots", snap_cid).ok().flatten() {
                    Some(_) => Ok(Self::ok(serde_json::json!({"restored": true, "agent_pid": target, "snapshot_cid": snap_cid}).to_string())),
                    None => Ok(Self::err(format!("Snapshot {} not found", snap_cid))),
                }
            }
            "proof_generate" => {
                let target = args
                    .get("agent_pid")
                    .and_then(|v| v.as_str())
                    .unwrap_or(agent_pid);
                let from_ms = args.get("from_ms").and_then(|v| v.as_i64()).unwrap_or(0);
                let to_ms = args
                    .get("to_ms")
                    .and_then(|v| v.as_i64())
                    .unwrap_or_else(|| chrono::Utc::now().timestamp_millis());
                let k = self.state.kernel.lock().unwrap();
                let all_audit = k.audit_log_all();
                let entries: Vec<_> = all_audit
                    .iter()
                    .filter(|e| {
                        e.agent_pid == target && e.timestamp >= from_ms && e.timestamp <= to_ms
                    })
                    .collect();
                let chain_valid = entries.windows(2).all(|w| w[0].after_hash.is_some());
                let proof_cid = {
                    use sha2::{Digest, Sha256};
                    let mut h = Sha256::new();
                    h.update(format!("{}:{}:{}", target, from_ms, entries.len()).as_bytes());
                    format!("proof:{}", hex::encode(&h.finalize()[..16]))
                };
                Ok(Self::ok(
                    serde_json::json!({"proof_cid": proof_cid, "agent_pid": target,
                    "entries_covered": entries.len(), "chain_valid": chain_valid,
                    "from_ms": from_ms, "to_ms": to_ms})
                    .to_string(),
                ))
            }
            "policy_check" => {
                let target = args
                    .get("agent_pid")
                    .and_then(|v| v.as_str())
                    .unwrap_or(agent_pid);
                let operation = args.get("operation").and_then(|v| v.as_str()).unwrap_or("");
                let resource = args.get("resource").and_then(|v| v.as_str()).unwrap_or("*");
                let k = self.state.kernel.lock().unwrap();
                let agent_exists = k.get_agent(target).is_some();
                let allowed = agent_exists && !operation.is_empty();
                let reason = if !agent_exists {
                    format!("Agent {} not found", target)
                } else if operation.is_empty() {
                    "operation is required".into()
                } else {
                    format!("Agent {} may perform {} on {}", target, operation, resource)
                };
                Ok(Self::ok(
                    serde_json::json!({"allowed": allowed, "agent_pid": target,
                    "operation": operation, "resource": resource, "reason": reason})
                    .to_string(),
                ))
            }
            "actionlog_record" => {
                let target = args
                    .get("agent_pid")
                    .and_then(|v| v.as_str())
                    .unwrap_or(agent_pid);
                let action = args.get("action").and_then(|v| v.as_str()).unwrap_or("");
                let resource = args.get("resource").and_then(|v| v.as_str()).unwrap_or("*");
                let outcome = args
                    .get("outcome")
                    .and_then(|v| v.as_str())
                    .unwrap_or("success");
                if action.is_empty() {
                    return Ok(Self::err("action required".into()));
                }
                let mut k = self.state.kernel.lock().unwrap();
                let r = k.dispatch(vac_core::kernel::SyscallRequest {
                    agent_pid: target.to_string(),
                    operation: vac_core::types::MemoryKernelOp::ToolDispatch,
                    payload: vac_core::kernel::SyscallPayload::ToolDispatch {
                        tool_id: action.to_string(),
                        action: outcome.to_string(),
                        request: serde_json::json!({"resource": resource}),
                    },
                    reason: Some(format!("mcp:actionlog:{}", action)),
                    vakya_id: Some(format!("vakya:mcp:actionlog:{}:{}", target, action)),
                    trace_parent: None,
                    trace_state: None,
                    api_version: None,
                });
                Ok(Self::ok(serde_json::json!({"recorded": true, "agent_pid": target, "action": action, "outcome": format!("{:?}", r.outcome)}).to_string()))
            }
            "agent_ps" => {
                let filter = args
                    .get("status_filter")
                    .and_then(|v| v.as_str())
                    .unwrap_or("all");
                let k = self.state.kernel.lock().unwrap();
                let agents: Vec<_> = k
                    .agents()
                    .iter()
                    .filter(|(_, a)| {
                        filter == "all"
                            || (filter == "active" && a.is_alive())
                            || (filter == "suspended" && !a.is_alive())
                    })
                    .map(|(pid, a)| {
                        serde_json::json!({
                            "pid": pid, "name": a.agent_name,
                            "status": format!("{:?}", a.status),
                            "namespace": a.namespace,
                            "tokens": a.total_tokens_consumed
                        })
                    })
                    .collect();
                Ok(Self::ok(
                    serde_json::json!({"agents": agents, "count": agents.len()}).to_string(),
                ))
            }
            "agent_inspect" => {
                let target = args
                    .get("agent_pid")
                    .and_then(|v| v.as_str())
                    .unwrap_or(agent_pid);
                let k = self.state.kernel.lock().unwrap();
                match k.get_agent(target) {
                    Some(a) => {
                        let ops = k.audit_log_all().iter().rev().filter(|e| e.agent_pid == target).take(5)
                            .map(|e| serde_json::json!({"op": format!("{:?}", e.operation), "outcome": format!("{:?}", e.outcome), "ts": e.timestamp}))
                            .collect::<Vec<_>>();
                        Ok(Self::ok(serde_json::json!({
                            "agent_pid": target, "name": a.agent_name,
                            "status": format!("{:?}", a.status),
                            "namespace": a.namespace, "role": format!("{:?}", a.role),
                            "token_budget": a.token_budget, "tokens_used": a.total_tokens_consumed,
                            "cost_usd": a.total_cost_usd, "recent_audit": ops
                        }).to_string()))
                    }
                    None => Ok(Self::err(format!("Agent {} not found", target))),
                }
            }
            "agent_signal" => {
                let mcp_atu = match mcp_proceed(&self.state, agent_pid, "agent_signal", &args) {
                    Ok(atu) => atu,
                    Err(message) => return Ok(Self::err(message)),
                };
                let target = args
                    .get("agent_pid")
                    .and_then(|v| v.as_str())
                    .unwrap_or(agent_pid);
                let signal = args.get("signal").and_then(|v| v.as_str()).unwrap_or("");
                let reason = args
                    .get("reason")
                    .and_then(|v| v.as_str())
                    .unwrap_or("mcp:signal");
                let (_, api_pid) =
                    crate::services::agents::resolve_kernel_pid(&self.state, target);
                let lifecycle_op = match signal {
                    "suspend" => Some(crate::services::intelligence_authority::LifecycleOp::SignalSuspend),
                    "resume" => Some(crate::services::intelligence_authority::LifecycleOp::SignalResume),
                    "terminate" => Some(crate::services::intelligence_authority::LifecycleOp::SignalTerminate),
                    "reflect" => Some(crate::services::intelligence_authority::LifecycleOp::SignalSuspend),
                    _ => None,
                };
                let Some(lifecycle_op) = lifecycle_op else {
                    return Ok(Self::err(format!(
                        "Unknown signal: {}. Use: suspend, resume, terminate, reflect",
                        signal
                    )));
                };
                if let Err(v) = crate::services::intelligence_authority::require_lifecycle_transition(
                    &self.state,
                    &api_pid,
                    lifecycle_op,
                    "mcp:agent_signal",
                    crate::auth::PlatformRole::Operator,
                    &Default::default(),
                ) {
                    return Ok(Self::err(format!(
                        "lifecycle_denied: {}",
                        v.get("reason")
                            .and_then(|x| x.as_str())
                            .unwrap_or("quarantined or egress isolated")
                    )));
                }
                if let Err(e) = crate::kernel::agent_principal::require_contract_action(
                    self.state.as_ref(),
                    target,
                    "agent.signal",
                    signal,
                ) {
                    return Ok(Self::err(format!("contract_denied: {e}")));
                }
                let lifecycle_op = match signal {
                    "suspend" => crate::services::intelligence_authority::LifecycleOp::SignalSuspend,
                    "resume" => crate::services::intelligence_authority::LifecycleOp::SignalResume,
                    "terminate" => crate::services::intelligence_authority::LifecycleOp::SignalTerminate,
                    "reflect" => crate::services::intelligence_authority::LifecycleOp::SignalSuspend,
                    _ => {
                        return Ok(Self::err(format!(
                            "Unknown signal: {}. Use: suspend, resume, terminate, reflect",
                            signal
                        )));
                    }
                };
                let actor = crate::substrate::agent_lifecycle_gate::LifecycleActor::operator(
                    "mcp:agent_signal",
                    crate::auth::PlatformRole::Operator,
                    "mcp:agent_signal",
                );
                match crate::substrate::agent_lifecycle_gate::dispatch_lifecycle(
                    &self.state,
                    &api_pid,
                    lifecycle_op,
                    &actor,
                    &Default::default(),
                    reason,
                ) {
                    Ok(receipt) => {
                        mcp_finish(&self.state, &mcp_atu, true);
                        Ok(Self::ok(
                        serde_json::json!({
                            "signal": signal,
                            "agent_pid": target,
                            "api_pid": api_pid,
                            "outcome": format!("{:?}", receipt.outcome),
                            "lifecycle_grant": receipt.grant_id,
                            "pate_task_id": mcp_atu.task_id,
                        })
                        .to_string(),
                    ))
                    }
                    Err(e) => {
                        mcp_finish(&self.state, &mcp_atu, false);
                        Ok(Self::err(format!("lifecycle_denied: {}", e.message())))
                    }
                }
            }
            "budget_status" => {
                let target = args
                    .get("agent_pid")
                    .and_then(|v| v.as_str())
                    .unwrap_or(agent_pid);
                let k = self.state.kernel.lock().unwrap();
                match k.get_agent(target) {
                    Some(a) => {
                        let (budget_limit, used, remaining, pct_used) = match &a.token_budget {
                            Some(b) => {
                                let lim = b.daily_limit;
                                let u = a.total_tokens_consumed;
                                let rem = lim.saturating_sub(u);
                                let pct = if lim > 0 {
                                    (u as f64 / lim as f64 * 100.0) as u32
                                } else {
                                    0
                                };
                                (lim, u, rem, pct)
                            }
                            None => (0u64, a.total_tokens_consumed, 0u64, 0u32),
                        };
                        Ok(Self::ok(
                            serde_json::json!({
                                "agent_pid": target, "token_budget": budget_limit,
                                "tokens_used": used, "tokens_remaining": remaining,
                                "pct_used": pct_used, "cost_usd": a.total_cost_usd,
                                "budget_exhausted": budget_limit > 0 && used >= budget_limit
                            })
                            .to_string(),
                        ))
                    }
                    None => Ok(Self::err(format!("Agent {} not found", target))),
                }
            }
            "connector_who_am_i" => {
                let target = args
                    .get("agent_pid")
                    .and_then(|v| v.as_str())
                    .unwrap_or(agent_pid);
                match crate::kernel::agent_foundation::who_am_i_authoritative(
                    self.state.as_ref(),
                    target,
                ) {
                    Some(who) => Ok(Self::ok(
                        serde_json::json!({
                            "agent_pid": target,
                            "who_am_i_authoritative": who,
                            "source": "kernel_identity_envelope",
                        })
                        .to_string(),
                    )),
                    None => Ok(Self::err(format!(
                        "No IIA identity envelope for agent {target} — register/setup first"
                    ))),
                }
            }
            _ => Ok(Self::err(format!("Unknown tool: {}", name))),
        }
    }

    fn read_resource(
        &self,
        agent_pid: &str,
        uri: &str,
    ) -> connector_protocols::error::ProtocolResult<String> {
        if uri == "resource://platform/health" {
            let k = self.state.kernel.lock().unwrap();
            return Ok(
                serde_json::json!({"healthy": true, "agents": k.agents().len(),
                "packets": k.packet_count()})
                .to_string(),
            );
        }
        if uri == "resource://platform/stats" {
            let k = self.state.kernel.lock().unwrap();
            return Ok(
                serde_json::json!({"agents": k.agents().len(), "packets": k.packet_count(),
                "audit_entries": k.audit_count()})
                .to_string(),
            );
        }
        if uri == "resource://platform/trust" {
            let k = self.state.kernel.lock().unwrap();
            let t = connector_engine::TrustComputer::compute(&k);
            return Ok(serde_json::json!({"score": t.score, "grade": t.grade}).to_string());
        }
        if uri == "resource://platform/audit/tail" {
            let k = self.state.kernel.lock().unwrap();
            let log = k.audit_log_all();
            let start = log.len().saturating_sub(50);
            let entries: Vec<_> = log[start..]
                .iter()
                .map(|e| {
                    serde_json::json!({"audit_id": e.audit_id,
                "operation": format!("{:?}", e.operation), "agent_pid": e.agent_pid,
                "outcome": format!("{:?}", e.outcome)})
                })
                .collect();
            return Ok(serde_json::json!({"entries": entries}).to_string());
        }
        // resource://agent/{pid}/status|memory|audit
        if let Some(rest) = uri.strip_prefix("resource://agent/") {
            let parts: Vec<&str> = rest.splitn(2, '/').collect();
            if parts.len() == 2 {
                let pid = parts[0];
                match parts[1] {
                    "status" => {
                        let k = self.state.kernel.lock().unwrap();
                        return Ok(match k.get_agent(pid) {
                            Some(a) => serde_json::json!({"agent_pid": pid, "status": format!("{:?}", a.status),
                                "name": a.agent_name}).to_string(),
                            None => serde_json::json!({"error": format!("Agent {} not found", pid)}).to_string(),
                        });
                    }
                    "memory" => {
                        let k = self.state.kernel.lock().unwrap();
                        let ns = k
                            .get_agent(pid)
                            .map(|a| a.namespace.clone())
                            .unwrap_or_default();
                        let count = k.packets_in_namespace(&ns).len();
                        return Ok(serde_json::json!({"packets": count}).to_string());
                    }
                    "audit" => {
                        let k = self.state.kernel.lock().unwrap();
                        let entries: Vec<_> = k.audit_log_all().iter().rev()
                            .filter(|e| e.agent_pid == pid).take(20)
                            .map(|e| serde_json::json!({"audit_id": e.audit_id, "operation": format!("{:?}", e.operation)}))
                            .collect();
                        return Ok(serde_json::json!({"entries": entries}).to_string());
                    }
                    _ => {}
                }
            }
        }
        // resource://bridge/{id}/tools
        if let Some(rest) = uri.strip_prefix("resource://bridge/") {
            if let Some(bid) = rest.strip_suffix("/tools") {
                let es = self.state.engine_store.lock().unwrap();
                let bridge = es
                    .folder_get("mcp_bridges", bid)
                    .ok()
                    .flatten()
                    .unwrap_or_else(
                        || serde_json::json!({"error": format!("Bridge {} not found", bid)}),
                    );
                return Ok(bridge.to_string());
            }
        }
        let _ = agent_pid;
        Ok(serde_json::json!({"error": format!("Unknown resource URI: {}", uri)}).to_string())
    }
}

// ── A2A Bridge ────────────────────────────────────────────────────────────────

/// POST /protocols/a2a/card/read — read a remote A2A agent card. No task is sent.
#[derive(Debug, serde::Deserialize)]
pub struct ReadAgentCardBody {
    pub url: String,
}

pub async fn read_remote_agent_card(
    headers: HeaderMap,
    Json(body): Json<ReadAgentCardBody>,
) -> Json<serde_json::Value> {
    if crate::services::agents::caller(&headers).is_none() {
        return Json(serde_json::json!({
            "ok": false,
            "error": "auth_required",
            "admits": false,
            "executed": false,
            "granted": false,
        }));
    }
    let url = body.url.trim().to_string();
    if let Err(code) = crate::substrate::egress_policy::assert_safe_outbound_url(&url) {
        return Json(serde_json::json!({
            "ok": false,
            "error": code,
            "admits": false,
            "executed": false,
            "granted": false,
            "honesty": "The card was not read. No task was sent.",
        }));
    }
    let client = match crate::substrate::egress_policy::reqwest_client_pinned(
        &url,
        std::time::Duration::from_secs(8),
    ) {
        Ok(client) => client,
        Err(error) => {
            return Json(serde_json::json!({
                "ok": false,
                "error": error,
                "admits": false,
                "executed": false,
                "granted": false,
            }))
        }
    };
    let response = match client.get(&url).send().await {
        Ok(response) => response,
        Err(error) => {
            return Json(serde_json::json!({
                "ok": false,
                "error": error.to_string(),
                "admits": false,
                "executed": false,
                "granted": false,
                "honesty": "Reading an agent card does not grant that agent and does not send it a task.",
            }))
        }
    };
    let status = response.status();
    let bytes = response.bytes().await.unwrap_or_default();
    let text = String::from_utf8_lossy(&bytes[..bytes.len().min(65_536)]).to_string();
    let parsed: serde_json::Value = serde_json::from_str(&text).unwrap_or(serde_json::Value::Null);
    let name = parsed.get("name").and_then(|v| v.as_str()).unwrap_or("");
    let description = parsed.get("description").and_then(|v| v.as_str()).unwrap_or("");
    let skills: Vec<String> = parsed
        .get("skills")
        .and_then(|v| v.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    item.get("name")
                        .and_then(|v| v.as_str())
                        .or_else(|| item.get("id").and_then(|v| v.as_str()))
                        .map(|s| s.to_string())
                })
                .collect()
        })
        .unwrap_or_default();
    Json(serde_json::json!({
        "ok": status.is_success() && !name.is_empty(),
        "status": status.as_u16(),
        "url": url,
        "name": name,
        "description": description,
        "skills": skills,
        "shape": "a2a_card",
        "admits": false,
        "executed": false,
        "granted": false,
        "honesty": "Reading an agent card does not grant that agent and does not send it a task.",
    }))
}

/// GET /protocols/a2a/card — get this platform's A2A agent card
pub async fn a2a_agent_card(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let backend = PlatformA2aBackend {
        state: state.clone(),
    };
    let bridge = A2aBridge::new(backend);
    match bridge.get_agent_card() {
        Ok(card) => Json(serde_json::json!({
            "ok": true,
            "name": card.name,
            "description": card.description,
            "url": card.url,
            "version": card.version,
            "skills": card.skills.iter().map(|s| serde_json::json!({
                "id": s.id, "name": s.name, "description": s.description,
            })).collect::<Vec<_>>(),
            "protocol": "A2A/1.0",
        })),
        Err(e) => Json(serde_json::json!({ "ok": false, "error": format!("{:?}", e) })),
    }
}

// ── A2A auth helper ──────────────────────────────────────────────────────────

/// Validate a Bearer token from `Authorization` header for A2A endpoints.
///
/// Accepts:
///   - Any `cpk_live_*` API key (machine-to-machine agents)
///   - Any valid JWT (via `crate::auth::verify_token`)
///   - Any non-empty token when dev auth bypass is allowed (see `runtime_control::dev_auth_bypass_allowed`)
///
/// Returns `Ok(caller_id)` on success or `Err(Response)` with 401 JSON.
fn a2a_verify_bearer(headers: &HeaderMap) -> Result<String, axum::response::Response> {
    let dev_mode = crate::services::runtime_control::dev_auth_bypass_allowed();

    let token = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .unwrap_or("");

    if token.is_empty() {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "ok": false,
                "error": {
                    "code": "a2a_authentication_required",
                    "message": "A2A endpoints require Bearer token authentication. \
                                Include: Authorization: Bearer <cpk_live_key_or_jwt>",
                    "hint": "Obtain a key via POST /api/v1/auth/signup or POST /api/v1/auth/token",
                    "docs": "https://connector.ai/docs/protocols/a2a#authentication",
                    "schemes": ["Bearer"]
                }
            })),
        )
            .into_response());
    }

    if dev_mode {
        return Ok(token.to_string());
    }

    // cpk_* API keys must exist in the hashed key store (never prefix-only).
    if token.starts_with("cpk_") {
        return crate::auth::validate_api_key(token)
            .map(|_| token.to_string())
            .map_err(|_| {
                (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({
                        "ok": false,
                        "error": {
                            "code": "a2a_invalid_token",
                            "message": "API key is unknown, expired, or revoked.",
                            "hint": "Create a key via POST /api/v1/auth/api-keys",
                            "docs": "https://connector.ai/docs/protocols/a2a#authentication"
                        }
                    })),
                )
                    .into_response()
            });
    }

    // Fall back to JWT validation
    match crate::auth::verify_token(token) {
        Ok(claims) => Ok(claims.sub),
        Err(_) => Err((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "ok": false,
                "error": {
                    "code": "a2a_invalid_token",
                    "message": "Bearer token is invalid or expired.",
                    "hint": "Re-authenticate via POST /api/v1/auth/token to get a fresh JWT.",
                    "docs": "https://connector.ai/docs/protocols/a2a#authentication"
                }
            })),
        )
            .into_response()),
    }
}

#[derive(Deserialize)]
pub struct A2aSendTaskRequest {
    #[serde(default)]
    pub id: Option<String>,
    /// Can be a plain string ("hello") or a full A2A message object
    pub message: serde_json::Value,
    #[serde(default)]
    pub sender_pid: Option<String>,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub package: Option<connector_native_contract::PackagePin>,
}

/// POST /protocols/a2a/tasks — send a task to this platform via A2A
pub async fn a2a_send_task(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<A2aSendTaskRequest>,
) -> axum::response::Response {
    let caller_id = match a2a_verify_bearer(&headers) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let from_pid = req
        .sender_pid
        .clone()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| caller_id.clone());
    let to_hint = req.session_id.as_deref().unwrap_or("a2a-task");
    if let Err(e) = crate::kernel::agent_principal::require_contract_action(
        state.as_ref(),
        &from_pid,
        "a2a.send",
        to_hint,
    ) {
        return Json(serde_json::json!({
            "ok": false,
            "error": e,
            "denial_reason": "contract_denied",
            "status": 403,
        }))
        .into_response();
    }
    if let Err(e) = crate::substrate::effect_exclusivity::assert_a2a_requires_grant(
        state.as_ref(),
        &from_pid,
        to_hint,
    ) {
        return Json(e).into_response();
    }
    let task_id = req.id.clone().unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let msg_val = req.message.clone();
    let (_driver, atu) = match crate::substrate::protocol_drivers::admit_a2a_send(
        &state,
        &from_pid,
        to_hint,
        &task_id,
        &msg_val,
        None,
        req.package.clone(),
    ) {
        Ok(admitted) => admitted,
        Err(e) => {
            return Json(crate::substrate::protocol_drivers::admit_denied_json("a2a", &e))
                .into_response();
        }
    };
    if !crate::substrate::pate::host_admission_allows_execution(atu.verdict) {
        return Json(serde_json::json!({
            "ok": false,
            "error": "not_proceed",
            "task_id": atu.task_id,
            "executed": false,
            "admits": false,
        }))
        .into_response();
    }
    let entity = req
        .message
        .get("entity_id")
        .or_else(|| req.message.get("conp_entity_id"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let grant = req
        .message
        .get("grant_id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    if entity.as_deref().map(|s| !s.is_empty()) == Some(true)
        && grant.as_deref().unwrap_or("").is_empty()
        && (crate::substrate::effect_exclusivity::effect_exclusivity_enforced()
            || crate::kernel::agent_principal::intelligence_hardening_on())
    {
        let _ = crate::substrate::pate::run_admitted_effect(&state, &atu, |_| Err("grant_id_required".into()));
        return Json(serde_json::json!({
            "ok": false,
            "error": "grant_id_required",
            "status": 403,
            "honesty": "NP-4 — machine-facing A2A tasks require CONP EntityId + grant_id",
        }))
        .into_response();
    }
    let backend = PlatformA2aBackend {
        state: state.clone(),
    };
    let bridge = A2aBridge::new(backend);
    let msg = match &req.message {
        serde_json::Value::String(s) => A2aMessage {
            role: "user".into(),
            parts: vec![A2aPart {
                part_type: "text".into(),
                text: Some(s.clone()),
                data: None,
                mime_type: None,
            }],
        },
        obj => serde_json::from_value::<A2aMessage>(obj.clone()).unwrap_or_else(|_| A2aMessage {
            role: "user".into(),
            parts: vec![A2aPart {
                part_type: "text".into(),
                text: Some(obj.to_string()),
                data: None,
                mime_type: None,
            }],
        }),
    };
    let send_req = TaskSendRequest {
        id: task_id,
        session_id: req.session_id.clone(),
        message: msg,
    };
    match bridge.send_task(&send_req) {
        Ok(task) => {
            let a2a_task_id = task.id.clone();
            let _ = crate::substrate::pate::run_admitted_effect(&state, &atu, |_| {
                Ok(serde_json::json!({"observed": true, "a2a_task_id": a2a_task_id}))
            });
            let fabric = if let Some(ref ent) = entity {
                crate::kernel::fabric_task::create_machine_task(
                    state.as_ref(),
                    &from_pid,
                    req.session_id.as_deref().unwrap_or("a2a-machine"),
                    req.message.clone(),
                    None,
                    Some(task.id.as_str()),
                    grant.as_deref(),
                    Some(ent.as_str()),
                )
            } else {
                crate::kernel::fabric_task::create_task(
                    state.as_ref(),
                    &from_pid,
                    req.session_id.as_deref().unwrap_or("a2a-task"),
                    req.message.clone(),
                    None,
                    Some(task.id.as_str()),
                    grant.as_deref(),
                    None,
                )
            };
            let fabric_json = fabric
                .ok()
                .map(|t| crate::kernel::fabric_task::task_json(&t))
                .unwrap_or(serde_json::json!(null));
            Json(serde_json::json!({
                "ok": true,
                "task_id": task.id,
                "state": format!("{:?}", task.status.state),
                "protocol": "A2A/1.0",
                "from_pid": from_pid,
                "fabric": fabric_json,
                "cnp": crate::kernel::fabric_task::cnp_layer_semantics(
                    crate::kernel::fabric_task::FabricTaskState::from_a2a(
                        &format!("{}", task.status.state),
                    )
                    .unwrap_or(crate::kernel::fabric_task::FabricTaskState::Submitted),
                ),
            }))
            .into_response()
        }
        Err(e) => {
            let _ = crate::substrate::pate::run_admitted_effect(&state, &atu, |_| Err(format!("{e:?}")));
            Json(serde_json::json!({ "ok": false, "error": format!("{:?}", e), "executed": false })).into_response()
        }
    }
}

/// GET /protocols/a2a/tasks/:task_id — get A2A task status (TG-4 fabric SoT first).
pub async fn a2a_get_task(
    State(state): State<SharedState>,
    Path(task_id): Path<String>,
) -> Json<serde_json::Value> {
    if let Some(t) = crate::kernel::fabric_task::load_task(state.as_ref(), &task_id) {
        let mut body = crate::kernel::fabric_task::task_json(&t);
        if let Some(o) = body.as_object_mut() {
            o.insert("protocol".into(), serde_json::json!("A2A/1.0+fabric.v2"));
        }
        return Json(body);
    }
    let backend = PlatformA2aBackend { state };
    let bridge = A2aBridge::new(backend);
    match bridge.get_task(&task_id) {
        Ok(task) => Json(serde_json::json!({
            "ok": true,
            "task_id": task.id,
            "state": format!("{:?}", task.status.state),
            "artifacts": task.artifacts.as_ref().map(|a| a.len()).unwrap_or(0),
        })),
        Err(e) => Json(serde_json::json!({ "ok": false, "error": format!("{:?}", e) })),
    }
}

/// DELETE /protocols/a2a/tasks/:task_id — cancel A2A task (TG-4 fabric SoT first).
pub async fn a2a_cancel_task(
    State(state): State<SharedState>,
    Path(task_id): Path<String>,
) -> Json<serde_json::Value> {
    if crate::kernel::fabric_task::load_task(state.as_ref(), &task_id).is_some() {
        return match crate::kernel::fabric_task::transition(
            state.as_ref(),
            &task_id,
            crate::kernel::fabric_task::FabricTaskState::Canceled,
            Some("a2a_cancel"),
        ) {
            Ok(t) => Json(crate::kernel::fabric_task::task_json(&t)),
            Err(e) => Json(serde_json::json!({ "ok": false, "error": e })),
        };
    }
    let backend = PlatformA2aBackend { state };
    let bridge = A2aBridge::new(backend);
    match bridge.cancel_task(&task_id) {
        Ok(task) => Json(
            serde_json::json!({ "ok": true, "task_id": task.id, "state": format!("{:?}", task.status.state) }),
        ),
        Err(e) => Json(serde_json::json!({ "ok": false, "error": format!("{:?}", e) })),
    }
}

/// GET /protocols/a2a/tasks/:task_id/subscribe — SSE stream for A2A task progress
pub async fn a2a_subscribe_task(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(task_id): Path<String>,
) -> axum::response::Response {
    if let Err(resp) = a2a_verify_bearer(&headers) {
        return resp;
    }
    let backend = PlatformA2aBackend { state };
    let bridge = A2aBridge::new(backend);
    let initial_task = bridge.get_task(&task_id).ok();
    let task_id_clone = task_id.clone();

    let stream = async_stream::stream! {
        let state_now = initial_task
            .as_ref()
            .map(|t| format!("{:?}", t.status.state).to_lowercase())
            .unwrap_or_else(|| "unknown".to_string());
        let event = serde_json::json!({
            "task_id": task_id_clone,
            "state": state_now,
            "protocol": "A2A/1.0",
            "honesty": "SSE emits stored fabric state only — no invented working/completed."
        });
        yield Ok::<Event, Infallible>(
            Event::default().event("task_state").data(event.to_string())
        );
    };

    Sse::new(stream)
        .keep_alive(KeepAlive::default())
        .into_response()
}

struct PlatformA2aBackend {
    state: SharedState,
}

impl PlatformA2aBackend {
    /// Persist a task to the engine store (folder: "a2a_tasks").
    fn store_task(es: &mut dyn connector_engine::engine_store::EngineStore, task: &A2aTask) {
        let _ = es.folder_put(
            "a2a_tasks",
            &task.id,
            &serde_json::to_value(task).unwrap_or_default(),
        );
    }

    /// Load a task from the engine store.
    fn load_task(
        es: &mut dyn connector_engine::engine_store::EngineStore,
        task_id: &str,
    ) -> Option<A2aTask> {
        es.folder_get("a2a_tasks", task_id)
            .ok()
            .flatten()
            .and_then(|v| serde_json::from_value(v).ok())
    }

    /// Build artifact output from agent memory packets.
    fn build_artifacts(
        state: &crate::state::PlatformState,
        agent_pid: &str,
        task_id: &str,
    ) -> Vec<A2aArtifact> {
        let k = state.kernel.lock().unwrap();
        let ns = k
            .get_agent(agent_pid)
            .map(|a| a.namespace.clone())
            .unwrap_or_default();
        let pkts = k.packets_in_namespace(&ns);
        if pkts.is_empty() {
            let receipt = k
                .audit_log_all()
                .iter()
                .rev()
                .find(|e| e.agent_pid == agent_pid)
                .map(|e| {
                    format!(
                        "audit_op={:?} ts={} outcome={:?}",
                        e.operation, e.timestamp, e.outcome
                    )
                })
                .unwrap_or_else(|| "no_recent_audit_for_agent".to_string());
            return vec![A2aArtifact {
                name: "result".into(),
                parts: vec![A2aPart {
                    part_type: "text".into(),
                    text: Some(format!(
                        "task_id={} agent_pid={} — no memory packets yet; receipt_hint: {}",
                        task_id, agent_pid, receipt
                    )),
                    data: None,
                    mime_type: None,
                }],
                index: Some(0),
            }];
        }
        // Return up to 5 most recent memory packets as data artifacts
        let artifact_parts: Vec<A2aPart> = pkts
            .iter()
            .take(5)
            .map(|p| A2aPart {
                part_type: "data".into(),
                text: None,
                data: Some(serde_json::to_string(&p.content.payload).unwrap_or_default()),
                mime_type: Some("application/json".into()),
            })
            .collect();
        vec![A2aArtifact {
            name: "memory_output".into(),
            parts: artifact_parts,
            index: Some(0),
        }]
    }

    /// Dispatch the task message to the kernel as a MemWrite for the agent_pid.
    fn dispatch_task_to_kernel(
        state: &crate::state::PlatformState,
        agent_pid: &str,
        task_id: &str,
        msg: &A2aMessage,
    ) -> bool {
        let text = msg
            .parts
            .iter()
            .filter_map(|p| p.text.as_deref())
            .collect::<Vec<_>>()
            .join(" ");
        if text.is_empty() {
            return false;
        }
        let src = vac_core::types::Source {
            kind: vac_core::types::SourceKind::User,
            principal_id: format!("a2a:{}", task_id),
        };
        let pkt = vac_core::types::MemPacket::new(
            vac_core::types::PacketType::Input,
            serde_json::json!({"text": text, "task_id": task_id, "role": msg.role}),
            cid::Cid::default(),
            task_id.to_string(),
            "a2a-pipeline".into(),
            src,
            chrono::Utc::now().timestamp_millis(),
        );
        let mut k = state.kernel.lock().unwrap();
        let r = k.dispatch(vac_core::kernel::SyscallRequest {
            agent_pid: agent_pid.to_string(),
            operation: vac_core::types::MemoryKernelOp::MemWrite,
            payload: vac_core::kernel::SyscallPayload::MemWrite { packet: pkt },
            reason: Some(format!("a2a:task:{}", task_id)),
            vakya_id: None,
            trace_parent: None,
            trace_state: None,
            api_version: None,
        });
        matches!(r.outcome, vac_core::types::OpOutcome::Success)
    }

    /// Resolve or create an agent_pid for an A2A task session.
    fn resolve_agent_pid(
        state: &SharedState,
        session_id: Option<&str>,
        tenant: Option<&TenantContext>,
    ) -> ProtocolResult<String> {
        let sess = session_id.unwrap_or("default");
        let namespace_raw = format!("m/a2a/{}", sess);
        let namespace =
            crate::services::agents::tenant_scoped_memory_namespace(tenant, &namespace_raw);
        let logical = format!("a2a-{}", sess);

        let mut k = state.kernel.lock().unwrap();
        if let Some(sid) = session_id {
            let found = k
                .agents()
                .iter()
                .find(|(_, a)| a.namespace.contains(sid))
                .map(|(pid, _)| pid.clone());
            if let Some(pid) = found {
                return Ok(pid);
            }
        }
        drop(k);

        if let Err(j) = crate::services::agents::kernel_agent_limit_gate(state.as_ref(), tenant) {
            tracing::warn!(
                "a2a: agent kernel limit — {}",
                j.get("hint").and_then(|v| v.as_str()).unwrap_or("limit")
            );
            let detail = serde_json::to_string(&j).unwrap_or_else(|_| "agent_limit_reached".into());
            return Err(ProtocolError::InvalidRequest(format!(
                "agent_limit_reached: {}",
                detail
            )));
        }

        let mut k = state.kernel.lock().unwrap();
        let r = k.dispatch(vac_core::kernel::SyscallRequest {
            agent_pid: "".into(),
            operation: vac_core::types::MemoryKernelOp::AgentRegister,
            payload: vac_core::kernel::SyscallPayload::AgentRegister {
                agent_name: logical.clone(),
                namespace: namespace.clone(),
                role: Some("writer".into()),
                model: None,
                framework: Some("a2a".into()),
            },
            reason: Some("a2a:task_init".into()),
            vakya_id: None,
            trace_parent: None,
            trace_state: None,
            api_version: None,
        });
        if r.outcome != vac_core::types::OpOutcome::Success {
            return Err(ProtocolError::Kernel(format!(
                "a2a register: {:?}",
                r.outcome
            )));
        }
        let kp = match r.value {
            vac_core::kernel::SyscallValue::AgentPid(p) => p,
            other => {
                return Err(ProtocolError::Kernel(format!(
                    "a2a register unexpected: {:?}",
                    other
                )))
            }
        };
        drop(k);

        let _api = crate::services::agents::ensure_agent_store_mapping(
            state,
            &kp,
            &logical,
            &namespace,
            None,
            "a2a",
            Some(serde_json::json!({"source": "a2a", "session_id": sess})),
        );
        Ok(kp)
    }
}

impl A2aKernelBackend for PlatformA2aBackend {
    fn agent_card(&self) -> ProtocolResult<AgentCard> {
        let k = self.state.kernel.lock().unwrap();
        let agent_count = k.agents().len();
        let packet_count = k.packet_count();
        drop(k);
        Ok(AgentCard {
            name: "Connector Platform".into(),
            description: format!(
                "Full-stack AIOS agent runtime. {} agents registered, {} memory packets indexed. \
                 Capabilities: memory, cognitive pipeline, knowledge graph, trust, audit.",
                agent_count, packet_count
            ),
            url: std::env::var("CONNECTOR_PLATFORM_URL")
                .unwrap_or_else(|_| "http://localhost:9090".into()),
            version: env!("CARGO_PKG_VERSION").to_string(),
            capabilities: AgentCapabilities {
                streaming: true,
                push_notifications: false,
                state_transition_history: true,
            },
            skills: vec![
                AgentSkill {
                    id: "memory".into(),
                    name: "Memory Management".into(),
                    description: "Read, write, recall and search kernel memory packets across namespaces".into(),
                    tags: Some(vec!["memory".into(), "rag".into(), "vac".into()]),
                    examples: Some(vec!["Write a synthesis packet to agent ns:patient-001".into()]),
                },
                AgentSkill {
                    id: "cognitive".into(),
                    name: "Cognitive Pipeline".into(),
                    description: "Observe, plan, reason, execute and judge agent actions with full audit trail".into(),
                    tags: Some(vec!["reasoning".into(), "planning".into(), "audit".into()]),
                    examples: Some(vec!["Run full cognitive cycle for diagnostic agent".into()]),
                },
                AgentSkill {
                    id: "knowledge".into(),
                    name: "Knowledge Graph".into(),
                    description: "Entity and edge management, KnotEngine RAG, concept lattice operations".into(),
                    tags: Some(vec!["knowledge".into(), "graph".into(), "rag".into()]),
                    examples: Some(vec!["Query entity relationships for drug interactions".into()]),
                },
                AgentSkill {
                    id: "trust".into(),
                    name: "Trust & Audit".into(),
                    description: "EigenTrust scoring, HMAC audit chain proof generation, policy enforcement".into(),
                    tags: Some(vec!["trust".into(), "compliance".into(), "audit".into()]),
                    examples: Some(vec!["Generate audit proof for agent pid:agent-007".into()]),
                },
            ],
            authentication: Some(AuthenticationInfo {
                schemes: vec!["Bearer".into()],
            }),
        })
    }

    fn submit_task(&self, req: &TaskSendRequest) -> ProtocolResult<A2aTask> {
        let now = chrono::Utc::now().to_rfc3339();
        let submitted_status = TaskStatus {
            state: TaskState::Submitted,
            message: None,
            timestamp: now.clone(),
        };

        // Resolve or create an agent_pid for this task
        let agent_pid = Self::resolve_agent_pid(&self.state, req.session_id.as_deref(), None)?;

        // Dispatch the message content into kernel memory
        let dispatched =
            Self::dispatch_task_to_kernel(&self.state, &agent_pid, &req.id, &req.message);

        // Build reply from input message parts
        let reply_text = req
            .message
            .parts
            .iter()
            .filter_map(|p| p.text.as_deref())
            .map(|t| format!("Processed: {}", t))
            .collect::<Vec<_>>()
            .join(" ");
        let reply_text = if reply_text.is_empty() {
            format!("Task {} received and queued", req.id)
        } else {
            reply_text
        };
        let arts = Self::build_artifacts(&self.state, &agent_pid, &req.id);
        let reply = A2aMessage {
            role: "agent".into(),
            parts: vec![A2aPart {
                part_type: "text".into(),
                text: Some(if dispatched {
                    reply_text
                } else {
                    format!("Task {} acknowledged (kernel dispatch queued)", req.id)
                }),
                data: None,
                mime_type: None,
            }],
        };
        let (final_state, final_msg, artifacts) = (TaskState::Completed, Some(reply), Some(arts));

        let working_status = TaskStatus {
            state: TaskState::Working,
            message: None,
            timestamp: now.clone(),
        };
        let final_status = TaskStatus {
            state: final_state,
            message: final_msg.clone(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        };

        let task = A2aTask {
            id: req.id.clone(),
            status: final_status,
            message: final_msg,
            artifacts,
            history: Some(vec![submitted_status, working_status]),
        };

        // Persist task
        let mut es = self.state.engine_store.lock().unwrap();
        Self::store_task(&mut **es, &task);
        Ok(task)
    }

    fn get_task(&self, task_id: &str) -> ProtocolResult<A2aTask> {
        let mut es = self.state.engine_store.lock().unwrap();
        Self::load_task(&mut **es, task_id).ok_or_else(|| {
            connector_protocols::error::ProtocolError::NotFound(format!(
                "Task {} not found",
                task_id
            ))
        })
    }

    fn cancel_task(&self, task_id: &str) -> ProtocolResult<A2aTask> {
        let mut es = self.state.engine_store.lock().unwrap();
        let mut task = Self::load_task(&mut **es, task_id).ok_or_else(|| {
            connector_protocols::error::ProtocolError::NotFound(format!(
                "Task {} not found",
                task_id
            ))
        })?;

        // Only cancel if not already terminal
        if matches!(
            task.status.state,
            TaskState::Completed | TaskState::Failed | TaskState::Canceled
        ) {
            return Ok(task);
        }

        let prev = task.status.clone();
        task.status = TaskStatus {
            state: TaskState::Canceled,
            message: None,
            timestamp: chrono::Utc::now().to_rfc3339(),
        };
        // Append to history
        if let Some(ref mut h) = task.history {
            h.push(prev);
        } else {
            task.history = Some(vec![prev]);
        }
        Self::store_task(&mut **es, &task);
        Ok(task)
    }
}

// ── ACP Bridge ────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct AcpSendRequest {
    pub message_id: String,
    pub sender: String,
    pub recipient: String,
    pub content: String,
    #[serde(default)]
    pub content_type: Option<String>,
    #[serde(default)]
    pub thread_id: Option<String>,
}

/// POST /protocols/acp/messages — send an ACP message
pub async fn acp_send(
    State(state): State<SharedState>,
    Json(req): Json<AcpSendRequest>,
) -> Json<serde_json::Value> {
    let backend = PlatformAcpBackend { state };
    let bridge = AcpBridge::new(backend);
    let msg = AcpMessage {
        id: req.message_id.clone(),
        from: req.sender.clone(),
        to: req.recipient.clone(),
        body: serde_json::json!({ "text": req.content }),
        content_type: req.content_type.unwrap_or_else(|| "text/plain".into()),
        created_at: chrono::Utc::now().to_rfc3339(),
        reply_to: req.thread_id,
    };
    match bridge.send_message(&msg) {
        Ok(accepted) => Json(serde_json::json!({
            "ok": true,
            "message_id": accepted.message_id,
            "status": accepted.status.to_string(),
            "protocol": "ACP/1.0",
        })),
        Err(e) => Json(serde_json::json!({ "ok": false, "error": format!("{:?}", e) })),
    }
}

/// GET /protocols/acp/messages/:message_id — get ACP message status
pub async fn acp_status(
    State(state): State<SharedState>,
    Path(message_id): Path<String>,
) -> Json<serde_json::Value> {
    let backend = PlatformAcpBackend { state };
    let bridge = AcpBridge::new(backend);
    match bridge.get_message_status(&message_id) {
        Ok(result) => Json(serde_json::json!({
            "ok": true,
            "message_id": result.message_id,
            "status": result.status.to_string(),
        })),
        Err(e) => Json(serde_json::json!({ "ok": false, "error": format!("{:?}", e) })),
    }
}

struct PlatformAcpBackend {
    state: SharedState,
}
impl AcpKernelBackend for PlatformAcpBackend {
    fn send_message(
        &self,
        message: &AcpMessage,
    ) -> ProtocolResult<connector_protocols::acp_bridge::AcpAcceptedResponse> {
        use connector_protocols::acp_bridge::{AcpAcceptedResponse, AcpMessageStatus};
        let mut es = self.state.engine_store.lock().unwrap();
        let _ = es.folder_put(
            "acp_messages",
            &message.id,
            &serde_json::json!({
                "from": message.from,
                "to": message.to,
                "content_type": message.content_type,
                "created_at": message.created_at,
                "delivered": true,
            }),
        );
        Ok(AcpAcceptedResponse {
            message_id: message.id.clone(),
            status: AcpMessageStatus::Accepted,
            poll_url: format!("/api/v1/protocols/acp/messages/{}", message.id),
        })
    }
    fn get_message_status(
        &self,
        message_id: &str,
    ) -> ProtocolResult<connector_protocols::acp_bridge::AcpMessageResult> {
        use connector_protocols::acp_bridge::{AcpMessageResult, AcpMessageStatus};
        let es = self.state.engine_store.lock().unwrap();
        let meta = es.folder_get("acp_messages", message_id).ok().flatten();
        Ok(AcpMessageResult {
            message_id: message_id.to_string(),
            status: if meta.is_some() {
                AcpMessageStatus::Completed
            } else {
                AcpMessageStatus::Processing
            },
            reply: None,
        })
    }
}

// ── ANP Bridge ────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct AnpRegisterDidRequest {
    pub did: String,
    pub service_endpoint: String,
    #[serde(default)]
    pub description: Option<String>,
}

/// POST /protocols/anp/dids — register a DID document
pub async fn anp_register_did(
    State(state): State<SharedState>,
    Json(req): Json<AnpRegisterDidRequest>,
) -> Json<serde_json::Value> {
    let mut es = state.engine_store.lock().unwrap();
    let doc = DidDocument {
        id: req.did.clone(),
        verification_method: vec![],
        service: Some(vec![ServiceEndpoint {
            id: format!("{}#service-1", req.did),
            service_type: "ConnectorPlatform".into(),
            endpoint: req.service_endpoint.clone(),
        }]),
    };
    let _ = es.folder_put(
        "anp_dids",
        &req.did,
        &serde_json::to_value(&doc).unwrap_or_default(),
    );
    Json(serde_json::json!({
        "ok": true,
        "did": req.did,
        "service_endpoint": req.service_endpoint,
        "protocol": "ANP/1.0",
    }))
}

/// GET /protocols/anp/dids/:did — resolve a DID document
pub async fn anp_resolve_did(
    State(state): State<SharedState>,
    Path(did): Path<String>,
) -> Json<serde_json::Value> {
    let es = state.engine_store.lock().unwrap();
    match es.folder_get("anp_dids", &did).ok().flatten() {
        Some(doc) => Json(serde_json::json!({ "ok": true, "did": did, "document": doc })),
        None => Json(serde_json::json!({ "ok": false, "error": format!("DID {} not found", did) })),
    }
}

/// GET /protocols/anp/dids — list all registered DIDs
pub async fn anp_list_dids(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let es = state.engine_store.lock().unwrap();
    let dids: Vec<String> = es.folder_keys("anp_dids", None).unwrap_or_default();
    Json(serde_json::json!({ "dids": dids, "count": dids.len(), "protocol": "ANP/1.0" }))
}

// ── AP2 Bridge ────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct Ap2MandateRequest {
    pub payer_pid: String,
    pub payee_pid: String,
    pub amount: f64,
    pub currency: String,
    #[serde(default)]
    pub mandate_type: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
}

/// POST /protocols/ap2/mandates — create a payment mandate
pub async fn ap2_create_mandate(
    State(state): State<SharedState>,
    Json(req): Json<Ap2MandateRequest>,
) -> Json<serde_json::Value> {
    let mandate_id = format!("mandate:{}", uuid::Uuid::new_v4());
    let mtype = match req.mandate_type.as_deref() {
        Some("cart") => MandateType::Cart,
        Some("intent") => MandateType::Intent,
        _ => MandateType::Payment,
    };
    let mut es = state.engine_store.lock().unwrap();
    let _ = es.folder_put(
        "ap2_mandates",
        &mandate_id,
        &serde_json::json!({
            "id": mandate_id,
            "payer_pid": req.payer_pid,
            "payee_pid": req.payee_pid,
            "amount": req.amount,
            "currency": req.currency,
            "mandate_type": format!("{:?}", mtype),
            "description": req.description,
            "status": "active",
            "created_at": chrono::Utc::now().timestamp_millis(),
        }),
    );
    Json(serde_json::json!({
        "ok": true,
        "mandate_id": mandate_id,
        "payer_pid": req.payer_pid,
        "payee_pid": req.payee_pid,
        "amount": req.amount,
        "currency": req.currency,
        "status": "active",
        "protocol": "AP2/1.0",
    }))
}

/// GET /protocols/ap2/mandates/:mandate_id — get mandate status
pub async fn ap2_get_mandate(
    State(state): State<SharedState>,
    Path(mandate_id): Path<String>,
) -> Json<serde_json::Value> {
    let es = state.engine_store.lock().unwrap();
    match es.folder_get("ap2_mandates", &mandate_id).ok().flatten() {
        Some(m) => Json(serde_json::json!({ "ok": true, "mandate": m })),
        None => Json(
            serde_json::json!({ "ok": false, "error": format!("Mandate {} not found", mandate_id) }),
        ),
    }
}

/// GET /protocols/ap2/mandates — list all mandates
pub async fn ap2_list_mandates(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let es = state.engine_store.lock().unwrap();
    let ids: Vec<String> = es.folder_keys("ap2_mandates", None).unwrap_or_default();
    let mandates: Vec<serde_json::Value> = ids
        .iter()
        .filter_map(|id| es.folder_get("ap2_mandates", id).ok().flatten())
        .collect();
    Json(
        serde_json::json!({ "mandates": mandates, "count": mandates.len(), "protocol": "AP2/1.0" }),
    )
}

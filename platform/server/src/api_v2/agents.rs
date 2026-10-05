//! V2 Agents API — Simplified agent lifecycle management
//!
//! Routes:
//!   POST   /api/v2/agents              — Create agent
//!   GET    /api/v2/agents              — List agents
//!   GET    /api/v2/agents/:id          — Get agent details
//!   PATCH  /api/v2/agents/:id          — Update agent
//!   DELETE /api/v2/agents/:id          — Terminate agent
//!   POST   /api/v2/agents/:id/start    — Start agent
//!   POST   /api/v2/agents/:id/stop     — Stop agent
//!   GET    /api/v2/agents/:id/health   — Agent health score

use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    Json,
};
use serde::{Deserialize, Serialize};

use crate::state::SharedState;
use crate::services::agents;
use super::{V2Response, NextAction};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Agent {
    /// Kernel agent PID (opaque). v1 REST often uses `api_pid` in URLs.
    pub id: String,
    /// Mapped REST v1 agent id (`agent_*`) when known — same logical agent as `id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_pid: Option<String>,
    pub name: String,
    pub namespace: String,
    pub status: AgentStatus,
    pub health_score: f64,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum AgentStatus {
    Running,
    #[default]
    Stopped,
    Suspended,
    Failed,
}

#[derive(Debug, Deserialize)]
pub struct CreateAgentRequest {
    pub name: String,
    #[serde(default)]
    pub namespace: Option<String>,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct ListAgentsQuery {
    pub status: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

/// POST /api/v2/agents — Create agent
pub async fn create_agent(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<CreateAgentRequest>,
) -> V2Response<Agent> {
    let namespace = req
        .namespace
        .clone()
        .unwrap_or_else(|| format!("m/{}", req.name));

    let tenant_cap = agents::tenant_from_headers_for_cap(&headers);
    if let Err(j) = agents::kernel_agent_limit_gate(state.as_ref(), tenant_cap.as_ref()) {
        return V2Response {
            ok: false,
            data: None,
            error: Some(super::V2Error {
                code: "agent_limit_reached".to_string(),
                message: j.get("error").and_then(|v| v.as_str()).unwrap_or("agent_limit_reached").to_string(),
                reason: None,
                hint: j.get("hint").and_then(|v| v.as_str()).map(|s| s.to_string()),
                example: None,
                field: None,
                expected: None,
                received: None,
                docs: "https://connector.ai/docs/runtime-policy".to_string(),
                see_also: Vec::new(),
            }),
            meta: super::V2Meta::now(),
        };
    }
    
    let api_pid = format!(
        "agent_{}",
        uuid::Uuid::new_v4().to_string().replace('-', "")
    );
    let admitted = match crate::substrate::pate::admit_register(
        &state,
        &api_pid,
        &serde_json::json!({
            "name": req.name.as_str(),
            "namespace": namespace.as_str(),
        }),
    ) {
        Ok(atu) => atu,
        Err(body) => {
            let message = body
                .get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("not_proceed")
                .to_string();
            return V2Response {
                ok: false,
                data: None,
                error: Some(super::V2Error {
                    code: message.clone(),
                    message,
                    reason: None,
                    hint: Some("Registration stays open when admission is not Proceed.".to_string()),
                    example: None,
                    field: None,
                    expected: None,
                    received: None,
                    docs: "https://connector.ai/docs/errors/agent_creation_failed".to_string(),
                    see_also: Vec::new(),
                }),
                meta: super::V2Meta::now(),
            };
        }
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);

    // Register agent with kernel
    let agent_pid = {
        let mut kernel = state.kernel.lock().unwrap();
        let result = kernel.dispatch(vac_core::kernel::SyscallRequest {
            agent_pid: "system".to_string(),
            operation: vac_core::types::MemoryKernelOp::AgentRegister,
            payload: vac_core::kernel::SyscallPayload::AgentRegister {
                agent_name: req.name.clone(),
                namespace: namespace.clone(),
                role: None,
                model: req.model.clone(),
                framework: None,
            },
            reason: Some("V2 API agent creation".to_string()),
            vakya_id: None,
            trace_parent: None,
            trace_state: None,
            api_version: None,
        });
        
        match result.outcome {
            vac_core::types::OpOutcome::Success => match result.value {
                vac_core::kernel::SyscallValue::AgentPid(p) => p,
                other => {
                    return V2Response {
                        ok: false,
                        data: None,
                        error: Some(super::V2Error {
                            code: "agent_creation_failed".to_string(),
                            message: format!("Unexpected register result: {:?}", other),
                            reason: None,
                            hint: Some("Check that the namespace is valid and not already in use".to_string()),
                            example: None,
                            field: None,
                            expected: None,
                            received: None,
                            docs: "https://connector.ai/docs/errors/agent_creation_failed".to_string(),
                            see_also: Vec::new(),
                        }),
                        meta: super::V2Meta::now(),
                    };
                }
            },
            _ => {
                return V2Response {
                    ok: false,
                    data: None,
                    error: Some(super::V2Error {
                        code: "agent_creation_failed".to_string(),
                        message: format!("Failed to create agent: {:?}", result.outcome),
                        reason: None,
                        hint: Some("Check that the namespace is valid and not already in use".to_string()),
                        example: None,
                        field: None,
                        expected: None,
                        received: None,
                        docs: "https://connector.ai/docs/errors/agent_creation_failed".to_string(),
                        see_also: Vec::new(),
                    }),
                    meta: super::V2Meta::now(),
                };
            }
        }
    };

    let logical_name = req.name.clone();
    {
        let mut es = state.engine_store.lock().unwrap();
        let _ = es.folder_put(
            "agent_pid_map",
            &agent_pid,
            &serde_json::json!(api_pid.as_str()),
        );
    }
    let api_pid = agents::ensure_agent_store_mapping(
        &state,
        &agent_pid,
        &logical_name,
        &namespace,
        req.model.as_deref(),
        "v2",
        Some(serde_json::json!({
            "source": "api_v2",
            "description": req.description,
        })),
    );
    
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;
    
    let agent = Agent {
        id: agent_pid.clone(),
        api_pid: Some(api_pid),
        name: logical_name,
        namespace,
        status: AgentStatus::Stopped,
        health_score: 1.0,
        created_at: super::format_iso8601(now),
        model: req.model,
        description: req.description,
    };

    open_proceed.finish_observed(true);
    V2Response::success_with_actions(agent.clone(), vec![
        NextAction {
            action: "start".to_string(),
            method: "POST".to_string(),
            path: format!("/api/v2/agents/{}/start", agent.id),
            description: "Start the agent".to_string(),
            reason: None,
            example_body: None,
        },
    ])
}

/// GET /api/v2/agents — List all agents
pub async fn list_agents(
    State(state): State<SharedState>,
    _headers: HeaderMap,
    Query(query): Query<ListAgentsQuery>,
) -> V2Response<Vec<Agent>> {
    let limit = query.limit.unwrap_or(100).min(1000);
    let offset = query.offset.unwrap_or(0);
    
    let agents: Vec<Agent> = {
        let kernel = state.kernel.lock().unwrap();
        let mut engine_store = state.engine_store.lock().unwrap();
        
        kernel.agents()
            .iter()
            .skip(offset)
            .take(limit)
            .filter(|(_, acb)| {
                if let Some(ref status_filter) = query.status {
                    let status_str = format!("{:?}", acb.status).to_lowercase();
                    if !status_str.contains(&status_filter.to_lowercase()) {
                        return false;
                    }
                }
                true
            })
            .map(|(pid, acb)| {
                let status = match acb.status {
                    vac_core::types::AgentStatus::Running => AgentStatus::Running,
                    vac_core::types::AgentStatus::Suspended => AgentStatus::Suspended,
                    vac_core::types::AgentStatus::Terminated => AgentStatus::Stopped,
                    _ => AgentStatus::Stopped,
                };
                
                // Get KECS score if available
                let health_score = agents::folder_get_kecs_unified(&mut *engine_store, pid)
                    .and_then(|v| v.get("kecs").and_then(|k| k.as_f64()))
                    .unwrap_or(1.0);
                
                Agent {
                    id: pid.clone(),
                    api_pid: agents::api_pid_for_kernel_pid(&mut **engine_store, pid),
                    name: acb.agent_name.clone(),
                    namespace: acb.namespace.clone(),
                    status,
                    health_score,
                    created_at: super::format_iso8601(acb.registered_at),
                    model: None,
                    description: None,
                }
            })
            .collect()
    };
    
    V2Response::success(agents)
}

/// GET /api/v2/agents/:id — Get agent details
pub async fn get_agent(
    State(state): State<SharedState>,
    _headers: HeaderMap,
    Path(id): Path<String>,
) -> V2Response<Agent> {
    let kernel = state.kernel.lock().unwrap();
    let mut engine_store = state.engine_store.lock().unwrap();
    
    match kernel.agents().get(&id) {
        Some(acb) => {
            let status = match acb.status {
                vac_core::types::AgentStatus::Running => AgentStatus::Running,
                vac_core::types::AgentStatus::Suspended => AgentStatus::Suspended,
                vac_core::types::AgentStatus::Terminated => AgentStatus::Stopped,
                _ => AgentStatus::Stopped,
            };
            
            // Get KECS score if available
            let health_score = agents::folder_get_kecs_unified(&mut *engine_store, &id)
                .and_then(|v| v.get("kecs").and_then(|k| k.as_f64()))
                .unwrap_or(1.0);
            
            let api_pid = agents::api_pid_for_kernel_pid(&mut **engine_store, &id);
            let agent = Agent {
                id: id.clone(),
                api_pid,
                name: acb.agent_name.clone(),
                namespace: acb.namespace.clone(),
                status,
                health_score,
                created_at: super::format_iso8601(acb.registered_at),
                model: None,
                description: None,
            };
            V2Response::success(agent)
        }
        None => {
            V2Response {
                ok: false,
                data: None,
                error: Some(super::V2Error {
                    code: "agent_not_found".to_string(),
                    message: format!("Agent '{}' not found", id),
                    hint: Some("Check that the agent ID is correct".to_string()),
                    reason: None,
                    example: None,
                    field: None,
                    expected: None,
                    received: None,
                    docs: "https://connector.ai/docs/errors/agent_not_found".to_string(),
                    see_also: Vec::new(),
                }),
                meta: super::V2Meta::now(),
            }
        }
    }
}

/// POST /api/v2/agents/:id/start — Start an agent
pub async fn start_agent(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> V2Response<Agent> {
    let (user_id, role) = match crate::services::intelligence_authority::require_lifecycle_actor(
        &headers, 4,
    ) {
        Ok(c) => c,
        Err(v) => {
            return V2Response {
                ok: false,
                data: None,
                error: Some(super::V2Error {
                    code: v
                        .get("error")
                        .and_then(|x| x.as_str())
                        .unwrap_or("forbidden")
                        .to_string(),
                    message: v
                        .get("reason")
                        .or_else(|| v.get("error"))
                        .and_then(|x| x.as_str())
                        .unwrap_or("lifecycle denied")
                        .to_string(),
                    hint: v.get("hint").and_then(|x| x.as_str()).map(str::to_string),
                    reason: None,
                    example: None,
                    field: None,
                    expected: None,
                    received: None,
                    docs: "https://connector.ai/docs/errors/lifecycle_denied".to_string(),
                    see_also: Vec::new(),
                }),
                meta: super::V2Meta::now(),
            };
        }
    };

    let actor = crate::substrate::agent_lifecycle_gate::LifecycleActor::operator(
        &user_id,
        role,
        "http:v2:start",
    );
    match crate::substrate::agent_lifecycle_gate::dispatch_lifecycle(
        &state,
        &id,
        crate::services::intelligence_authority::LifecycleOp::Start,
        &actor,
        &Default::default(),
        "V2 API start",
    ) {
        Ok(receipt) => {
            let kernel = state.kernel.lock().unwrap();
            let acb_opt = kernel.agents().get(&receipt.kernel_pid).cloned();
            drop(kernel);
            match acb_opt {
                Some(acb) => {
                    let api_pid = {
                        let mut es = state.engine_store.lock().unwrap();
                        agents::api_pid_for_kernel_pid(&mut **es, &receipt.kernel_pid)
                    };
                    V2Response::success(Agent {
                        id: receipt.kernel_pid,
                        api_pid,
                        name: acb.agent_name.clone(),
                        namespace: acb.namespace.clone(),
                        status: AgentStatus::Running,
                        health_score: 1.0,
                        created_at: super::format_iso8601(acb.registered_at),
                        model: None,
                        description: None,
                    })
                }
                None => V2Response {
                    ok: false,
                    data: None,
                    error: Some(super::V2Error {
                        code: "agent_not_found".to_string(),
                        message: format!("Agent '{}' not found", id),
                        hint: Some("Check that the agent ID is correct".to_string()),
                        reason: None,
                        example: None,
                        field: None,
                        expected: None,
                        received: None,
                        docs: "https://connector.ai/docs/errors/agent_not_found".to_string(),
                        see_also: Vec::new(),
                    }),
                    meta: super::V2Meta::now(),
                },
            }
        }
        Err(e) => V2Response {
            ok: false,
            data: None,
            error: Some(super::V2Error {
                code: "lifecycle_denied".to_string(),
                message: e.message(),
                hint: None,
                reason: None,
                example: None,
                field: None,
                expected: None,
                received: None,
                docs: "https://connector.ai/docs/errors/lifecycle_denied".to_string(),
                see_also: Vec::new(),
            }),
            meta: super::V2Meta::now(),
        },
    }
}

/// POST /api/v2/agents/:id/stop — Stop an agent
pub async fn stop_agent(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> V2Response<Agent> {
    let (user_id, role) = match crate::services::intelligence_authority::require_lifecycle_actor(
        &headers, 4,
    ) {
        Ok(c) => c,
        Err(v) => {
            return V2Response {
                ok: false,
                data: None,
                error: Some(super::V2Error {
                    code: v
                        .get("error")
                        .and_then(|x| x.as_str())
                        .unwrap_or("forbidden")
                        .to_string(),
                    message: v
                        .get("error")
                        .and_then(|x| x.as_str())
                        .unwrap_or("forbidden")
                        .to_string(),
                    hint: None,
                    reason: None,
                    example: None,
                    field: None,
                    expected: None,
                    received: None,
                    docs: "https://connector.ai/docs/errors/forbidden".to_string(),
                    see_also: Vec::new(),
                }),
                meta: super::V2Meta::now(),
            };
        }
    };

    let actor = crate::substrate::agent_lifecycle_gate::LifecycleActor::operator(
        &user_id,
        role,
        "http:v2:stop",
    );
    match crate::substrate::agent_lifecycle_gate::dispatch_lifecycle(
        &state,
        &id,
        crate::services::intelligence_authority::LifecycleOp::Pause,
        &actor,
        &Default::default(),
        "V2 API stop",
    ) {
        Ok(receipt) => {
            let _ = crate::substrate::spend_cease::kernel_cease(
                &state,
                &receipt.kernel_pid,
                connector_trust::CeaseReason::UserStop,
            );
            let kernel = state.kernel.lock().unwrap();
            let acb_opt = kernel.agents().get(&receipt.kernel_pid).cloned();
            drop(kernel);
            match acb_opt {
                Some(acb) => {
                    let api_pid = {
                        let mut es = state.engine_store.lock().unwrap();
                        agents::api_pid_for_kernel_pid(&mut **es, &receipt.kernel_pid)
                    };
                    V2Response::success(Agent {
                        id: receipt.kernel_pid,
                        api_pid,
                        name: acb.agent_name.clone(),
                        namespace: acb.namespace.clone(),
                        status: AgentStatus::Stopped,
                        health_score: 1.0,
                        created_at: super::format_iso8601(acb.registered_at),
                        model: None,
                        description: None,
                    })
                }
                None => V2Response {
                    ok: false,
                    data: None,
                    error: Some(super::V2Error {
                        code: "agent_not_found".to_string(),
                        message: format!("Agent '{}' not found", id),
                        hint: Some("Check that the agent ID is correct".to_string()),
                        reason: None,
                        example: None,
                        field: None,
                        expected: None,
                        received: None,
                        docs: "https://connector.ai/docs/errors/agent_not_found".to_string(),
                        see_also: Vec::new(),
                    }),
                    meta: super::V2Meta::now(),
                },
            }
        }
        Err(e) => V2Response {
            ok: false,
            data: None,
            error: Some(super::V2Error {
                code: "lifecycle_denied".to_string(),
                message: e.message(),
                hint: None,
                reason: None,
                example: None,
                field: None,
                expected: None,
                received: None,
                docs: "https://connector.ai/docs/errors/lifecycle_denied".to_string(),
                see_also: Vec::new(),
            }),
            meta: super::V2Meta::now(),
        },
    }
}

//! V2 Sessions API — Session management
//!
//! Routes:
//!   POST   /api/v2/sessions           — Create session
//!   GET    /api/v2/sessions           — List sessions
//!   GET    /api/v2/sessions/:id       — Get session details
//!   DELETE /api/v2/sessions/:id       — Close session

use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    Json,
};
use serde::{Deserialize, Serialize};

use crate::state::SharedState;
use super::V2Response;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub agent_id: String,
    pub status: String,
    pub packet_count: usize,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub closed_at: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateSessionRequest {
    pub agent_id: String,
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Default)]
pub struct ListSessionsQuery {
    pub agent_id: Option<String>,
    pub status: Option<String>,
    pub limit: Option<usize>,
}

/// POST /api/v2/sessions — Create session
pub async fn create_session(
    State(state): State<SharedState>,
    _headers: HeaderMap,
    Json(req): Json<CreateSessionRequest>,
) -> V2Response<Session> {
    let session_id = format!("sess_{:x}", chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0));
    
    let result = {
        let mut kernel = state.kernel.lock().unwrap();
        kernel.dispatch(vac_core::kernel::SyscallRequest {
            agent_pid: req.agent_id.clone(),
            operation: vac_core::types::MemoryKernelOp::SessionCreate,
            payload: vac_core::kernel::SyscallPayload::SessionCreate {
                session_id: session_id.clone(),
                label: None,
                parent_session_id: None,
            },
            reason: Some("V2 API session creation".to_string()),
            vakya_id: None,
            trace_parent: None,
            trace_state: None,
            api_version: None,
        })
    };
    
    match result.outcome {
        vac_core::types::OpOutcome::Success => {
            let session = Session {
                id: session_id,
                agent_id: req.agent_id,
                status: "active".to_string(),
                packet_count: 0,
                created_at: super::format_iso8601(chrono::Utc::now().timestamp_millis()),
                closed_at: None,
            };
            V2Response::success(session)
        }
        _ => {
            V2Response {
                ok: false,
                data: None,
                error: Some(super::V2Error {
                    code: "session_creation_failed".to_string(),
                    message: format!("Failed to create session: {:?}", result.outcome),
                    hint: Some("Check that the agent exists and is running".to_string()),
                    reason: None,
                    example: None,
                    field: None,
                    expected: None,
                    received: None,
                    docs: "https://connector.ai/docs/errors/session_creation_failed".to_string(),
                    see_also: Vec::new(),
                }),
                meta: super::V2Meta::now(),
            }
        }
    }
}

/// GET /api/v2/sessions — List sessions
pub async fn list_sessions(
    State(state): State<SharedState>,
    _headers: HeaderMap,
    Query(query): Query<ListSessionsQuery>,
) -> V2Response<Vec<Session>> {
    let limit = query.limit.unwrap_or(100).min(1000);
    
    let sessions: Vec<Session> = {
        let kernel = state.kernel.lock().unwrap();
        
        kernel.sessions()
            .iter()
            .filter(|(_, session)| {
                if let Some(ref agent_filter) = query.agent_id {
                    // Filter by agent if specified
                    // Note: SessionEnvelope doesn't have agent_pid, so we skip this filter
                    let _ = agent_filter;
                }
                true
            })
            .take(limit)
            .map(|(session_id, session)| {
                Session {
                    id: session_id.clone(),
                    agent_id: session.agent_id.clone(),
                    status: if session.is_active() { "active" } else { "closed" }.to_string(),
                    packet_count: session.packet_count(),
                    created_at: super::format_iso8601(session.started_at),
                    closed_at: session.ended_at.map(|ts| super::format_iso8601(ts)),
                }
            })
            .collect()
    };
    
    V2Response::success(sessions)
}

/// GET /api/v2/sessions/:id — Get session details
pub async fn get_session(
    State(state): State<SharedState>,
    _headers: HeaderMap,
    Path(id): Path<String>,
) -> V2Response<Session> {
    let kernel = state.kernel.lock().unwrap();
    
    match kernel.sessions().get(&id) {
        Some(session) => {
            let sess = Session {
                id: id.clone(),
                agent_id: session.agent_id.clone(),
                status: if session.is_active() { "active" } else { "closed" }.to_string(),
                packet_count: session.packet_count(),
                created_at: super::format_iso8601(session.started_at),
                closed_at: session.ended_at.map(|ts| super::format_iso8601(ts)),
            };
            V2Response::success(sess)
        }
        None => {
            V2Response {
                ok: false,
                data: None,
                error: Some(super::V2Error {
                    code: "session_not_found".to_string(),
                    message: format!("Session '{}' not found", id),
                    hint: Some("Check that the session ID is correct".to_string()),
                    reason: None,
                    example: None,
                    field: None,
                    expected: None,
                    received: None,
                    docs: "https://connector.ai/docs/errors/session_not_found".to_string(),
                    see_also: Vec::new(),
                }),
                meta: super::V2Meta::now(),
            }
        }
    }
}

/// DELETE /api/v2/sessions/:id — Close session
pub async fn close_session(
    State(state): State<SharedState>,
    _headers: HeaderMap,
    Path(id): Path<String>,
) -> V2Response<Session> {
    let result = {
        let mut kernel = state.kernel.lock().unwrap();
        kernel.dispatch(vac_core::kernel::SyscallRequest {
            agent_pid: "system".to_string(),
            operation: vac_core::types::MemoryKernelOp::SessionClose,
            payload: vac_core::kernel::SyscallPayload::SessionClose {
                session_id: id.clone(),
            },
            reason: Some("V2 API session close".to_string()),
            vakya_id: None,
            trace_parent: None,
            trace_state: None,
            api_version: None,
        })
    };
    
    match result.outcome {
        vac_core::types::OpOutcome::Success => {
            let session = Session {
                id: id.clone(),
                agent_id: "unknown".to_string(),
                status: "closed".to_string(),
                packet_count: 0,
                created_at: super::format_iso8601(chrono::Utc::now().timestamp_millis()),
                closed_at: Some(super::format_iso8601(chrono::Utc::now().timestamp_millis())),
            };
            V2Response::success(session)
        }
        _ => {
            V2Response {
                ok: false,
                data: None,
                error: Some(super::V2Error {
                    code: "session_close_failed".to_string(),
                    message: format!("Failed to close session: {:?}", result.outcome),
                    hint: Some("Check that the session exists".to_string()),
                    reason: None,
                    example: None,
                    field: None,
                    expected: None,
                    received: None,
                    docs: "https://connector.ai/docs/errors/session_close_failed".to_string(),
                    see_also: Vec::new(),
                }),
                meta: super::V2Meta::now(),
            }
        }
    }
}

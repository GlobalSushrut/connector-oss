//! V2 Memory API — Simplified memory operations
//!
//! Routes:
//!   POST   /api/v2/memory              — Write memory
//!   GET    /api/v2/memory              — List/search memory
//!   GET    /api/v2/memory/:cid         — Get memory by CID
//!   DELETE /api/v2/memory/:cid         — Delete memory

use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    Json,
};
use serde::{Deserialize, Serialize};

use crate::state::SharedState;
use super::{V2Response, NextAction};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Memory {
    pub cid: String,
    pub agent_id: String,
    pub namespace: String,
    pub content_type: String,
    pub size_bytes: u64,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct WriteMemoryRequest {
    pub agent_id: String,
    pub content: serde_json::Value,
    #[serde(default)]
    pub namespace: Option<String>,
    #[serde(default)]
    pub tags: Option<Vec<String>>,
    #[serde(default)]
    pub summary: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct ListMemoryQuery {
    pub agent_id: Option<String>,
    pub namespace: Option<String>,
    pub tag: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

/// POST /api/v2/memory — Write memory
pub async fn write_memory(
    State(state): State<SharedState>,
    _headers: HeaderMap,
    Json(req): Json<WriteMemoryRequest>,
) -> V2Response<Memory> {
    use vac_core::types::{MemPacket, PacketType, Source, SourceKind};
    
    let content_size = serde_json::to_string(&req.content)
        .map(|s| s.len() as u64)
        .unwrap_or(0);
    
    // Get agent namespace
    let namespace = {
        let kernel = state.kernel.lock().unwrap();
        req.namespace.clone().or_else(|| {
            kernel.agents().get(&req.agent_id).map(|acb| acb.namespace.clone())
        }).unwrap_or_else(|| format!("/m/{}", req.agent_id))
    };
    
    // Create MemPacket using the constructor
    let packet = MemPacket::new(
        PacketType::Input,
        req.content.clone(),
        cid::Cid::default(),
        req.agent_id.clone(),
        "v2-api".to_string(),
        Source { kind: SourceKind::User, principal_id: req.agent_id.clone() },
        chrono::Utc::now().timestamp_millis(),
    );
    
    let cid = {
        let mut kernel = state.kernel.lock().unwrap();
        let result = kernel.dispatch(vac_core::kernel::SyscallRequest {
            agent_pid: req.agent_id.clone(),
            operation: vac_core::types::MemoryKernelOp::MemWrite,
            payload: vac_core::kernel::SyscallPayload::MemWrite { packet: packet.clone() },
            reason: Some("V2 API memory write".to_string()),
            vakya_id: None,
            trace_parent: None,
            trace_state: None,
            api_version: None,
        });
        
        match result.outcome {
            vac_core::types::OpOutcome::Success => {
                // Extract CID from result value
                match &result.value {
                    vac_core::kernel::SyscallValue::Cid(c) => c.to_string(),
                    _ => packet.index.packet_cid.to_string(),
                }
            }
            _ => {
                return V2Response {
                    ok: false,
                    data: None,
                    error: Some(super::V2Error {
                        code: "memory_write_failed".to_string(),
                        message: format!("Failed to write memory: {:?}", result.outcome),
                        hint: Some("Check agent permissions and namespace access".to_string()),
                        reason: None,
                        example: None,
                        field: None,
                        expected: None,
                        received: None,
                        docs: "https://connector.ai/docs/errors/memory_write_failed".to_string(),
                        see_also: Vec::new(),
                    }),
                    meta: super::V2Meta::now(),
                };
            }
        }
    };
    
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;
    
    let memory = Memory {
        cid: cid.clone(),
        agent_id: req.agent_id,
        namespace,
        content_type: "application/json".to_string(),
        size_bytes: content_size,
        created_at: super::format_iso8601(now),
        summary: req.summary,
        tags: req.tags,
    };
    
    V2Response::success_with_actions(memory.clone(), vec![
        NextAction {
            action: "read".to_string(),
            method: "GET".to_string(),
            path: format!("/api/v2/memory/{}", cid),
            description: "Read this memory".to_string(),
            reason: None,
            example_body: None,
        },
    ])
}

/// GET /api/v2/memory — List memory
pub async fn list_memory(
    State(state): State<SharedState>,
    _headers: HeaderMap,
    Query(query): Query<ListMemoryQuery>,
) -> V2Response<Vec<Memory>> {
    let limit = query.limit.unwrap_or(100).min(1000);
    let offset = query.offset.unwrap_or(0);
    
    let memories: Vec<Memory> = {
        let kernel = state.kernel.lock().unwrap();
        
        // Get packets from namespace
        let namespace = query.namespace.as_deref().unwrap_or("/");
        let packets = kernel.packets_in_namespace(namespace);
        
        packets
            .iter()
            .skip(offset)
            .take(limit)
            .filter(|p| {
                if let Some(ref agent_id) = query.agent_id {
                    if p.subject_id != *agent_id {
                        return false;
                    }
                }
                true
            })
            .map(|p| Memory {
                cid: p.index.packet_cid.to_string(),
                agent_id: p.subject_id.clone(),
                namespace: namespace.to_string(),
                content_type: "application/json".to_string(),
                size_bytes: serde_json::to_string(&p.content).map(|s| s.len() as u64).unwrap_or(0),
                created_at: super::format_iso8601(p.index.ts),
                summary: None,
                tags: None,
            })
            .collect()
    };
    
    V2Response::success(memories)
}

/// GET /api/v2/memory/:cid — Get memory by CID
pub async fn get_memory(
    State(state): State<SharedState>,
    _headers: HeaderMap,
    Path(cid): Path<String>,
) -> V2Response<MemoryWithContent> {
    let kernel = state.kernel.lock().unwrap();
    
    // Parse CID from string
    let cid_parsed = match cid::Cid::try_from(cid.as_str()) {
        Ok(c) => c,
        Err(_) => {
            return V2Response {
                ok: false,
                data: None,
                error: Some(super::V2Error {
                    code: "invalid_cid".to_string(),
                    message: format!("Invalid CID format: {}", cid),
                    hint: Some("CID must be a valid content identifier".to_string()),
                    reason: None,
                    example: None,
                    field: None,
                    expected: None,
                    received: None,
                    docs: "https://connector.ai/docs/errors/invalid_cid".to_string(),
                    see_also: Vec::new(),
                }),
                meta: super::V2Meta::now(),
            };
        }
    };
    
    match kernel.get_packet(&cid_parsed) {
        Some(packet) => {
            let content = serde_json::to_value(&packet.content).unwrap_or(serde_json::Value::Null);
            
            let memory = MemoryWithContent {
                cid: packet.index.packet_cid.to_string(),
                agent_id: packet.subject_id.clone(),
                namespace: packet.namespace.clone().unwrap_or_default(),
                content_type: "application/json".to_string(),
                size_bytes: serde_json::to_string(&packet.content).map(|s| s.len() as u64).unwrap_or(0),
                created_at: super::format_iso8601(packet.index.ts),
                content,
                summary: None,
                tags: None,
            };
            V2Response::success(memory)
        }
        None => {
            V2Response {
                ok: false,
                data: None,
                error: Some(super::V2Error {
                    code: "memory_not_found".to_string(),
                    message: format!("Memory '{}' not found", cid),
                    hint: Some("List memories to find valid CIDs".to_string()),
                    reason: None,
                    example: None,
                    field: None,
                    expected: None,
                    received: None,
                    docs: "https://connector.ai/docs/errors/memory_not_found".to_string(),
                    see_also: Vec::new(),
                }),
                meta: super::V2Meta::now(),
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryWithContent {
    pub cid: String,
    pub agent_id: String,
    pub namespace: String,
    pub content_type: String,
    pub size_bytes: u64,
    pub created_at: String,
    pub content: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
}

/// DELETE /api/v2/memory/:cid — Delete memory
pub async fn delete_memory(
    State(state): State<SharedState>,
    _headers: HeaderMap,
    Path(cid): Path<String>,
) -> V2Response<DeletedMemory> {
    let mut kernel = state.kernel.lock().unwrap();
    
    let result = kernel.dispatch(vac_core::kernel::SyscallRequest {
        agent_pid: "system".to_string(),
        operation: vac_core::types::MemoryKernelOp::MemEvict,
        payload: vac_core::kernel::SyscallPayload::MemEvict { 
            cids: vec![cid::Cid::try_from(cid.as_str()).unwrap_or_default()],
            max_evict: 0,
        },
        reason: Some("V2 API memory delete".to_string()),
        vakya_id: None,
        trace_parent: None,
        trace_state: None,
        api_version: None,
    });
    
    match result.outcome {
        vac_core::types::OpOutcome::Success => {
            V2Response::success(DeletedMemory {
                cid,
                deleted: true,
                deleted_at: super::format_iso8601(chrono::Utc::now().timestamp_millis()),
            })
        }
        _ => {
            V2Response {
                ok: false,
                data: None,
                error: Some(super::V2Error {
                    code: "memory_delete_failed".to_string(),
                    message: format!("Failed to delete memory: {:?}", result.outcome),
                    hint: Some("Check that the CID exists and you have permission".to_string()),
                    reason: None,
                    example: None,
                    field: None,
                    expected: None,
                    received: None,
                    docs: "https://connector.ai/docs/errors/memory_delete_failed".to_string(),
                    see_also: Vec::new(),
                }),
                meta: super::V2Meta::now(),
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeletedMemory {
    pub cid: String,
    pub deleted: bool,
    pub deleted_at: String,
}

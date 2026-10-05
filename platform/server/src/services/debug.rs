use crate::auth;
use crate::error::error_response;
use crate::state::SharedState;
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};

/// Require admin or super_admin role; return 403 JSON envelope on failure.
fn require_admin(headers: &HeaderMap) -> Result<(), axum::response::Response> {
    if crate::services::runtime_control::dev_auth_bypass_allowed() {
        return Ok(());
    }
    let token = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .unwrap_or("");
    match auth::verify_token(token) {
        Ok(claims) => {
            let rank = auth::PlatformRole::from_str(&claims.role).rank();
            if rank >= auth::PlatformRole::Admin.rank() {
                Ok(())
            } else {
                Err(error_response(
                    StatusCode::FORBIDDEN,
                    "permission_denied",
                    "The /debug/* endpoints require admin role or higher.",
                ))
            }
        }
        Err(_) => Err(error_response(
            StatusCode::UNAUTHORIZED,
            "authentication_required",
            "Valid Bearer token required for /debug/* endpoints.",
        )),
    }
}

#[derive(Deserialize)]
pub struct ListQuery {
    #[serde(default = "default_limit")]
    pub limit: usize,
    #[serde(default)]
    pub offset: usize,
}
fn default_limit() -> usize {
    50
}
fn default_page() -> usize {
    1
}

#[derive(Deserialize, Default)]
pub struct SurfaceQueryParams {
    #[serde(default = "default_page")]
    pub page: usize,
    #[serde(default = "default_limit")]
    pub page_size: usize,
    #[serde(default)]
    pub filter: Vec<String>,
    #[serde(default)]
    pub search: Option<String>,
    #[serde(default)]
    pub sort: Vec<String>,
}

fn build_surface_query(params: &SurfaceQueryParams) -> Option<connector_engine::surface::Query> {
    use connector_engine::surface::{
        Filter, Query as SurfaceQuery, SearchQuery, Sort, SortDirection,
    };

    let explicit = params.page != 1
        || params.page_size != default_limit()
        || !params.filter.is_empty()
        || params.search.is_some()
        || !params.sort.is_empty();
    if !explicit {
        return None;
    }

    let mut query = SurfaceQuery::new().paginate(params.page.max(1), params.page_size.max(1));
    if let Some(search) = &params.search {
        query = query.search(SearchQuery::new(search));
    }
    for filter in &params.filter {
        if let Some(parsed) = Filter::parse(filter) {
            query = query.filter(parsed);
        }
    }
    for sort in &params.sort {
        let sort = sort.trim();
        let parsed = if let Some(field) = sort.strip_prefix('-') {
            Sort {
                field: field.to_string(),
                direction: SortDirection::Desc,
            }
        } else if let Some((field, direction)) = sort.split_once(':') {
            Sort {
                field: field.to_string(),
                direction: if direction.eq_ignore_ascii_case("desc") {
                    SortDirection::Desc
                } else {
                    SortDirection::Asc
                },
            }
        } else {
            Sort::asc(sort)
        };
        query = query.sort_by(parsed);
    }

    Some(query)
}

#[derive(Deserialize)]
pub struct AuditFilterQuery {
    #[serde(default = "default_limit")]
    pub limit: usize,
    #[serde(default)]
    pub agent_pid: Option<String>,
}

pub async fn list_sessions(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Query(q): Query<ListQuery>,
) -> impl IntoResponse {
    if let Err(r) = require_admin(&headers) {
        return r;
    }
    let k = state.kernel.lock().unwrap();
    let sessions: Vec<serde_json::Value> = k
        .sessions()
        .iter()
        .skip(q.offset)
        .take(q.limit)
        .map(|(id, env)| {
            serde_json::json!({
                "session_id": id,
                "type": env.type_,
                "version": env.version,
                "summary": env.summary,
                "total_tokens": env.total_tokens,
            })
        })
        .collect();
    Json(serde_json::json!({
        "count": sessions.len(),
        "sessions": sessions,
    }))
    .into_response()
}

pub async fn session_detail(
    State(state): State<SharedState>,
    Path(session_id): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let k = state.kernel.lock().unwrap();
    let packets: Vec<serde_json::Value> = k
        .packets_in_session(&session_id)
        .iter()
        .map(|p| {
            serde_json::json!({
                "cid": p.content.payload_cid.to_string(),
                "type": format!("{}", p.content.packet_type),
                "text": p.content.payload.get("text").and_then(|v| v.as_str()).unwrap_or(""),
                "tags": p.content.tags,
            })
        })
        .collect();
    Ok(Json(serde_json::json!({
        "session_id": session_id,
        "packets": packets,
        "count": packets.len(),
    })))
}

pub async fn audit_log(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Query(q): Query<AuditFilterQuery>,
) -> impl IntoResponse {
    if let Err(r) = require_admin(&headers) {
        return r;
    }
    let k = state.kernel.lock().unwrap();
    let entries: Vec<serde_json::Value> = k
        .audit_log()
        .iter()
        .rev()
        .filter(|e| q.agent_pid.as_ref().map_or(true, |pid| e.agent_pid == *pid))
        .take(q.limit)
        .map(|e| {
            serde_json::json!({
                "timestamp": e.timestamp,
                "operation": format!("{:?}", e.operation),
                "agent_pid": e.agent_pid,
                "outcome": format!("{:?}", e.outcome),
                "reason": e.reason,
                "target": e.target,
                "error": e.error,
            })
        })
        .collect();
    Json(serde_json::json!({
        "count": entries.len(),
        "entries": entries,
    }))
    .into_response()
}

pub async fn memory_recall(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(cid_str): Path<String>,
) -> impl IntoResponse {
    if let Err(r) = require_admin(&headers) {
        return r;
    }
    let k = state.kernel.lock().unwrap();
    // Search all namespaces for the CID
    for agent in k.agents().values() {
        let ns = format!("ns:{}", agent.agent_pid);
        for p in k.packets_in_namespace(&ns) {
            if p.content.payload_cid.to_string().contains(&cid_str) {
                return Json(serde_json::json!({
                    "found": true,
                    "cid": p.content.payload_cid.to_string(),
                    "type": format!("{}", p.content.packet_type),
                    "content": p.content.payload,
                    "namespace": ns,
                    "tags": p.content.tags,
                }))
                .into_response();
            }
        }
    }
    Json(serde_json::json!({"found": false, "cid": cid_str})).into_response()
}

/// Track 2 Phase B — Item B.4: List ToolBindings for agent
pub async fn agent_bindings(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(agent_pid): Path<String>,
) -> impl IntoResponse {
    if let Err(r) = require_admin(&headers) {
        return r;
    }
    let k = state.kernel.lock().unwrap();
    match k.get_agent(&agent_pid) {
        Some(acb) => {
            let bindings: Vec<serde_json::Value> = acb
                .tool_bindings
                .iter()
                .map(|tb| {
                    serde_json::json!({
                        "tool_id": &tb.tool_id,
                        "namespace_path": &tb.namespace_path,
                        "allowed_actions": &tb.allowed_actions,
                        "allowed_resources": &tb.allowed_resources,
                        "data_classification": &tb.data_classification,
                        "requires_approval": tb.requires_approval,
                    })
                })
                .collect();
            Json(serde_json::json!({
                "agent_pid": agent_pid,
                "tool_bindings": bindings.len(),
                "bindings": bindings,
            }))
            .into_response()
        }
        None => Json(
            serde_json::json!({"error": format!("Agent {} not found", agent_pid), "status": 404}),
        )
        .into_response(),
    }
}

/// Track 2 Phase B — Item B.5: View tool binding config for agent
pub async fn bind_tool(
    State(state): State<SharedState>,
    Path(agent_pid): Path<String>,
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let tool_id = req
        .get("tool_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let namespace_path = req
        .get("namespace_path")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let classification = req
        .get("data_classification")
        .and_then(|v| v.as_str())
        .unwrap_or("none")
        .to_string();
    let requires_approval = req
        .get("requires_approval")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let k = state.kernel.lock().unwrap();
    match k.get_agent(&agent_pid) {
        Some(acb) => {
            // Show proposed binding + current bindings
            Json(serde_json::json!({
                "agent_pid": agent_pid,
                "proposed_binding": {
                    "tool_id": tool_id,
                    "namespace_path": namespace_path,
                    "data_classification": classification,
                    "requires_approval": requires_approval,
                },
                "current_bindings": acb.tool_bindings.len(),
                "current_role": format!("{:?}", acb.role),
                "note": "Tool binding requires kernel-level agent re-registration with updated ACB",
            }))
        }
        None => Json(
            serde_json::json!({"error": format!("Agent {} not found", agent_pid), "status": 404}),
        ),
    }
}

/// Track 2 Phase B — Item B.6: View/describe AgentRole + ExecutionPolicy
pub async fn set_role(
    State(state): State<SharedState>,
    Path(agent_pid): Path<String>,
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let role_str = req.get("role").and_then(|v| v.as_str()).unwrap_or("reader");

    let k = state.kernel.lock().unwrap();
    match k.get_agent(&agent_pid) {
        Some(acb) => Json(serde_json::json!({
            "agent_pid": agent_pid,
            "current_role": format!("{:?}", acb.role),
            "requested_role": role_str,
            "available_roles": ["Reader", "Writer", "Admin", "ToolAgent", "Auditor", "Compactor"],
            "note": "Role change requires kernel-level agent re-registration",
        })),
        None => Json(
            serde_json::json!({"error": format!("Agent {} not found", agent_pid), "status": 404}),
        ),
    }
}

/// Wave 2 — Item 2.7: Per-agent access boundaries and permissions
pub async fn agent_permissions(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(agent_pid): Path<String>,
) -> impl IntoResponse {
    if let Err(r) = require_admin(&headers) {
        return r;
    }
    let k = state.kernel.lock().unwrap();
    match k.get_agent(&agent_pid) {
        Some(acb) => {
            let tool_bindings: Vec<serde_json::Value> = acb
                .tool_bindings
                .iter()
                .map(|tb| {
                    serde_json::json!({
                        "tool_id": &tb.tool_id,
                        "namespace_path": &tb.namespace_path,
                        "allowed_actions": &tb.allowed_actions,
                        "allowed_resources": &tb.allowed_resources,
                        "data_classification": &tb.data_classification,
                        "requires_approval": tb.requires_approval,
                        "rate_limit": tb.rate_limit.as_ref().map(|rl| serde_json::json!({
                            "max_per_second": rl.max_per_second,
                            "max_per_minute": rl.max_per_minute,
                            "max_burst": rl.max_burst,
                        })),
                    })
                })
                .collect();

            let mounts: Vec<serde_json::Value> = acb
                .namespace_mounts
                .iter()
                .map(|m| {
                    serde_json::json!({
                        "source": &m.source,
                        "mount_point": &m.mount_point,
                        "mode": format!("{:?}", m.mode),
                        "filters": m.filters.len(),
                    })
                })
                .collect();

            let recent_denials: Vec<serde_json::Value> = k
                .audit_log()
                .iter()
                .rev()
                .filter(|e| {
                    e.agent_pid == agent_pid && e.outcome == vac_core::types::OpOutcome::Denied
                })
                .take(10)
                .map(|e| {
                    serde_json::json!({
                        "operation": format!("{:?}", e.operation),
                        "error": &e.error,
                        "timestamp": e.timestamp,
                    })
                })
                .collect();

            Json(serde_json::json!({
                "agent_pid": agent_pid,
                "name": &acb.agent_name,
                "role": format!("{:?}", acb.role),
                "phase": format!("{:?}", acb.phase),
                "namespace": &acb.namespace,
                "readable_namespaces": &acb.readable_namespaces,
                "writable_namespaces": &acb.writable_namespaces,
                "tool_bindings": tool_bindings,
                "namespace_mounts": mounts,
                "memory_protection": {
                    "read": acb.memory_region.protection.read,
                    "write": acb.memory_region.protection.write,
                    "execute": acb.memory_region.protection.execute,
                    "share": acb.memory_region.protection.share,
                    "evict": acb.memory_region.protection.evict,
                    "requires_approval": acb.memory_region.protection.requires_approval,
                },
                "eviction_policy": format!("{:?}", acb.memory_region.eviction_policy),
                "recent_denials": recent_denials,
            }))
            .into_response()
        }
        None => Json(
            serde_json::json!({"error": format!("Agent {} not found", agent_pid), "status": 404}),
        )
        .into_response(),
    }
}

/// Wave 2 — Item 2.8: Live tool execution trace per agent
pub async fn agent_tool_trace(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(agent_pid): Path<String>,
) -> impl IntoResponse {
    if let Err(r) = require_admin(&headers) {
        return r;
    }
    let k = state.kernel.lock().unwrap();

    let tool_calls: Vec<serde_json::Value> = k
        .audit_log()
        .iter()
        .filter(|e| {
            e.agent_pid == agent_pid && e.operation == vac_core::types::MemoryKernelOp::ToolDispatch
        })
        .map(|e| {
            let target = e.target.as_deref().unwrap_or("");
            let parts: Vec<&str> = target.splitn(3, ':').collect();
            serde_json::json!({
                "tool_id": parts.first().copied().unwrap_or("unknown"),
                "action": parts.get(1).copied().unwrap_or("unknown"),
                "data_classification": parts.get(2).copied().unwrap_or("unclassified"),
                "outcome": format!("{:?}", e.outcome),
                "latency_us": e.duration_us,
                "timestamp": e.timestamp,
                "error": e.error,
            })
        })
        .collect();

    let mcp_calls: Vec<serde_json::Value> = k
        .audit_log()
        .iter()
        .filter(|e| {
            e.agent_pid == agent_pid
                && e.operation == vac_core::types::MemoryKernelOp::McpInvokeTool
        })
        .map(|e| {
            serde_json::json!({
                "target": e.target,
                "outcome": format!("{:?}", e.outcome),
                "latency_us": e.duration_us,
                "timestamp": e.timestamp,
            })
        })
        .collect();

    let approval_pending: Vec<serde_json::Value> = k
        .audit_log()
        .iter()
        .filter(|e| {
            e.agent_pid == agent_pid
                && e.operation == vac_core::types::MemoryKernelOp::ToolDispatch
                && e.outcome == vac_core::types::OpOutcome::Skipped
        })
        .map(|e| {
            serde_json::json!({
                "target": e.target,
                "reason": e.error,
                "timestamp": e.timestamp,
            })
        })
        .collect();

    Json(serde_json::json!({
        "agent_pid": agent_pid,
        "tool_calls": tool_calls.len(),
        "tool_trace": tool_calls,
        "mcp_calls": mcp_calls.len(),
        "mcp_trace": mcp_calls,
        "pending_approvals": approval_pending.len(),
        "approvals": approval_pending,
    }))
    .into_response()
}

/// Wave 4 — Item 4.1: ContextSnapshot export for an agent
pub async fn agent_snapshot(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(agent_pid): Path<String>,
) -> impl IntoResponse {
    if let Err(r) = require_admin(&headers) {
        return r;
    }
    let snapshot_ns = format!("snapshots/{}", agent_pid);
    // Persisting a snapshot is an effectful memory write — gate before mutate.
    if let Err(deny) =
        crate::substrate::admission_gate::require_memory_write(&state, &agent_pid, &snapshot_ns)
    {
        return Json(deny).into_response();
    }
    let snapshot = {
        let k = state.kernel.lock().unwrap();
        match k.export_agent_snapshot(&agent_pid) {
            Ok(snapshot) => snapshot,
            Err(err) => {
                return Json(serde_json::json!({"error": err, "status": 500})).into_response()
            }
        }
    };

    let snapshot_id = snapshot
        .snapshot_cid
        .as_ref()
        .map(|cid| cid.to_string())
        .unwrap_or_else(|| format!("snap_{}", uuid::Uuid::new_v4()));

    {
        let mut es = state.engine_store.lock().unwrap();
        let _ = es.folder_put(
            &snapshot_ns,
            &snapshot_id,
            &serde_json::to_value(&snapshot).unwrap_or_default(),
        );
    }

    Json(serde_json::json!({
        "snapshot_id": snapshot_id,
        "snapshot_cid": snapshot.snapshot_cid.as_ref().map(|cid| cid.to_string()),
        "agent_pid": agent_pid,
        "packets": snapshot.memory_packets.len(),
        "sessions": snapshot.sessions.len(),
        "delegation_chains": snapshot.delegation_chains.len(),
        "restore_url": format!("/api/v1/debug/agents/{}/restore", agent_pid),
        "restore_body": serde_json::json!({
            "snapshot_id": snapshot_id,
            "source_cell_id": "cell-0"
        }),
    }))
    .into_response()
}

/// Wave 4 — Item 4.2: Restore agent context from a snapshot
/// POST /debug/agents/{agent_pid}/restore  body: { "snapshot_id": "snap_..." }
pub async fn agent_restore(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(agent_pid): Path<String>,
    Json(req): Json<serde_json::Value>,
) -> impl IntoResponse {
    if let Err(r) = require_admin(&headers) {
        return r;
    }
    let snapshot_id = match req
        .get("snapshot_id")
        .or_else(|| req.get("snapshot_cid"))
        .and_then(|v| v.as_str())
    {
        Some(s) => s.to_string(),
        None => {
            return Json(serde_json::json!({
                "error": "snapshot_id required in request body",
                "status": 400
            }))
            .into_response()
        }
    };
    let source_cell_id = req
        .get("source_cell_id")
        .and_then(|v| v.as_str())
        .unwrap_or("debug");
    let ns = format!("snapshots/{}", agent_pid);
    // Kernel import reconstitutes agent memory — must not bypass admission.
    if let Err(deny) =
        crate::substrate::admission_gate::require_memory_write(&state, &agent_pid, &ns)
    {
        return Json(deny).into_response();
    }
    let snapshot_value =
        {
            let es = state.engine_store.lock().unwrap();
            match es.folder_get(&ns, &snapshot_id) {
                Ok(Some(snapshot)) => snapshot,
                _ => return Json(serde_json::json!({
                    "error": format!("Snapshot {} not found for agent {}", snapshot_id, agent_pid),
                }))
                .into_response(),
            }
        };

    let snapshot: vac_core::types::AgentSnapshot = match serde_json::from_value(snapshot_value) {
        Ok(snapshot) => snapshot,
        Err(err) => {
            return Json(serde_json::json!({
                "error": format!("Snapshot {} is invalid: {}", snapshot_id, err),
            }))
            .into_response()
        }
    };

    if snapshot.agent.agent_pid != agent_pid {
        return Json(serde_json::json!({
            "error": format!(
                "Snapshot {} belongs to agent {} but route targeted {}",
                snapshot_id,
                snapshot.agent.agent_pid,
                agent_pid
            ),
        }))
        .into_response();
    }

    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        &agent_pid,
        "debug",
        "restore",
        &serde_json::json!({"snapshot_id": snapshot_id}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body).into_response(),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    let imported_pid = {
        let mut k = state.kernel.lock().unwrap();
        k.import_agent_snapshot(snapshot.clone(), source_cell_id)
    };
    let imported_pid = match imported_pid {
        Ok(pid) => pid,
        Err(err) => {
            open_proceed.finish_observed(false);
            return Json(serde_json::json!({
                "error": err,
                "snapshot_id": snapshot_id,
                "agent_pid": agent_pid,
                "task_id": admitted.task_id,
                "executed": false,
                "admits": false,
            }))
            .into_response();
        }
    };
    open_proceed.finish_observed(true);

    Json(serde_json::json!({
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
        "snapshot_id": snapshot_id,
        "snapshot_cid": snapshot.snapshot_cid.as_ref().map(|cid| cid.to_string()),
        "agent_pid": imported_pid,
        "restored": true,
        "packets_in_snapshot": snapshot.memory_packets.len(),
        "sessions": snapshot.sessions.len(),
        "delegation_chains": snapshot.delegation_chains.len(),
        "snapshot_created_at_ms": snapshot.exported_at,
        "source_cell_id": source_cell_id,
        "note": "Snapshot imported into the active kernel. Import fails if the agent PID already exists.",
    }))
    .into_response()
}

/// Wave 4 — Item 4.3: Full reasoning chain with CIDs for an agent
pub async fn agent_reasoning_chain(
    State(state): State<SharedState>,
    Path(agent_pid): Path<String>,
) -> Json<serde_json::Value> {
    let k = state.kernel.lock().unwrap();

    // Build reasoning chain from audit log + memory packets
    let chain: Vec<serde_json::Value> = k
        .audit_log()
        .iter()
        .filter(|e| e.agent_pid == agent_pid)
        .map(|e| {
            let mut step = serde_json::json!({
                "timestamp": e.timestamp,
                "operation": format!("{:?}", e.operation),
                "outcome": format!("{:?}", e.outcome),
                "target_cid": e.target,
                "reason": e.reason,
                "task_id": e.vakya_id,
                "duration_us": e.duration_us,
            });
            // Enrich with SCITT receipt if available
            if let Some(ref scitt) = e.scitt_receipt_cid {
                step.as_object_mut()
                    .unwrap()
                    .insert("scitt_receipt_cid".into(), serde_json::json!(scitt));
            }
            step
        })
        .collect();

    // Get packet-level reasoning and assemble chain semantics
    let acb = k.get_agent(&agent_pid);
    let (memory_chain, reasoning_steps, conclusion, reflection_summary) = acb.map(|a| {
        let namespace_packets = k.packets_in_namespace(&a.namespace);
        let packets: Vec<_> = namespace_packets.into_iter().collect();
        let memory_chain: Vec<serde_json::Value> = packets.iter()
            .map(|p| serde_json::json!({
                "cid": p.content.payload_cid.to_string(),
                "type": format!("{}", p.content.packet_type),
                "memory_type": format!("{}", p.memory_type),
                "text": p.content.payload.get("text").and_then(|v| v.as_str()).unwrap_or(""),
                "reasoning": p.provenance.reasoning,
                "confidence": p.provenance.confidence,
                "epistemic": format!("{:?}", p.provenance.epistemic),
                "evidence_refs": p.provenance.evidence_refs.iter().map(|c| c.to_string()).collect::<Vec<_>>(),
                "supersedes": p.provenance.supersedes.map(|c| c.to_string()),
                "session_id": p.session_id,
                "tags": p.content.tags,
                "timestamp": p.index.ts,
            }))
            .collect();

        let reasoning_packets: Vec<_> = packets.iter()
            .filter(|p| p.content.tags.iter().any(|t| t == "reasoning") || p.provenance.reasoning.is_some())
            .collect();
        let reasoning_steps: Vec<serde_json::Value> = reasoning_packets.iter().enumerate().map(|(idx, p)| {
            serde_json::json!({
                "step_number": idx + 1,
                "cid": p.content.payload_cid.to_string(),
                "thought": p.content.payload.get("text").and_then(|v| v.as_str()).unwrap_or(""),
                "reasoning": p.provenance.reasoning,
                "confidence": p.provenance.confidence,
                "evidence_cids": p.provenance.evidence_refs.iter().map(|c| c.to_string()).collect::<Vec<_>>(),
                "timestamp": p.index.ts,
            })
        }).collect();

        let conclusion = packets.iter()
            .rev()
            .find(|p| matches!(p.content.packet_type, vac_core::types::PacketType::Decision) || p.content.tags.iter().any(|t| t == "conclusion"))
            .map(|p| serde_json::json!({
                "cid": p.content.payload_cid.to_string(),
                "text": p.content.payload.get("text").and_then(|v| v.as_str()).unwrap_or(""),
                "confidence": p.provenance.confidence,
                "evidence_cids": p.provenance.evidence_refs.iter().map(|c| c.to_string()).collect::<Vec<_>>(),
                "timestamp": p.index.ts,
            }))
            .unwrap_or_else(|| serde_json::json!({}));

        let reflection_packet = packets.iter()
            .rev()
            .find(|p| matches!(p.memory_type, vac_core::types::MemoryType::Reflective) || p.content.tags.iter().any(|t| t == "reflection"));
        let reflection_summary = reflection_packet.map(|p| {
            let text = p.content.payload.get("summary")
                .and_then(|v| v.as_str())
                .or_else(|| p.metadata.get("summary").and_then(|v| v.as_str()))
                .unwrap_or("");
            serde_json::json!({
                "cid": p.content.payload_cid.to_string(),
                "summary": text,
                "memory_type": format!("{}", p.memory_type),
                "evolution_stage": p.metadata.get("evolution_stage").and_then(|v| v.as_str()).unwrap_or(""),
                "timestamp": p.index.ts,
            })
        }).unwrap_or_else(|| serde_json::json!({}));

        (memory_chain, reasoning_steps, conclusion, reflection_summary)
    }).unwrap_or_else(|| (Vec::new(), Vec::new(), serde_json::json!({}), serde_json::json!({})));

    let reasoning_quality = if reasoning_steps.is_empty() {
        serde_json::json!({
            "step_count": 0,
            "evidence_coverage": 0.0,
            "has_conclusion": conclusion.as_object().map(|o| !o.is_empty()).unwrap_or(false),
        })
    } else {
        let evidence_count = reasoning_steps
            .iter()
            .filter(|s| {
                s.get("evidence_cids")
                    .and_then(|v| v.as_array())
                    .map(|a| !a.is_empty())
                    .unwrap_or(false)
            })
            .count();
        serde_json::json!({
            "step_count": reasoning_steps.len(),
            "evidence_coverage": evidence_count as f64 / reasoning_steps.len() as f64,
            "has_conclusion": conclusion.as_object().map(|o| !o.is_empty()).unwrap_or(false),
        })
    };

    Json(serde_json::json!({
        "agent_pid": agent_pid,
        "audit_chain_length": chain.len(),
        "audit_chain": chain,
        "memory_chain_length": memory_chain.len(),
        "memory_chain": memory_chain,
        "reasoning_steps": reasoning_steps,
        "conclusion": conclusion,
        "reflection": reflection_summary,
        "reasoning_quality": reasoning_quality,
    }))
}

pub async fn kernel_export(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(r) = require_admin(&headers) {
        return r;
    }
    let k = state.kernel.lock().unwrap();
    let trust = connector_engine::TrustComputer::compute(&k);
    Json(serde_json::json!({
        "packets": k.packet_count(),
        "agents": k.agents().len(),
        "sessions": k.sessions().len(),
        "audit_entries": k.audit_log().len(),
        "trust": {
            "score": trust.score,
            "grade": trust.grade,
            "dimensions": {
                "memory_integrity": trust.dimensions.memory_integrity,
                "audit_completeness": trust.dimensions.audit_completeness,
                "authorization_coverage": trust.dimensions.authorization_coverage,
                "decision_provenance": trust.dimensions.decision_provenance,
                "operational_health": trust.dimensions.operational_health,
            }
        }
    }))
    .into_response()
}

// ── E4.1: Run diff ────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct RunDiffQuery {
    pub run_a: Option<String>,
    pub run_b: Option<String>,
}

/// GET /debug/diff?run_a={cid}&run_b={cid}
pub async fn run_diff(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Query(q): Query<RunDiffQuery>,
) -> impl IntoResponse {
    if let Err(r) = require_admin(&headers) {
        return r;
    }
    let cid_a = match q.run_a {
        Some(ref c) => c.clone(),
        None => {
            return Json(serde_json::json!({"error": "run_a required", "status": 400}))
                .into_response()
        }
    };
    let cid_b = match q.run_b {
        Some(ref c) => c.clone(),
        None => {
            return Json(serde_json::json!({"error": "run_b required", "status": 400}))
                .into_response()
        }
    };

    let k = state.kernel.lock().unwrap();
    let es = state.engine_store.lock().unwrap();
    let now = chrono::Utc::now();

    // Load run snapshots from engine_store
    let snap_a = es
        .folder_get("run_snapshots", &cid_a)
        .ok()
        .flatten()
        .unwrap_or_else(|| serde_json::json!({"cid": cid_a, "missing": true}));
    let snap_b = es
        .folder_get("run_snapshots", &cid_b)
        .ok()
        .flatten()
        .unwrap_or_else(|| serde_json::json!({"cid": cid_b, "missing": true}));

    // Prompt delta
    let prompt_a = snap_a.get("prompt").and_then(|v| v.as_str()).unwrap_or("");
    let prompt_b = snap_b.get("prompt").and_then(|v| v.as_str()).unwrap_or("");
    let prompt_diff = unified_diff(prompt_a, prompt_b);

    // Token delta
    let tokens_a = snap_a.get("tokens").and_then(|v| v.as_i64()).unwrap_or(0);
    let tokens_b = snap_b.get("tokens").and_then(|v| v.as_i64()).unwrap_or(0);

    // Cost delta
    let cost_a = snap_a
        .get("cost_usd")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let cost_b = snap_b
        .get("cost_usd")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);

    // Guard verdict changes
    let guard_a = snap_a
        .get("guard_verdict")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let guard_b = snap_b
        .get("guard_verdict")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let guard_changed = guard_a != guard_b;

    // Output cosine similarity (simple token overlap if no embeddings)
    let out_a = snap_a.get("output").and_then(|v| v.as_str()).unwrap_or("");
    let out_b = snap_b.get("output").and_then(|v| v.as_str()).unwrap_or("");
    let cosine_sim = token_overlap_similarity(out_a, out_b);

    // Audit entries between the two runs
    let audit_log = k.audit_log();
    let entries_a: Vec<_> = audit_log
        .iter()
        .filter(|e| {
            snap_a
                .get("agent_pid")
                .and_then(|v| v.as_str())
                .map_or(false, |p| e.agent_pid == p)
        })
        .take(5)
        .collect();
    let entries_b: Vec<_> = audit_log
        .iter()
        .filter(|e| {
            snap_b
                .get("agent_pid")
                .and_then(|v| v.as_str())
                .map_or(false, |p| e.agent_pid == p)
        })
        .take(5)
        .collect();

    Json(serde_json::json!({
        "diff_id":        format!("diff_{}vs{}", &cid_a[..8.min(cid_a.len())], &cid_b[..8.min(cid_b.len())]),
        "generated_at":   now.to_rfc3339(),
        "run_a":          cid_a,
        "run_b":          cid_b,
        "prompt_diff": {
            "changed": prompt_a != prompt_b,
            "unified_diff": prompt_diff,
        },
        "token_delta": {
            "run_a": tokens_a,
            "run_b": tokens_b,
            "delta": tokens_b - tokens_a,
            "pct_change": if tokens_a > 0 { ((tokens_b - tokens_a) as f64 / tokens_a as f64 * 100.0).round() } else { 0.0 },
        },
        "cost_delta": {
            "run_a_usd": cost_a,
            "run_b_usd": cost_b,
            "delta_usd": (cost_b - cost_a * 10000.0).round() / 10000.0,
        },
        "guard_verdict": {
            "run_a": guard_a,
            "run_b": guard_b,
            "changed": guard_changed,
            "regression": guard_a == "pass" && guard_b == "fail",
        },
        "output_similarity": {
            "cosine_approx": cosine_sim,
            "changed": cosine_sim < 0.95,
        },
        "sample_audit_a": entries_a.iter().map(|e| serde_json::json!({"ts": e.timestamp, "op": format!("{:?}", e.operation), "outcome": format!("{:?}", e.outcome)})).collect::<Vec<_>>(),
        "sample_audit_b": entries_b.iter().map(|e| serde_json::json!({"ts": e.timestamp, "op": format!("{:?}", e.operation), "outcome": format!("{:?}", e.outcome)})).collect::<Vec<_>>(),
        "hint": "POST /debug/agents/{pid}/snapshot to capture a run snapshot",
    })).into_response()
}

fn unified_diff(a: &str, b: &str) -> Vec<String> {
    if a == b {
        return vec![];
    }
    let lines_a: Vec<&str> = a.lines().collect();
    let lines_b: Vec<&str> = b.lines().collect();
    let mut diff = Vec::new();
    let max = lines_a.len().max(lines_b.len());
    for i in 0..max {
        match (lines_a.get(i), lines_b.get(i)) {
            (Some(la), Some(lb)) if la == lb => diff.push(format!("  {}", la)),
            (Some(la), Some(lb)) => {
                diff.push(format!("- {}", la));
                diff.push(format!("+ {}", lb));
            }
            (Some(la), None) => diff.push(format!("- {}", la)),
            (None, Some(lb)) => diff.push(format!("+ {}", lb)),
            _ => {}
        }
    }
    diff
}

fn token_overlap_similarity(a: &str, b: &str) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    let set_a: std::collections::HashSet<&str> = a.split_whitespace().collect();
    let set_b: std::collections::HashSet<&str> = b.split_whitespace().collect();
    let intersection = set_a.intersection(&set_b).count();
    let union = set_a.union(&set_b).count();
    if union == 0 {
        1.0
    } else {
        (intersection as f64 / union as f64 * 100.0).round() / 100.0
    }
}

// ── E4.2: Failure clustering ──────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct FailureClusterQuery {
    pub agent_pid: Option<String>,
    pub window: Option<String>,
}

/// GET /debug/failure-clusters?agent_pid=&window=24h
pub async fn failure_clusters(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Query(q): Query<FailureClusterQuery>,
) -> impl IntoResponse {
    if let Err(r) = require_admin(&headers) {
        return r;
    }
    let now = chrono::Utc::now();
    let now_ms = now.timestamp_millis();

    let window_ms: i64 = match q.window.as_deref().unwrap_or("24h") {
        "1h" => 3_600_000,
        "6h" => 21_600_000,
        "24h" => 86_400_000,
        "7d" => 604_800_000,
        other => {
            if let Some(h) = other.strip_suffix('h').and_then(|s| s.parse::<i64>().ok()) {
                h * 3_600_000
            } else if let Some(d) = other.strip_suffix('d').and_then(|s| s.parse::<i64>().ok()) {
                d * 86_400_000
            } else {
                86_400_000
            }
        }
    };
    let cutoff_ms = now_ms - window_ms;

    let k = state.kernel.lock().unwrap();
    let audit_log = k.audit_log();

    let failures: Vec<_> = audit_log
        .iter()
        .filter(|e| e.timestamp >= cutoff_ms)
        .filter(|e| e.outcome == vac_core::types::OpOutcome::Denied)
        .filter(|e| {
            q.agent_pid
                .as_deref()
                .map_or(true, |pid| e.agent_pid == pid)
        })
        .collect();

    // Cluster by reason/operation similarity (token overlap grouping)
    let mut clusters: Vec<(String, Vec<serde_json::Value>)> = Vec::new();

    for entry in &failures {
        let op_str = format!("{:?}", entry.operation);
        let reason = entry.reason.as_deref().unwrap_or(&op_str);

        // Find existing cluster with >50% overlap
        let mut found = false;
        for (root, members) in clusters.iter_mut() {
            if token_overlap_similarity(root, reason) > 0.5 {
                members.push(serde_json::json!({
                    "ts":        entry.timestamp,
                    "agent_pid": entry.agent_pid,
                    "op":        op_str,
                    "reason":    reason,
                }));
                found = true;
                break;
            }
        }
        if !found {
            clusters.push((
                reason.to_string(),
                vec![serde_json::json!({
                    "ts":        entry.timestamp,
                    "agent_pid": entry.agent_pid,
                    "op":        op_str,
                    "reason":    reason,
                })],
            ));
        }
    }

    // Sort by cluster size descending
    clusters.sort_by(|a, b| b.1.len().cmp(&a.1.len()));

    let cluster_report: Vec<serde_json::Value> = clusters.iter().enumerate().map(|(i, (root, members))| {
        let agents: std::collections::HashSet<&str> = members.iter()
            .filter_map(|m| m.get("agent_pid").and_then(|v| v.as_str()))
            .collect();

        // Root cause summary: most common op
        let ops: Vec<&str> = members.iter()
            .filter_map(|m| m.get("op").and_then(|v| v.as_str()))
            .collect();
        let most_common_op = ops.iter()
            .max_by_key(|op| ops.iter().filter(|o| o == op).count())
            .copied()
            .unwrap_or("unknown");

        serde_json::json!({
            "cluster_id":        format!("cluster_{}", i),
            "count":             members.len(),
            "root_cause_summary":root,
            "most_common_op":    most_common_op,
            "affected_agents":   agents.len(),
            "sample_cids":       members.iter().take(5).map(|m| m.get("ts")).collect::<Vec<_>>(),
            "sample_entries":    members.iter().take(3).collect::<Vec<_>>(),
        })
    }).collect();

    Json(serde_json::json!({
        "scan_id":       format!("clusters_{}", now.timestamp_millis()),
        "generated_at":  now.to_rfc3339(),
        "window":        q.window.as_deref().unwrap_or("24h"),
        "agent_filter":  q.agent_pid,
        "total_failures":failures.len(),
        "cluster_count": cluster_report.len(),
        "clusters":      cluster_report,
        "recommendation": if cluster_report.is_empty() {
            "No failures in window. System healthy.".into()
        } else {
            format!("Top cluster '{}' accounts for {} failures. Investigate root cause.",
                clusters.first().map(|(r,_)| r.as_str()).unwrap_or("unknown"),
                clusters.first().map(|(_,m)| m.len()).unwrap_or(0))
        },
    }))
    .into_response()
}

// ── E4.3: Live trace stream (SSE) ─────────────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct TraceStreamQuery {
    pub last_ts: Option<i64>,
    pub limit: Option<usize>,
}

/// GET /debug/agents/{pid}/trace/stream?last_ts=&limit=
/// Returns recent audit entries as NDJSON. Clients poll with last_ts for incremental updates.
/// For true SSE, use a reverse proxy or client-side EventSource with repeated polling.
pub async fn trace_stream(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(agent_pid): Path<String>,
    Query(q): Query<TraceStreamQuery>,
) -> axum::response::Response {
    if let Err(r) = require_admin(&headers) {
        return r;
    }
    let last_ts = q.last_ts.unwrap_or(0);
    let limit = q.limit.unwrap_or(50).min(200);
    let now = chrono::Utc::now();

    let k = state.kernel.lock().unwrap();
    let mut filtered: Vec<_> = k
        .audit_log()
        .iter()
        .filter(|e| e.agent_pid == agent_pid && e.timestamp > last_ts)
        .collect();
    let start = filtered.len().saturating_sub(limit);
    let entries: Vec<serde_json::Value> = filtered[start..]
        .iter()
        .map(|e| {
            serde_json::json!({
                "ts":      e.timestamp,
                "agent":   e.agent_pid,
                "op":      format!("{:?}", e.operation),
                "outcome": format!("{:?}", e.outcome),
                "reason":  e.reason,
            })
        })
        .collect();

    let max_ts = entries
        .iter()
        .filter_map(|e| e.get("ts").and_then(|v| v.as_i64()))
        .max()
        .unwrap_or(last_ts);

    // Emit as SSE-compatible text/event-stream with data: lines
    let mut body = String::new();
    for entry in &entries {
        body.push_str(&format!("data: {}\n\n", entry));
    }
    // Append cursor sentinel
    body.push_str(&format!("data: {{\"event\":\"cursor\",\"next_last_ts\":{},\"count\":{},\"generated_at\":\"{}\"}}\n\n",
        max_ts, entries.len(), now.to_rfc3339()));

    axum::response::Response::builder()
        .status(200)
        .header("content-type", "text/event-stream")
        .header("cache-control", "no-cache")
        .header("x-agent-pid", &agent_pid)
        .header("x-next-last-ts", max_ts.to_string())
        .body(axum::body::Body::from(body))
        .unwrap_or_default()
}

// ── 2.5: OpenTelemetry trace info endpoint ──────────────────────────────────

#[derive(serde::Deserialize)]
pub struct TracesQuery {
    #[serde(default = "default_limit")]
    pub limit: usize,
    #[serde(default)]
    pub agent_pid: Option<String>,
    #[serde(default)]
    pub operation: Option<String>,
    #[serde(default)]
    pub from: Option<String>,
    #[serde(default)]
    pub to: Option<String>,
}

/// GET /debug/traces — List recent kernel dispatch traces with OTel context
///
/// Returns audit entries enriched with trace context for correlation with
/// external observability systems (Jaeger, Zipkin, Grafana Tempo).
pub async fn list_traces(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Query(q): Query<TracesQuery>,
) -> impl IntoResponse {
    if let Err(r) = require_admin(&headers) {
        return r;
    }

    let k = state.kernel.lock().unwrap();
    let now = chrono::Utc::now();

    let from_ms = q
        .from
        .as_deref()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|d| d.timestamp_millis())
        .unwrap_or(0);
    let to_ms =
        q.to.as_deref()
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|d| d.timestamp_millis())
            .unwrap_or(now.timestamp_millis());

    let traces: Vec<serde_json::Value> = k
        .audit_log()
        .iter()
        .filter(|e| e.timestamp >= from_ms && e.timestamp <= to_ms)
        .filter(|e| q.agent_pid.as_ref().map_or(true, |pid| &e.agent_pid == pid))
        .filter(|e| {
            q.operation.as_ref().map_or(true, |op| {
                format!("{:?}", e.operation)
                    .to_lowercase()
                    .contains(&op.to_lowercase())
            })
        })
        .take(q.limit)
        .map(|e| {
            let duration_ms = e.duration_us.map(|us| us as f64 / 1000.0);
            serde_json::json!({
                "trace_id": format!("{:032x}", e.timestamp),
                "span_id": format!("{:016x}", e.timestamp ^ (e.agent_pid.len() as i64)),
                "audit_id": e.audit_id,
                "timestamp": e.timestamp,
                "timestamp_iso": chrono::DateTime::from_timestamp_millis(e.timestamp)
                    .map(|d| d.to_rfc3339()).unwrap_or_default(),
                "agent_pid": e.agent_pid,
                "operation": format!("{:?}", e.operation),
                "outcome": format!("{:?}", e.outcome),
                "duration_ms": duration_ms,
                "target": e.target,
                "reason": e.reason,
                "error": e.error,
                "severity": format!("{:?}", e.severity),
                "otel": {
                    "service.name": "connector-platform",
                    "kernel.operation": format!("{:?}", e.operation),
                    "kernel.outcome": format!("{:?}", e.outcome),
                    "kernel.agent_pid": e.agent_pid,
                },
            })
        })
        .collect();

    let otlp_endpoint = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok();

    Json(serde_json::json!({
        "ok": true,
        "traces": traces,
        "count": traces.len(),
        "generated_at": now.to_rfc3339(),
        "otel_config": {
            "enabled": otlp_endpoint.is_some(),
            "endpoint": otlp_endpoint,
            "service_name": std::env::var("OTEL_SERVICE_NAME").unwrap_or_else(|_| "connector-platform".into()),
        },
        "query": {
            "from": q.from,
            "to": q.to,
            "agent_pid": q.agent_pid,
            "operation": q.operation,
            "limit": q.limit,
        },
        "links": {
            "jaeger": otlp_endpoint.as_ref().map(|_| "/debug/traces/jaeger-ui"),
            "zipkin": otlp_endpoint.as_ref().map(|_| "/debug/traces/zipkin-ui"),
            "docs": "https://opentelemetry.io/docs/",
        },
    })).into_response()
}

/// GET /debug/traces/:trace_id — Get a specific trace by ID
pub async fn get_trace(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(trace_id): Path<String>,
) -> impl IntoResponse {
    if let Err(r) = require_admin(&headers) {
        return r;
    }

    let k = state.kernel.lock().unwrap();

    // Parse trace_id as hex timestamp
    let timestamp = i64::from_str_radix(&trace_id, 16).unwrap_or(0);

    let entry = k
        .audit_log()
        .iter()
        .find(|e| e.timestamp == timestamp || e.audit_id == trace_id);

    match entry {
        Some(e) => {
            let duration_ms = e.duration_us.map(|us| us as f64 / 1000.0);
            Json(serde_json::json!({
                "ok": true,
                "trace": {
                    "trace_id": format!("{:032x}", e.timestamp),
                    "span_id": format!("{:016x}", e.timestamp ^ (e.agent_pid.len() as i64)),
                    "audit_id": e.audit_id,
                    "timestamp": e.timestamp,
                    "timestamp_iso": chrono::DateTime::from_timestamp_millis(e.timestamp)
                        .map(|d| d.to_rfc3339()).unwrap_or_default(),
                    "agent_pid": e.agent_pid,
                    "operation": format!("{:?}", e.operation),
                    "outcome": format!("{:?}", e.outcome),
                    "duration_ms": duration_ms,
                    "target": e.target,
                    "reason": e.reason,
                    "error": e.error,
                    "severity": format!("{:?}", e.severity),
                    "vakya_id": e.vakya_id,
                    "before_hash": e.before_hash,
                    "after_hash": e.after_hash,
                    "merkle_root": e.merkle_root,
                    "natural_language": e.natural_language,
                    "business_impact": e.business_impact,
                    "remediation_hint": e.remediation_hint,
                    "causal_chain": e.causal_chain,
                    "gen_ai_attrs": e.gen_ai_attrs,
                },
            }))
            .into_response()
        }
        None => error_response(
            StatusCode::NOT_FOUND,
            "trace_not_found",
            &format!("Trace {} not found in audit log", trace_id),
        ),
    }
}

/// GET /debug/traces/stats — Trace statistics summary
pub async fn trace_stats(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(r) = require_admin(&headers) {
        return r;
    }

    let k = state.kernel.lock().unwrap();
    let now = chrono::Utc::now();
    let audit_log = k.audit_log();

    let total = audit_log.len();
    let last_hour_ms = now.timestamp_millis() - 3600_000;
    let last_hour = audit_log
        .iter()
        .filter(|e| e.timestamp >= last_hour_ms)
        .count();

    // Count by outcome
    let mut by_outcome: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut by_operation: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    let mut total_duration_us: u64 = 0;
    let mut duration_count: u64 = 0;

    for entry in audit_log.iter() {
        *by_outcome
            .entry(format!("{:?}", entry.outcome))
            .or_default() += 1;
        *by_operation
            .entry(format!("{:?}", entry.operation))
            .or_default() += 1;
        if let Some(dur) = entry.duration_us {
            total_duration_us += dur;
            duration_count += 1;
        }
    }

    let avg_duration_ms = if duration_count > 0 {
        Some((total_duration_us as f64 / duration_count as f64) / 1000.0)
    } else {
        None
    };

    let otlp_endpoint = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok();

    Json(serde_json::json!({
        "ok": true,
        "stats": {
            "total_traces": total,
            "last_hour": last_hour,
            "by_outcome": by_outcome,
            "by_operation": by_operation,
            "avg_duration_ms": avg_duration_ms,
        },
        "otel_config": {
            "enabled": otlp_endpoint.is_some(),
            "endpoint": otlp_endpoint,
            "service_name": std::env::var("OTEL_SERVICE_NAME").unwrap_or_else(|_| "connector-platform".into()),
        },
        "generated_at": now.to_rfc3339(),
    })).into_response()
}

/// GET `/debug/surface/:subject_id` — validated Surface Contract Standard JSON
/// `surface_contract`, `decision_package`, and `document` (same shape as `connectorctl` `--json`).
/// Admin-only. Engine uses the SOE mock kernel; subject is the display id (e.g. agent PID).
pub async fn surface_contract_json(
    State(_state): State<SharedState>,
    Path(subject_id): Path<String>,
    headers: HeaderMap,
    Query(surface_query): Query<SurfaceQueryParams>,
) -> impl IntoResponse {
    if let Err(r) = require_admin(&headers) {
        return r;
    }
    let debug_surface_role_label = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .and_then(|t| auth::verify_token(t).ok())
        .map(|c| {
            crate::services::surface_http::platform_role_token(auth::PlatformRole::from_str(
                &c.role,
            ))
        })
        .unwrap_or("admin");
    use connector_engine::surface::{
        RenderError, RenderRequest, Role, SurfaceEngine, SurfaceTimeSelector, SurfaceType,
        SurfaceView,
    };
    let mut engine = SurfaceEngine::default();
    let mut request = RenderRequest::new(
        SurfaceType::Agent,
        &subject_id,
        "api-debug",
        Role::Developer,
    )
    .view(SurfaceView::Ops)
    .time(SurfaceTimeSelector::Now);
    if let Some(query) = build_surface_query(&surface_query) {
        request = request.query(query);
    }
    match engine.render(request) {
        Ok(result) => {
            let json_str = result.to_json_with_meta(
                Some(crate::services::surface_http::surface_type_token(
                    SurfaceType::Agent,
                )),
                Some(debug_surface_role_label),
            );
            match serde_json::from_str::<serde_json::Value>(&json_str) {
                Ok(v) => {
                    let mut res = (StatusCode::OK, Json(v)).into_response();
                    crate::services::surface_http::extend_surface_operator_headers(
                        res.headers_mut(),
                        crate::services::surface_http::surface_type_token(SurfaceType::Agent),
                        crate::services::surface_http::surface_view_token(SurfaceView::Ops),
                        &subject_id,
                        debug_surface_role_label,
                    );
                    res
                }
                Err(e) => error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "surface_json_encode_failed",
                    &e.to_string(),
                )
                .into_response(),
            }
        }
        Err(e) => crate::services::surface_http::render_error_to_response(&e),
    }
}

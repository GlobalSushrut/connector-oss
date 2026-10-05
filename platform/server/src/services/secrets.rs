//! # Agent Secret Vault Service — Opaque Handles, TTL, Kernel-Only
//!
//! Surfaces `connector_engine::secret_store::SecretStore` as a sellable service.
//! Replaces HashiCorp Vault for AI agent secret management.
//!
//! Routes:
//!   POST   /secrets/store             — store a secret (kernel-only)
//!   POST   /secrets/handle            — issue opaque handle to agent
//!   POST   /secrets/resolve           — resolve handle → actual value (kernel-only)
//!   GET    /secrets/handles/{pid}     — list handles for agent
//!   DELETE /secrets/{id}              — revoke a secret
//!   POST   /secrets/{id}/rotate       — rotate secret value
//!   GET    /secrets/audit             — secret access audit trail

use crate::state::SharedState;
use axum::{
    extract::{Path, State},
    Json,
};
use connector_engine::engine_store::{AuditFilter, EngineAuditEntry, EngineStore};
use serde::Deserialize;

/// Audit category for every vault operation, queried back by `GET /secrets/audit`.
const SECRET_AUDIT_CATEGORY: &str = "secret";

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}
fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339()
}

/// Append one vault operation to the engine audit log.
///
/// Only identifiers and verdicts are recorded — secret values never reach the log.
/// Callers must not hold the `secret_store` lock: this takes `engine_store`.
fn record_secret_audit(
    state: &SharedState,
    action: &str,
    agent_pid: Option<&str>,
    secret_id: Option<&str>,
    verdict: &str,
    severity: &str,
    details: Option<serde_json::Value>,
) {
    let entry = EngineAuditEntry {
        timestamp: now_ms(),
        category: SECRET_AUDIT_CATEGORY.to_string(),
        agent_pid: agent_pid.map(|s| s.to_string()),
        action: action.to_string(),
        resource: secret_id.map(|s| format!("secret://{s}")),
        verdict: Some(verdict.to_string()),
        details,
        severity: severity.to_string(),
    };
    let mut es = state.engine_store.lock().unwrap();
    if let Err(e) = es.append_audit(&entry) {
        tracing::warn!(error = %e, action, "secret vault audit append failed");
    }
}

#[derive(Deserialize)]
pub struct StoreSecretRequest {
    pub secret_id: String,
    pub agent_pid: String,
    pub value: String,
    pub ttl_ms: Option<i64>,
    #[serde(default)]
    pub description: String,
}

/// POST /secrets/store — store a secret with optional TTL.
pub async fn store_secret(
    State(state): State<SharedState>,
    Json(req): Json<StoreSecretRequest>,
) -> Json<serde_json::Value> {
    let outcome = {
        let mut ss = state.secret_store.lock().unwrap();
        match ss.store_secret(
            &req.secret_id,
            &req.agent_pid,
            &req.value,
            req.ttl_ms,
            now_ms(),
            &req.description,
        ) {
            Ok(_) => crate::kernel::vault_seal::persist(&ss)
                .map_err(|e| format!("vault_persist:{e}")),
            Err(e) => Err(e),
        }
    };
    match outcome {
        Ok(()) => {
            record_secret_audit(
                &state,
                "secret.store",
                Some(&req.agent_pid),
                Some(&req.secret_id),
                "allowed",
                "info",
                Some(serde_json::json!({"ttl_ms": req.ttl_ms})),
            );
            Json(serde_json::json!({
                "ok": true,
                "secret_id": req.secret_id,
                "agent_pid": req.agent_pid,
                "ttl_ms": req.ttl_ms,
                "stored_at": now_iso(),
                "note": "Secret stored. Agent must use opaque handle to reference it. Value is never logged.",
            }))
        }
        Err(e) => {
            record_secret_audit(
                &state,
                "secret.store",
                Some(&req.agent_pid),
                Some(&req.secret_id),
                "denied",
                "warning",
                Some(serde_json::json!({"error": e.clone()})),
            );
            Json(serde_json::json!({"ok": false, "error": e}))
        }
    }
}

#[derive(Deserialize)]
pub struct IssueHandleRequest {
    pub secret_id: String,
    pub agent_pid: String,
}

/// POST /secrets/handle — issue an opaque handle for an agent to reference a secret.
pub async fn issue_handle(
    State(state): State<SharedState>,
    Json(req): Json<IssueHandleRequest>,
) -> Json<serde_json::Value> {
    let outcome = {
        let mut ss = state.secret_store.lock().unwrap();
        match ss.issue_handle(&req.secret_id, &req.agent_pid) {
            Ok(handle) => match crate::kernel::vault_seal::persist(&ss) {
                Ok(()) => Ok(handle),
                Err(e) => Err(format!("vault_persist:{e}")),
            },
            Err(e) => Err(e),
        }
    };
    match outcome {
        Ok(handle) => {
            record_secret_audit(
                &state,
                "secret.handle.issue",
                Some(&handle.agent_pid),
                Some(&handle.secret_id),
                "allowed",
                "info",
                Some(serde_json::json!({"handle_id": handle.handle_id})),
            );
            Json(serde_json::json!({
                "ok": true,
                "handle_id": handle.handle_id,
                "secret_id": handle.secret_id,
                "agent_pid": handle.agent_pid,
                "namespace": handle.namespace,
                "issued_at": now_iso(),
                "note": "Agent uses this handle_id in tool calls. Kernel auto-injects the real secret at execution time.",
            }))
        }
        Err(e) => {
            record_secret_audit(
                &state,
                "secret.handle.issue",
                Some(&req.agent_pid),
                Some(&req.secret_id),
                "denied",
                "warning",
                Some(serde_json::json!({"error": e.clone()})),
            );
            Json(serde_json::json!({"ok": false, "error": e}))
        }
    }
}

#[derive(Deserialize)]
pub struct ResolveHandleRequest {
    pub handle_id: String,
    pub agent_pid: String,
}

/// POST /secrets/resolve — confirm a handle is valid. Never returns the secret
/// over HTTP. Kernel tool injection uses in-process `credential_proxy` / vault.
pub async fn resolve_handle(
    State(state): State<SharedState>,
    _headers: axum::http::HeaderMap,
    Json(req): Json<ResolveHandleRequest>,
) -> Json<serde_json::Value> {
    let outcome = {
        let ss = state.secret_store.lock().unwrap();
        ss.resolve_handle(&req.handle_id, now_ms())
            .map(|value| value.len())
    };
    match outcome {
        Ok(value_length) => {
            record_secret_audit(
                &state,
                "secret.handle.resolve",
                Some(&req.agent_pid),
                None,
                "allowed",
                "info",
                Some(serde_json::json!({"handle_id": req.handle_id, "value_length": value_length})),
            );
            Json(serde_json::json!({
                "ok": true,
                "handle_id": req.handle_id,
                "resolved": true,
                "value_length": value_length,
                "resolved_at": now_iso(),
                "note": "Secret value is never returned over HTTP. Inject via in-process vault / credential_proxy.",
            }))
        }
        Err(e) => {
            record_secret_audit(
                &state,
                "secret.handle.resolve",
                Some(&req.agent_pid),
                None,
                "denied",
                "warning",
                Some(serde_json::json!({"handle_id": req.handle_id, "error": e.clone()})),
            );
            Json(serde_json::json!({"ok": false, "error": e}))
        }
    }
}

/// GET /secrets/handles/{pid} — list all opaque handles for an agent.
///
/// Reads the live `SecretStore`, which owns handle state. An earlier version read
/// a `secret_handles:{pid}` engine folder that nothing ever wrote, so it always
/// reported zero handles regardless of how many were issued.
pub async fn list_handles(
    State(state): State<SharedState>,
    Path(pid): Path<String>,
) -> Json<serde_json::Value> {
    let (handles, handle_count, secret_count) = {
        let ss = state.secret_store.lock().unwrap();
        (
            ss.handles_for_agent(&pid),
            ss.handle_count(),
            ss.secret_count(),
        )
    };

    Json(serde_json::json!({
        "agent_pid": pid,
        "handle_count": handles.len(),
        "total_platform_handles": handle_count,
        "total_platform_secrets": secret_count,
        "handles": handles,
        "note": "Handle metadata only. Secret values are never exposed via API. Null lifecycle fields mean the backing secret was revoked (dangling handle).",
    }))
}

/// DELETE /secrets/{id} — revoke a secret (removes secret + all handles).
/// FIX BUG-027: Now actually removes the secret instead of just purging expired ones.
pub async fn revoke_secret(
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> Json<serde_json::Value> {
    let outcome = {
        let mut ss = state.secret_store.lock().unwrap();
        match ss.revoke_secret(&id) {
            Ok(()) => crate::kernel::vault_seal::persist(&ss)
                .map_err(|e| format!("vault_persist:{e}")),
            Err(e) => Err(e),
        }
    };
    match outcome {
        Ok(()) => {
            record_secret_audit(&state, "secret.revoke", None, Some(&id), "allowed", "warning", None);
            Json(serde_json::json!({
                "ok": true,
                "secret_id": id,
                "revoked_at": now_iso(),
                "note": "Secret and all associated handles have been permanently removed.",
            }))
        }
        Err(e) => {
            record_secret_audit(
                &state,
                "secret.revoke",
                None,
                Some(&id),
                "denied",
                "warning",
                Some(serde_json::json!({"error": e.clone()})),
            );
            Json(serde_json::json!({
                "ok": false,
                "error": e,
                "secret_id": id,
                "status": 404,
            }))
        }
    }
}

#[derive(Deserialize)]
pub struct RotateSecretRequest {
    pub new_value: String,
    pub new_ttl_ms: Option<i64>,
}

/// POST /secrets/{id}/rotate — rotate secret value (old handles continue to work).
pub async fn rotate_secret(
    State(state): State<SharedState>,
    Path(id): Path<String>,
    Json(req): Json<RotateSecretRequest>,
) -> Json<serde_json::Value> {
    let outcome = {
        let mut ss = state.secret_store.lock().unwrap();
        match ss.rotate_secret(&id, &req.new_value, req.new_ttl_ms, now_ms()) {
            Ok(()) => crate::kernel::vault_seal::persist(&ss)
                .map_err(|e| format!("vault_persist:{e}")),
            Err(e) => Err(e),
        }
    };
    match outcome {
        Ok(()) => {
            record_secret_audit(
                &state,
                "secret.rotate",
                None,
                Some(&id),
                "allowed",
                "warning",
                Some(serde_json::json!({"new_ttl_ms": req.new_ttl_ms})),
            );
            Json(serde_json::json!({
                "ok": true,
                "secret_id": id,
                "rotated_at": now_iso(),
                "new_ttl_ms": req.new_ttl_ms,
                "note": "Value replaced in place — handles already issued now resolve to the new value.",
            }))
        }
        Err(e) => {
            record_secret_audit(
                &state,
                "secret.rotate",
                None,
                Some(&id),
                "denied",
                "warning",
                Some(serde_json::json!({"error": e.clone()})),
            );
            Json(serde_json::json!({"ok": false, "error": e}))
        }
    }
}

/// GET /secrets/audit — secret access audit trail (values never recorded).
pub async fn audit_trail(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let (secret_count, handle_count) = {
        let ss = state.secret_store.lock().unwrap();
        (ss.secret_count(), ss.handle_count())
    };

    let mut entries = {
        let es = state.engine_store.lock().unwrap();
        es.query_audit(&AuditFilter {
            category: Some(SECRET_AUDIT_CATEGORY.to_string()),
            ..Default::default()
        })
        .unwrap_or_default()
    };
    entries.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

    let rows: Vec<serde_json::Value> = entries
        .iter()
        .take(200)
        .map(|e| {
            serde_json::json!({
                "timestamp": e.timestamp,
                "at": chrono::DateTime::from_timestamp_millis(e.timestamp)
                    .map(|d| d.to_rfc3339()),
                "action": e.action,
                "agent_pid": e.agent_pid,
                "resource": e.resource,
                "verdict": e.verdict,
                "severity": e.severity,
                "details": e.details,
            })
        })
        .collect();

    Json(serde_json::json!({
        "audit_count": entries.len(),
        "returned": rows.len(),
        "secret_count": secret_count,
        "handle_count": handle_count,
        "entries": rows,
        "note": "Vault operations recorded in the engine audit log under category 'secret'. Secret values are never logged. audit_count counts audit events, not stored secrets.",
    }))
}

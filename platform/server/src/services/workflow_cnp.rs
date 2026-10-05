//! Workflow ↔ CNP bus registration (T3.2 / 3.7 partial).
//!
//! On workflow **ENABLED**, registers `[workflow.actions]` and `[workflow.events]` topics,
//! mints a workflow-scoped dispatch token, and records a VAC audit entry.

use serde_json::{json, Value};

use crate::state::SharedState;

const CNP_BUS_FOLDER: &str = "workflow_cnp_bus";
const CNP_TOKEN_FOLDER: &str = "workflow_cnp_dispatch_tokens";

pub fn workflow_action_topic(workflow_id: &str) -> String {
    format!("workflow.actions.{workflow_id}")
}

pub fn workflow_event_topic(workflow_id: &str) -> String {
    format!("workflow.events.{workflow_id}")
}

/// Scopes for workflow→plugin calls over CNP (minted once per ENABLE).
fn workflow_dispatch_scopes(workflow_id: &str) -> Vec<String> {
    vec![
        workflow_action_topic(workflow_id),
        workflow_event_topic(workflow_id),
        format!("workflow:{workflow_id}:dispatch"),
    ]
}

/// Register CNP topics when a workflow transitions to ENABLED. Idempotent per workflow_id.
pub fn register_workflow_on_cnp_bus(
    state: &SharedState,
    workflow_id: &str,
    contract_name: &str,
) -> Value {
    let action_topic = workflow_action_topic(workflow_id);
    let event_topic = workflow_event_topic(workflow_id);
    let registered_at = chrono::Utc::now().to_rfc3339();
    let scopes = workflow_dispatch_scopes(workflow_id);
    let dispatch_token = crate::auth::generate_api_key("cpk_wf");

    let token_record = json!({
        "workflow_id": workflow_id,
        "token_prefix": dispatch_token.chars().take(12).collect::<String>(),
        "scopes": scopes.clone(),
        "minted_at": registered_at,
        "note": "Use dispatch_token only on CNP topics; not for REST /api/v1.",
    });

    let entry = json!({
        "workflow_id": workflow_id,
        "contract_name": contract_name,
        "transport": "cnp",
        "topics": [action_topic.clone(), event_topic.clone()],
        "workflow.actions": action_topic,
        "workflow.events": event_topic,
        "scoped_token_required": true,
        "direct_plugin_dispatch": false,
        "dispatch_scopes": scopes.clone(),
        "dispatch_token_minted": true,
        "registered_at": registered_at,
    });

    {
        let mut es = state.engine_store.lock().unwrap();
        let _ = es.folder_put(CNP_BUS_FOLDER, workflow_id, &entry);
        let _ = es.folder_put(CNP_TOKEN_FOLDER, workflow_id, &token_record);
    }

    {
        use vac_core::types::{MemoryKernelOp, OpOutcome};
        let mut k = state.kernel.lock().unwrap();
        k.record_audit_event(
            MemoryKernelOp::PolicyCheck,
            "kernel/workflow-cnp",
            Some(format!(
                "cnp_register:workflow_id={},contract={}",
                workflow_id, contract_name
            )),
            OpOutcome::Success,
            Some(
                "workflow.actions and workflow.events topics registered; dispatch token minted"
                    .into(),
            ),
            None,
            None,
            None,
        );
        k.flush_audit_batch();
    }

    let mut out = entry;
    if let Some(obj) = out.as_object_mut() {
        obj.insert(
            "dispatch_token".into(),
            json!({
                "value": dispatch_token,
                "scopes": scopes,
                "one_time": true,
            }),
        );
    }
    out
}

pub fn cnp_registration(state: &SharedState, workflow_id: &str) -> Option<Value> {
    let es = state.engine_store.lock().unwrap();
    es.folder_get(CNP_BUS_FOLDER, workflow_id).ok().flatten()
}

/// Token record from last ENABLE (prefix + scopes; never returns the secret value).
pub fn cnp_token_record(state: &SharedState, workflow_id: &str) -> Option<Value> {
    let es = state.engine_store.lock().unwrap();
    es.folder_get(CNP_TOKEN_FOLDER, workflow_id).ok().flatten()
}

/// True when ENABLE minted a CNP dispatch token for this workflow.
pub fn has_enable_dispatch_tokens(state: &SharedState, workflow_id: &str) -> bool {
    if cnp_token_record(state, workflow_id).is_some() {
        return true;
    }
    cnp_registration(state, workflow_id)
        .and_then(|r| r.get("dispatch_token_minted").and_then(|x| x.as_bool()))
        .unwrap_or(false)
}

/// Synthetic CNP-shaped event stubs derived from last-enable token scopes (P3.2 product path).
pub fn synthetic_cnp_events_from_enable_tokens(
    state: &SharedState,
    workflow_id: &str,
) -> Vec<Value> {
    let Some(tok) = cnp_token_record(state, workflow_id) else {
        // Fall back to registration topics when token folder empty but ENABLE recorded.
        let Some(reg) = cnp_registration(state, workflow_id) else {
            return vec![];
        };
        let registered_at = reg
            .get("registered_at")
            .and_then(|x| x.as_str())
            .unwrap_or("enable");
        return vec![json!({
            "event_id": format!("cnp_en_{}", short_fp(&format!("{workflow_id}|{registered_at}"))),
            "kind": "enable_registration",
            "workflow_id": workflow_id,
            "topics": reg.get("topics").cloned().unwrap_or(json!([])),
            "cnp_correlation": {
                "matched": true,
                "source": "enable_registration",
                "action_topic": workflow_action_topic(workflow_id),
                "event_topic": workflow_event_topic(workflow_id),
            },
        })];
    };
    let prefix = tok
        .get("token_prefix")
        .and_then(|x| x.as_str())
        .unwrap_or("tok");
    let minted_at = tok.get("minted_at").and_then(|x| x.as_str()).unwrap_or("");
    let scopes = tok
        .get("scopes")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
    let mut out = Vec::new();
    // One enable-shaped event from the token itself.
    out.push(json!({
        "event_id": format!("cnp_tok_{}", short_fp(&format!("{workflow_id}|{prefix}|{minted_at}"))),
        "kind": "enable_dispatch_token",
        "workflow_id": workflow_id,
        "token_prefix": prefix,
        "minted_at": minted_at,
        "cnp_correlation": {
            "matched": true,
            "source": "enable_dispatch_token",
            "action_topic": workflow_action_topic(workflow_id),
            "event_topic": workflow_event_topic(workflow_id),
        },
    }));
    // One synthetic event_id per scoped topic (CNP-shaped, not live bus replay).
    for (i, scope) in scopes.iter().enumerate().take(8) {
        let topic = scope.as_str().unwrap_or("");
        if topic.is_empty() {
            continue;
        }
        out.push(json!({
            "event_id": format!(
                "cnp_scope_{}",
                short_fp(&format!("{workflow_id}|{topic}|{i}"))
            ),
            "kind": "enable_scope",
            "topic": topic,
            "workflow_id": workflow_id,
            "cnp_correlation": {
                "matched": true,
                "source": "enable_dispatch_token_scope",
                "action_topic": workflow_action_topic(workflow_id),
                "event_topic": workflow_event_topic(workflow_id),
                "scope": topic,
            },
        }));
    }
    out
}

const CNP_CONSUMED_FOLDER: &str = "workflow_cnp_consumed";

/// WF-01 scaffold: for each ENABLED workflow with enable tokens, consume at most
/// one unconsumed synthetic event into `workflow_cnp_consumed`. Returns count consumed.
/// Honesty: this is **not** a live CNP bus consumer.
pub fn poll_consume_one_synthetic_event(state: &SharedState) -> usize {
    let ids: Vec<String> = {
        let es = match state.engine_store.lock() {
            Ok(g) => g,
            Err(_) => return 0,
        };
        es.folder_keys("workflow_runtime", None)
            .unwrap_or_default()
            .into_iter()
            .filter(|k| {
                es.folder_get("workflow_runtime", k)
                    .ok()
                    .flatten()
                    .and_then(|v| {
                        v.get("state")
                            .and_then(|s| s.as_str())
                            .map(|s| s == "ENABLED")
                    })
                    .unwrap_or(false)
            })
            .collect()
    };
    let mut consumed = 0usize;
    for wf_id in ids {
        if !has_enable_dispatch_tokens(state, &wf_id) {
            continue;
        }
        let events = synthetic_cnp_events_from_enable_tokens(state, &wf_id);
        let Some(ev) = events.first() else {
            continue;
        };
        let event_id = ev.get("event_id").and_then(|x| x.as_str()).unwrap_or("");
        if event_id.is_empty() {
            continue;
        }
        let key = format!("{wf_id}:{event_id}");
        let mut es = match state.engine_store.lock() {
            Ok(g) => g,
            Err(_) => continue,
        };
        if es
            .folder_get(CNP_CONSUMED_FOLDER, &key)
            .ok()
            .flatten()
            .is_some()
        {
            continue;
        }
        let _ = es.folder_put(
            CNP_CONSUMED_FOLDER,
            &key,
            &json!({
                "workflow_id": wf_id,
                "event_id": event_id,
                "kind": ev.get("kind"),
                "consumed_at": chrono::Utc::now().to_rfc3339(),
                "honesty": "ENABLE token observed — dispatching to CLS lease runner (not a live CNP bus)",
                "execution_mode": "cls_blueprint_lease_runner",
            }),
        );
        drop(es);
        if let Some(rec) = crate::services::workflow_runtime::get_workflow(state, &wf_id) {
            if !crate::services::workflow_runner::has_open_run(state, &wf_id) {
                let _ = crate::services::workflow_runner::enqueue_enabled_run(state, &rec);
            }
        }
        consumed += 1;
    }
    consumed
}

fn short_fp(s: &str) -> String {
    use sha2::{Digest, Sha256};
    let d = Sha256::digest(s.as_bytes());
    hex::encode(&d[..8])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn topics_are_stable() {
        assert_eq!(workflow_action_topic("wf-1"), "workflow.actions.wf-1");
        assert_eq!(workflow_event_topic("wf-1"), "workflow.events.wf-1");
    }
}

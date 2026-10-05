//! Read-only workspace projection. It composes existing records and does not store a second authority.

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::Json;
use serde_json::{json, Value};

use connector_trust::{AgentContractV2, ContinuityStateV2, IntelligencePrincipalV2};

use crate::kernel::agent_principal;
use crate::state::SharedState;

pub const SCHEMA: &str = "connector.agent_workspace_projection.v1";

#[derive(Debug, Clone)]
pub struct WorkspaceFacts {
    pub api_pid: String,
    pub principal: Option<IntelligencePrincipalV2>,
    pub contract: Option<AgentContractV2>,
    pub continuity_state: Option<String>,
    pub containers: usize,
    pub stored_files: usize,
    pub ingested_files: usize,
    pub memory_packets: Option<usize>,
    pub grant_count: usize,
    pub receipt_ids: Vec<String>,
    pub checkpoint_count: usize,
    pub context_state_present: bool,
    pub directive_count: usize,
    pub character_revision: Option<u64>,
    pub alias_count: usize,
    pub frame_drop_count: usize,
    pub activation_id: Option<String>,
}

fn generic_purpose(item: &str) -> bool {
    let trimmed = item.trim();
    trimmed.is_empty()
        || trimmed.eq_ignore_ascii_case("general-purpose")
        || trimmed.eq_ignore_ascii_case("general_purpose")
        || trimmed.eq_ignore_ascii_case("general,assistant")
}

fn specific_purpose(purpose: &[String]) -> Vec<String> {
    purpose
        .iter()
        .map(|item| item.trim().to_string())
        .filter(|item| !generic_purpose(item))
        .collect()
}

fn dimension(status: &str, source: &str, detail: Value) -> Value {
    json!({
        "status": status,
        "source": source,
        "detail": detail,
    })
}

pub fn project_workspace(facts: &WorkspaceFacts) -> Value {
    let principal = facts.principal.as_ref().map(|principal| {
        json!({
            "principal_id": principal.principal_id,
            "schema": principal.schema,
            "contract_version": principal.contract_version,
            "created_at_ms": principal.created_at_ms,
            "model_ref": principal.model_ref.clone(),
        })
    });
    let specific = facts
        .contract
        .as_ref()
        .map(|contract| specific_purpose(&contract.purpose))
        .unwrap_or_default();
    let purpose = if specific.is_empty() {
        dimension(
            "absent",
            "agent_contract_v2",
            json!({"reason": "specific_purpose_required"}),
        )
    } else {
        let contract = facts.contract.as_ref();
        dimension(
            "present",
            "agent_contract_v2",
            json!({
                "purpose": specific,
                "contract_version": contract.map(|item| item.contract_version),
                "contract_digest_sha256": contract.map(|item| item.contract_digest_sha256.clone()),
            }),
        )
    };
    let knowledge_present = facts.containers > 0 || facts.stored_files > 0 || facts.ingested_files > 0;
    let authority_present = facts.contract.is_some() || facts.grant_count > 0;
    let model_ref = facts
        .principal
        .as_ref()
        .and_then(|item| item.model_ref.clone())
        .filter(|item| !item.is_empty())
        .map(|_| "present")
        .unwrap_or("absent");
    let continuity = facts.continuity_state.clone().unwrap_or_else(|| "absent".into());
    let presence_present = model_ref == "present" || continuity != "absent" || facts.alias_count > 0;
    let presence = dimension(
        if presence_present { "present" } else { "absent" },
        "agent_presence_v1",
        json!({
            "honesty": "Read model over model ref, continuity, and aliases. Swarm membership is absent and does not grant authority.",
            "model_ref": model_ref,
            "continuity": continuity,
            "aliases": facts.alias_count,
            "swarm": "absent",
            "runtime_instance": "absent",
            "child_agent": "absent",
        }),
    );
    let situation_present = facts.checkpoint_count > 0 || facts.context_state_present;
    let situation = dimension(
        if situation_present { "present" } else { "absent" },
        "situation_v1",
        json!({
            "honesty": "Assembled from checkpoints and context state. It is not task authority.",
            "checkpoint_count": facts.checkpoint_count,
            "context_state": if facts.context_state_present { "present" } else { "absent" },
            "task": "absent",
            "commitments": "absent",
        }),
    );
    json!({
        "ok": true,
        "schema": SCHEMA,
        "agent_pid": facts.api_pid,
        "inventory_complete": true,
        "agentgateway": "TARGET",
        "honesty": "Missing records stay absent. This projection does not grant authority, activate context, or admit an effect.",
        "dimensions": {
            "principal": if principal.is_some() {
                dimension("present", "intelligence_principal_v2", json!({"record": principal}))
            } else {
                dimension("absent", "intelligence_principal_v2", json!({"reason": "principal_not_stored"}))
            },
            "purpose": purpose,
            "presence": presence,
            "knowledge": dimension(
                if knowledge_present { "present" } else { "absent" },
                "asset_containers",
                json!({
                    "collections": facts.containers,
                    "stored_files": facts.stored_files,
                    "ingested_files": facts.ingested_files,
                    "eligible": "absent",
                    "active": "absent",
                    "activation": "absent",
                }),
            ),
            "directives": dimension(
                if facts.directive_count > 0 { "present" } else { "absent" },
                "directive_v1",
                json!({
                    "count": facts.directive_count,
                    "character_revision": facts.character_revision,
                    "honesty": "A directive is not a grant. A knowledge document is not a directive.",
                }),
            ),
            "authority": dimension(
                if authority_present { "present" } else { "absent" },
                "agent_contract_v2",
                json!({
                    "contract": if facts.contract.is_some() { "present" } else { "absent" },
                    "network_default": facts.contract.as_ref().map(|item| item.network_default.clone()),
                    "denied_operations": facts.contract.as_ref().map(|item| item.denied_operations.len()).unwrap_or(0),
                    "grant_count": facts.grant_count,
                }),
            ),
            "situation": situation,
        },
        "memory": {
            "status": if facts.memory_packets.is_some() { "present" } else { "absent" },
            "source": "kernel_namespace",
            "packets": facts.memory_packets,
        },
        "active_context": {
            "status": if facts.activation_id.is_some() { "present" } else { "absent" },
            "source": "activation_receipt_v1",
            "activation_id": facts.activation_id,
            "admits": false,
            "frame_drops": facts.frame_drop_count,
            "reason": if facts.activation_id.is_some() { "index of a stored context transfer" } else { "No per-generation activation receipt is stored" },
        },
        "integration": project_preflight(facts),
        "evidence": {
            "status": if facts.receipt_ids.is_empty() { "absent" } else { "present" },
            "source": "intelligence_receipt_v2",
            "receipt_ids": facts.receipt_ids,
            "explain_join": "agent_latest",
            "explain_honesty": "PARTIAL",
        },
    })
}

fn authorized(headers: &HeaderMap, pid: &str) -> bool {
    crate::services::agents::caller(headers).is_some()
        || crate::kernel::agent_identity_envelope::agent_self_access(headers, pid)
}

fn kernel_pid(state: &crate::state::PlatformState, pid: &str) -> String {
    state
        .engine_store
        .lock()
        .ok()
        .and_then(|store| {
            store
                .folder_get("agent_meta", pid)
                .ok()
                .flatten()
                .and_then(|meta| meta.get("kernel_pid").and_then(|v| v.as_str()).map(str::to_string))
        })
        .unwrap_or_else(|| pid.to_string())
}

fn collect_facts(state: &crate::state::PlatformState, pid: &str) -> WorkspaceFacts {
    let principal = agent_principal::load_principal(state, pid);
    let contract = agent_principal::load_contract(state, pid);
    let continuity = agent_principal::load_continuity(state, pid).map(|record| {
        match record.state {
            ContinuityStateV2::Verified => "verified",
            ContinuityStateV2::Broken => "broken",
            ContinuityStateV2::Unknown => "unknown",
        }
        .to_string()
    });
    let mut containers = 0usize;
    let mut container_ids = Vec::new();
    if let Ok(store) = state.engine_store.lock() {
        for key in store.folder_keys("asset_containers", None).unwrap_or_default() {
            let Some(container) = store.folder_get("asset_containers", &key).ok().flatten() else {
                continue;
            };
            if container.get("agent_pid").and_then(|v| v.as_str()) == Some(pid) {
                containers += 1;
                if let Some(id) = container.get("id").and_then(|v| v.as_str()) {
                    container_ids.push(id.to_string());
                }
            }
        }
    }
    let mut stored_files = 0usize;
    let mut ingested_files = 0usize;
    if let Ok(store) = state.engine_store.lock() {
        for key in store.folder_keys("asset_records", None).unwrap_or_default() {
            let Some(record) = store.folder_get("asset_records", &key).ok().flatten() else {
                continue;
            };
            let container_id = record.get("container_id").and_then(|v| v.as_str()).unwrap_or("");
            if !container_ids.iter().any(|id| id == container_id) {
                continue;
            }
            stored_files += 1;
            if record.get("status").and_then(|v| v.as_str()) == Some("ingested") {
                ingested_files += 1;
            }
        }
    }
    let resolved_pid = kernel_pid(state, pid);
    let memory_packets = state.kernel.lock().ok().and_then(|kernel| {
        let agent = kernel.get_agent(&resolved_pid)?;
        Some(kernel.packets_in_namespace(&agent.namespace).len())
    });
    let mut grant_count = 0usize;
    if let Ok(store) = state.engine_store.lock() {
        for key in store
            .folder_keys(crate::kernel::agent_identity_envelope::GRANT_FOLDER, None)
            .unwrap_or_default()
        {
            let Some(grant) = store
                .folder_get(crate::kernel::agent_identity_envelope::GRANT_FOLDER, &key)
                .ok()
                .flatten()
            else {
                continue;
            };
            let listed = ["readable_by", "writable_by"].into_iter().any(|field| {
                grant
                    .get(field)
                    .and_then(|v| v.as_array())
                    .is_some_and(|items| items.iter().any(|item| item.as_str() == Some(pid)))
            });
            if listed || key.contains(pid) {
                grant_count += 1;
            }
        }
    }
    if let Some(setup) = crate::kernel::agent_identity_envelope::load_setup(state, pid) {
        grant_count = grant_count.max(setup.common_spaces.len());
    }
    let identities = [
        pid.to_string(),
        principal.as_ref().map(|item| item.principal_id.clone()).unwrap_or_default(),
    ];
    let receipt_ids = crate::kernel::forensics::export_receipt_chain(state, pid)
        .into_iter()
        .map(|receipt| receipt.receipt_id)
        .collect::<Vec<_>>();
    let mut checkpoint_count = 0usize;
    let mut context_state_present = false;
    if let Ok(store) = state.engine_store.lock() {
        context_state_present = identities.iter().any(|id| {
            !id.is_empty()
                && store
                    .folder_get(crate::substrate::agent_memory::context_store::STATE_FOLDER, id)
                    .ok()
                    .flatten()
                    .is_some()
        });
        for key in store
            .folder_keys(crate::substrate::agent_memory::context_store::CHECKPOINT_FOLDER, None)
            .unwrap_or_default()
        {
            let Some(row) = store
                .folder_get(crate::substrate::agent_memory::context_store::CHECKPOINT_FOLDER, &key)
                .ok()
                .flatten()
            else {
                continue;
            };
            let agent_vid = row.get("agent_vid").and_then(|v| v.as_str()).unwrap_or("");
            if identities.iter().any(|id| !id.is_empty() && id == agent_vid) {
                checkpoint_count += 1;
            }
        }
    }
    let records = crate::services::workspace_records::record_counts(state, pid);
    WorkspaceFacts {
        api_pid: pid.to_string(),
        principal,
        contract,
        continuity_state: continuity,
        containers,
        stored_files,
        ingested_files,
        memory_packets,
        grant_count,
        receipt_ids,
        checkpoint_count,
        context_state_present,
        directive_count: records.directives,
        character_revision: records.character_revision,
        alias_count: records.aliases,
        frame_drop_count: records.frame_drops,
        activation_id: crate::services::workspace_records::latest_activation(state, pid)
            .and_then(|row| row.get("activation_id").and_then(|value| value.as_str()).map(str::to_string)),
    }
}

pub fn project_preflight(facts: &WorkspaceFacts) -> Value {
    let model_present = facts
        .principal
        .as_ref()
        .and_then(|principal| principal.model_ref.as_deref())
        .is_some_and(|model| !model.trim().is_empty());
    let purpose_present = facts
        .contract
        .as_ref()
        .is_some_and(|contract| !specific_purpose(&contract.purpose).is_empty());
    let grant_present = facts.grant_count > 0;
    let posture = if model_present && !(purpose_present && grant_present) {
        "model_only"
    } else if purpose_present && grant_present {
        "inventory_unknown"
    } else {
        "absent"
    };
    json!({
        "schema": "connector.integration_preflight.v1",
        "agent_pid": facts.api_pid,
        "posture": posture,
        "brain": if model_present { "present" } else { "absent" },
        "purpose": if purpose_present { "present" } else { "absent" },
        "authority": if grant_present { "present" } else { "absent" },
        "pate_spine": "closed",
        "runtime": "absent",
        "discovered_tools": "unauthorized",
        "inventory_complete": true,
        "agentgateway": "TARGET",
        "admits": false,
        "honesty": "A model connection stays model_only until a specific purpose and a grant exist. The HTTP effect inventory is mediated. This posture is not a mediated runtime.",
    })
}

/// GET /api/v1/agents/:pid/preflight
pub async fn get_agent_preflight(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(pid): Path<String>,
) -> Json<Value> {
    if !authorized(&headers, &pid) {
        return Json(json!({"ok": false, "error": "auth_required", "admits": false}));
    }
    Json(project_preflight(&collect_facts(state.as_ref(), &pid)))
}

/// GET /api/v1/agents/:pid/workspace
pub async fn get_agent_workspace(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(pid): Path<String>,
) -> Json<Value> {
    if !authorized(&headers, &pid) {
        return Json(json!({"ok": false, "error": "auth_required"}));
    }
    Json(project_workspace(&collect_facts(state.as_ref(), &pid)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use connector_trust::AgentContractV2;

    fn contract(purpose: &[&str]) -> AgentContractV2 {
        AgentContractV2 {
            schema: "connector.iia.v2".into(),
            agent_id: "cnktr:agent:demo".into(),
            issuer: "test".into(),
            purpose: purpose.iter().map(|item| (*item).to_string()).collect(),
            capabilities: Vec::new(),
            denied_operations: vec!["shell".into()],
            filesystem_read: Vec::new(),
            filesystem_write: Vec::new(),
            network_allow: Vec::new(),
            network_default: "deny".into(),
            receipt_required: true,
            contract_digest_sha256: "abc".into(),
            contract_version: 2,
        }
    }

    #[test]
    fn missing_records_stay_absent_and_keys_stay_out() {
        let body = project_workspace(&WorkspaceFacts {
            api_pid: "missing".into(),
            principal: None,
            contract: None,
            continuity_state: None,
            containers: 0,
            stored_files: 0,
            ingested_files: 0,
            memory_packets: None,
            grant_count: 0,
            receipt_ids: Vec::new(),
            checkpoint_count: 0,
            context_state_present: false,
            directive_count: 0,
            character_revision: None,
            alias_count: 0,
            frame_drop_count: 0,
            activation_id: None,
        });
        assert_eq!(body["inventory_complete"], true);
        assert_eq!(body["dimensions"]["principal"]["status"], "absent");
        assert_eq!(body["dimensions"]["purpose"]["status"], "absent");
        assert_eq!(body["dimensions"]["directives"]["status"], "absent");
        assert_eq!(body["dimensions"]["situation"]["status"], "absent");
        assert_eq!(body["active_context"]["status"], "absent");
        let rendered = body.to_string();
        assert!(!rendered.contains("public_key"));
        assert!(!rendered.contains("PASS"));
    }

    #[test]
    fn specific_purpose_is_present_and_general_purpose_is_absent() {
        let specific = project_workspace(&WorkspaceFacts {
            api_pid: "agent".into(),
            principal: None,
            contract: Some(contract(&["Review unpaid invoices for the finance desk"])),
            continuity_state: None,
            containers: 1,
            stored_files: 2,
            ingested_files: 1,
            memory_packets: Some(0),
            grant_count: 1,
            receipt_ids: vec!["rcpt-1".into()],
            checkpoint_count: 3,
            context_state_present: true,
            directive_count: 0,
            character_revision: None,
            alias_count: 0,
            frame_drop_count: 0,
            activation_id: None,
        });
        assert_eq!(specific["dimensions"]["purpose"]["status"], "present");
        assert_eq!(specific["dimensions"]["knowledge"]["status"], "present");
        assert_eq!(specific["dimensions"]["knowledge"]["detail"]["activation"], "absent");
        assert_eq!(specific["dimensions"]["authority"]["status"], "present");
        assert_eq!(specific["dimensions"]["presence"]["status"], "absent");
        assert_eq!(specific["dimensions"]["situation"]["detail"]["checkpoint_count"], 3);
        assert_eq!(specific["evidence"]["explain_honesty"], "PARTIAL");

        let generic = project_workspace(&WorkspaceFacts {
            api_pid: "agent".into(),
            principal: None,
            contract: Some(contract(&["general-purpose"])),
            continuity_state: None,
            containers: 0,
            stored_files: 0,
            ingested_files: 0,
            memory_packets: None,
            grant_count: 0,
            receipt_ids: Vec::new(),
            checkpoint_count: 0,
            context_state_present: false,
            directive_count: 0,
            character_revision: None,
            alias_count: 0,
            frame_drop_count: 0,
            activation_id: None,
        });
        assert_eq!(generic["dimensions"]["purpose"]["status"], "absent");
        assert_eq!(generic["dimensions"]["purpose"]["detail"]["reason"], "specific_purpose_required");
    }

    fn principal(model_ref: Option<&str>) -> connector_trust::IntelligencePrincipalV2 {
        connector_trust::IntelligencePrincipalV2 {
            schema: "connector.iia.v2".into(),
            principal_id: "cnktr:agent:demo".into(),
            issuer: "test".into(),
            authority_chain: Vec::new(),
            public_key_hex: "key".into(),
            contract_digest_sha256: "abc".into(),
            model_ref: model_ref.map(str::to_string),
            runtime_hash: None,
            intelligence_id: None,
            created_at_ms: 1,
            node_witness_pubkey_hex: None,
            contract_version: 2,
        }
    }

    fn facts_with(model: Option<&str>, purpose: &[&str], grants: usize) -> WorkspaceFacts {
        WorkspaceFacts {
            api_pid: "agent".into(),
            principal: model.map(|_| principal(model)),
            contract: Some(contract(purpose)),
            continuity_state: None,
            containers: 0,
            stored_files: 1,
            ingested_files: 0,
            memory_packets: None,
            grant_count: grants,
            receipt_ids: Vec::new(),
            checkpoint_count: 0,
            context_state_present: false,
            directive_count: 0,
            character_revision: None,
            alias_count: 0,
            frame_drop_count: 0,
            activation_id: None,
        }
    }

    #[test]
    fn preflight_does_not_claim_a_mediated_runtime() {
        let model_only = project_preflight(&facts_with(Some("grok"), &["Review unpaid invoices"], 0));
        assert_eq!(model_only["posture"], "model_only");
        assert_eq!(model_only["discovered_tools"], "unauthorized");
        assert_eq!(model_only["runtime"], "absent");
        assert_eq!(model_only["inventory_complete"], true);
        assert_eq!(model_only["pate_spine"], "closed");

        let granted = project_preflight(&facts_with(
            Some("grok"),
            &["Review unpaid invoices for the finance desk"],
            1,
        ));
        assert_eq!(granted["posture"], "inventory_unknown");
        let rendered = granted.to_string();
        assert!(!rendered.contains("mediated_microvm"));
        assert!(!rendered.contains("PASS"));
    }
}

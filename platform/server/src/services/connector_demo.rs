//! Default Demo agent. It is present on a self-hosted boot and teaches Connector from stored knowledge.
//! Playground sessions keep their own BankOps seed.

use serde_json::json;

use crate::state::SharedState;

const TAG: &str = "connector-guide";
const NAME: &str = "Demo";
const CONTAINER_ID: &str = "ac_connector_demo";
const REVISION: u64 = 2;
const ORIGIN: &str = include_str!("connector_demo_origin.md");

pub fn purpose() -> &'static str {
    "Explain what Connector is, how a turn is admitted, and what the person can do next on this node."
}

pub fn instructions() -> &'static str {
    "You are Demo, the agent that ships with Connector. When someone talks, teach Connector from the knowledge below, including why it exists and who is building it. Start with the one-sentence definition, then how a turn is admitted, then the workspace. Answer follow-up questions from that knowledge. Do not claim the product is production-ready or Connector Ready. inventory_complete, effect_mediated, and production_ready stay separate. A backend row is ready only when this node's deploy board says so. Do not run a tool, spend money, or send data off this node unless they ask and Connector admits it. If no provider key is connected, say that free-text Talk needs one."
}

pub fn knowledge_sections() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "what-connector-is.md",
            "Connector governs an intelligence from identity to consequence. A person talks to an agent. The agent may propose a tool. Connector decides whether that proposal may run. The decision is Proceed, Ask, Defer, Quarantine, or Block. Proceed is the only verdict that executes. Ask stays open for a person. A receipt records what was observed. Memory can change after an observed effect. Cease stops the generation.\n\nConnector is not the model vendor. The model answers. Connector holds the identity, the contract, the grant, and the receipt.",
        ),
        (
            "how-a-turn-works.md",
            "A turn has a principal, a purpose, and a contract. The purpose must be specific. Blank and general-purpose are refused.\n\nTalk sends the person's words to the connected model together with this agent's name, purpose, instructions, and knowledge. That chat is not a tool effect.\n\nA tool proposal is different. Admit runs identity, then PATE, then ToolDispatch only on Proceed. One mutation spends one task. A failed or unfinished Proceed closes unobserved. Ask does not execute.\n\nThis conversation proves the path: Demo is a real agent, its knowledge is stored on this node, and the model answers as Demo rather than as the vendor.",
        ),
        (
            "what-you-can-do.md",
            "On Run, Demo is the default agent. Start talking opens the workbench. The center is the conversation. The side rail is the workspace.\n\nConnect a provider key before free-text answers. Until that ping succeeds, Talk is not live.\n\nThe workspace panes are Overview, Files, Knowledge folders, Knowledge, Memory, State, Context, Behavior, Permissions, and Evidence. The seven cards are Principal, Purpose, Presence, Knowledge, Directives, Authority, and Situation. A missing record stays absent.\n\nDevGuard, TraceTramp, and WitnessCtl are institutions on the node. They are not this agent.",
        ),
        (
            "knowledge-memory-and-context.md",
            "Files, knowledge, memory, state, and context stay separate. A stored file is a source. Ingest writes a knowledge packet. Neither step makes the text eligible or active model context.\n\nThese sections are ingested so the Knowledge pane can list them. Eligible and active stay absent. Talk still receives the same text as Demo's charter, which is why the connected model can teach from it.\n\nMemory is what the agent learns later. It is not this collection. Context is the assembled turn. Upload is not context.",
        ),
        (
            "industry-stack.md",
            "The intended host stack is seven backends plus agentgateway. The seven are Keycloak, SPIFFE/SPIRE, NVIDIA OpenShell, OPA inside OpenShell, Firecracker through connector-microd, OpenTelemetry, and Sigstore cosign. agentgateway is the proposed traffic plane for LLM, MCP, A2A, HTTP, and gRPC. It is not a seventh backend, and Connector does not forward through it until that path is proven.\n\nPresence is not evidence. The deploy board at GET /api/v1/runtime/deploy-verify?profile=linux-kvm is the live reading. operational_ready is true only when that board has no blockers. This demo does not flip that flag.",
        ),
        (
            "this-demo.md",
            "Ask Demo what Connector is, how Admit works, why it exists, or who is building it. Ask what is not ready. Demo should answer from these sections and should not invent a certification.\n\nChange the agent later if you want a different purpose. This copy is the pre-default so a new node can be tried immediately.",
        ),
        ("origin.md", ORIGIN),
    ]
}

pub fn knowledge_for_charter() -> String {
    let mut out = String::new();
    for (name, body) in knowledge_sections() {
        out.push_str("# ");
        out.push_str(name.trim_end_matches(".md"));
        out.push('\n');
        out.push_str(body);
        out.push_str("\n\n");
    }
    if out.len() > 30_000 {
        out.truncate(30_000);
        out.push_str("\n[knowledge continues in the Knowledge collection]");
    }
    out
}

/// Create Demo once on a self-hosted boot. A later boot finds the same agent and fills any missing knowledge.
pub fn ensure_default_demo(state: &SharedState) {
    if crate::services::playground::is_playground_mode() {
        return;
    }
    let api_pid = match find_guide(state) {
        Some(pid) => pid,
        None => match mint_guide(state) {
            Ok(pid) => pid,
            Err(error) => {
                tracing::warn!(error = %error, "demo agent was not created");
                return;
            }
        },
    };
    if let Err(error) = ensure_knowledge(state, &api_pid) {
        tracing::warn!(error = %error, api_pid = %api_pid, "demo knowledge was not stored");
    }
    if let Err(error) = ensure_talk_session(state, &api_pid) {
        tracing::warn!(error = %error, api_pid = %api_pid, "demo talk session was not stored");
    }
}

fn find_guide(state: &SharedState) -> Option<String> {
    let es = state.engine_store.lock().ok()?;
    let keys = es.folder_keys("agent_meta", None).unwrap_or_default();
    for key in keys {
        let Some(meta) = es.folder_get("agent_meta", &key).ok().flatten() else {
            continue;
        };
        let tagged = meta
            .get("tags")
            .and_then(|v| v.as_array())
            .map(|tags| tags.iter().any(|tag| tag.as_str() == Some(TAG)))
            .unwrap_or(false);
        if tagged {
            return Some(key);
        }
    }
    None
}

fn mint_guide(state: &SharedState) -> Result<String, String> {
    let namespace = "m/connector-guide";
    let actor = crate::substrate::agent_lifecycle_gate::LifecycleActor::system("connector-demo");
    let kernel_pid = crate::substrate::agent_progeny::register_with_progeny(
        state,
        crate::substrate::agent_progeny::KernelRegisterParams {
            agent_name: NAME,
            namespace,
            role: Some("writer".into()),
            model: None,
            framework: None,
            parent_kernel_pid: None,
            reason: "default Demo agent for this node".into(),
        },
        &actor,
    )
    .map_err(|e| e.message().to_string())?;
    let api_pid = format!("agent_{}", uuid::Uuid::new_v4().as_simple());
    let knowledge = knowledge_for_charter();
    {
        let mut es = state.engine_store.lock().map_err(|_| "engine lock".to_string())?;
        let _ = es.folder_put(
            "agent_meta",
            &api_pid,
            &json!({
                "pid": api_pid,
                "kernel_pid": kernel_pid,
                "name": NAME,
                "namespace": namespace,
                "role": "writer",
                "purpose": purpose(),
                "instructions": instructions(),
                "knowledge": knowledge,
                "knowledge_revision": REVISION,
                "token_budget": 16_000,
                "tags": ["demo", TAG, "ready"],
                "user_id": "connector-boot",
                "created_by": "connector-boot",
                "created_at": chrono::Utc::now().to_rfc3339(),
                "paused": false,
            }),
        );
        let _ = es.folder_put("agent_pid_map", &kernel_pid, &json!(api_pid));
    }
    let _ = crate::kernel::agent_principal::mint_at_register(
        state.as_ref(),
        crate::kernel::agent_principal::MintPrincipalParams {
            api_pid: &api_pid,
            agent_name: NAME,
            issuer: "cnktr:org:connector-node",
            model_ref: None,
            purpose: vec![purpose().to_string()],
            capabilities: vec![
                "read".into(),
                "write".into(),
                "llm".into(),
                "chat".into(),
                "tool".into(),
                "memory".into(),
            ],
            namespace,
            master_agent_id: None,
            geo_id: None,
            knowledge_base_id: None,
        },
    );
    let _ = crate::kernel::agent_identity_envelope::bootstrap_agent_identity(
        state.as_ref(),
        &api_pid,
        NAME,
        namespace,
        "connector-demo",
        None,
    );
    crate::services::agents::ensure_talk_identity(state, &api_pid);
    let _ = crate::kernel::agent_identity_envelope::force_activate_playground(state.as_ref(), &api_pid);
    tracing::info!(api_pid = %api_pid, "default Demo agent created");
    Ok(api_pid)
}

fn ensure_knowledge(state: &SharedState, api_pid: &str) -> Result<(), String> {
    let sections = knowledge_sections();
    let knowledge = knowledge_for_charter();
    let now = chrono::Utc::now().timestamp_millis();
    let mut es = state.engine_store.lock().map_err(|_| "engine lock".to_string())?;
    let revision = es
        .folder_get("agent_meta", api_pid)
        .ok()
        .flatten()
        .and_then(|meta| meta.get("knowledge_revision").and_then(|v| v.as_u64()))
        .unwrap_or(0);
    let existing = es.folder_get("asset_containers", CONTAINER_ID).ok().flatten();
    if existing.is_none() || revision < REVISION {
        let _ = es.folder_put(
            "asset_containers",
            CONTAINER_ID,
            &json!({
                "id": CONTAINER_ID,
                "name": "Connector",
                "namespace": format!("v/{CONTAINER_ID}"),
                "allowed_types": ["md", "txt"],
                "quota_bytes": 1024 * 1024 * 1024,
                "used_bytes": 0u64,
                "asset_count": sections.len(),
                "created_at": now,
                "owner": "connector-boot",
                "agent_pid": api_pid,
            }),
        );
        let mut used = 0u64;
        for (filename, body) in &sections {
            let cid = format!("asset_demo_{}", filename.trim_end_matches(".md").replace('-', "_"));
            let size = body.len() as u64;
            used = used.saturating_add(size);
            let _ = es.folder_put(
                "asset_records",
                &cid,
                &json!({
                    "cid": cid,
                    "filename": filename,
                    "file_type": "md",
                    "size_bytes": size,
                    "container_id": CONTAINER_ID,
                    "status": "ingested",
                    "lifecycle": "ingested",
                    "eligible": "absent",
                    "active": "absent",
                    "uploaded_at": now,
                    "uploaded_by": "connector-boot",
                }),
            );
            let _ = es.folder_put("asset_content", &cid, &json!({"content": body}));
        }
        if let Some(mut container) = es.folder_get("asset_containers", CONTAINER_ID).ok().flatten() {
            container["used_bytes"] = json!(used);
            let _ = es.folder_put("asset_containers", CONTAINER_ID, &container);
        }
    }
    if let Some(mut meta) = es.folder_get("agent_meta", api_pid).ok().flatten() {
        let revision = meta.get("knowledge_revision").and_then(|v| v.as_u64()).unwrap_or(0);
        if revision < REVISION || meta.get("knowledge").and_then(|v| v.as_str()).unwrap_or("").trim().is_empty()
        {
            meta["knowledge"] = json!(knowledge);
            meta["instructions"] = json!(instructions());
            meta["purpose"] = json!(purpose());
            meta["knowledge_revision"] = json!(REVISION);
            let _ = es.folder_put("agent_meta", api_pid, &meta);
        }
    }
    Ok(())
}

fn ensure_talk_session(state: &SharedState, api_pid: &str) -> Result<(), String> {
    if !crate::kernel::workbench_session::list_sessions(state.as_ref(), api_pid).is_empty() {
        return Ok(());
    }
    crate::kernel::workbench_session::create_session(
        state.as_ref(),
        api_pid,
        Some("Talk to Demo"),
        Some(purpose()),
    )
    .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demo_knowledge_is_specific_and_fits_the_charter() {
        let purpose = purpose().to_ascii_lowercase();
        assert!(!purpose.contains("general-purpose"));
        assert!(!purpose.contains("general_purpose"));
        let knowledge = knowledge_for_charter();
        assert!(knowledge.len() <= 32_000);
        assert!(knowledge.contains("PATE"));
        assert!(knowledge.contains("Umesh Adhikari"));
        assert!(knowledge.contains("inventory_complete"));
        assert!(knowledge.contains("agentgateway"));
        assert!(knowledge_sections().len() >= 6);
        for (name, body) in knowledge_sections() {
            assert!(name.ends_with(".md"));
            assert!(!body.is_empty());
        }
    }
}

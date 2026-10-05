//! Platform-backed CLS handlers — Tool/LLM/Memory/Message/Contract.
//!
//! Replaces `ContractExecutor::stub()` on the workflow ENABLE path.
//! Tool effects enter [`crate::substrate::native_invoker`]; LLM uses PATE
//! talk admission; memory is durable in the engine store.

use std::collections::HashMap;
use std::sync::Arc;

use connector_engine::cls::{
    ContractHandler, ExecutionContext, LlmHandler, MemoryHandler, MessageHandler, ToolHandler,
};
use connector_native_contract::{
    EffectDescriptor, InvocationMode, InvocationOrigin, PackagePin,
};
use serde_json::{json, Value};

use crate::state::SharedState;
use crate::substrate::native_invoker::{self, NativeInvokeRequest};

const MEM_FOLDER: &str = "cls_agent_memory_v1";
const MSG_FOLDER: &str = "cls_message_outbox_v1";

pub struct PlatformToolHandler {
    state: SharedState,
    package: Option<PackagePin>,
    workflow_id: String,
}

pub struct PlatformLlmHandler {
    state: SharedState,
}

pub struct PlatformMemoryHandler {
    state: SharedState,
}

pub struct PlatformMessageHandler {
    state: SharedState,
    workflow_id: String,
}

pub struct PlatformContractHandler;

impl PlatformToolHandler {
    pub fn new(state: SharedState, workflow_id: &str, package: Option<PackagePin>) -> Self {
        Self {
            state,
            package,
            workflow_id: workflow_id.into(),
        }
    }
}

impl ToolHandler for PlatformToolHandler {
    fn call(
        &self,
        tool_id: &str,
        params: &HashMap<String, Value>,
        ctx: &ExecutionContext,
    ) -> Result<Value, String> {
        let params_json = serde_json::to_value(params).unwrap_or(json!({}));
        let req = NativeInvokeRequest {
            origin: InvocationOrigin {
                software_uid: Some(format!("workflow:{}", self.workflow_id)),
                workload_uid: format!("wl:{}", self.workflow_id),
                intelligence_uid: ctx.agent_pid.clone(),
                principal: format!("workflow:{}", self.workflow_id),
            },
            surface_uid: None,
            channel_uid: None,
            effect: EffectDescriptor {
                effect_class: "tool".into(),
                mutates: true,
                disclosure_class: None,
            },
            contract_ref: format!("workflow:{}", self.workflow_id),
            authority_ref: String::new(),
            lifecycle_mode: InvocationMode::default(),
            enforcement_posture: None,
            agent_pid: Some(ctx.agent_pid.clone()),
            bridge_id: Some("cls".into()),
            tool_name: Some(tool_id.into()),
            parameters: Some(params_json),
            resource: Some(format!("cls://tool/{tool_id}")),
            mint_flow_lease: false,
            destination_host: None,
            destination_port: None,
            destination_protocol: None,
            tenant_id: None,
            mission_id: Some(format!("workflow:{}", self.workflow_id)),
            idempotency_key: Some(format!(
                "{}:{}:{}",
                ctx.session_id, tool_id, ctx.current_node
            )),
            package: self.package.clone(),
            budget: None,
        };
        let result = native_invoker::invoke(&self.state, req)?;
        if matches!(
            result.pate_verdict.as_str(),
            "deny" | "ask" | "escalate"
        ) {
            return Err(format!(
                "cls_tool_denied:{}:{}",
                tool_id, result.pate_verdict
            ));
        }
        Ok(json!({
            "tool": tool_id,
            "pate_verdict": result.pate_verdict,
            "action_digest": result.action_digest,
            "flow_id": result.flow_id,
            "receipt_operation_id": result.receipt.operation_id,
            "mock": false,
            "honesty": "PlatformToolHandler → native_invoker / PATE",
        }))
    }
}

impl PlatformLlmHandler {
    pub fn new(state: SharedState) -> Self {
        Self { state }
    }
}

impl LlmHandler for PlatformLlmHandler {
    fn infer(
        &self,
        prompt: &str,
        max_tokens: u32,
        temperature: f64,
        ctx: &ExecutionContext,
    ) -> Result<(String, u32), String> {
        let _ = (max_tokens, temperature);
        let atu = crate::substrate::pate::admit_talk(
            &self.state,
            &ctx.agent_pid,
            "cls",
            prompt,
            Some(format!("cls:{}", ctx.session_id)),
        )
        .map_err(|e| format!("cls_llm_admit_denied:{e:?}"))?;
        let _ = crate::substrate::pate::complete_augmented_task(
            &self.state,
            &atu,
            "deny",
            serde_json::json!({"observed": false, "error": "cls_llm_completion_deferred"}),
        );

        let has_router = self
            .state
            .llm_router
            .read()
            .map(|g| g.is_some())
            .unwrap_or(false);
        if !has_router {
            return Err(
                "cls_llm_no_provider: talk admitted but no llm_router configured — refusing mock completion"
                    .into(),
            );
        }
        Err(
            "cls_llm_completion_deferred: PATE talk admit succeeded; sync complete path not bound in CLS handler — use Talk gateway"
                .into(),
        )
    }
}

impl PlatformMemoryHandler {
    pub fn new(state: SharedState) -> Self {
        Self { state }
    }
}

impl MemoryHandler for PlatformMemoryHandler {
    fn read(
        &self,
        namespace: &str,
        query: &str,
        max_results: u32,
        _ctx: &ExecutionContext,
    ) -> Result<Value, String> {
        let es = self
            .state
            .engine_store
            .lock()
            .map_err(|e| e.to_string())?;
        let key = format!("{namespace}");
        let stored = es
            .folder_get(MEM_FOLDER, &key)
            .map_err(|e| e.to_string())?
            .unwrap_or_else(|| json!({ "entries": [] }));
        let entries = stored
            .get("entries")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let q = query.to_ascii_lowercase();
        let filtered: Vec<Value> = entries
            .into_iter()
            .filter(|e| {
                if q.is_empty() {
                    return true;
                }
                e.to_string().to_ascii_lowercase().contains(&q)
            })
            .take(max_results as usize)
            .collect();
        Ok(json!({
            "namespace": namespace,
            "query": query,
            "results": filtered,
            "mock": false,
            "honesty": "PlatformMemoryHandler durable engine_store read",
        }))
    }

    fn write(
        &self,
        namespace: &str,
        content: &Value,
        tags: &[String],
        ctx: &ExecutionContext,
    ) -> Result<(), String> {
        let mut es = self
            .state
            .engine_store
            .lock()
            .map_err(|e| e.to_string())?;
        let key = namespace.to_string();
        let mut stored = es
            .folder_get(MEM_FOLDER, &key)
            .map_err(|e| e.to_string())?
            .unwrap_or_else(|| json!({ "entries": [] }));
        let entry = json!({
            "at": chrono::Utc::now().to_rfc3339(),
            "agent_pid": ctx.agent_pid,
            "session_id": ctx.session_id,
            "tags": tags,
            "content": content,
        });
        if let Some(arr) = stored
            .as_object_mut()
            .and_then(|o| o.get_mut("entries"))
            .and_then(|v| v.as_array_mut())
        {
            arr.push(entry);
        } else {
            stored = json!({ "entries": [entry] });
        }
        es.folder_put(MEM_FOLDER, &key, &stored)
            .map_err(|e| e.to_string())
    }
}

impl PlatformMessageHandler {
    pub fn new(state: SharedState, workflow_id: &str) -> Self {
        Self {
            state,
            workflow_id: workflow_id.into(),
        }
    }
}

impl MessageHandler for PlatformMessageHandler {
    fn send(
        &self,
        to_agent: &str,
        payload: &Value,
        ctx: &ExecutionContext,
    ) -> Result<String, String> {
        let msg_id = connector_native_contract::new_uid("clsmsg_");
        let mut es = self
            .state
            .engine_store
            .lock()
            .map_err(|e| e.to_string())?;
        let v = json!({
            "message_id": msg_id,
            "from": ctx.agent_pid,
            "to": to_agent,
            "workflow_id": self.workflow_id,
            "session_id": ctx.session_id,
            "payload": payload,
            "at": chrono::Utc::now().to_rfc3339(),
            "honesty": "Outbox durable — CNP bus delivery is separate workflow_cnp registration",
            "delivered": false,
        });
        es.folder_put(MSG_FOLDER, &msg_id, &v)
            .map_err(|e| e.to_string())?;
        Ok(msg_id)
    }
}

impl ContractHandler for PlatformContractHandler {
    fn execute(
        &self,
        contract_id: &str,
        _inputs: HashMap<String, Value>,
        _ctx: &ExecutionContext,
    ) -> Result<Value, String> {
        Err(format!(
            "cls_subcontract_requires_registry:{contract_id} — nested contracts must be registered; refusing stub success"
        ))
    }
}

/// Build a production ContractExecutor for workflow CLS activation.
pub fn platform_executor(
    state: &SharedState,
    workflow_id: &str,
    package: Option<PackagePin>,
) -> connector_engine::cls::ContractExecutor {
    use connector_engine::cls::ContractExecutor;
    ContractExecutor::new(
        Box::new(PlatformToolHandler::new(Arc::clone(state), workflow_id, package)),
        Box::new(PlatformLlmHandler::new(Arc::clone(state))),
        Box::new(PlatformMemoryHandler::new(Arc::clone(state))),
        Box::new(PlatformMessageHandler::new(Arc::clone(state), workflow_id)),
        Box::new(PlatformContractHandler),
    )
}

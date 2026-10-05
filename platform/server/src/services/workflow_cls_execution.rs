//! T3.1 — Workflow activation records execution via CLS engine + CNP.
//!
//! On ENABLE: compile once → ContractExecutor (platform handlers + durable store) →
//! persist receipt CID. Tool effects enter native_invoker/PATE.

use std::collections::HashMap;
use std::sync::Arc;

use connector_engine::cls::{ExecutionContext, ExecutionReceipt, ExecutionStore};
use connector_native_contract::PackagePin;
use serde_json::{json, Value};

use crate::{
    services::cls::{blueprint_from_connector_ir, compile_ccl_emit},
    services::cls_handlers,
    state::SharedState,
};

const CLS_RUN_FOLDER: &str = "workflow_runtime_runs";
const CLS_RECEIPT_FOLDER: &str = "cls_execution_receipts";

struct EngineStoreExecutionSink {
    state: SharedState,
    run_id: String,
}

impl ExecutionStore for EngineStoreExecutionSink {
    fn checkpoint(
        &self,
        contract_cid: &str,
        run_id: &str,
        label: &str,
        _ctx: &ExecutionContext,
    ) -> Result<(), String> {
        let mut es = self
            .state
            .engine_store
            .lock()
            .map_err(|e| e.to_string())?;
        let key = format!("{}/ckpt/{}/{}", self.run_id, run_id, label);
        let v = json!({
            "contract_cid": contract_cid,
            "run_id": run_id,
            "label": label,
            "at": chrono::Utc::now().to_rfc3339(),
        });
        es.folder_put(CLS_RECEIPT_FOLDER, &key, &v)
            .map_err(|e| e.to_string())
    }

    fn complete(&self, receipt: &ExecutionReceipt) -> Result<(), String> {
        let mut es = self
            .state
            .engine_store
            .lock()
            .map_err(|e| e.to_string())?;
        let v = serde_json::to_value(receipt).map_err(|e| e.to_string())?;
        es.folder_put(CLS_RECEIPT_FOLDER, &receipt.receipt_cid, &v)
            .map_err(|e| e.to_string())
    }
}

/// Persist a CLS-engine activation run and audit. Called when a workflow reaches **ENABLED**.
pub fn record_cls_engine_activation(
    state: &SharedState,
    workflow_id: &str,
    cls_source: &str,
    contract_name: &str,
    package: Option<&PackagePin>,
) -> Value {
    let run_id = format!("cls_{}", uuid::Uuid::new_v4().simple());
    let started_at = chrono::Utc::now().to_rfc3339();
    let package_owned = package.cloned();

    let (cls_compile, blueprint, cls_execute, receipt_cid) = match compile_ccl_emit(cls_source) {
        Ok(emit) => {
            let cls_compile = json!({
                "ok": true,
                "contract_cid": emit.cid,
                "ir_cid": emit.connector_ir.ir_cid,
                "contract_name": emit.contract.id.name,
                "block_count": emit.contract.ir.nodes.len(),
                "node_count": emit.connector_ir.node_count,
                "effect_row_count": emit.connector_ir.effect_rows.len(),
                "requires_admission": emit.connector_ir.requires_admission(),
            });
            let blueprint = blueprint_from_connector_ir(&emit.connector_ir);
            let store = Arc::new(EngineStoreExecutionSink {
                state: Arc::clone(state),
                run_id: run_id.clone(),
            });
            let mut executor =
                cls_handlers::platform_executor(state, workflow_id, package_owned).with_store(store);
            let agent = format!("workflow:{workflow_id}");
            let cls_execute = match executor.execute(
                &emit.contract,
                &agent,
                &run_id,
                HashMap::new(),
            ) {
                Ok(receipt) => {
                    let cid = receipt.receipt_cid.clone();
                    (
                        json!({
                            "ok": true,
                            "receipt_cid": cid,
                            "outcome": format!("{:?}", receipt.outcome),
                            "final_state": receipt.final_state,
                            "duration_ms": receipt.duration_ms,
                            "honesty": "ContractExecutor with PlatformTool/LLM/Memory/Message handlers — tools via native_invoker; LLM completes via Talk gateway",
                        }),
                        Some(cid),
                    )
                }
                Err(e) => (
                    json!({
                        "ok": false,
                        "error": format!("{e}"),
                        "honesty": "ContractExecutor failed after successful compile (handlers fail-closed)",
                    }),
                    None,
                ),
            };
            (cls_compile, blueprint, cls_execute.0, cls_execute.1)
        }
        Err(e) => (
            json!({ "ok": false, "error": e.message }),
            vec![],
            json!({ "ok": false, "error": "compile_failed" }),
            None,
        ),
    };

    let record = json!({
        "run_id": run_id,
        "workflow_id": workflow_id,
        "execution_path": "cls_engine_only",
        "parallel_runners_allowed": false,
        "cnp_dispatch_required": true,
        "contract_name": contract_name,
        "started_at": started_at,
        "cls_compile": cls_compile,
        "cls_execute": cls_execute,
        "receipt_cid": receipt_cid,
        "planned_actions": blueprint,
        "planned_action_count": blueprint.len(),
        "package_digest": package.map(|p| p.package_digest.clone()),
        "executor_honesty": "Platform CLS handlers + EngineStoreExecutionSink — no StubTool/Llm/Memory on ENABLE",
        "note": "Side effects occur only through CLS handlers → native_invoker/PATE + durable memory/outbox.",
    });

    {
        let mut es = state.engine_store.lock().unwrap();
        let _ = es.folder_put(CLS_RUN_FOLDER, &run_id, &record);
    }

    {
        use vac_core::types::{MemoryKernelOp, OpOutcome};
        let mut k = state.kernel.lock().unwrap();
        k.record_audit_event(
            MemoryKernelOp::PolicyCheck,
            "kernel/workflow-cls",
            Some(format!(
                "cls_engine_activation:workflow_id={workflow_id},run_id={run_id},receipt={}",
                receipt_cid.as_deref().unwrap_or("none")
            )),
            OpOutcome::Success,
            Some("workflow execution path locked to cls_engine_only".into()),
            None,
            None,
            None,
        );
        k.flush_audit_batch();
    }

    record
}

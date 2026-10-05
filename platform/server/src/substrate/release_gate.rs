//! In-process release evidence. This is not an operator journey and not Connector Ready.

use serde_json::{json, Value};

use super::pate::{
    finish_task_record, host_admission_allows_execution, AugmentedTaskUnit, EffectKind, TaskAttempt,
    TaskRefs, TaskVerdict, ToolFootprint, PATE_SCHEMA,
};

pub fn report(effect: &AugmentedTaskUnit, ask: TaskVerdict) -> Value {
    let receipt = effect.spine.receipt_id.clone().unwrap_or_default();
    let receipt_keyed = !receipt.is_empty() && receipt.contains(&effect.task_id);
    json!({
        "schema": "connector.release_gate.v1",
        "connector_ready": false,
        "operator_journey": "not_run",
        "effect_task_id": effect.task_id,
        "effect_observed": effect.spine.observed,
        "execution_attempts": effect.spine.execution_attempts,
        "ask_executed": host_admission_allows_execution(ask),
        "receipt_id": if receipt.is_empty() { Value::Null } else { Value::String(receipt) },
        "receipt_keyed_to_task": receipt_keyed,
        "honesty": "One Proceed record can commit once and carry a receipt. An Ask does not execute. The operator journey was not run. This report does not say Connector Ready.",
    })
}

fn effect_unit(task_id: &str, verdict: TaskVerdict) -> AugmentedTaskUnit {
    AugmentedTaskUnit {
        schema: PATE_SCHEMA.into(),
        task_id: task_id.into(),
        agent_pid: "agent-release".into(),
        broker_epoch: 1,
        iac_epoch: 1,
        consistency_level: 2,
        effect_kind: EffectKind::ToolDispatch,
        action_digest: "digest-release".into(),
        tool_footprint: ToolFootprint::default(),
        mission_id: None,
        mission_step_id: None,
        verdict,
        autonomy: None,
        minted_at_ms: 1,
        context_ref: None,
        spine: Default::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_observed_effect_one_ask_and_a_keyed_receipt() {
        let task_id = "pate_release_1";
        let committed = finish_task_record(
            effect_unit(task_id, TaskVerdict::Proceed),
            &TaskAttempt {
                idempotency_key: task_id.into(),
                mutating: true,
                observed: true,
            },
            TaskRefs {
                receipt_id: Some(format!("receipt:{task_id}")),
                hitl_request_id: Some("hitl-release".into()),
                ..TaskRefs::default()
            },
        )
        .expect("commit");
        let again = finish_task_record(
            committed.clone(),
            &TaskAttempt {
                idempotency_key: task_id.into(),
                mutating: true,
                observed: true,
            },
            TaskRefs::default(),
        );
        assert!(again.is_err());
        let body = report(&committed, TaskVerdict::AskHitl);
        assert_eq!(body["connector_ready"], false);
        assert_eq!(body["operator_journey"], "not_run");
        assert_eq!(body["effect_observed"], true);
        assert_eq!(body["execution_attempts"], 1);
        assert_eq!(body["ask_executed"], false);
        assert_eq!(body["receipt_keyed_to_task"], true);
        assert_eq!(body["receipt_id"], format!("receipt:{task_id}"));
        let rendered = body.to_string();
        assert!(!rendered.contains("CONNECTOR READY"));
        assert!(!rendered.contains("PASS"));
    }
}

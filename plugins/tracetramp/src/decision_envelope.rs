//! Per-`trace_events` **decision envelope** (Section 10.2 compliance plan): `schema_version`,
//! `block_flags`, `action_trace`, and `step_snapshot` for exports, PDFs, and TUI.
//! JSON Schema (draft 2020-12): `plugins/tracetramp/schemas/metadata.decision.schema.json`.
//! Cumulative timeline: `trace_projection::cumulative_action_trace_entries`.
//!
//! **Ledger contract:** [`LEDGER_CONTRACT`] documents append-only + command-only semantics
//! (blockchain-inspired integrity model; not an on-chain network).

use serde_json::json;

use crate::types::{ExecutionStep, StepResult};

pub const DECISION_SCHEMA_VERSION: u32 = 1;

/// Declares append-only `trace_events` + explicit admin commands for block/quarantine mutations (see migration `trace_events_ledger_guard`).
pub const LEDGER_CONTRACT: &str = "tracetramp_append_only_ledger_v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionPipeline {
    /// Full enforcement path (`control.rs` → `trace_events`).
    Control,
    /// Observe path (`view.rs`); `view_exempt` documents reduced enforcement.
    View,
}

fn snapshot_reason(result: &StepResult) -> Option<String> {
    match result {
        StepResult::Block { reason } => Some(reason.clone()),
        StepResult::Redact { fields } if !fields.is_empty() => {
            Some(format!("redacted fields: {}", fields.join(",")))
        }
        _ => None,
    }
}

/// Stable `block_flags` codes for SIEM / export (extend as new deny paths are added).
pub fn block_flags_for(step: &ExecutionStep, result: &StepResult) -> Vec<String> {
    match result {
        StepResult::Block { reason } => {
            let r = reason.to_ascii_lowercase();
            if r.contains("tool") && (r.contains("approv") || r.contains("permit")) {
                return vec!["tool_not_allowed".to_string()];
            }
            if r.contains("operation") && r.contains("block") {
                return vec!["operation_blocked".to_string()];
            }
            if r.contains("quarantine") {
                return vec!["quarantine".to_string()];
            }
            if r.contains("pii") {
                return vec!["pii_violation".to_string()];
            }
            if r.contains("budget") || r.contains("exhausted") {
                return vec!["budget_exhausted".to_string()];
            }
            if r.contains("kernel") || r.contains("attachment") {
                return vec!["kernel_host_not_ready".to_string()];
            }
            // Policy / generic block
            if matches!(step, ExecutionStep::PolicyChecked) {
                return vec!["policy_blocked".to_string()];
            }
            vec!["policy_blocked".to_string()]
        }
        StepResult::RequireApproval { .. } => vec!["hitl_pending".to_string()],
        _ => vec![],
    }
}

fn trace_entry(step: &ExecutionStep, result: &StepResult) -> serde_json::Value {
    json!({
        "step": format!("{:?}", step),
        "result": format!("{:?}", result),
        "reason": snapshot_reason(result),
    })
}

/// JSON merged under `trace_events.metadata.decision` (Control) or embedded in View log payloads.
pub fn decision_envelope(
    step: &ExecutionStep,
    result: &StepResult,
    pipeline: DecisionPipeline,
) -> serde_json::Value {
    let entry = trace_entry(step, result);
    let (pipeline_s, view_exempt) = match pipeline {
        DecisionPipeline::Control => ("control", false),
        DecisionPipeline::View => ("view", true),
    };
    json!({
        "schema_version": DECISION_SCHEMA_VERSION,
        "pipeline": pipeline_s,
        "view_exempt": view_exempt,
        "ledger_contract": LEDGER_CONTRACT,
        "block_flags": block_flags_for(step, result),
        "step_snapshot": entry.clone(),
        "action_trace": [entry],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ExecutionStep, StepResult};

    #[test]
    fn envelope_carries_ledger_contract() {
        let v = decision_envelope(
            &ExecutionStep::PolicyChecked,
            &StepResult::Allow,
            DecisionPipeline::Control,
        );
        assert_eq!(
            v.get("ledger_contract").and_then(|x| x.as_str()),
            Some(LEDGER_CONTRACT)
        );
    }

    #[test]
    fn tool_block_maps_flag() {
        let flags = block_flags_for(
            &ExecutionStep::ToolBlocked,
            &StepResult::Block {
                reason: "Tool bash not approved".into(),
            },
        );
        assert!(flags.contains(&"tool_not_allowed".to_string()));
    }

    #[test]
    fn success_has_empty_flags() {
        let flags = block_flags_for(&ExecutionStep::RequestReceived, &StepResult::Success);
        assert!(flags.is_empty());
    }

    #[test]
    fn envelope_has_action_trace_and_pipeline() {
        let v = decision_envelope(
            &ExecutionStep::RequestReceived,
            &StepResult::Success,
            DecisionPipeline::Control,
        );
        assert_eq!(v["pipeline"], "control");
        assert_eq!(v["view_exempt"], false);
        assert!(v.get("action_trace").and_then(|x| x.as_array()).is_some());
    }
}

//! Deterministic fallback ladder after verify failure.
//! Every substitute path requires a fresh ActionBinding (new digest).

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const FALLBACK_SCHEMA: &str = "connector.fallback_ladder.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FallbackStep {
    Verify,
    Retrieve,
    Simulate,
    Shrink,
    Substitute,
    Wait,
    Ask,
    Halt,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FallbackDecision {
    pub schema: String,
    pub step: FallbackStep,
    pub reason: String,
    pub requires_new_binding: bool,
    pub next: Option<FallbackStep>,
}

/// Advance the ladder given verify outcome and attempt count.
pub fn next_step(verify_ok: bool, attempt: u32, can_retrieve: bool, can_simulate: bool) -> FallbackDecision {
    if verify_ok {
        return FallbackDecision {
            schema: FALLBACK_SCHEMA.into(),
            step: FallbackStep::Verify,
            reason: "verify_ok".into(),
            requires_new_binding: false,
            next: None,
        };
    }
    let step = match attempt {
        0 if can_retrieve => FallbackStep::Retrieve,
        0 => FallbackStep::Shrink,
        1 if can_simulate => FallbackStep::Simulate,
        1 => FallbackStep::Shrink,
        2 => FallbackStep::Shrink,
        3 => FallbackStep::Substitute,
        4 => FallbackStep::Wait,
        5 => FallbackStep::Ask,
        _ => FallbackStep::Halt,
    };
    let requires_new_binding = matches!(
        step,
        FallbackStep::Substitute | FallbackStep::Shrink | FallbackStep::Ask
    );
    let next = match step {
        FallbackStep::Halt => None,
        FallbackStep::Ask => Some(FallbackStep::Halt),
        FallbackStep::Wait => Some(FallbackStep::Ask),
        FallbackStep::Substitute => Some(FallbackStep::Wait),
        FallbackStep::Shrink => Some(FallbackStep::Substitute),
        FallbackStep::Simulate => Some(FallbackStep::Shrink),
        FallbackStep::Retrieve => Some(FallbackStep::Simulate),
        FallbackStep::Verify => Some(FallbackStep::Retrieve),
    };
    FallbackDecision {
        schema: FALLBACK_SCHEMA.into(),
        step,
        reason: format!("verify_failed_attempt_{attempt}"),
        requires_new_binding,
        next,
    }
}

pub fn to_json(d: &FallbackDecision) -> Value {
    serde_json::to_value(d).unwrap_or(json!({ "ok": false }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ladder_ends_in_halt() {
        let d = next_step(false, 99, true, true);
        assert_eq!(d.step, FallbackStep::Halt);
    }

    #[test]
    fn substitute_needs_new_binding() {
        let d = next_step(false, 3, true, true);
        assert!(d.requires_new_binding);
        assert_eq!(d.step, FallbackStep::Substitute);
    }
}

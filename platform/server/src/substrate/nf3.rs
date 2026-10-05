//! NF³ — categorical invariant verdicts (cognition/correction cannot authorize).
//!
//! Hard invariants are pass/fail. Soft cognition scores never compensate.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::kernel::action_binding::ActionBinding;
use crate::substrate::pate::ToolFootprint;
use crate::substrate::rgo::{self, OversightMode, ReversibilityClass};

pub const NF3_SCHEMA: &str = "connector.nf3.invariant.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvariantVerdict {
    Pass,
    Fail,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvariantCheck {
    pub id: String,
    pub verdict: InvariantVerdict,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Nf3Report {
    pub schema: String,
    pub ok: bool,
    pub checks: Vec<InvariantCheck>,
    /// Soft scores — informational only; never flip Fail→Pass.
    pub cognition_hint: f32,
    pub correction_hint: f32,
}

fn check(id: &str, ok: bool, detail: impl Into<String>) -> InvariantCheck {
    InvariantCheck {
        id: id.into(),
        verdict: if ok {
            InvariantVerdict::Pass
        } else {
            InvariantVerdict::Fail
        },
        detail: detail.into(),
    }
}

/// Evaluate categorical invariants for an admitted effect.
pub fn evaluate_invariants(
    binding: &ActionBinding,
    footprint: &ToolFootprint,
    oversight: OversightMode,
) -> Nf3Report {
    let mut checks = Vec::new();

    checks.push(check(
        "identity_bound",
        !binding.agent_pid.trim().is_empty(),
        "ActionBinding must name an agent_pid",
    ));
    checks.push(check(
        "digest_present",
        binding.digest_hex().len() >= 16,
        "Action digest must be present",
    ));
    checks.push(check(
        "reversibility_declared",
        !footprint.reversibility.is_empty(),
        "ToolFootprint.reversibility required (RGO)",
    ));

    let class = ReversibilityClass::from_label(&footprint.reversibility);
    let r3_ok = if class >= ReversibilityClass::R3Irreversible {
        !matches!(oversight, OversightMode::Autonomous)
    } else {
        true
    };
    checks.push(check(
        "r3_oversight",
        r3_ok,
        format!("R3 class={} oversight={:?}", class.as_str(), oversight),
    ));

    // Unknown capability → must not silently Autonomous on R3.
    if footprint.conp_capability.is_some()
        && class == ReversibilityClass::R3Irreversible
        && matches!(oversight, OversightMode::Autonomous)
    {
        checks.push(check(
            "unknown_or_r3_not_autonomous",
            false,
            "R3 CONP cannot resolve to Autonomous",
        ));
    } else {
        checks.push(check(
            "unknown_or_r3_not_autonomous",
            true,
            "oversight proportional to class",
        ));
    }

    let ok = checks.iter().all(|c| c.verdict == InvariantVerdict::Pass);
    Nf3Report {
        schema: NF3_SCHEMA.into(),
        ok,
        checks,
        cognition_hint: 0.0,
        correction_hint: 0.0,
    }
}

pub fn report_json(report: &Nf3Report) -> Value {
    serde_json::to_value(report).unwrap_or(json!({ "ok": false }))
}

/// Convenience: classify + resolve + invariant gate for PATE pre-commit.
pub fn gate_effect(
    binding: &ActionBinding,
    footprint: &ToolFootprint,
    egcm_disorder_bump: bool,
) -> (OversightMode, Nf3Report) {
    let class = rgo::classify_action(binding, footprint);
    let mode = rgo::resolve_oversight(class, rgo::autonomy_tier(), egcm_disorder_bump);
    let report = evaluate_invariants(binding, footprint, mode);
    (mode, report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::action_binding::ActionBinding;
    use serde_json::json;

    #[test]
    fn empty_pid_fails() {
        let b = ActionBinding::new(" ", "op", "t", "r", json!({}), None, "1", None);
        let fp = ToolFootprint {
            reversibility: "R1".into(),
            ..Default::default()
        };
        let r = evaluate_invariants(&b, &fp, OversightMode::Autonomous);
        assert!(!r.ok);
    }
}

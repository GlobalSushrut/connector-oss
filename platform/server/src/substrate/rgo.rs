//! RGO — Reversibility-Graded Oversight.
//!
//! Sits after static contracts / ActionBinding and before PATE commit.
//! Answers: does this crossing need a human, or can automation proceed?

use serde::{Deserialize, Serialize};

use crate::kernel::action_binding::ActionBinding;
use crate::substrate::pate::ToolFootprint;
use connector_protocol::{ProtocolCapabilityRegistry, RiskLevel};

/// Design-time reversibility class — not LLM-asserted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReversibilityClass {
    R0ReadOnly = 0,
    R1Reversible = 1,
    R2ExternalReversible = 2,
    R3Irreversible = 3,
}

impl ReversibilityClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::R0ReadOnly => "R0",
            Self::R1Reversible => "R1",
            Self::R2ExternalReversible => "R2",
            Self::R3Irreversible => "R3",
        }
    }

    pub fn from_label(s: &str) -> Self {
        match s.trim().to_ascii_uppercase().as_str() {
            "R0" | "READ" | "READONLY" | "OBSERVE" => Self::R0ReadOnly,
            "R1" | "LOW" | "REVERSIBLE" => Self::R1Reversible,
            "R2" | "MEDIUM" | "EXTERNAL" => Self::R2ExternalReversible,
            _ => Self::R3Irreversible, // unknown → R3 fail-closed for that action
        }
    }

    /// Map gateway / CP risk_class strings.
    pub fn from_risk_class(risk: &str) -> Self {
        match risk {
            "r0" | "read" | "observe" => Self::R0ReadOnly,
            "r1" | "low" | "normal" | "tool" | "llm" => Self::R1Reversible,
            "r2" | "medium" | "high" => Self::R2ExternalReversible,
            "irreversible" | "critical" | "estop" => Self::R3Irreversible,
            _ => Self::R3Irreversible,
        }
    }

    pub fn from_cp(level: RiskLevel) -> Self {
        match level {
            RiskLevel::Low => Self::R1Reversible,
            RiskLevel::Medium => Self::R2ExternalReversible,
            RiskLevel::High | RiskLevel::Critical => Self::R3Irreversible,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OversightMode {
    Autonomous,
    Hotl,
    HitlDigest,
    Halt,
}

/// CONNECTOR_AUTONOMY_TIER 1–4 (default 2 playground / 3 production).
pub fn autonomy_tier() -> u8 {
    let default = if crate::services::playground::is_playground_mode() {
        2
    } else {
        3
    };
    std::env::var("CONNECTOR_AUTONOMY_TIER")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
        .clamp(1, 4)
}

pub fn classify_action(binding: &ActionBinding, footprint: &ToolFootprint) -> ReversibilityClass {
    if !footprint.reversibility.is_empty() {
        return ReversibilityClass::from_label(&footprint.reversibility);
    }
    if let Some(cap) = footprint.conp_capability.as_deref() {
        let reg = ProtocolCapabilityRegistry::with_defaults();
        if let Some(c) = reg.get(cap) {
            return ReversibilityClass::from_cp(c.risk);
        }
        return ReversibilityClass::R3Irreversible;
    }
    let _ = binding;
    ReversibilityClass::from_risk_class(&footprint.risk_class)
}

/// Worst-case across a reachable plan frontier.
pub fn worst_case_chain(classes: &[ReversibilityClass]) -> ReversibilityClass {
    classes
        .iter()
        .copied()
        .max()
        .unwrap_or(ReversibilityClass::R3Irreversible)
}

/// Resolve oversight from class + autonomy tier (+ optional EGCM disorder bump).
pub fn resolve_oversight(
    class: ReversibilityClass,
    tier: u8,
    egcm_disorder_bump: bool,
) -> OversightMode {
    let mut class = class;
    if egcm_disorder_bump && class < ReversibilityClass::R3Irreversible {
        class = match class {
            ReversibilityClass::R0ReadOnly => ReversibilityClass::R1Reversible,
            ReversibilityClass::R1Reversible => ReversibilityClass::R2ExternalReversible,
            ReversibilityClass::R2ExternalReversible => ReversibilityClass::R3Irreversible,
            ReversibilityClass::R3Irreversible => ReversibilityClass::R3Irreversible,
        };
    }
    match tier {
        1 => match class {
            ReversibilityClass::R0ReadOnly | ReversibilityClass::R1Reversible => OversightMode::Hotl,
            _ => OversightMode::HitlDigest,
        },
        2 => match class {
            ReversibilityClass::R0ReadOnly | ReversibilityClass::R1Reversible => {
                OversightMode::Autonomous
            }
            ReversibilityClass::R2ExternalReversible | ReversibilityClass::R3Irreversible => {
                OversightMode::HitlDigest
            }
        },
        3 => match class {
            ReversibilityClass::R0ReadOnly | ReversibilityClass::R1Reversible => {
                OversightMode::Autonomous
            }
            ReversibilityClass::R2ExternalReversible => OversightMode::Hotl,
            ReversibilityClass::R3Irreversible => OversightMode::HitlDigest,
        },
        _ => match class {
            ReversibilityClass::R3Irreversible => OversightMode::HitlDigest,
            _ => OversightMode::Autonomous,
        },
    }
}

/// E-stop ambient: always Autonomous (still audited by ActionBinding).
pub fn estop_oversight() -> OversightMode {
    OversightMode::Autonomous
}

/// PACE fail-posture when verifier/EGCM is degraded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaceFailPosture {
    FailOpenLiveness,
    FailClosedIrreversibleOnly,
    FailClosedR2Plus,
    FailClosedAllEffects,
}

pub fn pace_fail_posture(tier: u8) -> PaceFailPosture {
    match tier {
        1 => PaceFailPosture::FailOpenLiveness,
        2 => PaceFailPosture::FailClosedIrreversibleOnly,
        3 => PaceFailPosture::FailClosedR2Plus,
        _ => PaceFailPosture::FailClosedAllEffects,
    }
}

pub fn autonomy_posture_json() -> serde_json::Value {
    let tier = autonomy_tier();
    serde_json::json!({
        "schema": "connector.autonomy_tier.v1",
        "tier": tier,
        "pace_fail_posture": pace_fail_posture(tier),
        "env": "CONNECTOR_AUTONOMY_TIER",
        "honesty": "RGO oversight scales with tier; ActionBinding remains SoT for digests",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_is_r3() {
        assert_eq!(
            ReversibilityClass::from_label("wat"),
            ReversibilityClass::R3Irreversible
        );
    }

    #[test]
    fn chain_takes_max() {
        let c = worst_case_chain(&[
            ReversibilityClass::R0ReadOnly,
            ReversibilityClass::R2ExternalReversible,
            ReversibilityClass::R1Reversible,
        ]);
        assert_eq!(c, ReversibilityClass::R2ExternalReversible);
    }

    #[test]
    fn tier2_r1_autonomous() {
        assert_eq!(
            resolve_oversight(ReversibilityClass::R1Reversible, 2, false),
            OversightMode::Autonomous
        );
        assert_eq!(
            resolve_oversight(ReversibilityClass::R3Irreversible, 2, false),
            OversightMode::HitlDigest
        );
    }

    #[test]
    fn harden_suite_r0_r1_r3() {
        // S21–S23: R0/R1 proportional; R3 never Autonomous under tiers 1–3.
        for tier in [1u8, 2, 3] {
            assert_ne!(
                resolve_oversight(ReversibilityClass::R3Irreversible, tier, false),
                OversightMode::Autonomous,
                "R3 must not be Autonomous at tier {tier}"
            );
        }
        // Tier 2: R0/R1 Autonomous; R2 HITL
        assert_eq!(
            resolve_oversight(ReversibilityClass::R0ReadOnly, 2, false),
            OversightMode::Autonomous
        );
        assert_eq!(
            resolve_oversight(ReversibilityClass::R2ExternalReversible, 2, false),
            OversightMode::HitlDigest
        );
        // Tier 1: even R0 is HOTL (human-on-the-loop)
        assert_eq!(
            resolve_oversight(ReversibilityClass::R0ReadOnly, 1, false),
            OversightMode::Hotl
        );
    }
}

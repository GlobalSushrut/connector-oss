//! SGKE basic gate — κ/Ψ × placement deny on outbound effect (P6.6 / I-19).
//!
//! High intelligence magnitude (I) without hardware/placement presence (H) is denied.
//! Spectral vocabulary aligns with `services::kecs_calculator::ComplexSpectral` (I ≈ |ψ|).

use connector_trust::HardwarePlacementV2;
use serde::{Deserialize, Serialize};

/// Default I threshold above which missing H fails closed.
pub const SGKE_HIGH_I_THRESHOLD: f64 = 0.7;

/// Reason codes returned to callers / actionlog.
pub const REASON_HIGH_I_MISSING_H: &str = "sgke_high_i_missing_h";
pub const REASON_ALLOW: &str = "sgke_allow";

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SgkeVerdict {
    Allow,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SgkeDecision {
    pub verdict: SgkeVerdict,
    pub reason_code: String,
    pub intelligence_magnitude: f64,
    pub hardware_present: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// True when placement carries usable H⃗ (region + at least one endpoint or capability).
pub fn hardware_placement_present(placement: &HardwarePlacementV2) -> bool {
    let region_ok = !placement.region.trim().is_empty()
        && placement.region.trim().to_ascii_lowercase() != "unknown";
    let endpoints_ok = !placement.endpoints.is_empty();
    let caps_ok = !placement.capabilities.is_empty();
    region_ok && (endpoints_ok || caps_ok || placement.cell_id.is_some())
}

/// Intelligence magnitude from complex spectral components (I ≈ √(re²+im²)).
pub fn intelligence_magnitude(re: f64, im: f64) -> f64 {
    (re.powi(2) + im.powi(2)).sqrt()
}

/// Basic SGKE deny: high I without H → deny.
pub fn evaluate_sgke_gate(intelligence_magnitude: f64, hardware_present: bool) -> SgkeDecision {
    evaluate_sgke_gate_threshold(intelligence_magnitude, hardware_present, SGKE_HIGH_I_THRESHOLD)
}

pub fn evaluate_sgke_gate_threshold(
    intelligence_magnitude: f64,
    hardware_present: bool,
    high_i_threshold: f64,
) -> SgkeDecision {
    let i = intelligence_magnitude.clamp(0.0, f64::MAX);
    if i >= high_i_threshold && !hardware_present {
        return SgkeDecision {
            verdict: SgkeVerdict::Deny,
            reason_code: REASON_HIGH_I_MISSING_H.into(),
            intelligence_magnitude: i,
            hardware_present,
            message: Some(
                "Denied-by-SGKE: high intelligence magnitude without hardware/placement (H)".into(),
            ),
        };
    }
    SgkeDecision {
        verdict: SgkeVerdict::Allow,
        reason_code: REASON_ALLOW.into(),
        intelligence_magnitude: i,
        hardware_present,
        message: None,
    }
}

/// Evaluate from ComplexSpectral-shaped re/im + optional placement.
pub fn evaluate_from_spectral(
    re: f64,
    im: f64,
    placement: Option<&HardwarePlacementV2>,
) -> SgkeDecision {
    let i = intelligence_magnitude(re, im);
    let h = placement.map(hardware_placement_present).unwrap_or(false);
    evaluate_sgke_gate(i, h)
}

/// Convenience for gateway egress: deny → JSON error body.
pub fn deny_json(decision: &SgkeDecision) -> serde_json::Value {
    serde_json::json!({
        "ok": false,
        "error": decision.reason_code,
        "sgke": decision,
        "message": decision.message.clone().unwrap_or_else(|| "SGKE gate denied egress".into()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use connector_trust::HardwarePlacementV2;

    #[test]
    fn high_i_missing_h_denied() {
        let d = evaluate_sgke_gate(0.95, false);
        assert_eq!(d.verdict, SgkeVerdict::Deny);
        assert_eq!(d.reason_code, REASON_HIGH_I_MISSING_H);
    }

    #[test]
    fn high_i_with_h_allowed() {
        let d = evaluate_sgke_gate(0.95, true);
        assert_eq!(d.verdict, SgkeVerdict::Allow);
    }

    #[test]
    fn low_i_without_h_allowed() {
        let d = evaluate_sgke_gate(0.2, false);
        assert_eq!(d.verdict, SgkeVerdict::Allow);
    }

    #[test]
    fn spectral_plus_placement() {
        let placement = HardwarePlacementV2::new("us-east-1")
            .with_cell_id("cell-1")
            .with_capabilities(vec!["llm".into()]);
        let deny = evaluate_from_spectral(0.8, 0.6, None);
        assert_eq!(deny.verdict, SgkeVerdict::Deny);
        let allow = evaluate_from_spectral(0.8, 0.6, Some(&placement));
        assert_eq!(allow.verdict, SgkeVerdict::Allow);
        assert!(hardware_placement_present(&placement));
    }

    #[test]
    fn empty_region_not_present() {
        let p = HardwarePlacementV2::new("unknown");
        assert!(!hardware_placement_present(&p));
    }
}

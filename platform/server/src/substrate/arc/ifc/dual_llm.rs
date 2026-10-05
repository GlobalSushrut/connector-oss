//! Dual-LLM quarantine summary (D4) — LAB only; never expands AutonomyVolume.

use serde_json::{json, Value};

use crate::substrate::arc::autonomy_volume::{AutonomyVolume, EnforcementGrade};
use crate::substrate::arc::flags::ArcFlags;

pub const SCHEMA: &str = "connector.arc.dual_llm_summary.v1";

/// Produce a quarantine-safe summary for operator/HITL surfaces.
/// Honesty: does **not** change \(\mathcal{A}\); Observed-grade LAB path.
pub fn quarantine_summary(agent_id: &str, raw_excerpt: &str) -> Value {
    let flags = ArcFlags::from_env();
    let truncated: String = raw_excerpt.chars().take(240).collect();
    let redacted = truncated
        .replace('@', "[at]")
        .chars()
        .map(|c| {
            if c.is_ascii_digit() {
                '#'
            } else {
                c
            }
        })
        .collect::<String>();

    json!({
        "schema": SCHEMA,
        "agent_id": agent_id,
        "summary": redacted,
        "grade": format!("{:?}", EnforcementGrade::Observed),
        "expands_autonomy": false,
        "lab_only": !flags.harden,
        "honesty": "Dual-LLM quarantine summary is advisory — never Admit / never expands A",
        "flag": "CONNECTOR_ARC_IFC",
    })
}

/// Explicit fence: summary path cannot raise autonomy volume.
pub fn assert_does_not_expand_a(
    before: &AutonomyVolume,
    after: &AutonomyVolume,
) -> Result<(), String> {
    if after.digest() != before.digest() {
        // Allow identical; any digest change treated as potential expand unless meet-equal.
        // Conservative: deny any change from summary path.
        return Err("dual_llm summary must not mutate AutonomyVolume".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::substrate::arc::autonomy_volume::AutonomyFacets;

    #[test]
    fn summary_does_not_claim_effective() {
        let s = quarantine_summary("a1", "secret 12345 email@x.com");
        assert_eq!(s["expands_autonomy"], false);
        assert!(!s["summary"].as_str().unwrap().contains('@'));
        assert!(!s["summary"].as_str().unwrap().contains('1'));
    }

    #[test]
    fn volume_unchanged() {
        let v = AutonomyVolume::from_facets(AutonomyFacets::lab_partial_v0());
        assert!(assert_does_not_expand_a(&v, &v).is_ok());
    }
}

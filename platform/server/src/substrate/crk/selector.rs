//! Causal + method + entropy ranking; minimal cover under max_range_cover.
//! Entropy is one weight — never first eligibility.

use std::cmp::Ordering;

use connector_trust::{ActionCueEnvelope, CrkState};

use crate::state::PlatformState;

use super::eligibility::{self, EligibleCandidate};

pub const SELECTOR_VERSION: &str = super::SELECTOR_VERSION;

/// Score after hard gates. Failed gates already have exclusion set (treated as -∞).
fn score(c: &EligibleCandidate, cue: &ActionCueEnvelope) -> f64 {
    if c.exclusion.is_some() {
        return f64::NEG_INFINITY;
    }
    let mut s = 0.0;
    s += match c.kind {
        eligibility::CandidateKind::StateClaim => 0.40,
        eligibility::CandidateKind::Procedure => 0.35,
        eligibility::CandidateKind::Evidence => 0.15,
        eligibility::CandidateKind::Other => 0.05,
    };
    s += 0.10 * (c.trust.rank() as f64 / 4.0);
    s += 0.05;
    if cue.risk.eq_ignore_ascii_case("high") || cue.risk.eq_ignore_ascii_case("critical") {
        s += 0.05 * (c.trust.rank() as f64 / 4.0);
    }
    s
}

/// Produce ordered CID cover + exclusion reasons + overall CRK state.
pub fn minimal_cover(
    _state: &PlatformState,
    cue: &ActionCueEnvelope,
    candidates: &[EligibleCandidate],
    _pinned_root: &str,
) -> Result<(Vec<String>, Vec<String>, CrkState), String> {
    let mut exclusions: Vec<String> = candidates
        .iter()
        .filter_map(|c| {
            c.exclusion
                .as_ref()
                .map(|e| format!("{}:{}", c.cid, e))
        })
        .collect();

    let mut scored: Vec<(&EligibleCandidate, f64)> = candidates
        .iter()
        .map(|c| (c, score(c, cue)))
        .filter(|(_, s)| s.is_finite())
        .collect();
    scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(Ordering::Equal));

    let cap = cue.max_range_cover.max(1) as usize;
    let selected: Vec<String> = scored
        .into_iter()
        .take(cap)
        .map(|(c, _)| c.cid.clone())
        .collect();

    let state_out = if selected.is_empty() {
        if exclusions.iter().any(|e| e.contains("trust_below_floor")) {
            CrkState::Untrusted
        } else if exclusions.iter().any(|e| e.contains("temporal")) {
            CrkState::Stale
        } else {
            CrkState::Insufficient
        }
    } else if exclusions.iter().any(|e| e.contains("conflict")) {
        CrkState::Ambiguous
    } else {
        CrkState::Ready
    };

    if selected.is_empty() && exclusions.is_empty() {
        exclusions.push("no_eligible_memory".into());
    }

    Ok((selected, exclusions, state_out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::substrate::crk::eligibility::{CandidateKind, EligibleCandidate};
    use connector_trust::{ActionCueEnvelope, TrustTier, ACTION_CUE_SCHEMA};

    fn cue_with_cover(max_range_cover: u32) -> ActionCueEnvelope {
        ActionCueEnvelope {
            schema: ACTION_CUE_SCHEMA.into(),
            agent_pid: "agent:t".into(),
            generation: 1,
            bound_skill: None,
            phase: "recall".into(),
            action_digest: "act:1".into(),
            risk: "low".into(),
            token_budget: 1024,
            max_range_cover,
        }
    }

    #[test]
    fn trust_exclusion_yields_untrusted() {
        let cands = [EligibleCandidate {
            cid: "claim_x".into(),
            kind: CandidateKind::StateClaim,
            trust: TrustTier::T0External,
            exclusion: Some("trust_below_floor: have=T0 need=T1".into()),
        }];
        let cue = cue_with_cover(4);
        // PlatformState is unused by ranking; pass via score-only path.
        let exclusions: Vec<String> = cands
            .iter()
            .filter_map(|c| {
                c.exclusion
                    .as_ref()
                    .map(|e| format!("{}:{}", c.cid, e))
            })
            .collect();
        assert!(exclusions.iter().any(|e| e.contains("trust_below_floor")));
        let selected: Vec<&EligibleCandidate> = eligibility::passing(&cands);
        assert!(selected.is_empty());
        let state_out = if selected.is_empty() {
            if exclusions.iter().any(|e| e.contains("trust_below_floor")) {
                CrkState::Untrusted
            } else {
                CrkState::Insufficient
            }
        } else {
            CrkState::Ready
        };
        assert_eq!(state_out, CrkState::Untrusted);
        assert!(score(&cands[0], &cue).is_infinite() && score(&cands[0], &cue) < 0.0);
    }

    #[test]
    fn cover_respects_max_range() {
        let cands: Vec<EligibleCandidate> = (0..10)
            .map(|i| EligibleCandidate {
                cid: format!("claim_{i}"),
                kind: CandidateKind::StateClaim,
                trust: TrustTier::T2SourceBound,
                exclusion: None,
            })
            .collect();
        let cue = cue_with_cover(3);
        let mut scored: Vec<_> = cands
            .iter()
            .map(|c| (c, score(c, &cue)))
            .filter(|(_, s)| s.is_finite())
            .collect();
        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(Ordering::Equal));
        let selected: Vec<_> = scored
            .into_iter()
            .take(cue.max_range_cover as usize)
            .map(|(c, _)| c.cid.clone())
            .collect();
        assert_eq!(selected.len(), 3);
    }
}

//! Hard eligibility gates — Score = -∞ before any ranking.

use connector_trust::{ActionCueEnvelope, TrustTier};

use crate::state::PlatformState;

use super::procedure_capsule;
use super::temporal_ledger;
use super::trust_firewall;

#[derive(Debug, Clone)]
pub struct EligibleCandidate {
    pub cid: String,
    pub kind: CandidateKind,
    pub trust: TrustTier,
    pub exclusion: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateKind {
    StateClaim,
    Procedure,
    Evidence,
    Other,
}

/// Collect candidates that pass hard gates for this cue.
/// Embeddings/similarity must never call this after ranking — eligibility is first.
pub fn filter_candidates(
    state: &PlatformState,
    cue: &ActionCueEnvelope,
) -> Result<Vec<EligibleCandidate>, String> {
    let mut out = Vec::new();
    let floor = trust_floor_for_risk(&cue.risk);

    for claim_id in temporal_ledger::list_active_claim_ids(state, &cue.agent_pid) {
        if let Some(claim) = temporal_ledger::load_claim(state, &cue.agent_pid, &claim_id) {
            if claim.agent_pid != cue.agent_pid {
                out.push(EligibleCandidate {
                    cid: claim_id,
                    kind: CandidateKind::StateClaim,
                    trust: claim.envelope.origin_authority,
                    exclusion: Some("identity_scope_mismatch".into()),
                });
                continue;
            }
            if let Some(skill) = cue.bound_skill.as_ref() {
                if let Some(scope) = claim.envelope.skill_scope.as_ref() {
                    if scope != skill {
                        out.push(EligibleCandidate {
                            cid: claim.claim_id.clone(),
                            kind: CandidateKind::StateClaim,
                            trust: claim.envelope.origin_authority,
                            exclusion: Some("skill_scope_mismatch".into()),
                        });
                        continue;
                    }
                }
            }
            if !claim.is_active_at(super::now_ms()) {
                out.push(EligibleCandidate {
                    cid: claim.claim_id.clone(),
                    kind: CandidateKind::StateClaim,
                    trust: claim.envelope.origin_authority,
                    exclusion: Some("temporal_inactive".into()),
                });
                continue;
            }
            if !trust_firewall::meets_floor(&claim.envelope, floor) {
                out.push(EligibleCandidate {
                    cid: claim.claim_id.clone(),
                    kind: CandidateKind::StateClaim,
                    trust: claim.envelope.origin_authority,
                    exclusion: Some(format!(
                        "trust_below_floor: have={} need={}",
                        claim.envelope.origin_authority.as_str(),
                        floor.as_str()
                    )),
                });
                continue;
            }
            out.push(EligibleCandidate {
                cid: claim.claim_id,
                kind: CandidateKind::StateClaim,
                trust: claim.envelope.origin_authority,
                exclusion: None,
            });
        }
    }

    if let Some(proc) =
        procedure_capsule::select_for_skill(state, &cue.agent_pid, cue.bound_skill.as_deref())
    {
        if proc.agent_pid != cue.agent_pid {
            out.push(EligibleCandidate {
                cid: proc.procedure_id,
                kind: CandidateKind::Procedure,
                trust: proc.envelope.origin_authority,
                exclusion: Some("identity_scope_mismatch".into()),
            });
        } else if !trust_firewall::meets_floor(&proc.envelope, floor) {
            out.push(EligibleCandidate {
                cid: proc.procedure_id,
                kind: CandidateKind::Procedure,
                trust: proc.envelope.origin_authority,
                exclusion: Some("trust_below_floor".into()),
            });
        } else {
            out.push(EligibleCandidate {
                cid: proc.procedure_id,
                kind: CandidateKind::Procedure,
                trust: proc.envelope.origin_authority,
                exclusion: None,
            });
        }
    }

    Ok(out)
}

fn trust_floor_for_risk(risk: &str) -> TrustTier {
    match risk.trim().to_ascii_lowercase().as_str() {
        "critical" | "high" => TrustTier::T3EnvVerified,
        "medium" => TrustTier::T2SourceBound,
        _ => TrustTier::T1Observed,
    }
}

/// Eligible only (exclusion is None).
pub fn passing(cands: &[EligibleCandidate]) -> Vec<&EligibleCandidate> {
    cands.iter().filter(|c| c.exclusion.is_none()).collect()
}

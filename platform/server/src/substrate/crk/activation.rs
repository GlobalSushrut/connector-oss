//! Type-aware Dynamic Node Activation (Memory Sequence DNA field).

use std::collections::{HashMap, HashSet, VecDeque};

use connector_trust::{
    ActionCueEnvelope, CrkState, MemoryDnaType, MemoryRelationKind, VerifiedProcedureCapsule,
};

use crate::state::PlatformState;

use super::eligibility::{self, CandidateKind, EligibleCandidate};
use super::node_index;
use super::relations;
use super::sequence_dna;

const DECAY: f64 = 0.5;
const MAX_HOPS: u32 = 3;
const TRAJ_CAP: f64 = 0.35;

#[derive(Debug, Clone)]
pub struct ActivatedNode {
    pub cid: String,
    pub kind: CandidateKind,
    pub type_dna: MemoryDnaType,
    pub activation: f64,
    pub score: f64,
    pub hops: u32,
    pub exclusion: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct DnaResult {
    pub field: Vec<ActivatedNode>,
    pub conflicts: Vec<(String, String)>,
    pub insufficient_requires: Vec<String>,
    pub exclusions: Vec<String>,
}

pub fn activate_dynamic(
    state: &PlatformState,
    cue: &ActionCueEnvelope,
    eligible: &[EligibleCandidate],
    procedure: Option<&VerifiedProcedureCapsule>,
    prior_cids: &[String],
    auth_root: &str,
) -> DnaResult {
    let mut result = DnaResult::default();
    let eligible_map: HashMap<String, &EligibleCandidate> =
        eligible.iter().map(|c| (c.cid.clone(), c)).collect();
    let mut activation: HashMap<String, f64> = HashMap::new();
    let mut hops: HashMap<String, u32> = HashMap::new();
    let mut types: HashMap<String, MemoryDnaType> = HashMap::new();
    let mut kinds: HashMap<String, CandidateKind> = HashMap::new();
    let mut trust: HashMap<String, u8> = HashMap::new();

    for c in eligible {
        let t = match c.kind {
            CandidateKind::StateClaim => MemoryDnaType::State,
            CandidateKind::Procedure => MemoryDnaType::Procedure,
            CandidateKind::Evidence => MemoryDnaType::Evidence,
            CandidateKind::Other => MemoryDnaType::OpenWork,
        };
        types.insert(c.cid.clone(), t);
        kinds.insert(c.cid.clone(), c.kind);
        trust.insert(c.cid.clone(), c.trust.rank());
        if c.exclusion.is_some() {
            continue;
        }
        // Seed active eligible nodes lightly; procedure/state get full seed below.
        activation.entry(c.cid.clone()).or_insert(0.0);
        hops.entry(c.cid.clone()).or_insert(0);
    }

    // Hard seeds: procedure + its required evidence + high-trust state.
    if let Some(p) = procedure {
        activation.insert(p.procedure_id.clone(), 1.0);
        hops.insert(p.procedure_id.clone(), 0);
        types.insert(p.procedure_id.clone(), MemoryDnaType::Procedure);
        kinds.insert(p.procedure_id.clone(), CandidateKind::Procedure);
        trust.insert(p.procedure_id.clone(), p.envelope.origin_authority.rank());
        for step in &p.steps {
            for ev in &step.required_evidence {
                if let Some(c) = eligible_map.get(ev) {
                    if c.exclusion.is_none() {
                        activation.insert(ev.clone(), 1.0);
                        hops.insert(ev.clone(), 0);
                    } else {
                        result.insufficient_requires.push(ev.clone());
                        result
                            .exclusions
                            .push(format!("{ev}:required_but_ineligible"));
                    }
                } else {
                    result.insufficient_requires.push(ev.clone());
                    result
                        .exclusions
                        .push(format!("{ev}:required_missing"));
                }
            }
        }
    }

    for c in eligible.iter().filter(|c| c.exclusion.is_none()) {
        if matches!(c.kind, CandidateKind::StateClaim) && c.trust.rank() >= 3 {
            let e = activation.entry(c.cid.clone()).or_insert(0.0);
            *e = e.max(0.85);
        }
    }

    // Soft trajectory seeds.
    for cid in prior_cids {
        if eligible_map.get(cid).map(|c| c.exclusion.is_none()).unwrap_or(false) {
            let e = activation.entry(cid.clone()).or_insert(0.0);
            *e = e.max(TRAJ_CAP.min(0.35));
            hops.entry(cid.clone()).or_insert(1);
        }
    }

    // Auth-root pin: indexed nodes under wrong root stay cold.
    for cid in activation.keys().cloned().collect::<Vec<_>>() {
        if let Some(node) = node_index::get_node(state, &cue.agent_pid, &cid) {
            if node.dna.auth_root != auth_root
                && auth_root != format!("genesis:{}", cue.agent_pid)
                && !auth_root.is_empty()
                && node.dna.auth_root != format!("genesis:{}", cue.agent_pid)
            {
                // Allow genesis↔first root; otherwise pin break for indexed nodes.
                if !node.dna.auth_root.starts_with("genesis:") && !auth_root.starts_with("genesis:")
                {
                    activation.insert(cid.clone(), f64::NEG_INFINITY);
                    result
                        .exclusions
                        .push(format!("{cid}:auth_root_mismatch"));
                }
            }
            types.insert(cid.clone(), node.dna.type_dna);
        }
    }

    // BFS forward + backward waves.
    let mut q: VecDeque<(String, u32)> = activation
        .iter()
        .filter(|(_, a)| a.is_finite() && **a > 0.0)
        .map(|(c, _)| (c.clone(), 0))
        .collect();
    let mut seen_edges = HashSet::new();

    while let Some((u, hop)) = q.pop_front() {
        if hop >= MAX_HOPS {
            continue;
        }
        let a_u = activation.get(&u).copied().unwrap_or(0.0);
        if !a_u.is_finite() || a_u <= 0.0 {
            continue;
        }
        let from_ty = types.get(&u).copied().unwrap_or(MemoryDnaType::OpenWork);

        for rel in relations::list_out(state, &cue.agent_pid, &u) {
            let edge_id = rel.relation_id.clone();
            if !seen_edges.insert(format!("f:{edge_id}")) {
                continue;
            }
            let to_ty = rel
                .to_type
                .or_else(|| types.get(&rel.to_cid).copied())
                .unwrap_or(MemoryDnaType::State);
            if !sequence_dna::edge_types_ok(rel.kind, from_ty, to_ty) {
                result
                    .exclusions
                    .push(format!("{}:type_pairing_forbidden", rel.to_cid));
                continue;
            }
            if let Some(c) = eligible_map.get(&rel.to_cid) {
                if c.exclusion.is_some() {
                    continue;
                }
            } else if !matches!(rel.kind, MemoryRelationKind::Requires) {
                continue;
            }

            match rel.kind {
                MemoryRelationKind::Conflicts | MemoryRelationKind::Forbids => {
                    result.conflicts.push((u.clone(), rel.to_cid.clone()));
                    continue;
                }
                MemoryRelationKind::Supersedes => {
                    activation.insert(rel.to_cid.clone(), f64::NEG_INFINITY);
                    result
                        .exclusions
                        .push(format!("{}:superseded_by_{u}", rel.to_cid));
                    continue;
                }
                MemoryRelationKind::Requires
                | MemoryRelationKind::Causal
                | MemoryRelationKind::Next
                | MemoryRelationKind::Derives
                | MemoryRelationKind::Refines => {
                    let boost = a_u * rel.weight.max(0.1) * DECAY.powi(hop as i32 + 1);
                    let e = activation.entry(rel.to_cid.clone()).or_insert(0.0);
                    if boost > *e {
                        *e = boost;
                        hops.insert(rel.to_cid.clone(), hop + 1);
                        types.insert(rel.to_cid.clone(), to_ty);
                        q.push_back((rel.to_cid.clone(), hop + 1));
                    }
                }
            }
        }

        // Backward wave along inbound Requires/Derives/Refines.
        for rel in relations::list_in(state, &cue.agent_pid, &u) {
            if !matches!(
                rel.kind,
                MemoryRelationKind::Requires
                    | MemoryRelationKind::Derives
                    | MemoryRelationKind::Refines
            ) {
                continue;
            }
            let edge_id = format!("b:{}", rel.relation_id);
            if !seen_edges.insert(edge_id) {
                continue;
            }
            let from_ty_e = rel
                .from_type
                .or_else(|| types.get(&rel.from_cid).copied())
                .unwrap_or(MemoryDnaType::Evidence);
            if !sequence_dna::edge_types_ok(rel.kind, from_ty_e, from_ty) {
                continue;
            }
            if let Some(c) = eligible_map.get(&rel.from_cid) {
                if c.exclusion.is_some() {
                    continue;
                }
            }
            let boost = a_u * rel.weight.max(0.1) * DECAY.powi(hop as i32 + 1) * 0.9;
            let e = activation.entry(rel.from_cid.clone()).or_insert(0.0);
            if boost > *e {
                *e = boost;
                hops.insert(rel.from_cid.clone(), hop + 1);
                types.insert(rel.from_cid.clone(), from_ty_e);
                q.push_back((rel.from_cid.clone(), hop + 1));
            }
        }
    }

    // Inhibition on conflict pairs.
    let mut inhibited = HashSet::new();
    for (a, b) in &result.conflicts {
        inhibited.insert(a.clone());
        inhibited.insert(b.clone());
    }

    for (cid, act) in &activation {
        let excl = eligible_map
            .get(cid)
            .and_then(|c| c.exclusion.clone())
            .or_else(|| {
                if !act.is_finite() {
                    Some("score_neg_inf".into())
                } else {
                    None
                }
            });
        let t = types.get(cid).copied().unwrap_or(MemoryDnaType::OpenWork);
        let tr = trust.get(cid).copied().unwrap_or(1) as f64;
        let kind = kinds
            .get(cid)
            .copied()
            .unwrap_or(CandidateKind::Other);
        let kind_bias = match kind {
            CandidateKind::Procedure => 0.35,
            CandidateKind::StateClaim => 0.40,
            CandidateKind::Evidence => 0.15,
            CandidateKind::Other => 0.05,
        };
        let mut score = if act.is_finite() {
            act + 0.10 * (tr / 4.0) + kind_bias
        } else {
            f64::NEG_INFINITY
        };
        if inhibited.contains(cid) && matches!(t, MemoryDnaType::State | MemoryDnaType::Evidence) {
            // Keep visible via conflict frame path; damp state cover score.
            score *= 0.15;
        }
        result.field.push(ActivatedNode {
            cid: cid.clone(),
            kind,
            type_dna: t,
            activation: *act,
            score,
            hops: hops.get(cid).copied().unwrap_or(0),
            exclusion: excl,
        });
    }

    // Carry eligibility exclusions.
    for c in eligible {
        if let Some(e) = &c.exclusion {
            result.exclusions.push(format!("{}:{}", c.cid, e));
        }
    }

    result
}

pub fn overall_state(dna: &DnaResult, selected: &[String]) -> CrkState {
    if !dna.insufficient_requires.is_empty()
        && selected
            .iter()
            .all(|c| !dna.insufficient_requires.iter().any(|r| r == c))
    {
        // missing required and not covered
        if selected.is_empty() {
            return CrkState::Insufficient;
        }
    }
    if selected.is_empty() {
        if dna.exclusions.iter().any(|e| e.contains("trust_below_floor")) {
            return CrkState::Untrusted;
        }
        if dna.exclusions.iter().any(|e| e.contains("temporal")) {
            return CrkState::Stale;
        }
        return CrkState::Insufficient;
    }
    let hot_conflicts = dna.conflicts.iter().any(|(a, b)| {
        selected.iter().any(|s| s == a) && selected.iter().any(|s| s == b)
            || selected.contains(a)
            || selected.contains(b)
    });
    if hot_conflicts || (!dna.conflicts.is_empty() && selected.iter().any(|s| {
        dna.conflicts.iter().any(|(a, b)| a == s || b == s)
    })) {
        return CrkState::Ambiguous;
    }
    if !dna.insufficient_requires.is_empty() {
        return CrkState::Insufficient;
    }
    CrkState::Ready
}

/// Expose eligibility module for tests.
pub use eligibility::passing;

//! Budget-first cover — type priority, must-include Requires, saturation.

use connector_trust::{ActionCueEnvelope, CrkState, MemoryDnaType};

use super::activation::{self, ActivatedNode, DnaResult};

/// Compile cover CIDs from DNA field under token_budget / max_range_cover safety.
pub fn budget_cover(
    cue: &ActionCueEnvelope,
    dna: &DnaResult,
) -> (Vec<String>, Vec<String>, CrkState) {
    let mut exclusions = dna.exclusions.clone();
    let mut selected: Vec<String> = Vec::new();

    // Must-include: procedures + finite high activation states from Requires seeds.
    let mut ranked: Vec<&ActivatedNode> = dna
        .field
        .iter()
        .filter(|n| n.exclusion.is_none() && n.score.is_finite() && n.activation > 0.0)
        .collect();
    ranked.sort_by(|a, b| {
        a.type_dna
            .cover_priority()
            .cmp(&b.type_dna.cover_priority())
            .then_with(|| {
                b.score
                    .partial_cmp(&a.score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .then_with(|| a.cid.cmp(&b.cid))
    });

    let safety_cap = cue.max_range_cover.max(1) as usize;
    // Estimate tokens: procedure 128, state 64, conflict 48, else 32.
    let mut used: u64 = 0;
    let budget = cue.token_budget.max(256);

    // Pass 1: must-include procedure + required-linked (activation >= 0.8).
    for n in ranked.iter().filter(|n| {
        matches!(n.type_dna, MemoryDnaType::Procedure)
            || (matches!(n.type_dna, MemoryDnaType::State) && n.activation >= 0.8)
    }) {
        let cost = token_cost(n.type_dna);
        if used + cost > budget && !selected.is_empty() {
            if matches!(n.type_dna, MemoryDnaType::Procedure) || n.activation >= 1.0 {
                // Must try to include — if truly no room, mark insufficient later.
                exclusions.push(format!("{}:saturation_must_include", n.cid));
            }
            continue;
        }
        if selected.len() >= safety_cap {
            break;
        }
        if !selected.contains(&n.cid) {
            selected.push(n.cid.clone());
            used = used.saturating_add(cost);
        }
    }

    // Pass 2: fill by score/type.
    for n in &ranked {
        if selected.len() >= safety_cap || used >= budget {
            break;
        }
        if selected.contains(&n.cid) {
            continue;
        }
        let cost = token_cost(n.type_dna);
        if used + cost > budget {
            continue;
        }
        // Never fill with index type as state.
        if matches!(n.type_dna, MemoryDnaType::Index) {
            continue;
        }
        selected.push(n.cid.clone());
        used = used.saturating_add(cost);
    }

    // Conflict exposure: ensure at least one side id noted (MomentRange unresolved).
    for (a, b) in &dna.conflicts {
        if selected.contains(a) || selected.contains(b) {
            if !selected.contains(a) && selected.len() < safety_cap {
                selected.push(a.clone());
            }
            if !selected.contains(b) && selected.len() < safety_cap {
                selected.push(b.clone());
            }
        }
    }

    if selected.is_empty() && exclusions.is_empty() {
        exclusions.push("no_eligible_memory".into());
    }

    let state = activation::overall_state(dna, &selected);
    let _ = used;
    (selected, exclusions, state)
}

fn token_cost(t: MemoryDnaType) -> u64 {
    match t {
        MemoryDnaType::Procedure => 128,
        MemoryDnaType::State => 64,
        MemoryDnaType::Conflict => 48,
        MemoryDnaType::OpenWork => 40,
        MemoryDnaType::Evidence => 32,
        MemoryDnaType::Relation => 16,
        MemoryDnaType::Index => 8,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::substrate::crk::activation::ActivatedNode;
    use crate::substrate::crk::eligibility::CandidateKind;
    use connector_trust::ACTION_CUE_SCHEMA;

    #[test]
    fn procedure_preferred_in_cover() {
        let cue = ActionCueEnvelope {
            schema: ACTION_CUE_SCHEMA.into(),
            agent_pid: "a".into(),
            generation: 1,
            bound_skill: Some("s".into()),
            phase: "recall".into(),
            action_digest: "x".into(),
            risk: "low".into(),
            token_budget: 2048,
            max_range_cover: 8,
        };
        let dna = DnaResult {
            field: vec![
                ActivatedNode {
                    cid: "noise".into(),
                    kind: CandidateKind::StateClaim,
                    type_dna: MemoryDnaType::State,
                    activation: 0.2,
                    score: 0.3,
                    hops: 2,
                    exclusion: None,
                },
                ActivatedNode {
                    cid: "proc".into(),
                    kind: CandidateKind::Procedure,
                    type_dna: MemoryDnaType::Procedure,
                    activation: 1.0,
                    score: 1.4,
                    hops: 0,
                    exclusion: None,
                },
                ActivatedNode {
                    cid: "claim".into(),
                    kind: CandidateKind::StateClaim,
                    type_dna: MemoryDnaType::State,
                    activation: 1.0,
                    score: 1.3,
                    hops: 0,
                    exclusion: None,
                },
            ],
            ..Default::default()
        };
        let (sel, _, st) = budget_cover(&cue, &dna);
        assert_eq!(sel[0], "proc");
        assert!(sel.contains(&"claim".to_string()));
        assert_eq!(st, CrkState::Ready);
    }
}

//! # Tension Engine
//!
//! Detects and manages unresolved cognitive pressure.
//! No tension → no thought. Tension is the engine of cognition.

use super::types::*;
use std::collections::HashMap;

/// Detects tensions from meaning objects and existing commitments.
pub struct TensionEngine;

impl TensionEngine {
    /// Detect tensions from newly formed meanings against the current world state.
    pub fn detect(
        meanings: &[MeaningObject],
        commitments: &CommitmentRegister,
        existing_tensions: &TensionGraph,
    ) -> TensionGraph {
        let mut graph = existing_tensions.clone();
        let now = chrono::Utc::now().timestamp();

        for meaning in meanings {
            let tensions = Self::tensions_from_meaning(meaning, commitments, now);
            for t in tensions {
                graph.tensions.insert(t.id.clone(), t);
            }
        }

        // Detect inter-tension relationships
        let edge_candidates = Self::detect_edges(&graph.tensions);
        graph.edges.extend(edge_candidates);

        // Decay old unresolved tensions
        Self::decay_tensions(&mut graph, now);

        graph
    }

    /// Extract tensions from a single meaning object.
    fn tensions_from_meaning(
        meaning: &MeaningObject,
        commitments: &CommitmentRegister,
        now: i64,
    ) -> Vec<Tension> {
        let mut tensions = Vec::new();
        let base_id = format!("tension:{}", meaning.id);

        match &meaning.meaning_type {
            MeaningType::Request { intent, urgency } => {
                let intensity = match urgency {
                    Urgency::Critical => 1.0,
                    Urgency::High => 0.8,
                    Urgency::Normal => 0.5,
                    Urgency::Low => 0.3,
                    Urgency::Background => 0.1,
                };
                tensions.push(Tension {
                    id: format!("{}_goal_gap", base_id),
                    tension_type: TensionType::GoalGap {
                        current: "no_response".into(),
                        desired: intent.clone(),
                    },
                    source_meanings: vec![meaning.id.clone()],
                    intensity,
                    created_at: now,
                    deadline: match urgency {
                        Urgency::Critical => Some(now + 5_000),
                        Urgency::High => Some(now + 30_000),
                        _ => None,
                    },
                    resolution: TensionResolution::Unresolved,
                    related_tensions: vec![],
                });
            }
            MeaningType::Contradiction { claim_a, claim_b } => {
                tensions.push(Tension {
                    id: format!("{}_contradiction", base_id),
                    tension_type: TensionType::ContradictionDetected {
                        claim_a: claim_a.clone(),
                        claim_b: claim_b.clone(),
                    },
                    source_meanings: vec![meaning.id.clone()],
                    intensity: 0.9,
                    created_at: now,
                    deadline: None,
                    resolution: TensionResolution::Unresolved,
                    related_tensions: vec![],
                });
            }
            MeaningType::Risk { threat, severity } => {
                let intensity = match severity {
                    Severity::Critical => 1.0,
                    Severity::High => 0.8,
                    Severity::Medium => 0.5,
                    Severity::Low => 0.3,
                    Severity::Negligible => 0.1,
                };
                tensions.push(Tension {
                    id: format!("{}_risk", base_id),
                    tension_type: TensionType::RiskTooHigh {
                        risk: threat.clone(),
                        threshold: 0.5,
                        actual: intensity,
                    },
                    source_meanings: vec![meaning.id.clone()],
                    intensity,
                    created_at: now,
                    deadline: None,
                    resolution: TensionResolution::Unresolved,
                    related_tensions: vec![],
                });
            }
            MeaningType::Anomaly { expected, observed } => {
                tensions.push(Tension {
                    id: format!("{}_anomaly", base_id),
                    tension_type: TensionType::GoalGap {
                        current: observed.clone(),
                        desired: expected.clone(),
                    },
                    source_meanings: vec![meaning.id.clone()],
                    intensity: meaning.salience,
                    created_at: now,
                    deadline: None,
                    resolution: TensionResolution::Unresolved,
                    related_tensions: vec![],
                });
            }
            MeaningType::Dependency { on } => {
                // Check if the dependency is met by existing commitments
                let met = commitments.commitments.values().any(|c| {
                    c.content.contains(on.as_str())
                        && c.status == CommitmentStatus::Active
                });
                if !met {
                    tensions.push(Tension {
                        id: format!("{}_missing_dep", base_id),
                        tension_type: TensionType::DataMissing {
                            what: on.clone(),
                            why_needed: "dependency_unmet".into(),
                        },
                        source_meanings: vec![meaning.id.clone()],
                        intensity: 0.6,
                        created_at: now,
                        deadline: None,
                        resolution: TensionResolution::Unresolved,
                        related_tensions: vec![],
                    });
                }
            }
            MeaningType::Unknown { description } => {
                tensions.push(Tension {
                    id: format!("{}_ambiguity", base_id),
                    tension_type: TensionType::Ambiguity {
                        interpretations: vec![description.clone()],
                    },
                    source_meanings: vec![meaning.id.clone()],
                    intensity: 0.4,
                    created_at: now,
                    deadline: None,
                    resolution: TensionResolution::Unresolved,
                    related_tensions: vec![],
                });
            }
            _ => {}
        }

        tensions
    }

    /// Detect relationships between tensions.
    fn detect_edges(tensions: &HashMap<String, Tension>) -> Vec<TensionEdge> {
        let mut edges = Vec::new();
        let ids: Vec<&String> = tensions.keys().collect();

        for i in 0..ids.len() {
            for j in (i + 1)..ids.len() {
                let a = &tensions[ids[i]];
                let b = &tensions[ids[j]];

                // Shared source meanings → likely related
                let shared_sources = a.source_meanings.iter()
                    .any(|s| b.source_meanings.contains(s));

                if shared_sources {
                    edges.push(TensionEdge {
                        from: a.id.clone(),
                        to: b.id.clone(),
                        relation: TensionRelation::Amplifies,
                    });
                }

                // Resource constraints block goal gaps
                if matches!(&a.tension_type, TensionType::ResourceConstrained { .. })
                    && matches!(&b.tension_type, TensionType::GoalGap { .. })
                {
                    edges.push(TensionEdge {
                        from: a.id.clone(),
                        to: b.id.clone(),
                        relation: TensionRelation::Blocks,
                    });
                }
            }
        }

        edges
    }

    /// Decay intensity of old unresolved tensions.
    fn decay_tensions(graph: &mut TensionGraph, now: i64) {
        let decay_rate = 0.001; // per second
        for tension in graph.tensions.values_mut() {
            if matches!(tension.resolution, TensionResolution::Unresolved) {
                let age_secs = (now - tension.created_at).max(0) as f64;
                let decay = (-decay_rate * age_secs).exp();
                tension.intensity *= decay;
            }
        }
    }

    /// Resolve a tension by linking it to a commitment.
    pub fn resolve(graph: &mut TensionGraph, tension_id: &str, commitment_id: &str) {
        if let Some(t) = graph.tensions.get_mut(tension_id) {
            t.resolution = TensionResolution::Resolved {
                by_commitment: commitment_id.to_string(),
                at: chrono::Utc::now().timestamp(),
            };
        }
    }

    /// Get all unresolved tensions sorted by intensity (highest first).
    pub fn unresolved_sorted(graph: &TensionGraph) -> Vec<&Tension> {
        let mut unresolved: Vec<&Tension> = graph
            .tensions
            .values()
            .filter(|t| matches!(t.resolution, TensionResolution::Unresolved))
            .collect();
        unresolved.sort_by(|a, b| b.intensity.partial_cmp(&a.intensity).unwrap_or(std::cmp::Ordering::Equal));
        unresolved
    }

    /// Total tension intensity — a measure of how much cognitive work is needed.
    pub fn total_intensity(graph: &TensionGraph) -> f64 {
        graph
            .tensions
            .values()
            .filter(|t| matches!(t.resolution, TensionResolution::Unresolved))
            .map(|t| t.intensity)
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_meaning(id: &str, meaning_type: MeaningType) -> MeaningObject {
        MeaningObject {
            id: id.to_string(),
            source_perception: "perc:1".into(),
            meaning_type,
            entities: vec![],
            salience: 0.7,
            confidence: 0.9,
            evidence_cids: vec![],
        }
    }

    #[test]
    fn test_detect_goal_gap_from_request() {
        let meanings = vec![make_meaning(
            "m1",
            MeaningType::Request {
                intent: "diagnose patient".into(),
                urgency: Urgency::High,
            },
        )];
        let register = CommitmentRegister::default();
        let graph = TensionEngine::detect(&meanings, &register, &TensionGraph::default());
        assert!(!graph.tensions.is_empty());
        let t = graph.tensions.values().next().unwrap();
        assert!(matches!(&t.tension_type, TensionType::GoalGap { .. }));
        assert!((t.intensity - 0.8).abs() < 0.01);
    }

    #[test]
    fn test_detect_contradiction() {
        let meanings = vec![make_meaning(
            "m2",
            MeaningType::Contradiction {
                claim_a: "patient is stable".into(),
                claim_b: "patient vitals declining".into(),
            },
        )];
        let register = CommitmentRegister::default();
        let graph = TensionEngine::detect(&meanings, &register, &TensionGraph::default());
        let t = graph.tensions.values().next().unwrap();
        assert!(matches!(&t.tension_type, TensionType::ContradictionDetected { .. }));
        assert!((t.intensity - 0.9).abs() < 0.01);
    }

    #[test]
    fn test_no_tension_no_thought() {
        let graph = TensionGraph::default();
        assert_eq!(TensionEngine::total_intensity(&graph), 0.0);
        assert!(TensionEngine::unresolved_sorted(&graph).is_empty());
    }

    #[test]
    fn test_resolve_tension() {
        let meanings = vec![make_meaning(
            "m3",
            MeaningType::Request {
                intent: "hello".into(),
                urgency: Urgency::Normal,
            },
        )];
        let register = CommitmentRegister::default();
        let mut graph = TensionEngine::detect(&meanings, &register, &TensionGraph::default());
        let tid = graph.tensions.keys().next().unwrap().clone();
        TensionEngine::resolve(&mut graph, &tid, "commit:1");
        assert!(TensionEngine::unresolved_sorted(&graph).is_empty());
    }
}

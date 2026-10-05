//! # Possibility Generator
//!
//! Generates candidate transformations of state from tensions and knowledge.
//! Possibilities are the CENTER of intelligence — everything serves this.

use super::types::*;

/// Generates typed possibilities from tensions and activated knowledge.
pub struct PossibilityGenerator;

impl PossibilityGenerator {
    /// Generate possibilities for a set of unresolved tensions using activated knowledge.
    pub fn generate(
        tensions: &[&Tension],
        knowledge: &ActiveKnowledgeSet,
        context: &CognitiveContext,
    ) -> Vec<Possibility> {
        let mut possibilities = Vec::new();
        let max = context.max_possibilities;

        for tension in tensions {
            let mut generated = Self::possibilities_for_tension(tension, knowledge, context);
            possibilities.append(&mut generated);
            if possibilities.len() >= max {
                break;
            }
        }

        possibilities.truncate(max);
        possibilities
    }

    /// Generate possibilities for a single tension.
    fn possibilities_for_tension(
        tension: &Tension,
        knowledge: &ActiveKnowledgeSet,
        _context: &CognitiveContext,
    ) -> Vec<Possibility> {
        let mut possibilities = Vec::new();
        let now = chrono::Utc::now().timestamp();
        let base_id = format!("poss:{}:{}", now, tension.id);

        match &tension.tension_type {
            TensionType::GoalGap { current, desired } => {
                // Possibility: directly act toward goal
                possibilities.push(Possibility {
                    id: format!("{}_act", base_id),
                    possibility_type: PossibilityType::Act {
                        action: format!("achieve: {}", desired),
                        target: current.clone(),
                    },
                    description: format!("Act to move from '{}' to '{}'", current, desired),
                    preconditions: vec![],
                    required_knowledge: vec![],
                    expected_value: 0.7,
                    risk: 0.3,
                    reversibility: Reversibility::PartiallyReversible,
                    dependencies: vec![],
                    policy_status: PolicyStatus::Unknown,
                    estimated_confidence: 0.5,
                    estimated_cost: Cost { tokens: 500, time_ms: 2000, monetary: 0.0 },
                    source_tensions: vec![tension.id.clone()],
                    evaluation: None,
                });

                // Possibility: decompose the goal
                possibilities.push(Possibility {
                    id: format!("{}_decompose", base_id),
                    possibility_type: PossibilityType::Decompose {
                        problem: desired.clone(),
                        into: vec![],
                    },
                    description: format!("Break '{}' into subgoals", desired),
                    preconditions: vec![],
                    required_knowledge: vec![],
                    expected_value: 0.6,
                    risk: 0.1,
                    reversibility: Reversibility::FullyReversible,
                    dependencies: vec![],
                    policy_status: PolicyStatus::Allowed,
                    estimated_confidence: 0.6,
                    estimated_cost: Cost { tokens: 300, time_ms: 1000, monetary: 0.0 },
                    source_tensions: vec![tension.id.clone()],
                    evaluation: None,
                });

                // If procedural knowledge is available, use it
                for ak in &knowledge.knowledge {
                    if let KnowledgeForm::Procedural { name, steps, success_rate, .. } = &ak.form {
                        possibilities.push(Possibility {
                            id: format!("{}_proc_{}", base_id, name),
                            possibility_type: PossibilityType::Plan {
                                goal: desired.clone(),
                                approach: name.clone(),
                            },
                            description: format!("Apply procedure '{}' ({} steps)", name, steps.len()),
                            preconditions: vec![],
                            required_knowledge: vec![name.clone()],
                            expected_value: *success_rate,
                            risk: 1.0 - success_rate,
                            reversibility: Reversibility::PartiallyReversible,
                            dependencies: vec![],
                            policy_status: PolicyStatus::Allowed,
                            estimated_confidence: ak.activation * success_rate,
                            estimated_cost: Cost {
                                tokens: (steps.len() as u64) * 200,
                                time_ms: (steps.len() as u64) * 1000,
                                monetary: 0.0,
                            },
                            source_tensions: vec![tension.id.clone()],
                            evaluation: None,
                        });
                    }
                }
            }

            TensionType::DataMissing { what, why_needed } => {
                // Possibility: ask the user
                possibilities.push(Possibility {
                    id: format!("{}_ask", base_id),
                    possibility_type: PossibilityType::Ask {
                        question: format!("What is {}?", what),
                        target: "user".into(),
                    },
                    description: format!("Ask user for missing data: {}", what),
                    preconditions: vec![],
                    required_knowledge: vec![],
                    expected_value: 0.8,
                    risk: 0.05,
                    reversibility: Reversibility::FullyReversible,
                    dependencies: vec![],
                    policy_status: PolicyStatus::Allowed,
                    estimated_confidence: 0.7,
                    estimated_cost: Cost { tokens: 100, time_ms: 500, monetary: 0.0 },
                    source_tensions: vec![tension.id.clone()],
                    evaluation: None,
                });

                // Possibility: retrieve from knowledge
                possibilities.push(Possibility {
                    id: format!("{}_retrieve", base_id),
                    possibility_type: PossibilityType::Retrieve {
                        query: what.clone(),
                        from: "knowledge_graph".into(),
                    },
                    description: format!("Search knowledge graph for: {}", what),
                    preconditions: vec![],
                    required_knowledge: vec![],
                    expected_value: 0.6,
                    risk: 0.02,
                    reversibility: Reversibility::FullyReversible,
                    dependencies: vec![],
                    policy_status: PolicyStatus::Allowed,
                    estimated_confidence: 0.4,
                    estimated_cost: Cost { tokens: 200, time_ms: 300, monetary: 0.0 },
                    source_tensions: vec![tension.id.clone()],
                    evaluation: None,
                });
            }

            TensionType::ContradictionDetected { claim_a, claim_b } => {
                // Possibility: verify claim A
                possibilities.push(Possibility {
                    id: format!("{}_verify_a", base_id),
                    possibility_type: PossibilityType::Verify {
                        claim: claim_a.clone(),
                        method: "evidence_check".into(),
                    },
                    description: format!("Verify claim: {}", claim_a),
                    preconditions: vec![],
                    required_knowledge: vec![],
                    expected_value: 0.8,
                    risk: 0.1,
                    reversibility: Reversibility::FullyReversible,
                    dependencies: vec![],
                    policy_status: PolicyStatus::Allowed,
                    estimated_confidence: 0.5,
                    estimated_cost: Cost { tokens: 300, time_ms: 1000, monetary: 0.0 },
                    source_tensions: vec![tension.id.clone()],
                    evaluation: None,
                });

                // Possibility: verify claim B
                possibilities.push(Possibility {
                    id: format!("{}_verify_b", base_id),
                    possibility_type: PossibilityType::Verify {
                        claim: claim_b.clone(),
                        method: "evidence_check".into(),
                    },
                    description: format!("Verify claim: {}", claim_b),
                    preconditions: vec![],
                    required_knowledge: vec![],
                    expected_value: 0.8,
                    risk: 0.1,
                    reversibility: Reversibility::FullyReversible,
                    dependencies: vec![],
                    policy_status: PolicyStatus::Allowed,
                    estimated_confidence: 0.5,
                    estimated_cost: Cost { tokens: 300, time_ms: 1000, monetary: 0.0 },
                    source_tensions: vec![tension.id.clone()],
                    evaluation: None,
                });
            }

            TensionType::Ambiguity { interpretations } => {
                for (i, interp) in interpretations.iter().enumerate() {
                    possibilities.push(Possibility {
                        id: format!("{}_interp_{}", base_id, i),
                        possibility_type: PossibilityType::Infer {
                            from: vec![interp.clone()],
                            conclusion: format!("Adopt interpretation: {}", interp),
                        },
                        description: format!("Interpret as: {}", interp),
                        preconditions: vec![],
                        required_knowledge: vec![],
                        expected_value: 0.5,
                        risk: 0.2,
                        reversibility: Reversibility::FullyReversible,
                        dependencies: vec![],
                        policy_status: PolicyStatus::Allowed,
                        estimated_confidence: 1.0 / (interpretations.len() as f64),
                        estimated_cost: Cost::default(),
                        source_tensions: vec![tension.id.clone()],
                        evaluation: None,
                    });
                }

                // Possibility: ask for clarification
                possibilities.push(Possibility {
                    id: format!("{}_clarify", base_id),
                    possibility_type: PossibilityType::Ask {
                        question: "Could you clarify your intent?".into(),
                        target: "user".into(),
                    },
                    description: "Ask for clarification to resolve ambiguity".into(),
                    preconditions: vec![],
                    required_knowledge: vec![],
                    expected_value: 0.9,
                    risk: 0.01,
                    reversibility: Reversibility::FullyReversible,
                    dependencies: vec![],
                    policy_status: PolicyStatus::Allowed,
                    estimated_confidence: 0.8,
                    estimated_cost: Cost { tokens: 50, time_ms: 200, monetary: 0.0 },
                    source_tensions: vec![tension.id.clone()],
                    evaluation: None,
                });
            }

            TensionType::RiskTooHigh { risk, .. } => {
                // Possibility: mitigate risk
                possibilities.push(Possibility {
                    id: format!("{}_mitigate", base_id),
                    possibility_type: PossibilityType::Act {
                        action: format!("mitigate risk: {}", risk),
                        target: risk.clone(),
                    },
                    description: format!("Take action to mitigate: {}", risk),
                    preconditions: vec![],
                    required_knowledge: vec![],
                    expected_value: 0.8,
                    risk: 0.2,
                    reversibility: Reversibility::PartiallyReversible,
                    dependencies: vec![],
                    policy_status: PolicyStatus::Unknown,
                    estimated_confidence: 0.5,
                    estimated_cost: Cost { tokens: 400, time_ms: 2000, monetary: 0.0 },
                    source_tensions: vec![tension.id.clone()],
                    evaluation: None,
                });

                // Possibility: escalate
                possibilities.push(Possibility {
                    id: format!("{}_escalate", base_id),
                    possibility_type: PossibilityType::Escalate {
                        to: "human_operator".into(),
                        reason: format!("Risk too high: {}", risk),
                    },
                    description: format!("Escalate high-risk situation: {}", risk),
                    preconditions: vec![],
                    required_knowledge: vec![],
                    expected_value: 0.6,
                    risk: 0.0,
                    reversibility: Reversibility::FullyReversible,
                    dependencies: vec![],
                    policy_status: PolicyStatus::Allowed,
                    estimated_confidence: 0.9,
                    estimated_cost: Cost { tokens: 100, time_ms: 500, monetary: 0.0 },
                    source_tensions: vec![tension.id.clone()],
                    evaluation: None,
                });
            }

            TensionType::ExpertiseGap { domain } => {
                // Possibility: delegate to domain expert
                possibilities.push(Possibility {
                    id: format!("{}_delegate", base_id),
                    possibility_type: PossibilityType::Delegate {
                        to_agent: format!("expert:{}", domain),
                        task: format!("Provide {} expertise", domain),
                    },
                    description: format!("Delegate to {} domain expert", domain),
                    preconditions: vec![],
                    required_knowledge: vec![],
                    expected_value: 0.7,
                    risk: 0.1,
                    reversibility: Reversibility::FullyReversible,
                    dependencies: vec![],
                    policy_status: PolicyStatus::Unknown,
                    estimated_confidence: 0.6,
                    estimated_cost: Cost { tokens: 200, time_ms: 3000, monetary: 0.0 },
                    source_tensions: vec![tension.id.clone()],
                    evaluation: None,
                });
            }

            _ => {
                // Generic: wait or escalate
                possibilities.push(Possibility {
                    id: format!("{}_wait", base_id),
                    possibility_type: PossibilityType::Wait {
                        for_event: "more_information".into(),
                        timeout_ms: 30_000,
                    },
                    description: "Wait for more information".into(),
                    preconditions: vec![],
                    required_knowledge: vec![],
                    expected_value: 0.3,
                    risk: 0.1,
                    reversibility: Reversibility::FullyReversible,
                    dependencies: vec![],
                    policy_status: PolicyStatus::Allowed,
                    estimated_confidence: 0.4,
                    estimated_cost: Cost { tokens: 0, time_ms: 30_000, monetary: 0.0 },
                    source_tensions: vec![tension.id.clone()],
                    evaluation: None,
                });
            }
        }

        possibilities
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tension(id: &str, tt: TensionType) -> Tension {
        Tension {
            id: id.into(),
            tension_type: tt,
            source_meanings: vec![],
            intensity: 0.7,
            created_at: 0,
            deadline: None,
            resolution: TensionResolution::Unresolved,
            related_tensions: vec![],
        }
    }

    #[test]
    fn test_goal_gap_generates_act_and_decompose() {
        let t = make_tension("t1", TensionType::GoalGap {
            current: "unknown".into(),
            desired: "diagnose patient".into(),
        });
        let knowledge = ActiveKnowledgeSet::default();
        let context = CognitiveContext::default();
        let poss = PossibilityGenerator::generate(&[&t], &knowledge, &context);
        assert!(poss.len() >= 2);
        assert!(poss.iter().any(|p| matches!(p.possibility_type, PossibilityType::Act { .. })));
        assert!(poss.iter().any(|p| matches!(p.possibility_type, PossibilityType::Decompose { .. })));
    }

    #[test]
    fn test_contradiction_generates_two_verifications() {
        let t = make_tension("t2", TensionType::ContradictionDetected {
            claim_a: "stable".into(),
            claim_b: "declining".into(),
        });
        let knowledge = ActiveKnowledgeSet::default();
        let context = CognitiveContext::default();
        let poss = PossibilityGenerator::generate(&[&t], &knowledge, &context);
        let verify_count = poss.iter().filter(|p| matches!(p.possibility_type, PossibilityType::Verify { .. })).count();
        assert_eq!(verify_count, 2);
    }

    #[test]
    fn test_respects_max_possibilities() {
        let t = make_tension("t3", TensionType::Ambiguity {
            interpretations: (0..20).map(|i| format!("interp_{}", i)).collect(),
        });
        let knowledge = ActiveKnowledgeSet::default();
        let mut context = CognitiveContext::default();
        context.max_possibilities = 5;
        let poss = PossibilityGenerator::generate(&[&t], &knowledge, &context);
        assert!(poss.len() <= 5);
    }

    #[test]
    fn test_procedural_knowledge_generates_plan_possibility() {
        let t = make_tension("t4", TensionType::GoalGap {
            current: "unknown".into(),
            desired: "diagnose".into(),
        });
        let knowledge = ActiveKnowledgeSet {
            knowledge: vec![ActivatedKnowledge {
                form: KnowledgeForm::Procedural {
                    name: "differential_diagnosis".into(),
                    preconditions: vec![],
                    steps: vec!["step1".into(), "step2".into()],
                    postconditions: vec![],
                    success_rate: 0.85,
                },
                activation: 0.9,
                source_cids: vec![],
            }],
            total_activation: 0.9,
            token_budget_used: 100,
        };
        let context = CognitiveContext::default();
        let poss = PossibilityGenerator::generate(&[&t], &knowledge, &context);
        assert!(poss.iter().any(|p| matches!(p.possibility_type, PossibilityType::Plan { .. })));
    }
}

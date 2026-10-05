//! # Commitment Engine
//!
//! Adopts evaluated possibilities as working truths or planned actions.
//! Commitments persist across cycles, constrain future planning, and are
//! revisable under defined conditions.

use super::types::*;

/// Engine that manages the commitment lifecycle.
pub struct CommitmentEngine;

impl CommitmentEngine {
    /// Select the best evaluated possibility and commit to it.
    /// Returns the new commitment, or None if no possibility meets threshold.
    pub fn commit(
        evaluated: &[PossibilityEvaluation],
        possibilities: &[Possibility],
        tensions: &[Tension],
        register: &mut CommitmentRegister,
        weights: &EvaluationWeights,
        confidence_threshold: f64,
    ) -> Option<Commitment> {
        // Sort by composite score
        let mut ranked: Vec<&PossibilityEvaluation> = evaluated
            .iter()
            .filter(|e| e.recommendation != EvalRecommendation::Reject)
            .collect();
        ranked.sort_by(|a, b| {
            let sa = a.scores.composite(weights);
            let sb = b.scores.composite(weights);
            sb.partial_cmp(&sa).unwrap_or(std::cmp::Ordering::Equal)
        });

        let best = ranked.first()?;
        let possibility = possibilities.iter().find(|p| p.id == best.possibility_id)?;

        // Check confidence threshold
        if possibility.estimated_confidence < confidence_threshold
            && best.recommendation != EvalRecommendation::StrongCommit
        {
            return None;
        }

        let strength = match best.recommendation {
            EvalRecommendation::StrongCommit => CommitmentStrength::Strong,
            EvalRecommendation::Commit => CommitmentStrength::Working,
            EvalRecommendation::Tentative => CommitmentStrength::Tentative,
            EvalRecommendation::Defer => CommitmentStrength::Hypothetical,
            EvalRecommendation::Reject => return None,
        };

        let commitment_type = Self::infer_commitment_type(possibility);
        let now = chrono::Utc::now().timestamp();

        let commitment = Commitment {
            id: format!("commit:{}:{}", now, possibility.id),
            commitment_type,
            content: possibility.description.clone(),
            strength,
            justification: vec![best.justification.clone()],
            source_possibilities: vec![possibility.id.clone()],
            source_tensions: possibility.source_tensions.clone(),
            revisable: strength < CommitmentStrength::Absolute,
            revision_conditions: Self::default_revision_conditions(&strength),
            created_at: now,
            expires_at: None,
            status: CommitmentStatus::Active,
            evidence_cids: vec![],
        };

        // Register the commitment
        register.commitments.insert(commitment.id.clone(), commitment.clone());

        // Add edges to existing commitments
        Self::detect_commitment_edges(&commitment, register);

        Some(commitment)
    }

    /// Revise an existing commitment in light of new evidence.
    pub fn revise(
        register: &mut CommitmentRegister,
        commitment_id: &str,
        reason: &str,
        replacement: Option<Commitment>,
    ) -> Result<(), String> {
        let old = register.commitments.get_mut(commitment_id)
            .ok_or_else(|| format!("commitment {} not found", commitment_id))?;

        if !old.revisable {
            return Err(format!("commitment {} is not revisable (strength={:?})", commitment_id, old.strength));
        }

        old.status = CommitmentStatus::Revised { by: reason.to_string() };

        if let Some(new_commitment) = replacement {
            // Add replacement edge
            register.commitment_graph.push(CommitmentEdge {
                from: new_commitment.id.clone(),
                to: commitment_id.to_string(),
                relation: CommitmentRelation::Replaces,
            });
            register.commitments.insert(new_commitment.id.clone(), new_commitment);
        }

        Ok(())
    }

    /// Abandon a commitment.
    pub fn abandon(register: &mut CommitmentRegister, commitment_id: &str, reason: &str) -> Result<(), String> {
        let c = register.commitments.get_mut(commitment_id)
            .ok_or_else(|| format!("commitment {} not found", commitment_id))?;
        c.status = CommitmentStatus::Abandoned { reason: reason.to_string() };
        Ok(())
    }

    /// Mark a commitment as executed.
    pub fn mark_executed(register: &mut CommitmentRegister, commitment_id: &str) -> Result<(), String> {
        let c = register.commitments.get_mut(commitment_id)
            .ok_or_else(|| format!("commitment {} not found", commitment_id))?;
        c.status = CommitmentStatus::Executed;
        Ok(())
    }

    /// Get all active commitments sorted by strength (strongest first).
    pub fn active_sorted(register: &CommitmentRegister) -> Vec<&Commitment> {
        let mut active: Vec<&Commitment> = register
            .commitments
            .values()
            .filter(|c| c.status == CommitmentStatus::Active)
            .collect();
        active.sort_by(|a, b| b.strength.cmp(&a.strength));
        active
    }

    /// Check for contradictions among active commitments.
    pub fn detect_contradictions(register: &CommitmentRegister) -> Vec<(String, String)> {
        register
            .commitment_graph
            .iter()
            .filter(|e| e.relation == CommitmentRelation::Contradicts)
            .filter(|e| {
                let a_active = register.commitments.get(&e.from)
                    .map(|c| c.status == CommitmentStatus::Active)
                    .unwrap_or(false);
                let b_active = register.commitments.get(&e.to)
                    .map(|c| c.status == CommitmentStatus::Active)
                    .unwrap_or(false);
                a_active && b_active
            })
            .map(|e| (e.from.clone(), e.to.clone()))
            .collect()
    }

    fn infer_commitment_type(possibility: &Possibility) -> CommitmentType {
        match &possibility.possibility_type {
            PossibilityType::Infer { conclusion, .. } => CommitmentType::Belief {
                proposition: conclusion.clone(),
            },
            PossibilityType::Act { action, .. } => CommitmentType::Action {
                action_id: action.clone(),
            },
            PossibilityType::Delegate { to_agent, .. } => CommitmentType::Delegation {
                to_agent: to_agent.clone(),
            },
            PossibilityType::Plan { goal, .. } => CommitmentType::Goal {
                desired_state: goal.clone(),
            },
            _ => CommitmentType::Assumption {
                assumption: possibility.description.clone(),
            },
        }
    }

    fn default_revision_conditions(strength: &CommitmentStrength) -> Vec<String> {
        match strength {
            CommitmentStrength::Absolute => vec![],
            CommitmentStrength::Strong => vec![
                "contradicting evidence with confidence > 0.9".into(),
            ],
            CommitmentStrength::Working => vec![
                "contradicting evidence with confidence > 0.7".into(),
                "better alternative discovered".into(),
            ],
            CommitmentStrength::Tentative => vec![
                "any contradicting evidence".into(),
                "any better alternative".into(),
                "timeout exceeded".into(),
            ],
            CommitmentStrength::Hypothetical => vec![
                "any new information".into(),
            ],
        }
    }

    fn detect_commitment_edges(new: &Commitment, register: &mut CommitmentRegister) {
        let existing: Vec<String> = register
            .commitments
            .keys()
            .filter(|k| k.as_str() != new.id)
            .cloned()
            .collect();

        for eid in existing {
            if let Some(existing_c) = register.commitments.get(&eid) {
                if existing_c.status != CommitmentStatus::Active {
                    continue;
                }

                // Shared tensions → strengthens
                let shared_tensions = new.source_tensions.iter()
                    .any(|t| existing_c.source_tensions.contains(t));
                if shared_tensions {
                    register.commitment_graph.push(CommitmentEdge {
                        from: new.id.clone(),
                        to: eid.clone(),
                        relation: CommitmentRelation::Strengthens,
                    });
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_eval(pid: &str, score: f64, rec: EvalRecommendation) -> PossibilityEvaluation {
        PossibilityEvaluation {
            possibility_id: pid.into(),
            scores: EvaluationScores {
                coherence: score,
                utility: score,
                cost: 0.1,
                legality: 1.0,
                evidence: score,
                reversibility: 0.8,
                trust: score,
                urgency_fit: 0.5,
            },
            rank: 0,
            recommendation: rec,
            justification: "test".into(),
            evaluated_by: vec!["general".into()],
        }
    }

    fn make_possibility(id: &str, confidence: f64) -> Possibility {
        Possibility {
            id: id.into(),
            possibility_type: PossibilityType::Act {
                action: "test_action".into(),
                target: "target".into(),
            },
            description: "test possibility".into(),
            preconditions: vec![],
            required_knowledge: vec![],
            expected_value: 0.5,
            risk: 0.3,
            reversibility: Reversibility::FullyReversible,
            dependencies: vec![],
            policy_status: PolicyStatus::Allowed,
            estimated_confidence: confidence,
            estimated_cost: Cost::default(),
            source_tensions: vec!["t1".into()],
            evaluation: None,
        }
    }

    #[test]
    fn test_commit_selects_best() {
        let evals = vec![
            make_eval("p1", 0.6, EvalRecommendation::Tentative),
            make_eval("p2", 0.9, EvalRecommendation::StrongCommit),
        ];
        let possibilities = vec![
            make_possibility("p1", 0.6),
            make_possibility("p2", 0.9),
        ];
        let mut register = CommitmentRegister::default();
        let weights = EvaluationWeights::default();

        let commitment = CommitmentEngine::commit(&evals, &possibilities, &[], &mut register, &weights, 0.5);
        assert!(commitment.is_some());
        let c = commitment.unwrap();
        assert!(c.source_possibilities.contains(&"p2".to_string()));
        assert_eq!(c.strength, CommitmentStrength::Strong);
    }

    #[test]
    fn test_reject_below_threshold() {
        let evals = vec![make_eval("p1", 0.2, EvalRecommendation::Tentative)];
        let possibilities = vec![make_possibility("p1", 0.2)];
        let mut register = CommitmentRegister::default();
        let weights = EvaluationWeights::default();

        let commitment = CommitmentEngine::commit(&evals, &possibilities, &[], &mut register, &weights, 0.5);
        assert!(commitment.is_none());
    }

    #[test]
    fn test_revise_commitment() {
        let mut register = CommitmentRegister::default();
        let c = Commitment {
            id: "c1".into(),
            commitment_type: CommitmentType::Belief { proposition: "test".into() },
            content: "test".into(),
            strength: CommitmentStrength::Working,
            justification: vec![],
            source_possibilities: vec![],
            source_tensions: vec![],
            revisable: true,
            revision_conditions: vec![],
            created_at: 0,
            expires_at: None,
            status: CommitmentStatus::Active,
            evidence_cids: vec![],
        };
        register.commitments.insert("c1".into(), c);

        let result = CommitmentEngine::revise(&mut register, "c1", "new evidence", None);
        assert!(result.is_ok());
        assert!(matches!(register.commitments["c1"].status, CommitmentStatus::Revised { .. }));
    }
}

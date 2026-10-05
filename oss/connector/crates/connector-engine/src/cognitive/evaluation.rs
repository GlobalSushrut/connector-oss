//! # Evaluation Engine
//!
//! Multi-dimensional scoring of possibilities using base scores
//! and domain expertise kernels.

use super::types::*;
use super::expertise::ExpertiseRegistry;

/// Evaluates possibilities across multiple dimensions.
pub struct EvaluationEngine;

impl EvaluationEngine {
    /// Evaluate all possibilities and return ranked evaluations.
    pub fn evaluate(
        possibilities: &[Possibility],
        knowledge: &ActiveKnowledgeSet,
        expertise: &ExpertiseRegistry,
        context: &CognitiveContext,
    ) -> Vec<PossibilityEvaluation> {
        // First pass: prune obviously bad possibilities
        let pruned_ids = expertise.prune_all(possibilities, context);

        let mut evaluations: Vec<PossibilityEvaluation> = possibilities
            .iter()
            .filter(|p| !pruned_ids.contains(&p.id))
            .map(|p| Self::evaluate_single(p, knowledge, expertise, context))
            .collect();

        // Rank by composite score
        evaluations.sort_by(|a, b| {
            let sa = a.scores.composite(&context.evaluation_weights);
            let sb = b.scores.composite(&context.evaluation_weights);
            sb.partial_cmp(&sa).unwrap_or(std::cmp::Ordering::Equal)
        });

        // Assign ranks
        for (i, eval) in evaluations.iter_mut().enumerate() {
            eval.rank = i;
        }

        // Add pruned possibilities as Reject
        for pid in &pruned_ids {
            evaluations.push(PossibilityEvaluation {
                possibility_id: pid.clone(),
                scores: EvaluationScores::default(),
                rank: evaluations.len(),
                recommendation: EvalRecommendation::Reject,
                justification: "pruned by expertise kernel".into(),
                evaluated_by: expertise.domains().into_iter().map(String::from).collect(),
            });
        }

        evaluations
    }

    /// Evaluate a single possibility.
    fn evaluate_single(
        possibility: &Possibility,
        knowledge: &ActiveKnowledgeSet,
        expertise: &ExpertiseRegistry,
        context: &CognitiveContext,
    ) -> PossibilityEvaluation {
        let scores = Self::compute_scores(possibility, knowledge, context);
        let domain_evals = expertise.evaluate_all(possibility, context);

        // Merge domain evaluations into final score
        let mut final_scores = scores;
        let mut warnings = Vec::new();
        let mut evaluators = Vec::new();

        for de in &domain_evals {
            evaluators.push(de.domain.clone());
            warnings.extend(de.domain_warnings.clone());

            // Domain score modulates overall confidence
            if de.domain_score < 0.3 {
                final_scores.coherence *= 0.5;
                final_scores.utility *= 0.5;
            }
        }

        let composite = final_scores.composite(&context.evaluation_weights);
        let recommendation = Self::recommend(composite, possibility);

        let mut justification_parts = Vec::new();
        justification_parts.push(format!("composite={:.3}", composite));
        if !warnings.is_empty() {
            justification_parts.push(format!("warnings: {}", warnings.join("; ")));
        }

        PossibilityEvaluation {
            possibility_id: possibility.id.clone(),
            scores: final_scores,
            rank: 0, // assigned later
            recommendation,
            justification: justification_parts.join(" | "),
            evaluated_by: evaluators,
        }
    }

    /// Compute base evaluation scores for a possibility.
    fn compute_scores(
        possibility: &Possibility,
        knowledge: &ActiveKnowledgeSet,
        context: &CognitiveContext,
    ) -> EvaluationScores {
        // Coherence: how well does this fit with existing commitments?
        let coherence = Self::score_coherence(possibility, context);

        // Utility: expected value normalized
        let utility = possibility.expected_value.clamp(0.0, 1.0);

        // Cost: inverse of estimated cost (lower cost = higher score)
        let cost = Self::score_cost(possibility);

        // Legality: from policy status
        let legality = match possibility.policy_status {
            PolicyStatus::Allowed => 1.0,
            PolicyStatus::Unknown => 0.5,
            PolicyStatus::RequiresApproval => 0.3,
            PolicyStatus::Forbidden => 0.0,
        };

        // Evidence: based on required knowledge availability
        let evidence = Self::score_evidence(possibility, knowledge);

        // Reversibility
        let reversibility = match possibility.reversibility {
            Reversibility::FullyReversible => 1.0,
            Reversibility::PartiallyReversible => 0.5,
            Reversibility::Irreversible => 0.1,
        };

        // Trust: from confidence
        let trust = possibility.estimated_confidence.clamp(0.0, 1.0);

        // Urgency fit: check deadline against estimated cost
        let urgency_fit = Self::score_urgency_fit(possibility, context);

        EvaluationScores {
            coherence,
            utility,
            cost,
            legality,
            evidence,
            reversibility,
            trust,
            urgency_fit,
        }
    }

    fn score_coherence(possibility: &Possibility, context: &CognitiveContext) -> f64 {
        // Check if the possibility aligns with existing commitments
        let active_commitments: Vec<&Commitment> = context.active_commitments.commitments
            .values()
            .filter(|c| c.status == CommitmentStatus::Active)
            .collect();

        if active_commitments.is_empty() {
            return 0.7; // neutral if no commitments yet
        }

        // Simple heuristic: shared source tensions = more coherent
        let shared = possibility.source_tensions.iter()
            .filter(|t| active_commitments.iter().any(|c| c.source_tensions.contains(t)))
            .count();

        let ratio = shared as f64 / possibility.source_tensions.len().max(1) as f64;
        0.5 + 0.5 * ratio
    }

    fn score_cost(possibility: &Possibility) -> f64 {
        let c = &possibility.estimated_cost;
        // Normalize: lower cost = higher score
        let token_score = 1.0 / (1.0 + c.tokens as f64 / 1000.0);
        let time_score = 1.0 / (1.0 + c.time_ms as f64 / 5000.0);
        let money_score = 1.0 / (1.0 + c.monetary * 10.0);
        (token_score + time_score + money_score) / 3.0
    }

    fn score_evidence(possibility: &Possibility, knowledge: &ActiveKnowledgeSet) -> f64 {
        if possibility.required_knowledge.is_empty() {
            return 0.7; // no knowledge required = neutral
        }

        // How much of the required knowledge is available?
        let available = possibility.required_knowledge.iter()
            .filter(|rk| {
                knowledge.knowledge.iter().any(|ak| {
                    match &ak.form {
                        KnowledgeForm::Declarative { entity, .. } => entity.contains(rk.as_str()),
                        KnowledgeForm::Procedural { name, .. } => name.contains(rk.as_str()),
                        KnowledgeForm::Structural { from, to, .. } => from.contains(rk.as_str()) || to.contains(rk.as_str()),
                        _ => false,
                    }
                })
            })
            .count();

        available as f64 / possibility.required_knowledge.len() as f64
    }

    fn score_urgency_fit(possibility: &Possibility, context: &CognitiveContext) -> f64 {
        match context.deadline {
            Some(deadline) => {
                let now = chrono::Utc::now().timestamp_millis();
                let remaining_ms = (deadline - now).max(0) as u64;
                if possibility.estimated_cost.time_ms > remaining_ms {
                    0.1 // too slow for deadline
                } else {
                    let ratio = possibility.estimated_cost.time_ms as f64 / remaining_ms as f64;
                    1.0 - ratio // more time remaining = better fit
                }
            }
            None => 0.5, // no deadline = neutral
        }
    }

    fn recommend(composite: f64, possibility: &Possibility) -> EvalRecommendation {
        if possibility.policy_status == PolicyStatus::Forbidden {
            return EvalRecommendation::Reject;
        }
        match composite {
            x if x >= 0.8 => EvalRecommendation::StrongCommit,
            x if x >= 0.6 => EvalRecommendation::Commit,
            x if x >= 0.4 => EvalRecommendation::Tentative,
            x if x >= 0.2 => EvalRecommendation::Defer,
            _ => EvalRecommendation::Reject,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_possibility(id: &str, value: f64, confidence: f64) -> Possibility {
        Possibility {
            id: id.into(),
            possibility_type: PossibilityType::Act {
                action: "test".into(),
                target: "target".into(),
            },
            description: "test".into(),
            preconditions: vec![],
            required_knowledge: vec![],
            expected_value: value,
            risk: 0.2,
            reversibility: Reversibility::FullyReversible,
            dependencies: vec![],
            policy_status: PolicyStatus::Allowed,
            estimated_confidence: confidence,
            estimated_cost: Cost { tokens: 100, time_ms: 500, monetary: 0.0 },
            source_tensions: vec!["t1".into()],
            evaluation: None,
        }
    }

    #[test]
    fn test_evaluate_ranks_by_score() {
        let possibilities = vec![
            make_possibility("p1", 0.3, 0.3),
            make_possibility("p2", 0.9, 0.9),
            make_possibility("p3", 0.5, 0.5),
        ];
        let knowledge = ActiveKnowledgeSet::default();
        let expertise = ExpertiseRegistry::new();
        let context = CognitiveContext::default();

        let evals = EvaluationEngine::evaluate(&possibilities, &knowledge, &expertise, &context);
        assert_eq!(evals[0].possibility_id, "p2");
        assert_eq!(evals[0].rank, 0);
    }

    #[test]
    fn test_forbidden_gets_rejected() {
        let mut p = make_possibility("p1", 0.9, 0.9);
        p.policy_status = PolicyStatus::Forbidden;
        let knowledge = ActiveKnowledgeSet::default();
        let expertise = ExpertiseRegistry::new();
        let context = CognitiveContext::default();

        let evals = EvaluationEngine::evaluate(&[p], &knowledge, &expertise, &context);
        // The general kernel prunes forbidden, so it should be rejected
        assert!(evals.iter().any(|e| e.recommendation == EvalRecommendation::Reject));
    }
}

//! # Reflection Engine
//!
//! Post-action comparison: expected vs actual, intended vs observed.
//! Generates learning deltas and tension updates from execution results.

use super::types::*;

/// Engine for reflecting on executed commitments and updating the cognitive state.
pub struct ReflectionEngine;

impl ReflectionEngine {
    /// Reflect on a completed commitment by comparing expected outcomes to actual results.
    pub fn reflect(
        commitment: &Commitment,
        expected: &Possibility,
        actual_result: &serde_json::Value,
        active_knowledge: &ActiveKnowledgeSet,
    ) -> ReflectionRecord {
        let now = chrono::Utc::now().timestamp();
        let record_id = format!("reflect:{}:{}", now, commitment.id);

        let comparisons = Self::build_comparisons(expected, actual_result);
        let overall = Self::assess_overall(&comparisons);
        let learning = Self::extract_learning(commitment, expected, actual_result, &overall);
        let tension_updates = Self::compute_tension_updates(commitment, &overall);

        ReflectionRecord {
            id: record_id,
            commitment_id: commitment.id.clone(),
            comparisons,
            learning_delta: learning,
            plan_revisions: Self::suggest_plan_revisions(&overall),
            tension_updates,
            overall_assessment: overall,
        }
    }

    /// Build comparisons between expected and actual outcomes.
    fn build_comparisons(
        expected: &Possibility,
        actual: &serde_json::Value,
    ) -> Vec<ReflectionComparison> {
        let mut comparisons = Vec::new();

        // Compare expected value vs actual success indicator
        let actual_success = actual.get("success")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let expected_value = expected.expected_value;
        let actual_value = if actual_success { 1.0 } else { 0.0 };
        let delta = actual_value - expected_value;

        comparisons.push(ReflectionComparison {
            dimension: "value".into(),
            expected: serde_json::json!(expected_value),
            actual: serde_json::json!(actual_value),
            delta,
            significance: Self::classify_significance(delta.abs()),
        });

        // Compare expected risk vs actual problems
        let actual_errors = actual.get("errors")
            .and_then(|v| v.as_array())
            .map(|a| a.len())
            .unwrap_or(0);
        let risk_delta = actual_errors as f64 * 0.2 - expected.risk;

        comparisons.push(ReflectionComparison {
            dimension: "risk".into(),
            expected: serde_json::json!(expected.risk),
            actual: serde_json::json!(actual_errors as f64 * 0.2),
            delta: risk_delta,
            significance: Self::classify_significance(risk_delta.abs()),
        });

        // Compare expected cost vs actual
        if let Some(actual_tokens) = actual.get("tokens_used").and_then(|v| v.as_u64()) {
            let expected_tokens = expected.estimated_cost.tokens;
            let token_delta = actual_tokens as f64 - expected_tokens as f64;
            comparisons.push(ReflectionComparison {
                dimension: "token_cost".into(),
                expected: serde_json::json!(expected_tokens),
                actual: serde_json::json!(actual_tokens),
                delta: token_delta,
                significance: Self::classify_significance(token_delta.abs() / expected_tokens.max(1) as f64),
            });
        }

        if let Some(actual_time) = actual.get("time_ms").and_then(|v| v.as_u64()) {
            let expected_time = expected.estimated_cost.time_ms;
            let time_delta = actual_time as f64 - expected_time as f64;
            comparisons.push(ReflectionComparison {
                dimension: "time_cost".into(),
                expected: serde_json::json!(expected_time),
                actual: serde_json::json!(actual_time),
                delta: time_delta,
                significance: Self::classify_significance(time_delta.abs() / expected_time.max(1) as f64),
            });
        }

        comparisons
    }

    fn classify_significance(abs_delta: f64) -> Significance {
        match abs_delta {
            x if x >= 0.8 => Significance::Critical,
            x if x >= 0.4 => Significance::Significant,
            x if x >= 0.1 => Significance::Minor,
            _ => Significance::Negligible,
        }
    }

    /// Assess overall reflection outcome.
    fn assess_overall(comparisons: &[ReflectionComparison]) -> ReflectionAssessment {
        if comparisons.is_empty() {
            return ReflectionAssessment::AsExpected;
        }

        let value_comp = comparisons.iter().find(|c| c.dimension == "value");

        match value_comp {
            Some(vc) if vc.delta > 0.3 => ReflectionAssessment::BetterThanExpected { delta: vc.delta },
            Some(vc) if vc.delta < -0.5 => {
                let has_critical = comparisons.iter().any(|c| c.significance == Significance::Critical);
                if has_critical {
                    ReflectionAssessment::CompletelyWrong {
                        root_cause: "critical deviation from expected outcome".into(),
                    }
                } else {
                    ReflectionAssessment::WorseThanExpected {
                        delta: vc.delta,
                        corrective: Some("review assumptions and retry".into()),
                    }
                }
            }
            Some(vc) if vc.delta < -0.1 => ReflectionAssessment::WorseThanExpected {
                delta: vc.delta,
                corrective: None,
            },
            _ => ReflectionAssessment::AsExpected,
        }
    }

    /// Extract learning from the reflection.
    fn extract_learning(
        commitment: &Commitment,
        expected: &Possibility,
        actual: &serde_json::Value,
        assessment: &ReflectionAssessment,
    ) -> Vec<KnowledgeForm> {
        let mut learning = Vec::new();

        let success = matches!(assessment,
            ReflectionAssessment::AsExpected | ReflectionAssessment::BetterThanExpected { .. }
        );

        // Experiential knowledge: what happened and what we learned
        learning.push(KnowledgeForm::Experiential {
            situation: commitment.content.clone(),
            action_taken: expected.description.clone(),
            outcome: format!("{}", actual),
            lesson: match assessment {
                ReflectionAssessment::AsExpected => "approach worked as expected".into(),
                ReflectionAssessment::BetterThanExpected { delta } =>
                    format!("approach exceeded expectations by {:.2}", delta),
                ReflectionAssessment::WorseThanExpected { delta, corrective } =>
                    format!("approach underperformed by {:.2}{}",
                        delta.abs(),
                        corrective.as_ref().map(|c| format!("; corrective: {}", c)).unwrap_or_default()
                    ),
                ReflectionAssessment::CompletelyWrong { root_cause } =>
                    format!("approach failed completely: {}", root_cause),
            },
            success,
        });

        // If the approach worked, extract causal knowledge
        if success {
            if let PossibilityType::Act { action, target } = &expected.possibility_type {
                learning.push(KnowledgeForm::Causal {
                    cause: action.clone(),
                    effect: format!("resolved: {}", commitment.content),
                    strength: expected.estimated_confidence,
                    conditions: commitment.source_tensions.clone(),
                });
            }
        }

        learning
    }

    /// Compute tension updates from the reflection.
    fn compute_tension_updates(
        commitment: &Commitment,
        assessment: &ReflectionAssessment,
    ) -> Vec<TensionUpdate> {
        let mut updates = Vec::new();

        for tid in &commitment.source_tensions {
            match assessment {
                ReflectionAssessment::AsExpected | ReflectionAssessment::BetterThanExpected { .. } => {
                    updates.push(TensionUpdate {
                        tension_id: tid.clone(),
                        update_type: TensionUpdateType::Resolved,
                    });
                }
                ReflectionAssessment::WorseThanExpected { .. } => {
                    updates.push(TensionUpdate {
                        tension_id: tid.clone(),
                        update_type: TensionUpdateType::Intensified { new_intensity: 0.8 },
                    });
                }
                ReflectionAssessment::CompletelyWrong { .. } => {
                    updates.push(TensionUpdate {
                        tension_id: tid.clone(),
                        update_type: TensionUpdateType::Intensified { new_intensity: 1.0 },
                    });
                }
            }
        }

        updates
    }

    /// Suggest plan revisions based on reflection.
    fn suggest_plan_revisions(assessment: &ReflectionAssessment) -> Vec<String> {
        match assessment {
            ReflectionAssessment::AsExpected => vec![],
            ReflectionAssessment::BetterThanExpected { .. } => vec![],
            ReflectionAssessment::WorseThanExpected { corrective, .. } => {
                let mut revisions = vec!["review and adjust approach".into()];
                if let Some(c) = corrective {
                    revisions.push(c.clone());
                }
                revisions
            }
            ReflectionAssessment::CompletelyWrong { root_cause } => {
                vec![
                    format!("abort current plan: {}", root_cause),
                    "re-evaluate all active commitments".into(),
                    "generate new possibilities from scratch".into(),
                ]
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_commitment() -> Commitment {
        Commitment {
            id: "c1".into(),
            commitment_type: CommitmentType::Action { action_id: "act1".into() },
            content: "test action".into(),
            strength: CommitmentStrength::Working,
            justification: vec![],
            source_possibilities: vec!["p1".into()],
            source_tensions: vec!["t1".into()],
            revisable: true,
            revision_conditions: vec![],
            created_at: 0,
            expires_at: None,
            status: CommitmentStatus::Executed,
            evidence_cids: vec![],
        }
    }

    fn make_possibility() -> Possibility {
        Possibility {
            id: "p1".into(),
            possibility_type: PossibilityType::Act {
                action: "test".into(),
                target: "target".into(),
            },
            description: "test possibility".into(),
            preconditions: vec![],
            required_knowledge: vec![],
            expected_value: 0.7,
            risk: 0.2,
            reversibility: Reversibility::FullyReversible,
            dependencies: vec![],
            policy_status: PolicyStatus::Allowed,
            estimated_confidence: 0.8,
            estimated_cost: Cost { tokens: 500, time_ms: 2000, monetary: 0.0 },
            source_tensions: vec!["t1".into()],
            evaluation: None,
        }
    }

    #[test]
    fn test_reflect_success() {
        let commitment = make_commitment();
        let possibility = make_possibility();
        let result = serde_json::json!({ "success": true, "tokens_used": 400, "time_ms": 1800 });
        let knowledge = ActiveKnowledgeSet::default();

        let record = ReflectionEngine::reflect(&commitment, &possibility, &result, &knowledge);
        assert!(matches!(record.overall_assessment, ReflectionAssessment::BetterThanExpected { .. }));
        assert!(!record.learning_delta.is_empty());
        assert!(record.tension_updates.iter().any(|u| matches!(u.update_type, TensionUpdateType::Resolved)));
    }

    #[test]
    fn test_reflect_failure() {
        let commitment = make_commitment();
        let possibility = make_possibility();
        let result = serde_json::json!({ "success": false, "errors": ["timeout", "auth_failed", "rate_limited"] });
        let knowledge = ActiveKnowledgeSet::default();

        let record = ReflectionEngine::reflect(&commitment, &possibility, &result, &knowledge);
        assert!(matches!(
            record.overall_assessment,
            ReflectionAssessment::WorseThanExpected { .. } | ReflectionAssessment::CompletelyWrong { .. }
        ));
    }
}

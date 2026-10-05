//! # Exposure Engine
//!
//! Multi-audience rendering from the thought substrate.
//! The same ThoughtRecord produces different explanations for different audiences.

use super::types::*;

/// Renders thought substrate into audience-appropriate explanations.
pub struct ExposureEngine;

impl ExposureEngine {
    /// Render a thought record for a specific audience at a given depth.
    pub fn render(
        record: &ThoughtRecord,
        audience: ExplanationAudience,
        depth: ExplanationDepth,
    ) -> Explanation {
        let sections = match (audience, depth) {
            (ExplanationAudience::Human, ExplanationDepth::Summary) =>
                Self::human_summary(record),
            (ExplanationAudience::Human, _) =>
                Self::human_standard(record, depth),
            (ExplanationAudience::PeerAgent, _) =>
                Self::peer_agent(record),
            (ExplanationAudience::AuditTrail, _) =>
                Self::audit_trail(record),
            (ExplanationAudience::Debugger, _) =>
                Self::debugger(record),
            (ExplanationAudience::ComplianceOfficer, _) =>
                Self::compliance(record),
        };

        Explanation {
            target_audience: audience,
            depth,
            sections,
        }
    }

    fn human_summary(record: &ThoughtRecord) -> Vec<ExplanationSection> {
        let mut sections = Vec::new();

        // What was decided
        if let Some(commitment) = record.commitments.first() {
            sections.push(ExplanationSection {
                title: "Decision".into(),
                content: commitment.content.clone(),
                evidence_cids: commitment.evidence_cids.clone(),
                related_tensions: commitment.source_tensions.clone(),
                related_commitments: vec![commitment.id.clone()],
            });
        }

        // Why (one-line justification)
        if let Some(commitment) = record.commitments.first() {
            if let Some(justification) = commitment.justification.first() {
                sections.push(ExplanationSection {
                    title: "Reason".into(),
                    content: justification.clone(),
                    evidence_cids: vec![],
                    related_tensions: vec![],
                    related_commitments: vec![],
                });
            }
        }

        sections
    }

    fn human_standard(record: &ThoughtRecord, depth: ExplanationDepth) -> Vec<ExplanationSection> {
        let mut sections = Self::human_summary(record);

        // What tensions drove the thinking
        if !record.tensions.is_empty() {
            let tension_summary: Vec<String> = record.tensions.iter()
                .map(|t| format!("- {} (intensity: {:.2})", Self::tension_description(t), t.intensity))
                .collect();
            sections.push(ExplanationSection {
                title: "What needed resolution".into(),
                content: tension_summary.join("\n"),
                evidence_cids: vec![],
                related_tensions: record.tensions.iter().map(|t| t.id.clone()).collect(),
                related_commitments: vec![],
            });
        }

        // Alternatives considered (if detailed)
        if matches!(depth, ExplanationDepth::Detailed | ExplanationDepth::Full) {
            let alternatives: Vec<String> = record.evaluations.iter()
                .take(5)
                .map(|e| {
                    let poss = record.possibility_set.iter().find(|p| p.id == e.possibility_id);
                    let desc = poss.map(|p| p.description.as_str()).unwrap_or("unknown");
                    format!("- {} ({:?}, score rank #{})", desc, e.recommendation, e.rank + 1)
                })
                .collect();
            if !alternatives.is_empty() {
                sections.push(ExplanationSection {
                    title: "Alternatives considered".into(),
                    content: alternatives.join("\n"),
                    evidence_cids: vec![],
                    related_tensions: vec![],
                    related_commitments: vec![],
                });
            }
        }

        // Reflection (if available)
        if let Some(ref reflection) = record.reflection {
            sections.push(ExplanationSection {
                title: "Reflection".into(),
                content: format!("{:?}", reflection.overall_assessment),
                evidence_cids: vec![],
                related_tensions: vec![],
                related_commitments: vec![reflection.commitment_id.clone()],
            });
        }

        sections
    }

    fn peer_agent(record: &ThoughtRecord) -> Vec<ExplanationSection> {
        let mut sections = Vec::new();

        // Share tensions for collaborative reasoning
        if !record.tensions.is_empty() {
            let tension_data = serde_json::to_string_pretty(&record.tensions).unwrap_or_default();
            sections.push(ExplanationSection {
                title: "Active tensions".into(),
                content: tension_data,
                evidence_cids: vec![],
                related_tensions: record.tensions.iter().map(|t| t.id.clone()).collect(),
                related_commitments: vec![],
            });
        }

        // Share commitments for coordination
        if !record.commitments.is_empty() {
            let commitment_data = serde_json::to_string_pretty(&record.commitments).unwrap_or_default();
            sections.push(ExplanationSection {
                title: "Active commitments".into(),
                content: commitment_data,
                evidence_cids: record.commitments.iter()
                    .flat_map(|c| c.evidence_cids.clone())
                    .collect(),
                related_tensions: vec![],
                related_commitments: record.commitments.iter().map(|c| c.id.clone()).collect(),
            });
        }

        // Share plan fragment if available
        if let Some(ref plan) = record.plan {
            let plan_data = serde_json::to_string_pretty(plan).unwrap_or_default();
            sections.push(ExplanationSection {
                title: "Active plan".into(),
                content: plan_data,
                evidence_cids: vec![],
                related_tensions: vec![plan.goal_tension.clone()],
                related_commitments: vec![plan.commitment_id.clone()],
            });
        }

        sections
    }

    fn audit_trail(record: &ThoughtRecord) -> Vec<ExplanationSection> {
        let mut sections = Vec::new();

        // Full CID chain
        sections.push(ExplanationSection {
            title: "Thought provenance".into(),
            content: format!(
                "agent={}, cycle={}, timestamp={}, prev_cid={:?}, cid={:?}",
                record.agent_pid, record.cycle_number, record.timestamp,
                record.prev_thought_cid, record.thought_cid
            ),
            evidence_cids: record.thought_cid.clone().into_iter().collect(),
            related_tensions: vec![],
            related_commitments: vec![],
        });

        // Trigger
        sections.push(ExplanationSection {
            title: "Trigger".into(),
            content: format!("{:?}", record.seed.trigger_type),
            evidence_cids: vec![],
            related_tensions: vec![],
            related_commitments: vec![],
        });

        // All commitments with justification
        for c in &record.commitments {
            sections.push(ExplanationSection {
                title: format!("Commitment: {}", c.id),
                content: format!(
                    "type={:?}, strength={:?}, content={}, justification={:?}",
                    c.commitment_type, c.strength, c.content, c.justification
                ),
                evidence_cids: c.evidence_cids.clone(),
                related_tensions: c.source_tensions.clone(),
                related_commitments: vec![c.id.clone()],
            });
        }

        // All evaluations
        for e in &record.evaluations {
            sections.push(ExplanationSection {
                title: format!("Evaluation: {}", e.possibility_id),
                content: format!(
                    "rank={}, rec={:?}, scores={{coh={:.2}, util={:.2}, cost={:.2}, legal={:.2}, evid={:.2}, rev={:.2}, trust={:.2}, urg={:.2}}}, justification={}",
                    e.rank, e.recommendation,
                    e.scores.coherence, e.scores.utility, e.scores.cost,
                    e.scores.legality, e.scores.evidence, e.scores.reversibility,
                    e.scores.trust, e.scores.urgency_fit, e.justification
                ),
                evidence_cids: vec![],
                related_tensions: vec![],
                related_commitments: vec![],
            });
        }

        sections
    }

    fn debugger(record: &ThoughtRecord) -> Vec<ExplanationSection> {
        // Full dump of the entire thought record
        let full_dump = serde_json::to_string_pretty(record).unwrap_or_else(|e| format!("serialization error: {}", e));
        vec![ExplanationSection {
            title: "Full ThoughtRecord dump".into(),
            content: full_dump,
            evidence_cids: record.thought_cid.clone().into_iter().collect(),
            related_tensions: record.tensions.iter().map(|t| t.id.clone()).collect(),
            related_commitments: record.commitments.iter().map(|c| c.id.clone()).collect(),
        }]
    }

    fn compliance(record: &ThoughtRecord) -> Vec<ExplanationSection> {
        let mut sections = Vec::new();

        // Policy compliance of all possibilities considered
        let policy_summary: Vec<String> = record.possibility_set.iter()
            .map(|p| format!("- {} → {:?}", p.description, p.policy_status))
            .collect();
        sections.push(ExplanationSection {
            title: "Policy compliance".into(),
            content: policy_summary.join("\n"),
            evidence_cids: vec![],
            related_tensions: vec![],
            related_commitments: vec![],
        });

        // Evidence chain for each commitment
        for c in &record.commitments {
            sections.push(ExplanationSection {
                title: format!("Evidence for: {}", c.content),
                content: format!(
                    "strength={:?}, justification={:?}, evidence_cids={:?}",
                    c.strength, c.justification, c.evidence_cids
                ),
                evidence_cids: c.evidence_cids.clone(),
                related_tensions: c.source_tensions.clone(),
                related_commitments: vec![c.id.clone()],
            });
        }

        // Reflection assessment
        if let Some(ref reflection) = record.reflection {
            sections.push(ExplanationSection {
                title: "Outcome assessment".into(),
                content: format!("{:?}", reflection.overall_assessment),
                evidence_cids: vec![],
                related_tensions: vec![],
                related_commitments: vec![reflection.commitment_id.clone()],
            });
        }

        sections
    }

    fn tension_description(tension: &Tension) -> String {
        match &tension.tension_type {
            TensionType::GoalGap { current, desired } =>
                format!("Goal gap: '{}' → '{}'", current, desired),
            TensionType::DataMissing { what, .. } =>
                format!("Missing data: {}", what),
            TensionType::ContradictionDetected { claim_a, claim_b } =>
                format!("Contradiction: '{}' vs '{}'", claim_a, claim_b),
            TensionType::Ambiguity { interpretations } =>
                format!("Ambiguity: {} interpretations", interpretations.len()),
            TensionType::RiskTooHigh { risk, .. } =>
                format!("High risk: {}", risk),
            TensionType::PolicyConflict { policy_a, policy_b } =>
                format!("Policy conflict: {} vs {}", policy_a, policy_b),
            TensionType::ResourceConstrained { resource, .. } =>
                format!("Resource constrained: {}", resource),
            TensionType::TimeoutPressure { deadline } =>
                format!("Timeout pressure: deadline={}", deadline),
            TensionType::TrustDeficit { entity, .. } =>
                format!("Trust deficit: {}", entity),
            TensionType::ExpertiseGap { domain } =>
                format!("Expertise gap: {}", domain),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_record() -> ThoughtRecord {
        ThoughtRecord {
            id: "tr:1".into(),
            agent_pid: "pid:bot".into(),
            cycle_number: 1,
            timestamp: 1000,
            seed: ThoughtSeed {
                trigger_type: TriggerType::UserRequest,
                perception_ids: vec!["perc:1".into()],
                meaning_ids: vec!["m:1".into()],
            },
            tensions: vec![Tension {
                id: "t:1".into(),
                tension_type: TensionType::GoalGap {
                    current: "unknown".into(),
                    desired: "diagnosed".into(),
                },
                source_meanings: vec!["m:1".into()],
                intensity: 0.8,
                created_at: 1000,
                deadline: None,
                resolution: TensionResolution::Unresolved,
                related_tensions: vec![],
            }],
            active_knowledge: ActiveKnowledgeSet::default(),
            possibility_set: vec![Possibility {
                id: "p:1".into(),
                possibility_type: PossibilityType::Act {
                    action: "diagnose".into(),
                    target: "patient".into(),
                },
                description: "Run diagnostic procedure".into(),
                preconditions: vec![],
                required_knowledge: vec![],
                expected_value: 0.8,
                risk: 0.1,
                reversibility: Reversibility::FullyReversible,
                dependencies: vec![],
                policy_status: PolicyStatus::Allowed,
                estimated_confidence: 0.9,
                estimated_cost: Cost::default(),
                source_tensions: vec!["t:1".into()],
                evaluation: None,
            }],
            evaluations: vec![PossibilityEvaluation {
                possibility_id: "p:1".into(),
                scores: EvaluationScores::default(),
                rank: 0,
                recommendation: EvalRecommendation::Commit,
                justification: "best option".into(),
                evaluated_by: vec!["general".into()],
            }],
            commitments: vec![Commitment {
                id: "c:1".into(),
                commitment_type: CommitmentType::Action { action_id: "diagnose".into() },
                content: "Run diagnostic procedure".into(),
                strength: CommitmentStrength::Working,
                justification: vec!["highest evaluated option".into()],
                source_possibilities: vec!["p:1".into()],
                source_tensions: vec!["t:1".into()],
                revisable: true,
                revision_conditions: vec![],
                created_at: 1000,
                expires_at: None,
                status: CommitmentStatus::Active,
                evidence_cids: vec![],
            }],
            plan: None,
            reflection: None,
            prev_thought_cid: None,
            thought_cid: Some("cid:abc123".into()),
        }
    }

    #[test]
    fn test_human_summary() {
        let record = make_record();
        let explanation = ExposureEngine::render(&record, ExplanationAudience::Human, ExplanationDepth::Summary);
        assert_eq!(explanation.sections.len(), 2);
        assert_eq!(explanation.sections[0].title, "Decision");
    }

    #[test]
    fn test_audit_trail_includes_provenance() {
        let record = make_record();
        let explanation = ExposureEngine::render(&record, ExplanationAudience::AuditTrail, ExplanationDepth::Full);
        assert!(explanation.sections.iter().any(|s| s.title == "Thought provenance"));
    }

    #[test]
    fn test_debugger_produces_full_dump() {
        let record = make_record();
        let explanation = ExposureEngine::render(&record, ExplanationAudience::Debugger, ExplanationDepth::Full);
        assert_eq!(explanation.sections.len(), 1);
        assert!(explanation.sections[0].content.contains("tr:1"));
    }

    #[test]
    fn test_peer_agent_shares_tensions_and_commitments() {
        let record = make_record();
        let explanation = ExposureEngine::render(&record, ExplanationAudience::PeerAgent, ExplanationDepth::Standard);
        assert!(explanation.sections.iter().any(|s| s.title == "Active tensions"));
        assert!(explanation.sections.iter().any(|s| s.title == "Active commitments"));
    }
}

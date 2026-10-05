//! # Cognitive Cycle — Full 11-Layer Pipeline
//!
//! Orchestrates the complete cognitive cycle from perception through
//! reflection. Each layer produces typed output consumed by the next.
//! Checkpoints are saved at each layer transition for recovery.

use super::types::*;
use super::tension::TensionEngine;
use super::possibility::PossibilityGenerator;
use super::evaluation::EvaluationEngine;
use super::expertise::ExpertiseRegistry;
use super::commitment::CommitmentEngine;
use super::plan::PlanEngine;
use super::reflection::ReflectionEngine;
use super::exposure::ExposureEngine;
use super::checkpoint::CheckpointManager;

/// Result of a full cognitive cycle.
#[derive(Debug, Clone)]
pub struct CognitiveCycleResult {
    pub thought_record: ThoughtRecord,
    pub explanation: Explanation,
    pub plan: Option<CognitivePlan>,
    pub new_knowledge: Vec<KnowledgeForm>,
    pub completed: bool,
    pub layers_executed: u8,
}

/// Configuration for a cognitive cycle.
#[derive(Debug, Clone)]
pub struct CycleConfig {
    pub audience: ExplanationAudience,
    pub explanation_depth: ExplanationDepth,
    pub max_cycles: u32,
    pub tension_threshold: f64,
}

impl Default for CycleConfig {
    fn default() -> Self {
        Self {
            audience: ExplanationAudience::Human,
            explanation_depth: ExplanationDepth::Standard,
            max_cycles: 5,
            tension_threshold: 0.05,
        }
    }
}

/// The cognitive substrate — orchestrates the full 11-layer pipeline.
pub struct CognitiveSubstrate {
    pub expertise: ExpertiseRegistry,
    pub checkpoint_mgr: CheckpointManager,
    pub cycle_count: u32,
    pub context: CognitiveContext,
}

impl CognitiveSubstrate {
    pub fn new(context: CognitiveContext) -> Self {
        Self {
            expertise: ExpertiseRegistry::new(),
            checkpoint_mgr: CheckpointManager::default(),
            cycle_count: 0,
            context,
        }
    }

    /// Run a single cognitive cycle over a set of perception objects.
    ///
    /// Flow: Perception → Meaning → Tension → Knowledge → Possibility →
    ///       Evaluation → Expertise → Commitment → Plan → Exposure → (Reflection)
    pub fn run_cycle(
        &mut self,
        perceptions: Vec<PerceptionObject>,
        prior_knowledge: ActiveKnowledgeSet,
        config: &CycleConfig,
    ) -> Result<CognitiveCycleResult, String> {
        self.cycle_count += 1;
        let cycle = self.cycle_count;
        let agent_pid = self.context.agent_pid.clone();
        let now = chrono::Utc::now().timestamp();

        // ── Layer 0 → 1: Perception → Meaning Formation ────────────────
        let meanings = Self::form_meanings(&perceptions);
        self.checkpoint_mgr.save(&agent_pid, cycle, 1, ThoughtCheckpointState {
            meanings: meanings.clone(),
            tensions: TensionGraph::default(),
            active_knowledge: None,
            possibilities: vec![],
            evaluations: vec![],
            commitments: self.context.active_commitments.clone(),
            plan: None,
        });

        // ── Layer 2: Tension Detection ─────────────────────────────────
        let tension_graph = TensionEngine::detect(
            &meanings,
            &self.context.active_commitments,
            &TensionGraph::default(),
        );

        let total_tension = TensionEngine::total_intensity(&tension_graph);
        if total_tension < config.tension_threshold {
            // No tension → no thought needed
            let record = ThoughtRecord {
                id: format!("thought:{}:{}", agent_pid, cycle),
                agent_pid: agent_pid.clone(),
                cycle_number: cycle,
                timestamp: now,
                seed: ThoughtSeed {
                    trigger_type: Self::infer_trigger(&perceptions),
                    perception_ids: perceptions.iter().map(|p| p.id.clone()).collect(),
                    meaning_ids: meanings.iter().map(|m| m.id.clone()).collect(),
                },
                tensions: vec![],
                active_knowledge: ActiveKnowledgeSet::default(),
                possibility_set: vec![],
                evaluations: vec![],
                commitments: vec![],
                plan: None,
                reflection: None,
                prev_thought_cid: None,
                thought_cid: None,
            };
            let explanation = ExposureEngine::render(&record, config.audience, config.explanation_depth);
            return Ok(CognitiveCycleResult {
                thought_record: record,
                explanation,
                plan: None,
                new_knowledge: vec![],
                completed: true,
                layers_executed: 2,
            });
        }

        let unresolved = TensionEngine::unresolved_sorted(&tension_graph);
        let tensions_snapshot: Vec<Tension> = unresolved.iter().map(|t| (*t).clone()).collect();

        self.checkpoint_mgr.save(&agent_pid, cycle, 2, ThoughtCheckpointState {
            meanings: meanings.clone(),
            tensions: tension_graph.clone(),
            active_knowledge: None,
            possibilities: vec![],
            evaluations: vec![],
            commitments: self.context.active_commitments.clone(),
            plan: None,
        });

        // ── Layer 3: Knowledge Activation ──────────────────────────────
        // Use provided knowledge (from KnotEngine/RagEngine externally)
        let active_knowledge = prior_knowledge;
        self.checkpoint_mgr.save(&agent_pid, cycle, 3, ThoughtCheckpointState {
            meanings: meanings.clone(),
            tensions: tension_graph.clone(),
            active_knowledge: Some(active_knowledge.clone()),
            possibilities: vec![],
            evaluations: vec![],
            commitments: self.context.active_commitments.clone(),
            plan: None,
        });

        // ── Layer 4: Possibility Generation ────────────────────────────
        let tension_refs: Vec<&Tension> = tensions_snapshot.iter().collect();
        let possibilities = PossibilityGenerator::generate(
            &tension_refs,
            &active_knowledge,
            &self.context,
        );
        self.checkpoint_mgr.save(&agent_pid, cycle, 4, ThoughtCheckpointState {
            meanings: meanings.clone(),
            tensions: tension_graph.clone(),
            active_knowledge: Some(active_knowledge.clone()),
            possibilities: possibilities.clone(),
            evaluations: vec![],
            commitments: self.context.active_commitments.clone(),
            plan: None,
        });

        // ── Layer 5+6: Evaluation + Expertise ──────────────────────────
        let evaluations = EvaluationEngine::evaluate(
            &possibilities,
            &active_knowledge,
            &self.expertise,
            &self.context,
        );
        self.checkpoint_mgr.save(&agent_pid, cycle, 6, ThoughtCheckpointState {
            meanings: meanings.clone(),
            tensions: tension_graph.clone(),
            active_knowledge: Some(active_knowledge.clone()),
            possibilities: possibilities.clone(),
            evaluations: evaluations.clone(),
            commitments: self.context.active_commitments.clone(),
            plan: None,
        });

        // ── Layer 7: Commitment ────────────────────────────────────────
        let confidence_threshold = self.expertise.best_confidence_threshold();
        let commitment = CommitmentEngine::commit(
            &evaluations,
            &possibilities,
            &tensions_snapshot,
            &mut self.context.active_commitments,
            &self.context.evaluation_weights,
            confidence_threshold,
        );

        let commitments_vec: Vec<Commitment> = commitment.into_iter().collect();
        self.checkpoint_mgr.save(&agent_pid, cycle, 7, ThoughtCheckpointState {
            meanings: meanings.clone(),
            tensions: tension_graph.clone(),
            active_knowledge: Some(active_knowledge.clone()),
            possibilities: possibilities.clone(),
            evaluations: evaluations.clone(),
            commitments: self.context.active_commitments.clone(),
            plan: None,
        });

        // ── Layer 8: Planning ──────────────────────────────────────────
        let plan = if !commitments_vec.is_empty() {
            let goal_tension = tensions_snapshot.first()
                .map(|t| t.id.as_str())
                .unwrap_or("unknown");
            PlanEngine::build(
                goal_tension,
                &commitments_vec,
                &possibilities,
                self.context.max_plan_depth,
            ).ok()
        } else {
            None
        };

        // ── Build ThoughtRecord ────────────────────────────────────────
        let thought_record = ThoughtRecord {
            id: format!("thought:{}:{}", agent_pid, cycle),
            agent_pid: agent_pid.clone(),
            cycle_number: cycle,
            timestamp: now,
            seed: ThoughtSeed {
                trigger_type: Self::infer_trigger(&perceptions),
                perception_ids: perceptions.iter().map(|p| p.id.clone()).collect(),
                meaning_ids: meanings.iter().map(|m| m.id.clone()).collect(),
            },
            tensions: tensions_snapshot,
            active_knowledge: active_knowledge.clone(),
            possibility_set: possibilities,
            evaluations,
            commitments: commitments_vec,
            plan: plan.clone(),
            reflection: None,
            prev_thought_cid: None,
            thought_cid: None,
        };

        // ── Layer 9: Exposure ──────────────────────────────────────────
        let explanation = ExposureEngine::render(
            &thought_record,
            config.audience,
            config.explanation_depth,
        );

        // Clean up checkpoints on success
        self.checkpoint_mgr.clear(&agent_pid);

        Ok(CognitiveCycleResult {
            thought_record,
            explanation,
            plan,
            new_knowledge: vec![],
            completed: true,
            layers_executed: 9,
        })
    }

    /// Run reflection on a completed cycle given execution results.
    pub fn reflect(
        &mut self,
        cycle_result: &CognitiveCycleResult,
        execution_result: &serde_json::Value,
    ) -> Option<ReflectionRecord> {
        let commitment = cycle_result.thought_record.commitments.first()?;
        let possibility = cycle_result.thought_record.possibility_set.iter()
            .find(|p| commitment.source_possibilities.contains(&p.id))?;

        Some(ReflectionEngine::reflect(
            commitment,
            possibility,
            execution_result,
            &cycle_result.thought_record.active_knowledge,
        ))
    }

    /// Attempt recovery from the last checkpoint for an agent.
    pub fn recover(&self) -> Option<&ThoughtCheckpoint> {
        self.checkpoint_mgr.recover(&self.context.agent_pid)
    }

    /// Convert perceptions into meaning objects.
    fn form_meanings(perceptions: &[PerceptionObject]) -> Vec<MeaningObject> {
        perceptions.iter().enumerate().map(|(i, p)| {
            let (meaning_type, salience) = Self::classify_perception(p);
            MeaningObject {
                id: format!("meaning:{}:{}", p.id, i),
                source_perception: p.id.clone(),
                meaning_type,
                entities: vec![],
                salience,
                confidence: 0.8,
                evidence_cids: p.evidence_cid.clone().into_iter().collect(),
            }
        }).collect()
    }

    /// Classify a perception into a meaning type.
    fn classify_perception(perception: &PerceptionObject) -> (MeaningType, f64) {
        match &perception.source {
            PerceptionSource::UserInput => {
                let content = perception.raw_content.as_str().unwrap_or("");
                if content.contains('?') {
                    (MeaningType::Request {
                        intent: content.to_string(),
                        urgency: Urgency::Normal,
                    }, 0.9)
                } else {
                    (MeaningType::Request {
                        intent: content.to_string(),
                        urgency: Urgency::Normal,
                    }, 0.8)
                }
            }
            PerceptionSource::ToolOutput => {
                (MeaningType::Information {
                    topic: "tool_result".into(),
                }, 0.7)
            }
            PerceptionSource::PeerAgentMessage { agent_pid } => {
                (MeaningType::Information {
                    topic: format!("message from {}", agent_pid),
                }, 0.6)
            }
            PerceptionSource::SystemEvent => {
                (MeaningType::Information {
                    topic: "system_event".into(),
                }, 0.5)
            }
            _ => {
                (MeaningType::Unknown {
                    description: format!("{:?}", perception.source),
                }, 0.3)
            }
        }
    }

    /// Infer the trigger type from perceptions.
    fn infer_trigger(perceptions: &[PerceptionObject]) -> TriggerType {
        perceptions.first()
            .map(|p| match &p.source {
                PerceptionSource::UserInput => TriggerType::UserRequest,
                PerceptionSource::ToolOutput => TriggerType::ToolResult,
                PerceptionSource::PeerAgentMessage { .. } => TriggerType::PeerMessage,
                PerceptionSource::SystemEvent => TriggerType::ExternalEvent,
                _ => TriggerType::ExternalEvent,
            })
            .unwrap_or(TriggerType::ExternalEvent)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_context() -> CognitiveContext {
        CognitiveContext {
            agent_pid: "pid:test".into(),
            namespace: "ns:test".into(),
            cycle_number: 0,
            token_budget: 4096,
            deadline: None,
            active_commitments: CommitmentRegister::default(),
            evaluation_weights: EvaluationWeights::default(),
            max_possibilities: 12,
            max_plan_depth: 5,
        }
    }

    fn make_user_perception(content: &str) -> PerceptionObject {
        PerceptionObject {
            id: format!("perc:{}", content.len()),
            source: PerceptionSource::UserInput,
            modality: Modality::Text,
            raw_content: serde_json::json!(content),
            timestamp: chrono::Utc::now().timestamp(),
            evidence_cid: None,
        }
    }

    #[test]
    fn test_full_cycle_with_user_input() {
        let context = make_context();
        let mut substrate = CognitiveSubstrate::new(context);
        let config = CycleConfig::default();

        let perceptions = vec![make_user_perception("What is the patient's diagnosis?")];
        let knowledge = ActiveKnowledgeSet::default();

        let result = substrate.run_cycle(perceptions, knowledge, &config);
        assert!(result.is_ok());

        let result = result.unwrap();
        assert!(result.completed);
        assert!(result.layers_executed >= 2);
        assert!(!result.thought_record.tensions.is_empty());
        assert!(!result.explanation.sections.is_empty());
    }

    #[test]
    fn test_no_tension_early_exit() {
        let context = make_context();
        let mut substrate = CognitiveSubstrate::new(context);
        let mut config = CycleConfig::default();
        config.tension_threshold = 100.0; // impossibly high → no tension passes

        let perceptions = vec![make_user_perception("hello")];
        let knowledge = ActiveKnowledgeSet::default();

        let result = substrate.run_cycle(perceptions, knowledge, &config).unwrap();
        assert_eq!(result.layers_executed, 2);
        assert!(result.thought_record.commitments.is_empty());
    }

    #[test]
    fn test_cycle_with_procedural_knowledge() {
        let context = make_context();
        let mut substrate = CognitiveSubstrate::new(context);
        let config = CycleConfig::default();

        let perceptions = vec![make_user_perception("Diagnose the patient")];
        let knowledge = ActiveKnowledgeSet {
            knowledge: vec![ActivatedKnowledge {
                form: KnowledgeForm::Procedural {
                    name: "differential_diagnosis".into(),
                    preconditions: vec!["symptoms observed".into()],
                    steps: vec!["list symptoms".into(), "rank diagnoses".into()],
                    postconditions: vec!["diagnosis ranked".into()],
                    success_rate: 0.85,
                },
                activation: 0.9,
                source_cids: vec![],
            }],
            total_activation: 0.9,
            token_budget_used: 200,
        };

        let result = substrate.run_cycle(perceptions, knowledge, &config).unwrap();
        assert!(result.completed);
        // Should have generated plan-type possibilities from procedural knowledge
        assert!(result.thought_record.possibility_set.iter()
            .any(|p| matches!(p.possibility_type, PossibilityType::Plan { .. })));
    }

    #[test]
    fn test_reflection_on_cycle_result() {
        let context = make_context();
        let mut substrate = CognitiveSubstrate::new(context);
        let config = CycleConfig::default();

        let perceptions = vec![make_user_perception("Run diagnostic test")];
        let knowledge = ActiveKnowledgeSet::default();

        let result = substrate.run_cycle(perceptions, knowledge, &config).unwrap();

        if !result.thought_record.commitments.is_empty() {
            let exec_result = serde_json::json!({
                "success": true,
                "tokens_used": 300,
                "time_ms": 1500
            });
            let reflection = substrate.reflect(&result, &exec_result);
            assert!(reflection.is_some());
        }
    }

    #[test]
    fn test_checkpoint_recovery() {
        let context = make_context();
        let mut substrate = CognitiveSubstrate::new(context);

        // Manually save a checkpoint
        substrate.checkpoint_mgr.save(
            "pid:test", 1, 3,
            ThoughtCheckpointState::default(),
        );

        let recovered = substrate.recover();
        assert!(recovered.is_some());
        assert_eq!(recovered.unwrap().layer, 3);
    }

    #[test]
    fn test_multiple_cycles_increment() {
        let context = make_context();
        let mut substrate = CognitiveSubstrate::new(context);
        let config = CycleConfig::default();
        let knowledge = ActiveKnowledgeSet::default();

        let r1 = substrate.run_cycle(
            vec![make_user_perception("first")], knowledge.clone(), &config
        ).unwrap();
        let r2 = substrate.run_cycle(
            vec![make_user_perception("second")], knowledge, &config
        ).unwrap();

        assert_eq!(r1.thought_record.cycle_number, 1);
        assert_eq!(r2.thought_record.cycle_number, 2);
    }
}

//! Binding Engine — cognitive loop orchestrating Perception + Knowledge + Logic.
//!
//! The Binding Engine is the top-level coordinator for agentic pipelines.
//! It manages the observe → think → act cycle with full CID provenance.
//!
//! ## Cognitive Loop:
//! 1. Perceive — observe input, extract entities, verify claims, score quality
//! 2. Retrieve — get relevant knowledge from graph + kernel memory
//! 3. Reason — plan, execute steps, record reasoning chain
//! 4. Reflect — evaluate reasoning quality, detect contradictions
//! 5. Act — commit decision, compile knowledge for future reuse

use vac_core::kernel::MemoryKernel;
use crate::perception::{PerceptionEngine, ObservationConfig};
use crate::knowledge::{KnowledgeEngine, CompiledKnowledge};
use crate::logic::{LogicEngine, ReasoningChain};
use crate::judgment::JudgmentConfig;
use crate::grounding::GroundingTable;
use crate::claims::Claim;
use serde::{Deserialize, Serialize};

// ═══════════════════════════════════════════════════════════════
// CognitiveState — snapshot of the binding engine's state
// ═══════════════════════════════════════════════════════════════

/// Current state of the cognitive loop.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CognitivePhase {
    Idle,
    Perceiving,
    Retrieving,
    Reasoning,
    Reflecting,
    Acting,
    Complete,
}

impl std::fmt::Display for CognitivePhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", match self {
            Self::Idle => "idle", Self::Perceiving => "perceiving",
            Self::Retrieving => "retrieving", Self::Reasoning => "reasoning",
            Self::Reflecting => "reflecting", Self::Acting => "acting",
            Self::Complete => "complete",
        })
    }
}

/// Summary of one cognitive cycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CycleSummary {
    pub cycle_number: u32,
    pub phase: String,
    pub observation_cid: Option<String>,
    pub facts_retrieved: usize,
    pub reasoning_steps: usize,
    pub quality_score: u32,
    pub contradiction_detected: bool,
    pub decision_cid: Option<String>,
    pub warnings: Vec<String>,
}

/// Full cognitive session report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CognitiveReport {
    pub agent_pid: String,
    pub namespace: String,
    pub total_cycles: u32,
    pub total_observations: u32,
    pub total_reasoning_steps: u32,
    pub total_decisions: u32,
    pub contradictions_detected: u32,
    pub compilations: u32,
    pub final_quality_score: u32,
    pub cycles: Vec<CycleSummary>,
}

// ═══════════════════════════════════════════════════════════════
// BindingEngine
// ═══════════════════════════════════════════════════════════════

/// The cognitive binding engine — orchestrates perception, knowledge, and logic.
pub struct BindingEngine {
    pub knowledge: KnowledgeEngine,
    phase: CognitivePhase,
    cycle_count: u32,
    cycles: Vec<CycleSummary>,
    judgment_config: JudgmentConfig,
    grounding: Option<GroundingTable>,
    /// Token budget for RAG retrieval
    token_budget: usize,
    /// Max facts per retrieval
    max_facts: usize,
}

impl BindingEngine {
    pub fn new() -> Self {
        Self {
            knowledge: KnowledgeEngine::new(),
            phase: CognitivePhase::Idle,
            cycle_count: 0,
            cycles: Vec::new(),
            judgment_config: JudgmentConfig::default(),
            grounding: None,
            token_budget: 4096,
            max_facts: 20,
        }
    }

    // ── Builder methods ──

    pub fn with_judgment(mut self, config: JudgmentConfig) -> Self {
        self.judgment_config = config; self
    }
    pub fn with_grounding(mut self, table: GroundingTable) -> Self {
        self.grounding = Some(table); self
    }
    pub fn with_token_budget(mut self, budget: usize) -> Self {
        self.token_budget = budget; self
    }
    pub fn with_max_facts(mut self, max: usize) -> Self {
        self.max_facts = max; self
    }
    pub fn medical() -> Self {
        Self::new().with_judgment(JudgmentConfig::medical())
    }
    pub fn financial() -> Self {
        Self::new().with_judgment(JudgmentConfig::financial())
    }

    // ── Accessors ──

    pub fn phase(&self) -> &CognitivePhase { &self.phase }
    pub fn cycle_count(&self) -> u32 { self.cycle_count }

    // ── Core cognitive loop ──

    /// Run one full cognitive cycle: perceive → retrieve → reason → reflect → act.
    pub fn cognitive_cycle(
        &mut self,
        kernel: &mut MemoryKernel,
        agent_pid: &str,
        input: &str,
        user: &str,
        pipeline: &str,
        session_id: Option<&str>,
        claims: Option<&[Claim]>,
        goal: &str,
        step_descriptions: &[&str],
    ) -> Result<CycleSummary, String> {
        self.cycle_count += 1;
        let cycle_num = self.cycle_count;
        let mut warnings = Vec::new();

        // ── Phase 1: Perceive ──
        self.phase = CognitivePhase::Perceiving;
        let obs_config = ObservationConfig {
            extract_claims: claims.is_some(),
            judgment_profile: self.judgment_config.clone(),
            ..ObservationConfig::default()
        };
        let observation = PerceptionEngine::observe(
            kernel, agent_pid, input, user, pipeline,
            session_id, claims, self.grounding.as_ref(), &obs_config,
        )?;
        warnings.extend(observation.warnings.clone());

        // ── Phase 2: Retrieve ──
        self.phase = CognitivePhase::Retrieving;
        // Ingest current namespace into knowledge graph
        let namespace = format!("ns:{}", agent_pid.split(':').last().unwrap_or(agent_pid));
        let ingest = self.knowledge.ingest(kernel, &namespace, agent_pid);
        if ingest.contradiction_detected { warnings.extend(ingest.warnings.clone()); }

        let retrieval = self.knowledge.retrieve(
            kernel, &observation.entities, &[], self.token_budget, self.max_facts, self.grounding.as_ref(),
        );

        // ── Phase 3: Reason ──
        self.phase = CognitivePhase::Reasoning;
        let mut plan = if !step_descriptions.is_empty() {
            Some(LogicEngine::plan(kernel, agent_pid, goal, step_descriptions, &[])?)
        } else { None };

        let mut chain = ReasoningChain::new(goal);
        LogicEngine::record_reasoning_step(
            kernel, agent_pid, &mut chain,
            &format!("Observed: {} (quality={})", &input[..input.len().min(100)], observation.quality_score),
            None, None, vec![observation.cid.clone()],
        )?;

        if retrieval.facts_included > 0 {
            LogicEngine::record_reasoning_step(
                kernel, agent_pid, &mut chain,
                &format!("Retrieved {} facts from knowledge graph", retrieval.facts_included),
                Some("knowledge_retrieve"), None, vec![],
            )?;
        }

        // ── Phase 4: Reflect ──
        self.phase = CognitivePhase::Reflecting;
        let reflection = LogicEngine::reflect(kernel, &chain, &self.judgment_config);
        if reflection.should_reconsider {
            warnings.push(format!("Reflection suggests reconsideration (score={})", reflection.quality_score));
        }

        // Check for contradictions
        let contradiction = if ingest.contradiction_detected {
            Some(self.knowledge.check_contradictions(kernel, &namespace, agent_pid))
        } else { None };

        // Reconsider if needed
        if let Some(ref mut p) = plan {
            let recon = LogicEngine::reconsider(p, contradiction.as_ref(), &reflection);
            if recon.revised { warnings.push("Plan revised due to contradiction".into()); }
        }

        // ── Phase 5: Act ──
        self.phase = CognitivePhase::Acting;
        let decision_cid = if chain.conclusion.is_none() {
            let cid = LogicEngine::record_conclusion(
                kernel, agent_pid, &mut chain,
                &format!("Processed input with quality={}", observation.quality_score),
                (observation.quality_score as f64 / 100.0).min(1.0),
            )?;
            Some(cid)
        } else { None };

        self.phase = CognitivePhase::Complete;

        let summary = CycleSummary {
            cycle_number: cycle_num,
            phase: "complete".into(),
            observation_cid: Some(observation.cid),
            facts_retrieved: retrieval.facts_included,
            reasoning_steps: chain.step_count(),
            quality_score: observation.quality_score,
            contradiction_detected: ingest.contradiction_detected,
            decision_cid,
            warnings,
        };
        self.cycles.push(summary.clone());
        Ok(summary)
    }

    /// Quick cycle — minimal parameters, just observe + judge.
    pub fn quick_cycle(
        &mut self,
        kernel: &mut MemoryKernel,
        agent_pid: &str,
        input: &str,
        user: &str,
        pipeline: &str,
    ) -> Result<CycleSummary, String> {
        self.cognitive_cycle(kernel, agent_pid, input, user, pipeline, None, None, "process input", &[])
    }

    /// Generate a full cognitive report.
    pub fn report(&self, agent_pid: &str, namespace: &str) -> CognitiveReport {
        let total_reasoning: u32 = self.cycles.iter().map(|c| c.reasoning_steps as u32).sum();
        let total_decisions = self.cycles.iter().filter(|c| c.decision_cid.is_some()).count() as u32;
        let contradictions = self.cycles.iter().filter(|c| c.contradiction_detected).count() as u32;
        let last_score = self.cycles.last().map(|c| c.quality_score).unwrap_or(0);
        CognitiveReport {
            agent_pid: agent_pid.into(),
            namespace: namespace.into(),
            total_cycles: self.cycle_count,
            total_observations: self.cycle_count,
            total_reasoning_steps: total_reasoning,
            total_decisions,
            contradictions_detected: contradictions,
            compilations: self.knowledge.compilations().len() as u32,
            final_quality_score: last_score,
            cycles: self.cycles.clone(),
        }
    }

    /// Compile knowledge from a reasoning chain result.
    pub fn compile_knowledge(
        &mut self,
        kernel: &mut MemoryKernel,
        agent_pid: &str,
        insight: &str,
        source_cids: Vec<String>,
        entities: Vec<String>,
        confidence: f64,
        reasoning_steps: usize,
    ) -> Result<CompiledKnowledge, String> {
        self.knowledge.compile(kernel, agent_pid, insight, source_cids, entities, confidence, reasoning_steps)
    }
}

impl Default for BindingEngine {
    fn default() -> Self { Self::new() }
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use vac_core::kernel::{SyscallRequest, SyscallPayload, SyscallValue};
    use vac_core::types::MemoryKernelOp;

    fn setup() -> (MemoryKernel, String) {
        let mut k = MemoryKernel::new();
        let r = k.dispatch(SyscallRequest {
            agent_pid: "system".into(), operation: MemoryKernelOp::AgentRegister,
            payload: SyscallPayload::AgentRegister {
                agent_name: "bot".into(), namespace: "ns:bot".into(),
                role: Some("writer".into()), model: None, framework: None,
            }, reason: None, vakya_id: None,
        });
        let pid = match r.value { SyscallValue::AgentPid(p) => p, _ => panic!() };
        k.dispatch(SyscallRequest { agent_pid: pid.clone(), operation: MemoryKernelOp::AgentStart,
            payload: SyscallPayload::Empty, reason: None, vakya_id: None });
        (k, pid)
    }

    #[test]
    fn test_quick_cycle() {
        let (mut k, pid) = setup();
        let mut engine = BindingEngine::new();
        let summary = engine.quick_cycle(&mut k, &pid, "patient has chest pain", "user:doc", "pipe:er").unwrap();
        assert!(summary.observation_cid.is_some());
        assert!(summary.quality_score > 0);
        assert_eq!(summary.cycle_number, 1);
        assert_eq!(engine.cycle_count(), 1);
    }

    #[test]
    fn test_full_cognitive_cycle() {
        let (mut k, pid) = setup();
        let mut engine = BindingEngine::new();
        let summary = engine.cognitive_cycle(
            &mut k, &pid, "patient presents with acute chest pain and ST elevation",
            "user:doc", "pipe:er", None, None,
            "Diagnose patient", &["Assess symptoms", "Order ECG", "Review results"],
        ).unwrap();
        assert!(summary.observation_cid.is_some());
        assert!(summary.reasoning_steps >= 1);
    }

    #[test]
    fn test_multiple_cycles() {
        let (mut k, pid) = setup();
        let mut engine = BindingEngine::new();
        engine.quick_cycle(&mut k, &pid, "observation 1", "user:a", "pipe:a").unwrap();
        engine.quick_cycle(&mut k, &pid, "observation 2", "user:a", "pipe:a").unwrap();
        engine.quick_cycle(&mut k, &pid, "observation 3", "user:a", "pipe:a").unwrap();
        assert_eq!(engine.cycle_count(), 3);
        let report = engine.report(&pid, "ns:bot");
        assert_eq!(report.total_cycles, 3);
        assert_eq!(report.cycles.len(), 3);
    }

    #[test]
    fn test_medical_binding() {
        let (mut k, pid) = setup();
        let mut engine = BindingEngine::medical();
        let summary = engine.quick_cycle(&mut k, &pid, "STEMI patient", "user:doc", "pipe:er").unwrap();
        assert!(summary.quality_score > 0);
    }

    #[test]
    fn test_compile_knowledge() {
        let (mut k, pid) = setup();
        let mut engine = BindingEngine::new();
        engine.quick_cycle(&mut k, &pid, "chest pain + ST elevation", "user:doc", "pipe:er").unwrap();
        let compiled = engine.compile_knowledge(
            &mut k, &pid, "STEMI diagnosis confirmed",
            vec!["cid:1".into()], vec!["diagnosis:stemi".into()], 0.95, 3,
        ).unwrap();
        assert!(!compiled.cid.is_empty());
        assert_eq!(compiled.confidence, 0.95);
    }

    #[test]
    fn test_report() {
        let (mut k, pid) = setup();
        let mut engine = BindingEngine::new();
        engine.quick_cycle(&mut k, &pid, "test input", "user:a", "pipe:a").unwrap();
        let report = engine.report(&pid, "ns:bot");
        assert_eq!(report.agent_pid, pid);
        assert_eq!(report.total_cycles, 1);
        assert!(report.final_quality_score > 0);
    }

    #[test]
    fn test_with_grounding() {
        let (mut k, pid) = setup();
        let json = r#"{"conditions": {"diabetes": {"code": "E11.9", "desc": "Type 2 DM"}}}"#;
        let table = GroundingTable::from_json(json).unwrap();
        let mut engine = BindingEngine::new().with_grounding(table);
        let summary = engine.quick_cycle(&mut k, &pid, "patient has diabetes", "user:doc", "pipe:er").unwrap();
        assert!(summary.observation_cid.is_some());
    }

    #[test]
    fn test_phase_transitions() {
        let engine = BindingEngine::new();
        assert_eq!(*engine.phase(), CognitivePhase::Idle);
    }
}

//! Logic Engine — planning, reasoning, reflection, reconsideration.

use vac_core::kernel::MemoryKernel;
use vac_core::types::*;
use crate::memory::MemoryCoordinator;
use crate::judgment::{JudgmentEngine, JudgmentConfig};
use crate::knowledge::ContradictionReport;
use serde::{Deserialize, Serialize};

// ═══════════════════════════════════════════════════════════════
// Plan types
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StepStatus { Pending, InProgress, Completed, Failed, Skipped, Reconsidered }

impl std::fmt::Display for StepStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", match self {
            Self::Pending => "pending", Self::InProgress => "in_progress",
            Self::Completed => "completed", Self::Failed => "failed",
            Self::Skipped => "skipped", Self::Reconsidered => "reconsidered",
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanStep {
    pub index: usize,
    pub description: String,
    pub dependencies: Vec<usize>,
    pub status: StepStatus,
    pub result_cid: Option<String>,
    pub evidence_cids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Plan {
    pub goal: String,
    pub steps: Vec<PlanStep>,
    pub plan_cid: Option<String>,
    pub current_step: usize,
    pub revised: bool,
    pub revision_count: u32,
}

impl Plan {
    pub fn is_complete(&self) -> bool {
        self.steps.iter().all(|s| s.status == StepStatus::Completed || s.status == StepStatus::Skipped)
    }
    pub fn next_step(&self) -> Option<usize> {
        for (i, step) in self.steps.iter().enumerate() {
            if step.status == StepStatus::Pending {
                let deps_met = step.dependencies.iter().all(|&d|
                    self.steps.get(d).map(|s| s.status == StepStatus::Completed).unwrap_or(true));
                if deps_met { return Some(i); }
            }
        }
        None
    }
    pub fn completed_count(&self) -> usize {
        self.steps.iter().filter(|s| s.status == StepStatus::Completed).count()
    }
    pub fn progress(&self) -> f64 {
        if self.steps.is_empty() { 1.0 } else { self.completed_count() as f64 / self.steps.len() as f64 }
    }
}

// ═══════════════════════════════════════════════════════════════
// Reasoning types
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReasoningStep {
    pub step_number: usize,
    pub thought: String,
    pub action: Option<String>,
    pub result: Option<String>,
    pub cid: Option<String>,
    pub evidence_cids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReasoningChain {
    pub query: String,
    pub steps: Vec<ReasoningStep>,
    pub conclusion: Option<String>,
    pub confidence: f64,
    pub all_evidence_cids: Vec<String>,
}

impl ReasoningChain {
    pub fn new(query: &str) -> Self {
        Self { query: query.into(), steps: Vec::new(), conclusion: None, confidence: 0.0, all_evidence_cids: Vec::new() }
    }
    pub fn add_step(&mut self, thought: &str, action: Option<&str>, result: Option<&str>) {
        let n = self.steps.len();
        self.steps.push(ReasoningStep {
            step_number: n, thought: thought.into(),
            action: action.map(|s| s.into()), result: result.map(|s| s.into()),
            cid: None, evidence_cids: Vec::new(),
        });
    }
    pub fn conclude(&mut self, conclusion: &str, confidence: f64) {
        self.conclusion = Some(conclusion.into()); self.confidence = confidence;
    }
    pub fn step_count(&self) -> usize { self.steps.len() }
}

// ═══════════════════════════════════════════════════════════════
// Reflection + Reconsideration types
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reflection {
    pub quality_score: u32,
    pub grade: String,
    pub evidence_coverage: f64,
    pub coherence: f64,
    pub completeness: f64,
    pub weaknesses: Vec<String>,
    pub suggestions: Vec<String>,
    pub should_reconsider: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconsiderationResult {
    pub revised: bool,
    pub reason: String,
    pub changed_steps: Vec<usize>,
    pub added_steps: Vec<PlanStep>,
    pub contradiction: Option<ContradictionReport>,
}

// ═══════════════════════════════════════════════════════════════
// LogicEngine
// ═══════════════════════════════════════════════════════════════

pub struct LogicEngine;

impl LogicEngine {
    pub fn plan(
        kernel: &mut MemoryKernel, agent_pid: &str, goal: &str,
        step_descs: &[&str], deps: &[(usize, usize)],
    ) -> Result<Plan, String> {
        let plan_text = format!("PLAN: {}\n{}", goal,
            step_descs.iter().enumerate().map(|(i,s)| format!("  {}. {}", i+1, s)).collect::<Vec<_>>().join("\n"));
        let cid = MemoryCoordinator::write(kernel, agent_pid, &plan_text, "system:planner", "pipe:logic",
            PacketType::Decision, None, vec!["plan".into()], vec!["plan".into()])?;
        let mut steps: Vec<PlanStep> = step_descs.iter().enumerate().map(|(i, d)| PlanStep {
            index: i, description: d.to_string(), dependencies: Vec::new(),
            status: StepStatus::Pending, result_cid: None, evidence_cids: Vec::new(),
        }).collect();
        for &(s, d) in deps { if s < steps.len() { steps[s].dependencies.push(d); } }
        Ok(Plan { goal: goal.into(), steps, plan_cid: Some(cid.to_string()), current_step: 0, revised: false, revision_count: 0 })
    }

    pub fn record_reasoning_step(
        kernel: &mut MemoryKernel, agent_pid: &str, chain: &mut ReasoningChain,
        thought: &str, action: Option<&str>, result: Option<&str>, evidence_cids: Vec<String>,
    ) -> Result<(), String> {
        chain.add_step(thought, action, result);
        let text = format!("STEP {}: {}", chain.steps.len(), thought);
        let cid = MemoryCoordinator::write(kernel, agent_pid, &text, "system:reasoner", "pipe:logic",
            PacketType::Extraction, None, evidence_cids.clone(), vec!["reasoning".into()])?;
        if let Some(last) = chain.steps.last_mut() {
            last.cid = Some(cid.to_string()); last.evidence_cids = evidence_cids.clone();
        }
        chain.all_evidence_cids.extend(evidence_cids);
        Ok(())
    }

    pub fn record_conclusion(
        kernel: &mut MemoryKernel, agent_pid: &str, chain: &mut ReasoningChain,
        conclusion: &str, confidence: f64,
    ) -> Result<String, String> {
        chain.conclude(conclusion, confidence);
        let text = format!("CONCLUSION (conf={:.2}): {}", confidence, conclusion);
        let cid = MemoryCoordinator::write(kernel, agent_pid, &text, "system:reasoner", "pipe:logic",
            PacketType::Decision, None, chain.all_evidence_cids.clone(), vec!["conclusion".into()])?;
        Ok(cid.to_string())
    }

    pub fn complete_step(
        kernel: &mut MemoryKernel, agent_pid: &str, plan: &mut Plan,
        idx: usize, result: &str, evidence: Vec<String>,
    ) -> Result<(), String> {
        if idx >= plan.steps.len() { return Err("Step index out of range".into()); }
        let cid = MemoryCoordinator::write(kernel, agent_pid, result, "system:planner", "pipe:logic",
            PacketType::Action, None, evidence.clone(), vec!["step_result".into()])?;
        plan.steps[idx].status = StepStatus::Completed;
        plan.steps[idx].result_cid = Some(cid.to_string());
        plan.steps[idx].evidence_cids = evidence;
        if let Some(next) = plan.next_step() { plan.current_step = next; }
        Ok(())
    }

    pub fn fail_step(plan: &mut Plan, idx: usize, _reason: &str) {
        if idx < plan.steps.len() { plan.steps[idx].status = StepStatus::Failed; }
    }

    pub fn reflect(kernel: &MemoryKernel, chain: &ReasoningChain, config: &JudgmentConfig) -> Reflection {
        let mut weaknesses = Vec::new();
        let mut suggestions = Vec::new();
        let ev_cov = if chain.steps.is_empty() { 0.0 } else {
            chain.steps.iter().filter(|s| !s.evidence_cids.is_empty()).count() as f64 / chain.steps.len() as f64
        };
        if ev_cov < 0.5 { weaknesses.push("Low evidence coverage".into()); suggestions.push("Retrieve more facts".into()); }
        let coherence = if chain.steps.len() > 1 {
            let c = chain.steps.windows(2).filter(|w| {
                let pw: std::collections::HashSet<&str> = w[0].thought.split_whitespace().collect();
                let cw: std::collections::HashSet<&str> = w[1].thought.split_whitespace().collect();
                pw.intersection(&cw).count() > 2
            }).count();
            (c as f64 / (chain.steps.len()-1) as f64).min(1.0)
        } else { 1.0 };
        if coherence < 0.5 { weaknesses.push("Steps disconnected".into()); }
        let completeness = if chain.conclusion.is_some() { 1.0 } else if chain.steps.is_empty() { 0.0 } else { 0.5 };
        if completeness < 1.0 { weaknesses.push("No conclusion".into()); suggestions.push("Add conclusion".into()); }
        let score = (ev_cov*30.0 + coherence*30.0 + completeness*20.0 + chain.confidence*20.0).min(100.0).round() as u32;
        let grade = match score { 90..=100=>"A+", 80..=89=>"A", 70..=79=>"B", 60..=69=>"C", 40..=59=>"D", _=>"F" };
        let j = JudgmentEngine::judge(kernel, None, config);
        Reflection { quality_score: score, grade: grade.into(), evidence_coverage: ev_cov, coherence, completeness,
            weaknesses, suggestions, should_reconsider: score < 50 || !j.warnings.is_empty() }
    }

    pub fn reconsider(plan: &mut Plan, contradiction: Option<&ContradictionReport>, reflection: &Reflection) -> ReconsiderationResult {
        let mut changed = Vec::new();
        let triggered = contradiction.map(|c| c.has_contradictions).unwrap_or(false);
        let reason = if triggered {
            for (i, s) in plan.steps.iter_mut().enumerate() {
                if s.status == StepStatus::Pending || s.status == StepStatus::InProgress {
                    s.status = StepStatus::Reconsidered; changed.push(i);
                }
            }
            plan.revised = true; plan.revision_count += 1;
            "Contradiction detected — revising pending steps".into()
        } else if reflection.should_reconsider {
            format!("Low quality ({}) — suggesting revision", reflection.quality_score)
        } else { "Plan reaffirmed".into() };
        ReconsiderationResult { revised: !changed.is_empty(), reason, changed_steps: changed,
            added_steps: Vec::new(), contradiction: contradiction.cloned() }
    }
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use vac_core::kernel::{SyscallRequest, SyscallPayload, SyscallValue};

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
    fn test_plan_creation() {
        let (mut k, pid) = setup();
        let plan = LogicEngine::plan(&mut k, &pid, "Diagnose", &["Gather", "Test", "Analyze", "Decide"], &[(1,0),(2,1),(3,2)]).unwrap();
        assert_eq!(plan.steps.len(), 4);
        assert!(plan.plan_cid.is_some());
        assert_eq!(plan.next_step(), Some(0));
    }

    #[test]
    fn test_step_completion() {
        let (mut k, pid) = setup();
        let mut plan = LogicEngine::plan(&mut k, &pid, "Test", &["A", "B"], &[(1,0)]).unwrap();
        LogicEngine::complete_step(&mut k, &pid, &mut plan, 0, "A done", vec![]).unwrap();
        assert_eq!(plan.steps[0].status, StepStatus::Completed);
        assert_eq!(plan.next_step(), Some(1));
        LogicEngine::complete_step(&mut k, &pid, &mut plan, 1, "B done", vec![]).unwrap();
        assert!(plan.is_complete());
        assert_eq!(plan.progress(), 1.0);
    }

    #[test]
    fn test_reasoning_chain() {
        let (mut k, pid) = setup();
        let mut chain = ReasoningChain::new("Diagnosis?");
        LogicEngine::record_reasoning_step(&mut k, &pid, &mut chain, "Chest pain + ST elevation", Some("ecg"), Some("STEMI"), vec!["cid:1".into()]).unwrap();
        LogicEngine::record_reasoning_step(&mut k, &pid, &mut chain, "Troponin elevated", Some("lab"), Some("2.5"), vec!["cid:2".into()]).unwrap();
        let cid = LogicEngine::record_conclusion(&mut k, &pid, &mut chain, "Acute STEMI", 0.95).unwrap();
        assert_eq!(chain.step_count(), 2);
        assert_eq!(chain.confidence, 0.95);
        assert!(!cid.is_empty());
    }

    #[test]
    fn test_reflection() {
        let (mut k, pid) = setup();
        let mut chain = ReasoningChain::new("Test");
        LogicEngine::record_reasoning_step(&mut k, &pid, &mut chain, "Step 1 with evidence", None, None, vec!["cid:1".into()]).unwrap();
        LogicEngine::record_conclusion(&mut k, &pid, &mut chain, "Done", 0.8).unwrap();
        let r = LogicEngine::reflect(&k, &chain, &JudgmentConfig::default());
        assert!(r.quality_score > 0);
        assert!(!r.grade.is_empty());
    }

    #[test]
    fn test_reconsider_no_contradiction() {
        let (mut k, pid) = setup();
        let mut plan = LogicEngine::plan(&mut k, &pid, "Test", &["A"], &[]).unwrap();
        let refl = Reflection { quality_score: 80, grade: "A".into(), evidence_coverage: 1.0,
            coherence: 1.0, completeness: 1.0, weaknesses: vec![], suggestions: vec![], should_reconsider: false };
        let r = LogicEngine::reconsider(&mut plan, None, &refl);
        assert!(!r.revised);
    }

    #[test]
    fn test_reconsider_with_contradiction() {
        let (mut k, pid) = setup();
        let mut plan = LogicEngine::plan(&mut k, &pid, "Test", &["A", "B"], &[]).unwrap();
        let contra = ContradictionReport { has_contradictions: true, interference_score: 0.8,
            phase_delta: 0.5, old_entity_count: 3, new_entity_count: 5, warnings: vec![] };
        let refl = Reflection { quality_score: 30, grade: "F".into(), evidence_coverage: 0.0,
            coherence: 0.0, completeness: 0.0, weaknesses: vec![], suggestions: vec![], should_reconsider: true };
        let r = LogicEngine::reconsider(&mut plan, Some(&contra), &refl);
        assert!(r.revised);
        assert!(!r.changed_steps.is_empty());
    }
}

//! Chain of Thought Ledger — Reasoning Step Recording
//!
//! FIX BUG-047: CoT reasoning tracking and replay

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};
use serde::{Serialize, Deserialize};

// =============================================================================
// Reasoning Types
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReasoningChain {
    pub chain_id: String,
    pub agent_pid: String,
    pub goal: String,
    pub steps: Vec<ReasoningStep>,
    pub premises: Vec<Premise>,
    pub conclusion: Option<Conclusion>,
    pub created_at: i64,
    pub completed_at: Option<i64>,
    pub status: ChainStatus,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReasoningStep {
    pub step_number: u32,
    pub step_type: StepType,
    pub description: String,
    pub input: Vec<String>,
    pub output: String,
    pub premise_refs: Vec<u32>,
    pub confidence: f64,
    pub timestamp: i64,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StepType {
    Observation,
    Hypothesis,
    Inference,
    Verification,
    Calculation,
    Lookup,
    Comparison,
    Synthesis,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Premise {
    pub premise_id: u32,
    pub statement: String,
    pub source: String,
    pub evidence_type: EvidenceType,
    pub confidence: f64,
    pub verified: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceType {
    Observation,
    Deduction,
    Induction,
    Abduction,
    Authority,
    Assumption,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Conclusion {
    pub statement: String,
    pub supporting_steps: Vec<u32>,
    pub confidence: f64,
    pub valid: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChainStatus {
    InProgress,
    Completed,
    Abandoned,
    Contradicted,
    Verified,
}

// =============================================================================
// Chain of Thought Ledger
// =============================================================================

pub struct CotLedger {
    /// Active chains
    active_chains: Arc<RwLock<HashMap<String, ReasoningChain>>>,
    /// Completed chains archive
    archived_chains: Arc<RwLock<VecDeque<ReasoningChain>>>,
    /// Premise registry
    premises: Arc<RwLock<HashMap<u32, Premise>>>,
    /// Premise counter
    premise_counter: Arc<RwLock<u32>>,
    /// Max archived chains
    max_archive: usize,
}

impl CotLedger {
    pub fn new(max_archive: usize) -> Self {
        Self {
            active_chains: Arc::new(RwLock::new(HashMap::new())),
            archived_chains: Arc::new(RwLock::new(VecDeque::new())),
            premises: Arc::new(RwLock::new(HashMap::new())),
            premise_counter: Arc::new(RwLock::new(0)),
            max_archive,
        }
    }

    /// Start new reasoning chain
    pub fn start_chain(&self, agent_pid: String, goal: String) -> String {
        let chain_id = format!("cot-{}", uuid::Uuid::new_v4());
        
        let goal_str = goal.clone();
        let chain = ReasoningChain {
            chain_id: chain_id.clone(),
            agent_pid,
            goal,
            steps: vec![],
            premises: vec![],
            conclusion: None,
            created_at: chrono::Utc::now().timestamp_millis(),
            completed_at: None,
            status: ChainStatus::InProgress,
            confidence: 1.0,
        };

        self.active_chains.write().unwrap().insert(chain_id.clone(), chain);

        println!("[CoT] Started chain {}: {}", chain_id, goal_str);
        chain_id
    }

    /// Record premise
    pub fn record_premise(&self, statement: String, source: String, evidence: EvidenceType, confidence: f64) -> u32 {
        let mut counter = self.premise_counter.write().unwrap();
        *counter += 1;
        let id = *counter;

        let premise = Premise {
            premise_id: id,
            statement,
            source,
            evidence_type: evidence,
            confidence,
            verified: false,
        };

        self.premises.write().unwrap().insert(id, premise);
        id
    }

    /// Add reasoning step
    pub fn add_step(
        &self,
        chain_id: &str,
        step_type: StepType,
        description: String,
        input: Vec<String>,
        output: String,
        premise_refs: Vec<u32>,
    ) -> Result<u32, String> {
        let mut chains = self.active_chains.write().unwrap();
        
        if let Some(chain) = chains.get_mut(chain_id) {
            let step_num = chain.steps.len() as u32 + 1;
            
            // Calculate step confidence from premises
            let step_confidence: f64 = {
                let premises_guard = self.premises.read().unwrap();
                let conf: f64 = premise_refs.iter()
                    .filter_map(|id| premises_guard.get(id))
                    .map(|p| p.confidence)
                    .product::<f64>();
                conf.powf(1.0 / premise_refs.len().max(1) as f64)
            };

            let step = ReasoningStep {
                step_number: step_num,
                step_type,
                description,
                input,
                output: output.clone(),
                premise_refs,
                confidence: step_confidence,
                timestamp: chrono::Utc::now().timestamp_millis(),
                metadata: HashMap::new(),
            };

            chain.steps.push(step);
            chain.confidence *= step_confidence;

            println!("[CoT] Chain {} step {}: {}", chain_id, step_num, output);
            Ok(step_num)
        } else {
            Err(format!("Chain {} not found", chain_id))
        }
    }

    /// Complete chain with conclusion
    pub fn complete_chain(&self, chain_id: &str, conclusion: String, valid: bool) -> Result<(), String> {
        let mut chains = self.active_chains.write().unwrap();
        
        if let Some(chain) = chains.get_mut(chain_id) {
            let supporting: Vec<u32> = chain.steps.iter().map(|s| s.step_number).collect();
            
            chain.conclusion = Some(Conclusion {
                statement: conclusion,
                supporting_steps: supporting,
                confidence: chain.confidence,
                valid,
            });
            
            chain.status = if valid { ChainStatus::Completed } else { ChainStatus::Abandoned };
            chain.completed_at = Some(chrono::Utc::now().timestamp_millis());

            // Archive
            let chain = chains.remove(chain_id).unwrap();
            self.archive_chain(chain);

            println!("[CoT] Completed chain {} (valid: {})", chain_id, valid);
            Ok(())
        } else {
            Err(format!("Chain {} not found", chain_id))
        }
    }

    /// Archive completed chain
    fn archive_chain(&self, chain: ReasoningChain) {
        let mut archive = self.archived_chains.write().unwrap();
        
        if archive.len() >= self.max_archive {
            archive.pop_front();
        }
        
        archive.push_back(chain);
    }

    /// Mark premise as verified
    pub fn verify_premise(&self, premise_id: u32) -> Result<(), String> {
        let mut premises = self.premises.write().unwrap();
        
        if let Some(premise) = premises.get_mut(&premise_id) {
            premise.verified = true;
            Ok(())
        } else {
            Err(format!("Premise {} not found", premise_id))
        }
    }

    /// Replay chain from beginning
    pub fn replay_chain(&self, chain_id: &str) -> Option<Vec<String>> {
        // Check active
        if let Some(chain) = self.active_chains.read().unwrap().get(chain_id) {
            return Some(self.format_replay(chain));
        }

        // Check archived
        self.archived_chains.read().unwrap()
            .iter()
            .find(|c| c.chain_id == chain_id)
            .map(|chain| self.format_replay(chain))
    }

    fn format_replay(&self, chain: &ReasoningChain) -> Vec<String> {
        let mut output = vec![
            format!("Chain: {} (Agent: {})", chain.chain_id, chain.agent_pid),
            format!("Goal: {}", chain.goal),
            format!("Confidence: {:.2}%", chain.confidence * 100.0),
            "".to_string(),
            "Premises:".to_string(),
        ];

        for premise in &chain.premises {
            output.push(format!(
                "  [{}] {} ({}): {} - {:.2}%",
                premise.premise_id,
                premise.statement,
                format!("{:?}", premise.evidence_type),
                if premise.verified { "✓" } else { "?" },
                premise.confidence * 100.0
            ));
        }

        output.push("".to_string());
        output.push("Steps:".to_string());

        for step in &chain.steps {
            output.push(format!(
                "  {}. [{}] {}",
                step.step_number,
                format!("{:?}", step.step_type),
                step.description
            ));
            output.push(format!("     Input: {:?}", step.input));
            output.push(format!("     Output: {}", step.output));
            output.push(format!("     Confidence: {:.2}%", step.confidence * 100.0));
            if !step.premise_refs.is_empty() {
                output.push(format!("     Based on premises: {:?}", step.premise_refs));
            }
            output.push("".to_string());
        }

        if let Some(ref conclusion) = chain.conclusion {
            output.push("Conclusion:".to_string());
            output.push(format!("  {} (valid: {})", conclusion.statement, conclusion.valid));
            output.push(format!("  Overall confidence: {:.2}%", conclusion.confidence * 100.0));
        }

        output
    }

    /// Trace premise usage
    pub fn trace_premise(&self, premise_id: u32) -> Vec<(String, u32)> {
        let mut results = Vec::new();

        // Check active chains
        for (chain_id, chain) in self.active_chains.read().unwrap().iter() {
            for step in &chain.steps {
                if step.premise_refs.contains(&premise_id) {
                    results.push((chain_id.clone(), step.step_number));
                }
            }
        }

        // Check archived chains
        for chain in self.archived_chains.read().unwrap().iter() {
            for step in &chain.steps {
                if step.premise_refs.contains(&premise_id) {
                    results.push((chain.chain_id.clone(), step.step_number));
                }
            }
        }

        results
    }

    /// Find chains by goal pattern
    pub fn find_chains(&self, pattern: &str) -> Vec<ReasoningChain> {
        let mut results = Vec::new();

        // Search active
        for chain in self.active_chains.read().unwrap().values() {
            if chain.goal.contains(pattern) {
                results.push(chain.clone());
            }
        }

        // Search archived
        for chain in self.archived_chains.read().unwrap().iter() {
            if chain.goal.contains(pattern) {
                results.push(chain.clone());
            }
        }

        results
    }

    /// Get chain statistics
    pub fn stats(&self) -> CotStats {
        let active = self.active_chains.read().unwrap();
        let archived = self.archived_chains.read().unwrap();

        let total_steps: usize = active.values()
            .chain(archived.iter())
            .map(|c| c.steps.len())
            .sum();

        let avg_steps = if active.len() + archived.len() > 0 {
            total_steps as f64 / (active.len() + archived.len()) as f64
        } else {
            0.0
        };

        CotStats {
            active_chains: active.len(),
            archived_chains: archived.len(),
            total_premises: self.premises.read().unwrap().len(),
            verified_premises: self.premises.read().unwrap().values().filter(|p| p.verified).count(),
            avg_steps_per_chain: avg_steps,
            valid_conclusions: archived.iter().filter(|c| c.conclusion.as_ref().map(|con| con.valid).unwrap_or(false)).count(),
        }
    }

    /// Export chain to JSON
    pub fn export_chain(&self, chain_id: &str) -> Option<String> {
        let chain = self.active_chains.read().unwrap()
            .get(chain_id)
            .cloned()
            .or_else(|| {
                self.archived_chains.read().unwrap()
                    .iter()
                    .find(|c| c.chain_id == chain_id)
                    .cloned()
            });

        chain.and_then(|c| serde_json::to_string_pretty(&c).ok())
    }

    /// Import chain from JSON
    pub fn import_chain(&self, json: &str) -> Result<String, String> {
        let chain: ReasoningChain = serde_json::from_str(json).map_err(|e| e.to_string())?;
        let id = chain.chain_id.clone();
        
        self.archived_chains.write().unwrap().push_back(chain);
        
        Ok(id)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CotStats {
    pub active_chains: usize,
    pub archived_chains: usize,
    pub total_premises: usize,
    pub verified_premises: usize,
    pub avg_steps_per_chain: f64,
    pub valid_conclusions: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reasoning_chain() {
        let ledger = CotLedger::new(1000);

        // Start chain
        let chain_id = ledger.start_chain(
            "agent-1".to_string(),
            "Determine if it will rain today".to_string(),
        );

        // Record premises
        let p1 = ledger.record_premise(
            "Clouds are dark".to_string(),
            "observation".to_string(),
            EvidenceType::Observation,
            0.9,
        );

        let p2 = ledger.record_premise(
            "Barometer is falling".to_string(),
            "observation".to_string(),
            EvidenceType::Observation,
            0.8,
        );

        // Add steps
        ledger.add_step(
            &chain_id,
            StepType::Observation,
            "Observed weather conditions".to_string(),
            vec!["sky".to_string(), "barometer".to_string()],
            "Dark clouds, falling pressure".to_string(),
            vec![p1, p2],
        ).unwrap();

        ledger.add_step(
            &chain_id,
            StepType::Inference,
            "Applied weather rules".to_string(),
            vec!["clouds".to_string(), "pressure".to_string()],
            "High probability of rain".to_string(),
            vec![p1, p2],
        ).unwrap();

        // Complete
        ledger.complete_chain(&chain_id, "It will rain today".to_string(), true).unwrap();

        // Replay
        let replay = ledger.replay_chain(&chain_id).unwrap();
        assert!(!replay.is_empty());
        assert!(replay.iter().any(|l| l.contains("will rain")));

        let stats = ledger.stats();
        assert_eq!(stats.archived_chains, 1);
        assert_eq!(stats.valid_conclusions, 1);
    }

    #[test]
    fn test_premise_tracking() {
        let ledger = CotLedger::new(1000);

        let p1 = ledger.record_premise(
            "Temperature > 30C".to_string(),
            "sensor".to_string(),
            EvidenceType::Observation,
            0.95,
        );

        let chain_id = ledger.start_chain("agent-1".to_string(), "Check heat".to_string());

        ledger.add_step(
            &chain_id,
            StepType::Observation,
            "Read temperature".to_string(),
            vec!["sensor".to_string()],
            "35C".to_string(),
            vec![p1],
        ).unwrap();

        // Trace premise
        let usages = ledger.trace_premise(p1);
        assert_eq!(usages.len(), 1);
        assert_eq!(usages[0].0, chain_id);
    }

    #[test]
    fn test_chain_export_import() {
        let ledger = CotLedger::new(1000);

        let chain_id = ledger.start_chain("agent-1".to_string(), "Test".to_string());
        ledger.complete_chain(&chain_id, "Done".to_string(), true).unwrap();

        let exported = ledger.export_chain(&chain_id).unwrap();
        
        let ledger2 = CotLedger::new(1000);
        let imported_id = ledger2.import_chain(&exported).unwrap();
        
        assert!(!imported_id.is_empty());
    }
}

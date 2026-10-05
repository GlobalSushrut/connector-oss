//! Policy Chain Generator — Tool Call Policy Decisions with Verifiable Execution Log
//!
//! FIX BUG-059: Policy decision chain for each tool call

use std::collections::{HashMap, VecDeque};
use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};

// =============================================================================
// Policy Chain Types
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyChain {
    pub chain_id: String,
    pub tool_call_id: String,
    pub agent_pid: String,
    pub decisions: Vec<PolicyDecision>,
    pub final_result: PolicyResult,
    pub merkle_root: String,
    pub created_at: i64,
    pub proof: ExecutionProof,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub step_number: u32,
    pub policy_name: String,
    pub policy_type: PolicyType,
    pub input_context: HashMap<String, String>,
    pub decision: Decision,
    pub confidence: f64,
    pub timestamp: i64,
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyType {
    ACL,
    Firewall,
    Behavior,
    Safety,
    RateLimit,
    Quota,
    Custom(u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Decision {
    Allow,
    Deny,
    RequireApproval,
    RateLimit(u32), // max per minute
    Modify, // allowed with modifications
    AuditOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyResult {
    Allowed,
    Denied { reason: String },
    Modified { changes: Vec<String> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionProof {
    pub previous_hash: String,
    pub this_hash: String,
    pub signature: String,
}

// =============================================================================
// Policy Chain Generator
// =============================================================================

pub struct PolicyChainGenerator {
    previous_hash: String,
    chains: VecDeque<PolicyChain>,
    max_chains: usize,
}

impl PolicyChainGenerator {
    pub fn new() -> Self {
        Self {
            previous_hash: "0".repeat(64),
            chains: VecDeque::new(),
            max_chains: 10000,
        }
    }

    /// Generate policy chain for tool call
    pub fn generate_chain(
        &mut self,
        tool_call_id: String,
        agent_pid: String,
        tool_name: &str,
        args: &HashMap<String, String>,
        context: &PolicyContext,
    ) -> PolicyChain {
        let chain_id = format!("pc-{}", uuid::Uuid::new_v4());
        let now = chrono::Utc::now().timestamp_millis();
        
        let mut decisions = Vec::new();
        
        // Step 1: ACL Check
        let acl_decision = self.evaluate_acl(tool_name, agent_pid.clone(), context);
        decisions.push(PolicyDecision {
            step_number: 1,
            policy_name: "acl".to_string(),
            policy_type: PolicyType::ACL,
            input_context: {
                let mut m = HashMap::new();
                m.insert("tool".to_string(), tool_name.to_string());
                m.insert("agent".to_string(), agent_pid.clone());
                m
            },
            decision: acl_decision,
            confidence: 0.99,
            timestamp: now,
            evidence_refs: vec![],
        });

        // Step 2: Firewall Check (if ACL allowed)
        if matches!(acl_decision, Decision::Allow | Decision::Modify) {
            let fw_decision = self.evaluate_firewall(tool_name, args, context);
            decisions.push(PolicyDecision {
                step_number: 2,
                policy_name: "firewall".to_string(),
                policy_type: PolicyType::Firewall,
                input_context: args.clone(),
                decision: fw_decision,
                confidence: 0.95,
                timestamp: now,
                evidence_refs: vec![],
            });
        }

        // Step 3: Behavior Check
        let behavior_decision = self.evaluate_behavior(agent_pid.clone(), tool_name, context);
        decisions.push(PolicyDecision {
            step_number: 3,
            policy_name: "behavior".to_string(),
            policy_type: PolicyType::Behavior,
            input_context: {
                let mut m = HashMap::new();
                m.insert("recent_calls".to_string(), context.recent_call_count.to_string());
                m
            },
            decision: behavior_decision,
            confidence: 0.90,
            timestamp: now,
            evidence_refs: vec![],
        });

        // Step 4: Safety Check
        let safety_decision = self.evaluate_safety(tool_name, args);
        decisions.push(PolicyDecision {
            step_number: 4,
            policy_name: "safety".to_string(),
            policy_type: PolicyType::Safety,
            input_context: args.clone(),
            decision: safety_decision,
            confidence: 0.98,
            timestamp: now,
            evidence_refs: vec![],
        });

        // Determine final result
        let final_result = self.compute_final_result(&decisions);

        // Build chain and compute hash
        let chain = PolicyChain {
            chain_id: chain_id.clone(),
            tool_call_id: tool_call_id.clone(),
            agent_pid: agent_pid.clone(),
            decisions: decisions.clone(),
            final_result: final_result.clone(),
            merkle_root: self.compute_merkle_root(&decisions),
            created_at: now,
            proof: ExecutionProof {
                previous_hash: self.previous_hash.clone(),
                this_hash: String::new(), // filled below
                signature: String::new(),
            },
        };

        // Compute this chain's hash
        let this_hash = self.hash_chain(&chain);
        let mut chain_with_proof = chain.clone();
        chain_with_proof.proof.this_hash = this_hash.clone();
        chain_with_proof.proof.signature = self.sign(&this_hash);

        // Update for next chain
        self.previous_hash = this_hash;

        // Store chain
        if self.chains.len() >= self.max_chains {
            self.chains.pop_front();
        }
        self.chains.push_back(chain_with_proof.clone());

        println!("[POLICY-CHAIN] Generated chain {} for {}: {:?}",
            chain_id, tool_call_id, final_result);

        chain_with_proof
    }

    fn evaluate_acl(&self, tool_name: &str, agent_pid: String, context: &PolicyContext) -> Decision {
        // Check if tool in agent's allowed list
        if context.allowed_tools.contains(&tool_name.to_string()) {
            Decision::Allow
        } else if context.requires_approval.contains(&tool_name.to_string()) {
            Decision::RequireApproval
        } else {
            Decision::Deny
        }
    }

    fn evaluate_firewall(&self, _tool_name: &str, args: &HashMap<String, String>, context: &PolicyContext) -> Decision {
        // Check argument patterns against firewall rules
        for (key, value) in args {
            for (pattern, score) in &context.firewall_patterns {
                if value.contains(pattern) && *score > 0.8 {
                    return Decision::Deny;
                }
            }
        }
        Decision::Allow
    }

    fn evaluate_behavior(&self, _agent_pid: String, _tool_name: &str, context: &PolicyContext) -> Decision {
        // Rate limiting
        if context.recent_call_count > 100 {
            return Decision::RateLimit(10);
        }
        Decision::Allow
    }

    fn evaluate_safety(&self, tool_name: &str, args: &HashMap<String, String>) -> Decision {
        // Safety checks for dangerous tools
        let dangerous_tools = vec!["exec", "eval", "write", "delete"];
        
        if dangerous_tools.contains(&tool_name) {
            // Require explicit confirmation in args
            if !args.contains_key("confirmed") {
                return Decision::RequireApproval;
            }
        }
        Decision::Allow
    }

    fn compute_final_result(&self, decisions: &[PolicyDecision]) -> PolicyResult {
        let mut denied = false;
        let mut reasons = Vec::new();
        let mut modifications = Vec::new();

        for d in decisions {
            match d.decision {
                Decision::Deny => {
                    denied = true;
                    reasons.push(format!("{}: denied", d.policy_name));
                }
                Decision::RequireApproval => {
                    denied = true;
                    reasons.push(format!("{}: requires approval", d.policy_name));
                }
                Decision::RateLimit(limit) => {
                    modifications.push(format!("rate limited to {}/min", limit));
                }
                Decision::Modify => {
                    modifications.push(format!("{}: modified", d.policy_name));
                }
                _ => {}
            }
        }

        if denied {
            PolicyResult::Denied { reason: reasons.join(", ") }
        } else if !modifications.is_empty() {
            PolicyResult::Modified { changes: modifications }
        } else {
            PolicyResult::Allowed
        }
    }

    fn compute_merkle_root(&self, decisions: &[PolicyDecision]) -> String {
        let hashes: Vec<String> = decisions.iter()
            .map(|d| self.hash_decision(d))
            .collect();

        if hashes.is_empty() {
            return String::new();
        }

        let mut level = hashes;
        while level.len() > 1 {
            let mut next = Vec::new();
            for pair in level.chunks(2) {
                let combined = if pair.len() == 2 {
                    format!("{}{}", pair[0], pair[1])
                } else {
                    format!("{}{}", pair[0], pair[0])
                };
                next.push(self.sha256(&combined));
            }
            level = next;
        }

        level[0].clone()
    }

    fn hash_chain(&self, chain: &PolicyChain) -> String {
        let data = format!(
            "{}:{}:{:?}:{}",
            chain.chain_id,
            chain.tool_call_id,
            chain.final_result,
            chain.merkle_root
        );
        self.sha256(&data)
    }

    fn hash_decision(&self, d: &PolicyDecision) -> String {
        let data = format!(
            "{}:{}:{:?}:{}",
            d.step_number,
            d.policy_name,
            d.decision,
            d.timestamp
        );
        self.sha256(&data)
    }

    fn sha256(&self, input: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(input.as_bytes());
        hex::encode(hasher.finalize())
    }

    fn sign(&self, hash: &str) -> String {
        // In production: cryptographic signature
        format!("sig-{}", &hash[..16])
    }

    /// Verify chain integrity
    pub fn verify_chain(&self, chain: &PolicyChain) -> bool {
        // Verify merkle root
        let computed_root = self.compute_merkle_root(&chain.decisions);
        if computed_root != chain.merkle_root {
            return false;
        }

        // Verify chain hash
        let computed_hash = self.hash_chain(chain);
        if computed_hash != chain.proof.this_hash {
            return false;
        }

        true
    }

    /// Get chain for tool call
    pub fn get_chain(&self, tool_call_id: &str) -> Option<&PolicyChain> {
        self.chains.iter().find(|c| c.tool_call_id == tool_call_id)
    }

    /// List recent chains
    pub fn list_recent(&self, n: usize) -> Vec<&PolicyChain> {
        self.chains.iter().rev().take(n).collect()
    }

    /// Export execution log (for audit)
    pub fn export_log(&self, from_time: i64) -> Vec<&PolicyChain> {
        self.chains.iter()
            .filter(|c| c.created_at >= from_time)
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct PolicyContext {
    pub allowed_tools: Vec<String>,
    pub requires_approval: Vec<String>,
    pub firewall_patterns: Vec<(String, f64)>,
    pub recent_call_count: u32,
}

// =============================================================================
// Integration with Dispatcher
// =============================================================================

pub struct PolicyEnforcer {
    chain_generator: PolicyChainGenerator,
}

impl PolicyEnforcer {
    pub fn new() -> Self {
        Self {
            chain_generator: PolicyChainGenerator::new(),
        }
    }

    /// Gate and execute tool with policy chain
    pub fn gate_and_execute(
        &mut self,
        agent_pid: String,
        tool_name: &str,
        args: HashMap<String, String>,
        context: &PolicyContext,
    ) -> PolicyResult {
        let tool_call_id = format!("call-{}", uuid::Uuid::new_v4());
        
        // Generate policy chain
        let chain = self.chain_generator.generate_chain(
            tool_call_id.clone(),
            agent_pid,
            tool_name,
            &args,
            context,
        );

        // Return the result
        chain.final_result.clone()
    }

    pub fn get_chain_generator(&self) -> &PolicyChainGenerator {
        &self.chain_generator
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_chain_generation() {
        let mut generator = PolicyChainGenerator::new();
        
        let context = PolicyContext {
            allowed_tools: vec!["read".to_string()],
            requires_approval: vec!["write".to_string()],
            firewall_patterns: vec![],
            recent_call_count: 5,
        };

        let mut args = HashMap::new();
        args.insert("path".to_string(), "/data".to_string());

        let chain = generator.generate_chain(
            "call-1".to_string(),
            "agent-1".to_string(),
            "read",
            &args,
            &context,
        );

        assert!(!chain.chain_id.is_empty());
        assert_eq!(chain.decisions.len(), 4);
        assert!(matches!(chain.final_result, PolicyResult::Allowed));
    }

    #[test]
    fn test_policy_denial() {
        let mut generator = PolicyChainGenerator::new();
        
        let context = PolicyContext {
            allowed_tools: vec!["read".to_string()],
            requires_approval: vec![],
            firewall_patterns: vec![],
            recent_call_count: 5,
        };

        let args = HashMap::new();

        let chain = generator.generate_chain(
            "call-1".to_string(),
            "agent-1".to_string(),
            "unauthorized_tool", // Not in allowed list
            &args,
            &context,
        );

        assert!(matches!(chain.final_result, PolicyResult::Denied { .. }));
    }

    #[test]
    fn test_chain_verification() {
        let mut generator = PolicyChainGenerator::new();
        
        let context = PolicyContext {
            allowed_tools: vec!["read".to_string()],
            requires_approval: vec![],
            firewall_patterns: vec![],
            recent_call_count: 5,
        };

        let chain = generator.generate_chain(
            "call-1".to_string(),
            "agent-1".to_string(),
            "read",
            &HashMap::new(),
            &context,
        );

        assert!(generator.verify_chain(&chain));
    }

    #[test]
    fn test_enforcer() {
        let mut enforcer = PolicyEnforcer::new();
        
        let context = PolicyContext {
            allowed_tools: vec!["compute".to_string()],
            requires_approval: vec![],
            firewall_patterns: vec![],
            recent_call_count: 1,
        };

        let result = enforcer.gate_and_execute(
            "agent-1".to_string(),
            "compute",
            HashMap::new(),
            &context,
        );

        assert!(matches!(result, PolicyResult::Allowed));
    }
}

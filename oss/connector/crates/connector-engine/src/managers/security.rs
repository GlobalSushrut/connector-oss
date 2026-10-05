//! SecurityManager — Runtime security enforcement subsystem.
//!
//! Groups security-related engines:
//! - `GuardPipeline` — 5-layer security gate (MAC → Policy → Content → Rate → Audit)
//! - `PolicyEngine` — Pattern-matching deny/allow policy evaluation
//! - `AgentFirewall` — Non-bypassable runtime boundary
//! - `SemanticInjectionDetector` — Advanced injection detection

use crate::guard_pipeline::{GuardPipeline, GuardRequest, GuardVerdictChain};
use crate::policy_engine::PolicyEngine;
use crate::firewall::{AgentFirewall, FirewallConfig, ThreatScore};
use crate::semantic_injection::SemanticInjectionDetector;

/// SecurityManager — unified security enforcement layer.
///
/// Consolidates all security-related engines into a single manager,
/// providing a cohesive API for security checks and policy enforcement.
pub struct SecurityManager {
    /// GuardPipeline — 5-layer security gate
    pub guard_pipeline: GuardPipeline,
    /// PolicyEngine — pattern-matching policy evaluation
    pub policy_engine: PolicyEngine,
    /// AgentFirewall — non-bypassable runtime boundary
    pub firewall: AgentFirewall,
    /// SemanticInjectionDetector — advanced injection detection
    pub injection_detector: SemanticInjectionDetector,
}

impl SecurityManager {
    /// Create a new SecurityManager with default configurations.
    pub fn new() -> Self {
        Self {
            guard_pipeline: GuardPipeline::new(),
            policy_engine: PolicyEngine::new(),
            firewall: AgentFirewall::default_firewall(),
            injection_detector: SemanticInjectionDetector::new(),
        }
    }

    /// Create with custom firewall configuration.
    pub fn with_firewall_config(mut self, config: FirewallConfig) -> Self {
        self.firewall = AgentFirewall::new(config);
        self
    }

    /// Check if a memory write is allowed.
    ///
    /// Runs through firewall scoring and injection detection.
    pub fn check_memory_write(
        &mut self,
        text: &str,
        agent_pid: &str,
        namespace: &str,
        anomaly_score: f64,
    ) -> ThreatScore {
        // Check for semantic injection first (score > 0.7 is considered blocked)
        let injection_result = self.injection_detector.analyze(text, agent_pid);
        if injection_result.score > 0.7 {
            // Use score_with_anomaly to inject the injection score as anomaly
            return self.firewall.score_with_anomaly(text, agent_pid, injection_result.score);
        }

        // Score through firewall - use anomaly if provided, otherwise standard memory write
        if anomaly_score > 0.0 {
            self.firewall.score_with_anomaly(text, agent_pid, anomaly_score)
        } else {
            self.firewall.score_memory_write(text, agent_pid, namespace)
        }
    }

    /// Run the full guard pipeline for a request.
    pub fn guard(&mut self, request: &GuardRequest) -> GuardVerdictChain {
        self.guard_pipeline.evaluate(request)
    }

    /// Check policy for an operation.
    pub fn check_policy(&self, ctx: &crate::policy_engine::PolicyContext) -> crate::policy_engine::PolicyDecisionResult {
        self.policy_engine.evaluate(ctx)
    }

    /// Get firewall reference for direct access.
    pub fn firewall(&self) -> &AgentFirewall {
        &self.firewall
    }

    /// Get mutable firewall reference.
    pub fn firewall_mut(&mut self) -> &mut AgentFirewall {
        &mut self.firewall
    }

    /// Get guard pipeline reference.
    pub fn guard_pipeline(&self) -> &GuardPipeline {
        &self.guard_pipeline
    }

    /// Get mutable guard pipeline reference.
    pub fn guard_pipeline_mut(&mut self) -> &mut GuardPipeline {
        &mut self.guard_pipeline
    }

    /// Get policy engine reference.
    pub fn policy_engine(&self) -> &PolicyEngine {
        &self.policy_engine
    }

    /// Get mutable policy engine reference.
    pub fn policy_engine_mut(&mut self) -> &mut PolicyEngine {
        &mut self.policy_engine
    }

    /// Get injection detector reference.
    pub fn injection_detector(&self) -> &SemanticInjectionDetector {
        &self.injection_detector
    }
}

impl Default for SecurityManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_manager_creation() {
        let manager = SecurityManager::new();
        // Just verify the manager can be created
        assert_eq!(manager.firewall().event_count(), 0);
    }
}

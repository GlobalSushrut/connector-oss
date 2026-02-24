//! Federated Policy Engine — 3-level policy evaluation.
//!
//! Merges policies from three levels:
//! 1. **Federation** — Cross-org rules (SCITT-attested). Federation deny is absolute.
//! 2. **Cluster** — Shared across cells (replicated via event bus).
//! 3. **Local** — Cell-level policies.
//!
//! Priority: federation deny > cluster deny > local deny > local allow.

use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::debug;

use aapi_metarules::context::EvaluationContext;
use aapi_metarules::decision::PolicyDecision;
use aapi_metarules::engine::PolicyEngine;
use aapi_metarules::error::MetaRulesResult;
use aapi_metarules::rules::Policy;

// ============================================================================
// FederatedPolicyEngine
// ============================================================================

/// Three-level federated policy engine.
///
/// Evaluation order:
/// 1. Federation policies (cross-org, absolute deny)
/// 2. Cluster policies (shared across cells)
/// 3. Local policies (cell-specific)
///
/// A deny at any level short-circuits — no lower level can override it.
pub struct FederatedPolicyEngine {
    /// Cell-level policies.
    pub local: PolicyEngine,
    /// Cluster-wide policies (replicated via event bus).
    pub cluster: Arc<RwLock<PolicyEngine>>,
    /// Federation-level policies (cross-org, SCITT-attested).
    pub federation: Arc<RwLock<PolicyEngine>>,
}

impl FederatedPolicyEngine {
    pub fn new() -> Self {
        // Federation and cluster default to allow (pass-through when empty).
        // Only local defaults to deny.
        Self {
            local: PolicyEngine::new(),
            cluster: Arc::new(RwLock::new(PolicyEngine::new().with_default_allow())),
            federation: Arc::new(RwLock::new(PolicyEngine::new().with_default_allow())),
        }
    }

    /// Create with a pre-configured local engine.
    pub fn with_local(local: PolicyEngine) -> Self {
        Self {
            local,
            cluster: Arc::new(RwLock::new(PolicyEngine::new().with_default_allow())),
            federation: Arc::new(RwLock::new(PolicyEngine::new().with_default_allow())),
        }
    }

    /// Evaluate against all 3 policy levels.
    ///
    /// Priority: federation deny > cluster deny > local deny > local allow.
    pub async fn evaluate(&self, context: &EvaluationContext) -> MetaRulesResult<PolicyDecision> {
        // 1. Federation policies first (cross-org rules, absolute)
        let fed_engine = self.federation.read().await;
        let fed_decision = fed_engine.evaluate(context).await?;
        if !fed_decision.allowed {
            debug!(
                reason = %fed_decision.reason,
                "Federation policy denied"
            );
            return Ok(fed_decision);
        }
        drop(fed_engine);

        // 2. Cluster policies (shared across cells)
        let cluster_engine = self.cluster.read().await;
        let cluster_decision = cluster_engine.evaluate(context).await?;
        if !cluster_decision.allowed {
            debug!(
                reason = %cluster_decision.reason,
                "Cluster policy denied"
            );
            return Ok(cluster_decision);
        }
        drop(cluster_engine);

        // 3. Local policies
        let local_decision = self.local.evaluate(context).await?;
        debug!(
            allowed = local_decision.allowed,
            reason = %local_decision.reason,
            "Local policy evaluated"
        );
        Ok(local_decision)
    }

    /// Add a policy to the local engine.
    pub async fn add_local_policy(&self, policy: Policy) {
        self.local.add_policy(policy).await;
    }

    /// Add a policy to the cluster engine.
    pub async fn add_cluster_policy(&self, policy: Policy) {
        let engine = self.cluster.read().await;
        engine.add_policy(policy).await;
    }

    /// Add a policy to the federation engine.
    pub async fn add_federation_policy(&self, policy: Policy) {
        let engine = self.federation.read().await;
        engine.add_policy(policy).await;
    }

    /// Count policies at each level.
    pub async fn policy_counts(&self) -> (usize, usize, usize) {
        let local_count = self.local.list_policies().await.len();
        let cluster_count = self.cluster.read().await.list_policies().await.len();
        let fed_count = self.federation.read().await.list_policies().await.len();
        (local_count, cluster_count, fed_count)
    }
}

impl Default for FederatedPolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

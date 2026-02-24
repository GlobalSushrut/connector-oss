//! Tests for aapi-federation.

use std::collections::HashMap;

use aapi_core::types::*;
use aapi_core::vakya::{CapabilityRef, TtlConstraint};
use aapi_core::Vakya;
use aapi_metarules::context::EvaluationContext;
use aapi_metarules::rules::{Policy, Rule, Condition, ConditionType, Operator};

use crate::capability_verify::*;
use crate::federated_policy::*;
use crate::scitt_exchange::*;

// ============================================================================
// Test helpers
// ============================================================================

fn make_test_vakya(agent_pid: &str, action: &str) -> Vakya {
    let (domain, verb) = action.split_once('.').unwrap_or((action, "do"));
    Vakya::builder()
        .karta(aapi_core::vakya::Karta {
            pid: PrincipalId::new(agent_pid),
            role: Some("agent".to_string()),
            realm: None,
            key_id: None,
            actor_type: aapi_core::vakya::ActorType::Agent,
            delegation_chain: vec![],
        })
        .karma(aapi_core::vakya::Karma {
            rid: ResourceId::new("res:test"),
            kind: Some("test".to_string()),
            ns: Some(Namespace::new("test")),
            version: None,
            labels: HashMap::new(),
        })
        .kriya(aapi_core::vakya::Kriya::new(domain, verb))
        .adhikarana(aapi_core::vakya::Adhikarana {
            cap: CapabilityRef::Reference {
                cap_ref: "cap:test:all".to_string(),
            },
            policy_ref: None,
            ttl: Some(TtlConstraint {
                expires_at: Timestamp(chrono::Utc::now() + chrono::Duration::hours(1)),
                max_duration_ms: None,
            }),
            budgets: vec![],
            approval_lane: ApprovalLane::None,
            scopes: vec!["read".to_string(), "write".to_string(), "admin".to_string()],
            context: None,
            delegation_chain_cid: None,
            execution_constraints: None,
            port_id: None,
            required_phase: None,
            required_role: None,
        })
        .build()
        .expect("test vakya should be valid")
}

fn make_deny_policy(id: &str, name: &str, action_pattern: &str) -> Policy {
    Policy::new(id, name)
        .with_priority(100)
        .with_rule(
            Rule::deny(format!("{}-r1", id), format!("{} deny rule", name))
                .with_condition(Condition::action(Operator::Eq, action_pattern))
                .with_priority(100),
        )
}

fn make_allow_policy(id: &str, name: &str) -> Policy {
    Policy::new(id, name)
        .with_default_allow()
        .with_priority(50)
        .with_rule(
            Rule::allow(format!("{}-r1", id), format!("{} allow rule", name))
                .with_priority(50),
        )
}

fn make_eval_context(action: &str) -> EvaluationContext {
    let vakya = make_test_vakya("pid:001", action);
    EvaluationContext::new(vakya)
}

// ============================================================================
// FederatedPolicyEngine tests (D9)
// ============================================================================

#[tokio::test]
async fn test_federated_policy_default_deny() {
    let engine = FederatedPolicyEngine::new();
    let ctx = make_eval_context("file.read");
    let decision = engine.evaluate(&ctx).await.unwrap();
    // Default PolicyEngine denies when no rules match
    assert!(!decision.allowed);
}

#[tokio::test]
async fn test_federated_policy_local_allow() {
    let engine = FederatedPolicyEngine::new();
    engine.add_local_policy(make_allow_policy("local-1", "Allow all")).await;

    let ctx = make_eval_context("file.read");
    let decision = engine.evaluate(&ctx).await.unwrap();
    assert!(decision.allowed);
}

#[tokio::test]
async fn test_federated_federation_deny_overrides_local_allow() {
    let engine = FederatedPolicyEngine::new();
    // Local allows everything
    engine.add_local_policy(make_allow_policy("local-1", "Allow all")).await;
    // Federation denies file.delete
    engine
        .add_federation_policy(make_deny_policy("fed-1", "No deletes", "file.delete"))
        .await;

    // file.read should still be allowed (federation deny doesn't match)
    let ctx_read = make_eval_context("file.read");
    let decision_read = engine.evaluate(&ctx_read).await.unwrap();
    assert!(decision_read.allowed);

    // file.delete should be denied by federation
    let ctx_delete = make_eval_context("file.delete");
    let decision_delete = engine.evaluate(&ctx_delete).await.unwrap();
    assert!(!decision_delete.allowed);
}

#[tokio::test]
async fn test_federated_cluster_deny_overrides_local_allow() {
    let engine = FederatedPolicyEngine::new();
    engine.add_local_policy(make_allow_policy("local-1", "Allow all")).await;
    engine
        .add_cluster_policy(make_deny_policy("cluster-1", "No admin", "admin.delete"))
        .await;

    let ctx = make_eval_context("admin.delete");
    let decision = engine.evaluate(&ctx).await.unwrap();
    assert!(!decision.allowed);
}

#[tokio::test]
async fn test_federated_policy_counts() {
    let engine = FederatedPolicyEngine::new();
    engine.add_local_policy(make_allow_policy("l1", "L1")).await;
    engine.add_local_policy(make_allow_policy("l2", "L2")).await;
    engine.add_cluster_policy(make_allow_policy("c1", "C1")).await;
    engine.add_federation_policy(make_allow_policy("f1", "F1")).await;

    let (local, cluster, fed) = engine.policy_counts().await;
    assert_eq!(local, 2);
    assert_eq!(cluster, 1);
    assert_eq!(fed, 1);
}

// ============================================================================
// CrossCellCapabilityVerifier tests (D10)
// ============================================================================

#[test]
fn test_capability_verifier_register_cells() {
    let mut verifier = CrossCellCapabilityVerifier::new();
    assert_eq!(verifier.cell_count(), 0);

    verifier.register_cell("cell-1", vec![1, 2, 3]);
    verifier.register_cell("cell-2", vec![4, 5, 6]);
    assert_eq!(verifier.cell_count(), 2);
    assert!(verifier.is_known_cell("cell-1"));
    assert!(!verifier.is_known_cell("cell-99"));

    verifier.deregister_cell("cell-1");
    assert_eq!(verifier.cell_count(), 1);
    assert!(!verifier.is_known_cell("cell-1"));
}

#[test]
fn test_capability_verify_unknown_cell() {
    let verifier = CrossCellCapabilityVerifier::new();
    let vakya = make_test_vakya("pid:001", "file.read");
    let result = verifier.verify_cross_cell(&vakya, "unknown-cell");
    assert!(result.is_err());
}

#[test]
fn test_capability_verify_valid_chain() {
    let mut verifier = CrossCellCapabilityVerifier::new();
    verifier.register_cell("cell-1", vec![1, 2, 3]);

    let vakya = make_test_vakya("pid:001", "file.read");
    let result = verifier.verify_cross_cell(&vakya, "cell-1").unwrap();
    assert!(result.valid);
    assert_eq!(result.source_cell_id, "cell-1");
    assert_eq!(result.delegation_depth, 0); // no delegation hops
    assert!(result.issues.is_empty());
}

#[test]
fn test_capability_verify_with_delegation() {
    let mut verifier = CrossCellCapabilityVerifier::new();
    verifier.register_cell("cell-1", vec![1, 2, 3]);

    // Build a vakya with delegation chain
    let mut vakya = make_test_vakya("pid:001", "file.read");
    vakya.v1_karta.delegation_chain = vec![
        aapi_core::vakya::DelegationHop {
            delegator: PrincipalId::new("pid:admin"),
            delegated_at: Timestamp::now(),
            reason: Some("cross-cell delegation".into()),
            attenuation: Some(aapi_core::vakya::CapabilityAttenuation {
                removed_scopes: vec!["admin".to_string()],
                reduced_budgets: vec![],
                reduced_ttl_ms: None,
            }),
        },
    ];

    let result = verifier.verify_cross_cell(&vakya, "cell-1").unwrap();
    assert!(result.valid);
    assert_eq!(result.delegation_depth, 1);
}

// ============================================================================
// ScittExchange tests (D10)
// ============================================================================

#[test]
fn test_scitt_issue_receipt() {
    let exchange = ScittExchange::new("org-1", vec![42; 32]);
    let receipt = exchange.issue_receipt(
        "bafyrei_action_123",
        vec!["bafyrei_evidence_1".into(), "bafyrei_evidence_2".into()],
    );

    assert_eq!(receipt.issuer, "org-1");
    assert_eq!(receipt.action_cid, "bafyrei_action_123");
    assert_eq!(receipt.evidence_cids.len(), 2);
    assert!(!receipt.payload_hash.is_empty());
    assert!(!receipt.signature.is_empty());
    assert!(!receipt.receipt_id.is_empty());
}

#[test]
fn test_scitt_verify_receipt_success() {
    let secret = vec![42; 32];
    let issuer_exchange = ScittExchange::new("org-1", secret.clone());

    let receipt = issuer_exchange.issue_receipt(
        "bafyrei_action_456",
        vec!["bafyrei_ev_1".into()],
    );

    // Verifier knows org-1's key
    let mut verifier_exchange = ScittExchange::new("org-2", vec![99; 32]);
    verifier_exchange.register_issuer("org-1", secret);

    let result = verifier_exchange.verify_receipt(&receipt);
    assert!(result.is_ok());
    assert!(result.unwrap());
}

#[test]
fn test_scitt_verify_unknown_issuer() {
    let exchange = ScittExchange::new("org-1", vec![42; 32]);
    let receipt = exchange.issue_receipt("bafyrei_x", vec![]);

    // Verifier does NOT know org-1
    let verifier = ScittExchange::new("org-2", vec![99; 32]);
    let result = verifier.verify_receipt(&receipt);
    assert!(result.is_err());
}

#[test]
fn test_scitt_verify_tampered_receipt() {
    let secret = vec![42; 32];
    let exchange = ScittExchange::new("org-1", secret.clone());
    let mut receipt = exchange.issue_receipt("bafyrei_y", vec!["ev1".into()]);

    // Tamper with the action CID
    receipt.action_cid = "bafyrei_TAMPERED".to_string();

    let mut verifier = ScittExchange::new("org-2", vec![99; 32]);
    verifier.register_issuer("org-1", secret);

    let result = verifier.verify_receipt(&receipt);
    assert!(result.is_err());
}

#[test]
fn test_scitt_issuer_management() {
    let mut exchange = ScittExchange::new("org-1", vec![42; 32]);
    assert_eq!(exchange.issuer_count(), 0);

    exchange.register_issuer("org-2", vec![1, 2, 3]);
    exchange.register_issuer("org-3", vec![4, 5, 6]);
    assert_eq!(exchange.issuer_count(), 2);

    exchange.deregister_issuer("org-2");
    assert_eq!(exchange.issuer_count(), 1);
}

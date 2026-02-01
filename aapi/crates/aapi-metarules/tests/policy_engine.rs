use aapi_core::{
    Vakya,
    Karta,
    Karma,
    Kriya,
    Adhikarana,
    CapabilityRef,
    ApprovalLane,
    PrincipalId,
    ResourceId,
    ActorType,
};
use aapi_metarules::{
    EvaluationContext,
    PolicyEngine,
    Policy,
    Rule,
    ApprovalConfig,
    Condition,
    ConditionType,
    Operator,
    DecisionType,
    ApprovalType,
};

fn test_adhikarana() -> Adhikarana {
    Adhikarana {
        cap: CapabilityRef::Reference { cap_ref: "cap:test:123".to_string() },
        policy_ref: None,
        ttl: None,
        budgets: vec![],
        approval_lane: ApprovalLane::None,
        scopes: vec![],
        context: None,
    }
}

fn build_vakya(action: &str, rid: &str) -> Vakya {
    let (domain, verb) = action.split_once('.').expect("action must be domain.verb");

    Vakya::builder()
        .karta(Karta {
            pid: PrincipalId::new("agent:test"),
            role: None,
            realm: None,
            key_id: None,
            actor_type: ActorType::Agent,
            delegation_chain: vec![],
        })
        .karma(Karma {
            rid: ResourceId::new(rid),
            kind: None,
            ns: None,
            version: None,
            labels: std::collections::HashMap::new(),
        })
        .kriya(Kriya::new(domain, verb))
        .adhikarana(test_adhikarana())
        .build()
        .expect("vakya build")
}

#[tokio::test]
async fn policy_engine_denies_matching_rule() {
    let engine = PolicyEngine::new().with_default_allow();

    let policy = Policy::new("p1", "Deny deletes")
        .with_priority(100)
        .with_rule(
            Rule::deny("r1", "Deny file.delete")
                .with_condition(Condition {
                    condition_type: ConditionType::Action,
                    field: "action".to_string(),
                    operator: Operator::Eq,
                    value: serde_json::json!("file.delete"),
                })
                .with_priority(100),
        )
        .with_default_allow();

    engine.add_policy(policy).await;

    let vakya = build_vakya("file.delete", "file:/tmp/aapi/test.txt");
    let ctx = EvaluationContext::new(vakya);

    let decision = engine.evaluate(&ctx).await.expect("evaluate");
    assert_eq!(decision.decision, DecisionType::Deny);
    assert!(!decision.allowed);
}

#[tokio::test]
async fn policy_engine_requires_approval() {
    let engine = PolicyEngine::new().with_default_allow();

    let policy = Policy::new("p2", "Approve http.post")
        .with_priority(50)
        .with_rule(
            Rule::require_approval("r2", "Approve http.post")
                .with_condition(Condition {
                    condition_type: ConditionType::Action,
                    field: "action".to_string(),
                    operator: Operator::Eq,
                    value: serde_json::json!("http.post"),
                })
                .with_approval_config(
                    ApprovalConfig::new(ApprovalType::Human)
                        .with_min_approvals(1)
                        .with_timeout(3600)
                        .with_reason("Approval required for http.post"),
                )
                .with_priority(50),
        )
        .with_default_allow();

    engine.add_policy(policy).await;

    let vakya = build_vakya("http.post", "http:https://example.com/api");
    let ctx = EvaluationContext::new(vakya);

    let decision = engine.evaluate(&ctx).await.expect("evaluate");
    assert_eq!(decision.decision, DecisionType::PendingApproval);
    assert!(!decision.allowed);
    assert!(decision.requires_approval());
}

#[tokio::test]
async fn policy_engine_allows_when_no_rules_match_and_default_allow() {
    let engine = PolicyEngine::new().with_default_allow();

    let vakya = build_vakya("file.read", "file:/tmp/aapi/ok.txt");
    let ctx = EvaluationContext::new(vakya);

    let decision = engine.evaluate(&ctx).await.expect("evaluate");
    assert_eq!(decision.decision, DecisionType::Allow);
    assert!(decision.allowed);
}

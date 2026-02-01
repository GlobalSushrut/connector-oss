use std::sync::Arc;

use axum::extract::State;
use axum::Json;

use aapi_core::{
    ActorType,
    Adhikarana,
    ApprovalLane,
    CapabilityRef,
    Karta,
    Karma,
    Kriya,
    PrincipalId,
    ResourceId,
    Vakya,
};

use aapi_gateway::handlers::{submit_vakya, SubmitVakyaRequest};
use aapi_gateway::state::{AppState, GatewayConfig};

fn test_adhikarana() -> Adhikarana {
    Adhikarana {
        cap: CapabilityRef::Reference {
            cap_ref: "cap:test:123".to_string(),
        },
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
            kind: Some(domain.to_string()),
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
async fn deny_decision_blocks_execution_and_stores_no_effects() {
    let config = GatewayConfig::default();
    let state = Arc::new(AppState::in_memory(config).await.expect("state"));

    let vakya = build_vakya("file.delete", "file:/tmp/aapi/should-deny.txt");
    let vakya_id = vakya.vakya_id.0.clone();

    let request = SubmitVakyaRequest {
        vakya,
        signature: None,
        key_id: None,
    };

    let response = submit_vakya(State(Arc::clone(&state)), Json(request))
        .await
        .expect("handler ok")
        .0;

    assert_eq!(response.status, "denied");
    assert_eq!(response.vakya_id, vakya_id);

    let receipt = response.receipt.expect("receipt");
    assert_eq!(receipt.reason_code, aapi_core::error::ReasonCode::PolicyDenied);
    assert!(receipt.effect_ids.is_empty());

    let effects = state
        .index_db
        .get_effects(&vakya_id)
        .await
        .expect("effects query");
    assert!(effects.is_empty());

    let stored_receipt = state
        .index_db
        .get_receipt(&vakya_id)
        .await
        .expect("receipt query")
        .expect("stored receipt");
    assert_eq!(stored_receipt.reason_code, aapi_core::error::ReasonCode::PolicyDenied);
}

#[tokio::test]
async fn pending_approval_blocks_execution_and_stores_no_effects() {
    let config = GatewayConfig::default();
    let state = Arc::new(AppState::in_memory(config).await.expect("state"));

    let vakya = build_vakya("http.post", "http:https://example.com/api");
    let vakya_id = vakya.vakya_id.0.clone();

    let request = SubmitVakyaRequest {
        vakya,
        signature: None,
        key_id: None,
    };

    let response = submit_vakya(State(Arc::clone(&state)), Json(request))
        .await
        .expect("handler ok")
        .0;

    assert_eq!(response.status, "pending_approval");
    assert_eq!(response.vakya_id, vakya_id);

    let receipt = response.receipt.expect("receipt");
    assert_eq!(receipt.reason_code, aapi_core::error::ReasonCode::ApprovalRequired);
    assert!(receipt.effect_ids.is_empty());

    let policy_decision = response.policy_decision.expect("policy_decision");
    assert_eq!(policy_decision.decision, "pending_approval");
    assert!(policy_decision.approval_id.is_some());

    let effects = state
        .index_db
        .get_effects(&vakya_id)
        .await
        .expect("effects query");
    assert!(effects.is_empty());

    let stored_receipt = state
        .index_db
        .get_receipt(&vakya_id)
        .await
        .expect("receipt query")
        .expect("stored receipt");
    assert_eq!(stored_receipt.reason_code, aapi_core::error::ReasonCode::ApprovalRequired);
}

use std::sync::Arc;

use axum::extract::State;
use axum::Json;
use axum::response::IntoResponse;
use axum::http::StatusCode;

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

use aapi_gateway::handlers::{delete_capability, issue_capability, submit_vakya, DeleteCapabilityResponse, IssueCapabilityRequest, SubmitVakyaRequest};
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
        delegation_chain_cid: None,
        execution_constraints: None,
        port_id: None,
        required_phase: None,
        required_role: None,
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
        capability_token: None,
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
        capability_token: None,
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

#[tokio::test]
async fn revoked_capability_token_returns_403_on_resubmit() {
    let mut config = GatewayConfig::default();
    config.require_capabilities = true;
    let state = Arc::new(AppState::in_memory(config).await.expect("state"));
    tokio::fs::create_dir_all("/tmp/aapi").await.expect("sandbox dir");
    tokio::fs::write("/tmp/aapi/allowed.txt", b"ok").await.expect("seed file");

    let issued = issue_capability(
        State(Arc::clone(&state)),
        Json(IssueCapabilityRequest {
            subject: "agent:test".to_string(),
            action: "file.read".to_string(),
            resource: "file:/tmp/aapi/allowed.txt".to_string(),
            ttl_seconds: Some(3600),
        }),
    )
    .await
    .expect("capability issued")
    .0;

    let capability_json = serde_json::to_string(&issued.capability_token).expect("token json");

    let first = submit_vakya(
        State(Arc::clone(&state)),
        Json(SubmitVakyaRequest {
            vakya: build_vakya("file.read", "file:/tmp/aapi/allowed.txt"),
            signature: None,
            key_id: None,
            capability_token: Some(capability_json.clone()),
        }),
    )
    .await
    .expect("first submit succeeds")
    .0;
    assert_eq!(first.status, "accepted");

    let deleted: DeleteCapabilityResponse = delete_capability(
        State(Arc::clone(&state)),
        axum::extract::Path(issued.token_id.clone()),
    )
    .await
    .expect("delete capability")
    .0;
    assert!(deleted.deleted);

    let denied = submit_vakya(
        State(Arc::clone(&state)),
        Json(SubmitVakyaRequest {
            vakya: build_vakya("file.read", "file:/tmp/aapi/allowed.txt"),
            signature: None,
            key_id: None,
            capability_token: Some(capability_json),
        }),
    )
    .await
    .expect_err("revoked token must be denied")
    .into_response();

    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
}

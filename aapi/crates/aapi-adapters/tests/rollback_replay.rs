use aapi_adapters::{Dispatcher, RegistryBuilder};
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

fn build_vakya(action: &str, rid: &str, body: serde_json::Value) -> Vakya {
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
        .body(body)
        .build()
        .expect("vakya build")
}

#[tokio::test]
async fn dispatcher_rollback_restores_previous_file_state() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let base_dir = temp_dir.path().to_path_buf();

    let file_path = base_dir.join("rb.txt");
    tokio::fs::write(&file_path, b"before").await.expect("write before");

    let rid = format!("file:{}", file_path.display());

    let dispatcher = Dispatcher::from_arc(std::sync::Arc::new(tokio::sync::RwLock::new(
        RegistryBuilder::new()
            .with_file_adapter_config(aapi_adapters::FileAdapter::new().with_base_dir(&base_dir))
            .build(),
    )));

    let ctx = aapi_adapters::ExecutionContext::new("req-rollback");

    let write_vakya = build_vakya(
        "file.write",
        &rid,
        serde_json::json!({"content": "after"}),
    );

    let exec = dispatcher
        .dispatch(&write_vakya, &ctx)
        .await
        .expect("dispatch");

    assert!(exec.success);
    assert_eq!(exec.effects.len(), 1);
    assert!(exec.effects[0].reversible);

    let after = tokio::fs::read_to_string(&file_path)
        .await
        .expect("read after");
    assert!(after.contains("after"));

    dispatcher
        .rollback(&exec.effects[0])
        .await
        .expect("rollback");

    let restored = tokio::fs::read_to_string(&file_path)
        .await
        .expect("read restored");
    assert!(restored.contains("before"));
}

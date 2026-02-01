use aapi_adapters::{Adapter, ExecutionContext, FileAdapter};
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

fn build_file_vakya(action: &str, rid: &str) -> Vakya {
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
            kind: Some("file".to_string()),
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
async fn file_adapter_allows_access_within_sandbox() {
    let base = tempfile::tempdir().expect("tempdir");
    let base_path = base.path().to_path_buf();

    let file_path = base_path.join("ok.txt");
    tokio::fs::write(&file_path, b"hello").await.expect("write");

    let rid = format!("file:{}", file_path.display());
    let vakya = build_file_vakya("file.read", &rid);

    let adapter = FileAdapter::new().with_base_dir(&base_path);
    let ctx = ExecutionContext::new("req-1");

    let result = adapter.execute(&vakya, &ctx).await;
    assert!(result.is_ok(), "expected ok, got: {:?}", result);
}

#[tokio::test]
async fn file_adapter_denies_access_outside_sandbox_existing_path() {
    let base = tempfile::tempdir().expect("tempdir");
    let outside = tempfile::tempdir().expect("tempdir");

    let base_path = base.path().to_path_buf();
    let outside_file = outside.path().join("outside.txt");
    tokio::fs::write(&outside_file, b"nope").await.expect("write");

    let rid = format!("file:{}", outside_file.display());
    let vakya = build_file_vakya("file.read", &rid);

    let adapter = FileAdapter::new().with_base_dir(&base_path);
    let ctx = ExecutionContext::new("req-2");

    let result = adapter.execute(&vakya, &ctx).await;
    assert!(result.is_err(), "expected err for out-of-sandbox access");
}

#[tokio::test]
async fn file_adapter_denies_path_traversal_attempt() {
    let base = tempfile::tempdir().expect("tempdir");
    let base_path = base.path().to_path_buf();

    let traversal = base_path.join("..").join("outside.txt");
    let rid = format!("file:{}", traversal.display());
    let vakya = build_file_vakya("file.read", &rid);

    let adapter = FileAdapter::new().with_base_dir(&base_path);
    let ctx = ExecutionContext::new("req-3");

    let result = adapter.execute(&vakya, &ctx).await;
    assert!(result.is_err(), "expected err for traversal attempt");
}

//! Offline `.witness` bundle round-trip (prod-readiness smoke).

use serde_json::json;
use uuid::Uuid;
use witnessctl::bundle_file::{load_bundle_json, write_bundle_artifacts, BUNDLE_TYPE};
use witnessctl::receipt::{compute_bundle_signature, generate_receipt, verify_bundle_value};
#[test]
fn witness_bundle_offline_roundtrip() {
    let secret = "witness-bundle-smoke-secret";
    let session_id = Uuid::new_v4();
    let receipt = generate_receipt(
        session_id,
        None,
        "session.open",
        0,
        json!({"upstream": "https://smoke.test"}),
        None,
        secret,
    );
    let captures = vec![json!({
        "id": Uuid::new_v4(),
        "seq": 1,
        "method": "GET",
        "host": "smoke.test",
        "path": "/health",
    })];
    let receipts = vec![json!({
        "id": receipt.id,
        "capture_id": receipt.capture_id,
        "event_type": receipt.event_type,
        "seq": receipt.seq,
        "payload": receipt.payload,
        "hmac": receipt.hmac,
        "prev_hmac": receipt.prev_hmac,
        "created_at": receipt.created_at.to_rfc3339(),
    })];
    let content_sha = sha256::digest(
        serde_json::to_vec(&json!({"captures": &captures, "receipts": &receipts})).unwrap(),
    );
    let chain_head = receipt.hmac.clone();
    let signature = compute_bundle_signature(&content_sha, &chain_head, secret);
    let bundle = json!({
        "bundle_type": BUNDLE_TYPE,
        "session": {"id": session_id, "chain_head_hmac": chain_head},
        "manifest": {"content_sha256": content_sha},
        "bundle_signature": signature,
        "captures": captures,
        "receipts": receipts,
    });

    let report = verify_bundle_value(&bundle, secret).expect("verify");
    assert!(!report.tamper_detected, "{:?}", report);

    let dir = std::env::temp_dir().join(format!("wc-bundle-smoke-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let (witness, legacy, meta) = (
        dir.join("smoke.witness"),
        dir.join("smoke.witnessctl"),
        dir.join("smoke.witness.json"),
    );
    let meta_doc = json!({
        "bundle_type": BUNDLE_TYPE,
        "primary_path": witness.display().to_string(),
    });
    write_bundle_artifacts(&witness, &legacy, &meta, &bundle, &meta_doc).unwrap();
    let loaded = load_bundle_json(&witness).unwrap();
    let report2 = verify_bundle_value(&loaded, secret).expect("reload verify");
    assert!(!report2.tamper_detected);
    let loaded_meta = load_bundle_json(&meta).unwrap();
    let report3 = verify_bundle_value(&loaded_meta, secret).expect("meta verify");
    assert!(!report3.tamper_detected);
    let _ = std::fs::remove_dir_all(&dir);
}

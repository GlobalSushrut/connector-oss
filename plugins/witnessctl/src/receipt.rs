use hmac::{Hmac, Mac};
use sha2::Sha256;
use uuid::Uuid;

use crate::types::Receipt;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, serde::Serialize)]
pub struct BundleVerifyReport {
    pub chain_valid: bool,
    pub head_matches: bool,
    pub content_hash_matches: bool,
    pub signature_valid: bool,
    pub receipt_count: usize,
    pub capture_count: usize,
    pub tamper_detected: bool,
}

/// Compute HMAC-SHA256 for receipt chaining
pub fn compute_hmac(payload: &str, prev_hmac: Option<&str>, secret: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .expect("HMAC can take key of any size");

    mac.update(payload.as_bytes());

    if let Some(prev) = prev_hmac {
        mac.update(prev.as_bytes());
    }

    let result = mac.finalize();
    hex::encode(result.into_bytes())
}

/// Generate a new receipt in the chain
pub fn generate_receipt(
    session_id: Uuid,
    capture_id: Option<Uuid>,
    event_type: &str,
    seq: i64,
    payload: serde_json::Value,
    prev_hmac: Option<&str>,
    secret: &str,
) -> Receipt {
    let payload_str = serde_json::to_string(&payload).unwrap_or_default();
    let hmac = compute_hmac(&payload_str, prev_hmac, secret);

    Receipt {
        id: Uuid::new_v4(),
        session_id,
        capture_id,
        event_type: event_type.to_string(),
        seq,
        payload,
        hmac: hmac.clone(),
        prev_hmac: prev_hmac.map(|s| s.to_string()),
        created_at: chrono::Utc::now(),
    }
}

/// Verify receipt chain integrity
pub fn verify_chain(receipts: &[Receipt], secret: &str) -> bool {
    if receipts.is_empty() {
        return true;
    }

    for window in receipts.windows(2) {
        let prev = &window[0];
        let curr = &window[1];

        // Check that curr.prev_hmac matches prev.hmac
        if curr.prev_hmac.as_ref() != Some(&prev.hmac) {
            return false;
        }

        // Verify curr's HMAC is correct
        let payload_str = serde_json::to_string(&curr.payload).unwrap_or_default();
        let expected_hmac = compute_hmac(&payload_str, Some(&prev.hmac), secret);
        if curr.hmac != expected_hmac {
            return false;
        }
    }

    // Verify first receipt (no prev_hmac)
    let first = &receipts[0];
    let payload_str = serde_json::to_string(&first.payload).unwrap_or_default();
    let expected_hmac = compute_hmac(&payload_str, None, secret);
    if first.hmac != expected_hmac {
        return false;
    }

    true
}

pub fn compute_bundle_signature(content_sha256: &str, chain_head_hmac: &str, secret: &str) -> String {
    compute_hmac(
        &format!("{}:{}", content_sha256, chain_head_hmac),
        None,
        secret,
    )
}

pub fn verify_bundle_value(bundle: &serde_json::Value, secret: &str) -> Result<BundleVerifyReport, String> {
    let captures = bundle
        .get("captures")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "bundle.captures is missing or invalid".to_string())?;
    let receipts_json = bundle
        .get("receipts")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "bundle.receipts is missing or invalid".to_string())?;
    let session = bundle
        .get("session")
        .ok_or_else(|| "bundle.session is missing".to_string())?;
    let expected_head = session
        .get("chain_head_hmac")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let manifest = bundle
        .get("manifest")
        .ok_or_else(|| "bundle.manifest is missing".to_string())?;
    let expected_content_hash = manifest
        .get("content_sha256")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let bundle_signature = bundle
        .get("bundle_signature")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();

    let mut chain_valid = true;
    let mut prev: Option<String> = None;
    for row in receipts_json {
        let payload = row.get("payload").cloned().unwrap_or(serde_json::Value::Null);
        let payload_str = serde_json::to_string(&payload).unwrap_or_default();
        let expected = compute_hmac(&payload_str, prev.as_deref(), secret);
        let got = row.get("hmac").and_then(|v| v.as_str()).unwrap_or_default();
        if got != expected {
            chain_valid = false;
            break;
        }
        let got_prev = row.get("prev_hmac").and_then(|v| v.as_str());
        let expected_prev = prev.as_deref();
        if got_prev != expected_prev {
            chain_valid = false;
            break;
        }
        prev = Some(got.to_string());
    }

    let computed_head = receipts_json
        .last()
        .and_then(|r| r.get("hmac"))
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let head_matches = !expected_head.is_empty() && computed_head == expected_head;

    let computed_content_hash = sha256::digest(serde_json::to_vec(&serde_json::json!({
        "captures": captures,
        "receipts": receipts_json,
    }))
    .unwrap_or_default());
    let content_hash_matches = !expected_content_hash.is_empty() && computed_content_hash == expected_content_hash;

    let expected_signature = compute_bundle_signature(&computed_content_hash, &computed_head, secret);
    let signature_valid = !bundle_signature.is_empty() && expected_signature == bundle_signature;

    let tamper_detected = !(chain_valid && head_matches && content_hash_matches && signature_valid);
    Ok(BundleVerifyReport {
        chain_valid,
        head_matches,
        content_hash_matches,
        signature_valid,
        receipt_count: receipts_json.len(),
        capture_count: captures.len(),
        tamper_detected,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_hmac_computation() {
        let secret = "test-secret";
        let payload = r#"{"event":"test"}"#;
        let hmac1 = compute_hmac(payload, None, secret);
        let hmac2 = compute_hmac(payload, None, secret);
        assert_eq!(hmac1, hmac2);

        let hmac_chained = compute_hmac(payload, Some(&hmac1), secret);
        assert_ne!(hmac1, hmac_chained);
    }

    #[test]
    fn test_receipt_generation() {
        let secret = "test-secret";
        let r1 = generate_receipt(
            Uuid::new_v4(),
            None,
            "session.open",
            0,
            json!({"upstream": "https://api.example.com"}),
            None,
            secret,
        );

        let r2 = generate_receipt(
            r1.session_id,
            Some(Uuid::new_v4()),
            "api.call",
            1,
            json!({"method": "GET", "url": "/users"}),
            Some(&r1.hmac),
            secret,
        );

        assert!(r2.prev_hmac.as_ref() == Some(&r1.hmac));
        assert!(verify_chain(&[r1.clone(), r2.clone()], secret));
    }

    #[test]
    fn test_tamper_detection() {
        let secret = "test-secret";
        let mut r1 = generate_receipt(
            Uuid::new_v4(),
            None,
            "test",
            0,
            json!({"data": "original"}),
            None,
            secret,
        );

        // Tamper with payload but not HMAC
        r1.payload = json!({"data": "tampered"});

        // Should fail verification
        assert!(!verify_chain(&[r1.clone()], secret));
    }

    #[test]
    fn test_verify_bundle_value_ok_and_tamper() {
        let secret = "test-secret";
        let receipt = generate_receipt(
            Uuid::new_v4(),
            None,
            "session.open",
            0,
            json!({"upstream":"https://example.test"}),
            None,
            secret,
        );
        let captures = vec![json!({
            "id": Uuid::new_v4(),
            "seq": 1,
            "method": "GET",
            "host": "example.test",
            "path": "/health"
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
            serde_json::to_vec(&json!({"captures": captures, "receipts": receipts})).unwrap()
        );
        let chain_head = receipts[0].get("hmac").and_then(|v| v.as_str()).unwrap().to_string();
        let signature = compute_bundle_signature(&content_sha, &chain_head, secret);
        let bundle = json!({
            "bundle_type": "witnessctl.evidence_bundle.v1",
            "session": {"id": Uuid::new_v4(), "chain_head_hmac": chain_head},
            "manifest": {"content_sha256": content_sha},
            "bundle_signature": signature,
            "captures": captures,
            "receipts": receipts
        });
        let report = verify_bundle_value(&bundle, secret).expect("verify report");
        assert!(!report.tamper_detected);
        assert!(report.chain_valid && report.head_matches && report.content_hash_matches && report.signature_valid);

        let mut tampered = bundle;
        tampered["receipts"][0]["payload"] = json!({"upstream":"https://evil.test"});
        let bad = verify_bundle_value(&tampered, secret).expect("tampered report");
        assert!(bad.tamper_detected);
    }
}

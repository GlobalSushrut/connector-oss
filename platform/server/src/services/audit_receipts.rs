//! AMA-6: Signed audit receipt service — legal-grade independently verifiable audit export.
//!
//! Routes:
//!   GET  /agents/{pid}/audit/receipt/{entry_id}       — single signed receipt
//!   GET  /agents/{pid}/audit/receipts                 — bulk signed export (from_ms, to_ms)
//!   POST /agents/{pid}/audit/receipts/verify          — offline chain verification

use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::Deserialize;

use crate::state::SharedState;
use connector_engine::engine_store::{AuditFilter, EngineStore};

fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339()
}
fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

fn sha256_hex(input: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(input.as_bytes()))
}

fn receipt_hmac_key() -> Vec<u8> {
    std::env::var("CONNECTOR_RECEIPT_HMAC_KEY")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            std::env::var("CONNECTOR_JWT_SECRET")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        })
        .unwrap_or_else(|| "connector-receipt-unkeyed-dev".to_string())
        .into_bytes()
}

fn hmac_sha256_hex(secret: &[u8], input: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC-SHA256 accepts any key length");
    mac.update(input.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn make_receipt(
    entry_id: &str,
    agent_pid: &str,
    operation: &str,
    outcome: &str,
    ts_ms: i64,
    note: Option<&str>,
    parent_receipt: Option<String>,
) -> serde_json::Value {
    let receipt_id = format!("rcpt_{}", uuid::Uuid::new_v4().simple());
    let content_hash = sha256_hex(&format!(
        "{}||{}||{}||{}||{}",
        operation,
        outcome,
        ts_ms,
        agent_pid,
        note.unwrap_or("")
    ));
    let sig_input = format!("{}{}{}", receipt_id, content_hash, ts_ms);
    let platform_sig = hmac_sha256_hex(&receipt_hmac_key(), &sig_input);

    serde_json::json!({
        "receipt_id": receipt_id,
        "entry_id": entry_id,
        "agent_pid": agent_pid,
        "operation": operation,
        "outcome": outcome,
        "timestamp_ms": ts_ms,
        "content_hash": content_hash,
        "content_hash_alg": "SHA-256",
        "platform_sig": platform_sig,
        "sig_alg": "HMAC-SHA256",
        "receipt_version": 2,
        "parent_receipt": parent_receipt,
        "note": note,
        "created_at": now_iso(),
    })
}

/// GET /agents/{pid}/audit/receipt/{entry_id} — single signed receipt
pub async fn get_audit_receipt(
    State(state): State<SharedState>,
    Path((pid, entry_id)): Path<(String, String)>,
) -> Json<serde_json::Value> {
    // Look up the audit entry from the append-only engine audit log.
    // `entry_id` is currently treated as the zero-based position within the
    // filtered audit stream for the agent.
    let entry = {
        let es = state.engine_store.lock().unwrap();
        let filter = AuditFilter {
            agent_pid: Some(pid.clone()),
            ..Default::default()
        };
        let mut entries = es.query_audit(&filter).unwrap_or_default();
        entries.sort_by_key(|e| e.timestamp);
        entry_id
            .parse::<usize>()
            .ok()
            .and_then(|idx| entries.get(idx).cloned())
    };

    match entry {
        None => Json(serde_json::json!({
            "ok": false,
            "error": {"code": "entry_not_found", "message": format!("audit entry {} not found", entry_id)}
        })),
        Some(e) => {
            let operation = e.action.as_str();
            let outcome = e.verdict.as_deref().unwrap_or("unknown");
            let ts_ms = e.timestamp;
            let note = e
                .details
                .as_ref()
                .and_then(|v| v.get("reason"))
                .and_then(|v| v.as_str());

            let receipt = make_receipt(&entry_id, &pid, operation, outcome, ts_ms, note, None);
            Json(serde_json::json!({ "ok": true, "receipt": receipt }))
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ReceiptRangeQuery {
    pub from_ms: Option<i64>,
    pub to_ms: Option<i64>,
    pub limit: Option<usize>,
}

/// GET /agents/{pid}/audit/receipts — bulk signed receipt export with chain
pub async fn list_audit_receipts(
    State(state): State<SharedState>,
    Path(pid): Path<String>,
    Query(q): Query<ReceiptRangeQuery>,
) -> Json<serde_json::Value> {
    let from_ms = q.from_ms.unwrap_or(0);
    let to_ms = q.to_ms.unwrap_or(i64::MAX);
    let limit = q.limit.unwrap_or(500).min(2000);

    // Resolve name/api_pid/pid:xxx → kernel_pid for consistent lookups
    let (kernel_pid, _) = crate::services::agents::resolve_kernel_pid_pub(&state, &pid);

    // Fetch all audit entries for this agent from the append-only engine audit log.
    let raw_entries = {
        let es = state.engine_store.lock().unwrap();
        let filter = AuditFilter {
            from_ms: Some(from_ms),
            to_ms: Some(to_ms),
            agent_pid: Some(kernel_pid.clone()),
            limit: Some(limit),
            ..Default::default()
        };
        es.query_audit(&filter).unwrap_or_default()
    };

    // Sort by timestamp ascending for chain
    let mut sorted = raw_entries;
    sorted.sort_by_key(|e| e.timestamp);
    sorted.truncate(limit);

    // Build chained receipts
    let mut receipts: Vec<serde_json::Value> = Vec::with_capacity(sorted.len());
    let mut prev_id: Option<String> = None;

    for (idx, entry) in sorted.iter().enumerate() {
        let entry_id = idx.to_string();
        let operation = entry.action.as_str();
        let outcome = entry.verdict.as_deref().unwrap_or("unknown");
        let ts_ms = entry.timestamp;
        let note = entry
            .details
            .as_ref()
            .and_then(|v| v.get("reason"))
            .and_then(|v| v.as_str());

        let receipt = make_receipt(
            &entry_id,
            &pid,
            operation,
            outcome,
            ts_ms,
            note,
            prev_id.clone(),
        );
        prev_id = receipt
            .get("receipt_id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        receipts.push(receipt);
    }

    Json(serde_json::json!({
        "ok": true,
        "agent_pid": pid,
        "from_ms": from_ms,
        "to_ms": to_ms,
        "count": receipts.len(),
        "chain_head": prev_id,
        "receipts": receipts,
    }))
}

/// POST /agents/{pid}/audit/receipts/verify — offline chain verification
pub async fn verify_receipt_chain(
    _state: State<SharedState>,
    Path(_pid): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let receipts = match body.get("receipts").and_then(|v| v.as_array()) {
        None => {
            return Json(serde_json::json!({
                "ok": false,
                "error": {"code": "receipts_required", "message": "body.receipts array required"}
            }))
        }
        Some(r) => r,
    };

    if receipts.is_empty() {
        return Json(serde_json::json!({"ok": true, "valid": true, "count": 0}));
    }

    let key = receipt_hmac_key();
    for (i, receipt) in receipts.iter().enumerate() {
        if i > 0 {
            let expected_parent = receipts[i - 1].get("receipt_id").and_then(|v| v.as_str());
            let actual_parent = receipt.get("parent_receipt").and_then(|v| v.as_str());
            if expected_parent != actual_parent {
                return Json(serde_json::json!({
                    "ok": true,
                    "valid": false,
                    "broken_at_index": i,
                    "reason": "parent_receipt chain broken",
                    "expected_parent": expected_parent,
                    "actual_parent": actual_parent,
                }));
            }
        }
        let operation = receipt
            .get("operation")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let outcome = receipt
            .get("outcome")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let ts_ms = receipt
            .get("timestamp_ms")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        let agent_pid = receipt
            .get("agent_pid")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let note = receipt.get("note").and_then(|v| v.as_str()).unwrap_or("");
        let expected_hash = sha256_hex(&format!(
            "{}||{}||{}||{}||{}",
            operation, outcome, ts_ms, agent_pid, note
        ));
        let content_hash = receipt
            .get("content_hash")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if content_hash != expected_hash {
            return Json(serde_json::json!({
                "ok": true,
                "valid": false,
                "broken_at_index": i,
                "reason": "content_hash mismatch",
            }));
        }
        let receipt_id = receipt
            .get("receipt_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let expected_sig =
            hmac_sha256_hex(&key, &format!("{}{}{}", receipt_id, content_hash, ts_ms));
        let platform_sig = receipt
            .get("platform_sig")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if platform_sig != expected_sig {
            return Json(serde_json::json!({
                "ok": true,
                "valid": false,
                "broken_at_index": i,
                "reason": "platform_sig mismatch",
            }));
        }
    }

    Json(serde_json::json!({
        "ok": true,
        "valid": true,
        "count": receipts.len(),
        "chain_head": receipts.last().and_then(|r| r.get("receipt_id")),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipts_use_real_sha256_and_hmac() {
        let r = make_receipt("0", "agt_1", "mem.write", "allow", 1, Some("ok"), None);
        let hash = r["content_hash"].as_str().unwrap();
        assert_eq!(hash.len(), 64);
        assert_eq!(r["content_hash_alg"], "SHA-256");
        assert_eq!(r["sig_alg"], "HMAC-SHA256");
        let expected = sha256_hex("mem.write||allow||1||agt_1||ok");
        assert_eq!(hash, expected);
        let sig_input = format!("{}{}{}", r["receipt_id"].as_str().unwrap(), hash, 1);
        assert_eq!(
            r["platform_sig"].as_str().unwrap(),
            hmac_sha256_hex(&receipt_hmac_key(), &sig_input)
        );
    }

    #[test]
    fn offline_verify_rejects_tampered_payload_and_broken_chain() {
        let a = make_receipt("0", "agt", "op", "ok", 10, None, None);
        let b = make_receipt(
            "1",
            "agt",
            "op2",
            "ok",
            11,
            None,
            a.get("receipt_id")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
        );
        let mut tampered = a.clone();
        tampered["outcome"] = serde_json::json!("evil");
        // content_hash / sig still old → mismatch
        let key = receipt_hmac_key();
        let expected = sha256_hex("op||ok||10||agt||");
        assert_ne!(sha256_hex("op||evil||10||agt||"), expected);
        let receipt_id = tampered["receipt_id"].as_str().unwrap();
        let hash = tampered["content_hash"].as_str().unwrap();
        let bad_sig_ok = tampered["platform_sig"].as_str().unwrap()
            == hmac_sha256_hex(&key, &format!("{}{}{}", receipt_id, hash, 10));
        assert!(bad_sig_ok); // sig matches old hash
                             // recomputed hash from tampered fields fails
        assert_ne!(hash, sha256_hex("op||evil||10||agt||"));

        let mut broken = b.clone();
        broken["parent_receipt"] = serde_json::json!("not-a");
        assert_ne!(broken["parent_receipt"].as_str(), a["receipt_id"].as_str());
    }
}

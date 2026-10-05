//! Persist peer UsageReceipts for Books honesty (P6.5 / I-08).

use connector_trust::{UnmeteredPeerHonesty, UsageReceipt, USAGE_RECEIPT_SCHEMA};

use crate::state::PlatformState;

pub const USAGE_RECEIPTS_FOLDER: &str = "usage_receipts_v2";

pub fn append_usage_receipt(state: &PlatformState, receipt: &UsageReceipt) -> String {
    debug_assert_eq!(receipt.schema, USAGE_RECEIPT_SCHEMA);
    let mut es = state.engine_store.lock().unwrap();
    let _ = es.folder_put(
        USAGE_RECEIPTS_FOLDER,
        &receipt.receipt_id,
        &serde_json::to_value(receipt).unwrap_or_default(),
    );
    receipt.receipt_id.clone()
}

pub fn list_usage_receipts(state: &PlatformState, limit: usize) -> Vec<UsageReceipt> {
    let keys = {
        let es = state.engine_store.lock().unwrap();
        es.folder_keys(USAGE_RECEIPTS_FOLDER, None)
            .unwrap_or_default()
    };
    let es = state.engine_store.lock().unwrap();
    let mut out = Vec::new();
    for k in keys.into_iter().rev().take(limit) {
        if let Some(v) = es.folder_get(USAGE_RECEIPTS_FOLDER, &k).ok().flatten() {
            if let Ok(r) = serde_json::from_value::<UsageReceipt>(v) {
                out.push(r);
            }
        }
    }
    out
}

pub fn unmetered_peer_honesty(state: &PlatformState) -> UnmeteredPeerHonesty {
    let receipts = list_usage_receipts(state, 500);
    UnmeteredPeerHonesty::from_receipts(&receipts)
}

pub fn usage_receipt_count(state: &PlatformState) -> usize {
    let es = state.engine_store.lock().unwrap();
    es.folder_keys(USAGE_RECEIPTS_FOLDER, None)
        .map(|k| k.len())
        .unwrap_or(0)
}

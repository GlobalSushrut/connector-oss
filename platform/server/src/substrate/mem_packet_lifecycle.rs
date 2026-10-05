//! VAC MemPacket lifecycle: staged → verified → consolidated (+ supersede/forget).

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use vac_core::types::MemPacket;

use crate::state::PlatformState;

pub const LIFECYCLE_SCHEMA: &str = "connector.mem.lifecycle.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryLifecycle {
    Staged,
    Verified,
    Consolidated,
    SealedArchived,
    Forgotten,
}

impl MemoryLifecycle {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Staged => "staged",
            Self::Verified => "verified",
            Self::Consolidated => "consolidated",
            Self::SealedArchived => "sealed_archived",
            Self::Forgotten => "forgotten",
        }
    }

    pub fn from_packet(pkt: &MemPacket) -> Self {
        match pkt
            .content
            .payload
            .get("lifecycle")
            .and_then(|v| v.as_str())
        {
            Some("verified") => Self::Verified,
            Some("consolidated") => Self::Consolidated,
            Some("sealed_archived") => Self::SealedArchived,
            Some("forgotten") => Self::Forgotten,
            _ => Self::Staged,
        }
    }
}

/// Mark packet verified after EGCM/RGO/verify success.
pub fn mark_verified(state: &PlatformState, cid: &str) -> Result<Value, String> {
    let mut kernel = state.kernel.lock().map_err(|e| e.to_string())?;
    let cid_parsed = cid.parse().map_err(|e| format!("cid: {e}"))?;
    if !kernel.set_packet_lifecycle(&cid_parsed, MemoryLifecycle::Verified.as_str()) {
        return Err("packet_not_found".into());
    }
    Ok(json!({
        "ok": true,
        "cid": cid,
        "lifecycle": MemoryLifecycle::Verified.as_str(),
        "schema": LIFECYCLE_SCHEMA,
    }))
}

/// Governed supersede — new packet points at old via provenance.supersedes.
pub fn supersede(
    state: &PlatformState,
    old_cid: &str,
    new_cid: &str,
) -> Result<Value, String> {
    let mut kernel = state.kernel.lock().map_err(|e| e.to_string())?;
    let old = old_cid.parse().map_err(|e| format!("old_cid: {e}"))?;
    let new = new_cid.parse().map_err(|e| format!("new_cid: {e}"))?;
    kernel.supersede_packet(&old, &new)?;
    Ok(json!({
        "ok": true,
        "old_cid": old_cid,
        "new_cid": new_cid,
        "honesty": "supersede seals old evidence; does not delete",
    }))
}

/// Soft forget — archive + forgotten marker; never hard-delete evidence.
pub fn forget(state: &PlatformState, cid: &str, reason: &str) -> Result<Value, String> {
    let mut kernel = state.kernel.lock().map_err(|e| e.to_string())?;
    let cid_parsed = cid.parse().map_err(|e| format!("cid: {e}"))?;
    if !kernel.soft_forget_packet(&cid_parsed, reason) {
        return Err("packet_not_found".into());
    }
    Ok(json!({
        "ok": true,
        "cid": cid,
        "lifecycle": "forgotten",
        "honesty": "soft-forget only — packet retained sealed/archived",
    }))
}

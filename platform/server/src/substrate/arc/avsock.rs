//! A-VSOCK — Agency-aware IPC frame codec (Phase F).
//! Protocol between guest stochastic work and host governor — **not** the security boundary.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::{ConnectorError, DenialReason};

use super::flags::ArcFlags;
use super::runtime;

pub const SCHEMA: &str = "connector.arc.avsock.v1";
pub const FRAME_MAGIC: &[u8] = b"AVSK";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageClass {
    Observation,
    TransitionProposal,
    LeaseIssue,
    LeaseRedeem,
    EffectResult,
    MemoryRead,
    MemoryWrite,
    Spawn,
    Freeze,
    Quarantine,
    Revoke,
    Promote,
}

impl MessageClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observation => "OBSERVATION",
            Self::TransitionProposal => "TRANSITION_PROPOSAL",
            Self::LeaseIssue => "LEASE_ISSUE",
            Self::LeaseRedeem => "LEASE_REDEEM",
            Self::EffectResult => "EFFECT_RESULT",
            Self::MemoryRead => "MEMORY_READ",
            Self::MemoryWrite => "MEMORY_WRITE",
            Self::Spawn => "SPAWN",
            Self::Freeze => "FREEZE",
            Self::Quarantine => "QUARANTINE",
            Self::Revoke => "REVOKE",
            Self::Promote => "PROMOTE",
        }
    }

    /// Guest may only drive consequence via LEASE_REDEEM (F2).
    pub fn may_drive_effect(self) -> bool {
        matches!(self, Self::LeaseRedeem)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AvsockFrame {
    pub schema: String,
    pub agent_id: String,
    pub body_id: Option<String>,
    pub cognitive_epoch: u64,
    pub authority_epoch: u64,
    pub class: MessageClass,
    pub capability_id: Option<String>,
    pub transition_id: Option<String>,
    pub digests: Vec<String>,
    pub nonce: String,
    pub payload: Value,
    /// Integrity tag over canonical frame body (excluding tag itself).
    pub integrity_tag: String,
}

impl AvsockFrame {
    pub fn new(
        agent_id: impl Into<String>,
        body_id: Option<String>,
        cognitive_epoch: u64,
        authority_epoch: u64,
        class: MessageClass,
        payload: Value,
    ) -> Self {
        let mut f = Self {
            schema: SCHEMA.into(),
            agent_id: agent_id.into(),
            body_id,
            cognitive_epoch,
            authority_epoch,
            class,
            capability_id: None,
            transition_id: None,
            digests: Vec::new(),
            nonce: Uuid::new_v4().to_string(),
            payload,
            integrity_tag: String::new(),
        };
        f.integrity_tag = f.compute_tag();
        f
    }

    fn tag_material(&self) -> Value {
        json!({
            "schema": self.schema,
            "agent_id": self.agent_id,
            "body_id": self.body_id,
            "cognitive_epoch": self.cognitive_epoch,
            "authority_epoch": self.authority_epoch,
            "class": self.class.as_str(),
            "capability_id": self.capability_id,
            "transition_id": self.transition_id,
            "digests": self.digests,
            "nonce": self.nonce,
            "payload": self.payload,
        })
    }

    pub fn compute_tag(&self) -> String {
        let body = serde_json::to_vec(&self.tag_material()).unwrap_or_default();
        let mut h = Sha256::new();
        h.update(FRAME_MAGIC);
        h.update(b"|");
        h.update(&body);
        format!("{:x}", h.finalize())
    }

    pub fn verify_tag(&self) -> bool {
        !self.integrity_tag.is_empty() && self.integrity_tag == self.compute_tag()
    }

    /// Encode to length-prefixed JSON bytes (F1 round-trip).
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        let json = serde_json::to_vec(self).map_err(|e| e.to_string())?;
        let mut out = Vec::with_capacity(4 + FRAME_MAGIC.len() + json.len());
        out.extend_from_slice(FRAME_MAGIC);
        let len = json.len() as u32;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&json);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < FRAME_MAGIC.len() + 4 {
            return Err("avsock: frame too short".into());
        }
        if &bytes[..FRAME_MAGIC.len()] != FRAME_MAGIC {
            return Err("avsock: bad magic".into());
        }
        let len_off = FRAME_MAGIC.len();
        let len = u32::from_be_bytes(bytes[len_off..len_off + 4].try_into().unwrap()) as usize;
        let start = len_off + 4;
        if bytes.len() < start + len {
            return Err("avsock: truncated payload".into());
        }
        serde_json::from_slice(&bytes[start..start + len]).map_err(|e| e.to_string())
    }
}

/// Soft when flag off (F5 LAB). When on: verify tag + epoch fence.
pub fn accept_host_frame(frame: &AvsockFrame) -> Result<(), ConnectorError> {
    let flags = ArcFlags::from_env();
    if !flags.avsock {
        tracing::trace!("arc_avsock soft skip (CONNECTOR_ARC_AVSOCK off) — LAB");
        return Ok(());
    }
    if !frame.verify_tag() {
        return Err(ConnectorError::new(
            DenialReason::PolicyDenied,
            "avsock: integrity tag mismatch",
        )
        .with_denied_resource("arc.avsock"));
    }
    let live = runtime::epochs().current(&frame.agent_id).get();
    if frame.authority_epoch != live {
        return Err(ConnectorError::new(
            DenialReason::PolicyDenied,
            format!(
                "avsock: epoch fence — frame={} live={}",
                frame.authority_epoch, live
            ),
        )
        .with_denied_resource("arc.avsock")
        .with_hint("Stale A-VSOCK frame dropped (F3)"));
    }
    Ok(())
}

/// Guest-side: refuse to emit an effect-driving frame unless LEASE_REDEEM (F2).
pub fn guest_assert_effect_class(class: MessageClass) -> Result<(), ConnectorError> {
    let flags = ArcFlags::from_env();
    if !flags.avsock {
        return Ok(());
    }
    if !class.may_drive_effect() {
        return Err(ConnectorError::new(
            DenialReason::PolicyDenied,
            format!(
                "avsock: guest rejects effect without LEASE_REDEEM (got {})",
                class.as_str()
            ),
        )
        .with_denied_resource("arc.avsock.guest"));
    }
    Ok(())
}

pub fn posture_json() -> Value {
    let flags = ArcFlags::from_env();
    json!({
        "schema": SCHEMA,
        "flag": "CONNECTOR_ARC_AVSOCK",
        "enforced": flags.avsock,
        "role": "protocol — not the security boundary",
        "security_boundary": "MicroCell bypass inventory (F4) + exclusivity",
        "f5_soft": !flags.avsock,
        "honesty": if flags.avsock {
            "A-VSOCK frames verified (tag + epoch); guest effect requires LEASE_REDEEM"
        } else {
            "ARC_AVSOCK=0 — Soft/LAB; framed IPC not required"
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip() {
        let f = AvsockFrame::new("a1", Some("body".into()), 1, 0, MessageClass::Observation, json!({"x":1}));
        assert!(f.verify_tag());
        let bytes = f.encode().unwrap();
        let back = AvsockFrame::decode(&bytes).unwrap();
        assert_eq!(back.agent_id, "a1");
        assert!(back.verify_tag());
        assert_eq!(back.class, MessageClass::Observation);
    }

    #[test]
    fn guest_rejects_non_redeem_effect() {
        std::env::set_var("CONNECTOR_ARC_AVSOCK", "1");
        let err = guest_assert_effect_class(MessageClass::TransitionProposal).unwrap_err();
        assert!(err.human_readable.contains("LEASE_REDEEM"));
        assert!(guest_assert_effect_class(MessageClass::LeaseRedeem).is_ok());
        std::env::remove_var("CONNECTOR_ARC_AVSOCK");
    }

    #[test]
    fn stale_epoch_dropped() {
        std::env::set_var("CONNECTOR_ARC_AVSOCK", "1");
        let agent = "arc-f-epoch";
        runtime::epochs().bump(agent);
        let live = runtime::epochs().current(agent).get();
        let f = AvsockFrame::new(agent, None, 0, live.saturating_sub(1), MessageClass::LeaseRedeem, json!({}));
        let err = accept_host_frame(&f).unwrap_err();
        assert!(err.human_readable.contains("epoch fence"));
        std::env::remove_var("CONNECTOR_ARC_AVSOCK");
    }
}

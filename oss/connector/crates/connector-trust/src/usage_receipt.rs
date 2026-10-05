//! Peer UsageReceipt — honesty for A2A/MCP/… hops (P6.5 / I-08).
//!
//! Tokens are only authoritative when `metered == true` and a peer receipt exists.
//! Unmetered peers must never be projected as `$0`.

use serde::{Deserialize, Serialize};

pub const USAGE_RECEIPT_SCHEMA: &str = "usage_receipt.v2";

/// Protocol / peer class for a third-party hop.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PeerKind {
    A2a,
    Mcp,
    Acp,
    Anp,
    Ap2,
    Unknown,
}

impl PeerKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::A2a => "a2a",
            Self::Mcp => "mcp",
            Self::Acp => "acp",
            Self::Anp => "anp",
            Self::Ap2 => "ap2",
            Self::Unknown => "unknown",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "a2a" => Self::A2a,
            "mcp" => Self::Mcp,
            "acp" => Self::Acp,
            "anp" => Self::Anp,
            "ap2" => Self::Ap2,
            _ => Self::Unknown,
        }
    }
}

/// One peer-hop usage observation (append-only SoT fragment for Books).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UsageReceipt {
    pub schema: String,
    pub receipt_id: String,
    pub peer_kind: PeerKind,
    /// Remote peer / bridge / agent identity when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_id: Option<String>,
    /// True only when the peer reported meterable tokens.
    pub metered: bool,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub total_tokens: u64,
    /// Aligns with [`crate::UsageTokenSource`] string vocabulary.
    pub token_source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flow_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub moment_id: Option<String>,
    pub observed_at: String,
    /// Explicit honesty when unmetered — never imply `$0`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub honesty_note: Option<String>,
    #[serde(default = "trust_v2")]
    pub contract_version: u32,
}

fn trust_v2() -> u32 {
    2
}

impl UsageReceipt {
    /// Metered peer receipt with peer-reported tokens.
    pub fn metered_peer(
        peer_kind: PeerKind,
        peer_id: impl Into<String>,
        prompt_tokens: u64,
        completion_tokens: u64,
        latency_ms: Option<u64>,
        flow_id: Option<String>,
    ) -> Self {
        let total = prompt_tokens.saturating_add(completion_tokens);
        Self {
            schema: USAGE_RECEIPT_SCHEMA.into(),
            receipt_id: uuid::Uuid::new_v4().to_string(),
            peer_kind,
            peer_id: Some(peer_id.into()),
            metered: true,
            prompt_tokens,
            completion_tokens,
            total_tokens: total,
            token_source: crate::UsageTokenSource::PeerReported.as_str().into(),
            latency_ms,
            flow_id,
            moment_id: None,
            observed_at: chrono::Utc::now().to_rfc3339(),
            honesty_note: None,
            contract_version: 2,
        }
    }

    /// Unmetered peer hop — tokens unavailable (not zero).
    pub fn unmetered_peer(
        peer_kind: PeerKind,
        peer_id: impl Into<String>,
        latency_ms: Option<u64>,
        flow_id: Option<String>,
    ) -> Self {
        Self {
            schema: USAGE_RECEIPT_SCHEMA.into(),
            receipt_id: uuid::Uuid::new_v4().to_string(),
            peer_kind,
            peer_id: Some(peer_id.into()),
            metered: false,
            prompt_tokens: 0,
            completion_tokens: 0,
            total_tokens: 0,
            token_source: crate::UsageTokenSource::Unavailable.as_str().into(),
            latency_ms,
            flow_id,
            moment_id: None,
            observed_at: chrono::Utc::now().to_rfc3339(),
            honesty_note: Some(
                "unmetered_peer: tokens unavailable — do not project as $0".into(),
            ),
            contract_version: 2,
        }
    }
}

/// Append a receipt to an in-memory / export buffer (unit-testable helper).
pub fn append_usage_receipt(buf: &mut Vec<UsageReceipt>, receipt: UsageReceipt) -> String {
    let id = receipt.receipt_id.clone();
    buf.push(receipt);
    id
}

/// Books / API honesty summary for unmetered peer hops.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UnmeteredPeerHonesty {
    pub schema: String,
    pub unmetered_peer_count: u64,
    pub metered_peer_count: u64,
    /// Never treat unavailable peer tokens as zero cost.
    pub never_fake_zero_usd: bool,
    pub honesty: String,
    #[serde(default)]
    pub sample_peer_ids: Vec<String>,
}

impl UnmeteredPeerHonesty {
    pub fn from_receipts(receipts: &[UsageReceipt]) -> Self {
        let mut unmetered = 0u64;
        let mut metered = 0u64;
        let mut sample = Vec::new();
        for r in receipts {
            if r.metered {
                metered = metered.saturating_add(1);
            } else {
                unmetered = unmetered.saturating_add(1);
                if sample.len() < 8 {
                    if let Some(pid) = r.peer_id.as_ref() {
                        sample.push(pid.clone());
                    }
                }
            }
        }
        Self {
            schema: "unmetered_peer_honesty.v1".into(),
            unmetered_peer_count: unmetered,
            metered_peer_count: metered,
            never_fake_zero_usd: true,
            honesty: if unmetered > 0 {
                "unmetered peer hops present — tokens unavailable ≠ $0".into()
            } else if metered > 0 {
                "all recorded peer hops metered via UsageReceipt".into()
            } else {
                "no peer UsageReceipts recorded yet".into()
            },
            sample_peer_ids: sample,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unmetered_receipt_is_unavailable_not_zero_cost() {
        let r = UsageReceipt::unmetered_peer(PeerKind::Mcp, "bridge-1", Some(12), None);
        assert!(!r.metered);
        assert_eq!(r.token_source, "unavailable");
        assert_eq!(r.total_tokens, 0);
        assert!(r.honesty_note.as_deref().unwrap().contains("unmetered_peer"));
        let json = serde_json::to_value(&r).unwrap();
        assert_eq!(json["schema"], USAGE_RECEIPT_SCHEMA);
        assert_eq!(json["peer_kind"], "mcp");
        assert_eq!(json["metered"], false);
    }

    #[test]
    fn metered_receipt_peer_reported() {
        let r = UsageReceipt::metered_peer(PeerKind::A2a, "agent-x", 10, 20, Some(5), Some("flow1".into()));
        assert!(r.metered);
        assert_eq!(r.total_tokens, 30);
        assert_eq!(r.token_source, "peer_reported");
        assert_eq!(r.flow_id.as_deref(), Some("flow1"));
    }

    #[test]
    fn append_and_honesty_summary() {
        let mut buf = Vec::new();
        append_usage_receipt(
            &mut buf,
            UsageReceipt::unmetered_peer(PeerKind::Mcp, "p1", None, None),
        );
        append_usage_receipt(
            &mut buf,
            UsageReceipt::metered_peer(PeerKind::A2a, "p2", 1, 1, None, None),
        );
        assert_eq!(buf.len(), 2);
        let h = UnmeteredPeerHonesty::from_receipts(&buf);
        assert_eq!(h.unmetered_peer_count, 1);
        assert_eq!(h.metered_peer_count, 1);
        assert!(h.never_fake_zero_usd);
        assert!(h.honesty.contains("unavailable"));
        assert!(h.sample_peer_ids.contains(&"p1".to_string()));
    }

    #[test]
    fn peer_kind_round_trip() {
        assert_eq!(PeerKind::parse("MCP"), PeerKind::Mcp);
        assert_eq!(PeerKind::A2a.as_str(), "a2a");
    }
}

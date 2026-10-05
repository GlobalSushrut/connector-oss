//! BeliefSnapshot — VAC-backed projection of accepted claims / hypotheses.
//! Not a parallel world-truth store; every accepted claim cites evidence CIDs.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::state::PlatformState;

pub const BELIEF_SCHEMA: &str = "connector.belief_snapshot.v1";
pub const BELIEF_FOLDER: &str = "belief_snapshots";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimStatus {
    Accepted,
    Hypothesis,
    Contradicted,
    Stale,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeliefClaim {
    pub claim_id: String,
    pub status: ClaimStatus,
    pub evidence_cids: Vec<String>,
    pub summary: String,
    pub freshness_ms: i64,
    pub revision: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeliefSnapshot {
    pub schema: String,
    pub mission_id: String,
    pub agent_pid: String,
    pub claims: Vec<BeliefClaim>,
    pub coverage: f32,
    pub digest_hex: String,
    pub revision: u64,
    pub at_ms: i64,
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

fn digest_of(claims: &[BeliefClaim], revision: u64) -> String {
    let body = json!({ "claims": claims, "revision": revision });
    let bytes = serde_json::to_vec(&body).unwrap_or_default();
    format!("{:x}", Sha256::digest(&bytes))
}

/// Project beliefs from kernel packets in the agent's namespace (Decision/Extraction).
pub fn project_from_vac(
    state: &PlatformState,
    mission_id: &str,
    agent_pid: &str,
) -> BeliefSnapshot {
    let mut claims = Vec::new();
    let mut revision = 1u64;
    if let Ok(kernel) = state.kernel.lock() {
        let ns = format!("m/{}", agent_pid.trim_start_matches("agent_"));
        let packets = kernel.packets_in_namespace(&ns);
        for pkt in packets.into_iter().take(64) {
            let pt = format!("{:?}", pkt.content.packet_type);
            if !(pt.contains("Decision")
                || pt.contains("Extraction")
                || pt.contains("Contradiction"))
            {
                continue;
            }
            let status = if pt.contains("Contradiction") {
                ClaimStatus::Contradicted
            } else if pkt.trust_score >= 0.7 {
                ClaimStatus::Accepted
            } else {
                ClaimStatus::Hypothesis
            };
            let summary = pkt
                .content
                .payload
                .get("text")
                .or_else(|| pkt.content.payload.get("content"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .chars()
                .take(240)
                .collect::<String>();
            let cid = pkt.index.packet_cid.to_string();
            claims.push(BeliefClaim {
                claim_id: format!("b_{}", &cid[..cid.len().min(16)]),
                status,
                evidence_cids: pkt
                    .provenance
                    .evidence_refs
                    .iter()
                    .map(|c| c.to_string())
                    .chain(std::iter::once(cid))
                    .collect(),
                summary,
                freshness_ms: now_ms().saturating_sub(pkt.index.ts),
                revision: 1,
            });
            revision = revision.saturating_add(1);
        }
    }
    let accepted = claims
        .iter()
        .filter(|c| matches!(c.status, ClaimStatus::Accepted))
        .count();
    let coverage = if claims.is_empty() {
        0.0
    } else {
        accepted as f32 / claims.len() as f32
    };
    let digest_hex = digest_of(&claims, revision);
    let snap = BeliefSnapshot {
        schema: BELIEF_SCHEMA.into(),
        mission_id: mission_id.into(),
        agent_pid: agent_pid.into(),
        claims,
        coverage,
        digest_hex,
        revision,
        at_ms: now_ms(),
    };
    if let Ok(mut es) = state.engine_store.lock() {
        let key = format!("{}:{}", mission_id, agent_pid);
        let _ = es.folder_put(BELIEF_FOLDER, &key, &serde_json::to_value(&snap).unwrap_or(Value::Null));
    }
    snap
}

pub fn to_json(s: &BeliefSnapshot) -> Value {
    serde_json::to_value(s).unwrap_or(json!({ "ok": false }))
}

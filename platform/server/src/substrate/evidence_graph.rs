//! Dynamic intelligence → channel → surface evidence graph.
//!
//! Dual-writes EdgeReceipt edges into a queryable index without becoming a
//! grant authority. Confidence / posture / revisions are recorded as observed.

use connector_native_contract::EdgeReceipt;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use connector_engine::engine_store::EngineStore;

pub const EVIDENCE_GRAPH_FOLDER: &str = "evidence_graph_v1";
pub const EVIDENCE_EDGE_SCHEMA: &str = "connector.evidence_edge.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EvidenceEdge {
    pub schema: String,
    pub edge_id: String,
    pub intelligence_uid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel_uid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub surface_uid: Option<String>,
    pub operation_id: String,
    pub semantic_confidence: String,
    pub enforcement_posture: String,
    pub pate_verdict: String,
    pub issued_at_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package_digest: Option<String>,
}

impl EvidenceEdge {
    pub fn from_receipt(receipt: &EdgeReceipt) -> Self {
        let edge_id = format!(
            "eg:{}:{}",
            receipt.intelligence_uid,
            receipt.operation_id
        );
        Self {
            schema: EVIDENCE_EDGE_SCHEMA.into(),
            edge_id,
            intelligence_uid: receipt.intelligence_uid.clone(),
            channel_uid: receipt.channel_uid.clone(),
            surface_uid: receipt.surface_uid.clone(),
            operation_id: receipt.operation_id.clone(),
            semantic_confidence: format!("{:?}", receipt.semantic_confidence),
            enforcement_posture: format!("{:?}", receipt.enforcement_posture),
            pate_verdict: receipt.pate_verdict.clone(),
            issued_at_ms: receipt.issued_at_ms,
            package_digest: None,
        }
    }
}

/// Dual-write an evidence edge from a committed EdgeReceipt.
pub fn index_receipt(es: &mut dyn EngineStore, receipt: &EdgeReceipt) -> Result<EvidenceEdge, String> {
    let edge = EvidenceEdge::from_receipt(receipt);
    let v = serde_json::to_value(&edge).map_err(|e| e.to_string())?;
    es.folder_put(EVIDENCE_GRAPH_FOLDER, &edge.edge_id, &v)
        .map_err(|e| e.to_string())?;
    // Secondary index by intelligence for list queries.
    let idx_key = format!("intel:{}:{}", receipt.intelligence_uid, receipt.operation_id);
    let _ = es.folder_put(EVIDENCE_GRAPH_FOLDER, &idx_key, &json!({ "edge_id": edge.edge_id }));
    Ok(edge)
}

pub fn list_for_intelligence(es: &dyn EngineStore, intelligence_uid: &str, limit: usize) -> Vec<EvidenceEdge> {
    let prefix = format!("eg:{intelligence_uid}:");
    let Ok(keys) = es.folder_keys(EVIDENCE_GRAPH_FOLDER, None) else {
        return vec![];
    };
    let mut out = Vec::new();
    for key in keys {
        if !key.starts_with(&prefix) {
            continue;
        }
        if let Ok(Some(v)) = es.folder_get(EVIDENCE_GRAPH_FOLDER, &key) {
            if let Ok(edge) = serde_json::from_value::<EvidenceEdge>(v) {
                out.push(edge);
            }
        }
        if out.len() >= limit {
            break;
        }
    }
    out
}

pub fn graph_snapshot(es: &dyn EngineStore, intelligence_uid: Option<&str>, limit: usize) -> Value {
    let edges = if let Some(id) = intelligence_uid {
        list_for_intelligence(es, id, limit)
    } else {
        let Ok(keys) = es.folder_keys(EVIDENCE_GRAPH_FOLDER, None) else {
            return json!({ "schema": EVIDENCE_EDGE_SCHEMA, "count": 0, "edges": [] });
        };
        let mut out = Vec::new();
        for key in keys {
            if !key.starts_with("eg:") {
                continue;
            }
            if let Ok(Some(v)) = es.folder_get(EVIDENCE_GRAPH_FOLDER, &key) {
                if let Ok(edge) = serde_json::from_value::<EvidenceEdge>(v) {
                    out.push(edge);
                }
            }
            if out.len() >= limit {
                break;
            }
        }
        out
    };
    json!({
        "schema": EVIDENCE_EDGE_SCHEMA,
        "count": edges.len(),
        "edges": edges,
        "honesty": "Evidence graph indexes EdgeReceipts; it is not an authority source",
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use connector_engine::engine_store::InMemoryEngineStore;
    use connector_native_contract::{EnforcementPosture, SemanticConfidence, SemanticProvenance};

    #[test]
    fn indexes_receipt_edge() {
        let mut es = InMemoryEngineStore::new();
        let receipt = EdgeReceipt {
            operation_id: "op1".into(),
            intelligence_uid: "intel-a".into(),
            workload_uid: "wl".into(),
            software_uid: None,
            channel_uid: Some("ch1".into()),
            surface_uid: Some("sf1".into()),
            semantic_confidence: SemanticConfidence::AdapterVerified,
            semantic_provenance: SemanticProvenance::SignedAdapter {
                adapter_ref: "test".into(),
            },
            enforcement_posture: EnforcementPosture::Advisory,
            target_ref: None,
            observed_locators: vec![],
            action_digest: None,
            effect_digest: None,
            projection_digest: None,
            projection_loss_digest: None,
            contract_ref: "c".into(),
            contract_revision: 1,
            grant_ref: "g".into(),
            authority_revision: 1,
            pate_verdict: "allow".into(),
            execution_state: "succeeded".into(),
            evidence_refs: vec![],
            issued_at_ms: 1,
        };
        let edge = index_receipt(&mut es, &receipt).unwrap();
        assert!(edge.edge_id.contains("intel-a"));
        let listed = list_for_intelligence(&es, "intel-a", 10);
        assert_eq!(listed.len(), 1);
    }
}

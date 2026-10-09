//! Dehallucination chain — grounding verification for LLM claims.
//!
//! Delegates to Connector Chain 3 (chain_tree.rs / grounding.rs in the kernel).
//! Engram's role: orchestrate the request, apply on_fail policy, emit audit,
//! and return typed ClaimResult structs to the route layer.

use anyhow::Result;
use serde_json::json;

use crate::connector::ConnectorClient;
use crate::metrics;
use crate::types::ClaimResult;

#[derive(Debug)]
pub struct GroundingConfig {
    pub threshold: f64,
    pub on_fail:   OnFail,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum OnFail {
    Block,
    Flag,
    Hitl,
}

impl OnFail {
    pub fn from_str(s: &str) -> Self {
        match s {
            "block" => Self::Block,
            "hitl"  => Self::Hitl,
            _       => Self::Flag,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::Flag  => "flag",
            Self::Hitl  => "hitl",
        }
    }
}

/// Ground a set of claims against memory in `namespace`.
/// Returns one `ClaimResult` per input claim.
pub async fn ground_claims(
    connector: &ConnectorClient,
    namespace: &str,
    claims:    &[String],
    config:    &GroundingConfig,
    agent_id:  &str,
) -> Result<(Vec<ClaimResult>, Option<String>)> {
    let dehall = connector
        .ground_claims(namespace, claims, config.threshold)
        .await?;

    let mut results = Vec::with_capacity(dehall.results.len());

    for dr in &dehall.results {
        let outcome = if dr.grounded {
            "passed".to_owned()
        } else {
            match config.on_fail {
                OnFail::Block => "blocked".to_owned(),
                OnFail::Flag  => "flagged".to_owned(),
                OnFail::Hitl  => "hitl".to_owned(),
            }
        };

        metrics::record_grounding(namespace, &outcome);

        results.push(ClaimResult {
            claim:           dr.claim_text.clone(),
            grounding_score: dr.grounding_score,
            grounded:        dr.grounded,
            source_cids:     dr.source_cids.clone(),
            outcome,
        });
    }

    // Emit audit journal entry for this grounding check
    let all_grounded = results.iter().all(|r| r.grounded);
    let _ = connector.write_audit(
        "dehallucination_check",
        agent_id,
        namespace,
        json!({
            "claim_count":    claims.len(),
            "grounded_count": results.iter().filter(|r| r.grounded).count(),
            "all_grounded":   all_grounded,
            "chain_cid":      dehall.chain_cid,
        }),
    ).await;

    Ok((results, dehall.chain_cid))
}

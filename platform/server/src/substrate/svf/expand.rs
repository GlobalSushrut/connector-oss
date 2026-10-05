//! Purpose-bound EXPAND — progressive disclosure S0–S5 via AutonomyGateway when required.

use connector_trust::{
    BrokerDecision, BrokerDecisionCode, DisclosureLevel, DisclosureReceipt, Projection,
    BROKER_DECISION_SCHEMA, DISCLOSURE_RECEIPT_SCHEMA, PROJECTION_SCHEMA,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::kernel::action_binding::{self, ActionBinding, AutonomyVerdict};
use crate::state::SharedState;

use super::{broker_epoch, grants, now_ms, store, svf_enabled};

#[derive(Debug, Clone)]
pub struct ExpandRequest {
    pub agent_vid: String,
    pub object_id: String,
    pub level: DisclosureLevel,
    pub purpose: String,
}

#[derive(Debug, Clone)]
pub struct ExpandResult {
    pub decision: BrokerDecision,
    pub projection: Option<Projection>,
    pub receipt_id: Option<String>,
    pub grant_ceiling: DisclosureLevel,
}

/// EXPAND an object view to `level` for `purpose`. Never mints Allow for effects.
pub fn expand(state: &SharedState, req: &ExpandRequest) -> ExpandResult {
    if !svf_enabled() {
        return ExpandResult {
            decision: decision(BrokerDecisionCode::Block, "svf_disabled", Some("Set CONNECTOR_SVF=1")),
            projection: None,
            receipt_id: None,
            grant_ceiling: DisclosureLevel::S0Stub,
        };
    }

    if grants::grants_frozen(state, &req.agent_vid) {
        return ExpandResult {
            decision: decision(
                BrokerDecisionCode::Quarantine,
                "quarantine_freezes_cdp",
                Some("Human approval required — CDP/EXPAND frozen"),
            ),
            projection: None,
            receipt_id: None,
            grant_ceiling: DisclosureLevel::S0Stub,
        };
    }

    if req.level.model_plane_forbidden() {
        return ExpandResult {
            decision: decision(
                BrokerDecisionCode::ExpandDenied,
                "s5_cdp_only",
                Some("S5 materialize is CDP/ActionBroker only — not model-plane EXPAND"),
            ),
            projection: None,
            receipt_id: None,
            grant_ceiling: grants::max_granted_level(
                state,
                &req.agent_vid,
                &req.object_id,
                &req.purpose,
            ),
        };
    }

    if req.level.requires_purpose() && req.purpose.trim().is_empty() {
        return ExpandResult {
            decision: decision(
                BrokerDecisionCode::ExpandDenied,
                "purpose_required",
                Some("S2+ EXPAND requires a non-empty purpose"),
            ),
            projection: None,
            receipt_id: None,
            grant_ceiling: DisclosureLevel::S1Labels,
        };
    }

    let ceiling = grants::max_granted_level(state, &req.agent_vid, &req.object_id, &req.purpose);

    // S2+ without existing grant covering level → AutonomyGateway.
    if req.level.rank() > ceiling.rank() || req.level.requires_purpose() {
        match admit_expand(state, req) {
            Ok(AutonomyVerdict::Allow) => {
                // Mint grant at requested level (TTL 1h default).
                let _ = grants::mint_grant(
                    state,
                    &req.agent_vid,
                    &req.object_id,
                    req.level,
                    &req.purpose,
                    Some(3_600_000),
                );
            }
            Ok(AutonomyVerdict::Ask) => {
                return ExpandResult {
                    decision: decision(
                        BrokerDecisionCode::Ask,
                        "hitl_required",
                        Some("AutonomyGateway Ask — digest-bound HITL for svf.expand"),
                    ),
                    projection: None,
                    receipt_id: None,
                    grant_ceiling: ceiling,
                };
            }
            Ok(AutonomyVerdict::Block) | Err(_) => {
                return ExpandResult {
                    decision: decision(
                        BrokerDecisionCode::Block,
                        "autonomy_block",
                        Some("AutonomyGateway Block on svf.expand"),
                    ),
                    projection: None,
                    receipt_id: None,
                    grant_ceiling: ceiling,
                };
            }
        }
    }

    let ceiling = grants::max_granted_level(state, &req.agent_vid, &req.object_id, &req.purpose);
    if req.level.rank() > ceiling.rank() {
        return ExpandResult {
            decision: decision(
                BrokerDecisionCode::ExpandDenied,
                "above_grant_ceiling",
                Some(&format!(
                    "requested {} above grant ceiling {}",
                    req.level.as_str(),
                    ceiling.as_str()
                )),
            ),
            projection: None,
            receipt_id: None,
            grant_ceiling: ceiling,
        };
    }

    let view = render_view(state, &req.agent_vid, &req.object_id, req.level, &req.purpose);
    let epoch = broker_epoch(state, &req.agent_vid);
    let projection = Projection {
        schema: PROJECTION_SCHEMA.to_string(),
        object_id: req.object_id.clone(),
        level: req.level,
        view_text: view,
        broker_epoch: epoch,
        purpose: Some(req.purpose.clone()),
    };

    let receipt_id = record_expand_disclosure(state, req, &projection);

    ExpandResult {
        decision: decision(BrokerDecisionCode::Allow, "expanded", None),
        projection: Some(projection),
        receipt_id: Some(receipt_id),
        grant_ceiling: ceiling,
    }
}

fn admit_expand(state: &SharedState, req: &ExpandRequest) -> Result<AutonomyVerdict, Value> {
    let params = json!({
        "object_id": req.object_id,
        "level": req.level.as_str(),
        "purpose": req.purpose,
        "broker_epoch": broker_epoch(state, &req.agent_vid),
    });
    let binding = ActionBinding::new(
        req.agent_vid.clone(),
        "svf.expand",
        "svf.expand",
        format!("svf:{}", req.object_id),
        params,
        None,
        "svf.v1",
        None,
    );
    let risk = action_binding::infer_risk_class("svf.expand", "svf.expand");
    let decision = action_binding::autonomy_decide(state.as_ref(), &binding, risk);
    action_binding::record_gateway_verdict(decision.verdict.clone());
    Ok(decision.verdict)
}

fn render_view(
    state: &SharedState,
    agent_vid: &str,
    object_id: &str,
    level: DisclosureLevel,
    purpose: &str,
) -> String {
    let obj = store::get_object(state, agent_vid, object_id);
    match level {
        DisclosureLevel::S0Stub => format!(
            "stub object_id={object_id} type={}",
            obj.as_ref()
                .map(|o| o.object_type.as_str())
                .unwrap_or("unknown")
        ),
        DisclosureLevel::S1Labels => obj
            .map(|o| {
                format!(
                    "labels object_id={} type={} handle={}",
                    o.object_id, o.object_type, o.handle.handle
                )
            })
            .unwrap_or_else(|| format!("labels object_id={object_id} (not in store)")),
        DisclosureLevel::S2Schema => obj
            .map(|o| {
                format!(
                    "schema object_id={} type={} fragments={} knot={:?} mem_cid={:?} purpose={purpose}",
                    o.object_id,
                    o.object_type,
                    o.manifest.fragments.len(),
                    o.knot_node_id,
                    o.mem_packet_cid
                )
            })
            .unwrap_or_else(|| format!("schema object_id={object_id} purpose={purpose}")),
        DisclosureLevel::S3Partial => {
            let base = render_view(state, agent_vid, object_id, DisclosureLevel::S2Schema, purpose);
            // Partial: include first fragment digest only (no raw payload).
            let frag = obj
                .and_then(|o| o.manifest.fragments.first().cloned())
                .map(|f| format!(" fragment_digest={}", f.content_digest))
                .unwrap_or_default();
            format!("{base}{frag} (partial)")
        }
        DisclosureLevel::S4FullLogical => {
            let base = render_view(state, agent_vid, object_id, DisclosureLevel::S3Partial, purpose);
            format!("{base} full_logical=true secrets=never")
        }
        DisclosureLevel::S5Materialize => "FORBIDDEN_ON_MODEL_PLANE".into(),
    }
}

fn record_expand_disclosure(
    state: &SharedState,
    req: &ExpandRequest,
    projection: &Projection,
) -> String {
    let digest = format!(
        "{:x}",
        Sha256::digest(
            format!(
                "{}:{}:{}:{}",
                req.agent_vid, req.object_id, req.level.as_str(), projection.broker_epoch
            )
            .as_bytes()
        )
    );
    let receipt_id = format!("dr-exp-{}", &digest[..16.min(digest.len())]);
    let receipt = DisclosureReceipt {
        schema: DISCLOSURE_RECEIPT_SCHEMA.to_string(),
        receipt_id: receipt_id.clone(),
        agent_vid: req.agent_vid.clone(),
        object_refs: vec![req.object_id.clone()],
        level: req.level,
        sink: "svf.expand.model".to_string(),
        purpose: req.purpose.clone(),
        broker_epoch: projection.broker_epoch,
        issued_at_ms: now_ms(),
        pate_task_id: None,
        action_digest: None,
    };
    if let Ok(v) = serde_json::to_value(&receipt) {
        store::put_json(
            state,
            store::RECEIPT_FOLDER,
            &format!("{}:{}", req.agent_vid, receipt_id),
            &v,
        );
    }
    receipt_id
}

fn decision(code: BrokerDecisionCode, message: &str, denial: Option<&str>) -> BrokerDecision {
    BrokerDecision {
        schema: BROKER_DECISION_SCHEMA.to_string(),
        code,
        message: message.to_string(),
        denial_reason: denial.map(|s| s.to_string()),
        redo_hints: None,
    }
}

pub fn expand_result_json(r: &ExpandResult) -> Value {
    json!({
        "schema": "connector.svf.expand_result.v1",
        "decision": r.decision,
        "projection": r.projection,
        "receipt_id": r.receipt_id,
        "grant_ceiling": r.grant_ceiling.as_str(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s5_forbidden_on_model() {
        assert!(DisclosureLevel::S5Materialize.model_plane_forbidden());
        assert!(!DisclosureLevel::S4FullLogical.model_plane_forbidden());
    }
}

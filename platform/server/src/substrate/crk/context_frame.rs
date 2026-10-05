//! ContextFrame compilation — usable form for Plan / optional Talk.

use connector_trust::{
    ContextFrame, ContextFrameKind, CrkState, MomentRange, RenderPolicy, TrustTier,
    VerifiedProcedureCapsule, CONTEXT_FRAME_SCHEMA,
};

use crate::state::PlatformState;

use super::digest_hex;
use super::temporal_ledger;

const MAX_FRAME_BYTES: usize = 8_192;
const MAX_PAYLOAD_CHARS: usize = 4_000;

/// Compile MomentRange into hydrated frames (claim values, not bare CIDs).
pub fn from_moment_range(
    state: &PlatformState,
    range: &MomentRange,
    procedure: Option<&VerifiedProcedureCapsule>,
) -> Vec<ContextFrame> {
    let mut frames = Vec::new();
    for (i, cid) in range.context_cids.iter().enumerate() {
        if let Some(frame) = hydrate_claim_frame(state, range, cid, i as u32) {
            frames.push(frame);
        } else {
            // Unresolved CID — reference-only stub (still influence-bound).
            frames.push(ContextFrame {
                schema: CONTEXT_FRAME_SCHEMA.into(),
                frame_id: format!("frm_{}_{}", range.moment_range_id, i),
                kind: ContextFrameKind::Evidence,
                canonical_cids: vec![cid.clone()],
                content_digest: digest_hex(cid.as_bytes()),
                provenance_root: range.moment_range_id.clone(),
                valid_at_ms: Some(range.created_at_ms),
                trust_floor: TrustTier::T1Observed,
                skill_scope: range.bound_skill.clone(),
                priority: (i as u32) + 10,
                dependency_ids: vec![],
                token_cost: 32,
                machine_payload: serde_json::json!({ "cid": cid, "hydrated": false }),
                render_policy: RenderPolicy::Reference,
            });
        }
    }
    if let Some(p) = procedure {
        let steps_payload = serde_json::json!({
            "procedure_id": p.procedure_id,
            "version": p.procedure_version,
            "skill_id": p.skill_id,
            "steps": p.steps,
            "preconditions": p.preconditions,
            "exit_conditions": p.exit_conditions,
        });
        let digest = digest_hex(serde_json::to_vec(&steps_payload).unwrap_or_default().as_slice());
        frames.push(ContextFrame {
            schema: CONTEXT_FRAME_SCHEMA.into(),
            frame_id: format!("frm_proc_{}", p.procedure_id),
            kind: ContextFrameKind::Procedure,
            canonical_cids: vec![p.procedure_id.clone()],
            content_digest: digest,
            provenance_root: p.envelope.lineage_digest.clone(),
            valid_at_ms: Some(range.created_at_ms),
            trust_floor: p.envelope.origin_authority,
            skill_scope: Some(p.skill_id.clone()),
            priority: 0,
            dependency_ids: vec![],
            token_cost: estimate_tokens(&steps_payload),
            machine_payload: steps_payload,
            render_policy: RenderPolicy::Full,
        });
    }
    if matches!(range.state, CrkState::Ambiguous) && !range.unresolved_conflicts.is_empty() {
        let payload = serde_json::json!({ "conflicts": range.unresolved_conflicts });
        frames.push(ContextFrame {
            schema: CONTEXT_FRAME_SCHEMA.into(),
            frame_id: format!("frm_conflict_{}", range.moment_range_id),
            kind: ContextFrameKind::Conflict,
            canonical_cids: range.unresolved_conflicts.clone(),
            content_digest: digest_hex(serde_json::to_vec(&payload).unwrap_or_default().as_slice()),
            provenance_root: range.moment_range_id.clone(),
            valid_at_ms: Some(range.created_at_ms),
            trust_floor: TrustTier::T1Observed,
            skill_scope: range.bound_skill.clone(),
            priority: 1,
            dependency_ids: vec![],
            token_cost: 48,
            machine_payload: payload,
            render_policy: RenderPolicy::Compact,
        });
    }
    frames.sort_by_key(|f| f.priority);
    let drops: Vec<serde_json::Value> = frames
        .iter()
        .filter_map(|frame| {
            unusable_reason(frame).map(|reason| {
                serde_json::json!({
                    "schema": "connector.frame_drop.v1",
                    "agent_pid": range.agent_pid,
                    "moment_range_id": range.moment_range_id,
                    "frame_id": frame.frame_id,
                    "reason": reason,
                })
            })
        })
        .collect();
    if !drops.is_empty() {
        crate::services::workspace_records::persist_frame_drops(state, &range.agent_pid, &range.moment_range_id, &drops);
    }
    reject_unusable(frames)
}

pub fn unusable_reason(frame: &ContextFrame) -> Option<&'static str> {
    if matches!(frame.render_policy, RenderPolicy::Omit) {
        return Some("render_omit");
    }
    if frame.canonical_cids.is_empty() {
        return Some("empty_cids");
    }
    if frame.content_digest.is_empty() {
        return Some("empty_digest");
    }
    if frame.machine_payload.to_string().len() > MAX_PAYLOAD_CHARS {
        return Some("oversized");
    }
    None
}

fn hydrate_claim_frame(
    state: &PlatformState,
    range: &MomentRange,
    cid: &str,
    index: u32,
) -> Option<ContextFrame> {
    let claim = temporal_ledger::load_claim(state, &range.agent_pid, cid)?;
    let payload = serde_json::json!({
        "claim_id": claim.claim_id,
        "subject": claim.subject,
        "predicate": claim.predicate,
        "value": claim.value,
        "valid_from_ms": claim.valid_from_ms,
        "valid_until_ms": claim.valid_until_ms,
        "source": claim.source,
        "confidence": claim.confidence,
        "trust": claim.envelope.origin_authority.as_str(),
        "evidence_cids": claim.evidence_cids,
        "active": claim.active,
    });
    let raw = serde_json::to_vec(&payload).unwrap_or_default();
    if raw.len() > MAX_FRAME_BYTES {
        return None;
    }
    Some(ContextFrame {
        schema: CONTEXT_FRAME_SCHEMA.into(),
        frame_id: format!("frm_{}_{}", range.moment_range_id, index),
        kind: ContextFrameKind::State,
        canonical_cids: vec![cid.to_string()],
        content_digest: digest_hex(&raw),
        provenance_root: claim.envelope.lineage_digest,
        valid_at_ms: Some(claim.valid_from_ms),
        trust_floor: claim.envelope.origin_authority,
        skill_scope: range.bound_skill.clone(),
        priority: index + 1,
        dependency_ids: claim.evidence_cids,
        token_cost: estimate_tokens(&payload),
        machine_payload: payload,
        render_policy: RenderPolicy::Compact,
    })
}

fn estimate_tokens(v: &serde_json::Value) -> u32 {
    let n = v.to_string().len() as u32;
    (n / 4).max(16).min(512)
}

/// Drop empty / oversized / non-renderable frames.
pub fn reject_unusable(frames: Vec<ContextFrame>) -> Vec<ContextFrame> {
    frames
        .into_iter()
        .filter(|frame| unusable_reason(frame).is_none())
        .collect()
}

/// Deterministic degradation when over budget.
pub fn fit_budget(frames: &mut Vec<ContextFrame>, token_budget: u64) {
    let mut used: u64 = frames.iter().map(|f| f.token_cost as u64).sum();
    if used <= token_budget {
        return;
    }
    let mut order: Vec<usize> = (0..frames.len()).collect();
    order.sort_by_key(|&i| std::cmp::Reverse(frames[i].priority));
    for i in order {
        if used <= token_budget {
            break;
        }
        match frames[i].render_policy {
            RenderPolicy::Full => {
                frames[i].render_policy = RenderPolicy::Compact;
                used = used.saturating_sub(frames[i].token_cost as u64 / 2);
                frames[i].token_cost = frames[i].token_cost.max(1) / 2;
            }
            RenderPolicy::Compact => {
                frames[i].render_policy = RenderPolicy::Reference;
                used = used.saturating_sub(frames[i].token_cost as u64 / 2);
                frames[i].token_cost = frames[i].token_cost.max(1) / 2;
            }
            RenderPolicy::Reference => {
                frames[i].render_policy = RenderPolicy::Omit;
                used = used.saturating_sub(frames[i].token_cost as u64);
                frames[i].token_cost = 0;
            }
            RenderPolicy::Omit => {}
        }
    }
    *frames = reject_unusable(std::mem::take(frames));
}

#[cfg(test)]
mod tests {
    use super::*;
    use connector_trust::{ACTION_CUE_SCHEMA, MOMENT_RANGE_SCHEMA};

    fn empty_range() -> MomentRange {
        MomentRange {
            schema: MOMENT_RANGE_SCHEMA.into(),
            moment_range_id: "mr_test".into(),
            agent_pid: "a".into(),
            action_digest: "act".into(),
            phase: "recall".into(),
            bound_skill: None,
            context_cids: vec![],
            range_generation: 1,
            token_budget: 100,
            state: CrkState::Ready,
            unresolved_conflicts: vec![],
            procedure_id: None,
            created_at_ms: 0,
        }
    }

    #[test]
    fn reject_drops_omit_and_empty() {
        let mut frames = vec![ContextFrame {
            schema: CONTEXT_FRAME_SCHEMA.into(),
            frame_id: "f1".into(),
            kind: ContextFrameKind::State,
            canonical_cids: vec![],
            content_digest: "x".into(),
            provenance_root: "p".into(),
            valid_at_ms: None,
            trust_floor: TrustTier::T1Observed,
            skill_scope: None,
            priority: 1,
            dependency_ids: vec![],
            token_cost: 10,
            machine_payload: serde_json::json!({}),
            render_policy: RenderPolicy::Compact,
        }];
        frames = reject_unusable(frames);
        assert!(frames.is_empty());
        let _ = ACTION_CUE_SCHEMA;
        let _ = empty_range();
    }

    #[test]
    fn fit_budget_omits_lowest_priority() {
        let mut frames = vec![
            ContextFrame {
                schema: CONTEXT_FRAME_SCHEMA.into(),
                frame_id: "hi".into(),
                kind: ContextFrameKind::Procedure,
                canonical_cids: vec!["p".into()],
                content_digest: "d".into(),
                provenance_root: "r".into(),
                valid_at_ms: None,
                trust_floor: TrustTier::T4OperatorVerified,
                skill_scope: None,
                priority: 0,
                dependency_ids: vec![],
                token_cost: 80,
                machine_payload: serde_json::json!({"k":"v"}),
                render_policy: RenderPolicy::Full,
            },
            ContextFrame {
                schema: CONTEXT_FRAME_SCHEMA.into(),
                frame_id: "lo".into(),
                kind: ContextFrameKind::State,
                canonical_cids: vec!["c".into()],
                content_digest: "d2".into(),
                provenance_root: "r".into(),
                valid_at_ms: None,
                trust_floor: TrustTier::T1Observed,
                skill_scope: None,
                priority: 9,
                dependency_ids: vec![],
                token_cost: 80,
                machine_payload: serde_json::json!({"k":"noise"}),
                render_policy: RenderPolicy::Full,
            },
        ];
        fit_budget(&mut frames, 90);
        assert!(frames.iter().any(|f| f.frame_id == "hi"));
        assert!(!frames.iter().any(|f| f.frame_id == "lo" && matches!(f.render_policy, RenderPolicy::Full)));
    }
}

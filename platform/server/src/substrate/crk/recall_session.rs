//! Pinned RecallSession — active, bounded retrieval (not one-shot top-k).

use connector_trust::{ActionCueEnvelope, RecallSession, RECALL_SESSION_SCHEMA};

use crate::state::PlatformState;

use super::memory_commit;
use super::{digest_hex, now_ms};

pub fn begin(state: &PlatformState, cue: &ActionCueEnvelope) -> RecallSession {
    let root = memory_commit::current_root(state, &cue.agent_pid)
        .unwrap_or_else(|| format!("genesis:{}", cue.agent_pid));
    let cue_digest = digest_hex(
        format!(
            "{}|{}|{}|{}",
            cue.agent_pid,
            cue.action_digest,
            cue.phase,
            cue.bound_skill.as_deref().unwrap_or("")
        )
        .as_bytes(),
    );
    RecallSession {
        schema: RECALL_SESSION_SCHEMA.into(),
        session_id: format!("rs_{}", &cue_digest[..16]),
        agent_pid: cue.agent_pid.clone(),
        cue_digest,
        pinned_memory_root: root,
        pinned_read_set_epoch: cue.generation,
        query_plan: vec![
            "hard_eligibility".into(),
            "exact_state".into(),
            "causal_expand".into(),
            "sufficiency".into(),
        ],
        visited_node_ids: vec![],
        candidate_cids: vec![],
        exclusion_reasons: vec![],
        remaining_budget: cue.token_budget,
        round: 0,
    }
}

pub fn record_round(
    session: &mut RecallSession,
    candidates: Vec<String>,
    exclusions: Vec<String>,
) {
    session.round = session.round.saturating_add(1);
    for c in &candidates {
        if !session.visited_node_ids.contains(c) {
            session.visited_node_ids.push(c.clone());
        }
    }
    session.candidate_cids = candidates;
    session.exclusion_reasons = exclusions;
    let used = session.candidate_cids.len() as u64 * 64;
    session.remaining_budget = session.remaining_budget.saturating_sub(used);
    let _ = now_ms();
}

/// Fail closed if memory root drifted under the pin (mixed visibility).
pub fn assert_pinned_root(state: &PlatformState, session: &RecallSession) -> Result<(), String> {
    let live = memory_commit::current_root(state, &session.agent_pid)
        .unwrap_or_else(|| format!("genesis:{}", session.agent_pid));
    if live != session.pinned_memory_root {
        return Err(format!(
            "recall_pin_broken: pinned={} live={}",
            session.pinned_memory_root, live
        ));
    }
    Ok(())
}

/// Refine: expand candidates under the same pin; refuse if root moved.
pub fn refine(
    state: &PlatformState,
    session: &mut RecallSession,
    extra_candidates: Vec<String>,
    extra_exclusions: Vec<String>,
) -> Result<(), String> {
    assert_pinned_root(state, session)?;
    if session.remaining_budget == 0 {
        return Err("recall_budget_exhausted".into());
    }
    let mut merged = session.candidate_cids.clone();
    for c in extra_candidates {
        if !merged.contains(&c) {
            merged.push(c);
        }
    }
    let mut excl = session.exclusion_reasons.clone();
    excl.extend(extra_exclusions);
    record_round(session, merged, excl);
    Ok(())
}

/// Tail-completeness: every selected CID was visited; exclusions recorded.
pub fn completeness_ok(session: &RecallSession) -> bool {
    if session.round == 0 {
        return false;
    }
    session
        .candidate_cids
        .iter()
        .all(|c| session.visited_node_ids.contains(c))
}

/// Repeat-stability: same cue digests to same session_id + pin.
pub fn stable_with(a: &RecallSession, b: &RecallSession) -> bool {
    a.cue_digest == b.cue_digest
        && a.session_id == b.session_id
        && a.pinned_memory_root == b.pinned_memory_root
}

#[cfg(test)]
mod tests {
    use super::*;
    use connector_trust::ACTION_CUE_SCHEMA;

    fn session(root: &str) -> RecallSession {
        RecallSession {
            schema: RECALL_SESSION_SCHEMA.into(),
            session_id: "rs_abc".into(),
            agent_pid: "agent:t".into(),
            cue_digest: "cue".into(),
            pinned_memory_root: root.into(),
            pinned_read_set_epoch: 1,
            query_plan: vec![],
            visited_node_ids: vec![],
            candidate_cids: vec![],
            exclusion_reasons: vec![],
            remaining_budget: 1024,
            round: 0,
        }
    }

    #[test]
    fn completeness_requires_visit() {
        let mut s = session("root:1");
        record_round(&mut s, vec!["c1".into(), "c2".into()], vec![]);
        assert!(completeness_ok(&s));
        s.visited_node_ids.pop();
        assert!(!completeness_ok(&s));
        let _ = ACTION_CUE_SCHEMA;
    }

    #[test]
    fn stable_sessions_match() {
        let a = session("root:1");
        let b = session("root:1");
        assert!(stable_with(&a, &b));
        let c = session("root:2");
        assert!(!stable_with(&a, &c));
    }
}

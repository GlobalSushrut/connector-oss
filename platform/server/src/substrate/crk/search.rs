//! Paginated dynamic search under pinned RecallSession (cold path).

use serde_json::{json, Value};

use crate::state::SharedState;

use super::{
    activation, cover, cue_from, eligibility, memory_commit, procedure_capsule, recall_session,
};

#[derive(Debug, Clone)]
pub struct SearchPage {
    pub session_id: String,
    pub pinned_memory_root: String,
    pub page: Vec<Value>,
    pub next_cursor: Option<String>,
    pub round: u32,
}

pub fn search(
    state: &SharedState,
    agent_pid: &str,
    action_digest: &str,
    bound_skill: Option<&str>,
    risk: &str,
    page_size: usize,
    cursor: Option<&str>,
    session_id: Option<&str>,
) -> Result<SearchPage, String> {
    let generation =
        crate::substrate::llm_context_broker::current_generation(state, agent_pid);
    let cue = cue_from(
        agent_pid,
        generation,
        bound_skill,
        "search",
        action_digest,
        risk,
        2048,
        32,
    );
    let mut session = recall_session::begin(state.as_ref(), &cue);
    if let Some(sid) = session_id {
        session.session_id = sid.to_string();
    }
    recall_session::assert_pinned_root(state.as_ref(), &session)?;

    let eligible = eligibility::filter_candidates(state.as_ref(), &cue)?;
    let procedure =
        procedure_capsule::select_for_skill(state.as_ref(), agent_pid, bound_skill);
    let root = memory_commit::current_root(state.as_ref(), agent_pid)
        .unwrap_or_else(|| format!("genesis:{agent_pid}"));
    let dna = activation::activate_dynamic(
        state.as_ref(),
        &cue,
        &eligible,
        procedure.as_ref(),
        &[],
        &root,
    );
    let (selected, excl, _) = cover::budget_cover(&cue, &dna);
    recall_session::record_round(&mut session, selected, excl);

    let mut ranked = dna.field.clone();
    ranked.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.cid.cmp(&b.cid))
    });

    let offset: usize = cursor
        .and_then(|c| c.strip_prefix("cur_"))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let size = page_size.clamp(1, 64);
    let total = ranked.len();
    let slice: Vec<_> = ranked.into_iter().skip(offset).take(size).collect();
    let next = if offset + size < total {
        Some(format!("cur_{}", offset + size))
    } else {
        None
    };

    let page: Vec<Value> = slice
        .iter()
        .map(|n| {
            json!({
                "cid": n.cid,
                "type_dna": n.type_dna.as_str(),
                "activation": n.activation,
                "score": n.score,
                "hops": n.hops,
                "exclusion": n.exclusion,
            })
        })
        .collect();

    Ok(SearchPage {
        session_id: session.session_id,
        pinned_memory_root: session.pinned_memory_root,
        page,
        next_cursor: next,
        round: session.round,
    })
}

//! Per-agent LLM broker sandbox — one shared model, N isolated agent slots.
//!
//! Same LLM provider may power 100+ agents. Each agent gets a **sandbox slot**
//! bound to identity / character / knowledge / generation. Cross-slot seals,
//! tokens, or VAC CIDs → HTTP 499 (cannot bypass). After human approval the
//! slot is reopened on a **new** epoch and talk returns to normal 200.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::error::ConnectorError;
use crate::state::SharedState;
use crate::substrate::agentic_context::AgenticContext;

pub const SCHEMA: &str = "connector.llm_agent_sandbox.v1";
const FOLDER: &str = "llm_agent_sandbox_v1";

fn sha(s: &str) -> String {
    format!("{:x}", Sha256::digest(s.as_bytes()))
}

#[derive(Debug, Clone)]
pub struct AgentSandboxSlot {
    pub sandbox_id: String,
    pub agent_pid: String,
    pub generation: u64,
    pub principal_hash: String,
    pub character_hash: String,
    pub knowledge_hash: String,
    pub identity_hash: String,
    pub open: bool,
}

impl AgentSandboxSlot {
    pub fn to_json(&self) -> Value {
        json!({
            "schema": SCHEMA,
            "sandbox_id": self.sandbox_id,
            "agent_pid": self.agent_pid,
            "generation": self.generation,
            "principal_hash": self.principal_hash,
            "character_hash": self.character_hash,
            "knowledge_hash": self.knowledge_hash,
            "identity_hash": self.identity_hash,
            "open": self.open,
        })
    }

    fn from_json(v: &Value) -> Option<Self> {
        Some(Self {
            sandbox_id: v.get("sandbox_id")?.as_str()?.to_string(),
            agent_pid: v.get("agent_pid")?.as_str()?.to_string(),
            generation: v.get("generation")?.as_u64()?,
            principal_hash: v.get("principal_hash")?.as_str()?.to_string(),
            character_hash: v.get("character_hash")?.as_str()?.to_string(),
            knowledge_hash: v.get("knowledge_hash")?.as_str()?.to_string(),
            identity_hash: v.get("identity_hash")?.as_str()?.to_string(),
            open: v.get("open")?.as_bool()?,
        })
    }
}

fn fingerprints(state: &SharedState, agent_pid: &str, ctx: &AgenticContext) -> (String, String, String, String) {
    let principal = ctx
        .principal_id
        .clone()
        .unwrap_or_else(|| format!("pending:{agent_pid}"));
    let character = format!(
        "{}|{}",
        ctx.character_name.as_deref().unwrap_or(""),
        ctx.character_purpose.as_deref().unwrap_or("")
    );
    let knowledge = format!(
        "{}|{}",
        ctx.knowledge_capabilities.join(","),
        ctx.denied_operations.join(",")
    );
    let identity = ctx
        .who_am_i
        .clone()
        .or_else(|| {
            crate::kernel::agent_foundation::who_am_i_authoritative(state.as_ref(), agent_pid)
        })
        .unwrap_or_else(|| format!("pending-who:{agent_pid}"));
    (
        sha(&principal),
        sha(&character),
        sha(&knowledge),
        sha(&identity),
    )
}

/// Open or refresh the per-agent sandbox slot (after admission / human approval).
pub fn open_slot(
    state: &SharedState,
    agent_pid: &str,
    ctx: &AgenticContext,
) -> Result<AgentSandboxSlot, ConnectorError> {
    if crate::substrate::llm_sealed_context::agent_brain_quarantined(state, agent_pid) {
        return Err(ConnectorError::llm_quarantined_need_approval(
            agent_pid,
            "sandbox_closed",
            "agent sandbox closed until human approval",
        ));
    }
    let generation = crate::substrate::llm_context_broker::current_generation(state, agent_pid);
    let (principal_hash, character_hash, knowledge_hash, identity_hash) =
        fingerprints(state, agent_pid, ctx);
    let sandbox_id = format!(
        "sbx_{}",
        &sha(&format!("{agent_pid}|{generation}|{identity_hash}"))[..24]
    );
    let slot = AgentSandboxSlot {
        sandbox_id: sandbox_id.clone(),
        agent_pid: agent_pid.to_string(),
        generation,
        principal_hash,
        character_hash,
        knowledge_hash,
        identity_hash,
        open: true,
    };
    // Bind Linux-visible cgroup/nsfs so the slot is kernel-attributable (like SO_MARK).
    let linux = crate::kernel::agent_cgroup::bind_agent_process_tree(
        state.as_ref(),
        agent_pid,
        ctx.principal_id.as_deref().unwrap_or(agent_pid),
    )
    .unwrap_or_else(|e| json!({ "cgroup_bind_error": e }));
    if let Ok(mut es) = state.engine_store.lock() {
        let mut body = slot.to_json();
        if let Some(obj) = body.as_object_mut() {
            obj.insert("linux_bind".into(), linux);
            obj.insert(
                "egress_mark".into(),
                json!(format!(
                    "0x{:08x}",
                    crate::kernel::matrix_host_egress::intelligence_egress_mark(agent_pid)
                )),
            );
        }
        let _ = es.folder_put(FOLDER, agent_pid, &body);
        let _ = es.folder_put(
            FOLDER,
            &format!("by_sandbox:{sandbox_id}"),
            &json!({ "agent_pid": agent_pid, "generation": generation }),
        );
    }
    Ok(slot)
}

pub fn load_slot(state: &SharedState, agent_pid: &str) -> Option<AgentSandboxSlot> {
    let es = state.engine_store.lock().ok()?;
    let v = es.folder_get(FOLDER, agent_pid).ok().flatten()?;
    AgentSandboxSlot::from_json(&v)
}

/// Close slot on quarantine — same LLM may keep other agents' slots open.
pub fn close_slot(state: &SharedState, agent_pid: &str, reason: &str) {
    if let Ok(mut es) = state.engine_store.lock() {
        let mut slot = es
            .folder_get(FOLDER, agent_pid)
            .ok()
            .flatten()
            .unwrap_or_else(|| json!({"agent_pid": agent_pid}));
        if let Some(obj) = slot.as_object_mut() {
            obj.insert("open".into(), json!(false));
            obj.insert("closed_reason".into(), json!(reason));
            obj.insert(
                "closed_at_ms".into(),
                json!(chrono::Utc::now().timestamp_millis()),
            );
        }
        let _ = es.folder_put(FOLDER, agent_pid, &slot);
    }
}

/// Fail-closed: live slot must match this agent's identity/character/knowledge epoch.
pub fn assert_slot_live(
    state: &SharedState,
    agent_pid: &str,
) -> Result<AgentSandboxSlot, ConnectorError> {
    let Some(slot) = load_slot(state, agent_pid) else {
        return Err(ConnectorError::llm_not_allowed(
            "agent_sandbox",
            "no open broker sandbox slot — talk must open a per-agent slot first",
        ));
    };
    if !slot.open {
        return Err(ConnectorError::llm_quarantined_need_approval(
            agent_pid,
            "sandbox_closed",
            "sandbox closed — need human approval to reopen",
        ));
    }
    let live_gen = crate::substrate::llm_context_broker::current_generation(state, agent_pid);
    if slot.generation != live_gen {
        return Err(ConnectorError::llm_not_allowed(
            "agent_sandbox_epoch",
            format!(
                "sandbox generation {} != live {} — redo under current agent context",
                slot.generation, live_gen
            ),
        ));
    }
    if crate::substrate::llm_sealed_context::agent_brain_quarantined(state, agent_pid) {
        return Err(ConnectorError::llm_quarantined_need_approval(
            agent_pid,
            "brain_quarantined",
            "LLM brain quarantined for this agent slot",
        ));
    }
    // Re-check fingerprints against live kernel (drift → 499, not silent continue).
    let ctx = crate::substrate::agentic_context::build_for_shared(state, agent_pid);
    let (p, c, k, i) = fingerprints(state, agent_pid, &ctx);
    if p != slot.principal_hash
        || c != slot.character_hash
        || k != slot.knowledge_hash
        || i != slot.identity_hash
    {
        return Err(ConnectorError::llm_not_allowed(
            "agent_sandbox_identity_drift",
            "identity/character/knowledge drifted vs sandbox slot — redo after re-bind",
        ));
    }
    Ok(slot)
}

/// Refuse using another agent's sandbox id / seal namespace (cross-agent bypass).
pub fn assert_no_cross_agent(
    state: &SharedState,
    agent_pid: &str,
    referenced_sandbox_id: Option<&str>,
) -> Result<(), ConnectorError> {
    let Some(sid) = referenced_sandbox_id.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(());
    };
    let Ok(es) = state.engine_store.lock() else {
        return Err(ConnectorError::llm_not_allowed(
            "agent_sandbox",
            "sandbox store unavailable",
        ));
    };
    if let Some(owner) = es
        .folder_get(FOLDER, &format!("by_sandbox:{sid}"))
        .ok()
        .flatten()
    {
        let owner_pid = owner
            .get("agent_pid")
            .and_then(|x| x.as_str())
            .unwrap_or("");
        if owner_pid != agent_pid {
            return Err(ConnectorError::llm_quarantined_need_approval(
                agent_pid,
                "cross_agent_sandbox",
                format!("attempted to use sandbox {sid} owned by {owner_pid}"),
            ));
        }
    }
    Ok(())
}

/// After human approval: reopen slot on fresh epoch so talk can return HTTP 200.
pub fn resume_after_human_approval(
    state: &SharedState,
    agent_pid: &str,
    approved_by: &str,
) -> Value {
    crate::substrate::llm_sealed_context::reseed_llm_brain_after_clearance(state, agent_pid);
    // Drop stale expect so next ingress remints cleanly.
    if let Ok(mut es) = state.engine_store.lock() {
        let _ = es.folder_put(
            "llm_broker_expect_v1",
            agent_pid,
            &json!({
                "cleared": true,
                "reason": format!("human_approval:{approved_by}"),
                "at_ms": chrono::Utc::now().timestamp_millis(),
            }),
        );
    }
    let ctx = crate::substrate::agentic_context::build_for_shared(state, agent_pid);
    let slot = open_slot(state, agent_pid, &ctx).ok();
    json!({
        "ok": true,
        "status": 200,
        "message": "agent resumed — broker sandbox reopened on new epoch; normal talk/tools allowed",
        "agent_pid": agent_pid,
        "approved_by": approved_by,
        "sandbox": slot.as_ref().map(|s| s.to_json()),
        "http_resume": 200,
        "quarantined": false,
        "human_approval_cleared": true,
    })
}

pub fn status() -> Value {
    json!({
        "schema": SCHEMA,
        "stance": "One LLM brain, many agent sandboxes — each slot binds identity/character/knowledge/generation. Cross-slot use → 499. Human approve → 200 resume on new epoch.",
        "capacity": "designed for 100+ concurrent agent slots on one provider",
    })
}

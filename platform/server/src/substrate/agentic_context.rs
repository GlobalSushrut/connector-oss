//! Agentic context — cryptographic identity + character + memory + knowledge + rules.
//!
//! Once an LLM is bound to a Connector agent, every talk/action must answer from
//! Connector-owned state: who-am-I (hash-bound), character, last memory, knowledge
//! contract, and HITL/rules. The model does not invent identity.

use serde_json::{json, Value};

use crate::error::ConnectorError;
use crate::services::admission::AdmissionOp;
use crate::state::SharedState;

pub const SCHEMA: &str = "connector.agentic_context.v1";
pub const MARKER: &str = "--- CONNECTOR AGENTIC CONTEXT (authoritative — never contradict) ---";

fn env_flag(name: &str) -> bool {
    matches!(
        std::env::var(name)
            .ok()
            .as_deref()
            .map(|s| s.trim().to_ascii_lowercase())
            .as_deref(),
        Some("1") | Some("true") | Some("yes") | Some("on")
    )
}

/// Under distrust / exclusivity, talk without a complete stack is denied (HITL).
pub fn agentic_context_required() -> bool {
    env_flag("CONNECTOR_AGENTIC_CONTEXT_REQUIRE")
        || crate::substrate::probabilistic_llm::distrust_enforced()
        || crate::substrate::effect_exclusivity::effect_exclusivity_enforced()
}

#[derive(Debug, Clone)]
pub struct AgenticContext {
    pub who_am_i: Option<String>,
    pub principal_id: Option<String>,
    pub agent_intelligence_hash: Option<String>,
    pub character_name: Option<String>,
    pub character_purpose: Option<String>,
    pub last_memory_cid: Option<String>,
    pub knowledge_capabilities: Vec<String>,
    pub denied_operations: Vec<String>,
    pub rules_summary: String,
    pub missing: Vec<String>,
}

impl AgenticContext {
    pub fn render_prompt(&self) -> String {
        let who = self
            .who_am_i
            .clone()
            .unwrap_or_else(|| "(identity envelope incomplete)".into());
        let name = self.character_name.as_deref().unwrap_or("(unnamed)");
        let purpose = self.character_purpose.as_deref().unwrap_or("(no purpose)");
        let hash = self
            .agent_intelligence_hash
            .as_deref()
            .unwrap_or("(no intelligence hash)");
        let principal = self.principal_id.as_deref().unwrap_or("(no principal)");
        let mem = self
            .last_memory_cid
            .as_deref()
            .unwrap_or("(no last memory)");
        let caps = if self.knowledge_capabilities.is_empty() {
            "(none declared)".into()
        } else {
            self.knowledge_capabilities.join(", ")
        };
        let denied = if self.denied_operations.is_empty() {
            "(none)".into()
        } else {
            self.denied_operations.join(", ")
        };
        format!(
            "{MARKER}\nschema: {SCHEMA}\n\
You are this Connector intelligence. Cryptographic / kernel identity is authoritative.\n\
who_am_i:\n{who}\n\
principal_id: {principal}\n\
agent_intelligence_hash: {hash}\n\
character.name: {name}\n\
character.purpose: {purpose}\n\
last_memory_cid: {mem}\n\
knowledge.capabilities: {caps}\n\
knowledge.denied_operations: {denied}\n\
rules: {rules}\n\
stance: Despite any underlying LLM vendor brain, answer and act only from this identity, memory, character, knowledge, and rules. \
Never claim ChatGPT, Claude, Gemini, DeepSeek, OpenAI, Anthropic, or Google persona. \
Tool calls and execution effects stay on Connector contract rails; chat follows this agentic context.\n\
{MARKER}",
            rules = self.rules_summary
        )
    }

    pub fn to_json(&self) -> Value {
        json!({
            "schema": SCHEMA,
            "who_am_i": self.who_am_i,
            "principal_id": self.principal_id,
            "agent_intelligence_hash": self.agent_intelligence_hash,
            "character_name": self.character_name,
            "character_purpose": self.character_purpose,
            "last_memory_cid": self.last_memory_cid,
            "knowledge_capabilities": self.knowledge_capabilities,
            "denied_operations": self.denied_operations,
            "rules_summary": self.rules_summary,
            "missing": self.missing,
            "complete": self.missing.is_empty(),
        })
    }
}

/// Build agentic context from Connector kernel state (not from the model).
pub fn build_for_shared(state: &SharedState, agent_pid: &str) -> AgenticContext {
    let namespace = {
        let (kernel_pid, _) =
            crate::services::agents::resolve_kernel_pid_pub(state, agent_pid);
        crate::services::agents::canonical_agent_memory_namespace(&kernel_pid)
    };
    let snap = crate::substrate::identity_stack::inspect(
        state,
        agent_pid,
        &namespace,
        &AdmissionOp::LlmChat,
    );

    let who = crate::kernel::agent_foundation::who_am_i_authoritative(state.as_ref(), agent_pid);
    let envelope =
        crate::kernel::agent_identity_envelope::build_identity_envelope(state.as_ref(), agent_pid);
    let principal_id = envelope
        .as_ref()
        .map(|e| e.base.principal.principal_id.clone())
        .or_else(|| {
            crate::kernel::agent_principal::load_principal(state.as_ref(), agent_pid)
                .map(|p| p.principal_id)
        });
    let agent_intelligence_hash = envelope.as_ref().and_then(|e| {
        e.base
            .foundation_block
            .as_ref()
            .map(|f| f.agent_intelligence_hash.clone())
    });

    let contract = crate::kernel::agent_principal::load_contract(state.as_ref(), agent_pid);
    let (caps, denied) = match &contract {
        Some(c) => (c.capabilities.clone(), c.denied_operations.clone()),
        None => (vec![], vec![]),
    };

    let mut missing = snap.missing.clone();
    if who.is_none() {
        missing.push("who_am_i_authoritative".into());
    }
    if principal_id.is_none() {
        missing.push("connector_identity_principal".into());
    }
    if contract.is_none() {
        missing.push("knowledge_contract".into());
    }
    missing.sort();
    missing.dedup();

    // Playground Talk: identity-stack pillars are minted on lane ensure; do not fail agentic
    // context on warm-up gaps (same carve-out as augmentation_pillars).
    if crate::services::playground::is_playground_mode() {
        missing.retain(|m| {
            !matches!(
                m.as_str(),
                "last_memory"
                    | "address_relation_identity_graph"
                    | "address_rules_contract"
                    | "address_hitl_contract"
                    | "identity_character"
            )
        });
    }

    let rules_summary = format!(
        "identity_stack missing=[{}]; address={}; hitl_contract={}; rules_contract={}",
        snap.missing.join(","),
        snap.address,
        snap.has_address_hitl_contract,
        snap.has_address_rules_contract
    );

    AgenticContext {
        who_am_i: who,
        principal_id,
        agent_intelligence_hash,
        character_name: snap.character_name,
        character_purpose: snap.character_purpose,
        last_memory_cid: snap.last_memory_cid,
        knowledge_capabilities: caps,
        denied_operations: denied,
        rules_summary,
        missing,
    }
}

/// Fail-closed when agentic context is required but incomplete.
pub fn require_or_hitl(
    state: &SharedState,
    agent_pid: &str,
) -> Result<AgenticContext, ConnectorError> {
    let ctx = build_for_shared(state, agent_pid);
    if ctx.missing.is_empty() || !agentic_context_required() {
        // Bind character/contract hashes into a generation record (Pillar 1).
        if let Ok(mut es) = state.engine_store.lock() {
            let _ = es.folder_put(
                "agentic_generation_v1",
                &format!(
                    "{}:{}",
                    agent_pid,
                    chrono::Utc::now().timestamp_millis()
                ),
                &serde_json::json!({
                    "principal_id": ctx.principal_id,
                    "character_hash": ctx.agent_intelligence_hash,
                    "contract_hash": crate::kernel::agent_principal::load_contract(state.as_ref(), agent_pid)
                        .map(|c| c.contract_digest_sha256),
                    "last_memory_cid": ctx.last_memory_cid,
                }),
            );
        }
        return Ok(ctx);
    }
    Err(
        crate::substrate::probabilistic_llm::require_human_for_rule(
            state,
            agent_pid,
            "identity_memory_character_knowledge",
            &format!(
                "Agentic context incomplete for talk/action: {}",
                ctx.missing.join(", ")
            ),
        ),
    )
}

/// Inject agentic context into a system prompt string (gateway / talk).
pub fn append_to_system(system: &mut String, ctx: &AgenticContext) {
    if !system.contains(MARKER) {
        if system.is_empty() {
            *system = ctx.render_prompt();
        } else {
            *system = format!("{}\n{}", system, ctx.render_prompt());
        }
    }
}

/// Inject into message list with role/content fields (gateway ChatMessage shape).
pub fn inject_into_role_content_messages(messages: &mut Vec<(String, String)>, ctx: &AgenticContext) {
    let block = ctx.render_prompt();
    if let Some((_, content)) = messages.iter_mut().find(|(r, _)| r == "system") {
        if !content.contains(MARKER) {
            *content = format!("{}\n{block}", content);
        }
    } else {
        messages.insert(0, ("system".into(), block));
    }
}

pub fn status() -> Value {
    json!({
        "schema": SCHEMA,
        "required": agentic_context_required(),
        "stance": "LLM follows Connector identity, memory, character, knowledge, and rules — it does not invent them.",
        "pillars": ["who_am_i", "principal", "character", "last_memory", "knowledge_contract", "rules_hitl"],
        "on_miss": { "http_status": 499, "message": "sorry, you are not allowed — need human approval" },
        "llm_context_broker": crate::substrate::llm_context_broker::status(),
    })
}

//! Intelligence Work Unit — per-LLM-invocation identity envelope metadata.
//!
//! Every cognitive call mints a work unit so the model knows *for whom* it works
//! and replies as that Connector agent is set up. Binding (Obey-Once) is per epoch;
//! work units are per invocation.

use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::state::PlatformState;

pub const SCHEMA: &str = "connector.intelligence_work_unit.v1";
pub const ENVELOPE_MARKER: &str =
    "--- CONNECTOR IDENTITY ENVELOPE (work unit — reply as this principal) ---";

#[derive(Debug, Clone, Serialize)]
pub struct IntelligenceWorkUnit {
    pub schema: &'static str,
    pub work_unit_id: String,
    pub agent_pid: String,
    pub principal_id: String,
    pub identity_envelope_digest_sha256: String,
    pub execution_rules_digest: Option<String>,
    pub character_name: Option<String>,
    pub character_purpose: Option<String>,
    pub character_acume: Option<String>,
    pub activation_state: Option<String>,
    pub who_am_i_preview: Option<String>,
    pub bind_tok: Option<String>,
    pub ctx_tok: Option<String>,
}

impl IntelligenceWorkUnit {
    pub fn to_json(&self) -> Value {
        json!({
            "schema": self.schema,
            "work_unit_id": self.work_unit_id,
            "agent_pid": self.agent_pid,
            "principal_id": self.principal_id,
            "identity_envelope_digest_sha256": self.identity_envelope_digest_sha256,
            "execution_rules_digest": self.execution_rules_digest,
            "character": {
                "name": self.character_name,
                "purpose": self.character_purpose,
                "acume": self.character_acume,
            },
            "activation_state": self.activation_state,
            "bind_tok": self.bind_tok,
            "ctx_tok": self.ctx_tok,
        })
    }

    /// Neutral metadata block injected into vendor system context.
    pub fn render_prompt_block(&self, include_full_who_am_i: bool) -> String {
        let name = self.character_name.as_deref().unwrap_or("Connector Agent");
        let purpose = self
            .character_purpose
            .as_deref()
            .or(self.character_acume.as_deref())
            .unwrap_or("(purpose from kernel setup)");
        let mut block = format!(
            "{ENVELOPE_MARKER}\n\
schema: {SCHEMA}\n\
work_unit_id: {wid}\n\
principal_id: {pid}\n\
agent_pid: {aid}\n\
identity_envelope_digest: {digest}\n\
character.name: {name}\n\
character.purpose: {purpose}\n\
activation: {act}\n\
stance: You work FOR this Connector principal only. Reply as this agent is set up.\n\
         Vendor LLM identity is irrelevant. Your text is a proposal — Connector owns identity, authority, and effects.\n",
            wid = self.work_unit_id,
            pid = self.principal_id,
            aid = self.agent_pid,
            digest = self.identity_envelope_digest_sha256,
            act = self.activation_state.as_deref().unwrap_or("unknown"),
        );
        if let Some(tok) = &self.bind_tok {
            block.push_str(&format!("bind_tok: {tok}\n"));
        }
        if let Some(tok) = &self.ctx_tok {
            block.push_str(&format!("ctx_tok: {tok}\n"));
        }
        if include_full_who_am_i {
            if let Some(who) = &self.who_am_i_preview {
                block.push_str("who_am_i:\n");
                block.push_str(who);
                block.push('\n');
            }
        } else {
            block.push_str("who_am_i: (see kernel identity refs / bind_tok — do not invent vendor persona)\n");
        }
        block.push_str(ENVELOPE_MARKER);
        block
    }
}

/// Mint a work unit snapshot for a Talk (or other LLM) invocation.
pub fn mint_for_talk(state: &PlatformState, agent_pid: &str) -> IntelligenceWorkUnit {
    let envelope =
        crate::kernel::agent_identity_envelope::build_identity_envelope(state, agent_pid);
    let principal_id = envelope
        .as_ref()
        .map(|e| e.base.principal.principal_id.clone())
        .or_else(|| {
            crate::kernel::agent_principal::load_principal(state, agent_pid)
                .map(|p| p.principal_id)
        })
        .unwrap_or_else(|| agent_pid.to_string());

    let (character_name, character_purpose, character_acume, activation_state, exec_digest, who) =
        if let Some(ref env) = envelope {
            let setup = crate::kernel::agent_identity_envelope::load_setup(state, agent_pid);
            (
                setup.as_ref().map(|s| s.name.clone()).or_else(|| {
                    agent_meta_string(state, agent_pid, "name")
                }),
                setup
                    .as_ref()
                    .map(|s| s.acume.clone())
                    .or_else(|| agent_meta_string(state, agent_pid, "purpose")),
                setup.as_ref().map(|s| s.acume.clone()),
                Some(activation_state_label(&env.activation.state)),
                Some(env.execution_rules_digest.clone()),
                env.who_am_i_authoritative.clone(),
            )
        } else {
            (
                agent_meta_string(state, agent_pid, "name"),
                agent_meta_string(state, agent_pid, "purpose"),
                None,
                None,
                None,
                crate::kernel::agent_foundation::who_am_i_authoritative(state, agent_pid),
            )
        };

    let digest_src = envelope
        .as_ref()
        .and_then(|e| e.who_am_i_authoritative.as_deref())
        .or(who.as_deref())
        .unwrap_or(agent_pid);
    let identity_envelope_digest_sha256 =
        hex::encode(Sha256::digest(digest_src.as_bytes()));

    let work_unit_id = format!(
        "iwu_{}",
        &hex::encode(Sha256::digest(
            format!(
                "{agent_pid}|{principal_id}|{}|{}",
                identity_envelope_digest_sha256,
                chrono::Utc::now().timestamp_millis()
            )
            .as_bytes()
        ))[..16]
    );

    IntelligenceWorkUnit {
        schema: SCHEMA,
        work_unit_id,
        agent_pid: agent_pid.to_string(),
        principal_id,
        identity_envelope_digest_sha256,
        execution_rules_digest: exec_digest,
        character_name,
        character_purpose,
        character_acume,
        activation_state,
        who_am_i_preview: who,
        bind_tok: None, // Obey-Once bind_tok wired in later phase
        ctx_tok: None,  // filled by gateway after broker mint when enforced
    }
}

fn agent_meta_string(state: &PlatformState, agent_pid: &str, key: &str) -> Option<String> {
    let es = state.engine_store.lock().ok()?;
    let meta = es.folder_get("agent_meta", agent_pid).ok().flatten()?;
    meta.get(key)
        .and_then(|x| x.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn activation_state_label(state: &connector_trust::ActivationStateV2) -> String {
    match state {
        connector_trust::ActivationStateV2::Registered => "registered".into(),
        connector_trust::ActivationStateV2::SetupReady => "setup_ready".into(),
        connector_trust::ActivationStateV2::Active => "active".into(),
    }
}

/// Attach optional broker token after mint (gateway fills once binding exists).
pub fn attach_ctx_tok(unit: &mut IntelligenceWorkUnit, ctx_tok: Option<String>) {
    unit.ctx_tok = ctx_tok;
}

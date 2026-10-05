//! GovernedTalkCore — single substrate entry for Talk prepare + finalize.
//!
//! Adapters (OpenAI, Anthropic, stream, playground, multiagent) call this instead
//! of assembling identity / projection ad hoc.
//!
//!   prepare → [vendor reasons freely] → finalize (Principal Projection)

use serde::Serialize;
use serde_json::Value;

use crate::error::ConnectorError;
use crate::services::llm_output_contract::OutputAttestation;
use crate::state::{PlatformState, SharedState};
use crate::substrate::intelligence_binding::{
    self, IntelligenceBindingRecord, BIND_MARKER,
};
use crate::substrate::intelligence_work_unit::{
    self, IntelligenceWorkUnit, ENVELOPE_MARKER,
};
use crate::substrate::principal_projection::{self, ProjectionOutcome, ProjectionResult};

pub const SCHEMA: &str = "connector.governed_talk_core.v1";

#[derive(Debug, Clone, Serialize)]
pub struct PreparedTalk {
    pub schema: &'static str,
    pub work_unit: IntelligenceWorkUnit,
    pub binding: IntelligenceBindingRecord,
    /// System blocks to prepend (binding envelope + work unit).
    pub system_blocks: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FinalizedTalk {
    pub schema: &'static str,
    pub outcome: ProjectionOutcome,
    pub text: String,
    pub mutations: Vec<String>,
    pub attestation: OutputAttestation,
    pub work_unit: Value,
    pub binding_status: Value,
    /// AiPassport leave-behind (sibling to payload — not embedded in hashed text).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aipsprt: Option<Value>,
}

/// Prepare Talk context: Obey-Once bind + work unit + system blocks.
pub fn prepare_talk(
    state: &SharedState,
    agent_pid: &str,
    model_ref: &str,
    provider: &str,
) -> Result<PreparedTalk, ConnectorError> {
    let mut binding =
        intelligence_binding::assert_or_bind_once(state, agent_pid, model_ref, provider)?;
    let mut work_unit = intelligence_work_unit::mint_for_talk(state.as_ref(), agent_pid);
    work_unit.bind_tok = Some(binding.bind_tok.clone());

    let name = work_unit
        .character_name
        .clone()
        .unwrap_or_else(|| "Connector Agent".into());
    let purpose = work_unit
        .character_purpose
        .clone()
        .or_else(|| work_unit.character_acume.clone())
        .unwrap_or_else(|| "connector:agent".into());

    let mut system_blocks = Vec::new();
    if binding.envelope_pending {
        system_blocks.push(binding.render_binding_envelope(&name, &purpose));
        intelligence_binding::mark_envelope_delivered(state.as_ref(), agent_pid);
        binding.envelope_pending = false;
    } else {
        system_blocks.push(binding.render_bind_ref());
    }
    system_blocks.push(work_unit.render_prompt_block(true));

    Ok(PreparedTalk {
        schema: SCHEMA,
        work_unit,
        binding,
        system_blocks,
    })
}

/// Finalize raw vendor proposal through Principal Projection.
pub fn finalize_talk(
    state: &PlatformState,
    agent_pid: &str,
    raw: &str,
    user_text: &str,
    work_unit: &IntelligenceWorkUnit,
) -> Result<FinalizedTalk, ConnectorError> {
    let projected = principal_projection::project_proposal(
        state,
        agent_pid,
        raw,
        user_text,
        Some(work_unit.work_unit_id.as_str()),
    )?;
    // Soft PROJECT for hallucinated "I executed / transferred / succeeded" claims.
    let (text, mut mutations) =
        project_false_execution_claims(&projected.text, projected.mutations.clone());
    let outcome = if mutations.is_empty() && projected.outcome == ProjectionOutcome::Pass {
        ProjectionOutcome::Pass
    } else if projected.outcome == ProjectionOutcome::Deny {
        ProjectionOutcome::Deny
    } else {
        ProjectionOutcome::Project
    };
    let mut attestation = projected.attestation;
    if outcome == ProjectionOutcome::Project && attestation.status == "pass" {
        attestation.status = "project";
    }
    for m in &mutations {
        if !attestation.enforced_rules.iter().any(|r| r == m) {
            attestation.enforced_rules.push(m.clone());
        }
    }
    mutations.extend(projected.mutations);

    // AiPassport at last governed boundary (finalized text after projection).
    let generation_id = {
        let gen = state
            .engine_store
            .lock()
            .ok()
            .and_then(|es| {
                es.folder_get("llm_context_broker_v1", &format!("gen:{agent_pid}"))
                    .ok()
                    .flatten()
                    .and_then(|v| v.get("generation").and_then(|g| g.as_u64()))
            })
            .unwrap_or(0);
        gen.to_string()
    };
    let _ = crate::substrate::spend_cease::ensure_ceiling(
        state,
        agent_pid,
        &generation_id,
        work_unit.work_unit_id.as_str(),
    );
    let char_hex = {
        use sha2::{Digest, Sha256};
        let material = format!(
            "{}|{}",
            work_unit.character_name.as_deref().unwrap_or(""),
            work_unit.character_purpose.as_deref().unwrap_or("")
        );
        format!("{:x}", Sha256::digest(material.as_bytes()))
    };
    let aipsprt = crate::substrate::aipsprt::mint_for_talk_text(
        state,
        crate::substrate::aipsprt::MintTalkPassportArgs {
            agent_pid,
            principal_id: work_unit.principal_id.as_str(),
            generation_id: &generation_id,
            quantum_id: work_unit.work_unit_id.as_str(),
            text: &text,
            character_digest_hex: &char_hex,
            context_exposure_manifest_id: None,
            parent_passport_id: None,
            provenance_role: connector_trust::ProvenanceRole::Created,
        },
    )
    .ok()
    .and_then(|p| serde_json::to_value(p).ok());

    Ok(FinalizedTalk {
        schema: SCHEMA,
        outcome,
        text,
        mutations,
        attestation,
        work_unit: work_unit.to_json(),
        binding_status: intelligence_binding::status(state, agent_pid),
        aipsprt,
    })
}

/// Convenience used by gateway: prepare not required when identity already injected;
/// still mint work unit + project.
pub fn project_talk_with_receipt(
    state: &PlatformState,
    agent_pid: &str,
    raw: &str,
    user_text: &str,
) -> Result<FinalizedTalk, ConnectorError> {
    let work_unit = intelligence_work_unit::mint_for_talk(state, agent_pid);
    finalize_talk(state, agent_pid, raw, user_text, &work_unit)
}

fn project_false_execution_claims(text: &str, mut mutations: Vec<String>) -> (String, Vec<String>) {
    let lower = text.to_lowercase();
    let false_exec = [
        "successfully executed",
        "i have executed",
        "i've executed",
        "transfer completed",
        "payment sent",
        "i deleted the file",
        "i have deleted",
        "successfully transferred",
        "tool call succeeded",
        "execution succeeded",
    ]
    .iter()
    .any(|p| lower.contains(p));
    if !false_exec {
        return (text.to_string(), mutations);
    }
    mutations.push("project:false_execution_claim".into());
    let disclaimer = "\n\n_[Connector] The above describes a **proposal** only — no effect was executed \
                      unless Connector admitted and attested it separately._";
    (format!("{text}{disclaimer}"), mutations)
}

/// Inject prepare blocks into OpenAI-style system messages.
pub fn inject_prepared_blocks(
    messages: &mut [crate::services::gateway::ChatMessage],
    prepared: &PreparedTalk,
) {
    let combined = prepared.system_blocks.join("\n");
    if let Some(sys) = messages.iter_mut().find(|m| m.role == "system") {
        if !sys.content.contains(ENVELOPE_MARKER) && !sys.content.contains(BIND_MARKER) {
            sys.content = format!("{combined}\n{}", sys.content);
        } else if !sys.content.contains(BIND_MARKER) {
            sys.content = format!("{}\n{}", prepared.system_blocks[0], sys.content);
        }
    }
}

/// Inject into engine ChatMessage (multiagent / experiments).
pub fn inject_prepared_engine_messages(
    messages: &mut Vec<connector_engine::llm::ChatMessage>,
    prepared: &PreparedTalk,
) {
    let combined = prepared.system_blocks.join("\n");
    if let Some(sys) = messages.iter_mut().find(|m| m.role == "system") {
        if !sys.content.contains(ENVELOPE_MARKER) {
            sys.content = format!("{combined}\n{}", sys.content);
        }
    } else {
        messages.insert(
            0,
            connector_engine::llm::ChatMessage {
                role: "system".into(),
                content: combined,
                reasoning_content: None,
                tool_calls: None,
                tool_call_id: None,
            },
        );
    }
}

/// Map FinalizedTalk into a ProjectionResult-compatible attestation path.
pub fn as_projection_pair(finalized: FinalizedTalk) -> (String, OutputAttestation, Value, Value) {
    (
        finalized.text,
        finalized.attestation,
        finalized.work_unit,
        finalized.binding_status,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn false_execution_gets_disclaimer() {
        let (out, muts) = project_false_execution_claims(
            "I have executed the transfer successfully.",
            vec![],
        );
        assert!(out.contains("proposal"));
        assert!(muts.iter().any(|m| m.contains("false_execution")));
    }
}

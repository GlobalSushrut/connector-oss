use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::error::{ConnectorError, DenialReason};
use crate::state::PlatformState;

pub const OUTPUT_CONTRACT_SCHEMA: &str = "connector.llm.output_contract.v1";
const PROVIDER_IDENTITY_CLAIMS: &[&str] = &[
    "i am chatgpt",
    "i'm chatgpt",
    "as chatgpt",
    "i am claude",
    "i'm claude",
    "as claude",
    "i am gemini",
    "i'm gemini",
    "as gemini",
    "i am deepseek",
    "i'm deepseek",
    "as deepseek",
    "created by deepseek",
    "深度求索",
    "i am an openai",
    "i am an anthropic",
    "i am a generic chatbot",
    "i am an ai language model",
    "i'm an ai assistant",
    "i am an ai assistant",
    "ai assistant created by",
];

#[derive(Debug, Clone, Serialize)]
pub struct OutputAttestation {
    pub schema: &'static str,
    pub status: &'static str,
    pub agent_pid: String,
    pub character_name: Option<String>,
    pub character_class: Option<String>,
    pub character_purpose: Option<String>,
    pub authoritative_identity_sha256: String,
    pub output_sha256: String,
    pub enforced_rules: Vec<String>,
}

fn string_at(value: Option<&Value>, pointer: &str) -> Option<String> {
    value
        .and_then(|v| v.pointer(pointer))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn string_list(value: Option<&Value>, pointer: &str) -> Vec<String> {
    value
        .and_then(|v| v.pointer(pointer))
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn deny(agent_pid: &str, rule: &str, detail: impl Into<String>) -> ConnectorError {
    ConnectorError::new(DenialReason::PolicyDenied, detail.into())
        .with_agent_scope(agent_pid)
        .with_denied_resource("llm.output")
        .with_hint(&format!(
            "Deterministic output contract rule failed: {rule}"
        ))
}

fn extract_identity_value(authoritative: &str, label: &str) -> Option<String> {
    authoritative.lines().find_map(|line| {
        line.trim()
            .strip_prefix(label)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    })
}

fn provider_identity_claim(output_lower: &str) -> Option<&'static str> {
    PROVIDER_IDENTITY_CLAIMS
        .iter()
        .copied()
        .find(|phrase| output_lower.contains(phrase))
}

/// User is asking who the agent is (playground Talk short-circuit).
pub fn playground_identity_question(user_text: &str) -> bool {
    let q = user_text.to_ascii_lowercase();
    [
        "who are you",
        "who are u",
        "what are you",
        "introduce yourself",
        "your name",
        "who am i talking to",
        "what is your name",
    ]
    .iter()
    .any(|m| q.contains(m))
}

/// Playground Workbench chip / charter probes — answer from kernel, not vendor LLM.
pub fn playground_charter_question(user_text: &str) -> bool {
    let q = user_text.to_ascii_lowercase();
    [
        "what must you refuse",
        "what do you refuse",
        "what will you refuse",
        "what is your job",
        "what's your job",
        "what are your duties",
        "what can you not do",
        "what can't you do",
        "what must you not",
    ]
    .iter()
    .any(|m| q.contains(m))
}

/// "Propose one safe next step" chip — safe kernel proposal (no vendor required).
pub fn playground_safe_step_question(user_text: &str) -> bool {
    let q = user_text.to_ascii_lowercase();
    [
        "propose one safe next step",
        "safe next step",
        "propose a safe next step",
        "one safe next step",
    ]
    .iter()
    .any(|m| q.contains(m))
}

/// Kernel charter / refuse reply for playground chips (no LLM).
pub fn playground_charter_answer(state: &PlatformState, agent_pid: &str) -> Option<String> {
    let meta = state
        .engine_store
        .lock()
        .ok()
        .and_then(|es| es.folder_get("agent_meta", agent_pid).ok().flatten());
    let name = meta
        .as_ref()
        .and_then(|m| m.get("name").and_then(|x| x.as_str()))
        .unwrap_or("Demo");
    let purpose = meta
        .as_ref()
        .and_then(|m| m.get("purpose").and_then(|x| x.as_str()))
        .unwrap_or("playground:demo");
    Some(format!(
        "**Kernel charter** (not the linked LLM vendor).\n\n\
         I'm **{name}** on this Connector playground tenant.\n\n\
         **Job:** {purpose}\n\n\
         **I must refuse:**\n\
         - Claiming to be DeepSeek, ChatGPT, Claude, Gemini, or any LLM vendor\n\
         - Executing tools or world effects without Connector Admit / DAL / PATE\n\
         - Bypassing quarantine, HITL, or charter limits\n\
         - Inventing completed actions that Connector did not attest\n\n\
                 Ask Isolate / Govern / Stop / Prove in Workbench (chips, no LLM key), or free-text after you link a model."
    ))
}

/// Safe next-step proposal for playground chip — no vendor LLM.
pub fn playground_safe_step_answer(state: &PlatformState, agent_pid: &str) -> Option<String> {
    let meta = state
        .engine_store
        .lock()
        .ok()
        .and_then(|es| es.folder_get("agent_meta", agent_pid).ok().flatten());
    let name = meta
        .as_ref()
        .and_then(|m| m.get("name").and_then(|x| x.as_str()))
        .unwrap_or("Demo");
    Some(format!(
        "**Kernel proposal** (not the linked LLM vendor).\n\n\
         Safe next step for **{name}** on this playground:\n\n\
         1. Use the Isolate / Govern / Stop / Prove chips — they enqueue real Admit orders (no LLM key).\n\
         2. Admit runs PATE → ToolDispatch. Stop cancels the loop and is not undo.\n\
         3. Then open TraceTramp / WitnessCtl to inspect the path and receipts.\n\n\
         Principal: `{agent_pid}`"
    ))
}

/// Vendor persona leaked through Talk (used for playground remediation + tests).
pub fn vendor_identity_slip(output_lower: &str) -> bool {
    provider_identity_claim(output_lower).is_some()
        || [
            "deepseek-chat",
            "deepseek-reasoner",
            "openai's",
            "anthropic's",
            "google's gemini",
            "newest deepseek model",
            "knowledge cutoff",
            "i was created by",
            "my knowledge is current up to",
            "completely free to use",
            "completely free",
            "text-based ai",
            "1 million tokens",
            "1m tokens",
            "depth求索",
            "company deepseek",
        ]
        .iter()
        .any(|m| output_lower.contains(m))
}

/// Playground kernel identity reply — meta first (fast), then full who_am_i envelope.
pub fn playground_identity_answer(
    state: &PlatformState,
    agent_pid: &str,
) -> Option<String> {
    if let Ok(es) = state.engine_store.lock() {
        if let Some(meta) = es.folder_get("agent_meta", agent_pid).ok().flatten() {
            let name = meta
                .get("name")
                .and_then(|x| x.as_str())
                .unwrap_or("Demo");
            let purpose = meta
                .get("purpose")
                .and_then(|x| x.as_str())
                .unwrap_or("playground:demo");
            return Some(format!(
                "**Kernel identity** (not DeepSeek / ChatGPT / Claude — Connector who_am_i).\n\n\
                 Hi! I'm **{name}**, your Connector playground demo agent.\n\n\
                 - **Purpose:** {purpose}\n\
                 - **Principal:** {agent_pid}\n\n\
                 Ask Isolate / Govern / Stop / Prove in Workbench (no LLM key), or Talk after you link a model."
            ));
        }
    }
    if let Some(who) = crate::kernel::agent_foundation::who_am_i_authoritative(state, agent_pid) {
        let name = extract_identity_value(&who, "Name:").unwrap_or_else(|| "Demo".into());
        let purpose =
            extract_identity_value(&who, "Acume/Purpose:").unwrap_or_else(|| "playground:demo".into());
        let pid =
            extract_identity_value(&who, "AgentID (principal):").unwrap_or_else(|| agent_pid.to_string());
        return Some(format!(
            "I'm **{name}**, a Connector Agent on this playground tenant — not the underlying LLM vendor.\n\n\
             - **Purpose:** {purpose}\n\
             - **Principal:** {pid}\n\n\
             My identity comes from the kernel block Connector injected before Talk. \
             Ask Isolate / Govern / Stop / Prove in Workbench (chips, no LLM key), or free-text after you link a model."
        ));
    }
    Some(format!(
        "I'm the **Demo** Connector agent on this playground tenant (principal `{agent_pid}`) — not the LLM vendor."
    ))
}

/// Attestation for playground kernel-identity short-circuit (no vendor LLM call).
pub fn attestation_playground_kernel_reply(agent_pid: &str, output: &str) -> OutputAttestation {
    let output_digest = hex::encode(Sha256::digest(output.as_bytes()));
    OutputAttestation {
        schema: OUTPUT_CONTRACT_SCHEMA,
        status: "playground_kernel_identity",
        agent_pid: agent_pid.to_string(),
        character_name: Some("Demo".into()),
        character_class: Some("playground".into()),
        character_purpose: Some("playground:demo".into()),
        authoritative_identity_sha256: output_digest.clone(),
        output_sha256: output_digest,
        enforced_rules: vec![
            "playground_kernel_identity_short_circuit".into(),
            "vendor_llm_bypassed".into(),
        ],
    }
}

/// Kernel/meta identity text for output contract + injection fallbacks.
pub fn resolve_authoritative_identity(state: &PlatformState, agent_pid: &str) -> String {
    if let Some(who) = crate::kernel::agent_foundation::who_am_i_authoritative(state, agent_pid) {
        return who;
    }
    if let Ok(es) = state.engine_store.lock() {
        if let Some(meta) = es.folder_get("agent_meta", agent_pid).ok().flatten() {
            let name = meta
                .get("name")
                .and_then(|x| x.as_str())
                .unwrap_or("Demo");
            let purpose = meta
                .get("purpose")
                .and_then(|x| x.as_str())
                .unwrap_or("playground:demo");
            let namespace = meta
                .get("namespace")
                .and_then(|x| x.as_str())
                .unwrap_or("m/demo");
            return format!(
                "Name: {name}\n\
                 Acume/Purpose: {purpose}\n\
                 AgentID (principal): {agent_pid}\n\
                 Namespace: {namespace}\n\
                 When asked who I am, I answer ONLY from this kernel block — not from the LLM vendor."
            );
        }
    }
    String::new()
}

/// Sanitize vendor-brain persona leaks before returning Talk text to the operator.
/// Prefers Principal Projection (PASS/PROJECT) — preserves useful reasoning.
/// Tool routing / execution is unchanged — this only rewrites chat content.
pub fn sanitize_talk_output(
    state: &PlatformState,
    agent_pid: &str,
    output: &str,
    user_text: &str,
) -> String {
    match crate::substrate::principal_projection::project_proposal(
        state,
        agent_pid,
        output,
        user_text,
        None,
    ) {
        Ok(r) => r.text,
        Err(_) => {
            // Fallback: minimal strip if projection/enforce path fails mid-flight.
            let lower = output.to_lowercase();
            if !vendor_identity_slip(&lower) {
                return output.to_string();
            }
            if playground_identity_question(user_text) || vendor_identity_dominates(&lower) {
                return playground_identity_answer(state, agent_pid)
                    .unwrap_or_else(|| output.to_string());
            }
            let stripped = strip_vendor_identity_paragraphs(output);
            if stripped.trim().is_empty() {
                playground_identity_answer(state, agent_pid).unwrap_or_else(|| output.to_string())
            } else {
                stripped
            }
        }
    }
}

fn vendor_identity_dominates(output_lower: &str) -> bool {
    let vendor_hits = [
        "i'm deepseek",
        "i am deepseek",
        "created by deepseek",
        "i'm chatgpt",
        "i am chatgpt",
        "i'm claude",
        "i am claude",
        "i'm gemini",
        "i am gemini",
        "ai assistant created by",
        "knowledge cutoff",
        "completely free",
        "1 million tokens",
    ]
    .iter()
    .filter(|m| output_lower.contains(*m))
    .count();
    vendor_hits >= 2 || output_lower.len() < 900 && vendor_hits >= 1
}

fn strip_vendor_identity_paragraphs(output: &str) -> String {
    let mut kept = Vec::new();
    for para in output.split("\n\n") {
        let pl = para.to_lowercase();
        if vendor_identity_slip(&pl) {
            continue;
        }
        kept.push(para.trim());
    }
    let joined = kept
        .into_iter()
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join("\n\n");
    if joined.trim().is_empty() {
        output.to_string()
    } else {
        joined
    }
}

/// Short kernel-grounded identity answer when the model impersonates its vendor.
pub fn playground_identity_remediation(
    state: &PlatformState,
    agent_pid: &str,
) -> Option<String> {
    playground_identity_answer(state, agent_pid)
}

pub fn enforce(
    state: &PlatformState,
    agent_pid: &str,
    output: &str,
) -> Result<OutputAttestation, ConnectorError> {
    let spec = crate::kernel::intelligence_spec::load_spec_doc(state, agent_pid);
    let hardened = !crate::services::playground::is_playground_mode()
        && (crate::connector_profile::is_productionish_env()
            || spec
                .as_ref()
                .and_then(|v| v.pointer("/spec/harden"))
                .and_then(Value::as_bool)
                .unwrap_or(false));
    let authoritative = resolve_authoritative_identity(state, agent_pid);
    if authoritative.trim().is_empty() {
        return Err(deny(
            agent_pid,
            "authoritative_identity_required",
            "LLM output blocked because no authoritative Connector identity exists",
        ));
    }
    if hardened && spec.is_none() {
        return Err(deny(
            agent_pid,
            "character_contract_required",
            "LLM output blocked because no server-owned Intelligence character contract exists",
        ));
    }

    let lower = output.to_lowercase();
    let has_text = !output.trim().is_empty();
    let mut enforced_rules = vec!["authoritative_identity".to_string()];
    if has_text {
        if let Some(phrase) = provider_identity_claim(&lower) {
            // Projection should have displaced ordinary vendor slips before enforce.
            // Residual claims: record PROJECT-style rule — do not soft-ship as "ok",
            // and do not hard-DENY ordinary identity slips (agent runtime, not wall).
            enforced_rules.push(format!("projection_residual_identity:{phrase}"));
            enforced_rules.push("prefer_principal_projection_upstream".into());
        }
    }

    if let Some(principal_id) = extract_identity_value(&authoritative, "AgentID (principal):") {
        if has_text
            && lower.contains("agentid (principal):")
            && !lower.contains(&principal_id.to_lowercase())
        {
            return Err(deny(
                agent_pid,
                "principal_identity_mismatch",
                "LLM output asserted a principal other than the kernel-authoritative principal",
            ));
        }
    }

    let character_name = string_at(spec.as_ref(), "/metadata/name");
    if let Some(expected) = character_name.as_deref() {
        for marker in ["my name is ", "i am called "] {
            if has_text {
                if let Some(start) = lower.find(marker) {
                    let claim = lower[start + marker.len()..]
                        .split(['.', ',', '\n', ';'])
                        .next()
                        .unwrap_or("")
                        .trim();
                    if !claim.is_empty() && !claim.contains(&expected.to_lowercase()) {
                        return Err(deny(
                            agent_pid,
                            "character_name_mismatch",
                            format!(
                                "LLM output claimed character name '{claim}', expected '{expected}'"
                            ),
                        ));
                    }
                }
            }
        }
    }

    let denied = string_list(spec.as_ref(), "/spec/output_contract/denied_phrases");
    for phrase in &denied {
        if has_text && lower.contains(&phrase.to_lowercase()) {
            return Err(deny(
                agent_pid,
                "character_denied_phrase",
                format!("LLM output contains denied character phrase: {phrase}"),
            ));
        }
    }
    if !denied.is_empty() {
        enforced_rules.push("denied_phrases".into());
    }

    let required = string_list(spec.as_ref(), "/spec/output_contract/required_phrases");
    for phrase in &required {
        if has_text && !lower.contains(&phrase.to_lowercase()) {
            return Err(deny(
                agent_pid,
                "character_required_phrase",
                format!("LLM output is missing required character phrase: {phrase}"),
            ));
        }
    }
    if !required.is_empty() {
        enforced_rules.push("required_phrases".into());
    }

    if let Some(max_chars) = spec
        .as_ref()
        .and_then(|v| v.pointer("/spec/output_contract/max_chars"))
        .and_then(Value::as_u64)
    {
        if output.chars().count() as u64 > max_chars {
            return Err(deny(
                agent_pid,
                "character_max_chars",
                format!("LLM output exceeds character contract maximum of {max_chars} chars"),
            ));
        }
        enforced_rules.push("max_chars".into());
    }

    let identity_digest = hex::encode(Sha256::digest(authoritative.as_bytes()));
    let output_digest = hex::encode(Sha256::digest(output.as_bytes()));
    Ok(OutputAttestation {
        schema: OUTPUT_CONTRACT_SCHEMA,
        status: "enforced",
        agent_pid: agent_pid.to_string(),
        character_name,
        character_class: string_at(spec.as_ref(), "/spec/class"),
        character_purpose: string_at(spec.as_ref(), "/spec/purpose"),
        authoritative_identity_sha256: identity_digest,
        output_sha256: output_digest,
        enforced_rules,
    })
}

pub fn denial_json(error: &ConnectorError) -> Value {
    json!({
        "ok": false,
        "error": "llm_output_contract_denied",
        "detail": error,
        "schema": OUTPUT_CONTRACT_SCHEMA,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_identity_claims_are_deterministically_detected() {
        assert_eq!(
            provider_identity_claim("as claude, i can help"),
            Some("as claude")
        );
        assert_eq!(
            provider_identity_claim("i am an ai language model"),
            Some("i am an ai language model")
        );
        assert_eq!(
            provider_identity_claim("i'm deepseek, an ai assistant"),
            Some("i'm deepseek")
        );
        assert!(vendor_identity_slip(
            "i'm deepseek, an ai assistant created by deepseek company"
        ));
        assert_eq!(provider_identity_claim("connector agent reporting"), None);
    }

    #[test]
    fn sanitize_talk_output_replaces_vendor_persona_on_identity_probe() {
        let vendor = "Hi! I'm DeepSeek, an AI assistant created by DeepSeek. Knowledge cutoff May 2025.";
        assert!(vendor_identity_slip(&vendor.to_lowercase()));
        assert!(playground_identity_question("hi who are you"));
        assert!(playground_charter_question("What must you refuse?"));
        assert!(playground_charter_question("What is your job?"));
        assert!(!playground_charter_question("Propose one safe next step"));
        assert!(playground_safe_step_question("Propose one safe next step"));
        assert!(!playground_safe_step_question("What must you refuse?"));
    }

    #[test]
    fn strip_preserves_nvidia_analysis() {
        let raw = "I'm Claude, an AI assistant created by Anthropic.\n\nHere is my analysis of NVIDIA...";
        let stripped = strip_vendor_identity_paragraphs(raw);
        assert!(stripped.contains("analysis of NVIDIA"));
        assert!(!stripped.to_lowercase().contains("claude"));
    }

    #[test]
    fn authoritative_identity_value_is_exactly_extracted() {
        let identity = "AgentID (principal): cnktr:agent:a1\nPurpose: test";
        assert_eq!(
            extract_identity_value(identity, "AgentID (principal):").as_deref(),
            Some("cnktr:agent:a1")
        );
    }
}

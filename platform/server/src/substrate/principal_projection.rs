//! Principal Projection Layer — `Final = Project(P | I, C, X)`.
//!
//! Philosophy:
//!   Reason freely. Speak as the active principal.
//!   Act only through granted authority. Prove what actually happened.
//!
//! Outcomes:
//!   PASS    — raw proposal already compatible; ship unchanged
//!   PROJECT — minimal mutation: displace conflicting parts, preserve useful reasoning
//!   DENY    — rare: hard security invariant / Connector bypass (not ordinary identity slips)

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::error::ConnectorError;
use crate::services::llm_output_contract::{
    self, OutputAttestation, OUTPUT_CONTRACT_SCHEMA,
};
use crate::state::PlatformState;

pub const SCHEMA: &str = "connector.principal_projection.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectionOutcome {
    Pass,
    Project,
    Deny,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProjectionResult {
    pub schema: &'static str,
    pub outcome: ProjectionOutcome,
    pub text: String,
    pub mutations: Vec<String>,
    pub work_unit_id: Option<String>,
    pub attestation: OutputAttestation,
}

/// Project a raw LLM proposal through the active principal.
///
/// Ordinary foreign-identity slips → PROJECT (preserve useful body).
/// Hard contract invariants that cannot be repaired → DENY (via enforce).
pub fn project_proposal(
    state: &PlatformState,
    agent_pid: &str,
    raw: &str,
    user_text: &str,
    work_unit_id: Option<&str>,
) -> Result<ProjectionResult, ConnectorError> {
    let mut mutations = Vec::new();
    let lower = raw.to_lowercase();
    let identity_q = llm_output_contract::playground_identity_question(user_text);
    let has_slip = llm_output_contract::vendor_identity_slip(&lower);

    let projected = if identity_q && (has_slip || raw.trim().is_empty() || !kernel_aligned(state, agent_pid, &lower)) {
        // Identity questions: prefer kernel voice; do not ship vendor persona.
        mutations.push("project:identity_question_kernel".into());
        llm_output_contract::playground_identity_answer(state, agent_pid)
            .unwrap_or_else(|| raw.to_string())
    } else if has_slip && vendor_identity_dominates(&lower) {
        // Vendor persona dominates → replace with kernel identity preface + stripped body if any.
        let stripped = strip_foreign_identity_paragraphs(raw);
        if stripped.trim().is_empty() || vendor_identity_dominates(&stripped.to_lowercase()) {
            mutations.push("project:identity_dominated_kernel_replace".into());
            llm_output_contract::playground_identity_answer(state, agent_pid)
                .unwrap_or_else(|| raw.to_string())
        } else {
            let kernel = llm_output_contract::playground_identity_answer(state, agent_pid)
                .unwrap_or_default();
            mutations.push("project:identity_dominated_preface_plus_body".into());
            if kernel.trim().is_empty() {
                stripped
            } else {
                format!("{kernel}\n\n{stripped}")
            }
        }
    } else if has_slip {
        // Local foreign-identity paragraphs only — minimal mutation.
        let stripped = strip_foreign_identity_paragraphs(raw);
        if stripped != raw {
            mutations.push("project:strip_foreign_identity_paragraphs".into());
        }
        if let Some(phrase) = first_provider_claim(&lower) {
            mutations.push(format!("project:displaced_claim:{phrase}"));
        }
        stripped
    } else {
        raw.to_string()
    };

    // After projection, soft-ship of vendor persona must not remain.
    let projected = if llm_output_contract::vendor_identity_slip(&projected.to_lowercase())
        && !kernel_aligned(state, agent_pid, &projected.to_lowercase())
    {
        mutations.push("project:residual_slip_kernel_fallback".into());
        let stripped = strip_foreign_identity_paragraphs(&projected);
        if stripped.trim().is_empty()
            || llm_output_contract::vendor_identity_slip(&stripped.to_lowercase())
        {
            llm_output_contract::playground_identity_answer(state, agent_pid)
                .unwrap_or(stripped)
        } else {
            stripped
        }
    } else {
        projected
    };

    let outcome = if mutations.is_empty() {
        ProjectionOutcome::Pass
    } else {
        ProjectionOutcome::Project
    };

    // Enforce contract on *projected* text. Identity slips should already be gone —
    // remaining denials are hard invariants (denied phrases, max_chars, etc.).
    let mut attestation = llm_output_contract::enforce(state, agent_pid, &projected)?;
    match outcome {
        ProjectionOutcome::Pass => {
            attestation.status = "pass";
            attestation.enforced_rules.push("projection:pass".into());
        }
        ProjectionOutcome::Project => {
            attestation.status = "project";
            attestation.enforced_rules.push("projection:project".into());
            for m in &mutations {
                attestation.enforced_rules.push(m.clone());
            }
        }
        ProjectionOutcome::Deny => {
            attestation.status = "deny";
        }
    }
    if let Some(id) = work_unit_id {
        attestation
            .enforced_rules
            .push(format!("work_unit:{id}"));
    }

    Ok(ProjectionResult {
        schema: SCHEMA,
        outcome,
        text: projected,
        mutations,
        work_unit_id: work_unit_id.map(str::to_string),
        attestation,
    })
}

/// Convenience for Talk paths: project then return text + attestation.
pub fn project_talk(
    state: &PlatformState,
    agent_pid: &str,
    raw: &str,
    user_text: &str,
) -> Result<(String, OutputAttestation), ConnectorError> {
    let work_unit = crate::substrate::intelligence_work_unit::mint_for_talk(state, agent_pid);
    let result = project_proposal(
        state,
        agent_pid,
        raw,
        user_text,
        Some(work_unit.work_unit_id.as_str()),
    )?;
    Ok((result.text, result.attestation))
}

fn kernel_aligned(state: &PlatformState, agent_pid: &str, lower: &str) -> bool {
    let who = llm_output_contract::resolve_authoritative_identity(state, agent_pid);
    if who.trim().is_empty() {
        return false;
    }
    let name = extract_label(&who, "Name:")
        .or_else(|| extract_label(&who, "character.name:"))
        .unwrap_or_default()
        .to_lowercase();
    let pid = extract_label(&who, "AgentID (principal):")
        .unwrap_or_else(|| agent_pid.to_string())
        .to_lowercase();
    (!name.is_empty() && lower.contains(&name)) || lower.contains(&pid) || lower.contains("connector")
}

fn extract_label(block: &str, label: &str) -> Option<String> {
    block.lines().find_map(|line| {
        line.trim()
            .strip_prefix(label)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    })
}

fn first_provider_claim(lower: &str) -> Option<&'static str> {
    const CLAIMS: &[&str] = &[
        "i'm deepseek",
        "i am deepseek",
        "i'm chatgpt",
        "i am chatgpt",
        "i'm claude",
        "i am claude",
        "i'm gemini",
        "i am gemini",
        "created by deepseek",
        "created by openai",
        "created by anthropic",
        "ai assistant created by",
        "i am an ai language model",
        "i'm an ai assistant",
        "i am an ai assistant",
    ];
    CLAIMS.iter().copied().find(|p| lower.contains(p))
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
    vendor_hits >= 2 || (output_lower.len() < 900 && vendor_hits >= 1)
}

/// Strip paragraphs that are foreign-identity / vendor-persona; keep useful body.
fn strip_foreign_identity_paragraphs(output: &str) -> String {
    let mut kept = Vec::new();
    for para in output.split("\n\n") {
        let pl = para.to_lowercase();
        if llm_output_contract::vendor_identity_slip(&pl) {
            continue;
        }
        // Also drop single-line self-ID openers without useful content.
        let trimmed = para.trim();
        if is_pure_identity_line(trimmed) {
            continue;
        }
        kept.push(trimmed);
    }
    let joined = kept
        .into_iter()
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join("\n\n");
    if joined.trim().is_empty() {
        // Nothing left — caller decides kernel replace.
        String::new()
    } else {
        joined
    }
}

fn is_pure_identity_line(line: &str) -> bool {
    let l = line.to_lowercase();
    let words = l.split_whitespace().count();
    if words > 40 {
        return false;
    }
    (l.starts_with("i'm ") || l.starts_with("i am ") || l.starts_with("as an ai"))
        && (l.contains("claude")
            || l.contains("chatgpt")
            || l.contains("openai")
            || l.contains("anthropic")
            || l.contains("deepseek")
            || l.contains("gemini")
            || l.contains("ai assistant")
            || l.contains("language model"))
}

/// Attestation helper when projection itself is denied upstream.
pub fn deny_attestation(agent_pid: &str, reason: &str) -> OutputAttestation {
    let digest = hex::encode(Sha256::digest(reason.as_bytes()));
    OutputAttestation {
        schema: OUTPUT_CONTRACT_SCHEMA,
        status: "deny",
        agent_pid: agent_pid.to_string(),
        character_name: None,
        character_class: None,
        character_purpose: None,
        authoritative_identity_sha256: digest.clone(),
        output_sha256: digest,
        enforced_rules: vec![
            "projection:deny".into(),
            format!("deny_reason:{reason}"),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_preserves_useful_analysis() {
        let raw = "I'm Claude, an AI assistant created by Anthropic.\n\n\
                   Here is my analysis of NVIDIA: revenue grew 14%.";
        let stripped = strip_foreign_identity_paragraphs(raw);
        assert!(stripped.contains("analysis of NVIDIA"));
        assert!(!stripped.to_lowercase().contains("claude"));
        assert!(!stripped.to_lowercase().contains("anthropic"));
    }

    #[test]
    fn pure_identity_line_detected() {
        assert!(is_pure_identity_line(
            "I'm Claude, an AI assistant created by Anthropic."
        ));
        assert!(!is_pure_identity_line(
            "I'm analyzing the semiconductor market trends for NVIDIA this quarter carefully."
        ));
    }

    #[test]
    fn pass_when_no_slip() {
        assert!(!llm_output_contract::vendor_identity_slip(
            "revenue grew 14% based on the supplied records."
        ));
    }
}

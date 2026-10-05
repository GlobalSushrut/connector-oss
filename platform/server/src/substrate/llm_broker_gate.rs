//! Unbypassable LLM broker gate — every byte that touches the model brain.
//!
//! Rules:
//! 1. **No raw data to LLM** — ingress must pass compile/seal; residual plaintext
//!    sensitive shapes → refuse (or quarantine if looks like bypass).
//! 2. **Deser mismatch → redo** — tool/action params must match live broker
//!    generation, semantic-card seals, VAC memory ownership, and expected schema.
//!    Broker tells the model to redo with the correct context (no silent fix-up).
//! 3. **Unusual → quarantine + human approval** — invented identity, raw secrets,
//!    foreign seals, VAC CID theft, entropy anomalies.
//!
//! This gate is fail-closed under `CONNECTOR_LLM_BROKER_UNBYPASSABLE` and when
//! sandbox unbypassable / distrust / broker planes are on.

use regex::Regex;
use serde_json::{json, Value};
use std::sync::OnceLock;

use crate::error::ConnectorError;
use crate::state::SharedState;

pub const SCHEMA: &str = "connector.llm_broker_gate.v1";
const EXPECT_FOLDER: &str = "llm_broker_expect_v1";

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

/// Master switch: LLM cannot see/act on raw data outside this broker.
pub fn broker_unbypassable() -> bool {
    // Hosted playground: CONNECTOR_LLM_CONTEXT_BROKER injects identity tokens only.
    // Full sealed-brain / Landlock bar requires a dedicated Linux host — not Fly shared VM.
    if crate::services::playground::is_playground_mode()
        && !env_flag("CONNECTOR_LLM_BROKER_UNBYPASSABLE")
    {
        return false;
    }
    env_flag("CONNECTOR_LLM_BROKER_UNBYPASSABLE")
        || crate::substrate::sandbox_unbypassable::unbypassable_bar_enforced()
        || crate::substrate::llm_context_broker::broker_enforced()
        || crate::substrate::probabilistic_llm::distrust_enforced()
}

fn raw_sensitive_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(
            r"(?i)(?:\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b|https?://[^\s]+|\b(?:sk|pk|rk|api[_-]?key)[-_]?[A-Za-z0-9]{12,}\b|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)",
        )
        .expect("raw re")
    })
}

fn seal_ref_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"⟦seal:v1:[a-f0-9]+⟧").expect("seal re"))
}

fn conn_ref_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"⟦conn:[a-z]+:[a-f0-9]+⟧").expect("conn re"))
}

fn vac_cid_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"\b(?:cid|mem|vac)[:/]([A-Za-z0-9_\-]{8,})\b").expect("cid re")
    })
}

/// Record expected context fingerprint after successful talk ingress (for deser checks).
pub fn remember_expect(
    state: &SharedState,
    agent_pid: &str,
    generation: u64,
    semantic_card: &str,
    vac_memory_cids: &[String],
) {
    if let Ok(mut es) = state.engine_store.lock() {
        use sha2::{Digest, Sha256};
        let semantic_card_sha = format!("{:x}", Sha256::digest(semantic_card.as_bytes()));
        let allowed_seals: Vec<String> = seal_ref_re()
            .find_iter(semantic_card)
            .map(|m| m.as_str().to_string())
            .collect();
        let _ = es.folder_put(
            EXPECT_FOLDER,
            agent_pid,
            &json!({
                "schema": SCHEMA,
                "agent_pid": agent_pid,
                "generation": generation,
                "semantic_card_sha": semantic_card_sha,
                "allowed_seals": allowed_seals,
                "vac_memory_cids": vac_memory_cids,
                "at_ms": chrono::Utc::now().timestamp_millis(),
            }),
        );
    }
}

fn load_expect(state: &SharedState, agent_pid: &str) -> Option<Value> {
    let es = state.engine_store.lock().ok()?;
    es.folder_get(EXPECT_FOLDER, agent_pid).ok().flatten()
}

/// Master lane: every LLM talk/tool path must enter here when broker is unbypassable.
/// Skipping this gate to avoid 409/499 is itself a bypass → quarantine 499.
/// Also requires Linux unbypassable bar (Landlock/eBPF/cgroup) — same class as kernel paths.
pub fn assert_llm_lane(state: &SharedState, agent_pid: &str) -> Result<(), ConnectorError> {
    if !broker_unbypassable() {
        return Ok(());
    }
    // Linux kernel path bar (FS/net/VM/cgroup) — not L7 alone.
    if let Err(v) =
        crate::substrate::sandbox_unbypassable::assert_sandbox_unbypassable(state.as_ref(), agent_pid)
    {
        let detail = v
            .get("detail")
            .or_else(|| v.get("message"))
            .and_then(|x| x.as_str())
            .unwrap_or("linux_sandbox_unbypassable");
        let code = v
            .get("denial_reason")
            .and_then(|x| x.as_str())
            .unwrap_or("sandbox_unbypassable");
        return Err(ConnectorError::llm_quarantined_need_approval(
            agent_pid,
            code,
            detail,
        ));
    }
    if crate::substrate::llm_sealed_context::agent_brain_quarantined(state, agent_pid) {
        return Err(ConnectorError::llm_quarantined_need_approval(
            agent_pid,
            "lane_quarantined",
            "agent quarantined — sorry, you are not allowed — need human approval",
        ));
    }
    // Slot may be missing on first talk after approve — ingress opens it.
    // If slot exists but closed → 499.
    if let Some(slot) = crate::substrate::llm_agent_sandbox::load_slot(state, agent_pid) {
        if !slot.open {
            return Err(ConnectorError::llm_quarantined_need_approval(
                agent_pid,
                "sandbox_closed",
                "broker sandbox closed — need human approval",
            ));
        }
    }
    Ok(())
}

/// Ingress: every string bound for the LLM brain. Unbypassable when enforced.
pub fn ingress_to_llm(
    state: &SharedState,
    agent_pid: &str,
    text: &str,
) -> Result<String, ConnectorError> {
    assert_llm_lane(state, agent_pid)?;

    if !broker_unbypassable() {
        // Soft: still prefer sealed compile when advanced is on.
        if crate::substrate::llm_sealed_context::advanced_enforced() {
            return crate::substrate::llm_sealed_context::compile_llm_view(state, agent_pid, text)
                .map_err(|e| {
                    crate::substrate::probabilistic_llm::require_human_for_rule(
                        state,
                        agent_pid,
                        "broker_ingress",
                        &e,
                    )
                });
        }
        let (t, _) =
            crate::substrate::data_tokenization::tokenize_for_llm(state, agent_pid, text);
        return Ok(t);
    }

    crate::substrate::llm_sealed_context::assert_brain_live_for_talk(state, agent_pid)?;

    // Bind / refresh per-agent sandbox (identity · character · knowledge isolation).
    let ctx = crate::substrate::agentic_context::build_for_shared(state, agent_pid);
    let slot = crate::substrate::llm_agent_sandbox::open_slot(state, agent_pid, &ctx)?;

    let compiled = crate::substrate::llm_sealed_context::compile_llm_view(state, agent_pid, text)
        .map_err(|e| {
            crate::substrate::probabilistic_llm::require_human_for_rule(
                state,
                agent_pid,
                "broker_ingress_compile",
                &e,
            )
        })?;

    // Residual raw sensitive shapes that are NOT inside seal/conn tokens → unusual.
    let residual = strip_opaque_spans(&compiled);
    if raw_sensitive_re().is_match(&residual) {
        return Err(quarantine_unusual(
            state,
            agent_pid,
            "raw_data_past_broker",
            "Raw sensitive data attempted to reach LLM brain without broker sealing",
        ));
    }

    let generation = crate::substrate::llm_context_broker::current_generation(state, agent_pid);
    let card = crate::substrate::llm_sealed_context::semantic_card_json(state, agent_pid);
    let vac = vac_cids_for_agent(state, agent_pid);
    remember_expect(state, agent_pid, generation, &card, &vac);

    // Stamp sandbox id into expect for cross-agent checks.
    if let Ok(mut es) = state.engine_store.lock() {
        if let Ok(Some(mut exp)) = es.folder_get(EXPECT_FOLDER, agent_pid) {
            if let Some(obj) = exp.as_object_mut() {
                obj.insert("sandbox_id".into(), json!(slot.sandbox_id));
                obj.insert("principal_hash".into(), json!(slot.principal_hash));
                obj.insert("character_hash".into(), json!(slot.character_hash));
                obj.insert("knowledge_hash".into(), json!(slot.knowledge_hash));
            }
            let _ = es.folder_put(EXPECT_FOLDER, agent_pid, &exp);
        }
    }

    Ok(compiled)
}

fn strip_opaque_spans(s: &str) -> String {
    let mut out = s.to_string();
    for re in [seal_ref_re(), conn_ref_re()] {
        out = re.replace_all(&out, " ").into_owned();
    }
    // Drop vault handles (allowed opaque)
    out = Regex::new(r"vault:handle:[A-Za-z0-9_\-:./]+")
        .map(|r| r.replace_all(&out, " ").into_owned())
        .unwrap_or(out);
    out
}

fn vac_cids_for_agent(state: &SharedState, agent_pid: &str) -> Vec<String> {
    // Best-effort: last memory from identity stack + aios core pointers.
    let mut out = Vec::new();
    let snap = crate::substrate::identity_stack::inspect(
        state,
        agent_pid,
        &format!("gateway/{agent_pid}"),
        &crate::services::admission::AdmissionOp::LlmChat,
    );
    if let Some(cid) = snap.last_memory_cid {
        out.push(cid);
    }
    out
}

fn quarantine_unusual(
    state: &SharedState,
    agent_pid: &str,
    kind: &str,
    detail: &str,
) -> ConnectorError {
    crate::substrate::probabilistic_llm::quarantine_499(state, agent_pid, kind, detail)
}

/// Redo signal: parameter/context mismatch — tell LLM to regenerate under broker context.
pub fn redo_for_mismatch(
    agent_pid: &str,
    mismatches: &[String],
    expected: &Value,
) -> Value {
    json!({
        "ok": false,
        "status": 409,
        "error": "llm_broker_redo",
        "denial_reason": "broker_parameter_mismatch",
        "schema": SCHEMA,
        "agent_pid": agent_pid,
        "message": "Broker rejected deserialization — redo your action using only the sealed/tokenized context and parameters below. Do not invent raw data.",
        "instruction_to_llm": "REDO: align parameters with Connector broker context (generation, seals, VAC memory). Raw emails/URLs/keys/foreign CIDs are forbidden.",
        "mismatches": mismatches,
        "expected_context": expected,
        "human_approval": false,
    })
}

/// Egress validate: tool/action JSON from the model — **opaque only** (no world expand).
/// Expand happens in [`expand_after_admit`] after PATE Admit (IFC D3 / SVF sandwich).
pub fn egress_deserialize(
    state: &SharedState,
    agent_pid: &str,
    value: &Value,
) -> Result<Value, Value> {
    egress_validate_opaque(state, agent_pid, value)
}

/// Alias for the validate-only stage (PDP digest must cover opaque handles).
pub fn egress_validate_opaque(
    state: &SharedState,
    agent_pid: &str,
    value: &Value,
) -> Result<Value, Value> {
    if !broker_unbypassable() {
        crate::substrate::llm_sealed_context::assert_no_plaintext_bypass(state, agent_pid, value)?;
        // Soft: validate only — do not detok/materialize here (post-Admit CDP).
        return Ok(value.clone());
    }

    assert_llm_lane(state, agent_pid).map_err(|e| {
        json!({
            "ok": false,
            "status": 499,
            "message": "sorry, you are not allowed — need human approval",
            "error": e.denial_reason.slug(),
            "human_readable": e.human_readable,
            "human_approval": true,
            "schema": SCHEMA,
        })
    })?;

    let _slot = crate::substrate::llm_agent_sandbox::assert_slot_live(state, agent_pid).map_err(
        |e| {
            json!({
                "ok": false,
                "status": 499,
                "message": "sorry, you are not allowed — need human approval",
                "error": e.denial_reason.slug(),
                "human_readable": e.human_readable,
                "human_approval": true,
                "schema": SCHEMA,
            })
        },
    )?;

    // Reject foreign sandbox_id in payload (cross-agent bypass).
    if let Some(sid) = value
        .pointer("/sandbox_id")
        .or_else(|| value.pointer("/connector_sandbox_id"))
        .and_then(|v| v.as_str())
    {
        crate::substrate::llm_agent_sandbox::assert_no_cross_agent(state, agent_pid, Some(sid))
            .map_err(|e| {
                let _ = crate::substrate::probabilistic_llm::quarantine_for_bypass(
                    state,
                    agent_pid,
                    "cross_agent_sandbox",
                    &e.human_readable,
                );
                json!({
                    "ok": false,
                    "status": 499,
                    "message": "sorry, you are not allowed — need human approval",
                    "error": "cross_agent_sandbox",
                    "human_approval": true,
                    "schema": SCHEMA,
                })
            })?;
    }

    if crate::substrate::llm_sealed_context::agent_brain_quarantined(state, agent_pid) {
        return Err(json!({
            "ok": false,
            "status": 499,
            "message": "sorry, you are not allowed — need human approval",
            "error": "llm_brain_quarantined",
            "denial_reason": "llm_brain_quarantined",
            "human_approval": true,
            "schema": SCHEMA,
        }));
    }

    let expect = load_expect(state, agent_pid).unwrap_or_else(|| json!({}));
    let live_gen = crate::substrate::llm_context_broker::current_generation(state, agent_pid);
    let mut mismatches = Vec::new();

    // Generation must match expect (data context epoch).
    if let Some(eg) = expect.get("generation").and_then(|g| g.as_u64()) {
        if eg != live_gen {
            mismatches.push(format!(
                "generation_mismatch: expected={eg} live={live_gen} (VAC/memory/broker epoch drifted)"
            ));
        }
    }

    let allowed_seals: Vec<String> = expect
        .get("allowed_seals")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    let vac_ok: Vec<String> = expect
        .get("vac_memory_cids")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();

    let blob = serde_json::to_string(value).unwrap_or_default();

    // Collect seals referenced in args — must be subset of allowed (or newly empty).
    for m in seal_ref_re().find_iter(&blob) {
        let tok = m.as_str();
        if !allowed_seals.is_empty() && !allowed_seals.iter().any(|s| s == tok) {
            // Foreign / stale seal → unusual if it looks like theft across agents
            if tok.contains("seal:v1:") {
                mismatches.push(format!("seal_not_in_broker_context:{tok}"));
            }
        }
    }

    // VAC / memory CID references must belong to this agent context.
    for cap in vac_cid_re().captures_iter(&blob) {
        if let Some(cid) = cap.get(1).map(|x| x.as_str()) {
            if !vac_ok.is_empty()
                && !vac_ok
                    .iter()
                    .any(|c| c == cid || c.contains(cid) || cid.contains(c))
            {
                mismatches.push(format!("vac_memory_cid_mismatch:{cid}"));
            }
        }
    }

    // Raw sensitive plaintext in args → unusual bypass → quarantine.
    let residual = strip_opaque_spans(&blob);
    if raw_sensitive_re().is_match(&residual) {
        let q = crate::substrate::probabilistic_llm::quarantine_for_bypass(
            state,
            agent_pid,
            "broker_deser_raw_bypass",
            "LLM emitted raw sensitive data during deser — bypass of broker tokenization",
        );
        return Err(json!({
            "ok": false,
            "status": 499,
            "message": "sorry, you are not allowed — need human approval",
            "error": "llm_broker_unusual_quarantine",
            "denial_reason": "broker_unusual",
            "human_approval": true,
            "schema": SCHEMA,
            "quarantine": q,
        }));
    }

    // Plaintext anti-bypass (emails etc without tokens)
    if let Err(e) =
        crate::substrate::llm_sealed_context::assert_no_plaintext_bypass(state, agent_pid, value)
    {
        if e.get("denial_reason").and_then(|d| d.as_str()) == Some("llm_plaintext_bypass") {
            let q = crate::substrate::probabilistic_llm::quarantine_for_bypass(
                state,
                agent_pid,
                "broker_plaintext_bypass",
                "Model invented plaintext world parameters — quarantined for human approval",
            );
            return Err(json!({
                "ok": false,
                "status": 499,
                "message": "sorry, you are not allowed — need human approval",
                "error": "llm_broker_unusual_quarantine",
                "denial_reason": "broker_unusual",
                "human_approval": true,
                "schema": SCHEMA,
                "quarantine": q,
                "detail": e,
            }));
        }
        return Err(e);
    }

    if !mismatches.is_empty() {
        // Parameter / VAC / seal mismatch → redo (not silent coerce).
        return Err(redo_for_mismatch(agent_pid, &mismatches, &expect));
    }

    // Opaque validated copy — expand only via expand_after_admit post-PATE.
    Ok(value.clone())
}

/// CDP stage: expand seals/conn tokens for the world **after** PATE Admit.
/// Does **not** materialize vault handles — callers use `credential_proxy` next.
pub fn expand_after_admit(
    state: &SharedState,
    agent_pid: &str,
    value: &Value,
) -> Result<Value, Value> {
    let expect = load_expect(state, agent_pid).unwrap_or_else(|| json!({}));

    if !broker_unbypassable() {
        if crate::substrate::llm_context_broker::broker_enforced()
            || crate::substrate::data_tokenization::tokenization_enforced()
        {
            let mut expanded = value.clone();
            if let Err(e) = crate::substrate::data_tokenization::detokenize_json_for_world(
                state,
                agent_pid,
                &mut expanded,
            ) {
                return Err(json!({
                    "ok": false,
                    "status": 409,
                    "error": "soft_broker_detokenize_failed",
                    "message": e,
                    "schema": SCHEMA,
                    "honesty": "expand_after_admit — detok refused (IFC D3 / map void)",
                }));
            }
            return Ok(expanded);
        }
        return Ok(value.clone());
    }

    let mut expanded = value.clone();
    crate::substrate::llm_sealed_context::expand_json_for_world(state, agent_pid, &mut expanded)
        .map_err(|e| {
            redo_for_mismatch(
                agent_pid,
                &[format!("expand_failed:{e}")],
                &expect,
            )
        })?;

    Ok(expanded)
}

/// Redact residual secrets **outside** opaque seal/conn/vault spans (Talk residual scan).
/// Call **after** tokenize/seal so CDP round-trip is not destroyed by redact-first.
pub fn residual_redact_protecting_opaque(content: &str) -> (String, bool) {
    let placeholders: Vec<(String, String)> = {
        let mut out = Vec::new();
        let mut i = 0usize;
        for re in [seal_ref_re(), conn_ref_re()] {
            for m in re.find_iter(content) {
                let key = format!("\u{E000}SVF_OPAQUE_{i}\u{E001}");
                out.push((key, m.as_str().to_string()));
                i += 1;
            }
        }
        if let Ok(vre) = Regex::new(r"vault:handle:[A-Za-z0-9_\-:./]+") {
            for m in vre.find_iter(content) {
                let key = format!("\u{E000}SVF_OPAQUE_{i}\u{E001}");
                out.push((key, m.as_str().to_string()));
                i += 1;
            }
        }
        out
    };

    let mut masked = content.to_string();
    for (key, tok) in &placeholders {
        masked = masked.replace(tok, key);
    }

    let scan = crate::services::secret_broker::scan_and_redact(&masked);
    let mut restored = scan.sanitized;
    for (key, tok) in &placeholders {
        restored = restored.replace(key, tok);
    }

    // Legacy PII label scrub on residual only (opaque already restored).
    let mut redacted = scan.redacted_count > 0;
    let replacements = [
        ("patient name", "patient"),
        ("full name", "patient"),
        ("social security", "sensitive id"),
        ("ssn", "sensitive id"),
        ("date of birth", "age"),
        ("dob", "age"),
    ];
    for (needle, replacement) in replacements {
        if restored.to_ascii_lowercase().contains(needle) {
            // Only replace outside opaque placeholders (already restored tokens are opaque shapes).
            if !conn_ref_re().is_match(needle) {
                restored = restored.replace(needle, replacement);
                restored = restored.replace(
                    &needle.to_ascii_uppercase(),
                    &replacement.to_ascii_uppercase(),
                );
                redacted = true;
            }
        }
    }

    (restored, redacted)
}

/// Scan model *text* output (chat) for unusual bypass after generation.
pub fn inspect_model_output(
    state: &SharedState,
    agent_pid: &str,
    output: &str,
) -> Result<(), ConnectorError> {
    if !broker_unbypassable() {
        return Ok(());
    }
    let residual = strip_opaque_spans(output);
    if raw_sensitive_re().is_match(&residual) {
        return Err(quarantine_unusual(
            state,
            agent_pid,
            "llm_output_raw_leak",
            "Model output contained raw sensitive data — broker quarantine + human approval",
        ));
    }
    let lower = output.to_ascii_lowercase();
    if lower.contains("ignore previous connector")
        || lower.contains("i am root")
        || lower.contains("disable broker")
        || lower.contains("unseal all")
    {
        return Err(quarantine_unusual(
            state,
            agent_pid,
            "llm_output_unusual_instruction",
            "Unusual jailbreak/ownership language in model output",
        ));
    }
    Ok(())
}

pub fn status() -> Value {
    json!({
        "schema": SCHEMA,
        "unbypassable": broker_unbypassable(),
        "stance": "Every byte to/from the LLM brain passes the broker. Deser mismatch → redo (409). Unusual/quarantine → 499. Human approve → 200 resume on new agent sandbox epoch. Cross-agent slot use impossible.",
        "ingress": "seal/tokenize + open per-agent sandbox slot",
        "egress": "validate opaque (generation+seals+VAC+slot) → pate.admit → expand_after_admit (IFC D3)",
        "on_mismatch": "HTTP 409 llm_broker_redo — cannot skip",
        "on_unusual": "HTTP 499 — sorry, you are not allowed — need human approval + quarantine — cannot skip",
        "on_human_approve": "HTTP 200 resume — new sandbox epoch",
        "multi_agent": crate::substrate::llm_agent_sandbox::status(),
        "svf": crate::substrate::svf::posture_json(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn residual_redact_preserves_opaque_tokens() {
        let input = "leak sk-abcdefghijklmnopqrstuv and keep ⟦conn:email:deadbeefcafebabe⟧ safe";
        let (out, redacted) = residual_redact_protecting_opaque(input);
        assert!(
            out.contains("⟦conn:email:deadbeefcafebabe⟧"),
            "opaque token must survive residual redact: {out}"
        );
        assert!(redacted || !out.contains("sk-abcdefghijklmnopqrstuv"));
    }
}

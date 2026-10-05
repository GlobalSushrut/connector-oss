//! Advanced sealed LLM context — full reasoning context, zero ownership.
//!
//! Higher models can still *guess* from pattern tokens. This plane goes further:
//!
//! 1. **AES-GCM seals** bound to `(agent_pid, generation)` — ciphertext is useless
//!    after quarantine bumps generation (key material changes).
//! 2. **Semantic cards** give the model *structure* enough to plan actions
//!    (kinds, roles, relations, seal refs) without plaintext ownership.
//! 3. **World egress** only unseals when broker binding is live and agent is not
//!    quarantined — otherwise the LLM brain for that agent is cryptographically dead.
//! 4. **Anti-bypass:** tool args that invent plaintext (email/url/key) instead of
//!    seal/conn tokens are refused when advanced mode is on.
//!
//! Inspired by: Presidio sandwich + vault-proxy + CaMeL data isolation, with
//! cryptographic capability binding (generation as epoch).

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use regex::Regex;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

use crate::error::ConnectorError;
use crate::state::{PlatformState, SharedState};

pub const SCHEMA: &str = "connector.llm_sealed_context.v1";
pub const SEAL_PREFIX: &str = "⟦seal:v1:";
pub const SEAL_SUFFIX: &str = "⟧";
const FOLDER: &str = "llm_sealed_context_v1";

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

/// Advanced plane: crypto seals + semantic cards + anti-bypass.
pub fn advanced_enforced() -> bool {
    if crate::services::playground::is_playground_mode()
        && !env_flag("CONNECTOR_LLM_BROKER_UNBYPASSABLE")
        && !env_flag("CONNECTOR_LLM_SEALED_CONTEXT")
        && !env_flag("CONNECTOR_LLM_ADVANCED_ISOLATION")
    {
        return false;
    }
    env_flag("CONNECTOR_LLM_SEALED_CONTEXT")
        || env_flag("CONNECTOR_LLM_ADVANCED_ISOLATION")
        || env_flag("CONNECTOR_LLM_BROKER_UNBYPASSABLE")
        || crate::substrate::llm_context_broker::broker_enforced()
}

fn master_secret() -> Vec<u8> {
    for key in [
        "CONNECTOR_LLM_SEAL_HMAC",
        "CONNECTOR_LLM_CONTEXT_HMAC",
        "CONNECTOR_PACKET_DNA_HMAC",
        "CONNECTOR_AUDIT_HMAC_KEY",
    ] {
        if let Ok(s) = std::env::var(key) {
            if !s.trim().is_empty() {
                return s.into_bytes();
            }
        }
    }
    b"connector-llm-seal-lab-fallback-do-not-use-prod".to_vec()
}

/// Epoch key: changes when quarantine bumps generation → old seals unreadable.
fn epoch_key(agent_pid: &str, generation: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"connector.llm_seal.v1|");
    hasher.update(&master_secret());
    hasher.update(b"|");
    hasher.update(agent_pid.as_bytes());
    hasher.update(b"|");
    hasher.update(generation.to_string().as_bytes());
    let out = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&out);
    key
}

fn seal_id(agent_pid: &str, generation: u64, plaintext: &[u8]) -> String {
    let h = Sha256::digest(
        format!(
            "{agent_pid}|{generation}|{}",
            URL_SAFE_NO_PAD.encode(Sha256::digest(plaintext))
        )
        .as_bytes(),
    );
    let hex = format!("{h:x}");
    hex.chars().take(16).collect()
}

/// Encrypt plaintext under agent epoch. Returns opaque `⟦seal:v1:id⟧`.
pub fn seal_bytes(
    state: &SharedState,
    agent_pid: &str,
    plaintext: &[u8],
    kind: &str,
) -> Result<String, String> {
    let generation = crate::substrate::llm_context_broker::current_generation(state, agent_pid);
    if agent_brain_quarantined(state, agent_pid) {
        return Err("llm_brain_quarantined: cannot seal for a dead agent brain".into());
    }
    let key = epoch_key(agent_pid, generation);
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| e.to_string())?;
    // 96-bit nonce from hash of content+epoch (deterministic for identical spans → coreference)
    let nonce_src = Sha256::digest(
        format!("{agent_pid}|{generation}|{}", URL_SAFE_NO_PAD.encode(plaintext)).as_bytes(),
    );
    let nonce = Nonce::from_slice(&nonce_src[..12]);
    let ct = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| format!("seal_encrypt:{e}"))?;
    let id = seal_id(agent_pid, generation, plaintext);
    let ref_tok = format!("{SEAL_PREFIX}{id}{SEAL_SUFFIX}");
    let sha_prefix: String = format!("{:x}", Sha256::digest(plaintext))
        .chars()
        .take(16)
        .collect();

    if let Ok(mut es) = state.engine_store.lock() {
        let _ = es.folder_put(
            FOLDER,
            &format!("seal:{agent_pid}:{generation}:{id}"),
            &json!({
                "schema": SCHEMA,
                "agent_pid": agent_pid,
                "generation": generation,
                "kind": kind,
                "nonce_b64": URL_SAFE_NO_PAD.encode(&nonce_src[..12]),
                "ciphertext_b64": URL_SAFE_NO_PAD.encode(&ct),
                "len": plaintext.len(),
                "sha256_prefix": sha_prefix,
            }),
        );
        // Semantic index (no plaintext): kind + length + ref for the card.
        let mut card = es
            .folder_get(FOLDER, &format!("card:{agent_pid}:{generation}"))
            .ok()
            .flatten()
            .unwrap_or_else(|| json!({"schema": SCHEMA, "entities": []}));
        let ents = card
            .as_object_mut()
            .map(|o| o.entry("entities").or_insert_with(|| json!([])))
            .and_then(|v| v.as_array_mut());
        if let Some(arr) = ents {
            let already = arr.iter().any(|e| e.get("seal") == Some(&json!(&ref_tok)));
            if !already {
                arr.push(json!({
                    "seal": ref_tok,
                    "kind": kind,
                    "bytes": plaintext.len(),
                    "role": kind,
                }));
            }
        }
        card["agent_pid"] = json!(agent_pid);
        card["generation"] = json!(generation);
        card["stance"] = json!("semantic card only — plaintext lives in seals; quarantine voids epoch key");
        let _ = es.folder_put(FOLDER, &format!("card:{agent_pid}:{generation}"), &card);
    }
    Ok(ref_tok)
}

pub fn seal_text(
    state: &SharedState,
    agent_pid: &str,
    text: &str,
    kind: &str,
) -> Result<String, String> {
    seal_bytes(state, agent_pid, text.as_bytes(), kind)
}

/// Unseal only with live epoch. Quarantine → fail (LLM brain dead for this agent).
pub fn unseal_ref(state: &SharedState, agent_pid: &str, token: &str) -> Result<Vec<u8>, String> {
    if agent_brain_quarantined(state, agent_pid) {
        return Err(
            "llm_brain_quarantined: agent epoch void — sealed data is cryptographically useless"
                .into(),
        );
    }
    let id = token
        .strip_prefix(SEAL_PREFIX)
        .and_then(|s| s.strip_suffix(SEAL_SUFFIX))
        .ok_or_else(|| "not a seal token".to_string())?;
    let generation = crate::substrate::llm_context_broker::current_generation(state, agent_pid);
    let raw = {
        let es = state.engine_store.lock().map_err(|e| e.to_string())?;
        es.folder_get(FOLDER, &format!("seal:{agent_pid}:{generation}:{id}"))
            .ok()
            .flatten()
            .ok_or_else(|| {
                "seal_not_found_for_live_generation: prior LLM seals die with quarantine".to_string()
            })?
    };
    let ct_b64 = raw
        .get("ciphertext_b64")
        .and_then(|v| v.as_str())
        .ok_or("missing ciphertext")?;
    let nonce_b64 = raw
        .get("nonce_b64")
        .and_then(|v| v.as_str())
        .ok_or("missing nonce")?;
    let ct = URL_SAFE_NO_PAD
        .decode(ct_b64)
        .map_err(|e| format!("ct_b64:{e}"))?;
    let nonce_bytes = URL_SAFE_NO_PAD
        .decode(nonce_b64)
        .map_err(|e| format!("nonce_b64:{e}"))?;
    if nonce_bytes.len() != 12 {
        return Err("bad nonce len".into());
    }
    let key = epoch_key(agent_pid, generation);
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| e.to_string())?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    cipher
        .decrypt(nonce, ct.as_ref())
        .map_err(|_| {
            "seal_decrypt_failed: epoch key mismatch — agent LLM brain quarantined or forged seal"
                .to_string()
        })
}

pub fn agent_brain_quarantined(state: &SharedState, agent_pid: &str) -> bool {
    agent_brain_quarantined_platform(state.as_ref(), agent_pid)
}

pub fn agent_brain_quarantined_platform(state: &PlatformState, agent_pid: &str) -> bool {
    let Ok(es) = state.engine_store.lock() else {
        return true;
    };
    if es
        .folder_get("agent_meta", agent_pid)
        .ok()
        .flatten()
        .and_then(|m| m.get("quarantined").and_then(|q| q.as_bool()))
        .unwrap_or(false)
    {
        return true;
    }
    es.folder_get(FOLDER, &format!("brain_dead:{agent_pid}"))
        .ok()
        .flatten()
        .and_then(|v| v.get("dead").and_then(|d| d.as_bool()))
        .unwrap_or(false)
}

/// Mark LLM brain cryptographically dead for this agent (called on quarantine).
pub fn quarantine_llm_brain(state: &SharedState, agent_pid: &str, reason: &str) {
    let gen = crate::substrate::llm_context_broker::current_generation(state, agent_pid);
    if let Ok(mut es) = state.engine_store.lock() {
        let _ = es.folder_put(
            FOLDER,
            &format!("brain_dead:{agent_pid}"),
            &json!({
                "dead": true,
                "reason": reason,
                "voided_at_generation": gen,
                "at_ms": chrono::Utc::now().timestamp_millis(),
                "effect": "all seals for prior epochs unreadable; model retains ciphertext only",
            }),
        );
        // Wipe live card so no semantic scaffolding remains for this epoch.
        let _ = es.folder_put(
            FOLDER,
            &format!("card:{agent_pid}:{gen}"),
            &json!({
                "schema": SCHEMA,
                "entities": [],
                "invalidated": true,
                "reason": reason,
            }),
        );
    }
}

/// Clear brain_dead on unquarantine *after* generation bump (fresh epoch only).
pub fn reseed_llm_brain_after_clearance(state: &SharedState, agent_pid: &str) {
    if let Ok(mut es) = state.engine_store.lock() {
        let _ = es.folder_put(
            FOLDER,
            &format!("brain_dead:{agent_pid}"),
            &json!({
                "dead": false,
                "cleared_at_ms": chrono::Utc::now().timestamp_millis(),
                "note": "new seals must be minted; old ciphertext stays dead",
            }),
        );
    }
}

/// Compile chat/tool text into sealed refs + semantic card for the model.
/// Model gets full *planning* context; never plaintext ownership.
pub fn compile_llm_view(state: &SharedState, agent_pid: &str, text: &str) -> Result<String, String> {
    if !advanced_enforced() {
        let (tok, _) = crate::substrate::data_tokenization::tokenize_for_llm(state, agent_pid, text);
        return Ok(tok);
    }
    if agent_brain_quarantined(state, agent_pid) {
        return Err("llm_brain_quarantined".into());
    }
    // First pattern-tokenize, then seal residual long plaintext paragraphs.
    let (tokenized, _) =
        crate::substrate::data_tokenization::tokenize_for_llm(state, agent_pid, text);

    // Seal any remaining non-token spans longer than 48 chars as narrative packs.
    let mut out = String::new();
    let mut buf = String::new();
    let mut chars = tokenized.chars().peekable();
    while let Some(c) = chars.next() {
        // Keep existing conn/seal tokens intact
        if c == '⟦' {
            if !buf.trim().is_empty() && buf.len() >= 48 {
                let sealed = seal_text(state, agent_pid, &buf, "narrative")?;
                out.push_str(&sealed);
                out.push(' ');
                buf.clear();
            } else {
                out.push_str(&buf);
                buf.clear();
            }
            out.push(c);
            for c2 in chars.by_ref() {
                out.push(c2);
                if c2 == '⟧' {
                    break;
                }
            }
            continue;
        }
        buf.push(c);
        if buf.len() >= 200 {
            let sealed = seal_text(state, agent_pid, &buf, "narrative")?;
            out.push_str(&sealed);
            out.push(' ');
            buf.clear();
        }
    }
    if !buf.is_empty() {
        if buf.len() >= 48 {
            let sealed = seal_text(state, agent_pid, &buf, "narrative")?;
            out.push_str(&sealed);
        } else {
            out.push_str(&buf);
        }
    }

    let card = semantic_card_json(state, agent_pid);
    Ok(format!(
        "{out}\n\n--- CONNECTOR SEMANTIC CARD (plan with this; you do not own plaintext) ---\n{card}\n--- END SEMANTIC CARD ---\n\
Rules: You may reason over kinds/roles/seal refs. You never own data. \
To act, emit only ⟦conn:…⟧ / ⟦seal:v1:…⟧ / vault:handle:… — Connector unseals if agent brain is live. \
If this agent is quarantined, seals are cryptographically dead."
    ))
}

pub fn semantic_card_json(state: &SharedState, agent_pid: &str) -> String {
    let generation = crate::substrate::llm_context_broker::current_generation(state, agent_pid);
    let Ok(es) = state.engine_store.lock() else {
        return "{}".into();
    };
    es.folder_get(FOLDER, &format!("card:{agent_pid}:{generation}"))
        .ok()
        .flatten()
        .map(|v| v.to_string())
        .unwrap_or_else(|| "{}".into())
}

fn plaintext_leak_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(
            r"(?i)(?:\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b|https?://[^\s]+|\b(?:sk|pk|rk)[-_]?[A-Za-z0-9]{16,}\b)",
        )
        .expect("leak re")
    })
}

/// Refuse tool/world args where the model invents plaintext instead of seals/tokens.
pub fn assert_no_plaintext_bypass(
    state: &SharedState,
    agent_pid: &str,
    value: &Value,
) -> Result<(), Value> {
    if !advanced_enforced() {
        return Ok(());
    }
    if agent_brain_quarantined(state, agent_pid) {
        return Err(json!({
            "error": "llm_brain_quarantined",
            "denial_reason": "llm_brain_quarantined",
            "message": "Agent LLM brain is quarantined — sealed context is useless; no world effects",
        }));
    }
    fn walk(v: &Value, bad: &mut Vec<String>) {
        match v {
            Value::String(s) => {
                // Allowed opaque forms (model may pass these through).
                if s.contains(SEAL_PREFIX)
                    || s.contains("⟦conn:")
                    || s.starts_with("vault:handle:")
                    || s.starts_with("ctx_tok_")
                {
                    return;
                }
                if plaintext_leak_re().is_match(s) {
                    bad.push(format!("plaintext_bypass:{}", &s[..s.len().min(48)]));
                }
            }
            Value::Array(a) => a.iter().for_each(|x| walk(x, bad)),
            Value::Object(o) => o.values().for_each(|x| walk(x, bad)),
            _ => {}
        }
    }
    let mut bad = Vec::new();
    walk(value, &mut bad);
    if !bad.is_empty() {
        return Err(json!({
            "error": "llm_plaintext_bypass_refused",
            "denial_reason": "llm_plaintext_bypass",
            "message": "Higher models cannot invent real emails/URLs/keys for tools — use Connector seals/tokens only",
            "hits": bad,
        }));
    }
    Ok(())
}

/// Expand seals + conn tokens for world egress (tools/robots/APIs).
pub fn expand_for_world(
    state: &SharedState,
    agent_pid: &str,
    text: &str,
) -> Result<String, String> {
    if agent_brain_quarantined(state, agent_pid) {
        return Err("llm_brain_quarantined: cannot expand".into());
    }
    let mut out = text.to_string();
    // Unseal all seal refs
    let re = Regex::new(r"⟦seal:v1:[a-f0-9]+⟧").map_err(|e| e.to_string())?;
    let owned = out.clone();
    for m in re.find_iter(&owned) {
        let tok = m.as_str();
        let plain = unseal_ref(state, agent_pid, tok)?;
        let s = String::from_utf8_lossy(&plain);
        out = out.replace(tok, &s);
    }
    crate::substrate::data_tokenization::detokenize_for_world(state, agent_pid, &out)
}

pub fn expand_json_for_world(
    state: &SharedState,
    agent_pid: &str,
    value: &mut Value,
) -> Result<usize, String> {
    let mut n = 0;
    match value {
        Value::String(s) => {
            if s.contains(SEAL_PREFIX) || s.contains("⟦conn:") {
                *s = expand_for_world(state, agent_pid, s)?;
                n += 1;
            }
        }
        Value::Array(a) => {
            for v in a.iter_mut() {
                n += expand_json_for_world(state, agent_pid, v)?;
            }
        }
        Value::Object(o) => {
            for (_k, v) in o.iter_mut() {
                n += expand_json_for_world(state, agent_pid, v)?;
            }
        }
        _ => {}
    }
    Ok(n)
}

/// Fail talk if brain is quarantined under advanced mode.
pub fn assert_brain_live_for_talk(
    state: &SharedState,
    agent_pid: &str,
) -> Result<(), ConnectorError> {
    if !advanced_enforced() {
        return Ok(());
    }
    if agent_brain_quarantined(state, agent_pid) {
        return Err(
            crate::substrate::probabilistic_llm::require_human_for_rule(
                state,
                agent_pid,
                "llm_brain_quarantined",
                "Agent LLM brain quarantined — sealed context epoch is void; human unquarantine required before talk",
            ),
        );
    }
    Ok(())
}

pub fn status() -> Value {
    json!({
        "schema": SCHEMA,
        "enforced": advanced_enforced(),
        "stance": "Probabilistic model gets semantic cards + seal refs (full planning context) but never owns plaintext. Quarantine voids epoch keys — LLM brain for that agent is cryptographically dead.",
        "anti_bypass": "tool args with invented emails/URLs/keys refused",
        "crypto": "AES-256-GCM per (agent_pid, generation)",
        "inspired_by": ["Presidio sandwich", "vault-proxy", "CaMeL", "capability epochs"],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_key_changes_with_generation() {
        let a = epoch_key("agent-1", 1);
        let b = epoch_key("agent-1", 2);
        assert_ne!(a, b);
    }

    #[test]
    fn seal_token_shape() {
        let t = format!("{SEAL_PREFIX}abcd1234ef567890{SEAL_SUFFIX}");
        assert!(t.starts_with("⟦seal:v1:"));
        assert!(t.ends_with("⟧"));
    }
}

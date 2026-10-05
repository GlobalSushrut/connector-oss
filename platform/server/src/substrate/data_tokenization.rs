//! Data tokenization plane — LLM sees structure, never owns real bytes.
//!
//! Technique (proven in production / research):
//! - Presidio-style reversible anonymize sandwich (tokenize → LLM → detokenize)
//! - Vault-proxy / AWS asm-exec: opaque refs; plaintext only outside the model
//! - CaMeL / Dual-LLM: data plane has no world authority without Connector
//!
//! Maps are **agent-scoped** and bound to LLM context broker **generation**.
//! Quarantine / revoke voids the map — leftover model tokens cannot hydrate
//! tools, chat, APIs, or robots.

use regex::Regex;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::OnceLock;

use crate::state::SharedState;

pub const SCHEMA: &str = "connector.llm_data_tokenization.v1";
/// Opaque token shown to the model (stable shape for coreference).
pub const TOKEN_OPEN: &str = "⟦conn:";
pub const TOKEN_CLOSE: &str = "⟧";
const FOLDER: &str = "llm_data_tokens_v1";

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

/// On with explicit flag or when identity broker is enforced.
pub fn tokenization_enforced() -> bool {
    env_flag("CONNECTOR_LLM_DATA_TOKENIZE")
        || crate::substrate::llm_context_broker::broker_enforced()
}

fn email_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"(?i)\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b").expect("email re")
    })
}

fn phone_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"(?:\+?\d{1,3}[\s\-.]?)?(?:\(?\d{3}\)?[\s\-.]?)?\d{3}[\s\-.]?\d{4}\b")
            .expect("phone re")
    })
}

fn url_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r#"https?://[^\s"'<>]+"#).expect("url re"))
}

fn api_key_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"(?i)\b(?:sk|pk|rk|key|token|bearer)[-_]?[A-Za-z0-9]{16,}\b")
            .expect("api key re")
    })
}

fn vault_handle_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"vault:handle:[A-Za-z0-9_\-:./]+").expect("vault re"))
}

fn ipv4_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
            .expect("ipv4 re")
    })
}

fn long_secret_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    // High-entropy-ish blobs the model should not own.
    R.get_or_init(|| Regex::new(r"\b[A-Za-z0-9+/_=-]{32,}\b").expect("blob re"))
}

fn map_key(agent_pid: &str, generation: u64) -> String {
    format!("{agent_pid}:gen:{generation}")
}

fn load_map(state: &SharedState, agent_pid: &str, generation: u64) -> HashMap<String, String> {
    let Ok(es) = state.engine_store.lock() else {
        return HashMap::new();
    };
    let Some(v) = es
        .folder_get(FOLDER, &map_key(agent_pid, generation))
        .ok()
        .flatten()
    else {
        return HashMap::new();
    };
    let mut out = HashMap::new();
    if let Some(obj) = v.get("tokens").and_then(|t| t.as_object()) {
        for (tok, real) in obj {
            if let Some(s) = real.as_str() {
                out.insert(tok.clone(), s.to_string());
            }
        }
    }
    out
}

fn save_map(state: &SharedState, agent_pid: &str, generation: u64, map: &HashMap<String, String>) {
    let tokens: serde_json::Map<String, Value> = map
        .iter()
        .map(|(k, v)| (k.clone(), Value::String(v.clone())))
        .collect();
    if let Ok(mut es) = state.engine_store.lock() {
        let _ = es.folder_put(
            FOLDER,
            &map_key(agent_pid, generation),
            &json!({
                "schema": SCHEMA,
                "agent_pid": agent_pid,
                "generation": generation,
                "tokens": tokens,
                "updated_at_ms": chrono::Utc::now().timestamp_millis(),
                "stance": "agent-scoped map — LLM cannot detokenize; quarantine voids generation",
            }),
        );
    }
}

fn mint_token_id(agent_pid: &str, generation: u64, plaintext: &str, kind: &str) -> String {
    let h = Sha256::digest(format!("{agent_pid}|{generation}|{kind}|{plaintext}").as_bytes());
    let hex = format!("{h:x}");
    format!("{TOKEN_OPEN}{kind}:{}{TOKEN_CLOSE}", &hex[..hex.len().min(12)])
}

/// Replace sensitive spans with opaque tokens; persist map under agent + generation.
/// Returns (tokenized_text, how_many_spans). Idempotent for already-tokenized text.
pub fn tokenize_for_llm(state: &SharedState, agent_pid: &str, text: &str) -> (String, usize) {
    if !tokenization_enforced() || text.is_empty() {
        return (text.to_string(), 0);
    }
    let generation = crate::substrate::llm_context_broker::current_generation(state, agent_pid);
    let mut map = load_map(state, agent_pid, generation);
    // Reverse lookup for stable coreference (same real → same token).
    let mut reverse: HashMap<String, String> = map
        .iter()
        .map(|(tok, real)| (real.clone(), tok.clone()))
        .collect();

    let mut count = 0usize;
    let mut out = text.to_string();

    let mut replace_all = |re: &Regex, kind: &str, out: &mut String, count: &mut usize| {
        let owned = out.clone();
        for m in re.find_iter(&owned) {
            let real = m.as_str();
            if real.contains(TOKEN_OPEN) {
                continue;
            }
            // Skip short numeric noise for phone-like matches that are years etc.
            if kind == "phone" && real.chars().filter(|c| c.is_ascii_digit()).count() < 7 {
                continue;
            }
            if kind == "blob" && real.contains('@') {
                continue;
            }
            let tok = if let Some(existing) = reverse.get(real) {
                existing.clone()
            } else {
                let t = mint_token_id(agent_pid, generation, real, kind);
                map.insert(t.clone(), real.to_string());
                reverse.insert(real.to_string(), t.clone());
                *count += 1;
                t
            };
            *out = out.replacen(real, &tok, 1);
        }
    };

    replace_all(vault_handle_re(), "vault", &mut out, &mut count);
    replace_all(api_key_re(), "key", &mut out, &mut count);
    replace_all(email_re(), "email", &mut out, &mut count);
    replace_all(url_re(), "url", &mut out, &mut count);
    replace_all(ipv4_re(), "ip", &mut out, &mut count);
    replace_all(phone_re(), "phone", &mut out, &mut count);
    replace_all(long_secret_re(), "blob", &mut out, &mut count);

    if count > 0 || !map.is_empty() {
        save_map(state, agent_pid, generation, &map);
    }
    (out, count)
}

/// Restore real bytes from opaque tokens. Only for Connector world egress.
/// Fails closed if tokenization is enforced and tokens exist without a live map
/// (wrong generation / quarantined → useless).
pub fn detokenize_for_world(
    state: &SharedState,
    agent_pid: &str,
    text: &str,
) -> Result<String, String> {
    if text.is_empty() || !text.contains(TOKEN_OPEN) {
        return Ok(text.to_string());
    }
    // ARC D3: when IFC on, detok only post-Admit.
    if let Err(e) = crate::substrate::arc::ifc::assert_detokenize_post_admit(agent_pid) {
        return Err(e.human_readable);
    }
    let generation = crate::substrate::llm_context_broker::current_generation(state, agent_pid);
    let map = load_map(state, agent_pid, generation);
    if map.is_empty() && tokenization_enforced() {
        return Err(
            "data_tokenization: opaque tokens present but agent map void (quarantined, wrong generation, or never minted) — LLM view is useless without Connector detokenization"
                .into(),
        );
    }
    let mut out = text.to_string();
    // Longest tokens first to avoid partial replace issues.
    let mut pairs: Vec<_> = map.into_iter().collect();
    pairs.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
    for (tok, real) in pairs {
        out = out.replace(&tok, &real);
    }
    if tokenization_enforced() && out.contains(TOKEN_OPEN) {
        return Err(
            "data_tokenization: unresolved conn tokens remain — refuse world egress".into(),
        );
    }
    Ok(out)
}

/// Walk JSON values: tokenize all strings for LLM-bound payloads.
pub fn tokenize_json_for_llm(state: &SharedState, agent_pid: &str, value: &mut Value) -> usize {
    if !tokenization_enforced() {
        return 0;
    }
    let mut n = 0;
    match value {
        Value::String(s) => {
            let (t, c) = tokenize_for_llm(state, agent_pid, s);
            *s = t;
            n += c;
        }
        Value::Array(arr) => {
            for v in arr.iter_mut() {
                n += tokenize_json_for_llm(state, agent_pid, v);
            }
        }
        Value::Object(map) => {
            for (_k, v) in map.iter_mut() {
                n += tokenize_json_for_llm(state, agent_pid, v);
            }
        }
        _ => {}
    }
    n
}

/// Walk JSON: detokenize strings before tool/world dispatch.
pub fn detokenize_json_for_world(
    state: &SharedState,
    agent_pid: &str,
    value: &mut Value,
) -> Result<usize, String> {
    let mut n = 0usize;
    match value {
        Value::String(s) => {
            if s.contains(TOKEN_OPEN) {
                *s = detokenize_for_world(state, agent_pid, s)?;
                n += 1;
            }
        }
        Value::Array(arr) => {
            for v in arr.iter_mut() {
                n += detokenize_json_for_world(state, agent_pid, v)?;
            }
        }
        Value::Object(map) => {
            for (_k, v) in map.iter_mut() {
                n += detokenize_json_for_world(state, agent_pid, v)?;
            }
        }
        _ => {}
    }
    Ok(n)
}

/// Drop agent maps (all generations for pid). Called with broker invalidate.
pub fn invalidate_agent(state: &SharedState, agent_pid: &str, reason: &str) {
    let Ok(mut es) = state.engine_store.lock() else {
        return;
    };
    // Mark a tombstone; generation bump makes old keys unreachable for live ops.
    let gen = es
        .folder_get("llm_context_broker_v1", &format!("gen:{agent_pid}"))
        .ok()
        .flatten()
        .and_then(|v| v.get("generation").and_then(|g| g.as_u64()))
        .unwrap_or(0);
    let _ = es.folder_put(
        FOLDER,
        &format!("tombstone:{agent_pid}:{gen}"),
        &json!({
            "schema": SCHEMA,
            "agent_pid": agent_pid,
            "voided_generation": gen,
            "reason": reason,
            "effect": "prior_data_tokens_useless_without_connector",
            "at_ms": chrono::Utc::now().timestamp_millis(),
        }),
    );
    // Overwrite current map with empty so detokenize fail-closes.
    let _ = es.folder_put(
        FOLDER,
        &map_key(agent_pid, gen),
        &json!({
            "schema": SCHEMA,
            "agent_pid": agent_pid,
            "generation": gen,
            "tokens": {},
            "invalidated": true,
            "reason": reason,
        }),
    );
}

pub fn status() -> Value {
    json!({
        "schema": SCHEMA,
        "enforced": tokenization_enforced(),
        "token_shape": format!("{TOKEN_OPEN}kind:hex{TOKEN_CLOSE}"),
        "inspired_by": [
            "Presidio reversible anonymize sandwich",
            "Vault-proxy / Infisical Agent Vault / OpenLegion $CRED",
            "AWS asm-exec secret refs",
            "Google CaMeL / Dual-LLM data isolation",
        ],
        "stance": "LLM gets tokenized packets for reasoning; ownership + detokenization stay in Connector agent secrets",
        "on_quarantine": "generation bump voids maps — model tokens cannot hydrate tools/robots/APIs",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_shape_stable() {
        let t = mint_token_id("a1", 0, "alice@example.com", "email");
        assert!(t.starts_with("⟦conn:email:"));
        assert!(t.ends_with("⟧"));
        assert!(!t.contains('@'));
    }

    #[test]
    fn regex_finds_email() {
        let s = "Contact alice@example.com now";
        assert!(email_re().is_match(s));
    }
}

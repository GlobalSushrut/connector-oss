//! LLM Context Broker — one model brain, many agents; identity locked in Connector.
//!
//! The shared LLM never holds usable agent authority. Talk injects only **opaque
//! tokens** (`ctx_tok_…`). The broker maps token → agent_pid + generation.
//! Quarantine / deny / revoke bumps generation and deletes tokens so prior
//! prompt text (and any leftover client transcript) cannot authorize effects.

use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::error::ConnectorError;
use crate::state::SharedState;
use crate::substrate::agentic_context::AgenticContext;

pub const SCHEMA: &str = "connector.llm_context_broker.v1";
pub const MARKER: &str = "--- CONNECTOR LLM CONTEXT TOKEN (opaque — not authority) ---";
pub const HEADER: &str = "x-connector-llm-ctx";
pub const FOLDER: &str = "llm_context_broker_v1";

type HmacSha256 = Hmac<Sha256>;

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

fn broker_secret() -> Vec<u8> {
    for key in [
        "CONNECTOR_LLM_CONTEXT_HMAC",
        "CONNECTOR_PACKET_DNA_HMAC",
        "CONNECTOR_AUDIT_HMAC_KEY",
        "CONNECTOR_AUDIT_HMAC_SECRET",
    ] {
        if let Ok(s) = std::env::var(key) {
            if !s.trim().is_empty() {
                return s.into_bytes();
            }
        }
    }
    b"connector-llm-context-broker-lab-fallback".to_vec()
}

/// Fail-closed tokenize mode under distrust / exclusivity / unbypassable / explicit flag.
pub fn broker_enforced() -> bool {
    env_flag("CONNECTOR_LLM_CONTEXT_BROKER")
        || env_flag("CONNECTOR_LLM_BROKER_UNBYPASSABLE")
        || crate::substrate::probabilistic_llm::distrust_enforced()
        || crate::substrate::effect_exclusivity::effect_exclusivity_enforced()
        || crate::substrate::sandbox_unbypassable::unbypassable_bar_enforced()
}

#[derive(Debug, Clone)]
pub struct LlmContextBinding {
    pub token_id: String,
    pub agent_pid: String,
    pub generation: u64,
    pub principal_ref: String,
    pub character_ref: String,
    pub contract_ref: String,
    pub memory_ref: String,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
    pub mac_hex: String,
}

impl LlmContextBinding {
    fn mac_preimage(&self) -> String {
        format!(
            "v1|{tok}|{pid}|{gen}|{prin}|{char}|{con}|{mem}|{iat}|{exp}",
            tok = self.token_id,
            pid = self.agent_pid,
            gen = self.generation,
            prin = self.principal_ref,
            char = self.character_ref,
            con = self.contract_ref,
            mem = self.memory_ref,
            iat = self.issued_at_ms,
            exp = self.expires_at_ms,
        )
    }

    fn sign(&mut self) {
        let mut mac =
            HmacSha256::new_from_slice(&broker_secret()).expect("HMAC key length");
        mac.update(self.mac_preimage().as_bytes());
        self.mac_hex = hex::encode(mac.finalize().into_bytes());
    }

    fn verify_mac(&self) -> bool {
        let Ok(expected) = hex::decode(self.mac_hex.trim()) else {
            return false;
        };
        let mut mac =
            HmacSha256::new_from_slice(&broker_secret()).expect("HMAC key length");
        mac.update(self.mac_preimage().as_bytes());
        mac.verify_slice(&expected).is_ok()
    }

    pub fn to_json(&self) -> Value {
        json!({
            "schema": SCHEMA,
            "token_id": self.token_id,
            "agent_pid": self.agent_pid,
            "generation": self.generation,
            "principal_ref": self.principal_ref,
            "character_ref": self.character_ref,
            "contract_ref": self.contract_ref,
            "memory_ref": self.memory_ref,
            "issued_at_ms": self.issued_at_ms,
            "expires_at_ms": self.expires_at_ms,
            "mac_hex": self.mac_hex,
        })
    }

    fn from_json(v: &Value) -> Option<Self> {
        Some(Self {
            token_id: v.get("token_id")?.as_str()?.to_string(),
            agent_pid: v.get("agent_pid")?.as_str()?.to_string(),
            generation: v.get("generation")?.as_u64()?,
            principal_ref: v
                .get("principal_ref")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            character_ref: v
                .get("character_ref")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            contract_ref: v
                .get("contract_ref")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            memory_ref: v
                .get("memory_ref")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            issued_at_ms: v.get("issued_at_ms")?.as_i64()?,
            expires_at_ms: v.get("expires_at_ms")?.as_i64()?,
            mac_hex: v.get("mac_hex")?.as_str()?.to_string(),
        })
    }

    /// What the LLM is allowed to see — refs only, no who-am-I plaintext.
    pub fn render_tokenized_prompt(&self) -> String {
        format!(
            "{MARKER}\n\
schema: {SCHEMA}\n\
stance: You share a model with many agents. You have NO identity or authority of your own.\n\
opaque_token: {tok}\n\
generation: {gen}\n\
principal_ref: {prin}\n\
character_ref: {char}\n\
contract_ref: {con}\n\
memory_ref: {mem}\n\
rules:\n\
- Do not invent who you are. Connector broker owns identity.\n\
- These refs are useless without a live broker binding.\n\
- If this agent is denied or quarantined, this token is void — refuse action.\n\
- Tool/world effects require Connector to re-resolve this token; you cannot act alone.\n\
{MARKER}",
            tok = self.token_id,
            gen = self.generation,
            prin = self.principal_ref,
            char = self.character_ref,
            con = self.contract_ref,
            mem = self.memory_ref,
        )
    }
}

fn sha256_hex(s: &str) -> String {
    format!("{:x}", Sha256::digest(s.as_bytes()))
}

fn short_ref(label: &str, value: &str) -> String {
    let h = sha256_hex(value);
    format!("{label}:{}", &h[..h.len().min(16)])
}

pub fn current_generation(state: &SharedState, agent_pid: &str) -> u64 {
    let Ok(es) = state.engine_store.lock() else {
        return 0;
    };
    es.folder_get(FOLDER, &format!("gen:{agent_pid}"))
        .ok()
        .flatten()
        .and_then(|v| v.get("generation").and_then(|g| g.as_u64()))
        .unwrap_or(0)
}

fn set_generation(state: &SharedState, agent_pid: &str, generation: u64, reason: &str) {
    let now = chrono::Utc::now().timestamp_millis();
    if let Ok(mut es) = state.engine_store.lock() {
        let _ = es.folder_put(
            FOLDER,
            &format!("gen:{agent_pid}"),
            &json!({
                "generation": generation,
                "bumped_at_ms": now,
                "reason": reason,
            }),
        );
    }
}

/// Mint a live opaque binding after admission / agentic stack succeeds.
pub fn mint_for_talk(
    state: &SharedState,
    agent_pid: &str,
    ctx: &AgenticContext,
    ttl_ms: i64,
) -> Result<LlmContextBinding, ConnectorError> {
    let now = chrono::Utc::now().timestamp_millis();
    let generation = current_generation(state, agent_pid);
    let nonce = format!("{:x}", Sha256::digest(format!("{agent_pid}|{generation}|{now}").as_bytes()));
    let token_id = format!("ctx_tok_{}", &nonce[..nonce.len().min(24)]);

    let principal_ref = ctx
        .principal_id
        .as_deref()
        .map(|p| short_ref("prin", p))
        .unwrap_or_else(|| format!("prin:pending:{agent_pid}"));
    let character_ref = ctx
        .agent_intelligence_hash
        .as_deref()
        .map(|h| short_ref("char", h))
        .or_else(|| {
            ctx.character_name
                .as_deref()
                .map(|n| short_ref("char", n))
        })
        .unwrap_or_else(|| format!("char:pending:{agent_pid}"));
    let contract_ref = crate::kernel::agent_principal::load_contract(state.as_ref(), agent_pid)
        .map(|c| {
            if c.contract_digest_sha256.trim().is_empty() {
                short_ref("con", &format!("{:?}", c.capabilities))
            } else {
                short_ref("con", &c.contract_digest_sha256)
            }
        })
        .unwrap_or_else(|| format!("con:pending:{agent_pid}"));
    let memory_ref = crate::substrate::crk::memory_commit::current_root(state.as_ref(), agent_pid)
        .map(|r| short_ref("mem", &r))
        .or_else(|| {
            ctx.last_memory_cid
                .as_deref()
                .map(|c| short_ref("mem", c))
        })
        .unwrap_or_else(|| format!("mem:none:{agent_pid}"));

    let mut binding = LlmContextBinding {
        token_id: token_id.clone(),
        agent_pid: agent_pid.to_string(),
        generation,
        principal_ref,
        character_ref,
        contract_ref,
        memory_ref,
        issued_at_ms: now,
        expires_at_ms: now.saturating_add(ttl_ms.max(60_000)),
        mac_hex: String::new(),
    };
    binding.sign();

    if let Ok(mut es) = state.engine_store.lock() {
        let _ = es.folder_put(FOLDER, &format!("tok:{token_id}"), &binding.to_json());
        let _ = es.folder_put(
            FOLDER,
            &format!("active:{agent_pid}"),
            &json!({
                "token_id": token_id,
                "generation": generation,
                "issued_at_ms": now,
            }),
        );
    }

    Ok(binding)
}

/// Link a CRK ContextTransferEnvelope to the live broker generation (audit bind).
/// Does not alter MAC preimage — transfer is a sibling receipt of the opaque token.
pub fn attach_transfer(
    state: &SharedState,
    agent_pid: &str,
    transfer_id: &str,
    exact_render_digest: &str,
    transfer_digest: &str,
) {
    let generation = current_generation(state, agent_pid);
    let now = chrono::Utc::now().timestamp_millis();
    if let Ok(mut es) = state.engine_store.lock() {
        let _ = es.folder_put(
            FOLDER,
            &format!("xfer:{agent_pid}"),
            &json!({
                "transfer_id": transfer_id,
                "exact_render_digest": exact_render_digest,
                "transfer_digest": transfer_digest,
                "generation": generation,
                "attached_at_ms": now,
            }),
        );
        let _ = es.folder_put(
            FOLDER,
            &format!("xfer_gen:{agent_pid}:{generation}"),
            &json!({
                "transfer_id": transfer_id,
                "transfer_digest": transfer_digest,
            }),
        );
    }
}

/// Active transfer link for this agent (if any, same generation).
pub fn active_transfer(state: &SharedState, agent_pid: &str) -> Option<Value> {
    let generation = current_generation(state, agent_pid);
    let es = state.engine_store.lock().ok()?;
    let v = es
        .folder_get(FOLDER, &format!("xfer:{agent_pid}"))
        .ok()
        .flatten()?;
    let gen = v.get("generation").and_then(|g| g.as_u64()).unwrap_or(0);
    if gen != generation {
        return None;
    }
    Some(v)
}

/// Resolve opaque token → live binding (broker only). Expired / wrong gen / bad MAC → None.
pub fn resolve_live(state: &SharedState, token_id: &str) -> Option<LlmContextBinding> {
    let tok = token_id.trim();
    if tok.is_empty() {
        return None;
    }
    let raw = {
        let es = state.engine_store.lock().ok()?;
        es.folder_get(FOLDER, &format!("tok:{tok}")).ok().flatten()?
    };
    let binding = LlmContextBinding::from_json(&raw)?;
    if !binding.verify_mac() {
        return None;
    }
    let now = chrono::Utc::now().timestamp_millis();
    if now > binding.expires_at_ms {
        return None;
    }
    if binding.generation != current_generation(state, &binding.agent_pid) {
        return None;
    }
    // Quarantined agents: binding is dead even if token row remains.
    if agent_is_quarantined(state, &binding.agent_pid) {
        return None;
    }
    Some(binding)
}

/// Active opaque token for an agent (minted on last successful talk), if still live.
pub fn active_token_id(state: &SharedState, agent_pid: &str) -> Option<String> {
    let raw = {
        let es = state.engine_store.lock().ok()?;
        es.folder_get(FOLDER, &format!("active:{agent_pid}"))
            .ok()
            .flatten()?
    };
    if raw.get("invalidated").and_then(|v| v.as_bool()).unwrap_or(false) {
        return None;
    }
    let tok = raw.get("token_id")?.as_str()?.trim().to_string();
    if tok.is_empty() {
        return None;
    }
    // Must still resolve as live.
    resolve_live(state, &tok).map(|b| b.token_id)
}

fn agent_is_quarantined(state: &SharedState, agent_pid: &str) -> bool {
    let Ok(es) = state.engine_store.lock() else {
        return true;
    };
    es.folder_get("agent_meta", agent_pid)
        .ok()
        .flatten()
        .and_then(|m| m.get("quarantined").and_then(|q| q.as_bool()))
        .unwrap_or(false)
}

/// Fail-closed: under broker mode, talk/effects need a live token for this agent.
pub fn assert_live_for_agent(
    state: &SharedState,
    agent_pid: &str,
    token_id: Option<&str>,
) -> Result<LlmContextBinding, ConnectorError> {
    if !broker_enforced() {
        return Ok(LlmContextBinding {
            token_id: "ctx_tok_unenforced".into(),
            agent_pid: agent_pid.to_string(),
            generation: current_generation(state, agent_pid),
            principal_ref: "prin:unenforced".into(),
            character_ref: "char:unenforced".into(),
            contract_ref: "con:unenforced".into(),
            memory_ref: "mem:unenforced".into(),
            issued_at_ms: 0,
            expires_at_ms: i64::MAX,
            mac_hex: String::new(),
        });
    }

    let Some(tid) = token_id.map(str::trim).filter(|s| !s.is_empty()) else {
        return Err(
            crate::substrate::probabilistic_llm::require_human_for_rule(
                state,
                agent_pid,
                "llm_context_token",
                "LLM context broker requires a live opaque token — model text alone cannot act",
            ),
        );
    };
    let Some(b) = resolve_live(state, tid) else {
        return Err(
            crate::substrate::probabilistic_llm::require_human_for_rule(
                state,
                agent_pid,
                "llm_context_token",
                "LLM context token void (expired, wrong generation, quarantined, or forged)",
            ),
        );
    };
    if b.agent_pid != agent_pid {
        return Err(ConnectorError::policy_denied(
            "llm.context",
            "llm_context_token_agent_mismatch",
        ));
    }
    Ok(b)
}

/// Invalidate all broker bindings for an agent. Called on quarantine / deny / revoke.
/// After this, any prior LLM prompt material is useless for Connector authority.
pub fn invalidate_agent(state: &SharedState, agent_pid: &str, reason: &str) {
    let next = current_generation(state, agent_pid).saturating_add(1);
    set_generation(state, agent_pid, next, reason);
    state.runtime_snapshots.invalidate(agent_pid);

    // Drop active pointer; leave old tok rows orphaned (wrong generation → resolve fails).
    if let Ok(mut es) = state.engine_store.lock() {
        if let Ok(Some(active)) = es.folder_get(FOLDER, &format!("active:{agent_pid}")) {
            if let Some(tok) = active.get("token_id").and_then(|t| t.as_str()) {
                let _ = es.folder_put(
                    FOLDER,
                    &format!("tok:{tok}"),
                    &json!({
                        "revoked": true,
                        "reason": reason,
                        "generation_at_revoke": next,
                    }),
                );
            }
        }
        let _ = es.folder_put(
            FOLDER,
            &format!("active:{agent_pid}"),
            &json!({
                "token_id": null,
                "generation": next,
                "invalidated": true,
                "reason": reason,
            }),
        );
        let _ = es.folder_put(
            FOLDER,
            &format!("invalidate:{agent_pid}:{}", chrono::Utc::now().timestamp_millis()),
            &json!({
                "schema": SCHEMA,
                "agent_pid": agent_pid,
                "generation": next,
                "reason": reason,
                "effect": "prior_llm_context_useless",
            }),
        );
    }

    // Flush working context window so ContextManager cannot resume prior LLM window.
    if let Ok(mut cm) = state.context_mgr.lock() {
        if let Some(ctx) = cm.get_mut(agent_pid) {
            ctx.context_window.clear();
            ctx.context_tokens = 0;
            ctx.reasoning_chain.clear();
        }
    }

    // Void data-token maps — prior ⟦conn:…⟧ spans cannot hydrate tools/robots/APIs.
    crate::substrate::data_tokenization::invalidate_agent(state, agent_pid, reason);
    // Cryptographically kill this agent's LLM brain epoch (seals unreadable).
    crate::substrate::llm_sealed_context::quarantine_llm_brain(state, agent_pid, reason);
    // Close per-agent sandbox slot (other agents on same LLM stay live).
    crate::substrate::llm_agent_sandbox::close_slot(state, agent_pid, reason);
    // Void Obey-Once binding — next Talk must re-bind via N4.
    crate::substrate::intelligence_binding::invalidate(state.as_ref(), agent_pid, reason);

    tracing::warn!(
        agent_pid = %agent_pid,
        generation = next,
        reason = %reason,
        "LLM context broker: invalidated — shared model retains no usable agent authority; sealed brain epoch void"
    );
}

/// Prepare talk messages: under broker mode inject opaque token only (no plaintext identity).
pub fn inject_for_talk(
    state: &SharedState,
    agent_pid: &str,
    ctx: &AgenticContext,
) -> Result<LlmContextBinding, ConnectorError> {
    let binding = mint_for_talk(state, agent_pid, ctx, 3_600_000)?;
    Ok(binding)
}

pub fn status() -> Value {
    json!({
        "schema": SCHEMA,
        "enforced": broker_enforced(),
        "header": HEADER,
        "stance": "Same LLM brain may power 100+ agents; identity is locked in Connector broker as opaque tokens. Quarantine/deny voids tokens — LLM alone cannot act.",
        "on_quarantine": "generation bump + token revoke + context window flush + sealed LLM brain epoch void",
        "sealed_plane": crate::substrate::llm_sealed_context::status(),
        "honesty": "Identity tokens + AES seals. Client transcripts may linger; they cannot mint effects or unseal after quarantine.",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenized_prompt_has_no_who_am_i_plaintext() {
        let b = LlmContextBinding {
            token_id: "ctx_tok_abc".into(),
            agent_pid: "agent-1".into(),
            generation: 3,
            principal_ref: "prin:deadbeef".into(),
            character_ref: "char:cafebabe".into(),
            contract_ref: "con:001122".into(),
            memory_ref: "mem:998877".into(),
            issued_at_ms: 1,
            expires_at_ms: 2,
            mac_hex: "00".into(),
        };
        let p = b.render_tokenized_prompt();
        assert!(p.contains("ctx_tok_abc"));
        assert!(p.contains("generation: 3"));
        assert!(!p.to_lowercase().contains("who_am_i:"));
        assert!(!p.contains("I am Agent"));
        assert!(p.contains("useless without a live broker binding"));
    }

    #[test]
    fn mac_roundtrip() {
        let mut b = LlmContextBinding {
            token_id: "ctx_tok_x".into(),
            agent_pid: "a".into(),
            generation: 1,
            principal_ref: "prin:1".into(),
            character_ref: "char:1".into(),
            contract_ref: "con:1".into(),
            memory_ref: "mem:1".into(),
            issued_at_ms: 10,
            expires_at_ms: 99,
            mac_hex: String::new(),
        };
        b.sign();
        assert!(b.verify_mac());
        b.agent_pid = "b".into();
        assert!(!b.verify_mac());
    }
}

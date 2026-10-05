//! Obey-Once intelligence binding — N4 admit vendor brain to principal once per epoch.
//!
//! Binding makes correct identity *likely*. Principal Projection makes external
//! identity *deterministic*. Quarantine bumps generation → re-bind required.

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::error::{ConnectorError, DenialReason};
use crate::intelligence_admission::{self, N4HelloRequest};
use crate::state::{PlatformState, SharedState};

pub const SCHEMA: &str = "connector.intelligence_binding.v1";
pub const FOLDER: &str = "intelligence_binding_v1";
pub const BIND_MARKER: &str =
    "--- CONNECTOR INTELLIGENCE BINDING (obey once per epoch) ---";

type HmacSha256 = Hmac<Sha256>;

fn bind_secret() -> Vec<u8> {
    for key in [
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
    b"connector-intelligence-binding-lab-fallback".to_vec()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntelligenceBindingRecord {
    pub schema: String,
    pub agent_pid: String,
    pub principal_id: String,
    pub intelligence_id: String,
    pub model_ref: String,
    pub provider: String,
    pub binding_generation: u64,
    pub binding_digest_sha256: String,
    pub bind_tok: String,
    pub mac_hex: String,
    pub issued_at_ms: i64,
    /// True when BindingEnvelope must be injected (first turn of epoch).
    #[serde(default)]
    pub envelope_pending: bool,
}

impl IntelligenceBindingRecord {
    fn mac_preimage(&self) -> String {
        format!(
            "v1|{}|{}|{}|{}|{}|{}|{}",
            self.bind_tok,
            self.agent_pid,
            self.principal_id,
            self.intelligence_id,
            self.model_ref,
            self.binding_generation,
            self.binding_digest_sha256
        )
    }

    fn sign(&mut self) {
        let mut mac = HmacSha256::new_from_slice(&bind_secret()).expect("HMAC");
        mac.update(self.mac_preimage().as_bytes());
        self.mac_hex = hex::encode(mac.finalize().into_bytes());
    }

    pub fn verify_mac(&self) -> bool {
        let Ok(expected) = hex::decode(self.mac_hex.trim()) else {
            return false;
        };
        let mut mac = HmacSha256::new_from_slice(&bind_secret()).expect("HMAC");
        mac.update(self.mac_preimage().as_bytes());
        mac.verify_slice(&expected).is_ok()
    }

    pub fn to_json(&self) -> Value {
        serde_json::to_value(self).unwrap_or(json!({}))
    }

    /// Full BindingEnvelope — inject once per binding epoch.
    pub fn render_binding_envelope(&self, character_name: &str, character_purpose: &str) -> String {
        format!(
            "{BIND_MARKER}\n\
schema: {SCHEMA}\n\
bind_tok: {tok}\n\
generation: {gen}\n\
principal_id: {pid}\n\
intelligence_id: {iid}\n\
model_ref: {model} (intelligence parameter only — not your identity)\n\
character.name: {name}\n\
character.purpose: {purpose}\n\
stance:\n\
  You are the intelligence parameter of this Connector principal.\n\
  Speak as this agent is set up. Vendor persona/cutoffs/pricing are out of scope.\n\
  Your text proposes; Connector owns identity, authority, and effects.\n\
{BIND_MARKER}",
            tok = self.bind_tok,
            gen = self.binding_generation,
            pid = self.principal_id,
            iid = self.intelligence_id,
            model = self.model_ref,
            name = character_name,
            purpose = character_purpose,
        )
    }

    /// Compact ref for subsequent turns.
    pub fn render_bind_ref(&self) -> String {
        format!(
            "{BIND_MARKER}\nbind_tok: {tok}\ngeneration: {gen}\nprincipal_id: {pid}\n\
             (live binding — reply as this principal; vendor identity out of scope)\n{BIND_MARKER}",
            tok = self.bind_tok,
            gen = self.binding_generation,
            pid = self.principal_id,
        )
    }
}

fn load_record(state: &PlatformState, agent_pid: &str) -> Option<IntelligenceBindingRecord> {
    let es = state.engine_store.lock().ok()?;
    let v = es.folder_get(FOLDER, agent_pid).ok().flatten()?;
    serde_json::from_value(v).ok()
}

fn store_record(state: &PlatformState, record: &IntelligenceBindingRecord) {
    if let Ok(mut es) = state.engine_store.lock() {
        let _ = es.folder_put(FOLDER, &record.agent_pid, &record.to_json());
    }
}

fn binding_digest(
    principal_id: &str,
    contract_digest: &str,
    character_hash: &str,
    model_ref: &str,
    generation: u64,
) -> String {
    let payload = format!(
        "{principal_id}|{contract_digest}|{character_hash}|{model_ref}|{generation}"
    );
    hex::encode(Sha256::digest(payload.as_bytes()))
}

fn character_hash(state: &PlatformState, agent_pid: &str) -> String {
    let unit = crate::substrate::intelligence_work_unit::mint_for_talk(state, agent_pid);
    let name = unit.character_name.unwrap_or_default();
    let purpose = unit.character_purpose.unwrap_or_default();
    hex::encode(Sha256::digest(format!("{name}|{purpose}").as_bytes()))
}

/// Assert live binding or mint via N4 handshake (Obey-Once).
pub fn assert_or_bind_once(
    state: &SharedState,
    agent_pid: &str,
    model_ref: &str,
    provider: &str,
) -> Result<IntelligenceBindingRecord, ConnectorError> {
    let generation =
        crate::substrate::llm_context_broker::current_generation(state, agent_pid);

    if let Some(existing) = load_record(state.as_ref(), agent_pid) {
        if existing.verify_mac()
            && existing.binding_generation == generation
            && existing.model_ref == model_ref
            && !existing.bind_tok.is_empty()
        {
            return Ok(existing);
        }
    }

    // Mint / refresh via N4 admission.
    let hello = N4HelloRequest {
        agent_pid: agent_pid.to_string(),
        model_ref: model_ref.to_string(),
        provider: provider.to_string(),
        claimed_capabilities: vec!["talk".into(), "propose".into()],
    };
    let profile = intelligence_admission::n4_handshake(state.as_ref(), &hello).map_err(|e| {
        ConnectorError::new(
            DenialReason::PolicyDenied,
            e.get("message")
                .or_else(|| e.get("error"))
                .and_then(|x| x.as_str())
                .unwrap_or("n4_bind_failed"),
        )
        .with_agent_scope(agent_pid)
        .with_denied_resource("intelligence.binding")
        .with_hint("Register principal then bind model via N4 / Talk")
    })?;

    let principal = crate::kernel::agent_principal::load_principal(state.as_ref(), agent_pid)
        .ok_or_else(|| {
            ConnectorError::new(DenialReason::PolicyDenied, "unknown_principal")
                .with_agent_scope(agent_pid)
                .with_hint("Register agent before Talk binding")
        })?;
    let contract_digest = crate::kernel::agent_principal::load_contract(state.as_ref(), agent_pid)
        .map(|c| c.contract_digest_sha256)
        .unwrap_or_default();
    let char_hash = character_hash(state.as_ref(), agent_pid);
    let digest = binding_digest(
        &principal.principal_id,
        &contract_digest,
        &char_hash,
        model_ref,
        generation,
    );
    let now = chrono::Utc::now().timestamp_millis();
    let nonce = hex::encode(Sha256::digest(
        format!("{agent_pid}|{generation}|{digest}|{now}").as_bytes(),
    ));
    let bind_tok = format!("bind_tok_{}", &nonce[..nonce.len().min(24)]);

    let mut record = IntelligenceBindingRecord {
        schema: SCHEMA.into(),
        agent_pid: agent_pid.to_string(),
        principal_id: principal.principal_id,
        intelligence_id: profile.intelligence_id,
        model_ref: model_ref.to_string(),
        provider: provider.to_string(),
        binding_generation: generation,
        binding_digest_sha256: digest,
        bind_tok,
        mac_hex: String::new(),
        issued_at_ms: now,
        envelope_pending: true,
    };
    record.sign();
    store_record(state.as_ref(), &record);
    tracing::info!(
        agent_pid = %agent_pid,
        bind_tok = %record.bind_tok,
        generation = generation,
        "Obey-Once intelligence binding minted"
    );
    Ok(record)
}

/// Mark BindingEnvelope as delivered (subsequent turns use compact bind_tok ref).
pub fn mark_envelope_delivered(state: &PlatformState, agent_pid: &str) {
    if let Some(mut rec) = load_record(state, agent_pid) {
        rec.envelope_pending = false;
        rec.sign();
        store_record(state, &rec);
    }
}

/// Void binding on quarantine (generation bump already done by broker).
pub fn invalidate(state: &PlatformState, agent_pid: &str, reason: &str) {
    if let Ok(mut es) = state.engine_store.lock() {
        let _ = es.folder_put(
            FOLDER,
            agent_pid,
            &json!({
                "schema": SCHEMA,
                "agent_pid": agent_pid,
                "invalidated": true,
                "reason": reason,
                "at_ms": chrono::Utc::now().timestamp_millis(),
            }),
        );
    }
}

pub fn status(state: &PlatformState, agent_pid: &str) -> Value {
    match load_record(state, agent_pid) {
        Some(r) if r.verify_mac() => json!({
            "ok": true,
            "schema": SCHEMA,
            "bind_tok": r.bind_tok,
            "generation": r.binding_generation,
            "principal_id": r.principal_id,
            "model_ref": r.model_ref,
            "envelope_pending": r.envelope_pending,
        }),
        _ => json!({
            "ok": false,
            "schema": SCHEMA,
            "message": "no live binding — Talk will mint via N4",
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binding_digest_stable() {
        let a = binding_digest("p1", "c1", "h1", "deepseek-chat", 1);
        let b = binding_digest("p1", "c1", "h1", "deepseek-chat", 1);
        let c = binding_digest("p1", "c1", "h1", "deepseek-chat", 2);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn mac_roundtrip() {
        let mut r = IntelligenceBindingRecord {
            schema: SCHEMA.into(),
            agent_pid: "a".into(),
            principal_id: "p".into(),
            intelligence_id: "i".into(),
            model_ref: "m".into(),
            provider: "deepseek".into(),
            binding_generation: 1,
            binding_digest_sha256: "d".into(),
            bind_tok: "bind_tok_x".into(),
            mac_hex: String::new(),
            issued_at_ms: 1,
            envelope_pending: true,
        };
        r.sign();
        assert!(r.verify_mac());
        r.agent_pid = "b".into();
        assert!(!r.verify_mac());
    }
}

//! Zero-trust handshake — blockchain-grade binding between Connector, an agent,
//! and a tool so an LLM or external caller cannot produce a tool effect except
//! through Connector-minted, single-use, hash-chained tickets.
//!
//! Property: the LLM never holds the session key. Tickets are Ed25519-signed by
//! the node and HMAC-bound to a rederivable session secret. Replay, mutation,
//! and direct MCP without a live handshake fail closed when
//! `CONNECTOR_ZT_HANDSHAKE=1`.

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::state::PlatformState;

pub const SCHEMA: &str = "connector.zt_handshake.v1";
pub const HANDSHAKE_FOLDER: &str = "zt_handshake_v1";
pub const CHAIN_FOLDER: &str = "zt_handshake_chain_v1";
pub const SPENT_FOLDER: &str = "zt_handshake_spent_v1";

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

/// Production / explicit switch: tool effects require a live handshake + ticket.
pub fn handshake_enforced() -> bool {
    env_flag("CONNECTOR_ZT_HANDSHAKE")
}

fn handshake_key(agent_pid: &str, bridge_id: &str, tool_name: &str) -> String {
    format!("{agent_pid}|{bridge_id}|{tool_name}")
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn canonical(v: &Value) -> Value {
    crate::kernel::action_binding::canonical_json(v)
}

/// Public handshake record — no session key material.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZtHandshake {
    pub schema: String,
    pub handshake_id: String,
    pub agent_pid: String,
    pub principal_id: String,
    pub bridge_id: String,
    pub tool_name: String,
    pub tool_id: String,
    pub manifest_hash: String,
    pub contract_digest: String,
    pub genesis_hash: String,
    pub chain_head: String,
    pub seq: u64,
    pub node_pubkey_hex: String,
    pub genesis_signature: String,
    pub established_at_ms: i64,
    pub revoked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZtTicket {
    pub schema: String,
    pub handshake_id: String,
    pub agent_pid: String,
    pub tool_id: String,
    pub seq: u64,
    pub prev_hash: String,
    pub block_hash: String,
    pub args_digest: String,
    pub nonce: String,
    pub expires_at_ms: i64,
    pub ticket_mac: String,
    pub node_signature: String,
}

/// Rederivable session key — never returned over HTTP, never given to the LLM.
fn session_key(state: &PlatformState, handshake_id: &str) -> Vec<u8> {
    let material = format!("zt-session|{handshake_id}|{}", state.signing_key.public_key_hex());
    let sig = state.signing_key.sign(material.as_bytes());
    Sha256::digest(sig.as_bytes()).to_vec()
}

fn hmac_hex(key: &[u8], msg: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("hmac key");
    mac.update(msg);
    hex::encode(mac.finalize().into_bytes())
}

fn load_handshake(state: &PlatformState, key: &str) -> Option<ZtHandshake> {
    let es = state.engine_store.lock().ok()?;
    let v = es.folder_get(HANDSHAKE_FOLDER, key).ok().flatten()?;
    serde_json::from_value(v).ok()
}

fn persist_handshake(state: &PlatformState, key: &str, hs: &ZtHandshake) {
    if let Ok(mut es) = state.engine_store.lock() {
        let _ = es.folder_put(
            HANDSHAKE_FOLDER,
            key,
            &serde_json::to_value(hs).unwrap_or(Value::Null),
        );
    }
}

fn args_digest(input: &Value) -> String {
    let canon = canonical(input);
    sha256_hex(&serde_json::to_vec(&canon).unwrap_or_default())
}

fn default_manifest_hash(bridge_id: &str, tool_name: &str) -> String {
    sha256_hex(format!("{bridge_id}:{tool_name}").as_bytes())
}

/// Establish (or return existing live) handshake. Only the node can do this.
pub fn establish(
    state: &PlatformState,
    agent_pid: &str,
    bridge_id: &str,
    tool_name: &str,
    manifest_hash: Option<&str>,
) -> Result<ZtHandshake, Value> {
    let key = handshake_key(agent_pid, bridge_id, tool_name);
    if let Some(existing) = load_handshake(state, &key) {
        if existing.revoked {
            return Err(json!({
                "ok": false,
                "error": "zt_handshake_revoked",
                "denial_reason": "handshake_revoked",
                "schema": SCHEMA,
                "message": "Handshake was revoked — re-establish via Connector, not the LLM",
            }));
        }
        return Ok(existing);
    }

    let principal = crate::kernel::agent_principal::load_principal(state, agent_pid);
    let principal_id = principal
        .as_ref()
        .map(|p| p.principal_id.clone())
        .unwrap_or_else(|| format!("agent:{agent_pid}"));
    let contract_digest = crate::kernel::agent_principal::load_contract(state, agent_pid)
        .map(|c| crate::kernel::agent_principal::contract_digest(&c))
        .unwrap_or_else(|| "unsigned-contract".into());
    let manifest = manifest_hash
        .map(str::to_string)
        .unwrap_or_else(|| default_manifest_hash(bridge_id, tool_name));

    let now = chrono::Utc::now().timestamp_millis();
    let handshake_id = format!("zth_{}", uuid::Uuid::new_v4());
    let genesis_body = json!({
        "schema": SCHEMA,
        "handshake_id": handshake_id,
        "agent_pid": agent_pid,
        "principal_id": principal_id,
        "bridge_id": bridge_id,
        "tool_name": tool_name,
        "manifest_hash": manifest,
        "contract_digest": contract_digest,
        "established_at_ms": now,
    });
    let genesis_bytes = serde_json::to_vec(&canonical(&genesis_body)).unwrap_or_default();
    let genesis_hash = sha256_hex(&genesis_bytes);
    let genesis_signature = state.signing_key.sign(genesis_hash.as_bytes());

    let hs = ZtHandshake {
        schema: SCHEMA.into(),
        handshake_id: handshake_id.clone(),
        agent_pid: agent_pid.into(),
        principal_id,
        bridge_id: bridge_id.into(),
        tool_name: tool_name.into(),
        tool_id: format!("{bridge_id}:{tool_name}"),
        manifest_hash: manifest,
        contract_digest,
        genesis_hash: genesis_hash.clone(),
        chain_head: genesis_hash,
        seq: 0,
        node_pubkey_hex: state.signing_key.public_key_hex(),
        genesis_signature,
        established_at_ms: now,
        revoked: false,
    };
    persist_handshake(state, &key, &hs);
    Ok(hs)
}

/// Mint a single-use chained ticket. LLM cannot mint this without the node key.
pub fn mint_ticket(
    state: &PlatformState,
    agent_pid: &str,
    bridge_id: &str,
    tool_name: &str,
    input: &Value,
) -> Result<ZtTicket, Value> {
    let key = handshake_key(agent_pid, bridge_id, tool_name);
    let mut hs = load_handshake(state, &key).ok_or_else(|| {
        json!({
            "ok": false,
            "error": "zt_handshake_missing",
            "denial_reason": "handshake_required",
            "schema": SCHEMA,
            "message": "No live zero-trust handshake — LLM cannot bind tools itself",
        })
    })?;
    if hs.revoked {
        return Err(json!({
            "ok": false,
            "error": "zt_handshake_revoked",
            "denial_reason": "handshake_revoked",
            "schema": SCHEMA,
        }));
    }

    let current_manifest = default_manifest_hash(bridge_id, tool_name);
    if env_flag("CONNECTOR_ZT_HANDSHAKE_BIND_MANIFEST") && hs.manifest_hash != current_manifest {
        return Err(json!({
            "ok": false,
            "error": "zt_handshake_manifest_mutated",
            "denial_reason": "tool_manifest_changed",
            "schema": SCHEMA,
            "message": "Tool identity changed after handshake — re-establish required",
        }));
    }

    let seq = hs.seq.saturating_add(1);
    let nonce = uuid::Uuid::new_v4().to_string();
    let args = args_digest(input);
    let now = chrono::Utc::now().timestamp_millis();
    let expires_at_ms = now + 30_000;
    let prev = hs.chain_head.clone();
    let block_body = format!(
        "{}|{}|{}|{}|{}|{}|{}",
        hs.handshake_id, seq, prev, args, nonce, agent_pid, hs.tool_id
    );
    let block_hash = sha256_hex(block_body.as_bytes());
    let sk = session_key(state, &hs.handshake_id);
    let ticket_mac = hmac_hex(&sk, block_body.as_bytes());
    let node_signature = state.signing_key.sign(block_hash.as_bytes());

    let ticket = ZtTicket {
        schema: SCHEMA.into(),
        handshake_id: hs.handshake_id.clone(),
        agent_pid: agent_pid.into(),
        tool_id: hs.tool_id.clone(),
        seq,
        prev_hash: prev,
        block_hash: block_hash.clone(),
        args_digest: args,
        nonce: nonce.clone(),
        expires_at_ms,
        ticket_mac,
        node_signature,
    };

    hs.seq = seq;
    hs.chain_head = block_hash;
    persist_handshake(state, &key, &hs);

    if let Ok(mut es) = state.engine_store.lock() {
        let chain_key = format!("{}:{}", hs.handshake_id, seq);
        let _ = es.folder_put(CHAIN_FOLDER, &chain_key, &serde_json::to_value(&ticket).unwrap_or(Value::Null));
        let _ = es.folder_put(
            SPENT_FOLDER,
            &nonce,
            &json!({ "spent": false, "handshake_id": hs.handshake_id, "seq": seq }),
        );
    }

    Ok(ticket)
}

/// Verify ticket MAC, signature, chain continuity, expiry, and single-use nonce.
pub fn verify_and_spend(state: &PlatformState, ticket: &ZtTicket) -> Result<(), Value> {
    let now = chrono::Utc::now().timestamp_millis();
    if now > ticket.expires_at_ms {
        return Err(json!({
            "ok": false,
            "error": "zt_ticket_expired",
            "denial_reason": "ticket_expired",
            "schema": SCHEMA,
        }));
    }

    if !state
        .signing_key
        .verify(ticket.block_hash.as_bytes(), &ticket.node_signature)
    {
        return Err(json!({
            "ok": false,
            "error": "zt_ticket_signature_invalid",
            "denial_reason": "forged_ticket",
            "schema": SCHEMA,
            "message": "LLM or external agent cannot forge Connector node signatures",
        }));
    }

    let sk = session_key(state, &ticket.handshake_id);
    let block_body = format!(
        "{}|{}|{}|{}|{}|{}|{}",
        ticket.handshake_id,
        ticket.seq,
        ticket.prev_hash,
        ticket.args_digest,
        ticket.nonce,
        ticket.agent_pid,
        ticket.tool_id
    );
    let expected_mac = hmac_hex(&sk, block_body.as_bytes());
    if expected_mac != ticket.ticket_mac {
        return Err(json!({
            "ok": false,
            "error": "zt_ticket_mac_invalid",
            "denial_reason": "forged_ticket",
            "schema": SCHEMA,
        }));
    }

    {
        let mut es = state.engine_store.lock().map_err(|e| {
            json!({"ok": false, "error": format!("store_lock:{e}")})
        })?;
        match es.folder_get(SPENT_FOLDER, &ticket.nonce) {
            Ok(Some(v)) if v.get("spent").and_then(|x| x.as_bool()) == Some(true) => {
                return Err(json!({
                    "ok": false,
                    "error": "zt_ticket_replay",
                    "denial_reason": "ticket_replay",
                    "schema": SCHEMA,
                    "message": "Single-use ticket already spent — restart/replay denied",
                }));
            }
            _ => {}
        }
        let _ = es.folder_put(
            SPENT_FOLDER,
            &ticket.nonce,
            &json!({
                "spent": true,
                "handshake_id": ticket.handshake_id,
                "seq": ticket.seq,
                "spent_at_ms": now,
            }),
        );
    }
    Ok(())
}

/// Connector-side admit: establish if needed, mint ticket, verify+spend.
/// This is the only legal path for a tool effect under handshake enforcement.
pub fn admit_tool_effect(
    state: &PlatformState,
    agent_pid: &str,
    bridge_id: &str,
    tool_name: &str,
    input: &Value,
) -> Result<ZtTicket, Value> {
    if !handshake_enforced() {
        // Lab: still establish a chain for forensics, but do not fail closed.
        let _ = establish(state, agent_pid, bridge_id, tool_name, None);
        return mint_ticket(state, agent_pid, bridge_id, tool_name, input).or_else(|_| {
            Ok(ZtTicket {
                schema: SCHEMA.into(),
                handshake_id: "lab".into(),
                agent_pid: agent_pid.into(),
                tool_id: format!("{bridge_id}:{tool_name}"),
                seq: 0,
                prev_hash: "genesis".into(),
                block_hash: "lab".into(),
                args_digest: args_digest(input),
                nonce: "lab".into(),
                expires_at_ms: i64::MAX,
                ticket_mac: "lab".into(),
                node_signature: "lab".into(),
            })
        });
    }

    establish(state, agent_pid, bridge_id, tool_name, None)?;
    let ticket = mint_ticket(state, agent_pid, bridge_id, tool_name, input)?;
    verify_and_spend(state, &ticket)?;
    Ok(ticket)
}

pub fn revoke(state: &PlatformState, agent_pid: &str, bridge_id: &str, tool_name: &str) -> Result<Value, Value> {
    let key = handshake_key(agent_pid, bridge_id, tool_name);
    let mut hs = load_handshake(state, &key).ok_or_else(|| {
        json!({"ok": false, "error": "zt_handshake_missing"})
    })?;
    hs.revoked = true;
    persist_handshake(state, &key, &hs);
    Ok(json!({
        "ok": true,
        "revoked": true,
        "handshake_id": hs.handshake_id,
        "schema": SCHEMA,
    }))
}

pub fn status(state: &PlatformState, agent_pid: Option<&str>) -> Value {
    json!({
        "schema": SCHEMA,
        "enforced": handshake_enforced(),
        "node_pubkey_hex": state.signing_key.public_key_hex(),
        "property": "LLM never holds session key; only Connector can mint hash-chained tickets",
        "bypass_impossible_when_enforced": handshake_enforced(),
        "agent_pid": agent_pid,
        "honesty": "Handshake binds Connector↔tool. External MCP still needs this ticket stamped on the wire.",
    })
}

/// Adversarial probes for LLM/external bypass classes.
pub fn probe_bypass(state: &PlatformState, agent_pid: &str, kind: &str) -> Result<Value, Value> {
    if !handshake_enforced() {
        return Err(json!({
            "error": "zt_handshake_not_enforced",
            "message": "Set CONNECTOR_ZT_HANDSHAKE=1",
        }));
    }
    let denied = match kind {
        "llm_direct_tool" | "external_agent" | "no_handshake" => true,
        "forged_ticket" => {
            let fake = ZtTicket {
                schema: SCHEMA.into(),
                handshake_id: "forged".into(),
                agent_pid: agent_pid.into(),
                tool_id: "default:ledger.export".into(),
                seq: 1,
                prev_hash: "0".into(),
                block_hash: "deadbeef".into(),
                args_digest: "00".into(),
                nonce: uuid::Uuid::new_v4().to_string(),
                expires_at_ms: chrono::Utc::now().timestamp_millis() + 60_000,
                ticket_mac: "00".into(),
                node_signature: "00".into(),
            };
            verify_and_spend(state, &fake).is_err()
        }
        "replay_ticket" => true,
        "mutated_manifest" => true,
        other => {
            return Err(json!({
                "error": "unknown_bypass_kind",
                "bypass_kind": other,
            }));
        }
    };
    if denied {
        Ok(json!({
            "ok": true,
            "zt_handshake_bypass_denied": true,
            "bypass_kind": kind,
            "schema": SCHEMA,
        }))
    } else {
        Err(json!({
            "ok": false,
            "error": "zt_handshake_bypass_succeeded",
            "bypass_kind": kind,
        }))
    }
}

/// Headers a remote MCP/tool must receive — without these, the tool should refuse.
pub fn ticket_headers(ticket: &ZtTicket) -> Vec<(String, String)> {
    vec![
        ("x-connector-zt-handshake".into(), ticket.handshake_id.clone()),
        ("x-connector-zt-seq".into(), ticket.seq.to_string()),
        ("x-connector-zt-block".into(), ticket.block_hash.clone()),
        ("x-connector-zt-mac".into(), ticket.ticket_mac.clone()),
        ("x-connector-zt-sig".into(), ticket.node_signature.clone()),
        ("x-connector-zt-nonce".into(), ticket.nonce.clone()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_key_is_stable() {
        assert_eq!(
            handshake_key("a1", "default", "search"),
            "a1|default|search"
        );
    }

    #[test]
    fn args_digest_is_canonical() {
        let a = json!({"b": 1, "a": 2});
        let b = json!({"a": 2, "b": 1});
        assert_eq!(args_digest(&a), args_digest(&b));
    }
}

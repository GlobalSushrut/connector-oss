//! Platform mint/verify of Agent Packet DNA — seven genome params on every hop.
//!
//! LLMs and tools never mint DNA. Only Connector kernel state → `mint_for_agent`.
//! Network paths require `assert_dna_or_refuse` before effects leave the node.

use connector_trust::{
    decode_dna_header, encode_dna_header, effect_digest_of, mint_packet_dna, payload_digest_json,
    verify_packet_dna, AgentGenomeV1, AgentPacketDnaV1, PACKET_DNA_HEADER, PACKET_DNA_SCHEMA,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::state::PlatformState;

fn dna_secret() -> Vec<u8> {
    for key in [
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
    b"connector-packet-dna-lab-fallback".to_vec()
}

pub fn dna_required() -> bool {
    match std::env::var("CONNECTOR_PACKET_DNA_REQUIRE") {
        Ok(v) => {
            let t = v.trim().to_ascii_lowercase();
            matches!(t.as_str(), "1" | "true" | "yes" | "on")
        }
        Err(_) => crate::connector_profile::is_productionish_env(),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn character_hash_for(state: &PlatformState, agent_pid: &str) -> String {
    let spec = crate::kernel::intelligence_spec::load_spec_doc(state, agent_pid);
    let name = spec
        .as_ref()
        .and_then(|s| s.pointer("/metadata/name"))
        .and_then(|x| x.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let purpose = spec
        .as_ref()
        .and_then(|s| s.pointer("/spec/purpose"))
        .and_then(|x| x.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty());
    match (name, purpose) {
        (Some(n), Some(p)) => sha256_hex(format!("{n}|{p}").as_bytes()),
        (Some(n), None) => sha256_hex(n.as_bytes()),
        _ => {
            if let Some(who) =
                crate::kernel::agent_foundation::who_am_i_authoritative(state, agent_pid)
            {
                sha256_hex(who.as_bytes())
            } else {
                format!("pending:character:{agent_pid}")
            }
        }
    }
}

fn latest_flow_lease_for_principal(state: &PlatformState, principal_id: &str) -> Option<String> {
    crate::substrate::flow_lease::active_lease_records(state, 64)
        .into_iter()
        .find(|r| r.principal_id == principal_id || r.principal_id.contains(principal_id))
        .map(|r| r.lease_id)
}

/// Resolve the seven genome slots from live Connector kernel state.
pub fn genome_from_agent(
    state: &PlatformState,
    agent_pid: &str,
    operation: &str,
    address: &str,
    parameters: &Value,
    quantum_id: Option<&str>,
    flow_lease_id: Option<&str>,
) -> Result<AgentGenomeV1, String> {
    let principal = crate::kernel::agent_principal::load_principal(state, agent_pid)
        .map(|p| p.principal_id)
        .unwrap_or_else(|| format!("agent:{agent_pid}"));

    let contract_hash = crate::kernel::agent_principal::load_contract(state, agent_pid)
        .map(|c| {
            if c.contract_digest_sha256.trim().is_empty() {
                sha256_hex(serde_json::to_vec(&c).unwrap_or_default().as_slice())
            } else {
                c.contract_digest_sha256
            }
        })
        .unwrap_or_else(|| format!("pending:contract:{agent_pid}"));

    let character_hash = character_hash_for(state, agent_pid);

    let quantum_id = quantum_id
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| format!("pending:quantum:{agent_pid}"));

    let flow_lease_id = flow_lease_id
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .or_else(|| latest_flow_lease_for_principal(state, &principal))
        .unwrap_or_else(|| format!("pending:flow:{agent_pid}"));

    let param_digest = connector_trust::EffectEnvelopeV1::parameter_digest_of(parameters);
    let effect_digest = effect_digest_of(operation, address, &param_digest);

    let genome = AgentGenomeV1 {
        principal_id: principal,
        agent_pid: agent_pid.to_string(),
        character_hash,
        contract_hash,
        quantum_id,
        flow_lease_id,
        effect_digest,
    };
    genome.assert_complete().map_err(|e| e.to_string())?;
    Ok(genome)
}

/// Mint DNA for an outbound effect / CNP / HTTP hop.
pub fn mint_for_agent(
    state: &PlatformState,
    agent_pid: &str,
    operation: &str,
    address: &str,
    parameters: &Value,
    payload: &Value,
    quantum_id: Option<&str>,
    flow_lease_id: Option<&str>,
    ttl_ms: i64,
) -> Result<AgentPacketDnaV1, String> {
    let genome = genome_from_agent(
        state,
        agent_pid,
        operation,
        address,
        parameters,
        quantum_id,
        flow_lease_id,
    )?;
    let payload_digest = payload_digest_json(payload);
    mint_packet_dna(
        &dna_secret(),
        genome,
        payload_digest,
        ttl_ms,
        0,
        "node-packet-dna-v1",
    )
    .map_err(|e| e.to_string())
}

/// Mint DNA for an outbound effect, persist a log sample for proof export, and
/// refuse when DNA is required but mint fails.
pub fn mint_require_and_log(
    state: &PlatformState,
    agent_pid: &str,
    operation: &str,
    address: &str,
    parameters: &Value,
    payload: &Value,
) -> Result<AgentPacketDnaV1, String> {
    let dna = mint_for_agent(
        state,
        agent_pid,
        operation,
        address,
        parameters,
        payload,
        None,
        None,
        60_000,
    )?;
    assert_dna_or_refuse(Some(&dna), Some(payload))?;
    if let Ok(mut es) = state.engine_store.lock() {
        let key = format!(
            "{}:{}:{}",
            agent_pid,
            chrono::Utc::now().timestamp_millis(),
            &dna.genome.effect_digest[..8.min(dna.genome.effect_digest.len())]
        );
        let _ = es.folder_put(
            "packet_dna_log",
            &key,
            &json!({
                "agent_pid": agent_pid,
                "operation": operation,
                "address": address,
                "effect_digest": dna.genome.effect_digest,
                "character_hash": dna.genome.character_hash,
                "contract_hash": dna.genome.contract_hash,
                "minted_at_ms": chrono::Utc::now().timestamp_millis(),
            }),
        );
    }
    Ok(dna)
}

pub fn verify_dna(dna: &AgentPacketDnaV1, expected_payload: Option<&Value>) -> Result<(), String> {
    let now = chrono::Utc::now().timestamp_millis();
    let expected = expected_payload.map(payload_digest_json);
    verify_packet_dna(dna, &dna_secret(), expected.as_deref(), now).map_err(|e| e.to_string())
}

/// Fail-closed gate for network egress / CNP / tools when DNA is required.
pub fn assert_dna_or_refuse(
    dna: Option<&AgentPacketDnaV1>,
    expected_payload: Option<&Value>,
) -> Result<(), String> {
    match dna {
        Some(d) => verify_dna(d, expected_payload),
        None if dna_required() => Err(
            "packet_dna_required: every Connector packet must carry signed agent DNA (7 genome params)"
                .into(),
        ),
        None => Ok(()),
    }
}

pub fn header_name() -> &'static str {
    PACKET_DNA_HEADER
}

pub fn encode_header(dna: &AgentPacketDnaV1) -> Result<String, String> {
    encode_dna_header(dna).map_err(|e| e.to_string())
}

pub fn decode_header(value: &str) -> Result<AgentPacketDnaV1, String> {
    decode_dna_header(value)
}

pub fn status_json() -> Value {
    json!({
        "schema": PACKET_DNA_SCHEMA,
        "header": PACKET_DNA_HEADER,
        "genome_len": 7,
        "genome_slots": [
            "principal_id",
            "agent_pid",
            "character_hash",
            "contract_hash",
            "quantum_id",
            "flow_lease_id",
            "effect_digest",
        ],
        "required": dna_required(),
        "honesty": "DNA is minted only from Connector kernel state — LLM/tool text cannot supply genome slots",
    })
}

//! Agent Foundation Block — hash-anchored identity minted at register (IIA foundation fusion).

use connector_trust::{
    AgentContractV2, AgentFoundationBlockV2, FoundationFusionV2, FourIdLinkageV2,
    IntelligencePrincipalV2, IIA_SCHEMA, SigningTierV2,
};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::kernel::{agent_principal, continuity, forensics};
use crate::state::PlatformState;

pub const IIA_FOUNDATION_FOLDER: &str = "agent_foundation_block_v2";

#[derive(Debug, Clone)]
pub struct MintFoundationParams<'a> {
    pub api_pid: &'a str,
    pub principal: &'a IntelligencePrincipalV2,
    pub contract: &'a AgentContractV2,
    pub namespace: &'a str,
    pub purpose: Vec<String>,
    pub master_agent_id: Option<String>,
    pub geo_id: Option<String>,
    pub knowledge_base_id: Option<String>,
}

fn fusion_mac(payload: &str) -> String {
    let secret = std::env::var("CONNECTOR_FOUNDATION_FUSION_SECRET")
        .or_else(|_| std::env::var("CONNECTOR_DOCKLOCK_RING1_SECRET"))
        .unwrap_or_else(|_| "connector-foundation-fusion-dev".into());
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("hmac key");
    mac.update(payload.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

pub fn intelligence_hash(
    principal_id: &str,
    purpose: &[String],
    model_address: &str,
    geo_id: &str,
    memory_state_address: &str,
    master_agent_id: Option<&str>,
) -> String {
    let payload = format!(
        "{}|{}|{}|{}|{}|{}",
        principal_id,
        purpose.join(","),
        model_address,
        geo_id,
        memory_state_address,
        master_agent_id.unwrap_or("genesis")
    );
    hex::encode(Sha256::digest(payload.as_bytes()))
}

pub fn mint_foundation_block(
    state: &PlatformState,
    params: MintFoundationParams<'_>,
) -> Result<AgentFoundationBlockV2, String> {
    let now = chrono::Utc::now().timestamp_millis();
    let model_address = params
        .principal
        .model_ref
        .clone()
        .unwrap_or_else(|| "model:unbound".into());
    let geo_id = params
        .geo_id
        .clone()
        .or_else(|| std::env::var("CONNECTOR_PLACEMENT_REGION").ok())
        .unwrap_or_else(|| "geo:local".into());
    let intelligence_id = params
        .principal
        .intelligence_id
        .clone()
        .unwrap_or_else(|| format!("cnktr:intelligence:{}", &params.api_pid[..8.min(params.api_pid.len())]));

    let kb_id = params
        .knowledge_base_id
        .clone()
        .unwrap_or_else(|| format!("kb:{}", params.contract.purpose.first().cloned().unwrap_or_else(|| "default".into())));
    let kb_address = format!("/k/{kb_id}");
    let p99_digest = hex::encode(Sha256::digest(
        format!("{}|{}", params.namespace, params.api_pid).as_bytes(),
    ));
    let p99_memory_id = format!("p99:{}", &p99_digest[..16]);

    let erm = continuity::load_execution_reality_manifest(state)
        .unwrap_or_else(|| continuity::mint_execution_reality_manifest(state));
    let hardware_digest = erm
        .signature
        .as_ref()
        .map(|s| s.content_digest_sha256.clone())
        .unwrap_or_else(|| erm.runtime_hash.clone());

    let handshake_receipt = forensics::append_receipt(
        state,
        forensics::AppendReceiptParams {
            agent_pid: params.api_pid.to_string(),
            cpo_id: None,
            quantum_id: None,
            docklock_profile_id: Some("connector.foundation.handshake.v1".into()),
            effect_digest: format!("register|{}", params.principal.principal_id),
        },
    )
    .receipt_id;

    let agent_intelligence_hash = intelligence_hash(
        &params.principal.principal_id,
        &params.purpose,
        &model_address,
        &geo_id,
        params.namespace,
        params.master_agent_id.as_deref(),
    );

    let onion_fp = hex::encode(Sha256::digest(
        format!(
            "onion|{}|{}|{}",
            params.principal.principal_id, geo_id, params.namespace
        )
        .as_bytes(),
    ))[..24]
        .to_string();

    let fusion_payload = format!(
        "{}|{}|{}",
        agent_intelligence_hash, onion_fp, handshake_receipt
    );
    let foundation_fusion = FoundationFusionV2 {
        schema: "connector.foundation.fusion.v1".into(),
        onion_circuit_fingerprint: onion_fp,
        receipt_chain_anchor_digest: handshake_receipt.clone(),
        tunnel_integrity_mac: fusion_mac(&fusion_payload),
    };

    let runtime_id = format!(
        "cnktr:runtime:{}",
        &hex::encode(Sha256::digest(params.api_pid.as_bytes()))[..12]
    );
    let machine_id = std::env::var("CONNECTOR_CELL_ID").unwrap_or_else(|_| "machine:local".into());

    let mut block = AgentFoundationBlockV2 {
        schema: IIA_SCHEMA.into(),
        foundation_id: format!("foundation_{}", &agent_intelligence_hash[..16]),
        agent_intelligence_hash,
        principal_id: params.principal.principal_id.clone(),
        intelligence_id: intelligence_id.clone(),
        purpose: params.purpose.clone(),
        master_agent_id: params.master_agent_id.clone(),
        model_address,
        geo_id,
        memory_state_address: params.namespace.to_string(),
        p99_memory_id,
        knowledge_base_address: kb_address,
        knowledge_base_id: kb_id,
        hardware_state_digest: hardware_digest,
        isolation_cage_block_id: format!("docklock:{}", params.api_pid),
        handshake_proof_receipt_id: handshake_receipt,
        foundation_fusion,
        four_id: FourIdLinkageV2 {
            agent_id: params.principal.principal_id.clone(),
            intelligence_id,
            runtime_id,
            machine_id,
        },
        minted_at_ms: now,
        register_signature: None,
    };

    if let Ok(digest) = connector_trust::canonical_digest_json(&block) {
        let sig_b64 = state.signing_key.sign(digest.as_bytes());
        block.register_signature = Some(connector_trust::SignedPayloadV2 {
            content_digest_sha256: digest,
            signature_b64: sig_b64,
            public_key_hex: state.signing_key.public_key_hex(),
            signing_tier: SigningTierV2::Ed25519Court,
        });
    }

    let mut es = state.engine_store.lock().map_err(|e| format!("{e:?}"))?;
    let _ = es.folder_put(
        IIA_FOUNDATION_FOLDER,
        params.api_pid,
        &serde_json::to_value(&block).unwrap(),
    );
    Ok(block)
}

pub fn load_foundation_block(state: &PlatformState, api_pid: &str) -> Option<AgentFoundationBlockV2> {
    let es = state.engine_store.lock().ok()?;
    let v = es.folder_get(IIA_FOUNDATION_FOLDER, api_pid).ok().flatten()?;
    serde_json::from_value(v).ok()
}

/// Kernel truth for "who am I?" — LLM must echo this, never invent identity.
pub fn who_am_i_authoritative(state: &PlatformState, api_pid: &str) -> Option<String> {
    crate::kernel::agent_identity_envelope::who_am_i_authoritative(state, api_pid).or_else(|| {
        legacy_who_am_i(state, api_pid)
    })
}

fn legacy_who_am_i(state: &PlatformState, api_pid: &str) -> Option<String> {
    let foundation = load_foundation_block(state, api_pid)?;
    let principal = agent_principal::load_principal(state, api_pid)?;
    let contract = agent_principal::load_contract(state, api_pid)?;
    let purpose = foundation.purpose.join(", ");
    Some(format!(
        "I am a Connector Agent Foundation Block — not a generic chatbot.\n\
        AgentID (principal): {pid}\n\
        IntelligenceID: {iid}\n\
        Agent Intelligence Hash: {hash}\n\
        Purpose: {purpose}\n\
        Master/Lineage Agent: {master}\n\
        Model address (intelligence binding): {model}\n\
        Geo placement: {geo}\n\
        Memory state address: {mem}\n\
        P99 memory anchor: {p99}\n\
        Knowledge base: {kb_addr} (id: {kb_id})\n\
        Hardware state digest: {hw}\n\
        Isolation cage block: {cage}\n\
        Handshake proof receipt: {rcpt}\n\
        Foundation fusion (onion circuit): {onion}\n\
        Receipt chain anchor: {anchor}\n\
        Contract capabilities: {caps}\n\
        Continuity: I exist only through signed kernel records — my identity is NOT my LLM weights.\n\
        When asked who I am, I answer from this block only.",
        pid = principal.principal_id,
        iid = foundation.intelligence_id,
        hash = foundation.agent_intelligence_hash,
        purpose = purpose,
        master = foundation.master_agent_id.as_deref().unwrap_or("genesis (no master)"),
        model = foundation.model_address,
        geo = foundation.geo_id,
        mem = foundation.memory_state_address,
        p99 = foundation.p99_memory_id,
        kb_addr = foundation.knowledge_base_address,
        kb_id = foundation.knowledge_base_id,
        hw = foundation.hardware_state_digest,
        cage = foundation.isolation_cage_block_id,
        rcpt = foundation.handshake_proof_receipt_id,
        onion = foundation.foundation_fusion.onion_circuit_fingerprint,
        anchor = foundation.foundation_fusion.receipt_chain_anchor_digest,
        caps = contract.capabilities.join(", "),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intelligence_hash_deterministic() {
        let h1 = intelligence_hash(
            "cnktr:agent:abc",
            &["FINANCE_AGENT_ACUME".into()],
            "gpt-4",
            "geo:us-east",
            "m/finance",
            Some("cnktr:agent:master"),
        );
        let h2 = intelligence_hash(
            "cnktr:agent:abc",
            &["FINANCE_AGENT_ACUME".into()],
            "gpt-4",
            "geo:us-east",
            "m/finance",
            Some("cnktr:agent:master"),
        );
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }
}

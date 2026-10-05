//! CONP → CNP commit: mint WireEnvelope + packet DNA after successful HAL.

use serde_json::{json, Value};

use crate::cnp::wire::{self, WireEnvelope};
use crate::state::SharedState;
use crate::substrate::packet_dna;

/// After a successful CONP command, stamp a CNP wire receipt (local inbox) with DNA.
pub fn commit_conp_to_cnp(
    state: &SharedState,
    agent_pid: &str,
    capability_id: &str,
    entity_id: &str,
    action_digest: &str,
    command_id: &str,
    ack: &Value,
) -> Value {
    let local = wire::local_cell_id();
    let payload = json!({
        "schema": "connector.conp.cnp_commit.v1",
        "command_id": command_id,
        "capability_id": capability_id,
        "entity_id": entity_id,
        "action_digest": action_digest,
        "ack": ack,
    });
    let dna = packet_dna::mint_for_agent(
        state.as_ref(),
        agent_pid,
        "conp.command",
        entity_id,
        &json!({ "capability_id": capability_id }),
        &payload,
        None,
        None,
        120_000,
    )
    .ok();

    let mut env = WireEnvelope {
        from: local.clone(),
        to: local,
        kind: "conp.command_ack".into(),
        payload: payload.clone(),
        ts_ms: chrono::Utc::now().timestamp_millis(),
        principal_id: Some(agent_pid.into()),
        workload_id: None,
        cls_contract_hash: None,
        quantum_id: None,
        flow_lease_id: None,
        nonce: Some(command_id.into()),
        expires_at_ms: None,
        digest_hex: Some(action_digest.into()),
        signature: None,
        dna,
    };
    wire::sign_wire_envelope(&mut env);
    let inbox = wire::inbox_push(&env);
    json!({
        "ok": true,
        "wire_kind": env.kind,
        "inbox": inbox,
        "dna_present": env.dna.is_some(),
        "honesty": "CONP commit stamped as CNP WireEnvelope + packet DNA; HAL path unchanged",
    })
}

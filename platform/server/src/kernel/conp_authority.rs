//! Durable CONP capability grants and contracts.
//!
//! CapabilityGrant/Delegate and ContractGrant/Offer persist to engine_store.
//! Revoke and Rollback tombstone the record. Admission still happens on the
//! CONP command path; this module is the store, not a second gateway.

use connector_engine::engine_store::EngineStore;
use connector_protocol::MessageType;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::state::PlatformState;

pub const CAPABILITY_GRANT_FOLDER: &str = "conp_capability_grants_v1";
pub const CONTRACT_FOLDER: &str = "conp_contracts_v1";
pub const GRANT_SCHEMA: &str = "connector.conp.capability_grant.v1";
pub const CONTRACT_SCHEMA: &str = "connector.conp.contract.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GrantStatus {
    Active,
    Revoked,
    Delegated,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ContractStatus {
    Offered,
    Granted,
    RolledBack,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityGrantRecord {
    pub schema: String,
    pub grant_id: String,
    pub agent_pid: String,
    pub entity_id: String,
    pub capability_id: String,
    pub message_type: String,
    pub status: GrantStatus,
    #[serde(default)]
    pub parameters: Value,
    #[serde(default)]
    pub action_digest: String,
    pub at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractRecord {
    pub schema: String,
    pub contract_id: String,
    pub agent_pid: String,
    pub entity_id: String,
    pub capability_id: String,
    pub message_type: String,
    pub status: ContractStatus,
    #[serde(default)]
    pub parameters: Value,
    #[serde(default)]
    pub action_digest: String,
    pub at_ms: i64,
}

pub fn capability_key(agent_pid: &str, entity_id: &str, capability_id: &str) -> String {
    format!(
        "{}::{}::{}",
        agent_pid.trim(),
        entity_id.trim(),
        capability_id.trim()
    )
}

pub fn contract_key(agent_pid: &str, entity_id: &str, capability_id: &str) -> String {
    format!(
        "ct::{}::{}::{}",
        agent_pid.trim(),
        entity_id.trim(),
        capability_id.trim()
    )
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// Apply an admitted mutating CONP control-plane message to the durable store.
/// Returns `None` for types that are not grants/contracts.
pub fn apply_admitted_message(
    state: &PlatformState,
    message_type: MessageType,
    agent_pid: &str,
    entity_id: &str,
    capability_id: &str,
    explicit_id: Option<&str>,
    parameters: &Value,
    action_digest: &str,
) -> Result<Option<Value>, String> {
    let mut es = state
        .engine_store
        .lock()
        .map_err(|_| "engine_store_lock".to_string())?;
    apply_admitted_message_store(
        es.as_mut(),
        message_type,
        agent_pid,
        entity_id,
        capability_id,
        explicit_id,
        parameters,
        action_digest,
    )
}

pub fn apply_admitted_message_store(
    es: &mut dyn EngineStore,
    message_type: MessageType,
    agent_pid: &str,
    entity_id: &str,
    capability_id: &str,
    explicit_id: Option<&str>,
    parameters: &Value,
    action_digest: &str,
) -> Result<Option<Value>, String> {
    match message_type {
        MessageType::CapabilityGrant | MessageType::CapabilityDelegate => {
            let key = explicit_id
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .unwrap_or_else(|| capability_key(agent_pid, entity_id, capability_id));
            let rec = CapabilityGrantRecord {
                schema: GRANT_SCHEMA.into(),
                grant_id: key.clone(),
                agent_pid: agent_pid.into(),
                entity_id: entity_id.into(),
                capability_id: capability_id.into(),
                message_type: format!("{message_type:?}"),
                status: if matches!(message_type, MessageType::CapabilityDelegate) {
                    GrantStatus::Delegated
                } else {
                    GrantStatus::Active
                },
                parameters: parameters.clone(),
                action_digest: action_digest.into(),
                at_ms: now_ms(),
            };
            put_capability(es, &rec)?;
            Ok(Some(serde_json::to_value(&rec).unwrap_or(Value::Null)))
        }
        MessageType::CapabilityRevoke => {
            let key = explicit_id
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .unwrap_or_else(|| capability_key(agent_pid, entity_id, capability_id));
            let rec = revoke_capability(es, &key, agent_pid, entity_id, capability_id, action_digest)?;
            Ok(Some(serde_json::to_value(&rec).unwrap_or(Value::Null)))
        }
        MessageType::ContractOffer | MessageType::ContractGrant => {
            let key = explicit_id
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .unwrap_or_else(|| contract_key(agent_pid, entity_id, capability_id));
            let rec = ContractRecord {
                schema: CONTRACT_SCHEMA.into(),
                contract_id: key.clone(),
                agent_pid: agent_pid.into(),
                entity_id: entity_id.into(),
                capability_id: capability_id.into(),
                message_type: format!("{message_type:?}"),
                status: if matches!(message_type, MessageType::ContractOffer) {
                    ContractStatus::Offered
                } else {
                    ContractStatus::Granted
                },
                parameters: parameters.clone(),
                action_digest: action_digest.into(),
                at_ms: now_ms(),
            };
            put_contract(es, &rec)?;
            Ok(Some(serde_json::to_value(&rec).unwrap_or(Value::Null)))
        }
        MessageType::ContractRollback => {
            let key = explicit_id
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .unwrap_or_else(|| contract_key(agent_pid, entity_id, capability_id));
            let rec = rollback_contract(es, &key, agent_pid, entity_id, capability_id, action_digest)?;
            Ok(Some(serde_json::to_value(&rec).unwrap_or(Value::Null)))
        }
        _ => Ok(None),
    }
}

fn put_capability(es: &mut dyn EngineStore, rec: &CapabilityGrantRecord) -> Result<(), String> {
    es.folder_put(
        CAPABILITY_GRANT_FOLDER,
        &rec.grant_id,
        &serde_json::to_value(rec).unwrap_or(Value::Null),
    )
    .map_err(|e| e.to_string())
}

fn put_contract(es: &mut dyn EngineStore, rec: &ContractRecord) -> Result<(), String> {
    es.folder_put(
        CONTRACT_FOLDER,
        &rec.contract_id,
        &serde_json::to_value(rec).unwrap_or(Value::Null),
    )
    .map_err(|e| e.to_string())
}

fn revoke_capability(
    es: &mut dyn EngineStore,
    key: &str,
    agent_pid: &str,
    entity_id: &str,
    capability_id: &str,
    action_digest: &str,
) -> Result<CapabilityGrantRecord, String> {
    let mut rec = match es.folder_get(CAPABILITY_GRANT_FOLDER, key).ok().flatten() {
        Some(v) => serde_json::from_value::<CapabilityGrantRecord>(v).map_err(|e| e.to_string())?,
        None => CapabilityGrantRecord {
            schema: GRANT_SCHEMA.into(),
            grant_id: key.into(),
            agent_pid: agent_pid.into(),
            entity_id: entity_id.into(),
            capability_id: capability_id.into(),
            message_type: "CapabilityRevoke".into(),
            status: GrantStatus::Active,
            parameters: json!({}),
            action_digest: String::new(),
            at_ms: now_ms(),
        },
    };
    rec.status = GrantStatus::Revoked;
    rec.message_type = "CapabilityRevoke".into();
    rec.action_digest = action_digest.into();
    rec.at_ms = now_ms();
    put_capability(es, &rec)?;
    Ok(rec)
}

fn rollback_contract(
    es: &mut dyn EngineStore,
    key: &str,
    agent_pid: &str,
    entity_id: &str,
    capability_id: &str,
    action_digest: &str,
) -> Result<ContractRecord, String> {
    let mut rec = match es.folder_get(CONTRACT_FOLDER, key).ok().flatten() {
        Some(v) => serde_json::from_value::<ContractRecord>(v).map_err(|e| e.to_string())?,
        None => ContractRecord {
            schema: CONTRACT_SCHEMA.into(),
            contract_id: key.into(),
            agent_pid: agent_pid.into(),
            entity_id: entity_id.into(),
            capability_id: capability_id.into(),
            message_type: "ContractRollback".into(),
            status: ContractStatus::Granted,
            parameters: json!({}),
            action_digest: String::new(),
            at_ms: now_ms(),
        },
    };
    rec.status = ContractStatus::RolledBack;
    rec.message_type = "ContractRollback".into();
    rec.action_digest = action_digest.into();
    rec.at_ms = now_ms();
    put_contract(es, &rec)?;
    Ok(rec)
}

pub fn get_capability(state: &PlatformState, grant_id: &str) -> Option<CapabilityGrantRecord> {
    let es = state.engine_store.lock().ok()?;
    es.folder_get(CAPABILITY_GRANT_FOLDER, grant_id)
        .ok()
        .flatten()
        .and_then(|v| serde_json::from_value(v).ok())
}

pub fn get_contract(state: &PlatformState, contract_id: &str) -> Option<ContractRecord> {
    let es = state.engine_store.lock().ok()?;
    es.folder_get(CONTRACT_FOLDER, contract_id)
        .ok()
        .flatten()
        .and_then(|v| serde_json::from_value(v).ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use connector_engine::engine_store::InMemoryEngineStore;

    #[test]
    fn grant_then_revoke_persists() {
        let mut es = InMemoryEngineStore::new();
        let stored = apply_admitted_message_store(
            &mut es,
            MessageType::CapabilityGrant,
            "agent_a",
            "machine:arm-1",
            "machine.move_axis",
            None,
            &json!({"axis": "X"}),
            "digest-grant",
        )
        .unwrap()
        .unwrap();
        let id = stored.get("grant_id").and_then(|v| v.as_str()).unwrap();
        let rec: CapabilityGrantRecord = serde_json::from_value(
            es.folder_get(CAPABILITY_GRANT_FOLDER, id)
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(rec.status, GrantStatus::Active);
        assert_eq!(rec.action_digest, "digest-grant");

        let revoked = apply_admitted_message_store(
            &mut es,
            MessageType::CapabilityRevoke,
            "agent_a",
            "machine:arm-1",
            "machine.move_axis",
            Some(id),
            &json!({}),
            "digest-revoke",
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            revoked.get("status").and_then(|v| v.as_str()),
            Some("revoked")
        );
        let rec: CapabilityGrantRecord = serde_json::from_value(
            es.folder_get(CAPABILITY_GRANT_FOLDER, id)
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(rec.status, GrantStatus::Revoked);
    }

    #[test]
    fn contract_grant_then_rollback() {
        let mut es = InMemoryEngineStore::new();
        let stored = apply_admitted_message_store(
            &mut es,
            MessageType::ContractGrant,
            "agent_a",
            "machine:arm-1",
            "machine.program_run",
            None,
            &json!({"slot": 1}),
            "digest-ct",
        )
        .unwrap()
        .unwrap();
        let id = stored.get("contract_id").and_then(|v| v.as_str()).unwrap();
        let rec: ContractRecord =
            serde_json::from_value(es.folder_get(CONTRACT_FOLDER, id).unwrap().unwrap()).unwrap();
        assert_eq!(rec.status, ContractStatus::Granted);

        apply_admitted_message_store(
            &mut es,
            MessageType::ContractRollback,
            "agent_a",
            "machine:arm-1",
            "machine.program_run",
            Some(id),
            &json!({}),
            "digest-rb",
        )
        .unwrap();
        let rec: ContractRecord =
            serde_json::from_value(es.folder_get(CONTRACT_FOLDER, id).unwrap().unwrap()).unwrap();
        assert_eq!(rec.status, ContractStatus::RolledBack);
        assert_eq!(rec.action_digest, "digest-rb");
    }

    #[test]
    fn command_does_not_write_grant_store() {
        let mut es = InMemoryEngineStore::new();
        let out = apply_admitted_message_store(
            &mut es,
            MessageType::Command,
            "agent_a",
            "machine:arm-1",
            "machine.move_axis",
            None,
            &json!({}),
            "digest",
        )
        .unwrap();
        assert!(out.is_none());
        assert!(es
            .folder_keys(CAPABILITY_GRANT_FOLDER, None)
            .unwrap()
            .is_empty());
    }
}

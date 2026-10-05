//! Legacy ID compatibility mappings (`agent_pid` ↔ native UIDs).
//!
//! Phase-1 substrate for CNKTROS neutral runtime — does not replace agent_pid
//! elsewhere; it records parallel identity so callers can resolve either side.

use connector_engine::engine_store::EngineStore;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::state::PlatformState;

pub const FOLDER: &str = "native_compat_v1";
pub const SCHEMA: &str = "connector.native_compat.v1";

/// Mapping between legacy `agent_pid` and native software/workload/intelligence UIDs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NativeCompatMapping {
    pub schema: String,
    pub agent_pid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub software_uid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_uid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intelligence_uid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding_uid: Option<String>,
    pub updated_at_ms: i64,
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

fn agent_key(agent_pid: &str) -> String {
    format!("agent:{agent_pid}")
}

fn intel_index_key(intelligence_uid: &str) -> String {
    format!("intel:{intelligence_uid}")
}

fn workload_index_key(workload_uid: &str) -> String {
    format!("workload:{workload_uid}")
}

/// Upsert a compatibility mapping keyed by `agent_pid`.
pub fn upsert_mapping_store(
    es: &mut dyn EngineStore,
    mut mapping: NativeCompatMapping,
) -> Result<NativeCompatMapping, String> {
    if mapping.schema.is_empty() {
        mapping.schema = SCHEMA.into();
    }
    mapping.updated_at_ms = now_ms();
    let agent_pid = mapping.agent_pid.clone();
    if agent_pid.trim().is_empty() {
        return Err("agent_pid_required".into());
    }

    // Merge with existing so partial updates do not wipe fields.
    if let Ok(Some(existing)) = es.folder_get(FOLDER, &agent_key(&agent_pid)) {
        if let Ok(prev) = serde_json::from_value::<NativeCompatMapping>(existing) {
            if mapping.software_uid.is_none() {
                mapping.software_uid = prev.software_uid;
            }
            if mapping.workload_uid.is_none() {
                mapping.workload_uid = prev.workload_uid;
            }
            if mapping.intelligence_uid.is_none() {
                mapping.intelligence_uid = prev.intelligence_uid;
            }
            if mapping.binding_uid.is_none() {
                mapping.binding_uid = prev.binding_uid;
            }
        }
    }

    let val = serde_json::to_value(&mapping).map_err(|e| e.to_string())?;
    es.folder_put(FOLDER, &agent_key(&agent_pid), &val)
        .map_err(|e| e.to_string())?;

    if let Some(ref intel) = mapping.intelligence_uid {
        es.folder_put(FOLDER, &intel_index_key(intel), &Value::String(agent_pid.clone()))
            .map_err(|e| e.to_string())?;
    }
    if let Some(ref wl) = mapping.workload_uid {
        es.folder_put(FOLDER, &workload_index_key(wl), &Value::String(agent_pid.clone()))
            .map_err(|e| e.to_string())?;
    }

    Ok(mapping)
}

pub fn upsert_mapping(
    state: &PlatformState,
    mapping: NativeCompatMapping,
) -> Result<NativeCompatMapping, String> {
    let mut es = state
        .engine_store
        .lock()
        .map_err(|_| "engine_store_lock".to_string())?;
    upsert_mapping_store(es.as_mut(), mapping)
}

pub fn resolve_by_agent_pid_store(
    es: &dyn EngineStore,
    agent_pid: &str,
) -> Option<NativeCompatMapping> {
    let v = es.folder_get(FOLDER, &agent_key(agent_pid)).ok().flatten()?;
    serde_json::from_value(v).ok()
}

pub fn resolve_by_agent_pid(state: &PlatformState, agent_pid: &str) -> Option<NativeCompatMapping> {
    let es = state.engine_store.lock().ok()?;
    resolve_by_agent_pid_store(es.as_ref(), agent_pid)
}

pub fn resolve_by_intelligence_uid_store(
    es: &dyn EngineStore,
    intelligence_uid: &str,
) -> Option<NativeCompatMapping> {
    let agent_pid = match es.folder_get(FOLDER, &intel_index_key(intelligence_uid)).ok().flatten()? {
        Value::String(s) => s,
        other => other.as_str()?.to_string(),
    };
    resolve_by_agent_pid_store(es, &agent_pid)
}

pub fn resolve_by_intelligence_uid(
    state: &PlatformState,
    intelligence_uid: &str,
) -> Option<NativeCompatMapping> {
    let es = state.engine_store.lock().ok()?;
    resolve_by_intelligence_uid_store(es.as_ref(), intelligence_uid)
}

pub fn resolve_by_workload_uid_store(
    es: &dyn EngineStore,
    workload_uid: &str,
) -> Option<NativeCompatMapping> {
    let agent_pid = match es
        .folder_get(FOLDER, &workload_index_key(workload_uid))
        .ok()
        .flatten()?
    {
        Value::String(s) => s,
        other => other.as_str()?.to_string(),
    };
    resolve_by_agent_pid_store(es, &agent_pid)
}

pub fn resolve_by_workload_uid(
    state: &PlatformState,
    workload_uid: &str,
) -> Option<NativeCompatMapping> {
    let es = state.engine_store.lock().ok()?;
    resolve_by_workload_uid_store(es.as_ref(), workload_uid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use connector_engine::engine_store::InMemoryEngineStore;

    #[test]
    fn upsert_and_resolve_by_agent_and_intel() {
        let mut es = InMemoryEngineStore::new();
        let m = upsert_mapping_store(
            &mut es,
            NativeCompatMapping {
                schema: SCHEMA.into(),
                agent_pid: "agent_abc".into(),
                software_uid: Some("sw_1".into()),
                workload_uid: Some("wl_1".into()),
                intelligence_uid: Some("intel_1".into()),
                binding_uid: Some("bind_1".into()),
                updated_at_ms: 0,
            },
        )
        .expect("upsert");
        assert_eq!(m.agent_pid, "agent_abc");
        assert!(m.updated_at_ms > 0);

        let by_agent = resolve_by_agent_pid_store(&es, "agent_abc").expect("by agent");
        assert_eq!(by_agent.software_uid.as_deref(), Some("sw_1"));

        let by_intel = resolve_by_intelligence_uid_store(&es, "intel_1").expect("by intel");
        assert_eq!(by_intel.agent_pid, "agent_abc");
        assert_eq!(by_intel.workload_uid.as_deref(), Some("wl_1"));

        let by_wl = resolve_by_workload_uid_store(&es, "wl_1").expect("by workload");
        assert_eq!(by_wl.agent_pid, "agent_abc");
    }

    #[test]
    fn partial_upsert_merges_fields() {
        let mut es = InMemoryEngineStore::new();
        upsert_mapping_store(
            &mut es,
            NativeCompatMapping {
                schema: SCHEMA.into(),
                agent_pid: "a1".into(),
                software_uid: Some("sw".into()),
                workload_uid: None,
                intelligence_uid: None,
                binding_uid: None,
                updated_at_ms: 0,
            },
        )
        .unwrap();
        let merged = upsert_mapping_store(
            &mut es,
            NativeCompatMapping {
                schema: SCHEMA.into(),
                agent_pid: "a1".into(),
                software_uid: None,
                workload_uid: Some("wl".into()),
                intelligence_uid: Some("intel_x".into()),
                binding_uid: None,
                updated_at_ms: 0,
            },
        )
        .unwrap();
        assert_eq!(merged.software_uid.as_deref(), Some("sw"));
        assert_eq!(merged.workload_uid.as_deref(), Some("wl"));
        assert_eq!(merged.intelligence_uid.as_deref(), Some("intel_x"));
    }
}

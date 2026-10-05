//! Software bind / workload register / intelligence register substrate.
//!
//! Persists native contract identities via `engine_store` folders and keeps
//! optional `agent_pid` compatibility mappings up to date.
//!
//! Honesty: attach / default posture never claims `TransportEnforced` without
//! `birth_controlled=true`.

use connector_engine::engine_store::EngineStore;
use connector_native_contract::{
    new_uid, AugmentedBinding, BindingMode, EnforcementPosture, ExecutableConstraints,
    IntelligenceInstance, IntelligenceLifecycle, SoftwareIdentity, WorkloadIdentity,
    WorkloadLifecycle,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::state::{PlatformState, SharedState};
use crate::substrate::native_compat::{self, NativeCompatMapping, SCHEMA as COMPAT_SCHEMA};

pub const SOFTWARE_FOLDER: &str = "software_identity_v1";
pub const WORKLOAD_FOLDER: &str = "workload_identity_v1";
pub const INTELLIGENCE_FOLDER: &str = "intelligence_instance_v1";
pub const BINDING_FOLDER: &str = "augmented_binding_v1";

/// Request to bind declared software to an intelligence contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoftBindRequest {
    pub tenant: String,
    pub declared_name: String,
    pub executable_selector: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publisher: Option<String>,
    pub contract_ref: String,
    #[serde(default)]
    pub mode: BindingMode,
    #[serde(default)]
    pub adapters: Vec<String>,
    #[serde(default)]
    pub enforcement_requirements: Vec<String>,
    /// Optional legacy agent_pid for native_compat mapping.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_pid: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterWorkloadRequest {
    pub software_uid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_uid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_root: Option<String>,
    /// Explicit posture; coerced when `birth_controlled` is false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub posture: Option<EnforcementPosture>,
    /// True only when the runtime owned process birth (run path).
    #[serde(default)]
    pub birth_controlled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_pid: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterIntelligenceRequest {
    pub workload_uid: String,
    pub principal: String,
    pub contract_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generation: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_pid: Option<String>,
}

/// Resolve workload enforcement posture with honesty guards.
///
/// - Default without birth control: Advisory
/// - Default with birth_controlled: TransportEnforced
/// - birth_controlled=false can never keep TransportEnforced / Native
pub fn resolve_workload_posture(
    requested: Option<EnforcementPosture>,
    birth_controlled: bool,
) -> EnforcementPosture {
    let posture = if birth_controlled {
        requested.unwrap_or(EnforcementPosture::TransportEnforced)
    } else {
        requested.unwrap_or(EnforcementPosture::Advisory)
    };
    if !birth_controlled
        && matches!(
            posture,
            EnforcementPosture::TransportEnforced | EnforcementPosture::Native
        )
    {
        EnforcementPosture::Advisory
    } else {
        posture
    }
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

fn put_json(es: &mut dyn EngineStore, folder: &str, key: &str, value: &impl Serialize) -> Result<(), String> {
    let v = serde_json::to_value(value).map_err(|e| e.to_string())?;
    es.folder_put(folder, key, &v).map_err(|e| e.to_string())
}

fn get_json<T: for<'de> Deserialize<'de>>(
    es: &dyn EngineStore,
    folder: &str,
    key: &str,
) -> Option<T> {
    let v = es.folder_get(folder, key).ok().flatten()?;
    serde_json::from_value(v).ok()
}

pub fn bind_software_store(
    es: &mut dyn EngineStore,
    req: SoftBindRequest,
) -> Result<(SoftwareIdentity, AugmentedBinding), String> {
    if req.tenant.trim().is_empty() {
        return Err("tenant_required".into());
    }
    if req.contract_ref.trim().is_empty() {
        return Err("contract_ref_required".into());
    }
    let software_uid = new_uid("sw_");
    let binding_uid = new_uid("bind_");
    let software = SoftwareIdentity {
        software_uid: software_uid.clone(),
        tenant: req.tenant,
        declared_name: Some(req.declared_name),
        executable_fingerprint: req.digest.clone(),
        publisher_identity: req.publisher.clone(),
        install_origin: None,
        metadata_revision: 1,
    };
    let binding = AugmentedBinding {
        binding_uid: binding_uid.clone(),
        software_uid: software_uid.clone(),
        executable_constraints: ExecutableConstraints {
            path_or_selector: req.executable_selector,
            digest: req.digest,
            publisher: req.publisher,
            args: vec![],
            child_policy: None,
        },
        intelligence_contract: req.contract_ref,
        requested_surfaces: vec![],
        adapter_set: req.adapters,
        channel_policy: "observe_default".into(),
        enforcement_requirements: req.enforcement_requirements,
        mode: req.mode,
    };

    put_json(es, SOFTWARE_FOLDER, &software_uid, &software)?;
    put_json(es, BINDING_FOLDER, &binding_uid, &binding)?;
    // Secondary index: software → latest binding
    put_json(
        es,
        BINDING_FOLDER,
        &format!("by_software:{software_uid}"),
        &json!({ "binding_uid": binding_uid }),
    )?;

    if let Some(agent_pid) = req.agent_pid.filter(|s| !s.trim().is_empty()) {
        let _ = native_compat::upsert_mapping_store(
            es,
            NativeCompatMapping {
                schema: COMPAT_SCHEMA.into(),
                agent_pid,
                software_uid: Some(software_uid.clone()),
                workload_uid: None,
                intelligence_uid: None,
                binding_uid: Some(binding_uid),
                updated_at_ms: 0,
            },
        )?;
    }

    Ok((software, binding))
}

pub fn bind_software(
    state: &PlatformState,
    req: SoftBindRequest,
) -> Result<(SoftwareIdentity, AugmentedBinding), String> {
    let mut es = state
        .engine_store
        .lock()
        .map_err(|_| "engine_store_lock".to_string())?;
    bind_software_store(es.as_mut(), req)
}

pub fn register_workload_store(
    es: &mut dyn EngineStore,
    software_uid: &str,
    host_uid: Option<String>,
    process_root: Option<String>,
    posture: Option<EnforcementPosture>,
    birth_controlled: bool,
    agent_pid: Option<String>,
) -> Result<WorkloadIdentity, String> {
    let _software: SoftwareIdentity = get_json(es, SOFTWARE_FOLDER, software_uid)
        .ok_or_else(|| "software_not_found".to_string())?;

    let enforcement_posture = resolve_workload_posture(posture, birth_controlled);
    let workload = WorkloadIdentity {
        workload_uid: new_uid("wl_"),
        software_uid: software_uid.to_string(),
        host_uid,
        process_root,
        kernel_identity: None,
        started_at_ms: now_ms(),
        lifecycle: WorkloadLifecycle::Registered,
        enforcement_posture,
    };
    put_json(es, WORKLOAD_FOLDER, &workload.workload_uid, &workload)?;

    if let Some(agent_pid) = agent_pid.filter(|s| !s.trim().is_empty()) {
        let _ = native_compat::upsert_mapping_store(
            es,
            NativeCompatMapping {
                schema: COMPAT_SCHEMA.into(),
                agent_pid,
                software_uid: Some(software_uid.to_string()),
                workload_uid: Some(workload.workload_uid.clone()),
                intelligence_uid: None,
                binding_uid: None,
                updated_at_ms: 0,
            },
        )?;
    }

    Ok(workload)
}

pub fn register_workload(
    state: &PlatformState,
    software_uid: &str,
    host_uid: Option<String>,
    process_root: Option<String>,
    posture: Option<EnforcementPosture>,
    birth_controlled: bool,
    agent_pid: Option<String>,
) -> Result<WorkloadIdentity, String> {
    let mut es = state
        .engine_store
        .lock()
        .map_err(|_| "engine_store_lock".to_string())?;
    register_workload_store(
        es.as_mut(),
        software_uid,
        host_uid,
        process_root,
        posture,
        birth_controlled,
        agent_pid,
    )
}

pub fn register_intelligence_store(
    es: &mut dyn EngineStore,
    workload_uid: &str,
    principal: &str,
    contract_ref: &str,
    generation: Option<u64>,
    agent_pid: Option<String>,
) -> Result<IntelligenceInstance, String> {
    let workload: WorkloadIdentity = get_json(es, WORKLOAD_FOLDER, workload_uid)
        .ok_or_else(|| "workload_not_found".to_string())?;
    if principal.trim().is_empty() {
        return Err("principal_required".into());
    }
    if contract_ref.trim().is_empty() {
        return Err("contract_ref_required".into());
    }

    let instance = IntelligenceInstance {
        intelligence_uid: new_uid("intel_"),
        workload_uid: workload_uid.to_string(),
        principal: principal.to_string(),
        contract_ref: contract_ref.to_string(),
        generation: generation.unwrap_or(1),
        mission_ref: None,
        context_scope: Default::default(),
        authority_scope: Default::default(),
        lifecycle: IntelligenceLifecycle::Bound,
    };
    // Ensure no model_ref/provider leak — type has neither field.
    put_json(es, INTELLIGENCE_FOLDER, &instance.intelligence_uid, &instance)?;
    put_json(
        es,
        INTELLIGENCE_FOLDER,
        &format!("by_workload:{workload_uid}"),
        &json!({ "intelligence_uid": instance.intelligence_uid }),
    )?;

    if let Some(agent_pid) = agent_pid.filter(|s| !s.trim().is_empty()) {
        let _ = native_compat::upsert_mapping_store(
            es,
            NativeCompatMapping {
                schema: COMPAT_SCHEMA.into(),
                agent_pid,
                software_uid: Some(workload.software_uid),
                workload_uid: Some(workload_uid.to_string()),
                intelligence_uid: Some(instance.intelligence_uid.clone()),
                binding_uid: None,
                updated_at_ms: 0,
            },
        )?;
    }

    Ok(instance)
}

pub fn register_intelligence(
    state: &PlatformState,
    workload_uid: &str,
    principal: &str,
    contract_ref: &str,
    generation: Option<u64>,
    agent_pid: Option<String>,
) -> Result<IntelligenceInstance, String> {
    let mut es = state
        .engine_store
        .lock()
        .map_err(|_| "engine_store_lock".to_string())?;
    register_intelligence_store(
        es.as_mut(),
        workload_uid,
        principal,
        contract_ref,
        generation,
        agent_pid,
    )
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoftwareStatus {
    pub software: Option<SoftwareIdentity>,
    pub binding: Option<AugmentedBinding>,
    pub workloads: Vec<WorkloadIdentity>,
    pub intelligences: Vec<IntelligenceInstance>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compat: Option<NativeCompatMapping>,
}

pub fn status_by_software_uid_store(es: &dyn EngineStore, software_uid: &str) -> SoftwareStatus {
    let software = get_json::<SoftwareIdentity>(es, SOFTWARE_FOLDER, software_uid);
    let binding = es
        .folder_get(BINDING_FOLDER, &format!("by_software:{software_uid}"))
        .ok()
        .flatten()
        .and_then(|v| {
            let uid = v.get("binding_uid")?.as_str()?;
            get_json::<AugmentedBinding>(es, BINDING_FOLDER, uid)
        });

    let workloads: Vec<WorkloadIdentity> = es
        .folder_keys(WORKLOAD_FOLDER, None)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|k| get_json::<WorkloadIdentity>(es, WORKLOAD_FOLDER, &k))
        .filter(|w| w.software_uid == software_uid)
        .collect();

    let wl_uids: Vec<String> = workloads.iter().map(|w| w.workload_uid.clone()).collect();
    let intelligences: Vec<IntelligenceInstance> = es
        .folder_keys(INTELLIGENCE_FOLDER, None)
        .unwrap_or_default()
        .into_iter()
        .filter(|k| !k.starts_with("by_workload:"))
        .filter_map(|k| get_json::<IntelligenceInstance>(es, INTELLIGENCE_FOLDER, &k))
        .filter(|i| wl_uids.iter().any(|u| u == &i.workload_uid))
        .collect();

    SoftwareStatus {
        software,
        binding,
        workloads,
        intelligences,
        compat: None,
    }
}

pub fn status_by_software_uid(state: &PlatformState, software_uid: &str) -> SoftwareStatus {
    let Ok(es) = state.engine_store.lock() else {
        return SoftwareStatus {
            software: None,
            binding: None,
            workloads: vec![],
            intelligences: vec![],
            compat: None,
        };
    };
    status_by_software_uid_store(es.as_ref(), software_uid)
}

pub fn status_by_agent_pid(state: &PlatformState, agent_pid: &str) -> SoftwareStatus {
    let compat = native_compat::resolve_by_agent_pid(state, agent_pid);
    if let Some(ref m) = compat {
        if let Some(ref sw) = m.software_uid {
            let mut status = status_by_software_uid(state, sw);
            status.compat = compat;
            return status;
        }
    }
    SoftwareStatus {
        software: None,
        binding: None,
        workloads: vec![],
        intelligences: vec![],
        compat,
    }
}

// ── HTTP handlers ──────────────────────────────────────────────────────────

pub async fn post_bind_software(
    axum::extract::State(state): axum::extract::State<SharedState>,
    axum::Json(req): axum::Json<SoftBindRequest>,
) -> axum::Json<Value> {
    match bind_software(state.as_ref(), req) {
        Ok((software, binding)) => axum::Json(crate::operator::honesty::measured_envelope(json!({
            "software": software,
            "binding": binding,
            "honesty": "Software bind records identity + contract; no enforcement claim yet.",
        }))),
        Err(e) => axum::Json(json!({ "ok": false, "error": e })),
    }
}

pub async fn post_register_workload(
    axum::extract::State(state): axum::extract::State<SharedState>,
    axum::Json(req): axum::Json<RegisterWorkloadRequest>,
) -> axum::Json<Value> {
    match register_workload(
        state.as_ref(),
        &req.software_uid,
        req.host_uid,
        req.process_root,
        req.posture,
        req.birth_controlled,
        req.agent_pid,
    ) {
        Ok(wl) => axum::Json(crate::operator::honesty::measured_envelope(json!({
            "workload": wl,
            "honesty": "TransportEnforced requires birth_controlled=true; attach defaults to Advisory.",
        }))),
        Err(e) => axum::Json(json!({ "ok": false, "error": e })),
    }
}

pub async fn post_register_intelligence(
    axum::extract::State(state): axum::extract::State<SharedState>,
    axum::Json(req): axum::Json<RegisterIntelligenceRequest>,
) -> axum::Json<Value> {
    match register_intelligence(
        state.as_ref(),
        &req.workload_uid,
        &req.principal,
        &req.contract_ref,
        req.generation,
        req.agent_pid,
    ) {
        Ok(inst) => {
            let body = serde_json::to_value(&inst).unwrap_or(json!({}));
            axum::Json(crate::operator::honesty::measured_envelope(json!({
                "intelligence": body,
                "honesty": "IntelligenceInstance has no model_ref/provider fields by design.",
            })))
        }
        Err(e) => axum::Json(json!({ "ok": false, "error": e })),
    }
}

pub async fn get_software_status(
    axum::extract::State(state): axum::extract::State<SharedState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> axum::Json<Value> {
    let status = if id.starts_with("sw_") {
        status_by_software_uid(state.as_ref(), &id)
    } else {
        // Treat non-sw_ ids as software_uid first, then empty.
        let by_sw = status_by_software_uid(state.as_ref(), &id);
        if by_sw.software.is_some() {
            by_sw
        } else {
            status_by_agent_pid(state.as_ref(), &id)
        }
    };
    axum::Json(crate::operator::honesty::measured_envelope(
        serde_json::to_value(status).unwrap_or(json!({})),
    ))
}

pub async fn get_compat_agent(
    axum::extract::State(state): axum::extract::State<SharedState>,
    axum::extract::Path(agent_pid): axum::extract::Path<String>,
) -> axum::Json<Value> {
    match native_compat::resolve_by_agent_pid(state.as_ref(), &agent_pid) {
        Some(m) => axum::Json(crate::operator::honesty::measured_envelope(
            serde_json::to_value(m).unwrap_or(json!({})),
        )),
        None => axum::Json(json!({
            "ok": false,
            "error": "compat_mapping_not_found",
            "agent_pid": agent_pid,
        })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use connector_engine::engine_store::InMemoryEngineStore;

    fn soft_bind(es: &mut InMemoryEngineStore) -> (SoftwareIdentity, AugmentedBinding) {
        bind_software_store(
            es,
            SoftBindRequest {
                tenant: "t1".into(),
                declared_name: "demo-sw".into(),
                executable_selector: "/usr/bin/demo".into(),
                digest: Some("deadbeef".into()),
                publisher: Some("pub".into()),
                contract_ref: "contract:v1".into(),
                mode: BindingMode::Attached,
                adapters: vec!["http".into()],
                enforcement_requirements: vec![],
                agent_pid: Some("agent_demo".into()),
            },
        )
        .expect("bind")
    }

    #[test]
    fn bind_workload_intelligence_chain_advisory() {
        let mut es = InMemoryEngineStore::new();
        let (sw, binding) = soft_bind(&mut es);
        assert!(sw.software_uid.starts_with("sw_"));
        assert_eq!(binding.mode, BindingMode::Attached);

        let wl = register_workload_store(
            &mut es,
            &sw.software_uid,
            Some("host_1".into()),
            None,
            None,
            false,
            Some("agent_demo".into()),
        )
        .expect("wl");
        assert_eq!(wl.enforcement_posture, EnforcementPosture::Advisory);

        let intel = register_intelligence_store(
            &mut es,
            &wl.workload_uid,
            "principal:alice",
            "contract:v1",
            Some(1),
            Some("agent_demo".into()),
        )
        .expect("intel");
        assert!(intel.intelligence_uid.starts_with("intel_"));
        assert_eq!(intel.workload_uid, wl.workload_uid);

        let ser = serde_json::to_value(&intel).unwrap();
        assert!(ser.get("model_ref").is_none());
        assert!(ser.get("provider").is_none());

        let compat = native_compat::resolve_by_agent_pid_store(&es, "agent_demo").expect("compat");
        assert_eq!(compat.software_uid.as_deref(), Some(sw.software_uid.as_str()));
        assert_eq!(compat.workload_uid.as_deref(), Some(wl.workload_uid.as_str()));
        assert_eq!(
            compat.intelligence_uid.as_deref(),
            Some(intel.intelligence_uid.as_str())
        );
    }

    #[test]
    fn birth_controlled_false_cannot_get_transport_enforced() {
        assert_eq!(
            resolve_workload_posture(Some(EnforcementPosture::TransportEnforced), false),
            EnforcementPosture::Advisory
        );
        assert_eq!(
            resolve_workload_posture(Some(EnforcementPosture::Native), false),
            EnforcementPosture::Advisory
        );
        assert_eq!(
            resolve_workload_posture(None, false),
            EnforcementPosture::Advisory
        );
        assert_eq!(
            resolve_workload_posture(None, true),
            EnforcementPosture::TransportEnforced
        );
        assert_eq!(
            resolve_workload_posture(Some(EnforcementPosture::TransportEnforced), true),
            EnforcementPosture::TransportEnforced
        );
    }
}

//! Composable `WorkloadSecurityProfile` — engineer-owned policy over one kernel mechanism set.
//!
//! Profiles are configuration bundles, not alternate security implementations.
//! `START_REFUSED` applies only when the selected profile declares a mandatory unmet mechanism.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::state::{PlatformState, SharedState};

pub const SCHEMA: &str = "connector.workload_security_profile.v1";
pub const FOLDER: &str = "_workload_profiles";
pub const ACTIVE_KEY: &str = "active";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileId {
    LocalOpen,
    DeveloperGuarded,
    PilotBounded,
    EnterpriseHardened,
    RegulatedEvidence,
    AirgapSovereign,
    EdgeOffline,
    OtSafetyIntegrated,
    Custom,
}

impl ProfileId {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LocalOpen => "local-open",
            Self::DeveloperGuarded => "developer-guarded",
            Self::PilotBounded => "pilot-bounded",
            Self::EnterpriseHardened => "enterprise-hardened",
            Self::RegulatedEvidence => "regulated-evidence",
            Self::AirgapSovereign => "airgap-sovereign",
            Self::EdgeOffline => "edge-offline",
            Self::OtSafetyIntegrated => "ot-safety-integrated",
            Self::Custom => "custom",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "local-open" | "local_open" | "open" => Some(Self::LocalOpen),
            "developer-guarded" | "developer_guarded" | "dev-guarded" => {
                Some(Self::DeveloperGuarded)
            }
            "pilot-bounded" | "pilot_bounded" | "pilots" | "pilot" => Some(Self::PilotBounded),
            "enterprise-hardened" | "enterprise_hardened" | "enterprise" | "production" => {
                Some(Self::EnterpriseHardened)
            }
            "regulated-evidence" | "regulated_evidence" | "regulated" => {
                Some(Self::RegulatedEvidence)
            }
            "airgap-sovereign" | "airgap_sovereign" | "airgap" => Some(Self::AirgapSovereign),
            "edge-offline" | "edge_offline" | "edge" => Some(Self::EdgeOffline),
            "ot-safety-integrated" | "ot_safety_integrated" | "ot" => {
                Some(Self::OtSafetyIntegrated)
            }
            "custom" => Some(Self::Custom),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkloadSecurityProfile {
    pub schema: String,
    pub id: String,
    pub label: String,
    pub description: String,
    /// Authentication strength: open | session | jwt | mtls
    pub authentication: String,
    /// Tenant isolation: none | soft | hard
    pub tenant_isolation: String,
    /// HITL: off | high_risk | always
    pub hitl: String,
    /// Network pores: open | allowlist | deny_by_default
    pub network: String,
    /// Isolation body: subprocess | namespace | microvm | tee
    pub isolation_body: String,
    /// Evidence strength: none | audit | signed | custody
    pub evidence: String,
    /// Fail posture for unreachable policy deps: open | closed
    pub fail_posture: String,
    /// Require production-grade crypto secrets
    pub require_crypto_secrets: bool,
    /// Refuse start when mandatory mechanisms unmet
    pub refuse_start_on_unmet: bool,
    /// Physical/OT safety partner interlock required
    pub require_ot_safety_interlock: bool,
    pub notes: Vec<String>,
}

impl WorkloadSecurityProfile {
    pub fn reference(id: ProfileId) -> Self {
        match id {
            ProfileId::LocalOpen => Self {
                schema: SCHEMA.into(),
                id: id.as_str().into(),
                label: "Local open".into(),
                description: "Lab / laptop — open auth, subprocess OK, fail-open deps.".into(),
                authentication: "open".into(),
                tenant_isolation: "none".into(),
                hitl: "off".into(),
                network: "open".into(),
                isolation_body: "subprocess".into(),
                evidence: "audit".into(),
                fail_posture: "open".into(),
                require_crypto_secrets: false,
                refuse_start_on_unmet: false,
                require_ot_safety_interlock: false,
                notes: vec!["Not for production data.".into()],
            },
            ProfileId::DeveloperGuarded => Self {
                schema: SCHEMA.into(),
                id: id.as_str().into(),
                label: "Developer guarded".into(),
                description: "JWT + RBAC, allowlisted egress, namespace preferred.".into(),
                authentication: "jwt".into(),
                tenant_isolation: "soft".into(),
                hitl: "high_risk".into(),
                network: "allowlist".into(),
                isolation_body: "namespace".into(),
                evidence: "audit".into(),
                fail_posture: "closed".into(),
                require_crypto_secrets: true,
                refuse_start_on_unmet: false,
                require_ot_safety_interlock: false,
                notes: vec![],
            },
            ProfileId::PilotBounded => Self {
                schema: SCHEMA.into(),
                id: id.as_str().into(),
                label: "Pilot bounded".into(),
                description: "Scoped pilot keys, budgets, HITL on high-risk.".into(),
                authentication: "jwt".into(),
                tenant_isolation: "hard".into(),
                hitl: "high_risk".into(),
                network: "allowlist".into(),
                isolation_body: "microvm".into(),
                evidence: "signed".into(),
                fail_posture: "closed".into(),
                require_crypto_secrets: true,
                refuse_start_on_unmet: true,
                require_ot_safety_interlock: false,
                notes: vec!["Matches CONNECTOR_ENV=pilots intent.".into()],
            },
            ProfileId::EnterpriseHardened => Self {
                schema: SCHEMA.into(),
                id: id.as_str().into(),
                label: "Enterprise hardened".into(),
                description: "Production default — microVM, deny-by-default egress, signed evidence.".into(),
                authentication: "jwt".into(),
                tenant_isolation: "hard".into(),
                hitl: "high_risk".into(),
                network: "deny_by_default".into(),
                isolation_body: "microvm".into(),
                evidence: "signed".into(),
                fail_posture: "closed".into(),
                require_crypto_secrets: true,
                refuse_start_on_unmet: true,
                require_ot_safety_interlock: false,
                notes: vec!["Example profile — engineer owns threat model.".into()],
            },
            ProfileId::RegulatedEvidence => Self {
                schema: SCHEMA.into(),
                id: id.as_str().into(),
                label: "Regulated evidence".into(),
                description: "Custody + WitnessCtl quorum, long retention, no fail-open.".into(),
                authentication: "mtls".into(),
                tenant_isolation: "hard".into(),
                hitl: "always".into(),
                network: "deny_by_default".into(),
                isolation_body: "microvm".into(),
                evidence: "custody".into(),
                fail_posture: "closed".into(),
                require_crypto_secrets: true,
                refuse_start_on_unmet: true,
                require_ot_safety_interlock: false,
                notes: vec!["Does not itself constitute a SOC2 attestation.".into()],
            },
            ProfileId::AirgapSovereign => Self {
                schema: SCHEMA.into(),
                id: id.as_str().into(),
                label: "Air-gap sovereign".into(),
                description: "No outbound pores; local crypto; offline evidence.".into(),
                authentication: "mtls".into(),
                tenant_isolation: "hard".into(),
                hitl: "always".into(),
                network: "deny_by_default".into(),
                isolation_body: "microvm".into(),
                evidence: "custody".into(),
                fail_posture: "closed".into(),
                require_crypto_secrets: true,
                refuse_start_on_unmet: true,
                require_ot_safety_interlock: false,
                notes: vec!["Outbound must be structurally unavailable.".into()],
            },
            ProfileId::EdgeOffline => Self {
                schema: SCHEMA.into(),
                id: id.as_str().into(),
                label: "Edge offline".into(),
                description: "Constrained edge cell — namespace OK, intermittent sync.".into(),
                authentication: "jwt".into(),
                tenant_isolation: "soft".into(),
                hitl: "high_risk".into(),
                network: "allowlist".into(),
                isolation_body: "namespace".into(),
                evidence: "signed".into(),
                fail_posture: "closed".into(),
                require_crypto_secrets: true,
                refuse_start_on_unmet: false,
                require_ot_safety_interlock: false,
                notes: vec![],
            },
            ProfileId::OtSafetyIntegrated => Self {
                schema: SCHEMA.into(),
                id: id.as_str().into(),
                label: "OT safety integrated".into(),
                description: "Physical actuation — partner safety interlock required.".into(),
                authentication: "mtls".into(),
                tenant_isolation: "hard".into(),
                hitl: "always".into(),
                network: "deny_by_default".into(),
                isolation_body: "microvm".into(),
                evidence: "custody".into(),
                fail_posture: "closed".into(),
                require_crypto_secrets: true,
                refuse_start_on_unmet: true,
                require_ot_safety_interlock: true,
                notes: vec![
                    "Connector does not replace SIL/ISO robotics safety.".into(),
                    "Partner interlock attestation required before claim.".into(),
                ],
            },
            ProfileId::Custom => Self {
                schema: SCHEMA.into(),
                id: id.as_str().into(),
                label: "Custom".into(),
                description: "Engineer-composed profile.".into(),
                authentication: "jwt".into(),
                tenant_isolation: "soft".into(),
                hitl: "high_risk".into(),
                network: "allowlist".into(),
                isolation_body: "microvm".into(),
                evidence: "signed".into(),
                fail_posture: "closed".into(),
                require_crypto_secrets: true,
                refuse_start_on_unmet: false,
                require_ot_safety_interlock: false,
                notes: vec![],
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileCompileResult {
    pub profile_id: String,
    pub effective: WorkloadSecurityProfile,
    pub unmet: Vec<String>,
    pub weakening_deltas: Vec<String>,
    pub expected_evidence: Vec<String>,
    pub start_refused: bool,
    pub refuse_reason: Option<String>,
}

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

fn has_crypto_secret() -> bool {
    for k in [
        "CONNECTOR_EFFECT_AUTHZ_HMAC",
        "CONNECTOR_AUDIT_HMAC_KEY",
        "CONNECTOR_AUDIT_HMAC_SECRET",
    ] {
        if std::env::var(k).ok().filter(|s| !s.trim().is_empty()).is_some() {
            return true;
        }
    }
    false
}

/// Compile profile against live host mechanisms (Requested vs Available).
pub fn compile(profile: &WorkloadSecurityProfile, state: &PlatformState) -> ProfileCompileResult {
    let mut unmet = Vec::new();
    let mut weakening = Vec::new();
    let mut expected = Vec::new();

    if profile.require_crypto_secrets && !has_crypto_secret() {
        unmet.push("production-grade HMAC secrets (CONNECTOR_AUDIT_HMAC_KEY / EFFECT_AUTHZ)".into());
    }

    let isolation = *state.isolation_runtime.read().unwrap();
    let isolation_s = isolation.as_str();
    match profile.isolation_body.as_str() {
        "microvm" | "tee" => {
            if isolation_s != "microvm" && isolation_s != "tee" {
                unmet.push(format!(
                    "isolation_body={} but runtime is {}",
                    profile.isolation_body, isolation_s
                ));
            }
        }
        "namespace" => {
            if isolation_s == "subprocess" || isolation_s == "internal" {
                weakening.push(format!(
                    "profile wants namespace; effective isolation is {isolation_s}"
                ));
            }
        }
        _ => {}
    }

    if profile.fail_posture == "closed"
        && env_flag("CONNECTOR_CAPS_ALLOW_MOCK")
        && crate::connector_profile::is_productionish_env()
    {
        unmet.push("CONNECTOR_CAPS_ALLOW_MOCK forbidden under closed fail posture".into());
    }

    if profile.require_ot_safety_interlock && !env_flag("CONNECTOR_OT_SAFETY_INTERLOCK_OK") {
        unmet.push(
            "OT safety partner interlock not attested (set CONNECTOR_OT_SAFETY_INTERLOCK_OK=1 after partner proof)"
                .into(),
        );
    }

    if profile.authentication == "jwt" || profile.authentication == "mtls" {
        if crate::services::runtime_control::dev_auth_bypass_allowed() {
            weakening.push("dev auth bypass is active while profile requires JWT/mTLS".into());
        }
    }

    match profile.evidence.as_str() {
        "custody" => {
            expected.push("WitnessCtl custody / quorum receipts".into());
            expected.push("CFNI sealed envelopes".into());
        }
        "signed" => {
            expected.push("signed audit / effect envelopes".into());
        }
        "audit" => {
            expected.push("local audit log".into());
        }
        _ => {
            expected.push("no cryptographic evidence promised".into());
        }
    }

    let start_refused = profile.refuse_start_on_unmet && !unmet.is_empty();
    let refuse_reason = if start_refused {
        Some(format!(
            "START_REFUSED: profile {} unmet: {}",
            profile.id,
            unmet.join("; ")
        ))
    } else {
        None
    };

    ProfileCompileResult {
        profile_id: profile.id.clone(),
        effective: profile.clone(),
        unmet,
        weakening_deltas: weakening,
        expected_evidence: expected,
        start_refused,
        refuse_reason,
    }
}

pub fn default_profile_for_env() -> WorkloadSecurityProfile {
    let env = std::env::var("CONNECTOR_ENV")
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    let id = match env.as_str() {
        "production" | "prod" | "staging" => ProfileId::EnterpriseHardened,
        "pilots" | "pilot" => ProfileId::PilotBounded,
        "development" | "dev" | "" => ProfileId::LocalOpen,
        _ if crate::connector_profile::is_productionish_env() => ProfileId::EnterpriseHardened,
        _ => ProfileId::LocalOpen,
    };
    if let Ok(override_id) = std::env::var("CONNECTOR_WORKLOAD_PROFILE") {
        if let Some(pid) = ProfileId::from_str(&override_id) {
            return WorkloadSecurityProfile::reference(pid);
        }
    }
    WorkloadSecurityProfile::reference(id)
}

pub fn load_active(state: &PlatformState) -> WorkloadSecurityProfile {
    if let Ok(es) = state.engine_store.lock() {
        if let Ok(Some(v)) = es.folder_get(FOLDER, ACTIVE_KEY) {
            if let Ok(p) = serde_json::from_value::<WorkloadSecurityProfile>(v) {
                return p;
            }
        }
    }
    default_profile_for_env()
}

pub fn persist_active(state: &PlatformState, profile: &WorkloadSecurityProfile) -> Result<(), String> {
    let mut es = state
        .engine_store
        .lock()
        .map_err(|_| "engine_store lock poisoned".to_string())?;
    let val = serde_json::to_value(profile).map_err(|e| e.to_string())?;
    es.folder_put(FOLDER, ACTIVE_KEY, &val)
        .map_err(|e| e.to_string())?;
    Ok(())
}

pub fn list_references() -> Vec<WorkloadSecurityProfile> {
    [
        ProfileId::LocalOpen,
        ProfileId::DeveloperGuarded,
        ProfileId::PilotBounded,
        ProfileId::EnterpriseHardened,
        ProfileId::RegulatedEvidence,
        ProfileId::AirgapSovereign,
        ProfileId::EdgeOffline,
        ProfileId::OtSafetyIntegrated,
    ]
    .into_iter()
    .map(WorkloadSecurityProfile::reference)
    .collect()
}

pub fn posture_json(state: &PlatformState) -> Value {
    let active = load_active(state);
    let compiled = compile(&active, state);
    json!({
        "schema": SCHEMA,
        "active": active,
        "compiled": compiled,
        "references": list_references().iter().map(|p| p.id.clone()).collect::<Vec<_>>(),
        "honesty": "Profiles are engineer-selected mechanism bundles; Connector does not claim universal security.",
    })
}

/// Refuse agent start when active profile compiles to START_REFUSED.
pub fn assert_start_allowed(state: &PlatformState) -> Result<(), Value> {
    let active = load_active(state);
    let compiled = compile(&active, state);
    if compiled.start_refused {
        return Err(json!({
            "error": "START_REFUSED",
            "code": "workload_profile_unmet",
            "profile": active.id,
            "unmet": compiled.unmet,
            "hint": compiled.refuse_reason,
        }));
    }
    Ok(())
}

// ── HTTP handlers ──────────────────────────────────────────────────────────

pub async fn get_profile(
    axum::extract::State(state): axum::extract::State<SharedState>,
) -> axum::Json<Value> {
    axum::Json(crate::operator::honesty::operator_envelope(posture_json(
        state.as_ref(),
    )))
}

pub async fn list_profiles() -> axum::Json<Value> {
    axum::Json(crate::operator::honesty::operator_envelope(json!({
        "schema": SCHEMA,
        "profiles": list_references(),
    })))
}

#[derive(Debug, Deserialize)]
pub struct SetProfileRequest {
    pub profile_id: String,
    #[serde(default)]
    pub custom: Option<WorkloadSecurityProfile>,
}

pub async fn set_profile(
    axum::extract::State(state): axum::extract::State<SharedState>,
    axum::Json(req): axum::Json<SetProfileRequest>,
) -> axum::Json<Value> {
    let profile = if let Some(custom) = req.custom {
        let mut c = custom;
        c.schema = SCHEMA.into();
        c.id = "custom".into();
        c
    } else if let Some(pid) = ProfileId::from_str(&req.profile_id) {
        WorkloadSecurityProfile::reference(pid)
    } else {
        return axum::Json(json!({
            "ok": false,
            "error": "unknown_profile",
            "hint": "Use one of the reference ids or supply custom",
        }));
    };
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        "security-profile",
        "runtime",
        "set_profile",
        &json!({"profile_id": profile.id}),
    ) {
        Ok(atu) => atu,
        Err(body) => return axum::Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    if let Err(e) = persist_active(state.as_ref(), &profile) {
        open_proceed.finish_observed(false);
        return axum::Json(json!({
            "ok": false,
            "error": e,
            "task_id": admitted.task_id,
            "executed": false,
            "admits": false,
        }));
    }
    open_proceed.finish_observed(true);
    let compiled = compile(&profile, state.as_ref());
    axum::Json(crate::operator::honesty::operator_envelope(json!({
        "ok": true,
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
        "active": profile,
        "compiled": compiled,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reference_ids_roundtrip() {
        for id in [
            ProfileId::LocalOpen,
            ProfileId::EnterpriseHardened,
            ProfileId::OtSafetyIntegrated,
        ] {
            assert_eq!(ProfileId::from_str(id.as_str()), Some(id));
        }
    }

    #[test]
    fn enterprise_requires_crypto_when_missing() {
        std::env::remove_var("CONNECTOR_EFFECT_AUTHZ_HMAC");
        std::env::remove_var("CONNECTOR_AUDIT_HMAC_KEY");
        std::env::remove_var("CONNECTOR_AUDIT_HMAC_SECRET");
        let p = WorkloadSecurityProfile::reference(ProfileId::EnterpriseHardened);
        assert!(p.require_crypto_secrets);
        assert!(p.refuse_start_on_unmet);
    }
}

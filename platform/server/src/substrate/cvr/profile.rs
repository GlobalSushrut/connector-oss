//! Isolation profiles V0–V4 — engineer intent, not VMM plumbing.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::host_probe::{probe_host, HostProbe};

/// Engineer-facing isolation intent (YAML / API).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IsolationIntent {
    Auto,
    LinuxCell,
    HardenedLinuxCell,
    SharedMicrovm,
    DedicatedMicrovm,
}

impl IsolationIntent {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::LinuxCell => "linux-cell",
            Self::HardenedLinuxCell => "hardened-linux-cell",
            Self::SharedMicrovm => "shared-microvm",
            Self::DedicatedMicrovm => "dedicated-microvm",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().replace('_', "-").as_str() {
            "auto" => Some(Self::Auto),
            "linux-cell" | "linux" | "agentcell" | "v1" => Some(Self::LinuxCell),
            "hardened-linux-cell" | "hardened-linux" | "v2" => Some(Self::HardenedLinuxCell),
            "shared-microvm" | "shared-microcell" | "v3" => Some(Self::SharedMicrovm),
            "dedicated-microvm" | "dedicated-microcell" | "v4" => Some(Self::DedicatedMicrovm),
            _ => None,
        }
    }

    pub fn from_env() -> Self {
        if let Ok(v) = std::env::var("CONNECTOR_AGENT_ISOLATION") {
            if let Some(i) = Self::parse(&v) {
                return i;
            }
        }
        Self::Auto
    }
}

/// Architectural profile levels (architecture §15).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum IsolationProfile {
    V0,
    V1,
    V2,
    V3,
    V4,
}

impl IsolationProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::V0 => "V0",
            Self::V1 => "V1",
            Self::V2 => "V2",
            Self::V3 => "V3",
            Self::V4 => "V4",
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            Self::V0 => "Logical / Lab",
            Self::V1 => "AgentCell",
            Self::V2 => "Hardened AgentCell",
            Self::V3 => "Shared MicroCell",
            Self::V4 => "Dedicated MicroCell",
        }
    }

    pub fn requires_microcell(self) -> bool {
        matches!(self, Self::V3 | Self::V4)
    }

    pub fn requires_jailer(self) -> bool {
        matches!(self, Self::V3 | Self::V4)
    }

    pub fn requires_dedicated_microcell(self) -> bool {
        matches!(self, Self::V4)
    }

    pub fn catalog() -> Value {
        json!([
            {"id": "V0", "title": Self::V0.title(), "body": "logical", "use": "development only"},
            {"id": "V1", "title": Self::V1.title(), "body": "agentcell", "use": "high-density default"},
            {"id": "V2", "title": Self::V2.title(), "body": "agentcell_hardened", "use": "pilot/harden Linux"},
            {"id": "V3", "title": Self::V3.title(), "body": "microcell_shared", "use": "untrusted pool"},
            {"id": "V4", "title": Self::V4.title(), "body": "microcell_dedicated", "use": "high-risk / R3"},
        ])
    }
}

/// Optional risk hint for `auto` (architecture §17). Does not grant authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskHint {
    R0,
    R1,
    R2,
    R3,
    UntrustedCode,
}

impl RiskHint {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_uppercase().as_str() {
            "R0" => Some(Self::R0),
            "R1" => Some(Self::R1),
            "R2" => Some(Self::R2),
            "R3" => Some(Self::R3),
            "UNTRUSTED" | "UNTRUSTED_CODE" | "CODE" => Some(Self::UntrustedCode),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ResolvedIsolation {
    pub intent: IsolationIntent,
    pub profile: IsolationProfile,
    pub required: bool,
    pub allow_degraded: bool,
    pub body_kind: &'static str,
    pub reason: String,
}

impl ResolvedIsolation {
    pub fn to_json(&self) -> Value {
        json!({
            "intent": self.intent.as_str(),
            "profile": self.profile.as_str(),
            "profile_title": self.profile.title(),
            "required": self.required,
            "allow_degraded": self.allow_degraded,
            "body_kind": self.body_kind,
            "requires_microcell": self.profile.requires_microcell(),
            "requires_jailer": self.profile.requires_jailer(),
            "reason": self.reason,
        })
    }
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

/// Resolve engineer intent (+ optional risk) → IsolationProfile.
pub fn resolve_isolation(intent: IsolationIntent, risk: Option<RiskHint>) -> ResolvedIsolation {
    let required = env_flag("CONNECTOR_ISOLATION_REQUIRED")
        || matches!(
            intent,
            IsolationIntent::SharedMicrovm | IsolationIntent::DedicatedMicrovm
        ) && env_flag("CONNECTOR_MICROCELL_REQUIRED");
    let allow_degraded = env_flag("CONNECTOR_ISOLATION_ALLOW_DEGRADED");

    let (profile, reason) = match intent {
        IsolationIntent::LinuxCell => (IsolationProfile::V1, "explicit linux-cell".into()),
        IsolationIntent::HardenedLinuxCell => {
            (IsolationProfile::V2, "explicit hardened-linux-cell".into())
        }
        IsolationIntent::SharedMicrovm => (IsolationProfile::V3, "explicit shared-microvm".into()),
        IsolationIntent::DedicatedMicrovm => {
            (IsolationProfile::V4, "explicit dedicated-microvm".into())
        }
        IsolationIntent::Auto => {
            let r = risk.unwrap_or_else(auto_risk_from_env);
            let table = super::auto_policy::AutoPolicyTable::load();
            table.resolve(r)
        }
    };

    let body_kind = match profile {
        IsolationProfile::V0 => "logical",
        IsolationProfile::V1 | IsolationProfile::V2 => "agentcell",
        IsolationProfile::V3 => "microcell_shared",
        IsolationProfile::V4 => "microcell_dedicated",
    };

    // Playground forces V0/V1 soft unless explicit microvm intent.
    let (profile, reason, required) = if crate::services::playground::is_playground_mode()
        && !matches!(
            intent,
            IsolationIntent::SharedMicrovm | IsolationIntent::DedicatedMicrovm
        )
    {
        (
            IsolationProfile::V0,
            format!("{reason} · playground → V0 lab"),
            false,
        )
    } else {
        (profile, reason, required || profile.requires_microcell() && env_flag("CONNECTOR_AUGMENTED_ENV"))
    };

    ResolvedIsolation {
        intent,
        profile,
        required,
        allow_degraded,
        body_kind,
        reason,
    }
}

fn auto_risk_from_env() -> RiskHint {
    if let Ok(v) = std::env::var("CONNECTOR_ISOLATION_AUTO_RISK") {
        if let Some(r) = RiskHint::parse(&v) {
            return r;
        }
    }
    if crate::kernel::agent_principal::intelligence_hardening_on() {
        RiskHint::R1
    } else {
        RiskHint::R0
    }
}

/// Resolve for a specific agent (reads agent_meta.isolation if set).
pub fn resolve_for_agent(state: &crate::state::PlatformState, agent_pid: &str) -> ResolvedIsolation {
    let intent = load_agent_intent(state, agent_pid).unwrap_or_else(IsolationIntent::from_env);
    let risk = load_agent_risk(state, agent_pid);
    resolve_isolation(intent, risk)
}

fn load_agent_intent(state: &crate::state::PlatformState, agent_pid: &str) -> Option<IsolationIntent> {
    let es = state.engine_store.lock().ok()?;
    let meta = es.folder_get("agent_meta", agent_pid).ok().flatten()?;
    let s = meta
        .get("isolation")
        .or_else(|| meta.pointer("/isolation/intent"))
        .and_then(|v| v.as_str())?;
    IsolationIntent::parse(s)
}

fn load_agent_risk(state: &crate::state::PlatformState, agent_pid: &str) -> Option<RiskHint> {
    let es = state.engine_store.lock().ok()?;
    let meta = es.folder_get("agent_meta", agent_pid).ok().flatten()?;
    let s = meta
        .get("isolation_risk")
        .or_else(|| meta.get("risk_class"))
        .and_then(|v| v.as_str())?;
    RiskHint::parse(s)
}

/// Assert MicroCell-capable when resolved profile requires it (fail closed).
pub fn assert_profile_ready(
    resolved: &ResolvedIsolation,
    probe: &HostProbe,
) -> Result<(), Value> {
    if !resolved.profile.requires_microcell() {
        return Ok(());
    }
    if probe.microcell_ready() {
        return Ok(());
    }
    if resolved.allow_degraded && !resolved.required {
        return Ok(());
    }
    Err(json!({
        "ok": false,
        "status": 503,
        "error": "START_REFUSED",
        "denial_reason": "microcell_runtime_unavailable",
        "schema": "connector.cvr.isolation.gate.v1",
        "requested_profile": resolved.profile.as_str(),
        "host_probe": probe.to_json(),
        "honesty": "Required MicroCell posture cannot silently fall back to AgentCell",
        "hint": "Install RuntimeBundle + KVM, or set isolation to linux-cell / allow_degraded",
    }))
}

/// Applied/effective honesty for a resolved profile given live probe.
pub fn posture_triad_for(resolved: &ResolvedIsolation, probe: &HostProbe) -> Value {
    let requested = resolved.profile.as_str();
    let (applied, effective, detail) = if resolved.profile.requires_microcell() {
        if probe.microcell_ready() {
            (
                resolved.profile.as_str(),
                "hardened_ready",
                "HostProbe + RuntimeBundle verify — MicroCell path available",
            )
        } else if resolved.allow_degraded && !resolved.required {
            (
                "V2",
                "degraded",
                "MicroCell unavailable — degraded to Hardened AgentCell (explicit allow_degraded)",
            )
        } else if resolved.required || resolved.profile.requires_microcell() {
            (
                "none",
                "unavailable",
                "MicroCell required but HostProbe incomplete",
            )
        } else {
            ("none", "unavailable", "MicroCell not ready")
        }
    } else {
        match resolved.profile {
            IsolationProfile::V0 => ("V0", "lab", "Logical isolation only"),
            IsolationProfile::V1 => ("V1", "agentcell", "Linux AgentCell materials"),
            IsolationProfile::V2 => ("V2", "agentcell_hardened", "Hardened AgentCell"),
            _ => ("unknown", "unknown", ""),
        }
    };
    json!({
        "requested": requested,
        "applied": applied,
        "effective": effective,
        "detail": detail,
        "met": effective != "unavailable" && effective != "degraded" || (effective == "degraded" && resolved.allow_degraded),
        "degraded_labeled": effective == "degraded",
        "intent": resolved.to_json(),
        "host_probe_ready": probe.microcell_ready(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_intents() {
        assert_eq!(
            IsolationIntent::parse("dedicated-microvm"),
            Some(IsolationIntent::DedicatedMicrovm)
        );
        assert_eq!(IsolationIntent::parse("v2"), Some(IsolationIntent::HardenedLinuxCell));
    }

    #[test]
    fn auto_r3_is_v4() {
        let r = resolve_isolation(IsolationIntent::Auto, Some(RiskHint::R3));
        assert_eq!(r.profile, IsolationProfile::V4);
        assert!(r.profile.requires_microcell());
    }

    #[test]
    fn linux_cell_is_v1() {
        let r = resolve_isolation(IsolationIntent::LinuxCell, None);
        assert_eq!(r.profile, IsolationProfile::V1);
        assert!(!r.profile.requires_microcell());
    }

    #[test]
    fn assert_v4_refuses_without_probe() {
        let r = resolve_isolation(IsolationIntent::DedicatedMicrovm, None);
        let mut probe = HostProbe::empty();
        probe.kvm_usable = false;
        let err = assert_profile_ready(&r, &probe).unwrap_err();
        assert_eq!(err.get("error").and_then(|v| v.as_str()), Some("START_REFUSED"));
    }
}

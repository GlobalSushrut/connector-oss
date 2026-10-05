//! Resource profiles for MicroCell / AgentCell sizing (Phase E4).
//!
//! Honesty: these are **operator-chosen envelopes**, not density marketing claims.
//! Do not cite "N agents per host" without a measured benchmark artifact.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ResourceProfile {
    Small,
    #[default]
    Default,
    Compute,
}

impl ResourceProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Small => "small",
            Self::Default => "default",
            Self::Compute => "compute",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "small" | "sm" => Some(Self::Small),
            "default" | "medium" | "med" | "" => Some(Self::Default),
            "compute" | "large" | "lg" => Some(Self::Compute),
            _ => None,
        }
    }

    pub fn from_env() -> Self {
        std::env::var("CONNECTOR_AGENT_RESOURCES")
            .ok()
            .and_then(|v| Self::parse(&v))
            .unwrap_or_default()
    }

    /// Guest machine envelope for a MicroCell (shared vs dedicated).
    pub fn machine(&self, dedicated: bool) -> (u8, u32) {
        match (self, dedicated) {
            (Self::Small, false) => (1, 256),
            (Self::Small, true) => (1, 256),
            (Self::Default, false) => (1, 384),
            (Self::Default, true) => (2, 512),
            (Self::Compute, false) => (2, 512),
            (Self::Compute, true) => (4, 1024),
        }
    }

    pub fn catalog() -> Value {
        json!([
            {
                "id": "small",
                "shared": {"vcpu": 1, "mem_mib": 256},
                "dedicated": {"vcpu": 1, "mem_mib": 256},
                "use": "light tasks / constrained hosts",
            },
            {
                "id": "default",
                "shared": {"vcpu": 1, "mem_mib": 384},
                "dedicated": {"vcpu": 2, "mem_mib": 512},
                "use": "general agents",
            },
            {
                "id": "compute",
                "shared": {"vcpu": 2, "mem_mib": 512},
                "dedicated": {"vcpu": 4, "mem_mib": 1024},
                "use": "CPU-heavy workloads",
            },
        ])
    }

    pub fn to_json(self, dedicated: bool) -> Value {
        let (vcpu, mem) = self.machine(dedicated);
        json!({
            "profile": self.as_str(),
            "dedicated": dedicated,
            "vcpu_count": vcpu,
            "mem_mib": mem,
            "honesty": "Envelope only — not a capacity guarantee or density claim",
        })
    }
}

/// Load resource profile from agent_meta or env.
pub fn resolve_for_agent(state: &crate::state::PlatformState, agent_pid: &str) -> ResourceProfile {
    if let Ok(es) = state.engine_store.lock() {
        if let Ok(Some(meta)) = es.folder_get("agent_meta", agent_pid) {
            if let Some(s) = meta
                .get("resources")
                .or_else(|| meta.get("resource_profile"))
                .and_then(|v| v.as_str())
            {
                if let Some(p) = ResourceProfile::parse(s) {
                    return p;
                }
            }
        }
    }
    ResourceProfile::from_env()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_dedicated_larger() {
        let (v, m) = ResourceProfile::Compute.machine(true);
        assert!(v >= 2 && m >= 512);
    }

    #[test]
    fn parse_aliases() {
        assert_eq!(ResourceProfile::parse("large"), Some(ResourceProfile::Compute));
    }
}

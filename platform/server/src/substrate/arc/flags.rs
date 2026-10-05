//! ARC feature flags (honesty — surfaced on status + escape hatches).

use serde_json::{json, Value};

fn env_on(key: &str) -> bool {
    std::env::var(key)
        .map(|v| {
            let t = v.trim().to_ascii_lowercase();
            matches!(t.as_str(), "1" | "true" | "yes" | "on")
        })
        .unwrap_or(false)
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ArcFlags {
    pub governor: bool,
    pub lease: bool,
    pub ifc: bool,
    pub avsock: bool,
    pub scheduler: bool,
    /// Soft (default): governor off = no-op. Harden: governor off → deny effects.
    pub harden: bool,
    /// Memory class ABI enforcement (Phase H).
    pub memory: bool,
}

impl ArcFlags {
    pub fn from_env() -> Self {
        Self {
            governor: env_on("CONNECTOR_ARC_GOVERNOR"),
            lease: env_on("CONNECTOR_ARC_LEASE"),
            ifc: env_on("CONNECTOR_ARC_IFC"),
            avsock: env_on("CONNECTOR_ARC_AVSOCK"),
            scheduler: env_on("CONNECTOR_ARC_SCHEDULER"),
            harden: env_on("CONNECTOR_ARC_HARDEN"),
            memory: env_on("CONNECTOR_ARC_MEMORY"),
        }
    }

    pub fn to_json(self) -> Value {
        json!({
            "CONNECTOR_ARC_GOVERNOR": self.governor,
            "CONNECTOR_ARC_LEASE": self.lease,
            "CONNECTOR_ARC_IFC": self.ifc,
            "CONNECTOR_ARC_AVSOCK": self.avsock,
            "CONNECTOR_ARC_SCHEDULER": self.scheduler,
            "CONNECTOR_ARC_HARDEN": self.harden,
            "CONNECTOR_ARC_MEMORY": self.memory,
            "default": "all off — Phase A digests only; no behavior change",
            "b4": if self.harden {
                "Harden: skip governor → deny"
            } else {
                "Soft: governor off = log-only no-op"
            },
        })
    }
}

//! Scoped configuration envelope — Phase 2 foundation.
//!
//! Unifies provenance across node / intelligence / runtime / package planes
//! without merging incompatible `connector.yaml` schemas yet.

use serde::{Deserialize, Serialize};

pub const CONFIG_ENVELOPE_SCHEMA: &str = "connector.config.envelope.v1";

/// Which configuration plane a value belongs to.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ConfigPlane {
    Node,
    Intelligence,
    Runtime,
    Secrets,
    Package,
}

/// Where a config value originated.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum ConfigSource {
    EnvVar { key: String },
    File { path: String, plane: ConfigPlane },
    EngineStore { folder: String, key: String },
    RuntimeOverlay { handler: String },
    Preset { id: String },
    PackageDigest { package_id: String, digest: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConfigProvenance {
    pub plane: ConfigPlane,
    pub source: ConfigSource,
    /// False when a higher-precedence layer overrode this value.
    pub applied: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeProfileRef {
    pub host: Option<String>,
    pub port: Option<u16>,
    pub data_dir: Option<String>,
    pub preset: Option<String>,
    pub env_profile: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntelligenceConfigRef {
    /// Content digest of validated intelligence `connector.yaml` (OSS schema).
    pub config_digest: Option<String>,
    pub path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeSnapshot {
    pub mode: Option<String>,
    pub isolation: Option<String>,
    pub hardening: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PackageManifestRef {
    pub package_id: String,
    pub kind: String,
    pub digest: Option<String>,
    pub cnktr_present: bool,
    pub gloo_present: bool,
    pub plugin_toml_present: bool,
}

/// Unified *view* for SDK/CLI — references planes, does not flatten them.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConnectorConfigEnvelope {
    pub schema: String,
    pub node: NodeProfileRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intelligence: Option<IntelligenceConfigRef>,
    pub runtime: RuntimeSnapshot,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub packages: Vec<PackageManifestRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provenance: Vec<ConfigProvenance>,
}

impl ConnectorConfigEnvelope {
    pub fn empty() -> Self {
        Self {
            schema: CONFIG_ENVELOPE_SCHEMA.into(),
            node: NodeProfileRef {
                host: None,
                port: None,
                data_dir: None,
                preset: None,
                env_profile: None,
            },
            intelligence: None,
            runtime: RuntimeSnapshot {
                mode: None,
                isolation: None,
                hardening: false,
            },
            packages: vec![],
            provenance: vec![],
        }
    }

    /// Bootstrap snapshot from process environment (node + runtime planes only).
    pub fn from_process_env() -> Self {
        let mut env = Self::empty();
        env.node.host = std::env::var("CONNECTOR_HOST").ok();
        env.node.port = std::env::var("CONNECTOR_PORT")
            .ok()
            .and_then(|s| s.parse().ok());
        env.node.data_dir = std::env::var("CONNECTOR_DATA_DIR").ok();
        env.node.preset = std::env::var("CONNECTOR_PRESET").ok();
        env.node.env_profile = std::env::var("CONNECTOR_ENV")
            .or_else(|_| std::env::var("CONNECTOR_RUNTIME_PROFILE"))
            .ok();
        env.runtime.mode = env.node.env_profile.clone();
        env.runtime.isolation = std::env::var("CONNECTOR_ISOLATION_RUNTIME").ok();
        env.runtime.hardening = matches!(
            env.node.env_profile.as_deref(),
            Some("production" | "hardened" | "defense-strict" | "defense_strict")
        );
        if let Some(key) = env
            .node
            .env_profile
            .as_ref()
            .map(|_| "CONNECTOR_ENV".to_string())
        {
            env.provenance.push(ConfigProvenance {
                plane: ConfigPlane::Runtime,
                source: ConfigSource::EnvVar { key },
                applied: true,
            });
        }
        if env.node.preset.is_some() {
            env.provenance.push(ConfigProvenance {
                plane: ConfigPlane::Node,
                source: ConfigSource::Preset {
                    id: env.node.preset.clone().unwrap_or_default(),
                },
                applied: true,
            });
        }
        env
    }
}

/// Documented precedence (highest wins): env → runtime overlay → engine store → file → preset.
pub fn precedence_rank(source: &ConfigSource) -> u8 {
    match source {
        ConfigSource::EnvVar { .. } => 5,
        ConfigSource::RuntimeOverlay { .. } => 4,
        ConfigSource::EngineStore { .. } => 3,
        ConfigSource::File { .. } | ConfigSource::PackageDigest { .. } => 2,
        ConfigSource::Preset { .. } => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_from_env_has_schema() {
        let e = ConnectorConfigEnvelope::from_process_env();
        assert_eq!(e.schema, CONFIG_ENVELOPE_SCHEMA);
    }

    #[test]
    fn env_outranks_preset() {
        assert!(
            precedence_rank(&ConfigSource::EnvVar {
                key: "X".into()
            }) > precedence_rank(&ConfigSource::Preset {
                id: "local".into()
            })
        );
    }
}

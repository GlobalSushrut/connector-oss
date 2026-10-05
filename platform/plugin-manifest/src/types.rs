use std::collections::BTreeMap;

use semver::Version;
use serde::{Deserialize, Serialize};

use crate::ManifestError;

/// Root `plugin.toml` document.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PluginManifest {
    pub plugin: PluginSection,
    #[serde(default)]
    pub addressing: Option<AddressingSection>,
    pub runtime: RuntimeSection,
    #[serde(default)]
    pub ports: Option<PortsSection>,
    pub routes: RoutesSection,
    #[serde(default)]
    pub ui: Option<UiSection>,
    pub capabilities: CapabilitiesSection,
    #[serde(default)]
    pub depends: Option<DependsTable>,
    #[serde(default)]
    pub provides: Option<ProvidesTable>,
    #[serde(default)]
    pub migrations: Option<MigrationsSection>,
    #[serde(default)]
    pub settings: Option<SettingsSection>,
    #[serde(default)]
    pub health: Option<HealthSection>,
    #[serde(default)]
    pub signing: Option<SigningSection>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PluginSection {
    pub id: String,
    pub name: String,
    pub version: String,
    pub author: String,
    pub license: String,
    pub min_kernel: String,
    pub agos_abi: String,
}

impl PluginSection {
    pub(crate) fn validate_id(&self) -> Result<(), ManifestError> {
        let id = self.id.trim();
        let parts: Vec<&str> = id.split('/').collect();
        if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
            return Err(ManifestError::InvalidId(self.id.clone()));
        }
        let slug = |s: &str| {
            s.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        };
        if !slug(parts[0]) || !slug(parts[1]) {
            return Err(ManifestError::InvalidId(self.id.clone()));
        }
        Ok(())
    }

    pub(crate) fn validate_versions(&self) -> Result<(), ManifestError> {
        Version::parse(self.version.trim())
            .map_err(|e| ManifestError::Semver(format!("plugin.version: {e}")))?;
        Version::parse(self.min_kernel.trim())
            .map_err(|e| ManifestError::Semver(format!("plugin.min_kernel: {e}")))?;
        Ok(())
    }

    /// First-party `connector/*` ids require author `Connector`.
    pub(crate) fn validate_vendor_namespace(&self) -> Result<(), ManifestError> {
        if self.id.starts_with("connector/") && self.author.trim() != "Connector" {
            return Err(ManifestError::ReservedVendorNamespace {
                id: self.id.clone(),
                author: self.author.clone(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AddressingSection {
    pub scheme: String,
    pub base: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RuntimeType {
    Subprocess,
    Wasm,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RuntimeSection {
    #[serde(rename = "type")]
    pub runtime_type: RuntimeType,
    pub entrypoint: String,
    pub memory_mb: u32,
    pub vcpus: u32,
    #[serde(default)]
    pub shared: bool,
    pub max_concurrency: u32,
    pub idle_window: String,
    pub cold_start_budget_ms: u32,
}

impl RuntimeSection {
    pub(crate) fn validate(&self) -> Result<(), ManifestError> {
        if self.memory_mb == 0 {
            return Err(ManifestError::Invalid("runtime.memory_mb must be > 0".into()));
        }
        if self.vcpus == 0 {
            return Err(ManifestError::Invalid("runtime.vcpus must be > 0".into()));
        }
        if self.entrypoint.trim().is_empty() {
            return Err(ManifestError::Invalid("runtime.entrypoint must be non-empty".into()));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PortsSection {
    pub admin: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RoutesSection {
    pub prefix: String,
    pub admin: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UiSection {
    pub pages: Vec<UiPage>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UiPage {
    pub path: String,
    pub title: String,
    pub role: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CapabilitiesSection {
    #[serde(default)]
    pub required: Vec<String>,
}

pub type DependsTable = BTreeMap<String, String>;
pub type ProvidesTable = BTreeMap<String, ProvideEntry>;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProvideEntry {
    pub protocol: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MigrationsSection {
    pub dir: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SettingsSection {
    pub schema: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HealthSection {
    pub path: String,
    pub interval: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SigningSection {
    pub pubkey: String,
}

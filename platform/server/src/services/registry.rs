//! AgentRegistry — versioned manifest store for deployed agents (AIOS-A6).
//!
//! Analogous to: Kubernetes Deployment resource + image registry.
//! Every `connector deploy agent.yaml` writes a versioned record here.
//! Supports: register, get_latest, get_version_history, rollback.

use connector_api::manifest::AgentManifest;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// =============================================================================
// Types
// =============================================================================

/// A versioned manifest record stored in the registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestVersion {
    /// Version index (1-based, monotonically increasing per agent name)
    pub version_index: u32,
    /// Content CID of this manifest
    pub cid: String,
    /// Serialized manifest JSON
    pub manifest_json: String,
    /// When this version was deployed (epoch ms)
    pub deployed_at: i64,
    /// Who deployed this (account_id or "cli")
    pub deployed_by: String,
    /// Whether this is the currently active version
    pub is_active: bool,
    /// Blue-green canary traffic percentage (0 = stable/inactive, 1-99 = canary, 100 = fully promoted).
    /// `None` for versions registered before canary support was added.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canary_pct: Option<u8>,
}

/// Registry query response for a single agent's history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentHistory {
    pub name: String,
    pub versions: Vec<ManifestVersion>,
    pub active_version: u32,
}

/// Registry operation result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryResult {
    pub name: String,
    pub version_index: u32,
    pub cid: String,
    pub deployed_at: i64,
}

/// Result of a blue-green upgrade operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpgradeResult {
    pub name: String,
    /// Newly registered canary version index
    pub canary_version: u32,
    /// Version index of the currently stable version
    pub stable_version: u32,
    pub canary_cid: String,
    pub canary_pct: u8,
    pub deployed_at: i64,
}

// =============================================================================
// AgentRegistry
// =============================================================================

/// In-memory + engine_store backed registry of deployed agent manifests.
///
/// Storage layout: `agent_registry:{name}` key in engine_store folder_data table.
pub struct AgentRegistry {
    /// name → sorted vec of versions (index 0 = oldest)
    versions: HashMap<String, Vec<ManifestVersion>>,
}

impl AgentRegistry {
    pub fn new() -> Self {
        Self {
            versions: HashMap::new(),
        }
    }

    fn now_ms() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64
    }

    /// Register a new manifest version. Returns the new version record.
    pub fn register(&mut self, manifest: &AgentManifest, deployed_by: &str) -> RegistryResult {
        let name = manifest.metadata.name.clone();
        let cid = manifest.content_cid();
        let manifest_json = serde_json::to_string(manifest).unwrap_or_default();
        let now = Self::now_ms();

        let versions = self.versions.entry(name.clone()).or_default();

        // Deactivate all previous versions
        for v in versions.iter_mut() {
            v.is_active = false;
        }

        let version_index = (versions.len() as u32) + 1;
        let record = ManifestVersion {
            version_index,
            cid: cid.clone(),
            manifest_json,
            deployed_at: now,
            deployed_by: deployed_by.to_string(),
            is_active: true,
            canary_pct: None,
        };
        versions.push(record);

        RegistryResult {
            name,
            version_index,
            cid,
            deployed_at: now,
        }
    }

    /// Get the currently active manifest for an agent name.
    pub fn get_latest(&self, name: &str) -> Option<AgentManifest> {
        let versions = self.versions.get(name)?;
        let active = versions.iter().rev().find(|v| v.is_active)?;
        serde_json::from_str(&active.manifest_json).ok()
    }

    /// Get full version history for an agent.
    pub fn get_history(&self, name: &str) -> Option<AgentHistory> {
        let versions = self.versions.get(name)?;
        let active_version = versions
            .iter()
            .find(|v| v.is_active)
            .map(|v| v.version_index)
            .unwrap_or(0);
        Some(AgentHistory {
            name: name.to_string(),
            versions: versions.clone(),
            active_version,
        })
    }

    /// Roll back to a specific version index. Returns the restored manifest.
    pub fn rollback(&mut self, name: &str, version_index: u32) -> Option<AgentManifest> {
        let versions = self.versions.get_mut(name)?;

        // Deactivate all
        for v in versions.iter_mut() {
            v.is_active = false;
        }

        // Activate the target version
        let target = versions
            .iter_mut()
            .find(|v| v.version_index == version_index)?;
        target.is_active = true;
        let json = target.manifest_json.clone();

        serde_json::from_str(&json).ok()
    }

    /// Diff: compare running manifest with a given manifest string.
    /// Returns a list of changed fields.
    pub fn diff(&self, name: &str, new_manifest: &AgentManifest) -> Vec<DiffEntry> {
        let mut diffs = Vec::new();

        let current = match self.get_latest(name) {
            Some(m) => m,
            None => {
                diffs.push(DiffEntry {
                    field: "agent".to_string(),
                    current: "<not deployed>".to_string(),
                    proposed: name.to_string(),
                    change_type: ChangeType::Added,
                });
                return diffs;
            }
        };

        // Compare key fields
        if current.spec.model.provider != new_manifest.spec.model.provider
            || current.spec.model.name != new_manifest.spec.model.name
        {
            diffs.push(DiffEntry {
                field: "spec.model".to_string(),
                current: format!(
                    "{}/{}",
                    current.spec.model.provider, current.spec.model.name
                ),
                proposed: format!(
                    "{}/{}",
                    new_manifest.spec.model.provider, new_manifest.spec.model.name
                ),
                change_type: ChangeType::Modified,
            });
        }
        if current.spec.instructions != new_manifest.spec.instructions {
            diffs.push(DiffEntry {
                field: "spec.instructions".to_string(),
                current: truncate(&current.spec.instructions, 60),
                proposed: truncate(&new_manifest.spec.instructions, 60),
                change_type: ChangeType::Modified,
            });
        }
        if current.metadata.version != new_manifest.metadata.version {
            diffs.push(DiffEntry {
                field: "metadata.version".to_string(),
                current: current.metadata.version.clone(),
                proposed: new_manifest.metadata.version.clone(),
                change_type: ChangeType::Modified,
            });
        }
        let cur_comply = current.spec.comply.join(",");
        let new_comply = new_manifest.spec.comply.join(",");
        if cur_comply != new_comply {
            diffs.push(DiffEntry {
                field: "spec.comply".to_string(),
                current: cur_comply,
                proposed: new_comply,
                change_type: ChangeType::Modified,
            });
        }
        if current.spec.tools != new_manifest.spec.tools {
            diffs.push(DiffEntry {
                field: "spec.tools".to_string(),
                current: current.spec.tools.join(", "),
                proposed: new_manifest.spec.tools.join(", "),
                change_type: ChangeType::Modified,
            });
        }

        if diffs.is_empty() {
            diffs.push(DiffEntry {
                field: "manifest".to_string(),
                current: "identical".to_string(),
                proposed: "no changes".to_string(),
                change_type: ChangeType::Unchanged,
            });
        }

        diffs
    }

    /// List all registered agent names.
    pub fn list_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.versions.keys().cloned().collect();
        names.sort();
        names
    }

    /// Start a blue-green upgrade: register `new_manifest` as a canary version
    /// receiving `canary_pct` percent of traffic. The existing active version
    /// stays active (is_active = true) until `promote()` is called.
    ///
    /// Returns `None` if there is no existing deployment for this agent name.
    pub fn upgrade(
        &mut self,
        new_manifest: &AgentManifest,
        deployed_by: &str,
        canary_pct: u8,
    ) -> Option<UpgradeResult> {
        let name = new_manifest.metadata.name.clone();
        let versions = self.versions.get(&name)?;

        let stable_version = versions
            .iter()
            .find(|v| v.is_active)
            .map(|v| v.version_index)
            .unwrap_or(0);

        let cid = new_manifest.content_cid();
        let manifest_json = serde_json::to_string(new_manifest).unwrap_or_default();
        let now = Self::now_ms();
        let canary_pct = canary_pct.min(99); // cap at 99; use promote() to reach 100

        let versions = self.versions.entry(name.clone()).or_default();
        let version_index = (versions.len() as u32) + 1;
        versions.push(ManifestVersion {
            version_index,
            cid: cid.clone(),
            manifest_json,
            deployed_at: now,
            deployed_by: deployed_by.to_string(),
            is_active: false, // not yet active — canary only
            canary_pct: Some(canary_pct),
        });

        Some(UpgradeResult {
            name,
            canary_version: version_index,
            stable_version,
            canary_cid: cid,
            canary_pct,
            deployed_at: now,
        })
    }

    /// Promote a canary version to fully active (100% traffic).
    /// Deactivates all other versions and sets `canary_pct = 100`.
    ///
    /// Returns the promoted manifest, or `None` if the version does not exist.
    pub fn promote(&mut self, name: &str, version_index: u32) -> Option<AgentManifest> {
        let versions = self.versions.get_mut(name)?;

        // Deactivate all versions
        for v in versions.iter_mut() {
            v.is_active = false;
            if v.canary_pct.is_some() {
                v.canary_pct = Some(0);
            }
        }

        // Promote the target
        let target = versions
            .iter_mut()
            .find(|v| v.version_index == version_index)?;
        target.is_active = true;
        target.canary_pct = Some(100);
        let json = target.manifest_json.clone();

        serde_json::from_str(&json).ok()
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() > max {
        format!("{}…", &s[..max])
    } else {
        s.to_string()
    }
}

/// A single diff entry between current and proposed manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffEntry {
    pub field: String,
    pub current: String,
    pub proposed: String,
    pub change_type: ChangeType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChangeType {
    Added,
    Modified,
    Removed,
    Unchanged,
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use connector_api::manifest::AgentManifest;

    fn make_manifest(name: &str, version: &str) -> AgentManifest {
        let yaml = format!(
            r#"
apiVersion: connector/v1
kind: Agent
metadata:
  name: {}
  version: "{}"
spec:
  model:
    provider: openai
    name: gpt-4o
  instructions: "Test agent"
  comply: [soc2]
"#,
            name, version
        );
        AgentManifest::from_yaml(&yaml).unwrap()
    }

    #[test]
    fn test_register_and_get_latest() {
        let mut reg = AgentRegistry::new();
        let m = make_manifest("bot", "1.0.0");
        let result = reg.register(&m, "cli");
        assert_eq!(result.name, "bot");
        assert_eq!(result.version_index, 1);

        let latest = reg.get_latest("bot").unwrap();
        assert_eq!(latest.metadata.name, "bot");
    }

    #[test]
    fn test_version_history_increments() {
        let mut reg = AgentRegistry::new();
        reg.register(&make_manifest("bot", "1.0.0"), "cli");
        reg.register(&make_manifest("bot", "1.1.0"), "cli");
        reg.register(&make_manifest("bot", "2.0.0"), "cli");

        let history = reg.get_history("bot").unwrap();
        assert_eq!(history.versions.len(), 3);
        assert_eq!(history.active_version, 3);
        // Only version 3 is active
        let active_count = history.versions.iter().filter(|v| v.is_active).count();
        assert_eq!(active_count, 1);
    }

    #[test]
    fn test_rollback() {
        let mut reg = AgentRegistry::new();
        reg.register(&make_manifest("bot", "1.0.0"), "cli");
        reg.register(&make_manifest("bot", "2.0.0"), "cli");

        let restored = reg.rollback("bot", 1).unwrap();
        assert_eq!(restored.metadata.version, "1.0.0");

        let history = reg.get_history("bot").unwrap();
        assert_eq!(history.active_version, 1);
    }

    #[test]
    fn test_diff_detects_model_change() {
        let mut reg = AgentRegistry::new();
        reg.register(&make_manifest("bot", "1.0.0"), "cli");

        let yaml_v2 = r#"
apiVersion: connector/v1
kind: Agent
metadata:
  name: bot
  version: "2.0.0"
spec:
  model:
    provider: anthropic
    name: claude-3-5-sonnet
  instructions: "Test agent"
"#;
        let m2 = AgentManifest::from_yaml(yaml_v2).unwrap();
        let diffs = reg.diff("bot", &m2);
        assert!(diffs.iter().any(|d| d.field == "spec.model"));
    }

    #[test]
    fn test_diff_no_changes() {
        let mut reg = AgentRegistry::new();
        let m = make_manifest("bot", "1.0.0");
        reg.register(&m.clone(), "cli");
        let diffs = reg.diff("bot", &m);
        assert!(diffs
            .iter()
            .any(|d| matches!(d.change_type, ChangeType::Unchanged)));
    }
}

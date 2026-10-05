//! Extension WIT contract stub (typed Rust ↔ JSON).
//!
//! Full WIT 0.3 / component-model linking is deferred. These types mirror the
//! planned `extension-host@0.1` world so packages and ExtensionHost share one shape.

use serde::{Deserialize, Serialize};

use crate::digest_hex;

pub const EXTENSION_WIT_SCHEMA: &str = "connector.extension_wit.v1";
pub const EXTENSION_WIT_WORLD: &str = "extension-host@0.1";

/// Declared export from the extension-host WIT world (stub).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionWitExport {
    Preflight,
    Install,
    Activate,
    Deactivate,
    Uninstall,
    QueryStatus,
    Revoke,
}

/// Capability import the extension may request (not a grant).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExtensionCapabilityImport {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attenuation: Option<String>,
}

/// Stub WIT world document for an extension package.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExtensionWitWorld {
    pub schema: String,
    pub world: String,
    pub extension_id: String,
    #[serde(default)]
    pub exports: Vec<ExtensionWitExport>,
    #[serde(default)]
    pub capability_imports: Vec<ExtensionCapabilityImport>,
    /// Content digest of the sealed body (excludes digest field).
    pub digest: String,
    /// Honesty: no wasmtime component link in this slice.
    #[serde(default)]
    pub abi_status: String,
}

impl ExtensionWitWorld {
    pub fn default_for(extension_id: &str) -> Self {
        let mut w = Self {
            schema: EXTENSION_WIT_SCHEMA.into(),
            world: EXTENSION_WIT_WORLD.into(),
            extension_id: extension_id.into(),
            exports: vec![
                ExtensionWitExport::Preflight,
                ExtensionWitExport::Install,
                ExtensionWitExport::Activate,
                ExtensionWitExport::Deactivate,
                ExtensionWitExport::Uninstall,
                ExtensionWitExport::QueryStatus,
                ExtensionWitExport::Revoke,
            ],
            capability_imports: vec![],
            digest: String::new(),
            abi_status: "typed_stub_no_component_link".into(),
        };
        w.seal();
        w
    }

    /// Mark a package that declared a Wasm/component artifact path (still not linked).
    pub fn with_declared_component(mut self, artifact_path: &str) -> Self {
        self.abi_status = format!(
            "component_artifact_declared:{artifact_path}; link deferred (wasmtime not attached)"
        );
        self.seal();
        self
    }

    /// Fail closed when production requires a live component link.
    pub fn require_component_link_or_err(&self) -> Result<(), String> {
        let required = std::env::var("CONNECTOR_WIT_REQUIRE_COMPONENT")
            .map(|v| {
                matches!(
                    v.trim().to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on"
                )
            })
            .unwrap_or(false);
        if required && self.abi_status.starts_with("typed_stub") {
            return Err(
                "wit_component_link_required: CONNECTOR_WIT_REQUIRE_COMPONENT=1 and abi_status is typed stub"
                    .into(),
            );
        }
        Ok(())
    }

    pub fn seal(&mut self) {
        let body = serde_json::json!({
            "schema": self.schema,
            "world": self.world,
            "extension_id": self.extension_id,
            "exports": self.exports,
            "capability_imports": self.capability_imports,
            "abi_status": self.abi_status,
        });
        let bytes = serde_json::to_vec(&body).unwrap_or_default();
        self.digest = format!("wit1-sha256-{}", digest_hex(&bytes));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_stable() {
        let a = ExtensionWitWorld::default_for("devguard");
        let b = ExtensionWitWorld::default_for("devguard");
        assert_eq!(a.digest, b.digest);
        assert!(a.digest.starts_with("wit1-sha256-"));
        assert_eq!(a.abi_status, "typed_stub_no_component_link");
    }

    #[test]
    fn round_trip_json() {
        let w = ExtensionWitWorld::default_for("tracetramp");
        let v = serde_json::to_value(&w).unwrap();
        let back: ExtensionWitWorld = serde_json::from_value(v).unwrap();
        assert_eq!(back, w);
    }
}

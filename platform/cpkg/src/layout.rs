//! Paths inside a `.cpkg` ZIP (Phase 4.1 / AppPackage V2 contract).

/// Root manifest — parsed with [`connector_plugin_manifest::PluginManifest`].
pub const PLUGIN_MANIFEST_PATH: &str = "plugin.toml";

/// SPDX or CycloneDX JSON (optional).
pub const SBOM_PATH: &str = "sbom.json";

/// Detached signature envelope (Ed25519 verification is Phase 4.2).
pub const SIGNATURE_PATH: &str = "META/signature.json";

/// Plugin executables and helpers; paths align with `[runtime].entrypoint`.
pub const BIN_PREFIX: &str = "bin/";

/// Static dashboard / plugin UI bundle.
pub const UI_PREFIX: &str = "ui/";

/// Well-known prefix for Hub metadata extensions (reserved).
pub const META_PREFIX: &str = "META/";

/// AppPackage V2 immutable identity (`META/package.json`).
pub const PACKAGE_JSON_PATH: &str = "META/package.json";

/// AppPackage V2 semantic / deployment intent.
pub const CNKTR_YAML_PATH: &str = "cnktr.yaml";

/// Compiled connector IR (optional in V2 packages).
pub const IR_PATH: &str = "ir/connector.ir.json";

/// Build / publish provenance (optional).
pub const PROVENANCE_PATH: &str = "META/provenance.json";

/// Compatibility matrix (optional).
pub const COMPATIBILITY_PATH: &str = "META/compatibility.json";

/// Bundled adapter artifacts prefix.
pub const ADAPTERS_PREFIX: &str = "adapters/";

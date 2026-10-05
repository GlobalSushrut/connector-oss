//! **AGOS SDK** (Phase **6.2**) — public crate for community plugins: stable **`agos-abi`** contract ids,
//! **`plugin.toml`** types (`connector-plugin-manifest`), and kernel handshake bootstrap (`connector-plugin-handshake`).
//!
//! Typical process entry:
//! 1. [`handshake::apply_from_env`]
//! 2. [`load_manifest_path`] or [`PluginManifest::parse`] + [`PluginManifest::validate`]
//! 3. [`assert_manifest_matches_abi`] before registering routes / opening network caps.

use std::path::Path;

pub mod abi {
    //! Contract identifiers (**`agos.v1`**, reserved **`agos.v2`**) and handshake schema version.
    pub use agos_abi::{
        AGOS_CONTRACT_ID, AGOS_CONTRACT_ID_V2, CRATE_PKG_VERSION as ABI_CRATE_SEMVER,
        HANDSHAKE_SCHEMA_VERSION, PLUGIN_CONTRACT_REF, STAGED_AGOS_CONTRACT_IDS, SUPPORTED_AGOS_CONTRACT_IDS,
    };
}

pub mod handshake {
    //! Kernel → plugin bootstrap JSON (see **`PLUGIN_CONTRACT.md`** in the Connector OS repo).
    pub use connector_plugin_handshake::{
        apply_from_env, HandshakeError, ENV_HANDSHAKE_FD, ENV_HANDSHAKE_PATH,
    };
}

pub mod manifest {
    //! Parsed **`plugin.toml`** surface from **`connector-plugin-manifest`**.
    pub use connector_plugin_manifest::{
        AddressingSection, CapabilitiesSection, DependsTable, HealthSection, ManifestError, MigrationsSection,
        PluginManifest, PluginSection, PortsSection, ProvidesTable, RoutesSection, RuntimeSection, RuntimeType,
        SettingsSection, SigningSection, UiPage, UiSection,
    };
}

/// This SDK crate’s Cargo semver (for support tickets; distinct from [`abi::AGOS_CONTRACT_ID`]).
pub const SDK_CRATE_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, thiserror::Error)]
pub enum LoadManifestError {
    #[error("read plugin.toml: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Manifest(#[from] manifest::ManifestError),
}

/// Read UTF-8 **`plugin.toml`** from disk, parse, and run [`manifest::PluginManifest::validate`].
pub fn load_manifest_path(path: impl AsRef<Path>) -> Result<manifest::PluginManifest, LoadManifestError> {
    let src = std::fs::read_to_string(path.as_ref())?;
    let m = manifest::PluginManifest::parse(&src)?;
    m.validate()?;
    Ok(m)
}

/// Returns **`Ok(())`** when **`[plugin].agos_abi`** matches the kernel’s current [`abi::AGOS_CONTRACT_ID`].
#[derive(Debug, thiserror::Error)]
pub enum AbiMismatchError {
    #[error("manifest agos_abi `{0}` != kernel contract `{1}`")]
    Mismatch(String, &'static str),
}

pub fn assert_manifest_matches_abi(m: &manifest::PluginManifest) -> Result<(), AbiMismatchError> {
    let got = m.plugin.agos_abi.trim();
    if abi::SUPPORTED_AGOS_CONTRACT_IDS.contains(&got) {
        return Ok(());
    }
    Err(AbiMismatchError::Mismatch(
        m.plugin.agos_abi.clone(),
        abi::AGOS_CONTRACT_ID,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
[plugin]
id = "acme/hello"
name = "Hello"
version = "0.1.0"
author = "acme"
license = "MIT"
min_kernel = "0.1.0"
agos_abi = "agos.v1"

[runtime]
type = "subprocess"
entrypoint = "bin/hello"
memory_mb = 32
vcpus = 1
shared = false
max_concurrency = 4
idle_window = "30s"
cold_start_budget_ms = 500

[routes]
prefix = "/plugins/hello"
admin = "/plugins/hello/admin/*"

[capabilities]
required = ["audit.write"]

[ui]
pages = [{ path = "/plugins/hello", title = "Hello", role = "operator" }]
"#;

    #[test]
    fn load_and_abi_check_inline() {
        let m = manifest::PluginManifest::parse(SAMPLE).expect("parse");
        m.validate().expect("validate");
        assert_manifest_matches_abi(&m).expect("abi");
    }
}

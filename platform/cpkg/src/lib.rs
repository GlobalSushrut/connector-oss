//! Connector **`.cpkg`** — single-file plugin / workflow / app packages for Hub distribution.
//!
//! # Layout (ZIP, forward-slash paths)
//!
//! ## V1 plugin packages
//!
//! | Path | Required | Description |
//! |------|----------|-------------|
//! | [`PLUGIN_MANIFEST_PATH`](layout::PLUGIN_MANIFEST_PATH) | yes | `plugin.toml` — [`connector_plugin_manifest::PluginManifest`] |
//! | [`SBOM_PATH`](layout::SBOM_PATH) | no | SPDX or CycloneDX JSON |
//! | [`SIGNATURE_PATH`](layout::SIGNATURE_PATH) | no | [`CpkgSignatureEnvelope`] — Ed25519 verify via [`read_cpkg_verify_optional`] |
//! | [`BIN_PREFIX`](layout::BIN_PREFIX)`*` | no | Binaries (match `[runtime].entrypoint`) |
//! | [`UI_PREFIX`](layout::UI_PREFIX)`*` | no | Static UI bundle |
//!
//! ## AppPackage V2 (`cnktr.yaml`)
//!
//! Shared ZIP container; kinds: app, plugin, adapter, workflow. Attached apps bind
//! existing executables and do not require proprietary binaries in-package.
//!
//! | Path | Required | Description |
//! |------|----------|-------------|
//! | [`PACKAGE_JSON_PATH`](layout::PACKAGE_JSON_PATH) | yes | Immutable identity |
//! | [`CNKTR_YAML_PATH`](layout::CNKTR_YAML_PATH) | yes | Semantic / deployment intent |
//!
//! # Example
//!
//! ```ignore
//! use connector_cpkg::{read_cpkg, write_cpkg, CpkgFileEntry};
//! let bytes = write_cpkg(manifest_toml, &[], None, None)?;
//! let bundle = read_cpkg(&bytes)?;
//! bundle.manifest.validate()?;
//! ```

pub mod app_package_v2;
mod crypto;
mod error;
pub mod layout;
mod read;
mod signature;
mod write;
pub mod security_contract;

pub use app_package_v2::{
    cnktr_to_meta, is_forbidden_archive_path, parse_cnktr_yaml, validate_archive_paths,
    validate_meta_package, write_app_cpkg_v2, CnktrAppSection, CnktrAuthoritySection,
    CnktrIntelligenceSection, CnktrSoftwareSection, CnktrYamlV2, ExecutableIdentityV2,
    MetaPackageJsonV2, PackageKindV2, PackageModeV2, APP_PACKAGE_V2_SCHEMA,
};
pub use crypto::{
    canonical_payload_digest, parse_verifying_key_b64, sign_envelope, verify_envelope,
    SIGN_MESSAGE_PREFIX,
};
pub use error::CpkgError;
pub use read::{read_cpkg, read_cpkg_verify_optional, CpkgBundle};
pub use security_contract::{
    from_manifest_fields, CpkgSecurityContractV1, CPKG_SECURITY_CONTRACT_SCHEMA,
};
pub use signature::CpkgSignatureEnvelope;
pub use write::{write_cpkg, CpkgFileEntry};

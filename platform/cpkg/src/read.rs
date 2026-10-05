use std::collections::BTreeMap;
use std::io::Read;

use connector_plugin_manifest::PluginManifest;
use ed25519_dalek::VerifyingKey;
use serde_json::Value;
use zip::ZipArchive;

use crate::crypto::verify_envelope;
use crate::error::CpkgError;
use crate::layout::{PLUGIN_MANIFEST_PATH, SBOM_PATH, SIGNATURE_PATH};
use crate::signature::CpkgSignatureEnvelope;

/// Parsed `.cpkg` contents (manifest required; other parts optional).
#[derive(Debug, Clone)]
pub struct CpkgBundle {
    pub manifest: PluginManifest,
    /// Original `plugin.toml` text (for hashing / re-signing).
    pub manifest_src: String,
    pub sbom: Option<Value>,
    pub signature: Option<CpkgSignatureEnvelope>,
    /// Paths present in the archive (files only; directory entries skipped).
    pub paths: Vec<String>,
    /// File contents keyed by archive path (excluding directory markers).
    pub files: BTreeMap<String, Vec<u8>>,
}

/// Read and parse a `.cpkg` ZIP from bytes.
pub fn read_cpkg(data: &[u8]) -> Result<CpkgBundle, CpkgError> {
    let cursor = std::io::Cursor::new(data);
    let mut zip = ZipArchive::new(cursor)?;
    let mut paths = Vec::new();
    let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut manifest_src: Option<String> = None;
    let mut sbom: Option<Value> = None;
    let mut signature: Option<CpkgSignatureEnvelope> = None;

    for i in 0..zip.len() {
        let mut file = zip.by_index(i)?;
        let name = file.name().to_string();
        if name.ends_with('/') || name.is_empty() {
            continue;
        }
        if files.contains_key(&name) {
            return Err(CpkgError::DuplicatePath(name));
        }
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;
        paths.push(name.clone());
        match name.as_str() {
            PLUGIN_MANIFEST_PATH => {
                manifest_src = Some(String::from_utf8(buf.clone())?);
            }
            SBOM_PATH => {
                sbom = Some(serde_json::from_slice(&buf)?);
            }
            SIGNATURE_PATH => {
                signature = Some(serde_json::from_slice(&buf)?);
            }
            _ => {}
        }
        files.insert(name, buf);
    }

    paths.sort();
    let manifest_src =
        manifest_src.ok_or(CpkgError::MissingFile(PLUGIN_MANIFEST_PATH))?;
    let manifest = PluginManifest::parse(&manifest_src)?;
    Ok(CpkgBundle {
        manifest,
        manifest_src,
        sbom,
        signature,
        paths,
        files,
    })
}

/// Read `.cpkg` bytes and optionally enforce Ed25519 verification (`Phase 4.2`).
///
/// * `trust`: when `Some`, a signature must be present and verify against these keys.
/// * When `None`, signature is ignored (install only if policy allows unsigned packages upstream).
pub fn read_cpkg_verify_optional(
    data: &[u8],
    trust: Option<&BTreeMap<String, VerifyingKey>>,
) -> Result<CpkgBundle, CpkgError> {
    let bundle = read_cpkg(data)?;
    match trust {
        None => Ok(bundle),
        Some(keys) => {
            let Some(ref env) = bundle.signature else {
                return Err(CpkgError::Invalid(
                    "signed package required but META/signature.json is missing",
                ));
            };
            verify_envelope(env, &bundle.manifest_src, &bundle.files, keys)?;
            Ok(bundle)
        }
    }
}

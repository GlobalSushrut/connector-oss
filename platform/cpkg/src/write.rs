use std::io::Write;

use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

use crate::error::CpkgError;
use crate::layout::{PLUGIN_MANIFEST_PATH, SBOM_PATH, SIGNATURE_PATH};
use crate::signature::CpkgSignatureEnvelope;

/// One file to store in the archive (path uses forward slashes).
pub struct CpkgFileEntry {
    pub path: String,
    pub bytes: Vec<u8>,
}

/// Build a `.cpkg` ZIP in memory.
///
/// `manifest_toml` must be valid UTF-8. Callers should run [`connector_plugin_manifest::PluginManifest::validate`]
/// before packaging when publishing.
pub fn write_cpkg(
    manifest_toml: &str,
    extra: &[CpkgFileEntry],
    sbom: Option<&serde_json::Value>,
    signature: Option<&CpkgSignatureEnvelope>,
) -> Result<Vec<u8>, CpkgError> {
    let mut out = Vec::new();
    let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
    {
        let mut zip = ZipWriter::new(std::io::Cursor::new(&mut out));
        zip.start_file(PLUGIN_MANIFEST_PATH, opts)?;
        zip.write_all(manifest_toml.as_bytes())?;

        if let Some(sb) = sbom {
            zip.start_file(SBOM_PATH, opts)?;
            zip.write_all(serde_json::to_vec(sb)?.as_slice())?;
        }
        if let Some(sig) = signature {
            zip.start_file(SIGNATURE_PATH, opts)?;
            zip.write_all(serde_json::to_vec(sig)?.as_slice())?;
        }
        for e in extra {
            if e.path == PLUGIN_MANIFEST_PATH
                || e.path == SBOM_PATH
                || e.path == SIGNATURE_PATH
            {
                return Err(CpkgError::Invalid(
                    "extra entry conflicts with reserved plugin.toml / sbom.json / META/signature.json",
                ));
            }
            zip.start_file(&e.path, opts)?;
            zip.write_all(&e.bytes)?;
        }
        zip.finish()?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::read::read_cpkg;

    const SAMPLE_MANIFEST: &str = r#"
[plugin]
id = "acme/demo-pkg"
name = "Demo Package"
version = "0.1.0"
author = "acme"
license = "MIT"
min_kernel = "0.1.0"
agos_abi = "agos.v1"

[runtime]
type = "subprocess"
entrypoint = "bin/demo"
memory_mb = 64
vcpus = 1
shared = false
max_concurrency = 2
idle_window = "30s"
cold_start_budget_ms = 500

[routes]
prefix = "/plugins/demo"
admin = "/plugins/demo/admin/*"

[capabilities]
required = ["audit.write"]
"#;

    #[test]
    fn round_trip_minimal() {
        let sbom = json!({"spdxVersion": "SPDX-2.3", "name": "demo"});
        let sig = CpkgSignatureEnvelope {
            algorithm: "ed25519".into(),
            key_id: "test-key".into(),
            payload_sha256: Some("deadbeef".into()),
            signature_b64: "AAAA".into(),
            parent_key_id: None,
        };
        let extra = vec![
            CpkgFileEntry {
                path: "bin/demo".into(),
                bytes: b"#!/bin/false\n".to_vec(),
            },
            CpkgFileEntry {
                path: "ui/index.html".into(),
                bytes: b"<html/>".to_vec(),
            },
        ];
        let bytes = write_cpkg(SAMPLE_MANIFEST, &extra, Some(&sbom), Some(&sig)).unwrap();
        let bundle = read_cpkg(&bytes).unwrap();
        assert_eq!(bundle.manifest.plugin.id, "acme/demo-pkg");
        assert!(bundle.manifest_src.contains("acme/demo-pkg"));
        assert_eq!(bundle.sbom, Some(sbom));
        assert_eq!(bundle.signature, Some(sig));
        assert!(bundle.paths.contains(&"bin/demo".to_string()));
        assert!(bundle.paths.contains(&"ui/index.html".to_string()));
        bundle.manifest.validate().unwrap();
    }
}

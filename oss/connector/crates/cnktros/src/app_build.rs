//! Build signed AppPackageV2 `.cpkg` from a project directory.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use connector_cpkg::layout::{CNKTR_YAML_PATH, IR_PATH, PACKAGE_JSON_PATH, SIGNATURE_PATH};
use connector_cpkg::{
    cnktr_to_meta, parse_cnktr_yaml, sign_envelope, validate_meta_package, write_app_cpkg_v2,
    CpkgFileEntry, PackageKindV2,
};
use connector_native_contract::{digest_hex, PackagePin};
use ed25519_dalek::SigningKey;
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize)]
pub struct AppBuildResult {
    pub package_path: PathBuf,
    pub pin_path: PathBuf,
    pub pin: PackagePin,
    pub package_bytes_sha256: String,
    pub signed: bool,
    pub honesty: String,
}

pub fn scaffold_project(root: &Path, app_id: &str, lang: &str) -> Result<PathBuf, String> {
    fs::create_dir_all(root).map_err(|e| e.to_string())?;
    fs::create_dir_all(root.join("contracts")).map_err(|e| e.to_string())?;
    fs::create_dir_all(root.join("adapters")).map_err(|e| e.to_string())?;
    let cnktr = format!(
        "app:\n  id: {app_id}\n  mode: managed\nintelligence:\n  contract: contracts/main.cls\nauthority:\n  default: deny\nadapters: []\n"
    );
    let cnktr_path = root.join("cnktr.yaml");
    if !cnktr_path.exists() {
        fs::write(&cnktr_path, cnktr).map_err(|e| e.to_string())?;
    }
    let contract = root.join("contracts/main.cls");
    if !contract.exists() {
        fs::write(
            &contract,
            "// Connector CLS placeholder — replace with real CCL/CLS\ncontract main {\n}\n",
        )
        .map_err(|e| e.to_string())?;
    }
    let var_env = root.join("var.env");
    if !var_env.exists() {
        fs::write(&var_env, "# Non-secret bindings only; secrets use vault:handle:\n").map_err(|e| e.to_string())?;
    }
    let readme = root.join("CNKTROS_APP.md");
    fs::write(
        &readme,
        format!(
            "# Connector app\n\nPrimary language: **{lang}** (Python Gloo default).\n\n\
             Build: `cnktros app build` → signed `dist/*.cpkg`\n\
             Production refuses unpackaged execution.\n"
        ),
    )
    .map_err(|e| e.to_string())?;
    if lang == "python" {
        let gloo = root.join("gloo.json");
        if !gloo.exists() {
            fs::write(
                &gloo,
                serde_json::to_string_pretty(&json!({
                    "app_id": app_id,
                    "name": app_id,
                    "entry_module": "app.main",
                    "system_tier": "installed",
                    "contracts": ["contracts/main.cls"],
                }))
                .unwrap(),
            )
            .map_err(|e| e.to_string())?;
        }
        fs::create_dir_all(root.join("app")).map_err(|e| e.to_string())?;
        let main_py = root.join("app/main.py");
        if !main_py.exists() {
            fs::write(
                &main_py,
                "\"\"\"Gloo app entry — package via `cnktros app build` or `gloo build`.\"\"\"\n\ndef main():\n    print(\"gloo app — build .cpkg before production run\")\n\nif __name__ == \"__main__\":\n    main()\n",
            )
            .map_err(|e| e.to_string())?;
        }
    }
    Ok(readme)
}

/// Build AppPackageV2 from `root/cnktr.yaml` (+ optional contracts/IR).
pub fn build_app_package(
    root: &Path,
    output: Option<&Path>,
    version: &str,
    signing_key_path: Option<&Path>,
    key_id: &str,
) -> Result<AppBuildResult, String> {
    let cnktr_path = root.join("cnktr.yaml");
    if !cnktr_path.exists() {
        return Err(format!(
            "missing cnktr.yaml in {} — run `cnktros app init` first",
            root.display()
        ));
    }
    let cnktr_text = fs::read_to_string(&cnktr_path).map_err(|e| e.to_string())?;
    let cnktr = parse_cnktr_yaml(&cnktr_text).map_err(|e| e.to_string())?;
    let mut meta = cnktr_to_meta(&cnktr, version);

    let mut extras: Vec<CpkgFileEntry> = Vec::new();
    let mut files_for_sign: BTreeMap<String, Vec<u8>> = BTreeMap::new();

    // Optional IR / contracts → content digests
    let ir_path = root.join("ir/connector.ir.json");
    if ir_path.exists() {
        let bytes = fs::read(&ir_path).map_err(|e| e.to_string())?;
        let ir_digest = format!("cir1-sha256-{}", digest_hex(&bytes));
        meta.ir_digest = Some(ir_digest);
        extras.push(CpkgFileEntry {
            path: IR_PATH.into(),
            bytes: bytes.clone(),
        });
        files_for_sign.insert(IR_PATH.into(), bytes);
    } else {
        // Hash contracts as provisional contract_digest
        let contracts_dir = root.join("contracts");
        if contracts_dir.is_dir() {
            let mut hasher = Sha256::new();
            let mut paths: Vec<_> = walk_files(&contracts_dir)?;
            paths.sort();
            for p in &paths {
                let rel = p
                    .strip_prefix(root)
                    .unwrap_or(p)
                    .to_string_lossy()
                    .replace('\\', "/");
                if connector_cpkg::is_forbidden_archive_path(&rel) {
                    return Err(format!("forbidden path in package: {rel}"));
                }
                let bytes = fs::read(p).map_err(|e| e.to_string())?;
                hasher.update(rel.as_bytes());
                hasher.update(&bytes);
                extras.push(CpkgFileEntry {
                    path: rel.clone(),
                    bytes: bytes.clone(),
                });
                files_for_sign.insert(rel, bytes);
            }
            meta.contract_digest = Some(format!("cls-sha256-{}", hex::encode(hasher.finalize())));
        }
    }

    // Optional gloo.json (Python primary authoring manifest)
    let gloo = root.join("gloo.json");
    if gloo.exists() {
        let bytes = fs::read(&gloo).map_err(|e| e.to_string())?;
        extras.push(CpkgFileEntry {
            path: "gloo.json".into(),
            bytes: bytes.clone(),
        });
        files_for_sign.insert("gloo.json".into(), bytes);
    }

    // Optional adapters (non-secret text/json only)
    let adapters = root.join("adapters");
    if adapters.is_dir() {
        let mut paths: Vec<_> = walk_files(&adapters)?;
        paths.sort();
        for p in &paths {
            let rel = p
                .strip_prefix(root)
                .unwrap_or(p)
                .to_string_lossy()
                .replace('\\', "/");
            if connector_cpkg::is_forbidden_archive_path(&rel) {
                return Err(format!("forbidden path in package: {rel}"));
            }
            let bytes = fs::read(p).map_err(|e| e.to_string())?;
            extras.push(CpkgFileEntry {
                path: rel.clone(),
                bytes: bytes.clone(),
            });
            files_for_sign.insert(rel, bytes);
        }
    }

    validate_meta_package(&meta).map_err(|e| e.to_string())?;

    let meta_json = serde_json::to_vec_pretty(&meta).map_err(|e| e.to_string())?;
    files_for_sign.insert(PACKAGE_JSON_PATH.into(), meta_json.clone());
    files_for_sign.insert(CNKTR_YAML_PATH.into(), cnktr_text.as_bytes().to_vec());

    let mut signed = false;
    if let Some(key_path) = signing_key_path {
        let signing_key = load_signing_key(key_path)?;
        // For V2, sign over META/package.json as "manifest"
        let manifest_src = String::from_utf8_lossy(&meta_json).into_owned();
        let envelope = sign_envelope(&manifest_src, &files_for_sign, key_id, &signing_key)
            .map_err(|e| e.to_string())?;
        let sig_bytes = serde_json::to_vec_pretty(&envelope).map_err(|e| e.to_string())?;
        extras.push(CpkgFileEntry {
            path: SIGNATURE_PATH.into(),
            bytes: sig_bytes,
        });
        signed = true;
    }

    let zip_bytes = write_app_cpkg_v2(&meta, &cnktr_text, &extras).map_err(|e| e.to_string())?;
    let package_digest = format!("cpkg-sha256-{}", digest_hex(&zip_bytes));

    let dist = root.join("dist");
    fs::create_dir_all(&dist).map_err(|e| e.to_string())?;
    let out_path = match output {
        Some(p) => p.to_path_buf(),
        None => dist.join(format!("{}.cpkg", meta.package_id.replace('/', "-"))),
    };
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    fs::write(&out_path, &zip_bytes).map_err(|e| e.to_string())?;

    let kind = match meta.kind {
        PackageKindV2::App => "app",
        PackageKindV2::Plugin => "plugin",
        PackageKindV2::Adapter => "adapter",
        PackageKindV2::Workflow => "workflow",
    };
    let pin = PackagePin::new(&meta.package_id, &package_digest, kind).with_signature(signed);
    let pin = if let Some(ir) = meta.ir_digest.clone() {
        pin.with_ir(ir)
    } else {
        pin
    };

    let pin_path = out_path.with_extension("package.pin.json");
    fs::write(
        &pin_path,
        serde_json::to_string_pretty(&pin).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;

    Ok(AppBuildResult {
        package_path: out_path,
        pin_path,
        pin,
        package_bytes_sha256: package_digest.clone(),
        signed,
        honesty: if signed {
            "AppPackageV2 built and Ed25519-signed; pin required for production invoke".into()
        } else {
            "AppPackageV2 built without signature — pass --signing-key for enforced profiles".into()
        },
    })
}

fn load_signing_key(key_path: &Path) -> Result<SigningKey, String> {
    let key_bytes = fs::read(key_path).map_err(|e| e.to_string())?;
    if let Ok(s) = std::str::from_utf8(&key_bytes) {
        let trimmed = s.trim();
        if trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
            let raw = hex::decode(trimmed).map_err(|e| e.to_string())?;
            let arr: [u8; 32] = raw
                .as_slice()
                .try_into()
                .map_err(|_| "hex signing key must be 32 bytes")?;
            return Ok(SigningKey::from_bytes(&arr));
        }
    }
    let seed: [u8; 32] = key_bytes
        .as_slice()
        .get(..32)
        .ok_or("signing key file must contain at least 32 raw bytes or 64 hex chars")?
        .try_into()
        .map_err(|_| "signing key length")?;
    Ok(SigningKey::from_bytes(&seed))
}

fn walk_files(dir: &Path) -> Result<Vec<PathBuf>, String> {
    let mut out = Vec::new();
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
        for ent in fs::read_dir(dir).map_err(|e| e.to_string())? {
            let ent = ent.map_err(|e| e.to_string())?;
            let p = ent.path();
            if p.is_dir() {
                walk(&p, out)?;
            } else if p.is_file() {
                out.push(p);
            }
        }
        Ok(())
    }
    walk(dir, &mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn build_unsigned_package_from_scaffold() {
        let dir = tempdir().unwrap();
        scaffold_project(dir.path(), "demo-app", "python").unwrap();
        let result = build_app_package(dir.path(), None, "0.1.0", None, "dev").unwrap();
        assert!(result.package_path.exists());
        assert!(result.pin_path.exists());
        assert!(result.pin.package_digest.starts_with("cpkg-sha256-"));
        assert_eq!(result.signed, false);
        assert_eq!(result.pin.kind, "app");
        // Forbidden: ensure var.env not inside zip
        let bytes = fs::read(&result.package_path).unwrap();
        let cursor = std::io::Cursor::new(bytes);
        let mut zip = zip::ZipArchive::new(cursor).unwrap();
        for i in 0..zip.len() {
            let name = zip.by_index(i).unwrap().name().to_string();
            assert!(!name.contains("var.env"), "{name}");
            assert!(!name.contains(".env"), "{name}");
        }
    }

    #[test]
    fn build_signed_package_with_hex_key() {
        let dir = tempdir().unwrap();
        scaffold_project(dir.path(), "signed-app", "python").unwrap();
        let key_path = dir.path().join("seed.hex");
        fs::write(&key_path, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
            .unwrap();
        let result =
            build_app_package(dir.path(), None, "0.2.0", Some(&key_path), "dev-key").unwrap();
        assert!(result.signed);
        assert_eq!(result.pin.signature_present, Some(true));
        let bytes = fs::read(&result.package_path).unwrap();
        let mut zip = zip::ZipArchive::new(std::io::Cursor::new(bytes)).unwrap();
        assert!(zip.by_name("META/signature.json").is_ok());
        assert!(zip.by_name("META/package.json").is_ok());
        assert!(zip.by_name("cnktr.yaml").is_ok());
    }

    #[test]
    fn adapter_files_are_archived_in_sorted_path_order() {
        let dir = tempdir().unwrap();
        scaffold_project(dir.path(), "adapter-app", "python").unwrap();
        let adapters = dir.path().join("adapters");
        fs::create_dir_all(adapters.join("nested")).unwrap();
        fs::write(adapters.join("z.json"), b"z").unwrap();
        fs::write(adapters.join("a.json"), b"a").unwrap();
        fs::write(adapters.join("nested/m.json"), b"m").unwrap();
        let result = build_app_package(dir.path(), None, "0.1.0", None, "dev").unwrap();
        let bytes = fs::read(&result.package_path).unwrap();
        let mut zip = zip::ZipArchive::new(std::io::Cursor::new(bytes)).unwrap();
        let adapter_names: Vec<String> = (0..zip.len())
            .map(|i| zip.by_index(i).unwrap().name().to_string())
            .filter(|n| n.starts_with("adapters/"))
            .collect();
        let mut sorted = adapter_names.clone();
        sorted.sort();
        assert_eq!(adapter_names, sorted);
        assert_eq!(
            adapter_names,
            vec![
                "adapters/a.json".to_string(),
                "adapters/nested/m.json".to_string(),
                "adapters/z.json".to_string(),
            ]
        );
    }
}

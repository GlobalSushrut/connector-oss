//! AppPackage V2 — shared ZIP container with `cnktr.yaml` + `META/package.json`.
//!
//! Distinct from V1 plugin `.cpkg` (`plugin.toml`). Attached apps bind existing
//! executables and do not require proprietary binaries inside the package.

use std::io::Write;

use serde::{Deserialize, Serialize};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

use crate::error::CpkgError;
use crate::layout::{CNKTR_YAML_PATH, PACKAGE_JSON_PATH};
use crate::write::CpkgFileEntry;

pub const APP_PACKAGE_V2_SCHEMA: &str = "connector.app_package.v2";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PackageKindV2 {
    App,
    Plugin,
    Adapter,
    Workflow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PackageModeV2 {
    Managed,
    Attached,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutableIdentityV2 {
    /// e.g. `"cursor"`
    pub selector: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_hint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publisher: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MetaPackageJsonV2 {
    pub schema: String,
    pub package_id: String,
    pub kind: PackageKindV2,
    pub mode: PackageModeV2,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ir_digest: Option<String>,
    /// Present for attached packages that bind an external executable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable: Option<ExecutableIdentityV2>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub adapters: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_isolation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_kernel_abi: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CnktrAppSection {
    pub id: String,
    pub mode: PackageModeV2,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CnktrSoftwareSection {
    pub executable: ExecutableIdentityV2,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CnktrIntelligenceSection {
    pub contract: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CnktrAuthoritySection {
    /// e.g. `"deny"`
    pub default: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CnktrYamlV2 {
    pub app: CnktrAppSection,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub software: Option<CnktrSoftwareSection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intelligence: Option<CnktrIntelligenceSection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority: Option<CnktrAuthoritySection>,
    /// Flexible channel map for V1 scaffold.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channels: Option<serde_yaml::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adapters: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub world: Option<serde_yaml::Value>,
}

pub fn parse_cnktr_yaml(text: &str) -> Result<CnktrYamlV2, CpkgError> {
    Ok(serde_yaml::from_str(text)?)
}

pub fn validate_meta_package(meta: &MetaPackageJsonV2) -> Result<(), CpkgError> {
    if meta.schema != APP_PACKAGE_V2_SCHEMA {
        return Err(CpkgError::Invalid(
            "META/package.json schema must be connector.app_package.v2",
        ));
    }
    if meta.package_id.trim().is_empty() {
        return Err(CpkgError::Invalid("package_id is required"));
    }
    if meta.version.trim().is_empty() {
        return Err(CpkgError::Invalid("version is required"));
    }
    if meta.mode == PackageModeV2::Attached {
        let Some(exe) = meta.executable.as_ref() else {
            return Err(CpkgError::Invalid(
                "attached mode requires executable identity",
            ));
        };
        if exe.selector.trim().is_empty() {
            return Err(CpkgError::Invalid(
                "attached executable.selector is required",
            ));
        }
    }
    Ok(())
}

/// True for secret-like archive paths that must never ship in a package.
pub fn is_forbidden_archive_path(path: &str) -> bool {
    let normalized = path.trim_start_matches('/').replace('\\', "/");
    if normalized.is_empty() {
        return false;
    }
    let lower = normalized.to_ascii_lowercase();
    let segments: Vec<&str> = lower.split('/').filter(|s| !s.is_empty()).collect();
    let file_name = *segments.last().unwrap_or(&"");

    if segments.iter().any(|s| *s == "secrets") {
        return true;
    }

    if file_name == ".env" || file_name == "var.env" {
        return true;
    }
    if file_name.starts_with(".env.") {
        return true;
    }
    if file_name.ends_with(".pem") || file_name.ends_with(".key") {
        return true;
    }
    matches!(
        file_name,
        "id_rsa"
            | "id_dsa"
            | "id_ecdsa"
            | "id_ed25519"
            | "id_rsa.pub"
            | "id_dsa.pub"
            | "id_ecdsa.pub"
            | "id_ed25519.pub"
    )
}

pub fn validate_archive_paths(paths: &[String]) -> Result<(), CpkgError> {
    for path in paths {
        if is_forbidden_archive_path(path) {
            return Err(CpkgError::ForbiddenPath(path.clone()));
        }
    }
    Ok(())
}

/// Derive immutable META identity from semantic `cnktr.yaml` intent.
pub fn cnktr_to_meta(cnktr: &CnktrYamlV2, version: &str) -> MetaPackageJsonV2 {
    MetaPackageJsonV2 {
        schema: APP_PACKAGE_V2_SCHEMA.into(),
        package_id: cnktr.app.id.clone(),
        kind: PackageKindV2::App,
        mode: cnktr.app.mode,
        version: version.into(),
        contract_digest: None,
        ir_digest: None,
        executable: cnktr
            .software
            .as_ref()
            .map(|s| s.executable.clone()),
        adapters: cnktr.adapters.clone().unwrap_or_default(),
        required_isolation: None,
        min_kernel_abi: None,
    }
}

/// Build an AppPackage V2 ZIP: `META/package.json` + `cnktr.yaml` + optional extras.
///
/// Does **not** embed `var.env` or other secret-like paths. Attached packages need
/// no `bin/` entry — they bind an existing executable via identity metadata.
pub fn write_app_cpkg_v2(
    meta: &MetaPackageJsonV2,
    cnktr_yaml: &str,
    extra_files: &[CpkgFileEntry],
) -> Result<Vec<u8>, CpkgError> {
    validate_meta_package(meta)?;
    let mut paths: Vec<String> = vec![PACKAGE_JSON_PATH.into(), CNKTR_YAML_PATH.into()];
    for e in extra_files {
        paths.push(e.path.clone());
    }
    validate_archive_paths(&paths)?;

    for e in extra_files {
        if e.path == PACKAGE_JSON_PATH || e.path == CNKTR_YAML_PATH {
            return Err(CpkgError::Invalid(
                "extra entry conflicts with reserved META/package.json / cnktr.yaml",
            ));
        }
    }

    let meta_bytes = serde_json::to_vec_pretty(meta)?;
    let mut out = Vec::new();
    let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
    {
        let mut zip = ZipWriter::new(std::io::Cursor::new(&mut out));
        zip.start_file(PACKAGE_JSON_PATH, opts)?;
        zip.write_all(&meta_bytes)?;
        zip.start_file(CNKTR_YAML_PATH, opts)?;
        zip.write_all(cnktr_yaml.as_bytes())?;
        for e in extra_files {
            zip.start_file(&e.path, opts)?;
            zip.write_all(&e.bytes)?;
        }
        zip.finish()?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::BIN_PREFIX;

    const ATTACHED_CURSOR_CNKTR: &str = r#"
app:
  id: cursor
  mode: attached
software:
  executable:
    selector: cursor
    path_hint: /usr/local/bin/cursor
    publisher: anysphere
intelligence:
  contract: contracts/cursor.cls
authority:
  default: deny
adapters:
  - filesystem
  - clipboard
"#;

    #[test]
    fn parse_attached_cursor_cnktr() {
        let cnktr = parse_cnktr_yaml(ATTACHED_CURSOR_CNKTR).unwrap();
        assert_eq!(cnktr.app.id, "cursor");
        assert_eq!(cnktr.app.mode, PackageModeV2::Attached);
        let soft = cnktr.software.as_ref().unwrap();
        assert_eq!(soft.executable.selector, "cursor");
        assert_eq!(
            soft.executable.path_hint.as_deref(),
            Some("/usr/local/bin/cursor")
        );
        assert_eq!(
            cnktr.intelligence.as_ref().unwrap().contract,
            "contracts/cursor.cls"
        );
        assert_eq!(cnktr.authority.as_ref().unwrap().default, "deny");
        assert_eq!(
            cnktr.adapters.as_ref().unwrap(),
            &vec!["filesystem".to_string(), "clipboard".to_string()]
        );

        let meta = cnktr_to_meta(&cnktr, "1.0.0");
        assert_eq!(meta.schema, APP_PACKAGE_V2_SCHEMA);
        assert_eq!(meta.package_id, "cursor");
        assert_eq!(meta.kind, PackageKindV2::App);
        assert_eq!(meta.mode, PackageModeV2::Attached);
        assert_eq!(meta.version, "1.0.0");
        assert_eq!(meta.executable.as_ref().unwrap().selector, "cursor");
        validate_meta_package(&meta).unwrap();
    }

    #[test]
    fn forbidden_path_rejection() {
        let forbidden = [
            ".env",
            ".env.local",
            "config/.env.production",
            "var.env",
            "secrets/token",
            "app/secrets/key",
            "certs/server.pem",
            "tls/private.key",
            "id_rsa",
            "ssh/id_ed25519",
        ];
        for path in forbidden {
            assert!(
                is_forbidden_archive_path(path),
                "expected forbidden: {path}"
            );
        }
        assert!(!is_forbidden_archive_path("META/package.json"));
        assert!(!is_forbidden_archive_path("cnktr.yaml"));
        assert!(!is_forbidden_archive_path("adapters/fs.wasm"));

        let err = validate_archive_paths(&["ui/index.html".into(), ".env".into()]).unwrap_err();
        match err {
            CpkgError::ForbiddenPath(p) => assert_eq!(p, ".env"),
            other => panic!("expected ForbiddenPath, got {other:?}"),
        }
    }

    #[test]
    fn attached_mode_does_not_require_bin_entry() {
        let cnktr = parse_cnktr_yaml(ATTACHED_CURSOR_CNKTR).unwrap();
        let meta = cnktr_to_meta(&cnktr, "0.1.0");
        let bytes = write_app_cpkg_v2(&meta, ATTACHED_CURSOR_CNKTR, &[]).unwrap();
        assert!(!bytes.is_empty());

        let cursor = std::io::Cursor::new(&bytes);
        let mut zip = zip::ZipArchive::new(cursor).unwrap();
        let mut names = Vec::new();
        for i in 0..zip.len() {
            names.push(zip.by_index(i).unwrap().name().to_string());
        }
        assert!(names.iter().any(|n| n == PACKAGE_JSON_PATH));
        assert!(names.iter().any(|n| n == CNKTR_YAML_PATH));
        assert!(!names.iter().any(|n| n.starts_with(BIN_PREFIX)));
    }

    #[test]
    fn meta_validation_requires_package_id_and_version() {
        let mut meta = MetaPackageJsonV2 {
            schema: APP_PACKAGE_V2_SCHEMA.into(),
            package_id: "cursor".into(),
            kind: PackageKindV2::App,
            mode: PackageModeV2::Attached,
            version: "1.0.0".into(),
            contract_digest: None,
            ir_digest: None,
            executable: Some(ExecutableIdentityV2 {
                selector: "cursor".into(),
                path_hint: None,
                digest: None,
                publisher: None,
            }),
            adapters: vec![],
            required_isolation: None,
            min_kernel_abi: None,
        };
        validate_meta_package(&meta).unwrap();

        meta.package_id = "  ".into();
        assert!(matches!(
            validate_meta_package(&meta),
            Err(CpkgError::Invalid("package_id is required"))
        ));
        meta.package_id = "cursor".into();
        meta.version = "".into();
        assert!(matches!(
            validate_meta_package(&meta),
            Err(CpkgError::Invalid("version is required"))
        ));
    }

    #[test]
    fn write_rejects_forbidden_extra() {
        let cnktr = parse_cnktr_yaml(ATTACHED_CURSOR_CNKTR).unwrap();
        let meta = cnktr_to_meta(&cnktr, "0.1.0");
        let extras = [CpkgFileEntry {
            path: "var.env".into(),
            bytes: b"SECRET=1\n".to_vec(),
        }];
        let err = write_app_cpkg_v2(&meta, ATTACHED_CURSOR_CNKTR, &extras).unwrap_err();
        assert!(matches!(err, CpkgError::ForbiddenPath(_)));
    }
}

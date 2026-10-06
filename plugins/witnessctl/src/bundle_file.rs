//! Portable `.witness` evidence bundle paths and loading.

use serde_json::Value;
use std::path::{Path, PathBuf};
use uuid::Uuid;

pub const BUNDLE_TYPE: &str = "witnessctl.evidence_bundle.v1";

/// Directory for sealed bundles (`WITNESSCTL_BUNDLE_DIR` or `./witness-evidence`).
pub fn bundle_dir() -> PathBuf {
    std::env::var("WITNESSCTL_BUNDLE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("./witness-evidence"))
}

/// Primary `.witness`, legacy `.witnessctl`, and metadata `.witness.json` paths.
pub fn bundle_paths(session_id: Uuid, timestamp: i64) -> (PathBuf, PathBuf, PathBuf) {
    let stem = format!("{}-{}", session_id, timestamp);
    let dir = bundle_dir();
    (
        dir.join(format!("{stem}.witness")),
        dir.join(format!("{stem}.witnessctl")),
        dir.join(format!("{stem}.witness.json")),
    )
}

/// Load bundle JSON from `.witness`, `.witnessctl`, or metadata `.witness.json`.
pub fn load_bundle_json(path: &Path) -> Result<Value, String> {
    let path_str = path.to_string_lossy();
    if path_str.ends_with(".witness.json") {
        let meta: Value = read_json_file(path)?;
        if let Some(primary) = meta.get("primary_path").and_then(|v| v.as_str()) {
            return read_json_file(Path::new(primary));
        }
        let sibling = path.with_extension("witness");
        if sibling.exists() {
            return read_json_file(&sibling);
        }
    }
    read_json_file(path)
}

fn read_json_file(path: &Path) -> Result<Value, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| format!("read {}: {}", path.display(), e))?;
    serde_json::from_str(&raw).map_err(|e| format!("invalid JSON in {}: {}", path.display(), e))
}

/// Write primary `.witness`, legacy `.witnessctl`, and sidecar metadata.
pub fn write_bundle_artifacts(
    witness_path: &Path,
    legacy_path: &Path,
    meta_path: &Path,
    bundle: &Value,
    meta: &Value,
) -> Result<(), String> {
    if let Some(parent) = witness_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let bytes =
        serde_json::to_vec_pretty(bundle).map_err(|e| format!("serialize bundle: {}", e))?;
    std::fs::write(witness_path, &bytes).map_err(|e| e.to_string())?;
    std::fs::write(legacy_path, &bytes).map_err(|e| e.to_string())?;
    let meta_bytes =
        serde_json::to_vec_pretty(meta).map_err(|e| format!("serialize metadata: {}", e))?;
    std::fs::write(meta_path, &meta_bytes).map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn load_bundle_from_witness_extension() {
        let dir = std::env::temp_dir().join(format!(
            "wc-bundle-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("test.witness");
        std::fs::write(&p, r#"{"bundle_type":"witnessctl.evidence_bundle.v1","captures":[],"receipts":[]}"#).unwrap();
        let v = load_bundle_json(&p).unwrap();
        assert_eq!(
            v.get("bundle_type").and_then(|x| x.as_str()),
            Some(BUNDLE_TYPE)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

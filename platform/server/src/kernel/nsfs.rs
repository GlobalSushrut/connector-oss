//! Per-agent namespace filesystem (NS FS) — top-level OS primitive.
//!
//! Not a Docker volume and not a guest rootfs. Each `agent_pid` gets a light
//! directory tree under `{CONNECTOR_DATA_DIR}/nsfs/{pid}/` that Landlock / DockLock
//! bind as `/workspace`, `/m`, `/k`, `/p`, `/v`. Shared kernel, no overlay2 daemon.

use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};

pub const NSFS_SCHEMA: &str = "connector.nsfs.v1";

/// Trees every intelligence owns. `/p` never reaches the LLM (docs/56).
pub const TREES: &[&str] = &["workspace", "m", "k", "p", "v", "out", "share"];

pub fn data_dir() -> PathBuf {
    PathBuf::from(std::env::var("CONNECTOR_DATA_DIR").unwrap_or_else(|_| "./data".into()))
}

pub fn sanitize_pid(agent_pid: &str) -> Result<String, String> {
    let s = agent_pid.trim();
    if s.is_empty()
        || s.len() > 128
        || s.contains("..")
        || s.contains('/')
        || s.contains('\\')
        || s.contains('\0')
    {
        return Err("invalid_agent_pid_for_nsfs".into());
    }
    Ok(s.to_string())
}

pub fn nsfs_root(agent_pid: &str) -> Result<PathBuf, String> {
    let pid = sanitize_pid(agent_pid)?;
    Ok(data_dir().join("nsfs").join(pid))
}

/// Create the per-agent NS FS tree. Idempotent. Extreme-light: mkdir only.
pub fn ensure_tree(agent_pid: &str) -> Result<Value, String> {
    let root = nsfs_root(agent_pid)?;
    fs::create_dir_all(&root).map_err(|e| format!("nsfs_mkdir: {e}"))?;
    for t in TREES {
        fs::create_dir_all(root.join(t)).map_err(|e| format!("nsfs_mkdir_{t}: {e}"))?;
    }
    // Memory OS mounts (AIOS V1) — still under the same pid tree.
    for rel in ["m/core", "m/recall", "k/archival"] {
        fs::create_dir_all(root.join(rel)).map_err(|e| format!("nsfs_mkdir_{rel}: {e}"))?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        chmod_0700(&root);
        for t in TREES {
            chmod_0700(&root.join(t));
        }
        for rel in ["m/core", "m/recall", "k/archival"] {
            chmod_0700(&root.join(rel));
        }
    }
    Ok(snapshot_at(&root, agent_pid))
}

#[cfg(unix)]
fn chmod_0700(p: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(p, fs::Permissions::from_mode(0o700));
}

pub fn max_bytes() -> u64 {
    std::env::var("CONNECTOR_NSFS_MAX_BYTES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(256 * 1024 * 1024)
}

pub fn tree_bytes(agent_pid: &str) -> u64 {
    let Ok(root) = nsfs_root(agent_pid) else {
        return 0;
    };
    dir_bytes(&root, 0, 8_000)
}

fn dir_bytes(dir: &Path, acc: u64, budget: u32) -> u64 {
    if budget == 0 {
        return acc;
    }
    let Ok(rd) = fs::read_dir(dir) else {
        return acc;
    };
    let mut n = acc;
    let mut left = budget;
    for ent in rd.flatten() {
        if left == 0 {
            break;
        }
        left -= 1;
        let path = ent.path();
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.file_type().is_symlink() {
            continue;
        }
        if meta.is_dir() {
            n = dir_bytes(&path, n, left);
        } else {
            n = n.saturating_add(meta.len());
        }
    }
    n
}

pub fn assert_quota(agent_pid: &str, extra: u64) -> Result<(), String> {
    let used = tree_bytes(agent_pid);
    let cap = max_bytes();
    if used.saturating_add(extra) > cap {
        return Err(format!(
            "nsfs_quota_exceeded: used={used} extra={extra} cap={cap}"
        ));
    }
    Ok(())
}

pub fn snapshot(agent_pid: &str) -> Value {
    match nsfs_root(agent_pid) {
        Ok(root) => snapshot_at(&root, agent_pid),
        Err(e) => json!({
            "ok": false,
            "schema": NSFS_SCHEMA,
            "error": e,
        }),
    }
}

fn snapshot_at(root: &Path, agent_pid: &str) -> Value {
    let exists = root.is_dir();
    let trees: Vec<Value> = TREES
        .iter()
        .map(|t| {
            let p = root.join(t);
            json!({
                "name": t,
                "path": p.to_string_lossy(),
                "exists": p.is_dir(),
                "bind": match *t {
                    "workspace" => "/workspace",
                    "out" => "/workspace/out",
                    "m" => "/m",
                    "k" => "/k",
                    "p" => "/p",
                    "v" => "/v",
                    "share" => "/share",
                    _ => "/workspace",
                },
            })
        })
        .collect();
    json!({
        "ok": true,
        "schema": NSFS_SCHEMA,
        "agent_pid": agent_pid,
        "root": root.to_string_lossy(),
        "exists": exists,
        "trees": trees,
        "honesty": "NS FS is a per-agent directory namespace on the host kernel — not a Docker volume, not a VM disk. Landlock/DockLock bind these paths. /p never reaches the LLM. /share is empty until a human+root sharing contract mints a portal. Agent A cannot read Agent B's tree.",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_path_escape() {
        assert!(sanitize_pid("../etc").is_err());
        assert!(sanitize_pid("a/b").is_err());
        assert!(sanitize_pid("agt_ok").is_ok());
    }

    #[test]
    fn ensure_creates_trees() {
        let dir = std::env::temp_dir().join(format!("connector-nsfs-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        std::env::set_var("CONNECTOR_DATA_DIR", dir.to_string_lossy().as_ref());
        let v = ensure_tree("agt_nsfs_unit").expect("ensure");
        assert_eq!(v["ok"], true);
        for t in TREES {
            assert!(dir.join("nsfs/agt_nsfs_unit").join(t).is_dir(), "{t}");
        }
        assert!(dir.join("nsfs/agt_nsfs_unit/m/core").is_dir());
        assert!(dir.join("nsfs/agt_nsfs_unit/k/archival").is_dir());
        let _ = fs::remove_dir_all(&dir);
    }
}

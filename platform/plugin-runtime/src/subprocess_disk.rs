//! Phase 5.8 partial — subprocess writable disk quota preflight.
//!
//! This is a host-side best-effort guard for plugin subprocess runtime. It checks the size of
//! the writable workspace tree before spawn and can fail closed when configured.

use serde_json::json;
use std::path::{Path, PathBuf};

use crate::error::PluginRuntimeError;
use crate::types::SpawnRequest;

fn env_truthy(name: &str) -> bool {
    match std::env::var(name) {
        Ok(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => false,
    }
}

fn parse_limit_bytes() -> Option<u64> {
    let raw = std::env::var("CONNECTOR_PLUGIN_SUBPROCESS_WORKSPACE_MAX_BYTES").ok()?;
    let n = raw.trim().parse::<u64>().ok()?;
    if n > 0 { Some(n) } else { None }
}

fn guarded_root(req: &SpawnRequest) -> Option<PathBuf> {
    req.workspace_host_mount
        .clone()
        .or_else(|| req.cwd.clone())
        .map(|p| p.to_path_buf())
}

fn dir_size_bytes(path: &Path) -> Result<u64, PluginRuntimeError> {
    let mut total: u64 = 0;
    let mut stack: Vec<PathBuf> = vec![path.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for ent in std::fs::read_dir(&dir)? {
            let ent = ent?;
            let ft = ent.file_type()?;
            let p = ent.path();
            if ft.is_symlink() {
                // Avoid following symlinks out of tree.
                continue;
            }
            if ft.is_dir() {
                stack.push(p);
            } else if ft.is_file() {
                total = total.saturating_add(ent.metadata()?.len());
            }
        }
    }
    Ok(total)
}

/// Returns a telemetry JSON fragment. If enforce=true and over limit, returns Err.
pub(crate) fn preflight_workspace_quota(req: &SpawnRequest) -> Result<serde_json::Value, PluginRuntimeError> {
    let enforce = env_truthy("CONNECTOR_PLUGIN_SUBPROCESS_WORKSPACE_MAX_ENFORCE");
    let Some(limit_bytes) = parse_limit_bytes() else {
        return Ok(json!({
            "scope": "workspace_quota",
            "configured": false,
            "enforce": enforce,
        }));
    };
    let Some(root) = guarded_root(req) else {
        return Ok(json!({
            "scope": "workspace_quota",
            "configured": true,
            "enforce": enforce,
            "limit_bytes": limit_bytes,
            "checked": false,
            "reason": "no_workspace_root"
        }));
    };
    if !root.is_dir() {
        return Ok(json!({
            "scope": "workspace_quota",
            "configured": true,
            "enforce": enforce,
            "limit_bytes": limit_bytes,
            "checked": false,
            "reason": "root_not_dir",
            "root": root,
        }));
    }
    let used_bytes = dir_size_bytes(&root)?;
    let over = used_bytes > limit_bytes;
    if over && enforce {
        return Err(PluginRuntimeError::Spawn(format!(
            "workspace quota exceeded before spawn: used={} limit={} root={}",
            used_bytes,
            limit_bytes,
            root.display()
        )));
    }
    Ok(json!({
        "scope": "workspace_quota",
        "configured": true,
        "enforce": enforce,
        "checked": true,
        "root": root,
        "used_bytes": used_bytes,
        "limit_bytes": limit_bytes,
        "over_limit": over,
    }))
}


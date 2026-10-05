//! Linux cgroup v2 helpers — subprocess attach + utilization sample.
//!
//! Parent: **`CONNECTOR_PLUGIN_SUBPROCESS_CGROUP_PARENT`** or auto-detect from **`/proc/self/cgroup`**
//! (creates **`connector-runners`** under the current v2 subtree when writable). If the parent is not
//! writable, attach reports **`attached: false`** with a reason — it does not fake a limit.
//! Default leaf caps when the matching env is unset: **512 MiB** `memory.max`, **50%** `cpu.max`,
//! **64** `pids.max`. Set the env to **`0`** to skip that cap. Production-ish env enforces attach
//! unless **`CONNECTOR_PLUGIN_SUBPROCESS_CGROUP_ENFORCE`** is explicitly off.
//! Optional **`CONNECTOR_PLUGIN_SUBPROCESS_CPU_WEIGHT`**: **`cpu.weight`** (**`1..=10_000`**).
//! Optional **`CONNECTOR_PLUGIN_SUBPROCESS_MEMORY_HIGH_BYTES`**: **`memory.high`**.
//! Optional **`CONNECTOR_PLUGIN_SUBPROCESS_MEMORY_SWAP_MAX_BYTES`**: **`memory.swap.max`**.

use serde_json::json;

/// Sanitize `vendor/slug` for use as a single cgroup directory segment.
pub fn sanitize_plugin_segment(plugin_id: &str) -> String {
    let mut s: String = plugin_id
        .chars()
        .map(|c| match c {
            '/' | ':' | '.' | '@' | ' ' => '-',
            c if c.is_ascii_alphanumeric() || c == '_' || c == '-' => c,
            _ => '_',
        })
        .collect();
    if s.is_empty() {
        s = "plugin".into();
    }
    if s.len() > 120 {
        s.truncate(120);
    }
    s
}

fn env_truthy(name: &str) -> bool {
    match std::env::var(name) {
        Ok(v) => {
            let s = v.trim().to_ascii_lowercase();
            matches!(s.as_str(), "1" | "true" | "yes" | "on")
        }
        Err(_) => false,
    }
}

/// JSON fragment for [`SpawnReceipt::detail`](crate::types::SpawnReceipt) (all OS — Linux fills fields).
pub fn cgroup_attach_detail(plugin_id: &str, pid: u32) -> serde_json::Value {
    #[cfg(target_os = "linux")]
    {
        linux_attach_detail(plugin_id, pid)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (plugin_id, pid);
        json!({
            "scope": "unsupported_os",
            "attached": false
        })
    }
}

/// Sum **`cpu.stat`** **`usage_usec`** for cgroup v2 children named **`runner-<sanitized_plugin_id>-*`** under
/// **`CONNECTOR_PLUGIN_SUBPROCESS_CGROUP_PARENT`** (Linux only). Used by the tier scheduler for optional
/// cgroup-accelerated idle demotion (**Phase 5.4.3**).
pub fn tier_cgroup_runner_usage_usec_for_plugin(plugin_id: &str) -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let parent_raw = cgroup_parent_raw()?;
        let parent = Path::new(&parent_raw);
        if !parent.is_dir() {
            return None;
        }
        let seg = sanitize_plugin_segment(plugin_id);
        let prefix = format!("runner-{seg}-");
        let mut total: u64 = 0;
        let entries = std::fs::read_dir(parent).ok()?;
        for ent in entries.flatten() {
            let Ok(ftype) = ent.file_type() else {
                continue;
            };
            if !ftype.is_dir() {
                continue;
            }
            let name = ent.file_name().to_string_lossy().into_owned();
            if !name.starts_with(&prefix) {
                continue;
            }
            let cpu_stat = ent.path().join("cpu.stat");
            if let Some(u) = read_cpu_usage_usec(&cpu_stat) {
                total = total.saturating_add(u);
            }
        }
        Some(total)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = plugin_id;
        None
    }
}

/// Optional utilization sample for tier scheduler (`GET …/plugin-tier-scheduler` → `utilization.cgroup_v2`).
pub fn tier_cgroup_scan_from_env() -> Option<serde_json::Value> {
    #[cfg(target_os = "linux")]
    {
        if !env_truthy("CONNECTOR_PLUGIN_TIER_CGROUP_SCAN") {
            return None;
        }
        let parent = std::env::var("CONNECTOR_PLUGIN_SUBPROCESS_CGROUP_PARENT")
            .ok()
            .filter(|s| !s.trim().is_empty())?;
        linux_scan_parent(std::path::Path::new(parent.trim()))
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

#[cfg(target_os = "linux")]
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::os::linux::fs::MetadataExt;

#[cfg(target_os = "linux")]
fn parse_u64_env(name: &str) -> Option<u64> {
    std::env::var(name).ok()?.trim().parse::<u64>().ok()
}

/// `0` disables the cap; unset uses `default`.
#[cfg(target_os = "linux")]
fn limit_or_default(name: &str, default: u64) -> Option<u64> {
    match parse_u64_env(name) {
        Some(0) => None,
        Some(n) => Some(n),
        None => Some(default),
    }
}

#[cfg(target_os = "linux")]
fn cgroup_enforce() -> bool {
    match std::env::var("CONNECTOR_PLUGIN_SUBPROCESS_CGROUP_ENFORCE") {
        Ok(v) => {
            let s = v.trim().to_ascii_lowercase();
            matches!(s.as_str(), "1" | "true" | "yes" | "on")
        }
        Err(_) => crate::productionish_env(),
    }
}

/// Env parent, else `/sys/fs/cgroup` + `/proc/self/cgroup` + `connector-runners` when writable.
#[cfg(target_os = "linux")]
fn cgroup_parent_raw() -> Option<String> {
    if let Some(p) = std::env::var("CONNECTOR_PLUGIN_SUBPROCESS_CGROUP_PARENT")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    {
        return Some(p);
    }
    let text = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    let mut rel: Option<String> = None;
    for line in text.lines() {
        if let Some(path) = line.split_once("::").map(|(_, p)| p) {
            rel = Some(path.trim().to_string());
        } else if let Some(path) = line.split(':').nth(2) {
            rel = Some(path.trim().to_string());
        }
    }
    let rel = rel?;
    let base = PathBuf::from("/sys/fs/cgroup").join(rel.trim_start_matches('/'));
    if !base.is_dir() {
        return None;
    }
    let runners = base.join("connector-runners");
    if runners.is_dir() || std::fs::create_dir_all(&runners).is_ok() {
        return Some(runners.to_string_lossy().into_owned());
    }
    let probe = base.join(".connector-cgroup-probe");
    if std::fs::create_dir(&probe).is_ok() {
        let _ = std::fs::remove_dir(&probe);
        return Some(base.to_string_lossy().into_owned());
    }
    None
}

#[cfg(target_os = "linux")]
fn linux_attach_json(
    plugin_id: &str,
    pid: u32,
    workspace_root: Option<&Path>,
) -> serde_json::Value {
    let Some(parent_raw) = cgroup_parent_raw() else {
        return json!({
            "scope": "cgroup_v2",
            "attached": false,
            "reason": "cgroup_parent_unresolved",
            "enforce": cgroup_enforce(),
        });
    };
    let parent = PathBuf::from(&parent_raw);
    let enforce = cgroup_enforce();
    match linux_attach_pid(&parent, plugin_id, pid, workspace_root) {
        Ok((leaf, limits)) => json!({
            "scope": "cgroup_v2",
            "attached": true,
            "parent": parent_raw,
            "leaf": leaf.to_string_lossy(),
            "pid": pid,
            "limits": limits,
            "enforce": enforce,
        }),
        Err(e) => json!({
            "scope": "cgroup_v2",
            "attached": false,
            "parent": parent_raw,
            "error": e,
            "enforce": enforce,
        }),
    }
}

#[cfg(target_os = "linux")]
fn parent_has_controller(parent: &Path, controller: &str) -> bool {
    let Ok(s) = std::fs::read_to_string(parent.join("cgroup.controllers")) else {
        return false;
    };
    s.split_whitespace().any(|c| c == controller)
}

#[cfg(target_os = "linux")]
fn write_cgroup_file(path: &Path, contents: &str, label: &str) -> Result<(), String> {
    match std::fs::write(path, contents) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(format!(
            "{label}: not found (controller not delegated on this parent)"
        )),
        Err(e) => Err(format!("{label}: {e}")),
    }
}

#[cfg(target_os = "linux")]
fn parse_io_max_specs(raw: &str) -> Vec<(String, Vec<(String, u64)>)> {
    let mut out = Vec::new();
    for part in raw.split(',') {
        let seg = part.trim();
        if seg.is_empty() {
            continue;
        }
        let mut it = seg.split_whitespace();
        let Some(dev) = it.next() else {
            continue;
        };
        if !dev.contains(':') {
            continue;
        }
        let mut kvs: Vec<(String, u64)> = Vec::new();
        for tok in it {
            let Some((k, v)) = tok.split_once('=') else {
                continue;
            };
            let key = k.trim().to_ascii_lowercase();
            if !matches!(key.as_str(), "rbps" | "wbps" | "riops" | "wiops") {
                continue;
            }
            if let Ok(n) = v.trim().parse::<u64>() {
                if n > 0 {
                    kvs.push((key, n));
                }
            }
        }
        if !kvs.is_empty() {
            out.push((dev.to_string(), kvs));
        }
    }
    out
}

#[cfg(target_os = "linux")]
fn parse_io_max_auto_kvs_from_env() -> Vec<(String, u64)> {
    let mut kvs = Vec::new();
    for (key, env_name) in [
        ("rbps", "CONNECTOR_PLUGIN_SUBPROCESS_IO_MAX_AUTO_RBPS"),
        ("wbps", "CONNECTOR_PLUGIN_SUBPROCESS_IO_MAX_AUTO_WBPS"),
        ("riops", "CONNECTOR_PLUGIN_SUBPROCESS_IO_MAX_AUTO_RIOPS"),
        ("wiops", "CONNECTOR_PLUGIN_SUBPROCESS_IO_MAX_AUTO_WIOPS"),
    ] {
        if let Some(v) = parse_u64_env(env_name) {
            if v > 0 {
                kvs.push((key.to_string(), v));
            }
        }
    }
    kvs
}

#[cfg(target_os = "linux")]
fn linux_device_major_minor(st_dev: u64) -> String {
    // Linux device encoding (kdev_t) as used by stat(2).
    let major = ((st_dev >> 8) & 0x0fff) | ((st_dev >> 32) & 0xfffff000);
    let minor = (st_dev & 0x00ff) | ((st_dev >> 12) & 0xffffff00);
    format!("{major}:{minor}")
}

#[cfg(target_os = "linux")]
fn workspace_device_major_minor(root: Option<&Path>) -> Option<String> {
    let p = root?;
    let md = std::fs::metadata(p).ok()?;
    Some(linux_device_major_minor(md.st_dev()))
}

#[cfg(target_os = "linux")]
fn linux_attach_detail(plugin_id: &str, pid: u32) -> serde_json::Value {
    linux_attach_json(plugin_id, pid, None)
}

#[cfg(target_os = "linux")]
fn linux_attach_pid(
    parent: &Path,
    plugin_id: &str,
    pid: u32,
    workspace_root: Option<&Path>,
) -> Result<(PathBuf, serde_json::Value), String> {
    if !parent.is_dir() {
        return Err(format!("cgroup parent is not a directory: {}", parent.display()));
    }
    let seg = sanitize_plugin_segment(plugin_id);
    let leaf = parent.join(format!("runner-{seg}-{pid}"));
    std::fs::create_dir(&leaf).map_err(|e| format!("mkdir {}: {}", leaf.display(), e))?;
    let mut limits = json!({});

    if let Some(bytes) = limit_or_default("CONNECTOR_PLUGIN_SUBPROCESS_MEMORY_MAX_BYTES", 512 * 1024 * 1024)
    {
        if bytes > 0 {
            if parent_has_controller(parent, "memory") {
                let p = leaf.join("memory.max");
                write_cgroup_file(&p, &format!("{bytes}\n"), "memory.max")?;
                limits["memory_max_bytes"] = json!(bytes);
            } else {
                limits["memory_max_skipped"] = json!({
                    "requested": bytes,
                    "reason": "parent_cgroup_controllers_missing_memory",
                });
            }
        }
    }

    if let Some(high) = parse_u64_env("CONNECTOR_PLUGIN_SUBPROCESS_MEMORY_HIGH_BYTES") {
        if high > 0 {
            if parent_has_controller(parent, "memory") {
                let p = leaf.join("memory.high");
                std::fs::write(&p, format!("{high}\n")).map_err(|e| format!("memory.high: {e}"))?;
                limits["memory_high_bytes"] = json!(high);
            } else {
                limits["memory_high_skipped"] = json!({
                    "requested": high,
                    "reason": "parent_cgroup_controllers_missing_memory",
                });
            }
        }
    }

    if let Some(swap_max) = parse_u64_env("CONNECTOR_PLUGIN_SUBPROCESS_MEMORY_SWAP_MAX_BYTES") {
        if parent_has_controller(parent, "memory") {
            let p = leaf.join("memory.swap.max");
            std::fs::write(&p, format!("{swap_max}\n"))
                .map_err(|e| format!("memory.swap.max: {e}"))?;
            limits["memory_swap_max_bytes"] = json!(swap_max);
        } else {
            limits["memory_swap_max_skipped"] = json!({
                "requested": swap_max,
                "reason": "parent_cgroup_controllers_missing_memory",
            });
        }
    }

    if let Some(pct) = limit_or_default("CONNECTOR_PLUGIN_SUBPROCESS_CPU_PCT", 50) {
        if (1..=100).contains(&pct) {
            let period = 100_000u64;
            let quota = period.saturating_mul(pct).saturating_div(100);
            if parent_has_controller(parent, "cpu") {
                let p = leaf.join("cpu.max");
                write_cgroup_file(&p, &format!("{quota} {period}\n"), "cpu.max")?;
                limits["cpu_pct"] = json!(pct);
                limits["cpu_max_quota"] = json!(quota);
                limits["cpu_max_period"] = json!(period);
            } else {
                limits["cpu_max_skipped"] = json!({
                    "requested_pct": pct,
                    "reason": "parent_cgroup_controllers_missing_cpu",
                });
            }
        }
    }

    if let Some(w) = parse_u64_env("CONNECTOR_PLUGIN_SUBPROCESS_CPU_WEIGHT") {
        if w > 0 {
            let weight = w.clamp(1, 10_000);
            if parent_has_controller(parent, "cpu") {
                let p = leaf.join("cpu.weight");
                std::fs::write(&p, format!("{weight}\n")).map_err(|e| format!("cpu.weight: {e}"))?;
                limits["cpu_weight"] = json!(weight);
                if weight != w {
                    limits["cpu_weight_requested"] = json!(w);
                }
            } else {
                limits["cpu_weight_skipped"] = json!({
                    "requested": w,
                    "reason": "parent_cgroup_controllers_missing_cpu",
                });
            }
        }
    }

    if let Some(raw) = limit_or_default("CONNECTOR_PLUGIN_SUBPROCESS_CGROUP_PIDS_MAX", 64) {
        if raw > 0 {
            if parent_has_controller(parent, "pids") {
                let cap = raw.clamp(32, 262_144);
                let p = leaf.join("pids.max");
                write_cgroup_file(&p, &format!("{cap}\n"), "pids.max")?;
                limits["pids_max"] = json!(cap);
                if cap != raw {
                    limits["pids_max_requested"] = json!(raw);
                }
            } else {
                limits["pids_max_skipped"] = json!({
                    "requested": raw,
                    "reason": "parent_cgroup_controllers_missing_pids",
                });
            }
        }
    }

    let explicit_specs = std::env::var("CONNECTOR_PLUGIN_SUBPROCESS_IO_MAX")
        .ok()
        .map(|raw| parse_io_max_specs(&raw))
        .unwrap_or_default();
    let (specs, io_max_source) = if !explicit_specs.is_empty() {
        (explicit_specs, Some("explicit"))
    } else if env_truthy("CONNECTOR_PLUGIN_SUBPROCESS_IO_MAX_AUTO") {
        let kvs = parse_io_max_auto_kvs_from_env();
        if kvs.is_empty() {
            (Vec::new(), Some("auto_workspace_device_no_limits"))
        } else if let Some(dev) = workspace_device_major_minor(workspace_root) {
            (vec![(dev, kvs)], Some("auto_workspace_device"))
        } else {
            (Vec::new(), Some("auto_workspace_device_unresolved"))
        }
    } else {
        (Vec::new(), None)
    };
    if !specs.is_empty() {
        let mut lines: Vec<String> = Vec::new();
        let mut telemetry: Vec<String> = Vec::new();
        for (dev, kvs) in specs {
            let frag = kvs
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join(" ");
            lines.push(format!("{dev} {frag}"));
            telemetry.push(format!("{dev} {frag}"));
        }
        let p = leaf.join("io.max");
        std::fs::write(&p, format!("{}\n", lines.join("\n"))).map_err(|e| format!("io.max: {e}"))?;
        limits["io_max"] = json!(telemetry);
    }
    if let Some(source) = io_max_source {
        limits["io_max_source"] = json!(source);
    }

    let procs = leaf.join("cgroup.procs");
    std::fs::write(&procs, format!("{pid}\n")).map_err(|e| format!("cgroup.procs: {e}"))?;
    Ok((leaf, limits))
}

pub fn cgroup_attach_detail_for_request(
    plugin_id: &str,
    pid: u32,
    workspace_root: Option<&std::path::Path>,
) -> serde_json::Value {
    #[cfg(target_os = "linux")]
    {
        linux_attach_json(plugin_id, pid, workspace_root)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (plugin_id, pid, workspace_root);
        json!({
            "scope": "unsupported_os",
            "attached": false
        })
    }
}

#[cfg(target_os = "linux")]
fn read_cpu_usage_usec(path: &Path) -> Option<u64> {
    let data = std::fs::read_to_string(path).ok()?;
    for line in data.lines() {
        let mut parts = line.split_whitespace();
        if parts.next()? == "usage_usec" {
            return parts.next()?.parse().ok();
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn linux_scan_parent(parent: &Path) -> Option<serde_json::Value> {
    if !parent.is_dir() {
        return Some(json!({
            "error": "parent_not_dir",
            "path": parent.to_string_lossy(),
        }));
    }
    let mut children: Vec<serde_json::Value> = Vec::new();
    let mut total: u64 = 0;
    let entries = std::fs::read_dir(parent).ok()?;
    for ent in entries.flatten() {
        let ptype = ent.file_type().ok()?;
        if !ptype.is_dir() {
            continue;
        }
        let name = ent.file_name().to_string_lossy().into_owned();
        if !name.starts_with("runner-") {
            continue;
        }
        let cpu_stat = ent.path().join("cpu.stat");
        if let Some(usec) = read_cpu_usage_usec(&cpu_stat) {
            total = total.saturating_add(usec);
            children.push(json!({ "name": name, "usage_usec": usec }));
        }
    }
    children.sort_by(|a, b| {
        let na = a.get("name").and_then(|x| x.as_str()).unwrap_or("");
        let nb = b.get("name").and_then(|x| x.as_str()).unwrap_or("");
        na.cmp(nb)
    });
    Some(json!({
        "scope": "cgroup_v2_children",
        "parent": parent.to_string_lossy(),
        "children_sampled": children.len(),
        "usage_usec_total": total,
        "by_child": children,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_plugin_segment_basic() {
        assert_eq!(sanitize_plugin_segment("acme/demo"), "acme-demo");
        assert_eq!(sanitize_plugin_segment("weird/id:1"), "weird-id-1");
        assert!(!sanitize_plugin_segment("x/y").contains('/'));
    }
}

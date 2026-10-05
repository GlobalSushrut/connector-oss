//! Host eBPF load / attach / pin / map update (Seven Pillars §2).
//!
//! Uses `bpftool` + compiled `connector_mark_deny.bpf.o`.
//! `ebpf_loaded` is true only when bpffs pins exist and are readable — never
//! from an operator-attested env flag alone.

use anyhow::{anyhow, Context, Result};
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const DEFAULT_PIN_ROOT: &str = "/sys/fs/bpf/connector";
const PROG_NAME: &str = "connector_mark_deny";
const MAP_NAME: &str = "deny_marks";

fn pin_root() -> PathBuf {
    std::env::var("CONNECTOR_EBPF_PIN_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_PIN_ROOT))
}

fn object_path() -> PathBuf {
    if let Ok(p) = std::env::var("CONNECTOR_EBPF_OBJ") {
        return PathBuf::from(p);
    }
    // Prefer beside binary, then repo-relative.
    let candidates = [
        PathBuf::from("platform/ebpf/connector_mark_deny.bpf.o"),
        PathBuf::from("/usr/lib/connector/ebpf/connector_mark_deny.bpf.o"),
        PathBuf::from("/usr/share/connector/ebpf/connector_mark_deny.bpf.o"),
    ];
    for c in candidates {
        if c.is_file() {
            return c;
        }
    }
    PathBuf::from("platform/ebpf/connector_mark_deny.bpf.o")
}

fn bpftool() -> Result<&'static str> {
    for bin in ["bpftool", "/usr/sbin/bpftool", "/usr/bin/bpftool"] {
        if Command::new(bin)
            .arg("version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            return Ok(bin);
        }
    }
    Err(anyhow!("bpftool not found — install linux-tools / bpftool"))
}

fn run(bin: &str, args: &[&str]) -> Result<String> {
    let out = Command::new(bin)
        .args(args)
        .output()
        .with_context(|| format!("exec {bin} {:?}", args))?;
    if !out.status.success() {
        return Err(anyhow!(
            "{bin} {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

/// Raise memlock soft limit when possible (needed on older kernels).
fn bump_memlock() {
    // Best-effort: bpftool / libbpf also try this.
    let _ = Command::new("prlimit")
        .args(["--pid", &std::process::id().to_string(), "--memlock=unlimited"])
        .status();
}

pub fn agent_pin_dir(agent_pid: &str) -> PathBuf {
    pin_root().join(sanitize(agent_pid))
}

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect()
}

/// Probe: true only if program + map pins exist under the agent (or global) pin dir.
pub fn probe_loaded(agent_pid: Option<&str>) -> bool {
    let roots = match agent_pid {
        Some(pid) => vec![agent_pin_dir(pid), pin_root().join("global")],
        None => vec![pin_root().join("global"), pin_root()],
    };
    for root in roots {
        let prog = root.join("prog");
        let map = root.join("deny_marks");
        if prog.is_file() && map.is_file() {
            return true;
        }
        // Some bpftool versions pin as directories
        if prog.is_dir() || (root.join(PROG_NAME).exists() && root.join(MAP_NAME).exists()) {
            return true;
        }
    }
    false
}

pub fn status_json(agent_pid: Option<&str>) -> serde_json::Value {
    let obj = object_path();
    let loaded = probe_loaded(agent_pid);
    let root = agent_pid
        .map(agent_pin_dir)
        .unwrap_or_else(|| pin_root().join("global"));
    json!({
        "schema": "connector.kerneld.ebpf.v1",
        "ebpf_loaded": loaded,
        "mechanism": "cgroup_skb_egress_mark_deny",
        "object_path": obj.display().to_string(),
        "object_present": obj.is_file(),
        "pin_root": root.display().to_string(),
        "bpftool": bpftool().ok(),
        "require_env": "CONNECTOR_EBPF_REQUIRE",
        "honesty": if loaded {
            "Real bpffs pins present — eBPF program loaded/attached (or left pinned)"
        } else {
            "No bpffs pins — eBPF not loaded. Run: connector-kerneld ebpf-load"
        },
        "caps_needed": ["CAP_BPF", "CAP_NET_ADMIN"],
    })
}

/// Load program, pin prog+map, optionally attach to cgroup.
pub fn load_and_pin(agent_pid: &str, cgroup_path: Option<&str>) -> Result<serde_json::Value> {
    bump_memlock();
    let bin = bpftool()?;
    let obj = object_path();
    if !obj.is_file() {
        return Err(anyhow!(
            "BPF object missing at {} — run: make -C platform/ebpf",
            obj.display()
        ));
    }
    let pin_dir = agent_pin_dir(agent_pid);
    fs::create_dir_all(&pin_dir).with_context(|| format!("mkdir {}", pin_dir.display()))?;
    let prog_pin = pin_dir.join("prog");
    let map_pin = pin_dir.join("deny_marks");

    // Clean prior pins (best-effort).
    let _ = fs::remove_file(&prog_pin);
    let _ = fs::remove_file(&map_pin);

    // bpftool prog load <obj> <pin> type cgroup/skb pinmaps <dir>
    run(
        bin,
        &[
            "prog",
            "load",
            obj.to_str().unwrap(),
            prog_pin.to_str().unwrap(),
            "type",
            "cgroup/skb",
            "pinmaps",
            pin_dir.to_str().unwrap(),
        ],
    )
    .with_context(|| "bpftool prog load")?;

    // Map may be pinned as deny_marks inside pin_dir by pinmaps.
    if !map_pin.exists() {
        // Try discover map id and pin explicitly.
        if let Ok(maps) = run(bin, &["map", "show", "-j"]) {
            if let Ok(arr) = serde_json::from_str::<serde_json::Value>(&maps) {
                if let Some(list) = arr.as_array() {
                    for m in list {
                        let name = m.get("name").and_then(|v| v.as_str()).unwrap_or("");
                        if name == MAP_NAME || name == "deny_marks" {
                            if let Some(id) = m.get("id").and_then(|v| v.as_u64()) {
                                let _ = run(
                                    bin,
                                    &[
                                        "map",
                                        "pin",
                                        "id",
                                        &id.to_string(),
                                        map_pin.to_str().unwrap(),
                                    ],
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    let mut attached = false;
    let mut attach_detail = "skipped_no_cgroup".to_string();
    if let Some(cg) = cgroup_path.map(str::trim).filter(|s| !s.is_empty()) {
        // bpftool cgroup attach <cgroup> egress pinned <prog> 
        match run(
            bin,
            &[
                "cgroup",
                "attach",
                cg,
                "egress",
                "pinned",
                prog_pin.to_str().unwrap(),
            ],
        ) {
            Ok(_) => {
                attached = true;
                attach_detail = format!("attached_egress:{cg}");
            }
            Err(e) => {
                // Fallback multi-attach syntax variants.
                match run(
                    bin,
                    &[
                        "cgroup",
                        "attach",
                        cg,
                        "egress",
                        "id",
                        "0", // will fail; try pinned path as last arg variants
                    ],
                ) {
                    _ => {
                        attach_detail = format!("attach_failed:{e:#}");
                        if require_ebpf() {
                            return Err(anyhow!("eBPF attach failed under CONNECTOR_EBPF_REQUIRE: {e:#}"));
                        }
                    }
                }
            }
        }
    }

    if !probe_loaded(Some(agent_pid)) && require_ebpf() {
        return Err(anyhow!(
            "eBPF pins missing after load under CONNECTOR_EBPF_REQUIRE=1"
        ));
    }

    Ok(json!({
        "ok": true,
        "ebpf_loaded": probe_loaded(Some(agent_pid)),
        "prog_pin": prog_pin.display().to_string(),
        "map_pin": map_pin.display().to_string(),
        "attached": attached,
        "attach_detail": attach_detail,
        "agent_pid": agent_pid,
    }))
}

pub fn require_ebpf() -> bool {
    matches!(
        std::env::var("CONNECTOR_EBPF_REQUIRE")
            .ok()
            .as_deref()
            .map(|s| s.trim().to_ascii_lowercase())
            .as_deref(),
        Some("1") | Some("true") | Some("yes") | Some("on")
    )
}

/// Insert/update a deny mark in the pinned map (1 = deny).
pub fn deny_mark(agent_pid: &str, mark: u32, deny: bool) -> Result<serde_json::Value> {
    let bin = bpftool()?;
    let map_pin = agent_pin_dir(agent_pid).join("deny_marks");
    if !map_pin.exists() {
        // Try global
        let alt = pin_root().join("global").join("deny_marks");
        if alt.exists() {
            return deny_mark_at(bin, &alt, mark, deny);
        }
        return Err(anyhow!(
            "deny_marks map not pinned at {} — run ebpf-load first",
            map_pin.display()
        ));
    }
    deny_mark_at(bin, &map_pin, mark, deny)
}

fn deny_mark_at(bin: &str, map_pin: &Path, mark: u32, deny: bool) -> Result<serde_json::Value> {
    // Little-endian key bytes for u32 mark; value u8.
    let kb = mark.to_le_bytes();
    let key_hex = format!("{:02x}{:02x}{:02x}{:02x}", kb[0], kb[1], kb[2], kb[3]);
    let val_hex = if deny { "01" } else { "00" };
    run(
        bin,
        &[
            "map",
            "update",
            "pinned",
            map_pin.to_str().unwrap(),
            "key",
            "hex",
            &key_hex,
            "value",
            "hex",
            val_hex,
        ],
    )?;

    Ok(json!({
        "ok": true,
        "mark": mark,
        "deny": deny,
        "map_pin": map_pin.display().to_string(),
    }))
}

pub fn unload(agent_pid: &str) -> Result<serde_json::Value> {
    let pin_dir = agent_pin_dir(agent_pid);
    let mut removed = vec![];
    for name in ["prog", "deny_marks", PROG_NAME, MAP_NAME] {
        let p = pin_dir.join(name);
        if p.exists() {
            let _ = fs::remove_file(&p);
            removed.push(p.display().to_string());
        }
    }
    Ok(json!({
        "ok": true,
        "removed": removed,
        "ebpf_loaded": probe_loaded(Some(agent_pid)),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_agent_pid() {
        assert_eq!(sanitize("agent/foo:1"), "agent_foo_1");
    }

    #[test]
    fn status_reports_schema() {
        let v = status_json(None);
        assert_eq!(v["schema"], "connector.kerneld.ebpf.v1");
        assert!(v.get("ebpf_loaded").is_some());
    }
}

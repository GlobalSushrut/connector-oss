//! CDMI **intelligence** host egress cut.
//!
//! This is not a generic process firewall. It cuts **intelligence execution
//! egress** for a principal/agent under matrix isolation using:
//!   1. **nftables** table `inet connector_matrix` (preferred — matrix tables)
//!   2. **iptables-nft** / modern iptables (fallback — nft-compatible CLI)
//!
//! Isolation key = `meta mark` derived from **agent/intelligence identity**
//! (not OS PID). Intelligence runtimes must set `SO_MARK` from
//! `CONNECTOR_MATRIX_EGRESS_MARK` in cage env (`docklock::cage_env_for_intelligence`).
//! Continuity break → add mark to the matrix drop set; unquarantine → remove.

use std::process::{Command, Stdio};

use sha2::{Digest, Sha256};

use crate::kernel::matrix_isolation::matrix_hw_enforce_enabled;

/// Result of attempting an OS-level intelligence egress cut.
#[derive(Debug, Clone)]
pub struct HostEgressCutResult {
    pub applied: bool,
    pub backend: String,
    pub detail: String,
    pub intelligence_mark: String,
}

fn tool_ok(bin: &str, probe: &[&str]) -> bool {
    Command::new(bin)
        .args(probe)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// TG-0: whether host cut backends exist (intent ≠ applied cut).
#[derive(Debug, Clone, Copy)]
pub struct HostCutTools {
    pub nft: bool,
    pub iptables: bool,
}

impl HostCutTools {
    pub fn any(self) -> bool {
        self.nft || self.iptables
    }
}

pub fn host_cut_tools_available() -> HostCutTools {
    HostCutTools {
        nft: tool_ok("nft", &["--version"]),
        iptables: iptables_bin().is_some(),
    }
}

fn enforce_host_cut() -> bool {
    matrix_hw_enforce_enabled()
        || std::env::var("CONNECTOR_MATRIX_HOST_EGRESS")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
}

/// Stable mark for an intelligence principal/agent (not a process PID).
///
/// Layout: `0xCD << 24 | (sha256(agent_pid) & 0xFFFF)` so matrix tooling can
/// recognize Connector intelligence marks at a glance.
pub fn intelligence_egress_mark(agent_pid: &str) -> u32 {
    if let Ok(raw) = std::env::var("CONNECTOR_MATRIX_EGRESS_MARK") {
        let s = raw.trim();
        if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
            if let Ok(v) = u32::from_str_radix(hex, 16) {
                return v;
            }
        }
        if let Ok(v) = s.parse::<u32>() {
            return v;
        }
    }
    let dig = Sha256::digest(agent_pid.as_bytes());
    // 24-bit principal slice under Connector intelligence prefix 0xCD (P2-T08 non-collision).
    let low = u32::from_be_bytes([0, dig[0], dig[1], dig[2]]) & 0x00FF_FFFF;
    0xCD00_0000 | low
}

pub fn intelligence_egress_mark_hex(agent_pid: &str) -> String {
    format!("0x{:08x}", intelligence_egress_mark(agent_pid))
}

/// True when Connector eBPF prog pins exist under bpffs (same-host probe).
pub fn probe_ebpf_pins(agent_pid: Option<&str>) -> bool {
    let root = std::env::var("CONNECTOR_EBPF_PIN_ROOT")
        .unwrap_or_else(|_| "/sys/fs/bpf/connector".into());
    let candidates = match agent_pid {
        Some(pid) => {
            let safe: String = pid
                .chars()
                .map(|c| {
                    if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                        c
                    } else {
                        '_'
                    }
                })
                .collect();
            vec![
                format!("{root}/{safe}/prog"),
                format!("{root}/{safe}/deny_marks"),
                format!("{root}/global/prog"),
            ]
        }
        None => vec![format!("{root}/global/prog"), format!("{root}/prog")],
    };
    candidates.iter().any(|p| std::path::Path::new(p).exists())
}

/// Project deny mark into kerneld eBPF map when pins exist.
fn project_ebpf_deny_mark(agent_pid: &str, mark: u32, deny: bool) -> Result<(), String> {
    let pin_root = std::env::var("CONNECTOR_EBPF_PIN_ROOT")
        .unwrap_or_else(|_| "/sys/fs/bpf/connector".into());
    let safe: String = agent_pid
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let map_pin = format!("{pin_root}/{safe}/deny_marks");
    if !std::path::Path::new(&map_pin).exists() {
        return Err("ebpf_map_not_pinned".into());
    }
    let bin = if tool_ok("bpftool", &["version"]) {
        "bpftool"
    } else if tool_ok("/usr/sbin/bpftool", &["version"]) {
        "/usr/sbin/bpftool"
    } else {
        return Err("bpftool_missing".into());
    };
    let out = Command::new(bin)
        .args([
            "map",
            "update",
            "pinned",
            &map_pin,
            "key",
            "hex",
            &format!(
                "{:02x}{:02x}{:02x}{:02x}",
                mark.to_le_bytes()[0],
                mark.to_le_bytes()[1],
                mark.to_le_bytes()[2],
                mark.to_le_bytes()[3]
            ),
            "value",
            "hex",
            if deny { "01" } else { "00" },
        ])
        .output()
        .map_err(|e| format!("bpftool spawn: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "bpftool map update: {}",
            String::from_utf8_lossy(&out.stderr)
        ))
    }
}

fn run_nft(args: &[&str]) -> Result<(), String> {
    let out = Command::new("nft")
        .args(args)
        .output()
        .map_err(|e| format!("nft spawn failed: {e}"))?;
    if out.status.success() {
        return Ok(());
    }
    let err = String::from_utf8_lossy(&out.stderr);
    // Idempotent: already exists is OK.
    if err.contains("File exists") || err.contains("exists") {
        return Ok(());
    }
    Err(format!("nft {}: {}", args.join(" "), err.trim()))
}

fn run_nft_script(script: &str) -> Result<(), String> {
    use std::io::Write;
    let mut child = Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("nft -f spawn: {e}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(script.as_bytes())
            .map_err(|e| format!("nft stdin: {e}"))?;
    }
    let out = child
        .wait_with_output()
        .map_err(|e| format!("nft wait: {e}"))?;
    if out.status.success() {
        return Ok(());
    }
    let err = String::from_utf8_lossy(&out.stderr);
    if err.contains("File exists") || err.contains("exists") {
        return Ok(());
    }
    Err(format!("nft -f failed: {}", err.trim()))
}

/// Ensure the intelligence matrix nftables table exists.
///
/// ```text
/// table inet connector_matrix {
///   set intel_isolated {
///     type mark
///   }
///   chain intelligence_egress {
///     type filter hook output priority filter; policy accept;
///     meta mark @intel_isolated counter drop
///   }
/// }
/// ```
pub fn ensure_matrix_nft_tables() -> Result<(), String> {
    if !tool_ok("nft", &["--version"]) {
        return Err("nftables (nft) not available".into());
    }
    // Intelligence-plane matrix tables (not a generic process filter).
    let bootstrap = r#"
add table inet connector_matrix
add set inet connector_matrix intel_isolated { type mark ; }
add chain inet connector_matrix intelligence_egress { type filter hook output priority filter ; policy accept ; }
"#;
    let _ = run_nft_script(bootstrap);
    // Rule: drop packets whose mark is in the intelligence isolated set.
    let rule_check = Command::new("nft")
        .args(["list", "chain", "inet", "connector_matrix", "intelligence_egress"])
        .output();
    let has_drop = rule_check
        .ok()
        .map(|o| {
            let s = String::from_utf8_lossy(&o.stdout);
            s.contains("intel_isolated") && s.contains("drop")
        })
        .unwrap_or(false);
    if !has_drop {
        run_nft(&[
            "add",
            "rule",
            "inet",
            "connector_matrix",
            "intelligence_egress",
            "meta",
            "mark",
            "@intel_isolated",
            "counter",
            "drop",
            "comment",
            "cdmi-intelligence-egress-cut",
        ])?;
    }
    Ok(())
}

fn apply_nft_intelligence_cut(agent_pid: &str, mark: u32, reason: &str) -> Result<HostEgressCutResult, String> {
    ensure_matrix_nft_tables()?;
    let mark_hex = format!("0x{mark:08x}");
    run_nft(&[
        "add",
        "element",
        "inet",
        "connector_matrix",
        "intel_isolated",
        &format!("{{ {mark_hex} }}"),
    ])?;
    tracing::warn!(
        agent_pid = %agent_pid,
        reason = %reason,
        mark = %mark_hex,
        table = "inet connector_matrix",
        set = "intel_isolated",
        "CDMI intelligence egress cut — nftables matrix table"
    );
    Ok(HostEgressCutResult {
        applied: true,
        backend: "nftables_matrix".into(),
        detail: format!(
            "table=inet connector_matrix set=intel_isolated mark={mark_hex} plane=intelligence_execution"
        ),
        intelligence_mark: mark_hex,
    })
}

fn clear_nft_intelligence_cut(agent_pid: &str, mark: u32) -> HostEgressCutResult {
    let mark_hex = format!("0x{mark:08x}");
    if !tool_ok("nft", &["--version"]) {
        return HostEgressCutResult {
            applied: false,
            backend: "none".into(),
            detail: "nft_missing".into(),
            intelligence_mark: mark_hex,
        };
    }
    let _ = run_nft(&[
        "delete",
        "element",
        "inet",
        "connector_matrix",
        "intel_isolated",
        &format!("{{ {mark_hex} }}"),
    ]);
    tracing::info!(
        agent_pid = %agent_pid,
        mark = %mark_hex,
        "CDMI intelligence egress cut cleared from matrix table"
    );
    HostEgressCutResult {
        applied: true,
        backend: "nftables_matrix".into(),
        detail: format!("deleted mark={mark_hex} from intel_isolated"),
        intelligence_mark: mark_hex,
    }
}

/// Prefer `iptables-nft` (nft-backend / "new iptables"), then legacy `iptables`.
fn iptables_bin() -> Option<&'static str> {
    if tool_ok("iptables-nft", &["--version"]) {
        Some("iptables-nft")
    } else if tool_ok("iptables", &["--version"]) {
        Some("iptables")
    } else {
        None
    }
}

fn apply_iptables_nft_fallback(
    agent_pid: &str,
    mark: u32,
    reason: &str,
    enforce: bool,
) -> Result<HostEgressCutResult, String> {
    let bin = iptables_bin().ok_or_else(|| "iptables-nft/iptables not available".to_string())?;
    let chain = std::env::var("CONNECTOR_MATRIX_IPTABLES_CHAIN")
        .unwrap_or_else(|_| "CONNECTOR_MATRIX_INTEL".into());
    let mark_hex = format!("0x{mark:08x}");
    let comment = format!("cdmi-intel:{agent_pid}");

    let _ = Command::new(bin)
        .args(["-N", &chain])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    let jumped = Command::new(bin)
        .args(["-C", "OUTPUT", "-j", &chain])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !jumped {
        let st = Command::new(bin)
            .args(["-I", "OUTPUT", "1", "-j", &chain])
            .status()
            .map_err(|e| format!("{bin} OUTPUT jump: {e}"))?;
        if !st.success() && enforce {
            return Err(format!("{bin} failed to install OUTPUT→{chain} jump"));
        }
    }

    let exists = Command::new(bin)
        .args([
            "-C",
            &chain,
            "-m",
            "mark",
            "--mark",
            &mark_hex,
            "-m",
            "comment",
            "--comment",
            &comment,
            "-j",
            "DROP",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !exists {
        let add = Command::new(bin)
            .args([
                "-A",
                &chain,
                "-m",
                "mark",
                "--mark",
                &mark_hex,
                "-m",
                "comment",
                "--comment",
                &comment,
                "-j",
                "DROP",
            ])
            .output()
            .map_err(|e| format!("{bin} add: {e}"))?;
        if !add.status.success() {
            let err = String::from_utf8_lossy(&add.stderr).to_string();
            if enforce {
                return Err(format!(
                    "matrix_intel_egress_failed ({bin}): {err}. \
                     Intelligence continuity break requires host cut under matrix HW enforce."
                ));
            }
            return Ok(HostEgressCutResult {
                applied: false,
                backend: bin.into(),
                detail: format!("rule_failed:{err}"),
                intelligence_mark: mark_hex,
            });
        }
    }
    tracing::warn!(
        agent_pid = %agent_pid,
        reason = %reason,
        bin = %bin,
        mark = %mark_hex,
        "CDMI intelligence egress cut — iptables-nft/modern fallback (mark DROP)"
    );
    Ok(HostEgressCutResult {
        applied: true,
        backend: format!("{bin}_intel"),
        detail: format!("chain={chain} mark={mark_hex} plane=intelligence_execution"),
        intelligence_mark: mark_hex,
    })
}

/// Cut host egress for an **intelligence** under matrix isolation.
///
/// Order: nftables matrix tables → iptables-nft → fail-closed (if enforce).
pub fn apply_matrix_host_egress_cut(agent_pid: &str, reason: &str) -> Result<HostEgressCutResult, String> {
    let enforce = enforce_host_cut();
    let mark = intelligence_egress_mark(agent_pid);
    let mark_hex = format!("0x{mark:08x}");

    // Best-effort eBPF map update when kerneld pins exist (defense in depth with nft).
    let _ = project_ebpf_deny_mark(agent_pid, mark, true);

    if tool_ok("nft", &["--version"]) {
        match apply_nft_intelligence_cut(agent_pid, mark, reason) {
            Ok(r) => return Ok(r),
            Err(e) => {
                tracing::warn!(
                    agent_pid = %agent_pid,
                    error = %e,
                    "nftables matrix cut failed — trying iptables-nft fallback"
                );
                if let Ok(r) = apply_iptables_nft_fallback(agent_pid, mark, reason, false) {
                    if r.applied {
                        return Ok(r);
                    }
                }
                if enforce {
                    return Err(format!(
                        "matrix_intel_egress_unavailable: nftables failed ({e}); \
                         install nftables (preferred) or iptables-nft for intelligence host cut"
                    ));
                }
                return Ok(HostEgressCutResult {
                    applied: false,
                    backend: "nftables_failed".into(),
                    detail: e,
                    intelligence_mark: mark_hex,
                });
            }
        }
    }

    if iptables_bin().is_some() {
        return apply_iptables_nft_fallback(agent_pid, mark, reason, enforce);
    }

    if enforce {
        return Err(
            "matrix_intel_egress_unavailable: need nftables (`nft`) or iptables-nft for \
             intelligence matrix host cut — this is not optional under HW enforce"
                .into(),
        );
    }

    Ok(HostEgressCutResult {
        applied: false,
        backend: "none".into(),
        detail: "no_nft_or_iptables_nft_lab_allow".into(),
        intelligence_mark: mark_hex,
    })
}

/// Clear intelligence host egress cut (restore matrix table membership).
pub fn clear_matrix_host_egress_cut(agent_pid: &str) -> HostEgressCutResult {
    let mark = intelligence_egress_mark(agent_pid);
    let mark_hex = format!("0x{mark:08x}");
    let _ = project_ebpf_deny_mark(agent_pid, mark, false);

    if tool_ok("nft", &["--version"]) {
        return clear_nft_intelligence_cut(agent_pid, mark);
    }

    if let Some(bin) = iptables_bin() {
        let chain = std::env::var("CONNECTOR_MATRIX_IPTABLES_CHAIN")
            .unwrap_or_else(|_| "CONNECTOR_MATRIX_INTEL".into());
        let comment = format!("cdmi-intel:{agent_pid}");
        let _ = Command::new(bin)
            .args([
                "-D",
                &chain,
                "-m",
                "mark",
                "--mark",
                &mark_hex,
                "-m",
                "comment",
                "--comment",
                &comment,
                "-j",
                "DROP",
            ])
            .status();
        return HostEgressCutResult {
            applied: true,
            backend: format!("{bin}_intel"),
            detail: format!("deleted mark={mark_hex}"),
            intelligence_mark: mark_hex,
        };
    }

    HostEgressCutResult {
        applied: false,
        backend: "none".into(),
        detail: "no_backend".into(),
        intelligence_mark: mark_hex,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intelligence_mark_is_stable_and_cdmi_prefixed() {
        let a = intelligence_egress_mark("agent_finance_1");
        let b = intelligence_egress_mark("agent_finance_1");
        let c = intelligence_egress_mark("agent_other");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a >> 24, 0xCD);
    }
}

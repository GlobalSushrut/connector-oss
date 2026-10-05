//! Phase 5.7.2 — Linux microVM egress: host TAP + **`iptables` / `ip6tables` FORWARD** allowlist (opt-in).
//!
//! Set **`CONNECTOR_MICROVM_EGRESS_ENFORCE=iptables`** (root / **`CAP_NET_ADMIN`**) with a non-empty
//! manifest allowlist and **`CONNECTOR_MICROVM_EGRESS_MODE`** ≠ **`deny_all`**. Resolves
//! **`network.outbound:`** caps to TCP destinations, creates a per-VM TAP, adds **`ip=`** kernel
//! boot args for IPv4, and inserts dedicated filter chains jumped from **`FORWARD`** for that TAP.
//!
//! **IPv6 TCP:** resolved **`AAAA`** targets get **`ip6tables`** rules; the guest receives a stable
//! ULA (`fd00:c0ff:ee99:<hash16>::2/64`) via **`connector.microvm_guest_ipv6`** on the kernel cmdline
//! and **`connector-vm-agent`** applies it with **`ip -6 addr add`** on **`eth0`**. The host TAP
//! gets the `::1` address on the same /64. **`ip -6 route get <first-v6-cap-dest>`** must succeed
//! (host needs a working IPv6 path to the allowlisted destinations).
//!
//! Rules are auto-removed when the Firecracker PID exits (best-effort watcher); receipt still
//! includes **`cleanup_hint`** for operator recovery after abrupt host termination.

#[cfg(target_os = "linux")]
use std::net::IpAddr;
#[cfg(target_os = "linux")]
use std::path::PathBuf;
#[cfg(target_os = "linux")]
use std::process::Command;
#[cfg(target_os = "linux")]
use std::thread;
#[cfg(target_os = "linux")]
use std::time::Duration;

use connector_microvm::NetworkIfaceConfig;

#[cfg(target_os = "linux")]
use crate::docker_egress;
use crate::error::PluginRuntimeError;

pub(crate) fn microvm_egress_enforce_iptables_requested() -> bool {
    #[cfg(target_os = "linux")]
    {
        let s = std::env::var("CONNECTOR_MICROVM_EGRESS_ENFORCE").unwrap_or_default();
        let s = s.trim();
        s.eq_ignore_ascii_case("iptables")
            || s.eq_ignore_ascii_case("iptables_forward")
            || s.eq_ignore_ascii_case("forward")
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

#[cfg(target_os = "linux")]
fn allow_resolver_dns_from_env() -> bool {
    let raw = std::env::var("CONNECTOR_MICROVM_ALLOW_RESOLVER_DNS")
        .or_else(|_| std::env::var("CONNECTOR_DOCKER_LAB_ALLOW_RESOLVER_DNS"))
        .unwrap_or_else(|_| "1".into());
    let s = raw.trim().to_ascii_lowercase();
    !matches!(s.as_str(), "0" | "off" | "false" | "no")
}

#[cfg(target_os = "linux")]
fn tap_name(vm_id: &str) -> String {
    let h = crate::microvm_backend::fxhash(vm_id);
    format!("fc{:012x}", h & 0x0000_ffff_ffff_ffffu64)
}

#[cfg(target_os = "linux")]
fn subnet_octet(vm_id: &str) -> u8 {
    let h = crate::microvm_backend::fxhash(vm_id);
    ((h % 200) + 20) as u8
}

#[cfg(target_os = "linux")]
fn ipt_chain(vm_id: &str) -> String {
    let h = crate::microvm_backend::fxhash(vm_id);
    format!("cvm{:08x}", (h as u32) ^ ((h >> 32) as u32))
}

#[cfg(target_os = "linux")]
fn ipt6_chain(vm_id: &str) -> String {
    let h = crate::microvm_backend::fxhash(vm_id);
    format!("c6m{:08x}", (h as u32) ^ ((h >> 32) as u32))
}

/// Per-VM ULA /64 on the TAP (`::1` host, `::2` guest), aligned with Docker-lab **`fd00:c0ff:ee99::`**
/// style addressing.
#[cfg(target_os = "linux")]
fn microvm_ula_guest_host(vm_id: &str) -> (std::net::Ipv6Addr, std::net::Ipv6Addr) {
    let h = crate::microvm_backend::fxhash(vm_id) as u32;
    let seg = (h & 0xffff) as u16;
    let gw = std::net::Ipv6Addr::new(0xfd00, 0xc0ff, 0xee99, seg, 0, 0, 0, 1);
    let guest = std::net::Ipv6Addr::new(0xfd00, 0xc0ff, 0xee99, seg, 0, 0, 0, 2);
    (guest, gw)
}

#[cfg(target_os = "linux")]
fn run_cmd(bin: &str, args: &[&str], ctx: &str) -> Result<(), PluginRuntimeError> {
    let s = Command::new(bin)
        .args(args)
        .status()
        .map_err(|e| PluginRuntimeError::Microvm(format!("{bin} {ctx}: {e}")))?;
    if !s.success() {
        return Err(PluginRuntimeError::Microvm(format!(
            "{bin} {ctx} failed (need root/CAP_NET_ADMIN?)"
        )));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn run_cmd_best_effort(bin: &str, args: &[String]) {
    let _ = Command::new(bin).args(args).status();
}

/// Start a background watcher that removes iptables/TAP state after Firecracker exits.
#[cfg(target_os = "linux")]
pub(crate) fn start_microvm_egress_cleanup_watcher(
    firecracker_pid: u32,
    detail: &serde_json::Value,
) -> serde_json::Value {
    let tap = detail
        .get("tap")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let chain = detail
        .get("iptables_chain")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let guest_ip = detail
        .get("guest_ipv4")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let wan_if = detail
        .get("wan_if")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let chain6 = detail
        .get("ip6tables_chain")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let guest_v6 = detail
        .get("guest_ipv6")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let wan_if_v6 = detail
        .get("wan_if_v6")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if tap.is_empty() || chain.is_empty() || guest_ip.is_empty() || wan_if.is_empty() {
        return serde_json::json!({
            "status": "skipped",
            "reason": "missing_cleanup_fields",
            "watched_pid": firecracker_pid
        });
    }
    thread::spawn(move || {
        let proc_path = PathBuf::from(format!("/proc/{firecracker_pid}"));
        while proc_path.exists() {
            thread::sleep(Duration::from_secs(2));
        }
        run_cmd_best_effort(
            "iptables",
            &vec![
                "-t".into(),
                "nat".into(),
                "-D".into(),
                "POSTROUTING".into(),
                "-s".into(),
                format!("{guest_ip}/32"),
                "-o".into(),
                wan_if.clone(),
                "-j".into(),
                "MASQUERADE".into(),
            ],
        );
        run_cmd_best_effort(
            "iptables",
            &vec![
                "-D".into(),
                "FORWARD".into(),
                "-i".into(),
                tap.clone(),
                "-j".into(),
                chain.clone(),
            ],
        );
        run_cmd_best_effort("iptables", &vec!["-F".into(), chain.clone()]);
        run_cmd_best_effort("iptables", &vec!["-X".into(), chain]);
        if !chain6.is_empty() && !guest_v6.is_empty() && !wan_if_v6.is_empty() {
            run_cmd_best_effort(
                "ip6tables",
                &vec![
                    "-t".into(),
                    "nat".into(),
                    "-D".into(),
                    "POSTROUTING".into(),
                    "-s".into(),
                    format!("{guest_v6}/128"),
                    "-o".into(),
                    wan_if_v6.clone(),
                    "-j".into(),
                    "MASQUERADE".into(),
                ],
            );
            run_cmd_best_effort(
                "ip6tables",
                &vec![
                    "-D".into(),
                    "FORWARD".into(),
                    "-i".into(),
                    tap.clone(),
                    "-j".into(),
                    chain6.clone(),
                ],
            );
            run_cmd_best_effort("ip6tables", &vec!["-F".into(), chain6.clone()]);
            run_cmd_best_effort("ip6tables", &vec!["-X".into(), chain6]);
        }
        run_cmd_best_effort("ip", &vec!["link".into(), "delete".into(), tap]);
    });
    serde_json::json!({
        "status": "armed",
        "mode": "pid_exit",
        "watched_pid": firecracker_pid
    })
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn start_microvm_egress_cleanup_watcher(
    _firecracker_pid: u32,
    _detail: &serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "status": "unsupported_os"
    })
}

#[cfg(target_os = "linux")]
fn default_route_out_if() -> Result<String, PluginRuntimeError> {
    let o = Command::new("ip")
        .args(["route", "get", "1.1.1.1"])
        .output()
        .map_err(|e| PluginRuntimeError::Microvm(format!("ip route get: {e}")))?;
    if !o.status.success() {
        return Err(PluginRuntimeError::Microvm(
            "ip route get 1.1.1.1 failed — cannot determine WAN interface for MASQUERADE".into(),
        ));
    }
    let s = String::from_utf8_lossy(&o.stdout);
    let Some(idx) = s.find(" dev ") else {
        return Err(PluginRuntimeError::Microvm(format!(
            "parse `ip route get` (no ' dev '): {}",
            s.trim()
        )));
    };
    let rest = s[idx + 5..].trim();
    let ifname = rest.split_whitespace().next().unwrap_or("").to_string();
    if ifname.is_empty() {
        return Err(PluginRuntimeError::Microvm("empty WAN ifname from `ip route get`".into()));
    }
    Ok(ifname)
}

#[cfg(target_os = "linux")]
fn ensure_ipv4_forwarding() -> Result<(), PluginRuntimeError> {
    let cur = Command::new("sysctl")
        .args(["-n", "net.ipv4.ip_forward"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    if cur == "1" {
        return Ok(());
    }
    let _ = run_cmd("sysctl", &["-w", "net.ipv4.ip_forward=1"], "enable ipv4 forwarding");
    let cur2 = Command::new("sysctl")
        .args(["-n", "net.ipv4.ip_forward"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    if cur2 != "1" {
        return Err(PluginRuntimeError::Microvm(
            "net.ipv4.ip_forward is not 1 — enable IP forwarding for microVM NAT (root)".into(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn ensure_ipv6_forwarding() -> Result<(), PluginRuntimeError> {
    for key in [
        "net.ipv6.conf.all.forwarding",
        "net.ipv6.conf.default.forwarding",
    ] {
        let w = format!("{key}=1");
        let _ = run_cmd("sysctl", &["-w", w.as_str()], "enable ipv6 forwarding");
    }
    let cur = Command::new("sysctl")
        .args(["-n", "net.ipv6.conf.all.forwarding"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    if cur != "1" {
        return Err(PluginRuntimeError::Microvm(
            "net.ipv6.conf.all.forwarding is not 1 — enable IPv6 forwarding for microVM egress (root)"
                .into(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn default_route_out_if_v6(probe: &std::net::Ipv6Addr) -> Result<String, PluginRuntimeError> {
    let probe_s = probe.to_string();
    let o = Command::new("ip")
        .args(["-6", "route", "get", &probe_s])
        .output()
        .map_err(|e| PluginRuntimeError::Microvm(format!("ip -6 route get: {e}")))?;
    if !o.status.success() {
        return Err(PluginRuntimeError::Microvm(format!(
            "ip -6 route get {probe_s} failed — the host needs a routable IPv6 path to allowlisted destinations for TCPv6 microVM egress"
        )));
    }
    let s = String::from_utf8_lossy(&o.stdout);
    let Some(idx) = s.find(" dev ") else {
        return Err(PluginRuntimeError::Microvm(format!(
            "parse `ip -6 route get` (no ' dev '): {}",
            s.trim()
        )));
    };
    let rest = s[idx + 5..].trim();
    let ifname = rest.split_whitespace().next().unwrap_or("").to_string();
    if ifname.is_empty() {
        return Err(PluginRuntimeError::Microvm(
            "empty WAN ifname from `ip -6 route get`".into(),
        ));
    }
    Ok(ifname)
}

/// Returns TAP network config, `ip=` kernel fragment (without leading space), and telemetry JSON.
#[cfg(target_os = "linux")]
pub(crate) async fn apply_microvm_tap_egress_linux(
    vm_id: &str,
    allowlist: &[String],
) -> Result<(NetworkIfaceConfig, String, serde_json::Value), PluginRuntimeError> {
    use std::net::Ipv6Addr;

    let tcp_dests = docker_egress::resolve_allowlist_tcp_dests(allowlist)
        .await
        .map_err(|e| PluginRuntimeError::Microvm(e.to_string()))?;
    let mut v4: Vec<(std::net::Ipv4Addr, u16)> = Vec::new();
    let mut v6: Vec<(Ipv6Addr, u16)> = Vec::new();
    for (a, p) in tcp_dests {
        match a {
            IpAddr::V4(v) => v4.push((v, p)),
            IpAddr::V6(v) => v6.push((v, p)),
        }
    }
    v4.sort_by(|a, b| a.0.to_bits().cmp(&b.0.to_bits()).then(a.1.cmp(&b.1)));
    v4.dedup();
    v6.sort_by(|a, b| a.0.octets().cmp(&b.0.octets()).then(a.1.cmp(&b.1)));
    v6.dedup();
    if v4.is_empty() && v6.is_empty() && !allowlist.is_empty() {
        return Err(PluginRuntimeError::Microvm(
            "egress enforce: no TCP destinations after DNS resolution".into(),
        ));
    }

    let tap = tap_name(vm_id);
    let chain = ipt_chain(vm_id);
    let chain6 = ipt6_chain(vm_id);
    let x = subnet_octet(vm_id);
    let guest_ip = format!("10.200.{x}.2");
    let gw_ip = format!("10.200.{x}.1");
    let ip_boot_arg = format!("ip={guest_ip}::{gw_ip}:255.255.255.0::eth0:off");
    let (guest_v6, gw_v6) = microvm_ula_guest_host(vm_id);
    let guest_v6_s = guest_v6.to_string();
    let gw_v6_s = gw_v6.to_string();

    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };
    let uid_s = uid.to_string();
    let gid_s = gid.to_string();

    let wan = default_route_out_if()?;
    let wan_v6 = if !v6.is_empty() {
        default_route_out_if_v6(&v6[0].0)?
    } else {
        String::new()
    };

    let _ = Command::new("iptables")
        .args([
            "-t",
            "nat",
            "-D",
            "POSTROUTING",
            "-s",
            &format!("{guest_ip}/32"),
            "-o",
            &wan,
            "-j",
            "MASQUERADE",
        ])
        .status();
    let _ = Command::new("iptables")
        .args(["-D", "FORWARD", "-i", &tap, "-j", &chain])
        .status();
    let _ = Command::new("iptables").args(["-F", &chain]).status();
    let _ = Command::new("iptables").args(["-X", &chain]).status();
    if !v6.is_empty() {
        let _ = Command::new("ip6tables")
            .args([
                "-t",
                "nat",
                "-D",
                "POSTROUTING",
                "-s",
                &format!("{guest_v6_s}/128"),
                "-o",
                &wan_v6,
                "-j",
                "MASQUERADE",
            ])
            .status();
        let _ = Command::new("ip6tables")
            .args(["-D", "FORWARD", "-i", &tap, "-j", &chain6])
            .status();
        let _ = Command::new("ip6tables").args(["-F", &chain6]).status();
        let _ = Command::new("ip6tables").args(["-X", &chain6]).status();
    }
    let _ = Command::new("ip").args(["link", "delete", &tap]).status();

    run_cmd(
        "ip",
        &[
            "tuntap",
            "add",
            "dev",
            &tap,
            "mode",
            "tap",
            "user",
            &uid_s,
            "group",
            &gid_s,
        ],
        "tuntap add",
    )?;
    run_cmd("ip", &["link", "set", "dev", &tap, "up"], "link up")?;
    run_cmd(
        "ip",
        &[
            "addr",
            "add",
            &format!("{gw_ip}/24"),
            "dev",
            &tap,
        ],
        "addr add gw",
    )?;

    if !v6.is_empty() {
        run_cmd(
            "ip",
            &[
                "-6",
                "addr",
                "add",
                &format!("{gw_v6_s}/64"),
                "dev",
                &tap,
            ],
            "addr add gw v6",
        )?;
    }

    ensure_ipv4_forwarding()?;
    if !v6.is_empty() {
        ensure_ipv6_forwarding()?;
    }

    run_cmd("iptables", &["-N", &chain], "new chain")?;

    run_cmd(
        "iptables",
        &[
            "-A",
            &chain,
            "-m",
            "conntrack",
            "--ctstate",
            "RELATED,ESTABLISHED",
            "-j",
            "ACCEPT",
        ],
        "chain established",
    )?;

    let dns4: Vec<_> = if allow_resolver_dns_from_env() {
        docker_egress::resolv_conf_nameservers()
            .into_iter()
            .filter(|a| a.is_ipv4())
            .collect()
    } else {
        vec![]
    };

    for ns in &dns4 {
        let d = ns.to_string();
        for proto in ["udp", "tcp"] {
            run_cmd(
                "iptables",
                &[
                    "-A",
                    &chain,
                    "-d",
                    &d,
                    "-p",
                    proto,
                    "--dport",
                    "53",
                    "-j",
                    "ACCEPT",
                ],
                "dns allow",
            )?;
        }
    }

    for (addr, port) in &v4 {
        let d = addr.to_string();
        let p = port.to_string();
        run_cmd(
            "iptables",
            &[
                "-A",
                &chain,
                "-d",
                &d,
                "-p",
                "tcp",
                "--dport",
                &p,
                "-j",
                "ACCEPT",
            ],
            "tcp allow",
        )?;
    }

    run_cmd("iptables", &["-A", &chain, "-j", "DROP"], "chain drop")?;

    run_cmd(
        "iptables",
        &[
            "-I",
            "FORWARD",
            "1",
            "-i",
            &tap,
            "-j",
            &chain,
        ],
        "jump forward",
    )?;

    run_cmd(
        "iptables",
        &[
            "-t",
            "nat",
            "-A",
            "POSTROUTING",
            "-s",
            &format!("{guest_ip}/32"),
            "-o",
            &wan,
            "-j",
            "MASQUERADE",
        ],
        "nat masquerade",
    )?;

    if !v6.is_empty() {
        run_cmd("ip6tables", &["-N", &chain6], "new ip6 chain")?;
        run_cmd(
            "ip6tables",
            &[
                "-A",
                &chain6,
                "-m",
                "conntrack",
                "--ctstate",
                "RELATED,ESTABLISHED",
                "-j",
                "ACCEPT",
            ],
            "ip6 chain established",
        )?;

        let dns6: Vec<_> = if allow_resolver_dns_from_env() {
            docker_egress::resolv_conf_nameservers()
                .into_iter()
                .filter(|a| a.is_ipv6())
                .collect()
        } else {
            vec![]
        };

        for ns in &dns6 {
            let d = ns.to_string();
            for proto in ["udp", "tcp"] {
                run_cmd(
                    "ip6tables",
                    &[
                        "-A",
                        &chain6,
                        "-d",
                        &d,
                        "-p",
                        proto,
                        "--dport",
                        "53",
                        "-j",
                        "ACCEPT",
                    ],
                    "dns6 allow",
                )?;
            }
        }

        for (addr, port) in &v6 {
            let d = addr.to_string();
            let p = port.to_string();
            run_cmd(
                "ip6tables",
                &[
                    "-A",
                    &chain6,
                    "-d",
                    &d,
                    "-p",
                    "tcp",
                    "--dport",
                    &p,
                    "-j",
                    "ACCEPT",
                ],
                "tcp6 allow",
            )?;
        }

        run_cmd(
            "ip6tables",
            &["-A", &chain6, "-j", "DROP"],
            "ip6 chain drop",
        )?;

        run_cmd(
            "ip6tables",
            &[
                "-I",
                "FORWARD",
                "1",
                "-i",
                &tap,
                "-j",
                &chain6,
            ],
            "jump forward v6",
        )?;

        run_cmd(
            "ip6tables",
            &[
                "-t",
                "nat",
                "-A",
                "POSTROUTING",
                "-s",
                &format!("{guest_v6_s}/128"),
                "-o",
                &wan_v6,
                "-j",
                "MASQUERADE",
            ],
            "nat6 masquerade",
        )?;
    }

    let mut cleanup = serde_json::json!({
        "iptables_forward_delete": ["iptables", "-D", "FORWARD", "-i", &tap, "-j", &chain],
        "iptables_chain_flush": ["iptables", "-F", &chain],
        "iptables_chain_delete": ["iptables", "-X", &chain],
        "nat_delete": ["iptables", "-t", "nat", "-D", "POSTROUTING", "-s", format!("{guest_ip}/32"), "-o", &wan, "-j", "MASQUERADE"],
        "tap_delete": ["ip", "link", "delete", &tap],
        "note": "Rules persist until removed; abrupt host exit may leave stale iptables / TAP."
    });
    if let Some(obj) = cleanup.as_object_mut() {
        if !v6.is_empty() {
            obj.insert(
                "ip6tables_forward_delete".into(),
                serde_json::json!(["ip6tables", "-D", "FORWARD", "-i", &tap, "-j", &chain6]),
            );
            obj.insert(
                "ip6tables_chain_flush".into(),
                serde_json::json!(["ip6tables", "-F", &chain6]),
            );
            obj.insert(
                "ip6tables_chain_delete".into(),
                serde_json::json!(["ip6tables", "-X", &chain6]),
            );
            obj.insert(
                "nat6_delete".into(),
                serde_json::json!(["ip6tables", "-t", "nat", "-D", "POSTROUTING", "-s", format!("{guest_v6_s}/128"), "-o", &wan_v6, "-j", "MASQUERADE"]),
            );
        }
    }

    let mut detail = serde_json::json!({
        "egress_enforce": "iptables_forward",
        "tap": &tap,
        "guest_ipv4": &guest_ip,
        "gw_ipv4": &gw_ip,
        "wan_if": &wan,
        "iptables_chain": &chain,
        "tcp_allow_v4": v4.iter().map(|(a,p)| format!("{}:{}", a, p)).collect::<Vec<_>>(),
        "resolver_dns_v4_allowed": dns4.iter().map(|a| a.to_string()).collect::<Vec<_>>(),
        "cleanup_hint": cleanup,
    });
    if let Some(obj) = detail.as_object_mut() {
        if !v6.is_empty() {
            obj.insert("guest_ipv6".into(), serde_json::json!(&guest_v6_s));
            obj.insert("gw_ipv6".into(), serde_json::json!(&gw_v6_s));
            obj.insert("wan_if_v6".into(), serde_json::json!(&wan_v6));
            obj.insert("ip6tables_chain".into(), serde_json::json!(&chain6));
            obj.insert(
                "tcp_allow_v6".into(),
                serde_json::json!(v6.iter().map(|(a,p)| format!("{}:{}", a, p)).collect::<Vec<_>>()),
            );
            obj.insert(
                "resolver_dns_v6_allowed".into(),
                serde_json::json!(
                    docker_egress::resolv_conf_nameservers()
                        .into_iter()
                        .filter(|a| a.is_ipv6())
                        .map(|a| a.to_string())
                        .collect::<Vec<_>>()
                ),
            );
            let mut extra: Vec<String> =
                vec![format!("connector.microvm_guest_ipv6={guest_v6_s}")];
            if let Ok(iface) = std::env::var("CONNECTOR_MICROVM_GUEST_IFACE") {
                let iface = iface.trim();
                if !iface.is_empty() {
                    extra.push(format!("connector.microvm_guest_iface={iface}"));
                }
            }
            obj.insert("extra_boot_args".into(), serde_json::json!(extra));
        }
    }

    Ok((
        NetworkIfaceConfig {
            iface_id: "eth0".into(),
            host_dev_name: tap,
        },
        ip_boot_arg,
        detail,
    ))
}

#[cfg(not(target_os = "linux"))]
pub(crate) async fn apply_microvm_tap_egress_linux(
    _vm_id: &str,
    _allowlist: &[String],
) -> Result<(NetworkIfaceConfig, String, serde_json::Value), PluginRuntimeError> {
    Err(PluginRuntimeError::Microvm(
        "CONNECTOR_MICROVM_EGRESS_ENFORCE=iptables is only supported on Linux hosts".into(),
    ))
}

//! Phase 5.7.2 — optional Linux **`iptables`** / **`ip6tables`** in **`DOCKER-USER`** for Docker lab
//! when **`CONNECTOR_DOCKER_LAB_EGRESS=allowlist_strict`** and the manifest allowlist is non-empty.
//!
//! Opt-in: **`CONNECTOR_DOCKER_LAB_EGRESS_ENFORCE=iptables`** (requires Linux, root or **`CAP_NET_ADMIN`**).
//! IPv4 and IPv6 destination addresses are supported; the lab bridge is created with an IPv6 ULA subnet when
//! any resolved cap maps to IPv6. **Foreground** runs hold rules until **`docker run`** exits; **detached**
//! runs use a background **`docker wait`** task.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Mutex, OnceLock};
#[cfg(target_os = "linux")]
use std::process::Command;

use crate::error::PluginRuntimeError;

pub(crate) const LAB_NETWORK: &str = "connector_plugin_lab";

const LAB_SUBNET: &str = "172.30.99.0/24";
const LAB_GATEWAY: &str = "172.30.99.1";
/// ULA subnet for **`connector_plugin_lab`** when IPv6 egress is required (`docker network create --ipv6`).
const LAB_IPV6_SUBNET: &str = "fd00:c0ff:ee99::/64";

pub(crate) fn egress_enforce_iptables_requested() -> bool {
    let s = std::env::var("CONNECTOR_DOCKER_LAB_EGRESS_ENFORCE").unwrap_or_default();
    let s = s.trim();
    s.eq_ignore_ascii_case("iptables")
        || s.eq_ignore_ascii_case("iptables_docker_user")
        || s.eq_ignore_ascii_case("docker_user")
}

pub(crate) fn allow_resolver_dns_from_env() -> bool {
    let raw =
        std::env::var("CONNECTOR_DOCKER_LAB_ALLOW_RESOLVER_DNS").unwrap_or_else(|_| "1".into());
    let s = raw.trim().to_ascii_lowercase();
    !matches!(s.as_str(), "0" | "off" | "false" | "no")
}

/// `network.outbound:host:port` — host is a hostname, IPv4 literal, or **`[IPv6]`** literal.
pub(crate) fn parse_outbound_host_port(cap: &str) -> Option<(String, u16)> {
    let rest = cap.strip_prefix("network.outbound:")?;
    if let Some(inner) = rest.strip_prefix('[') {
        let (addr_part, after) = inner.split_once("]:")?;
        let port: u16 = after.parse().ok()?;
        let host = addr_part.trim();
        if host.is_empty() {
            return None;
        }
        return Some((host.to_string(), port));
    }
    let (host, port_s) = rest.rsplit_once(':')?;
    let port: u16 = port_s.parse().ok()?;
    let host = host.trim();
    if host.is_empty() {
        return None;
    }
    Some((host.to_string(), port))
}

pub(crate) fn resolv_conf_nameservers() -> Vec<IpAddr> {
    let Ok(raw) = std::fs::read_to_string("/etc/resolv.conf") else {
        return vec![];
    };
    raw.lines()
        .filter_map(|line| {
            let line = line.split('#').next().unwrap_or("").trim();
            let mut it = line.split_whitespace();
            if it.next()? == "nameserver" {
                let ip_s = it.next()?;
                ip_s.parse().ok()
            } else {
                None
            }
        })
        .collect()
}

pub(crate) async fn resolve_allowlist_tcp_dests(
    allowlist: &[String],
) -> Result<Vec<(IpAddr, u16)>, PluginRuntimeError> {
    let mut out: Vec<(IpAddr, u16)> = Vec::new();
    for cap in allowlist {
        let Some((host, port)) = parse_outbound_host_port(cap) else {
            continue;
        };
        let addrs = tokio::net::lookup_host((host.as_str(), port))
            .await
            .map_err(|e| PluginRuntimeError::DockerLab(format!("egress dns {host}: {e}")))?;
        let mut resolved: Vec<IpAddr> = Vec::new();
        for sa in addrs {
            resolved.push(sa.ip());
        }
        resolved.sort();
        resolved.dedup();
        let pinned = pin_resolved_ips(&host, port, &resolved)?;
        for ip in pinned {
            out.push((ip, port));
        }
    }
    out.sort_by(|a, b| a.0.to_string().cmp(&b.0.to_string()).then(a.1.cmp(&b.1)));
    out.dedup();
    if out.is_empty() && !allowlist.is_empty() {
        return Err(PluginRuntimeError::DockerLab(
            "allowlist_strict: could not resolve any network.outbound destinations (check manifest caps)"
                .into(),
        ));
    }
    Ok(out)
}

fn pin_resolved_ips(host: &str, port: u16, resolved: &[IpAddr]) -> Result<Vec<IpAddr>, PluginRuntimeError> {
    static PINS: OnceLock<Mutex<BTreeMap<(String, u16), Vec<IpAddr>>>> = OnceLock::new();
    let map = PINS.get_or_init(|| Mutex::new(BTreeMap::new()));
    let mut g = map.lock().unwrap_or_else(|e| e.into_inner());
    let key = (host.to_ascii_lowercase(), port);
    match g.get(&key) {
        None => {
            g.insert(key, resolved.to_vec());
            Ok(resolved.to_vec())
        }
        Some(pin) => {
            let extra: Vec<_> = resolved.iter().filter(|ip| !pin.contains(ip)).cloned().collect();
            if !extra.is_empty() {
                return Err(PluginRuntimeError::DockerLab(format!(
                    "egress_dns_pin_mismatch host={host} port={port} extra={extra:?}"
                )));
            }
            Ok(pin.clone())
        }
    }
}

pub(crate) async fn ensure_lab_bridge_network(needs_ipv6: bool) -> Result<(), PluginRuntimeError> {
    let inspect = tokio::process::Command::new("docker")
        .args(["network", "inspect", LAB_NETWORK])
        .output()
        .await
        .map_err(|e| PluginRuntimeError::DockerLab(format!("docker network inspect: {e}")))?;
    if inspect.status.success() {
        if needs_ipv6 {
            let en = tokio::process::Command::new("docker")
                .args(["network", "inspect", "-f", "{{.EnableIPv6}}", LAB_NETWORK])
                .output()
                .await
                .map_err(|e| PluginRuntimeError::DockerLab(format!("docker network inspect: {e}")))?;
            if !en.status.success() {
                return Err(PluginRuntimeError::DockerLab(
                    "docker network inspect EnableIPv6 failed".into(),
                ));
            }
            let s = String::from_utf8_lossy(&en.stdout).trim().to_ascii_lowercase();
            if s != "true" {
                return Err(PluginRuntimeError::DockerLab(format!(
                    "Docker network {LAB_NETWORK} has IPv6 disabled; IPv6 egress needs `docker network rm {LAB_NETWORK}` once, then retry (network is recreated with --ipv6)."
                )));
            }
        }
        return Ok(());
    }
    let mut args: Vec<&str> = vec![
        "network",
        "create",
        "--driver",
        "bridge",
        "--subnet",
        LAB_SUBNET,
        "--gateway",
        LAB_GATEWAY,
    ];
    if needs_ipv6 {
        args.extend(["--ipv6", "--subnet", LAB_IPV6_SUBNET]);
    }
    args.push(LAB_NETWORK);
    let create = tokio::process::Command::new("docker")
        .args(&args)
        .output()
        .await
        .map_err(|e| PluginRuntimeError::DockerLab(format!("docker network create: {e}")))?;
    if create.status.success() {
        return Ok(());
    }
    let err = String::from_utf8_lossy(&create.stderr);
    if err.contains("already exists") {
        return Ok(());
    }
    Err(PluginRuntimeError::DockerLab(format!(
        "docker network create {LAB_NETWORK} failed: {err}"
    )))
}

pub(crate) fn random_lab_container_ipv4() -> Ipv4Addr {
    use std::time::{SystemTime, UNIX_EPOCH};
    let o = ((SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
        % 241)
        + 10) as u8;
    Ipv4Addr::new(172, 30, 99, o)
}

/// **`fd00:c0ff:ee99::{0x10..0xff}`** — retry **`docker run`** on address collision.
pub(crate) fn random_lab_container_ipv6() -> Ipv6Addr {
    use std::time::{SystemTime, UNIX_EPOCH};
    let o = ((SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
        % 239)
        + 16) as u16;
    Ipv6Addr::new(0xfd00, 0xc0ff, 0xee99, 0, 0, 0, 0, o)
}

#[cfg(target_os = "linux")]
pub(crate) struct EgressDockerUserGuard {
    iptables_delete: Vec<Vec<String>>,
    ip6tables_delete: Vec<Vec<String>>,
}

#[cfg(target_os = "linux")]
impl EgressDockerUserGuard {
    pub(crate) fn apply(
        container_ipv4: Option<&str>,
        container_ipv6: Option<&str>,
        tcp_dests: &[(IpAddr, u16)],
        dns_servers: &[IpAddr],
    ) -> Result<Self, PluginRuntimeError> {
        let mut iptables_delete: Vec<Vec<String>> = Vec::new();
        let mut ip6tables_delete: Vec<Vec<String>> = Vec::new();

        if let Some(c) = container_ipv4 {
            append_family_rules(
                Bin::Iptables,
                c,
                tcp_dests,
                dns_servers,
                true,
                &mut iptables_delete,
            )?;
        }
        if let Some(c) = container_ipv6 {
            append_family_rules(
                Bin::Ip6tables,
                c,
                tcp_dests,
                dns_servers,
                false,
                &mut ip6tables_delete,
            )?;
        }

        Ok(Self {
            iptables_delete,
            ip6tables_delete,
        })
    }
}

#[cfg(target_os = "linux")]
enum Bin {
    Iptables,
    Ip6tables,
}

#[cfg(target_os = "linux")]
fn append_family_rules(
    bin: Bin,
    container_ip: &str,
    tcp_dests: &[(IpAddr, u16)],
    dns_servers: &[IpAddr],
    want_v4: bool,
    delete_specs: &mut Vec<Vec<String>>,
) -> Result<(), PluginRuntimeError> {
    let bin_name = match bin {
        Bin::Iptables => "iptables",
        Bin::Ip6tables => "ip6tables",
    };
    run_nftable_bin(
        bin_name,
        &[
            "-I",
            "DOCKER-USER",
            "1",
            "-s",
            container_ip,
            "-j",
            "DROP",
        ],
        "insert DROP",
    )?;
    delete_specs.push(vec![
        "-D".into(),
        "DOCKER-USER".into(),
        "-s".into(),
        container_ip.into(),
        "-j".into(),
        "DROP".into(),
    ]);

    for ns in dns_servers {
        if ns.is_ipv4() != want_v4 {
            continue;
        }
        let d = ns.to_string();
        for proto in ["udp", "tcp"] {
            run_nftable_bin(
                bin_name,
                &[
                    "-I",
                    "DOCKER-USER",
                    "1",
                    "-s",
                    container_ip,
                    "-d",
                    &d,
                    "-p",
                    proto,
                    "--dport",
                    "53",
                    "-j",
                    "ACCEPT",
                ],
                "insert ACCEPT dns",
            )?;
            delete_specs.insert(
                0,
                vec![
                    "-D".into(),
                    "DOCKER-USER".into(),
                    "-s".into(),
                    container_ip.into(),
                    "-d".into(),
                    d.clone(),
                    "-p".into(),
                    proto.into(),
                    "--dport".into(),
                    "53".into(),
                    "-j".into(),
                    "ACCEPT".into(),
                ],
            );
        }
    }

    for (addr, port) in tcp_dests {
        if addr.is_ipv4() != want_v4 {
            continue;
        }
        let d = addr.to_string();
        let p = port.to_string();
        run_nftable_bin(
            bin_name,
            &[
                "-I",
                "DOCKER-USER",
                "1",
                "-s",
                container_ip,
                "-d",
                &d,
                "-p",
                "tcp",
                "--dport",
                &p,
                "-j",
                "ACCEPT",
            ],
            "insert ACCEPT tcp",
        )?;
        delete_specs.insert(
            0,
            vec![
                "-D".into(),
                "DOCKER-USER".into(),
                "-s".into(),
                container_ip.into(),
                "-d".into(),
                d,
                "-p".into(),
                "tcp".into(),
                "--dport".into(),
                p,
                "-j".into(),
                "ACCEPT".into(),
            ],
        );
    }

    Ok(())
}

#[cfg(target_os = "linux")]
impl Drop for EgressDockerUserGuard {
    fn drop(&mut self) {
        for spec in &self.iptables_delete {
            let _ = Command::new("iptables").args(spec).status();
        }
        for spec in &self.ip6tables_delete {
            let _ = Command::new("ip6tables").args(spec).status();
        }
    }
}

#[cfg(target_os = "linux")]
fn run_nftable_bin(bin: &str, args: &[&str], ctx: &str) -> Result<(), PluginRuntimeError> {
    let s = Command::new(bin)
        .args(args)
        .status()
        .map_err(|e| PluginRuntimeError::DockerLab(format!("{bin} {ctx}: {e}")))?;
    if !s.success() {
        return Err(PluginRuntimeError::DockerLab(format!(
            "{bin} {ctx} failed (need root/CAP_NET_ADMIN? is `{bin}` installed?)"
        )));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub(crate) struct EgressDockerUserGuard;

#[cfg(not(target_os = "linux"))]
impl EgressDockerUserGuard {
    pub(crate) fn apply(
        _container_ipv4: Option<&str>,
        _container_ipv6: Option<&str>,
        _tcp_dests: &[(IpAddr, u16)],
        _dns_servers: &[IpAddr],
    ) -> Result<Self, PluginRuntimeError> {
        Err(PluginRuntimeError::DockerLab(
            "CONNECTOR_DOCKER_LAB_EGRESS_ENFORCE=iptables is only supported on Linux hosts".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_outbound_caps() {
        assert_eq!(
            parse_outbound_host_port("network.outbound:api.example.com:443"),
            Some(("api.example.com".into(), 443))
        );
        assert_eq!(
            parse_outbound_host_port("network.outbound:198.51.100.7:443"),
            Some(("198.51.100.7".into(), 443))
        );
        assert_eq!(
            parse_outbound_host_port("network.outbound:[2001:db8::1]:443"),
            Some(("2001:db8::1".into(), 443))
        );
        assert_eq!(parse_outbound_host_port("network.outbound:*"), None);
        assert_eq!(parse_outbound_host_port("other:foo:443"), None);
    }
}

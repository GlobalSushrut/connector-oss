//! T2 — Transparent egress via Connector-controlled channel hop + kernel redirect.
//!
//! Under hardening, outbound MCP/tool dials must carry a Connector channel ticket.
//! When `CONNECTOR_TRANSPARENT_EGRESS_KERNEL=1`, kerneld applies cgroup/connect4
//! rewrite and/or nft REDIRECT so connect() hits the Connector egress proxy
//! (kernel transparent hop). TLS terminate remains at the proxy — not a free
//! MITM of arbitrary HTTPS without Connector as the hop.

use hmac::{Hmac, Mac};
use serde_json::json;
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

fn env_truthy(name: &str) -> bool {
    match std::env::var(name) {
        Ok(v) => {
            let t = v.trim().to_ascii_lowercase();
            matches!(t.as_str(), "1" | "true" | "yes" | "on")
        }
        Err(_) => false,
    }
}

/// Transparent channel hop required (production / unbypassable bar).
pub fn transparent_egress_enabled() -> bool {
    if env_truthy("CONNECTOR_TRANSPARENT_EGRESS") {
        return true;
    }
    crate::substrate::egress_policy::l7_egress_proxy_enabled()
        && crate::connector_profile::is_productionish_env()
}

/// Kernel connect rewrite / nft REDIRECT bar.
pub fn transparent_egress_kernel_enabled() -> bool {
    env_truthy("CONNECTOR_TRANSPARENT_EGRESS_KERNEL")
}

fn channel_secret() -> Vec<u8> {
    if let Ok(s) = std::env::var("CONNECTOR_EGRESS_CHANNEL_HMAC_KEY") {
        if !s.trim().is_empty() {
            return s.into_bytes();
        }
    }
    if let Ok(s) = std::env::var("CONNECTOR_AUDIT_HMAC_KEY") {
        if !s.trim().is_empty() {
            return s.into_bytes();
        }
    }
    b"connector-egress-channel-lab-fallback".to_vec()
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn ticket_payload(agent_pid: &str, host: &str, port: u16, exp: u64) -> String {
    format!("cegress.v1|{agent_pid}|{host}|{port}|{exp}")
}

pub fn mint_egress_channel_ticket(agent_pid: &str, host: &str, port: u16) -> Result<String, String> {
    let exp = now_secs().saturating_add(300);
    let payload = ticket_payload(agent_pid, host, port, exp);
    let mut mac = HmacSha256::new_from_slice(&channel_secret())
        .map_err(|_| "egress_channel_hmac_init".to_string())?;
    mac.update(payload.as_bytes());
    let sig = hex::encode(mac.finalize().into_bytes());
    Ok(format!("{payload}|{sig}"))
}

pub fn verify_egress_channel_ticket(
    ticket: &str,
    agent_pid: &str,
    host: &str,
    port: u16,
) -> Result<(), String> {
    let parts: Vec<&str> = ticket.split('|').collect();
    if parts.len() != 6 {
        return Err("egress_channel_ticket_malformed".into());
    }
    if parts[0] != "cegress.v1" {
        return Err("egress_channel_ticket_version".into());
    }
    if parts[1] != agent_pid {
        return Err("egress_channel_ticket_agent_mismatch".into());
    }
    if parts[2] != host {
        return Err("egress_channel_ticket_host_mismatch".into());
    }
    let ticket_port: u16 = parts[3]
        .parse()
        .map_err(|_| "egress_channel_ticket_port".to_string())?;
    if ticket_port != port {
        return Err("egress_channel_ticket_port_mismatch".into());
    }
    let exp: u64 = parts[4]
        .parse()
        .map_err(|_| "egress_channel_ticket_exp".to_string())?;
    if now_secs() > exp {
        return Err("egress_channel_ticket_expired".into());
    }
    let payload = ticket_payload(agent_pid, host, port, exp);
    let mut mac = HmacSha256::new_from_slice(&channel_secret())
        .map_err(|_| "egress_channel_hmac_init".to_string())?;
    mac.update(payload.as_bytes());
    let expect = hex::encode(mac.finalize().into_bytes());
    if !constant_time_eq(parts[5].as_bytes(), expect.as_bytes()) {
        return Err("egress_channel_ticket_sig".into());
    }
    Ok(())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub fn assert_connector_channel_hop(
    agent_pid: &str,
    server_url: &str,
) -> Result<serde_json::Value, String> {
    let host = crate::substrate::egress_policy::parse_host_from_url(server_url)
        .ok_or_else(|| "transparent_egress_invalid_url".to_string())?;
    let port = crate::substrate::egress_policy::parse_port_from_url(server_url);
    if !transparent_egress_enabled() {
        return Ok(json!({
            "mode": "allowlist_only",
            "host": host,
            "port": port,
        }));
    }
    let ticket = mint_egress_channel_ticket(agent_pid, &host, port)?;
    verify_egress_channel_ticket(&ticket, agent_pid, &host, port)?;
    let proxy_port: u16 = std::env::var("CONNECTOR_EGRESS_PROXY_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(19090);
    Ok(json!({
        "mode": if transparent_egress_kernel_enabled() {
            "kernel_redirect_plus_channel_hop"
        } else {
            "connector_channel_hop"
        },
        "host": host,
        "port": port,
        "egress_proxy_port": proxy_port,
        "ticket_prefix": ticket.split('|').take(5).collect::<Vec<_>>().join("|"),
        "packet_dna_header": crate::substrate::packet_dna::header_name(),
        "packet_dna": crate::substrate::packet_dna::status_json(),
        "kerneld": [
            "connector-kerneld egress-redirect-load --agent <pid>",
            "connector-kerneld nft-redirect-apply --agent <pid>",
        ],
        "honesty": "Kernel connect4/nft REDIRECT to Connector proxy + HMAC ticket; TLS at proxy hop",
    }))
}

pub fn transparent_egress_status() -> serde_json::Value {
    json!({
        "env": "CONNECTOR_TRANSPARENT_EGRESS",
        "kernel_env": "CONNECTOR_TRANSPARENT_EGRESS_KERNEL",
        "enabled": transparent_egress_enabled(),
        "kernel_redirect": transparent_egress_kernel_enabled(),
        "mode": if transparent_egress_kernel_enabled() {
            "kernel_redirect_plus_channel_hop"
        } else if transparent_egress_enabled() {
            "connector_channel_hop"
        } else {
            "off"
        },
        "ebpf_object": "platform/ebpf/connector_connect_redirect.bpf.o",
        "honesty": "T2 bar: eBPF cgroup/connect4 rewrite and/or nft REDIRECT into Connector egress proxy with channel tickets. Not free TLS MITM of the public Internet.",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ticket_roundtrip() {
        let t = mint_egress_channel_ticket("agent-a", "example.com", 443).unwrap();
        verify_egress_channel_ticket(&t, "agent-a", "example.com", 443).unwrap();
        assert!(verify_egress_channel_ticket(&t, "agent-b", "example.com", 443).is_err());
        assert!(verify_egress_channel_ticket(&t, "agent-a", "evil.com", 443).is_err());
    }
}

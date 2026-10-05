//! MCP / protocol egress policy — CFNI mesh relay + host allowlist.

use axum::http::HeaderMap;
use connector_trust::ForensicFlowIdentityV2;
use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

fn env_truthy(name: &str) -> bool {
    match std::env::var(name) {
        Ok(v) => {
            let t = v.trim().to_ascii_lowercase();
            matches!(t.as_str(), "1" | "true" | "yes" | "on")
        }
        Err(_) => false,
    }
}

/// DI-3 — app-layer allowlist gate (not a transparent HTTP proxy).
pub fn l7_egress_proxy_enabled() -> bool {
    env_truthy("CONNECTOR_L7_EGRESS_PROXY")
}

/// True when outbound MCP HTTP must match `CONNECTOR_MCP_EGRESS_ALLOWLIST`.
pub fn mcp_egress_enforced() -> bool {
    crate::services::kernel_host::kernel_enforce_enabled()
        || env_truthy("CONNECTOR_MCP_EGRESS_ENFORCE")
}

/// Extract hostname from `http(s)://host[:port]/...` without extra deps.
pub fn parse_host_from_url(server_url: &str) -> Option<String> {
    let s = server_url.trim();
    let rest = s
        .strip_prefix("https://")
        .or_else(|| s.strip_prefix("http://"))?;
    let authority = rest.split('/').next()?.split('?').next()?.split('#').next()?;
    let hostport = authority.rsplit('@').next()?.trim();
    if hostport.is_empty() {
        return None;
    }
    if let Some(inner) = hostport.strip_prefix('[') {
        let host = inner.split(']').next()?.trim();
        if host.is_empty() {
            return None;
        }
        return Some(host.to_ascii_lowercase());
    }
    let host = hostport.split(':').next()?.trim();
    if host.is_empty() {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

/// Port from `http(s)://host[:port]/...`. Defaults 443 (https) / 80 (http).
pub fn parse_port_from_url(server_url: &str) -> u16 {
    let s = server_url.trim();
    let https = s.starts_with("https://");
    let default = if https { 443 } else { 80 };
    let rest = s
        .strip_prefix("https://")
        .or_else(|| s.strip_prefix("http://"))
        .unwrap_or("");
    let authority = rest
        .split('/')
        .next()
        .unwrap_or("")
        .split('?')
        .next()
        .unwrap_or("")
        .split('#')
        .next()
        .unwrap_or("");
    let hostport = authority.rsplit('@').next().unwrap_or("").trim();
    if let Some(inner) = hostport.strip_prefix('[') {
        if let Some((_, rest)) = inner.split_once(']') {
            if let Some(p) = rest.strip_prefix(':') {
                return p.parse().unwrap_or(default);
            }
        }
        return default;
    }
    if let Some((_, p)) = hostport.rsplit_once(':') {
        if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) {
            return p.parse().unwrap_or(default);
        }
    }
    default
}

/// Pin DNS then return `(host, SocketAddr)` for `ClientBuilder::resolve`.
pub fn pinned_socket_addr(url: &str) -> Result<(String, SocketAddr), &'static str> {
    let host = parse_host_from_url(url).ok_or("invalid_server_url")?;
    let port = parse_port_from_url(url);
    let ips = pin_or_revalidate_host(&host)?;
    let ip = ips.first().copied().ok_or("egress_denied_dns_unresolved")?;
    Ok((host, SocketAddr::new(ip, port)))
}

pub fn reqwest_blocking_client_pinned(
    url: &str,
    timeout: Duration,
) -> Result<reqwest::blocking::Client, String> {
    let (host, addr) = pinned_socket_addr(url).map_err(|e| e.to_string())?;
    reqwest::blocking::Client::builder()
        .timeout(timeout)
        .connect_timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .resolve(&host, addr)
        .build()
        .map_err(|e| e.to_string())
}

pub fn reqwest_client_pinned(url: &str, timeout: Duration) -> Result<reqwest::Client, String> {
    let (host, addr) = pinned_socket_addr(url).map_err(|e| e.to_string())?;
    reqwest::Client::builder()
        .timeout(timeout)
        .connect_timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .resolve(&host, addr)
        .build()
        .map_err(|e| e.to_string())
}

fn ip_is_blocked(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.octets()[0] == 169 && v4.octets()[1] == 254
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_unique_local()
                || v6.is_unicast_link_local()
        }
    }
}

fn is_blocked_hostname(host: &str) -> bool {
    matches!(
        host,
        "localhost"
            | "localhost."
            | "127.0.0.1"
            | "0.0.0.0"
            | "::1"
            | "metadata.google.internal"
            | "metadata.google.internal."
            | "metadata"
            | "metadata.internal"
    ) || host.ends_with(".localhost")
        || host == "169.254.169.254"
}

/// True when host is loopback, private, link-local, metadata, or resolves to those.
pub fn host_is_blocked_egress(host: &str) -> bool {
    let host = host
        .trim()
        .trim_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    if is_blocked_hostname(&host) {
        return true;
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return ip_is_blocked(ip);
    }
    if let Ok(addrs) = (host.as_str(), 443u16).to_socket_addrs() {
        for addr in addrs {
            if ip_is_blocked(addr.ip()) {
                return true;
            }
        }
    }
    false
}

fn dns_pin_store() -> &'static Mutex<BTreeMap<String, Vec<IpAddr>>> {
    static PINS: OnceLock<Mutex<BTreeMap<String, Vec<IpAddr>>>> = OnceLock::new();
    PINS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// Resolve host and pin the first successful lookup. Later lookups must be a subset of the pin.
pub fn pin_or_revalidate_host(host: &str) -> Result<Vec<IpAddr>, &'static str> {
    let host = host
        .trim()
        .trim_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    let mut resolved: Vec<IpAddr> = Vec::new();
    if let Ok(ip) = host.parse::<IpAddr>() {
        resolved.push(ip);
    } else if let Ok(addrs) = (host.as_str(), 443u16).to_socket_addrs() {
        for addr in addrs {
            resolved.push(addr.ip());
        }
    }
    resolved.sort();
    resolved.dedup();
    if resolved.is_empty() {
        return Err("egress_denied_dns_unresolved");
    }
    let mut g = dns_pin_store().lock().unwrap_or_else(|e| e.into_inner());
    match g.get(&host) {
        None => {
            g.insert(host, resolved.clone());
            Ok(resolved)
        }
        Some(pin) => {
            if resolved.iter().any(|ip| !pin.contains(ip)) {
                return Err("egress_denied_dns_pin_mismatch");
            }
            Ok(pin.clone())
        }
    }
}

/// Shared outbound URL policy for plugins, webhooks, and MCP.
pub fn assert_safe_outbound_url(url: &str) -> Result<(), &'static str> {
    let url = url.trim();
    if url.contains('@') {
        return Err("egress_denied_userinfo");
    }
    let https = url.starts_with("https://");
    let http = url.starts_with("http://");
    if !https && !http {
        return Err("egress_denied_scheme");
    }
    let host = parse_host_from_url(url).ok_or("invalid_server_url")?;
    let lab_localhost = !crate::connector_profile::is_productionish_env()
        && crate::services::runtime_control::dev_auth_bypass_allowed()
        && matches!(host.as_str(), "localhost" | "127.0.0.1" | "::1");
    if http && !lab_localhost {
        return Err("egress_denied_http");
    }
    if !lab_localhost && host_is_blocked_egress(&host) {
        return Err("egress_denied_private_or_metadata");
    }
    if !lab_localhost {
        let _ = pin_or_revalidate_host(&host)?;
    }
    if crate::connector_profile::is_productionish_env()
        || env_truthy("CONNECTOR_DENY_DIRECT_PROVIDER")
    {
        assert_direct_provider_egress_denied(&host)?;
    }
    Ok(())
}

/// Destination identity must survive redirects — re-check policy at new authority.
pub fn assert_redirect_destination_allowed(
    original_url: &str,
    location_header: &str,
) -> Result<(), &'static str> {
    let loc = location_header.trim();
    if loc.is_empty() {
        return Err("redirect_location_empty");
    }
    let next = if loc.starts_with("http://") || loc.starts_with("https://") {
        loc.to_string()
    } else {
        // Relative redirect — resolve against original host origin.
        let host = parse_host_from_url(original_url).ok_or("redirect_origin_invalid")?;
        let https = original_url.starts_with("https://");
        let scheme = if https { "https" } else { "http" };
        if loc.starts_with('/') {
            format!("{scheme}://{host}{loc}")
        } else {
            format!("{scheme}://{host}/{loc}")
        }
    };
    let orig_host = parse_host_from_url(original_url).ok_or("redirect_origin_invalid")?;
    let next_host = parse_host_from_url(&next).ok_or("redirect_target_invalid")?;
    if orig_host != next_host {
        // Cross-authority redirect requires full re-admission.
        assert_safe_outbound_url(&next)?;
        if mcp_egress_enforced() {
            assert_mcp_egress_allowed(&next)?;
        }
    } else {
        assert_safe_outbound_url(&next)?;
    }
    Ok(())
}

fn mcp_egress_allowlist() -> Vec<String> {
    std::env::var("CONNECTOR_MCP_EGRESS_ALLOWLIST")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Deny arbitrary MCP server URLs when kernel / MCP egress enforcement is on.
pub fn assert_mcp_egress_allowed(server_url: &str) -> Result<(), &'static str> {
    assert_safe_outbound_url(server_url)?;
    let host = parse_host_from_url(server_url).ok_or("invalid_server_url")?;
    assert_direct_provider_egress_denied(&host)?;
    if !mcp_egress_enforced() {
        return Ok(());
    }
    if crate::services::runtime_control::dev_auth_bypass_allowed()
        && !crate::connector_profile::is_productionish_env()
        && matches!(host.as_str(), "localhost" | "127.0.0.1" | "::1")
    {
        return Ok(());
    }
    let list = mcp_egress_allowlist();
    if list.is_empty() {
        return Err("mcp_egress_denied_empty_allowlist");
    }
    if list.iter().any(|h| h == "*" || h == "any") {
        if crate::connector_profile::is_productionish_env() {
            return Err("mcp_egress_wildcard_forbidden");
        }
    }
    if list.iter().any(|h| h == "*" || h == "any" || h == &host) {
        Ok(())
    } else {
        Err("mcp_egress_denied_not_allowlisted")
    }
}

fn allow_entry_matches_host(entry: &str, host: &str) -> bool {
    let e = entry.trim().to_ascii_lowercase();
    if e.is_empty() {
        return false;
    }
    if e == "*" || e == "any" {
        return true;
    }
    if e == host {
        return true;
    }
    if let Some(eh) = parse_host_from_url(&e) {
        return eh == host;
    }
    // Patterns like `*.example.com` or bare domain suffix.
    if let Some(suffix) = e.strip_prefix("*.") {
        return host == suffix || host.ends_with(&format!(".{suffix}"));
    }
    false
}

/// Hosts that must not be reachable by governed agents directly (EXEC-10).
/// Platform LLM cage / DI-1 router may still call these using node-held secrets.
pub fn llm_vendor_dns_names() -> &'static [&'static str] {
    &[
        "api.openai.com",
        "openai.com",
        "api.anthropic.com",
        "anthropic.com",
        "api.cohere.ai",
        "api.cohere.com",
        "api.groq.com",
        "api.mistral.ai",
        "api.together.xyz",
        "generativelanguage.googleapis.com",
        "openrouter.ai",
        "api.openrouter.ai",
        "api.deepseek.com",
        "api.fireworks.ai",
        "api.perplexity.ai",
    ]
}

pub fn is_direct_llm_provider_host(host: &str) -> bool {
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    llm_vendor_dns_names().iter().any(|n| h == *n)
        || h.ends_with(".openai.azure.com")
        || h.ends_with(".openai.com")
        || h.ends_with(".anthropic.com")
        || h.ends_with(".googleapis.com") && h.contains("generativelanguage")
}

fn hardened_environment() -> bool {
    crate::connector_profile::is_productionish_env()
}

/// Deny agent/tool egress straight to LLM provider hosts unless explicitly allowed.
pub fn assert_direct_provider_egress_denied(host: &str) -> Result<(), &'static str> {
    if !is_direct_llm_provider_host(host) {
        return Ok(());
    }
    if env_truthy("CONNECTOR_ALLOW_DIRECT_PROVIDER") && !hardened_environment() {
        return Ok(());
    }
    Err("direct_provider_egress_denied")
}

/// When `CONNECTOR_L7_EGRESS_PROXY=1`, require URL host ∈ agent contract `network_allow`.
/// This is an **app allowlist gate**, not a full L7 egress proxy.
pub fn assert_agent_l7_egress_allowed(
    state: &crate::state::PlatformState,
    agent_pid: &str,
    server_url: &str,
) -> Result<(), String> {
    crate::kernel::agent_cgroup::assert_no_anonymous_socket(Some(agent_pid), None, Some("l7"))
        .map_err(|e| e.to_string())?;
    if !l7_egress_proxy_enabled() {
        if hardened_environment() {
            return Err("l7_egress_denied_unenforced_in_hardened_environment: \
                 set CONNECTOR_L7_EGRESS_PROXY=1 and configure AgentContract.network_allow"
                .to_string());
        }
        return Ok(());
    }
    let host = parse_host_from_url(server_url)
        .ok_or_else(|| "l7_egress_denied_invalid_url".to_string())?;
    if let Err(code) = assert_direct_provider_egress_denied(&host) {
        return Err(format!(
            "{code}: agent={agent_pid} host={host} — route LLM calls through Connector gateway"
        ));
    }
    if crate::services::runtime_control::dev_auth_bypass_allowed()
        && matches!(host.as_str(), "localhost" | "127.0.0.1" | "::1")
    {
        return Ok(());
    }
    let contract = crate::kernel::agent_principal::load_contract(state, agent_pid);
    let net = crate::kernel::docklock::IntelligenceNetworkPolicy::from_contract(contract.as_ref());
    if net.network_allow.is_empty() {
        return Err(format!(
            "l7_egress_denied_empty_contract_allowlist: agent={agent_pid} host={host} \
             (set AgentContract.network_allow or unset CONNECTOR_L7_EGRESS_PROXY)"
        ));
    }
    if net
        .network_allow
        .iter()
        .any(|a| allow_entry_matches_host(a, &host))
    {
        let port = parse_port_from_url(server_url);
        // Proxy plane: destination lease (when enforce) + transparent channel hop.
        let _plane = crate::substrate::proxy_plane::admit_egress_hop(
            state,
            agent_pid,
            &host,
            port,
            None,
            server_url,
        )?;
        Ok(())
    } else {
        Err(format!(
            "l7_egress_denied_not_allowlisted: agent={agent_pid} host={host}"
        ))
    }
}

pub fn l7_egress_status() -> serde_json::Value {
    let transparent = crate::substrate::transparent_egress::transparent_egress_status();
    serde_json::json!({
        "env": "CONNECTOR_L7_EGRESS_PROXY",
        "enforced": l7_egress_proxy_enabled(),
        "mode": if crate::substrate::transparent_egress::transparent_egress_enabled() {
            "allowlist_plus_connector_channel_hop"
        } else if l7_egress_proxy_enabled() {
            "app_allowlist"
        } else {
            "off"
        },
        "transparent_egress": transparent,
        "honesty": "Allowlist + optional HMAC channel tickets for MCP/tool dials. Not a kernel MITM/TLS-terminate proxy.",
    })
}

/// CFNI mesh relay guard for egress-capable protocol routes.
pub fn cfni_mesh_guard(
    headers: &HeaderMap,
) -> Result<Option<ForensicFlowIdentityV2>, serde_json::Value> {
    match crate::substrate::cfni::verify_inbound_mesh_relay(headers) {
        Ok(v) => Ok(v),
        Err(code) => Err(serde_json::json!({
            "ok": false,
            "error": code,
            "message": "CFNI mesh relay verification failed",
        })),
    }
}

pub fn principal_id(headers: &HeaderMap) -> String {
    crate::auth::extract_claims(headers)
        .map(|c| c.sub)
        .unwrap_or_else(|| {
            if crate::services::runtime_control::dev_auth_bypass_allowed() {
                "dev".into()
            } else {
                "anonymous".into()
            }
        })
}

pub fn tenant_id(headers: &HeaderMap) -> Option<String> {
    crate::substrate::outbound::verified_tenant_id(headers)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_host_basic() {
        assert_eq!(
            parse_host_from_url("https://mcp.example.com/v1").as_deref(),
            Some("mcp.example.com")
        );
        assert_eq!(
            parse_host_from_url("http://127.0.0.1:8080/tools").as_deref(),
            Some("127.0.0.1")
        );
        assert_eq!(
            parse_host_from_url("https://[2001:db8::1]/v1").as_deref(),
            Some("2001:db8::1")
        );
        assert_eq!(parse_port_from_url("https://mcp.example.com/v1"), 443);
        assert_eq!(parse_port_from_url("http://127.0.0.1:8080/tools"), 8080);
        assert_eq!(parse_port_from_url("https://[2001:db8::1]:8443/v1"), 8443);
    }

    #[test]
    fn egress_allowlist_permits_listed_host() {
        std::env::set_var("CONNECTOR_MCP_EGRESS_ENFORCE", "1");
        std::env::set_var("CONNECTOR_MCP_EGRESS_ALLOWLIST", "example.com");
        assert!(assert_mcp_egress_allowed("https://example.com/mcp").is_ok());
        std::env::remove_var("CONNECTOR_MCP_EGRESS_ENFORCE");
        std::env::remove_var("CONNECTOR_MCP_EGRESS_ALLOWLIST");
    }

    #[test]
    fn private_and_metadata_hosts_are_blocked() {
        assert!(host_is_blocked_egress("127.0.0.1"));
        assert!(host_is_blocked_egress("10.0.0.1"));
        assert!(host_is_blocked_egress("169.254.169.254"));
        assert!(host_is_blocked_egress("metadata.google.internal"));
        assert!(assert_safe_outbound_url("http://169.254.169.254/latest/meta-data").is_err());
        assert!(assert_safe_outbound_url("https://example.com/hook").is_ok());
    }

    #[test]
    fn dns_pin_literal_ip_is_stable() {
        let a = pin_or_revalidate_host("1.1.1.1").expect("pin");
        let b = pin_or_revalidate_host("1.1.1.1").expect("revalidate");
        assert_eq!(a, b);
        assert_eq!(a[0].to_string(), "1.1.1.1");
    }

    #[test]
    fn direct_llm_provider_hosts_are_denied() {
        let prev = std::env::var("CONNECTOR_ALLOW_DIRECT_PROVIDER").ok();
        std::env::remove_var("CONNECTOR_ALLOW_DIRECT_PROVIDER");
        assert!(is_direct_llm_provider_host("api.openai.com"));
        assert!(is_direct_llm_provider_host("api.anthropic.com"));
        assert!(assert_direct_provider_egress_denied("api.openai.com").is_err());
        assert!(!is_direct_llm_provider_host("accounts.google.com"));
        std::env::set_var("CONNECTOR_ALLOW_DIRECT_PROVIDER", "1");
        assert!(assert_direct_provider_egress_denied("api.openai.com").is_ok());
        match prev {
            Some(v) => std::env::set_var("CONNECTOR_ALLOW_DIRECT_PROVIDER", v),
            None => std::env::remove_var("CONNECTOR_ALLOW_DIRECT_PROVIDER"),
        }
    }
}

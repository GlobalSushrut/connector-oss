//! DNS Management API
//!
//! Provides endpoints for DNS operations.

use axum::{
    extract::{State, Query},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use chrono::Utc;

use crate::state::SharedState;
use super::V2Response;

/// Resolve domain using real DNS
pub async fn resolve_domain(
    State(_state): State<SharedState>,
    Query(params): Query<ResolveQuery>,
) -> impl IntoResponse {
    // Perform real DNS lookup
    let ips = resolve_hostname(&params.domain);
    
    let response = ResolveResponse {
        domain: params.domain.clone(),
        query_type: params.type_.unwrap_or_else(|| "A".to_string()),
        ips: ips.clone(),
        ttl: None,
        resolver: "system".to_string(),
        resolved_at: Utc::now().to_rfc3339(),
        count: ips.len() as u32,
    };
    
    V2Response::success(response)
}

/// Reverse DNS lookup via libc getnameinfo (NSS). Empty means no PTR.
pub async fn reverse_lookup(
    State(_state): State<SharedState>,
    Query(params): Query<LookupQuery>,
) -> impl IntoResponse {
    let domains = reverse_dns(&params.ip);
    let ptr = ptr_name(&params.ip);

    let response = LookupResponse {
        ip: params.ip.clone(),
        domains: domains.clone(),
        ptr_records: ptr.into_iter().collect(),
        ttl: None,
        resolved_at: Utc::now().to_rfc3339(),
    };

    V2Response::success(response)
}

/// List DNS records from engine store
pub async fn list_dns_records(
    State(state): State<SharedState>,
    Query(params): Query<ListRecordsQuery>,
) -> impl IntoResponse {
    // Get from engine store
    let records = {
        let engine_store = state.engine_store.lock().unwrap();
        engine_store.folder_get("dns_records", &params.zone.clone().unwrap_or_default())
            .ok()
            .flatten()
            .and_then(|v| serde_json::from_value::<Vec<DnsRecord>>(v).ok())
            .unwrap_or_default()
    };
    
    let total = records.len();
    let response = ListRecordsResponse {
        zone: params.zone.unwrap_or_else(|| "local".to_string()),
        records,
        total,
    };
    
    V2Response::success(response)
}

/// Check DNS propagation — UDP A query to each listed nameserver (or resolv.conf).
pub async fn check_propagation(
    State(_state): State<SharedState>,
    Query(params): Query<PropagationQuery>,
) -> impl IntoResponse {
    if params.domain.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            V2Response::<()>::error("dns_domain_required", "Query parameter domain is required."),
        )
            .into_response();
    }

    let nameservers = resolve_nameserver_list(&params.nameservers);
    if nameservers.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            V2Response::<()>::error_with_hint(
                "dns_nameservers_required",
                "No nameservers were provided and none were found in /etc/resolv.conf.",
                "Pass nameservers=8.8.8.8,1.1.1.1 or configure system resolvers.",
            ),
        )
            .into_response();
    }

    let domain = params.domain.clone();
    let expected = resolve_hostname(&domain);
    let mut results = Vec::new();
    for ns in nameservers {
        results.push(query_a_on_nameserver(&domain, &ns).await);
    }
    let fully_propagated = !expected.is_empty()
        && results.iter().all(|r| {
            r.propagated
                && expected.iter().all(|ip| r.ips.contains(ip))
                && r.ips.iter().all(|ip| expected.contains(ip))
        });

    V2Response::success(PropagationResponse {
        domain,
        expected_ips: expected,
        results,
        fully_propagated,
    })
    .into_response()
}

fn reverse_dns(ip: &str) -> Vec<String> {
    #[cfg(unix)]
    {
        reverse_dns_unix(ip)
    }
    #[cfg(not(unix))]
    {
        let _ = ip;
        Vec::new()
    }
}

#[cfg(unix)]
fn reverse_dns_unix(ip: &str) -> Vec<String> {
    use std::net::IpAddr;
    let Ok(addr) = ip.parse::<IpAddr>() else {
        return Vec::new();
    };
    let mut hostbuf = [0i8; 1025];
    let rc = match addr {
        IpAddr::V4(v4) => unsafe { getnameinfo_v4(v4, &mut hostbuf) },
        IpAddr::V6(v6) => unsafe { getnameinfo_v6(v6, &mut hostbuf) },
    };
    if rc != 0 {
        return Vec::new();
    }
    let name = unsafe { std::ffi::CStr::from_ptr(hostbuf.as_ptr()) }
        .to_string_lossy()
        .into_owned();
    if name.is_empty() {
        Vec::new()
    } else {
        vec![name]
    }
}

#[cfg(unix)]
unsafe fn getnameinfo_v4(v4: std::net::Ipv4Addr, hostbuf: &mut [i8]) -> i32 {
    let mut sa: libc::sockaddr_in = std::mem::zeroed();
    sa.sin_family = libc::AF_INET as libc::sa_family_t;
    sa.sin_port = 0;
    sa.sin_addr = libc::in_addr {
        s_addr: u32::from(v4).to_be(),
    };
    libc::getnameinfo(
        &sa as *const _ as *const libc::sockaddr,
        std::mem::size_of::<libc::sockaddr_in>() as u32,
        hostbuf.as_mut_ptr(),
        hostbuf.len() as u32,
        std::ptr::null_mut(),
        0,
        libc::NI_NAMEREQD,
    )
}

#[cfg(unix)]
unsafe fn getnameinfo_v6(v6: std::net::Ipv6Addr, hostbuf: &mut [i8]) -> i32 {
    let mut sa: libc::sockaddr_in6 = std::mem::zeroed();
    sa.sin6_family = libc::AF_INET6 as libc::sa_family_t;
    sa.sin6_port = 0;
    sa.sin6_addr = libc::in6_addr { s6_addr: v6.octets() };
    libc::getnameinfo(
        &sa as *const _ as *const libc::sockaddr,
        std::mem::size_of::<libc::sockaddr_in6>() as u32,
        hostbuf.as_mut_ptr(),
        hostbuf.len() as u32,
        std::ptr::null_mut(),
        0,
        libc::NI_NAMEREQD,
    )
}

fn ptr_name(ip: &str) -> Option<String> {
    use std::net::IpAddr;
    match ip.parse::<IpAddr>().ok()? {
        IpAddr::V4(v) => {
            let o = v.octets();
            Some(format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0]))
        }
        IpAddr::V6(v) => {
            let mut parts = Vec::with_capacity(32);
            for b in v.octets().iter().rev() {
                parts.push(format!("{:x}", b & 0x0f));
                parts.push(format!("{:x}", b >> 4));
            }
            Some(format!("{}.ip6.arpa", parts.join(".")))
        }
    }
}

fn resolve_nameserver_list(raw: &Option<String>) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(s) = raw {
        for part in s.split([',', ' ', ';']) {
            let p = part.trim();
            if !p.is_empty() {
                out.push(p.to_string());
            }
        }
    }
    if out.is_empty() {
        out.extend(resolv_conf_nameservers());
    }
    out
}

fn resolv_conf_nameservers() -> Vec<String> {
    let Ok(text) = std::fs::read_to_string("/etc/resolv.conf") else {
        return Vec::new();
    };
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            let rest = line.strip_prefix("nameserver ")?;
            let ns = rest.split_whitespace().next()?;
            Some(ns.to_string())
        })
        .collect()
}

async fn query_a_on_nameserver(domain: &str, nameserver: &str) -> PropagationResult {
    let start = std::time::Instant::now();
    match tokio::task::spawn_blocking({
        let domain = domain.to_string();
        let nameserver = nameserver.to_string();
        move || dns_query_a(&nameserver, &domain)
    })
    .await
    {
        Ok(Ok(ips)) => PropagationResult {
            domain: domain.to_string(),
            nameserver: nameserver.to_string(),
            propagated: !ips.is_empty(),
            ips,
            latency_ms: start.elapsed().as_millis() as u64,
            error: None,
        },
        Ok(Err(e)) => PropagationResult {
            domain: domain.to_string(),
            nameserver: nameserver.to_string(),
            propagated: false,
            ips: Vec::new(),
            latency_ms: start.elapsed().as_millis() as u64,
            error: Some(e),
        },
        Err(e) => PropagationResult {
            domain: domain.to_string(),
            nameserver: nameserver.to_string(),
            propagated: false,
            ips: Vec::new(),
            latency_ms: start.elapsed().as_millis() as u64,
            error: Some(format!("join: {e}")),
        },
    }
}

/// Minimal DNS A query over UDP/53. No invented latency.
fn dns_query_a(nameserver: &str, domain: &str) -> Result<Vec<String>, String> {
    use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
    use std::time::Duration;

    let candidate = if nameserver.contains(']') || nameserver.parse::<SocketAddr>().is_ok() {
        nameserver.to_string()
    } else if nameserver.contains(':') && !nameserver.starts_with('[') {
        format!("[{nameserver}]:53")
    } else {
        format!("{nameserver}:53")
    };
    let ns_addr: SocketAddr = candidate
        .to_socket_addrs()
        .map_err(|e| format!("nameserver {nameserver}: {e}"))?
        .next()
        .ok_or_else(|| format!("nameserver {nameserver}: no address"))?;

    let mut q = Vec::new();
    let id: u16 = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos()
        & 0xffff) as u16;
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
    q.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    q.extend_from_slice(&0u16.to_be_bytes());
    q.extend_from_slice(&0u16.to_be_bytes());
    q.extend_from_slice(&0u16.to_be_bytes());
    encode_qname(&mut q, domain);
    q.extend_from_slice(&1u16.to_be_bytes()); // A
    q.extend_from_slice(&1u16.to_be_bytes()); // IN

    let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("bind: {e}"))?;
    sock.set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(|e| format!("timeout: {e}"))?;
    sock.send_to(&q, ns_addr)
        .map_err(|e| format!("send {ns_addr}: {e}"))?;
    let mut buf = [0u8; 512];
    let (n, _) = sock
        .recv_from(&mut buf)
        .map_err(|e| format!("recv from {ns_addr}: {e}"))?;
    parse_a_answers(&buf[..n])
}

fn encode_qname(out: &mut Vec<u8>, name: &str) {
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() {
            continue;
        }
        let bytes = label.as_bytes();
        out.push(bytes.len() as u8);
        out.extend_from_slice(bytes);
    }
    out.push(0);
}

fn parse_a_answers(msg: &[u8]) -> Result<Vec<String>, String> {
    if msg.len() < 12 {
        return Err("DNS response shorter than header".into());
    }
    let flags = u16::from_be_bytes([msg[2], msg[3]]);
    let rcode = flags & 0x000f;
    if rcode != 0 {
        return Err(format!("DNS rcode {rcode}"));
    }
    let qd = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    let an = u16::from_be_bytes([msg[6], msg[7]]) as usize;
    let mut i = 12usize;
    for _ in 0..qd {
        i = skip_name(msg, i)?;
        i = i.checked_add(4).ok_or("truncated question")?;
        if i > msg.len() {
            return Err("truncated question".into());
        }
    }
    let mut ips = Vec::new();
    for _ in 0..an {
        i = skip_name(msg, i)?;
        if i + 10 > msg.len() {
            return Err("truncated answer".into());
        }
        let typ = u16::from_be_bytes([msg[i], msg[i + 1]]);
        let rdlen = u16::from_be_bytes([msg[i + 8], msg[i + 9]]) as usize;
        i += 10;
        if i + rdlen > msg.len() {
            return Err("truncated rdata".into());
        }
        if typ == 1 && rdlen == 4 {
            ips.push(format!("{}.{}.{}.{}", msg[i], msg[i + 1], msg[i + 2], msg[i + 3]));
        }
        i += rdlen;
    }
    Ok(ips)
}

fn skip_name(msg: &[u8], mut i: usize) -> Result<usize, String> {
    let mut jumps = 0;
    loop {
        if i >= msg.len() {
            return Err("truncated name".into());
        }
        let len = msg[i];
        if len == 0 {
            return Ok(i + 1);
        }
        if len & 0xc0 == 0xc0 {
            if i + 1 >= msg.len() {
                return Err("truncated pointer".into());
            }
            return Ok(i + 2);
        }
        if len & 0xc0 != 0 {
            return Err("invalid name length".into());
        }
        i = i
            .checked_add(1 + len as usize)
            .ok_or("name overflow")?;
        jumps += 1;
        if jumps > 128 {
            return Err("name too long".into());
        }
    }
}

// Helper functions for real DNS resolution
fn resolve_hostname(hostname: &str) -> Vec<String> {
    // Real DNS resolution using system resolver
    use std::net::ToSocketAddrs;
    
    let mut ips = Vec::new();
    if let Ok(addrs) = format!("{}:80", hostname).to_socket_addrs() {
        for addr in addrs {
            let ip = addr.ip().to_string();
            if !ips.contains(&ip) {
                ips.push(ip);
            }
        }
    }
    ips
}

// Types
#[derive(Debug, Clone, Deserialize)]
pub struct ResolveQuery {
    pub domain: String,
    #[serde(default)]
    type_: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResolveResponse {
    pub domain: String,
    pub query_type: String,
    pub ips: Vec<String>,
    pub ttl: Option<u32>,
    pub resolver: String,
    pub resolved_at: String,
    pub count: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LookupQuery {
    pub ip: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct LookupResponse {
    pub ip: String,
    pub domains: Vec<String>,
    pub ptr_records: Vec<String>,
    pub ttl: Option<u32>,
    pub resolved_at: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ListRecordsQuery {
    pub zone: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DnsRecord {
    pub name: String,
    pub type_: String,
    pub value: String,
    pub ttl: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct ListRecordsResponse {
    pub zone: String,
    pub records: Vec<DnsRecord>,
    pub total: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PropagationQuery {
    pub domain: String,
    /// Comma/space-separated nameserver IPs. Empty → /etc/resolv.conf.
    #[serde(default)]
    pub nameservers: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PropagationResult {
    pub domain: String,
    pub nameserver: String,
    pub propagated: bool,
    pub ips: Vec<String>,
    pub latency_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PropagationResponse {
    pub domain: String,
    pub expected_ips: Vec<String>,
    pub results: Vec<PropagationResult>,
    pub fully_propagated: bool,
}

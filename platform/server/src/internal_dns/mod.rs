//! Internal DNS — in-process service name → SocketAddr registry.
//!
//! Maps well-known service names to loopback ports so every subsystem
//! can call `DNS.resolve("connector-api")` instead of hard-coding ports.
//!
//! **Phase 1.4a — cage-internal DNS:** enabled first-party plugins register
//! `<slug>.<CONNECTOR_CAGE_TLD>` (default `cnktros`). [`resolve_cage_hostname`] answers only
//! from this table — never host `/etc/resolv.conf` or external resolvers for that suffix.
//!
//! In distributed mode the table is kept in sync via heartbeat gossip
//! piggy-backed onto the cell transport heartbeat (Phase R3).
//!
//! No external DNS server is used or required. This is purely in-process.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

// ── Well-known service names ────────────────────────────────────────────────

pub const SVC_API: &str = "connector-api";
pub const SVC_PROTOCOL_GATEWAY: &str = "connector-protocol-gw";
pub const SVC_UI_RPC: &str = "connector-ui-rpc";
pub const SVC_INTERNAL_BUS: &str = "connector-internal-bus";
pub const SVC_METRICS: &str = "connector-metrics";

// ── Types ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceRecord {
    /// Canonical service name, e.g. "connector-api"
    pub name: String,
    /// Bound address
    pub addr: SocketAddr,
    /// Optional human-readable description
    pub description: String,
    /// Tags for routing decisions (e.g. "public", "internal", "rpc")
    pub tags: Vec<String>,
    /// Health status
    pub healthy: bool,
    /// When registered
    #[serde(skip)]
    pub registered_at: Option<Instant>,
    /// Epoch-ms for serialisation
    pub registered_epoch_ms: u64,
    /// TTL — entries older than this are considered stale (0 = never expire)
    pub ttl_secs: u64,
}

impl ServiceRecord {
    pub fn new(name: &str, addr: SocketAddr, description: &str, tags: &[&str]) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        Self {
            name: name.to_string(),
            addr,
            description: description.to_string(),
            tags: tags.iter().map(|s| s.to_string()).collect(),
            healthy: true,
            registered_at: Some(Instant::now()),
            registered_epoch_ms: now,
            ttl_secs: 0,
        }
    }

    pub fn with_ttl(mut self, secs: u64) -> Self {
        self.ttl_secs = secs;
        self
    }

    pub fn is_stale(&self) -> bool {
        if self.ttl_secs == 0 { return false; }
        match self.registered_at {
            Some(t) => t.elapsed() > Duration::from_secs(self.ttl_secs),
            None => false,
        }
    }
}

// ── Registry ────────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct InternalDns {
    table: RwLock<HashMap<String, ServiceRecord>>,
}

impl InternalDns {
    pub fn new() -> Self {
        Self { table: RwLock::new(HashMap::new()) }
    }

    /// Register or overwrite a service entry.
    pub fn register(&self, record: ServiceRecord) {
        let name = record.name.clone();
        if let Ok(mut t) = self.table.write() {
            t.insert(name, record);
        }
    }

    /// Register with a shorthand.
    pub fn bind(&self, name: &str, addr: SocketAddr, description: &str, tags: &[&str]) {
        self.register(ServiceRecord::new(name, addr, description, tags));
    }

    /// Resolve a service name to its SocketAddr.
    /// Returns `None` if the service is unknown, unhealthy, or stale.
    pub fn resolve(&self, name: &str) -> Option<SocketAddr> {
        let t = self.table.read().ok()?;
        let rec = t.get(name)?;
        if !rec.healthy || rec.is_stale() { return None; }
        Some(rec.addr)
    }

    /// Resolve ignoring health/staleness (for diagnostics).
    pub fn resolve_any(&self, name: &str) -> Option<SocketAddr> {
        let t = self.table.read().ok()?;
        t.get(name).map(|r| r.addr)
    }

    /// Mark a service as unhealthy (routing will skip it).
    pub fn mark_unhealthy(&self, name: &str) {
        if let Ok(mut t) = self.table.write() {
            if let Some(rec) = t.get_mut(name) {
                rec.healthy = false;
            }
        }
    }

    /// Mark a service as healthy again.
    pub fn mark_healthy(&self, name: &str) {
        if let Ok(mut t) = self.table.write() {
            if let Some(rec) = t.get_mut(name) {
                rec.healthy = true;
            }
        }
    }

    /// Dump all entries — used by the /api/v1/internal/dns debug endpoint.
    pub fn dump(&self) -> Vec<ServiceRecord> {
        match self.table.read() {
            Ok(t) => t.values().cloned().collect(),
            Err(_) => vec![],
        }
    }

    /// Remove stale entries (call periodically).
    pub fn gc(&self) {
        if let Ok(mut t) = self.table.write() {
            t.retain(|_, v| !v.is_stale());
        }
    }

    /// Drop a name from the registry (e.g. plugin `DISABLED` / `UNINSTALLED`).
    pub fn remove(&self, name: &str) {
        if let Ok(mut t) = self.table.write() {
            t.remove(name);
        }
    }
}

// ── Global singleton ─────────────────────────────────────────────────────────

use std::sync::OnceLock;
static GLOBAL_DNS: OnceLock<Arc<InternalDns>> = OnceLock::new();

/// Get or initialise the global InternalDns registry.
pub fn global() -> Arc<InternalDns> {
    GLOBAL_DNS.get_or_init(|| Arc::new(InternalDns::new())).clone()
}

/// Convenience — register a service in the global registry.
pub fn register(name: &str, addr: SocketAddr, description: &str, tags: &[&str]) {
    global().bind(name, addr, description, tags);
}

/// Convenience — resolve a name in the global registry.
pub fn resolve(name: &str) -> Option<SocketAddr> {
    global().resolve(name)
}

/// Remove a service from the global registry.
pub fn deregister(name: &str) {
    global().remove(name);
}

// ── Cage TLD + plugin hostnames (Phase 1.4a) ─────────────────────────────────

fn sanitize_cage_tld(raw: &str) -> String {
    let lower = raw.trim().to_ascii_lowercase();
    let s: String = lower
        .chars()
        .filter(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '-')
        .take(63)
        .collect();
    if s.is_empty() {
        "cnktros".to_string()
    } else {
        s
    }
}

/// Effective cage DNS label (no leading dot), from `CONNECTOR_CAGE_TLD` or default `cnktros`.
pub fn cage_tld() -> String {
    sanitize_cage_tld(
        &std::env::var("CONNECTOR_CAGE_TLD").unwrap_or_else(|_| "cnktros".to_string()),
    )
}

/// Stable cage hostname for a plugin slug (CLS/CNP should key off this, not raw `localhost:port`).
pub fn plugin_cage_hostname(slug: &str) -> String {
    format!("{}.{}", slug.trim().to_ascii_lowercase(), cage_tld())
}

/// Alias for roadmap wording (“cage routing key”).
#[inline]
pub fn cage_routing_key(slug: &str) -> String {
    plugin_cage_hostname(slug)
}

/// True if `host` is a cage-scoped name for the configured TLD (suffix `.<cage_tld>`, ASCII folded).
pub fn is_cage_host(host: &str) -> bool {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    let suf = format!(".{}", cage_tld());
    host.contains('.') && host.ends_with(&suf)
}

/// Resolve `<slug>.<cage_tld>` using **only** the in-process table (no OS resolver, no UDP/53).
pub fn resolve_cage_hostname(host: &str) -> Option<SocketAddr> {
    let key = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if !is_cage_host(&key) {
        return None;
    }
    resolve(&key)
}

fn socket_from_http_base(base: &str) -> Option<SocketAddr> {
    let u = reqwest::Url::parse(base.trim()).ok()?;
    let host = u.host_str()?;
    let port = u.port_or_known_default()?;
    let ip: IpAddr = if host.eq_ignore_ascii_case("localhost") {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    } else {
        host.parse().ok()?
    };
    Some(SocketAddr::new(ip, port))
}

fn plugin_upstream_socket(slug: &str, main_api: SocketAddr) -> SocketAddr {
    match slug {
        "tracetramp" => {
            let base = std::env::var("CONNECTOR_TRACETRAMP_MANAGEMENT_URL")
                .or_else(|_| std::env::var("TRACETRAMP_MANAGEMENT_URL"))
                .unwrap_or_default();
            let base = base.trim();
            if base.is_empty() {
                socket_from_http_base("http://127.0.0.1:19742").unwrap_or(main_api)
            } else {
                socket_from_http_base(base).unwrap_or(main_api)
            }
        }
        "witnessctl" => {
            let base = std::env::var("CONNECTOR_WITNESSCTL_MANAGEMENT_URL")
                .or_else(|_| std::env::var("WITNESSCTL_MANAGEMENT_URL"))
                .unwrap_or_default();
            let base = base.trim();
            if base.is_empty() {
                socket_from_http_base("http://127.0.0.1:7443").unwrap_or(main_api)
            } else {
                socket_from_http_base(base).unwrap_or(main_api)
            }
        }
        "devguard" => {
            let base = std::env::var("CONNECTOR_DEVGUARD_MANAGEMENT_URL")
                .or_else(|_| std::env::var("DEVGUARD_MANAGEMENT_URL"))
                .unwrap_or_default();
            let base = base.trim();
            if base.is_empty() {
                main_api
            } else {
                socket_from_http_base(base).unwrap_or(main_api)
            }
        }
        _ => main_api,
    }
}

/// Register cage DNS names for enabled first-party plugins; remove names for disabled ones.
/// Call after [`register`](register) for `SVC_API` so `main_api` matches the REST listener.
pub fn sync_plugin_cage_dns_records(main_api: SocketAddr) {
    use crate::services::plugin_matrix;
    for slug in plugin_matrix::KNOWN_PLUGINS {
        deregister(&plugin_cage_hostname(slug));
    }
    for slug in plugin_matrix::enabled_plugin_ids().iter() {
        let name = plugin_cage_hostname(slug);
        let addr = plugin_upstream_socket(slug.as_str(), main_api);
        register(
            &name,
            addr,
            &format!("Cage host for plugin {slug} (internal DNS)"),
            &["cage", "plugin", slug.as_str()],
        );
    }
}

// ── JSON response shape (for the debug API endpoint) ─────────────────────────

#[derive(Debug, Serialize)]
pub struct DnsEntry {
    pub name: String,
    pub addr: String,
    pub description: String,
    pub tags: Vec<String>,
    pub healthy: bool,
    pub stale: bool,
    pub registered_epoch_ms: u64,
}

pub fn dump_json() -> Vec<DnsEntry> {
    global().dump().into_iter().map(|r| DnsEntry {
        addr: r.addr.to_string(),
        stale: r.is_stale(),
        name: r.name,
        description: r.description,
        tags: r.tags,
        healthy: r.healthy,
        registered_epoch_ms: r.registered_epoch_ms,
    }).collect()
}

// ── GC background task ────────────────────────────────────────────────────────

/// Spawn a background tokio task that runs GC on the global DNS every `interval`.
pub fn spawn_gc(interval: Duration) {
    let dns = global();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            dns.gc();
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cage_tld_and_hostname() {
        std::env::remove_var("CONNECTOR_CAGE_TLD");
        assert_eq!(cage_tld(), "cnktros");
        std::env::set_var("CONNECTOR_CAGE_TLD", "  Acme-99  ");
        assert_eq!(cage_tld(), "acme-99");
        assert_eq!(plugin_cage_hostname("tracetramp"), "tracetramp.acme-99");
        std::env::remove_var("CONNECTOR_CAGE_TLD");
    }
}

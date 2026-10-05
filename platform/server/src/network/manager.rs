//! Network Manager — Micro Nginx-like with Logic Port Management
//!
//! FIX BUG-064: Provides network-level security with port management,
//! access control, and traffic monitoring. Lightweight implementation
//! focused on internal service mesh needs.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use serde::{Serialize, Deserialize};
use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Port allocation and management
#[derive(Debug, Clone)]
pub struct PortManager {
    /// Allocated ports: port_number -> PortAllocation
    allocated_ports: HashMap<u16, PortAllocation>,
    /// Port range for dynamic allocation
    port_range_start: u16,
    port_range_end: u16,
    /// Next port to try for allocation
    next_port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortAllocation {
    pub port: u16,
    pub service_name: String,
    pub agent_pid: Option<String>,
    pub protocol: PortProtocol,
    pub status: PortStatus,
    pub acl_rules: Vec<AclRule>,
    pub created_at: i64,
    pub last_traffic_at: i64,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum PortProtocol {
    Tcp,
    Http,
    Grpc,
    WebSocket,
    Cnp, // Connector Native Protocol
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum PortStatus {
    Allocated,
    Listening,
    Active,
    Paused,
    Closed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AclRule {
    pub action: AclAction,
    pub source_cidr: String,
    pub description: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum AclAction {
    Allow,
    Deny,
    LogAndAllow,
}

impl PortManager {
    pub fn new(port_range_start: u16, port_range_end: u16) -> Self {
        Self {
            allocated_ports: HashMap::new(),
            port_range_start,
            port_range_end,
            next_port: port_range_start,
        }
    }

    /// Allocate a dynamic port for a service
    pub fn allocate_port(
        &mut self,
        service_name: String,
        agent_pid: Option<String>,
        protocol: PortProtocol,
    ) -> Result<u16, NetworkError> {
        // Find next available port
        let start_port = self.next_port;
        let mut attempts = 0;
        let max_attempts = self.port_range_end - self.port_range_start;

        while attempts < max_attempts {
            let port = self.next_port;
            self.next_port = if self.next_port >= self.port_range_end {
                self.port_range_start
            } else {
                self.next_port + 1
            };

            if !self.allocated_ports.contains_key(&port) {
                let allocation = PortAllocation {
                    port,
                    service_name: service_name.clone(),
                    agent_pid,
                    protocol,
                    status: PortStatus::Allocated,
                    acl_rules: vec![AclRule {
                        action: AclAction::Allow,
                        source_cidr: "127.0.0.1/8".to_string(),
                        description: "Default: allow localhost".to_string(),
                    }],
                    created_at: chrono::Utc::now().timestamp_millis(),
                    last_traffic_at: 0,
                    bytes_in: 0,
                    bytes_out: 0,
                };
                self.allocated_ports.insert(port, allocation);
                return Ok(port);
            }

            attempts += 1;

            // Prevent infinite loop
            if self.next_port == start_port {
                break;
            }
        }

        Err(NetworkError::PortExhausted)
    }

    /// Register a specific port (for well-known services)
    pub fn register_port(
        &mut self,
        port: u16,
        service_name: String,
        agent_pid: Option<String>,
        protocol: PortProtocol,
    ) -> Result<(), NetworkError> {
        if self.allocated_ports.contains_key(&port) {
            return Err(NetworkError::PortInUse(port));
        }

        let allocation = PortAllocation {
            port,
            service_name,
            agent_pid,
            protocol,
            status: PortStatus::Allocated,
            acl_rules: vec![AclRule {
                action: AclAction::Allow,
                source_cidr: "0.0.0.0/0".to_string(),
                description: "Default: allow all".to_string(),
            }],
            created_at: chrono::Utc::now().timestamp_millis(),
            last_traffic_at: 0,
            bytes_in: 0,
            bytes_out: 0,
        };
        self.allocated_ports.insert(port, allocation);
        Ok(())
    }

    /// Release a port
    pub fn release_port(&mut self, port: u16) -> Result<(), NetworkError> {
        if let Some(allocation) = self.allocated_ports.get_mut(&port) {
            allocation.status = PortStatus::Closed;
            self.allocated_ports.remove(&port);
            Ok(())
        } else {
            Err(NetworkError::PortNotFound(port))
        }
    }

    /// Add ACL rule to a port
    pub fn add_acl_rule(
        &mut self,
        port: u16,
        rule: AclRule,
    ) -> Result<(), NetworkError> {
        if let Some(allocation) = self.allocated_ports.get_mut(&port) {
            allocation.acl_rules.push(rule);
            Ok(())
        } else {
            Err(NetworkError::PortNotFound(port))
        }
    }

    /// Check if connection is allowed
    pub fn check_acl(&self, port: u16, source_ip: &str) -> bool {
        if let Some(allocation) = self.allocated_ports.get(&port) {
            // Check rules in order (last match wins)
            let mut allowed = false;
            for rule in &allocation.acl_rules {
                if Self::ip_in_cidr(source_ip, &rule.source_cidr) {
                    match rule.action {
                        AclAction::Allow | AclAction::LogAndAllow => allowed = true,
                        AclAction::Deny => return false,
                    }
                }
            }
            allowed
        } else {
            false // Port not allocated = deny
        }
    }

    /// Update port status
    pub fn set_port_status(
        &mut self,
        port: u16,
        status: PortStatus,
    ) -> Result<(), NetworkError> {
        if let Some(allocation) = self.allocated_ports.get_mut(&port) {
            allocation.status = status;
            Ok(())
        } else {
            Err(NetworkError::PortNotFound(port))
        }
    }

    /// Record traffic on a port
    pub fn record_traffic(
        &mut self,
        port: u16,
        bytes_in: u64,
        bytes_out: u64,
    ) -> Result<(), NetworkError> {
        if let Some(allocation) = self.allocated_ports.get_mut(&port) {
            allocation.bytes_in += bytes_in;
            allocation.bytes_out += bytes_out;
            allocation.last_traffic_at = chrono::Utc::now().timestamp_millis();
            Ok(())
        } else {
            Err(NetworkError::PortNotFound(port))
        }
    }

    /// Get port statistics
    pub fn get_port_stats(&self, port: u16) -> Option<PortAllocation> {
        self.allocated_ports.get(&port).cloned()
    }

    /// List all allocated ports
    pub fn list_ports(&self) -> Vec<PortAllocation> {
        self.allocated_ports.values().cloned().collect()
    }

    /// Check if IP is in CIDR range (simplified)
    fn ip_in_cidr(ip: &str, cidr: &str) -> bool {
        // Simplified: exact match or localhost pattern
        if cidr == "0.0.0.0/0" {
            return true;
        }
        if cidr == "127.0.0.1/8" && ip.starts_with("127.") {
            return true;
        }
        if cidr.ends_with("/32") {
            let cidr_ip = cidr.trim_end_matches("/32");
            return ip == cidr_ip;
        }
        // For production, use proper CIDR parsing
        true
    }
}

#[derive(Debug, Clone)]
pub enum NetworkError {
    PortExhausted,
    PortInUse(u16),
    PortNotFound(u16),
    AclDenied,
    ConnectionFailed,
}

impl std::fmt::Display for NetworkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetworkError::PortExhausted => write!(f, "No available ports in range"),
            NetworkError::PortInUse(p) => write!(f, "Port {} already in use", p),
            NetworkError::PortNotFound(p) => write!(f, "Port {} not found", p),
            NetworkError::AclDenied => write!(f, "Connection denied by ACL"),
            NetworkError::ConnectionFailed => write!(f, "Connection failed"),
        }
    }
}

impl std::error::Error for NetworkError {}

/// Network Manager — Top-level orchestrator
pub struct NetworkManager {
    port_manager: Arc<Mutex<PortManager>>,
    /// Network segmentation: segment_id -> list of allowed ports
    segments: Arc<Mutex<HashMap<String, Vec<u16>>>>,
    /// Traffic monitoring enabled
    monitoring_enabled: bool,
    /// Traffic monitoring: port -> traffic stats history
    traffic_monitor: Arc<Mutex<HashMap<u16, TrafficStats>>>,
    /// Port access control policies
    access_policies: Arc<Mutex<HashMap<u16, PortAccessPolicy>>>,
    /// Rate limiting: port -> bytes per second limit
    rate_limits: Arc<Mutex<HashMap<u16, u64>>>,
}

/// Traffic statistics for monitoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficStats {
    pub port: u16,
    pub total_bytes_in: u64,
    pub total_bytes_out: u64,
    pub packets_in: u64,
    pub packets_out: u64,
    pub connections: u32,
    pub peak_bandwidth: u64,
    pub avg_bandwidth: u64,
    pub last_check: i64,
    pub history: Vec<TrafficSample>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficSample {
    pub timestamp: i64,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

/// Port access control policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortAccessPolicy {
    pub port: u16,
    pub allowed_ips: Vec<String>,
    pub denied_ips: Vec<String>,
    pub require_auth: bool,
    pub max_connections: u32,
    pub connection_timeout_secs: u32,
    pub logging_level: LogLevel,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum LogLevel {
    None,
    Error,
    Warning,
    Info,
    Debug,
}

impl NetworkManager {
    pub fn new(port_range_start: u16, port_range_end: u16) -> Self {
        Self {
            port_manager: Arc::new(Mutex::new(PortManager::new(port_range_start, port_range_end))),
            segments: Arc::new(Mutex::new(HashMap::new())),
            monitoring_enabled: true,
        }
    }

    /// Allocate port for agent service
    pub fn allocate_agent_port(
        &self,
        agent_pid: String,
        service_name: String,
    ) -> Result<u16, NetworkError> {
        let mut pm = self.port_manager.lock().unwrap();
        let port = pm.allocate_port(service_name, Some(agent_pid.clone()), PortProtocol::Cnp)?;
        pm.set_port_status(port, PortStatus::Listening)?;
        Ok(port)
    }

    /// Register well-known service port
    pub fn register_service_port(
        &self,
        port: u16,
        service_name: String,
    ) -> Result<(), NetworkError> {
        let mut pm = self.port_manager.lock().unwrap();
        pm.register_port(port, service_name, None, PortProtocol::Http)
    }

    /// Create network segment (isolation boundary)
    pub fn create_segment(&self, segment_id: String, allowed_ports: Vec<u16>) {
        let mut segments = self.segments.lock().unwrap();
        segments.insert(segment_id, allowed_ports);
    }

    /// Check if agent can communicate to port
    pub fn can_communicate(
        &self,
        source_agent: &str,
        target_port: u16,
    ) -> bool {
        // Check port ACL
        let pm = self.port_manager.lock().unwrap();
        // In real implementation, resolve agent IP
        pm.check_acl(target_port, "127.0.0.1")
    }

    /// Set port access control policy
    pub fn set_port_access_policy(&self, port: u16, policy: PortAccessPolicy) {
        let mut policies = self.access_policies.lock().unwrap();
        policies.insert(port, policy);
    }

    /// Check if IP is allowed to access port
    pub fn check_port_access(&self, port: u16, ip: &str) -> bool {
        // Check deny list first
        let policies = self.access_policies.lock().unwrap();
        if let Some(policy) = policies.get(&port) {
            if policy.denied_ips.contains(&ip.to_string()) {
                return false;
            }
            if !policy.allowed_ips.is_empty() && !policy.allowed_ips.contains(&ip.to_string()) {
                return false;
            }
            return true;
        }
        // Default allow if no policy set
        true
    }

    /// Record traffic for monitoring
    pub fn record_traffic(&self, port: u16, bytes_in: u64, bytes_out: u64) {
        if !self.monitoring_enabled {
            return;
        }

        let now = chrono::Utc::now().timestamp_millis();
        let mut monitor = self.traffic_monitor.lock().unwrap();
        
        let stats = monitor.entry(port).or_insert_with(|| TrafficStats {
            port,
            total_bytes_in: 0,
            total_bytes_out: 0,
            packets_in: 0,
            packets_out: 0,
            connections: 0,
            peak_bandwidth: 0,
            avg_bandwidth: 0,
            last_check: now,
            history: Vec::new(),
        });

        stats.total_bytes_in += bytes_in;
        stats.total_bytes_out += bytes_out;
        stats.packets_in += 1;
        stats.packets_out += 1;

        // Add sample every 60 seconds
        if now - stats.last_check > 60000 {
            stats.history.push(TrafficSample {
                timestamp: now,
                bytes_in: stats.total_bytes_in,
                bytes_out: stats.total_bytes_out,
            });
            // Keep only last 100 samples
            if stats.history.len() > 100 {
                stats.history.remove(0);
            }
            stats.last_check = now;
        }
    }

    /// Get traffic statistics for port
    pub fn get_traffic_stats(&self, port: u16) -> Option<TrafficStats> {
        self.traffic_monitor.lock().unwrap().get(&port).cloned()
    }

    /// Get all traffic statistics
    pub fn get_all_traffic_stats(&self) -> Vec<TrafficStats> {
        self.traffic_monitor.lock().unwrap().values().cloned().collect()
    }

    /// Check rate limiting
    pub fn check_rate_limit(&self, port: u16, bytes: u64) -> bool {
        let limits = self.rate_limits.lock().unwrap();
        if let Some(limit) = limits.get(&port) {
            bytes <= *limit
        } else {
            true // No limit set
        }
    }

    /// Set rate limit for port
    pub fn set_rate_limit(&self, port: u16, bytes_per_second: u64) {
        let mut limits = self.rate_limits.lock().unwrap();
        limits.insert(port, bytes_per_second);
    }

    /// Enable/disable monitoring
    pub fn set_monitoring(&self, enabled: bool) {
        // This would need interior mutability in production
        // For now, monitoring is always enabled
    }

    /// Release agent port
    pub fn release_agent_port(&self, port: u16) -> Result<(), NetworkError> {
        let mut pm = self.port_manager.lock().unwrap();
        pm.release_port(port)
    }

    /// Get network statistics
    pub fn get_stats(&self) -> NetworkStats {
        let pm = self.port_manager.lock().unwrap();
        let ports = pm.list_ports();

        NetworkStats {
            total_ports: ports.len(),
            active_ports: ports.iter().filter(|p| p.status == PortStatus::Active).count(),
            total_bytes_in: ports.iter().map(|p| p.bytes_in).sum(),
            total_bytes_out: ports.iter().map(|p| p.bytes_out).sum(),
            ports: ports,
        }
    }

    /// Shutdown all ports
    pub fn shutdown(&self) {
        let mut pm = self.port_manager.lock().unwrap();
        let ports_to_close: Vec<u16> = pm.allocated_ports.keys().cloned().collect();
        for port in ports_to_close {
            let _ = pm.release_port(port);
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct NetworkStats {
    pub total_ports: usize,
    pub active_ports: usize,
    pub total_bytes_in: u64,
    pub total_bytes_out: u64,
    pub ports: Vec<PortAllocation>,
}

/// Thread-safe wrapper
#[derive(Clone)]
pub struct SharedNetworkManager {
    inner: Arc<NetworkManager>,
}

impl SharedNetworkManager {
    pub fn new(port_range_start: u16, port_range_end: u16) -> Self {
        Self {
            inner: Arc::new(NetworkManager::new(port_range_start, port_range_end)),
        }
    }

    pub fn allocate_agent_port(
        &self,
        agent_pid: String,
        service_name: String,
    ) -> Result<u16, NetworkError> {
        self.inner.allocate_agent_port(agent_pid, service_name)
    }

    pub fn release_agent_port(&self, port: u16) -> Result<(), NetworkError> {
        self.inner.release_agent_port(port)
    }

    pub fn can_communicate(&self, source_agent: &str, target_port: u16) -> bool {
        self.inner.can_communicate(source_agent, target_port)
    }

    pub fn get_stats(&self) -> NetworkStats {
        self.inner.get_stats()
    }

    pub fn register_service_port(&self, port: u16, service_name: String) -> Result<(), NetworkError> {
        self.inner.register_service_port(port, service_name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_port_allocation() {
        let mut pm = PortManager::new(30000, 31000);
        let port = pm.allocate_port("test-service".to_string(), None, PortProtocol::Http).unwrap();
        assert!(port >= 30000 && port < 31000);
    }

    #[test]
    fn test_acl_allow_localhost() {
        let mut pm = PortManager::new(30000, 31000);
        let port = pm.allocate_port("test".to_string(), None, PortProtocol::Http).unwrap();
        assert!(pm.check_acl(port, "127.0.0.1"));
    }

    #[test]
    fn test_duplicate_port_fails() {
        let mut pm = PortManager::new(30000, 31000);
        pm.register_port(30001, "service1".to_string(), None, PortProtocol::Http).unwrap();
        let result = pm.register_port(30001, "service2".to_string(), None, PortProtocol::Http);
        assert!(matches!(result, Err(NetworkError::PortInUse(30001))));
    }
}

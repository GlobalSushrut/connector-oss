//! Agent Service Discovery
//!
//! Kubernetes-style service discovery for agents within cells.
//!
//! # Service Types
//!
//! - **ClusterIP** — Internal service, accessible within the cluster
//! - **NodePort** — Exposed on each cell's port
//! - **LoadBalancer** — External load balancer
//! - **ExternalName** — DNS alias to external service
//!
//! # Example
//!
//! ```yaml
//! apiVersion: v1
//! kind: AgentService
//! metadata:
//!   name: triage-service
//!   namespace: hospital
//! spec:
//!   selector:
//!     app: triage
//!   ports:
//!   - name: grpc
//!     protocol: GRPC
//!     port: 50051
//!     targetPort: 50051
//!   type: ClusterIP
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use super::labels::LabelSelector;
use super::spec::{Condition, ConditionStatus, ObjectMeta};

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

// ═══════════════════════════════════════════════════════════════════════
// AgentService
// ═══════════════════════════════════════════════════════════════════════

/// Agent service for discovery and load balancing (like K8s Service)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentService {
    /// API version
    #[serde(default = "default_api_version")]
    pub api_version: String,
    /// Kind
    #[serde(default = "default_service_kind")]
    pub kind: String,
    /// Metadata
    pub metadata: ObjectMeta,
    /// Specification
    pub spec: ServiceSpec,
    /// Current status
    #[serde(default)]
    pub status: ServiceStatus,
}

fn default_api_version() -> String { "v1".to_string() }
fn default_service_kind() -> String { "AgentService".to_string() }

/// Service specification
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceSpec {
    /// Label selector for target agents
    #[serde(default)]
    pub selector: LabelSelector,
    /// Service ports
    #[serde(default)]
    pub ports: Vec<ServicePort>,
    /// Service type
    #[serde(default)]
    #[serde(rename = "type")]
    pub type_: ServiceType,
    /// Cluster IP (assigned by system for ClusterIP type)
    #[serde(default)]
    pub cluster_ip: Option<String>,
    /// External IPs
    #[serde(default)]
    pub external_ips: Vec<String>,
    /// Session affinity
    #[serde(default)]
    pub session_affinity: SessionAffinity,
    /// Session affinity config
    #[serde(default)]
    pub session_affinity_config: Option<SessionAffinityConfig>,
    /// External name (for ExternalName type)
    #[serde(default)]
    pub external_name: Option<String>,
    /// External traffic policy
    #[serde(default)]
    pub external_traffic_policy: Option<ExternalTrafficPolicy>,
    /// Internal traffic policy
    #[serde(default)]
    pub internal_traffic_policy: Option<InternalTrafficPolicy>,
    /// Health check node port
    #[serde(default)]
    pub health_check_node_port: Option<u16>,
    /// Publish not ready addresses
    #[serde(default)]
    pub publish_not_ready_addresses: bool,
}

/// Service port
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServicePort {
    /// Port name
    #[serde(default)]
    pub name: Option<String>,
    /// Protocol
    #[serde(default)]
    pub protocol: Protocol,
    /// Service port
    pub port: u16,
    /// Target port on agents
    #[serde(default)]
    pub target_port: Option<IntOrString>,
    /// Node port (for NodePort/LoadBalancer types)
    #[serde(default)]
    pub node_port: Option<u16>,
}

/// Integer or string (for port references)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum IntOrString {
    Int(u16),
    String(String),
}

impl Default for IntOrString {
    fn default() -> Self {
        IntOrString::Int(0)
    }
}

/// Protocol
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Protocol {
    #[default]
    TCP,
    UDP,
    GRPC,
    HTTP,
    HTTPS,
}

/// Service type
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceType {
    #[default]
    ClusterIP,
    NodePort,
    LoadBalancer,
    ExternalName,
}

/// Session affinity
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionAffinity {
    #[default]
    None,
    ClientIP,
}

/// Session affinity config
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionAffinityConfig {
    pub client_ip: Option<ClientIPConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientIPConfig {
    /// Timeout seconds for session affinity
    pub timeout_seconds: u32,
}

/// External traffic policy
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExternalTrafficPolicy {
    Cluster,
    Local,
}

/// Internal traffic policy
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InternalTrafficPolicy {
    Cluster,
    Local,
}

/// Service status
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceStatus {
    /// Load balancer status
    #[serde(default)]
    pub load_balancer: Option<LoadBalancerStatus>,
    /// Conditions
    #[serde(default)]
    pub conditions: Vec<Condition>,
}

/// Load balancer status
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoadBalancerStatus {
    /// Ingress points
    #[serde(default)]
    pub ingress: Vec<LoadBalancerIngress>,
}

/// Load balancer ingress
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoadBalancerIngress {
    /// IP address
    #[serde(default)]
    pub ip: Option<String>,
    /// Hostname
    #[serde(default)]
    pub hostname: Option<String>,
    /// Ports
    #[serde(default)]
    pub ports: Vec<PortStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortStatus {
    pub port: u16,
    pub protocol: Protocol,
    #[serde(default)]
    pub error: Option<String>,
}

impl AgentService {
    /// Create a new ClusterIP service
    pub fn new_cluster_ip(
        name: &str,
        namespace: &str,
        selector: LabelSelector,
        ports: Vec<ServicePort>,
    ) -> Self {
        Self {
            api_version: default_api_version(),
            kind: default_service_kind(),
            metadata: ObjectMeta {
                name: name.to_string(),
                namespace: namespace.to_string(),
                creation_timestamp: now_ms(),
                ..Default::default()
            },
            spec: ServiceSpec {
                selector,
                ports,
                type_: ServiceType::ClusterIP,
                cluster_ip: None, // Assigned by system
                external_ips: Vec::new(),
                session_affinity: SessionAffinity::None,
                session_affinity_config: None,
                external_name: None,
                external_traffic_policy: None,
                internal_traffic_policy: None,
                health_check_node_port: None,
                publish_not_ready_addresses: false,
            },
            status: ServiceStatus::default(),
        }
    }

    /// Create a new LoadBalancer service
    pub fn new_load_balancer(
        name: &str,
        namespace: &str,
        selector: LabelSelector,
        ports: Vec<ServicePort>,
    ) -> Self {
        let mut svc = Self::new_cluster_ip(name, namespace, selector, ports);
        svc.spec.type_ = ServiceType::LoadBalancer;
        svc
    }

    /// Check if an agent matches this service's selector
    pub fn matches_agent(&self, agent_labels: &HashMap<String, String>) -> bool {
        self.spec.selector.matches(agent_labels)
    }

    /// Get the fully qualified service name
    pub fn fqdn(&self) -> String {
        format!("{}.{}.svc.connector.local",
            self.metadata.name, self.metadata.namespace)
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Endpoints (like K8s Endpoints/EndpointSlice)
// ═══════════════════════════════════════════════════════════════════════

/// Endpoints for a service
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Endpoints {
    /// API version
    #[serde(default = "default_api_version")]
    pub api_version: String,
    /// Kind
    #[serde(default = "default_endpoints_kind")]
    pub kind: String,
    /// Metadata
    pub metadata: ObjectMeta,
    /// Subsets of endpoints
    #[serde(default)]
    pub subsets: Vec<EndpointSubset>,
}

fn default_endpoints_kind() -> String { "Endpoints".to_string() }

/// Subset of endpoints
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EndpointSubset {
    /// Ready addresses
    #[serde(default)]
    pub addresses: Vec<EndpointAddress>,
    /// Not ready addresses
    #[serde(default)]
    pub not_ready_addresses: Vec<EndpointAddress>,
    /// Ports
    #[serde(default)]
    pub ports: Vec<EndpointPort>,
}

/// Endpoint address
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EndpointAddress {
    /// IP address or agent PID
    pub ip: String,
    /// Hostname
    #[serde(default)]
    pub hostname: Option<String>,
    /// Node (cell) name
    #[serde(default)]
    pub node_name: Option<String>,
    /// Target reference
    #[serde(default)]
    pub target_ref: Option<ObjectReference>,
}

/// Object reference
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ObjectReference {
    pub api_version: String,
    pub kind: String,
    pub name: String,
    pub namespace: String,
    #[serde(default)]
    pub uid: String,
}

/// Endpoint port
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EndpointPort {
    /// Port name
    #[serde(default)]
    pub name: Option<String>,
    /// Port number
    pub port: u16,
    /// Protocol
    #[serde(default)]
    pub protocol: Protocol,
}

// ═══════════════════════════════════════════════════════════════════════
// Service Controller
// ═══════════════════════════════════════════════════════════════════════

/// Controller that manages services and endpoints
pub struct ServiceController {
    /// Registered services
    services: HashMap<String, AgentService>,
    /// Endpoints for each service
    endpoints: HashMap<String, Endpoints>,
    /// Cluster IP allocator
    next_cluster_ip: u32,
    /// Node port allocator
    next_node_port: u16,
}

impl ServiceController {
    pub fn new() -> Self {
        Self {
            services: HashMap::new(),
            endpoints: HashMap::new(),
            next_cluster_ip: 0x0A000001, // 10.0.0.1
            next_node_port: 30000,
        }
    }

    /// Create or update a service
    pub fn apply(&mut self, mut service: AgentService) -> Result<(), String> {
        let key = format!("{}/{}", service.metadata.namespace, service.metadata.name);

        // Assign cluster IP if needed
        if service.spec.type_ == ServiceType::ClusterIP && service.spec.cluster_ip.is_none() {
            service.spec.cluster_ip = Some(self.allocate_cluster_ip());
        }

        // Assign node ports if needed
        if service.spec.type_ == ServiceType::NodePort || service.spec.type_ == ServiceType::LoadBalancer {
            for port in &mut service.spec.ports {
                if port.node_port.is_none() {
                    port.node_port = Some(self.allocate_node_port());
                }
            }
        }

        // Create empty endpoints
        if !self.endpoints.contains_key(&key) {
            self.endpoints.insert(key.clone(), Endpoints {
                api_version: default_api_version(),
                kind: default_endpoints_kind(),
                metadata: ObjectMeta {
                    name: service.metadata.name.clone(),
                    namespace: service.metadata.namespace.clone(),
                    ..Default::default()
                },
                subsets: Vec::new(),
            });
        }

        self.services.insert(key, service);
        Ok(())
    }

    fn allocate_cluster_ip(&mut self) -> String {
        let ip = self.next_cluster_ip;
        self.next_cluster_ip += 1;
        format!("{}.{}.{}.{}",
            (ip >> 24) & 0xFF,
            (ip >> 16) & 0xFF,
            (ip >> 8) & 0xFF,
            ip & 0xFF)
    }

    fn allocate_node_port(&mut self) -> u16 {
        let port = self.next_node_port;
        self.next_node_port += 1;
        if self.next_node_port > 32767 {
            self.next_node_port = 30000;
        }
        port
    }

    /// Delete a service
    pub fn delete(&mut self, namespace: &str, name: &str) -> Option<AgentService> {
        let key = format!("{}/{}", namespace, name);
        self.endpoints.remove(&key);
        self.services.remove(&key)
    }

    /// Get a service
    pub fn get(&self, namespace: &str, name: &str) -> Option<&AgentService> {
        let key = format!("{}/{}", namespace, name);
        self.services.get(&key)
    }

    /// List all services
    pub fn list(&self) -> Vec<&AgentService> {
        self.services.values().collect()
    }

    /// List services in a namespace
    pub fn list_in_namespace(&self, namespace: &str) -> Vec<&AgentService> {
        self.services.values()
            .filter(|s| s.metadata.namespace == namespace)
            .collect()
    }

    /// Get endpoints for a service
    pub fn get_endpoints(&self, namespace: &str, name: &str) -> Option<&Endpoints> {
        let key = format!("{}/{}", namespace, name);
        self.endpoints.get(&key)
    }

    /// Update endpoints for a service based on matching agents
    pub fn update_endpoints(
        &mut self,
        namespace: &str,
        name: &str,
        agents: &[(String, HashMap<String, String>, bool)], // (pid, labels, ready)
    ) -> Result<(), String> {
        let key = format!("{}/{}", namespace, name);

        let service = self.services.get(&key)
            .ok_or_else(|| format!("Service {}/{} not found", namespace, name))?;

        let mut ready_addresses = Vec::new();
        let mut not_ready_addresses = Vec::new();

        for (pid, labels, ready) in agents {
            if service.matches_agent(labels) {
                let addr = EndpointAddress {
                    ip: pid.clone(),
                    hostname: None,
                    node_name: None,
                    target_ref: Some(ObjectReference {
                        api_version: "connector.io/v1".to_string(),
                        kind: "Agent".to_string(),
                        name: pid.clone(),
                        namespace: namespace.to_string(),
                        uid: String::new(),
                    }),
                };

                if *ready {
                    ready_addresses.push(addr);
                } else {
                    not_ready_addresses.push(addr);
                }
            }
        }

        // Build endpoint ports from service ports
        let ports: Vec<EndpointPort> = service.spec.ports.iter().map(|p| {
            EndpointPort {
                name: p.name.clone(),
                port: match &p.target_port {
                    Some(IntOrString::Int(port)) => *port,
                    _ => p.port,
                },
                protocol: p.protocol.clone(),
            }
        }).collect();

        // Update endpoints
        if let Some(endpoints) = self.endpoints.get_mut(&key) {
            endpoints.subsets = vec![EndpointSubset {
                addresses: ready_addresses,
                not_ready_addresses,
                ports,
            }];
        }

        Ok(())
    }

    /// Resolve a service to its endpoints
    pub fn resolve(&self, namespace: &str, name: &str) -> Vec<String> {
        let key = format!("{}/{}", namespace, name);
        self.endpoints.get(&key)
            .map(|e| {
                e.subsets.iter()
                    .flat_map(|s| s.addresses.iter().map(|a| a.ip.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Resolve with load balancing (round-robin)
    pub fn resolve_one(&self, namespace: &str, name: &str, index: usize) -> Option<String> {
        let endpoints = self.resolve(namespace, name);
        if endpoints.is_empty() {
            None
        } else {
            Some(endpoints[index % endpoints.len()].clone())
        }
    }
}

impl Default for ServiceController {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_service(name: &str) -> AgentService {
        let mut labels = HashMap::new();
        labels.insert("app".to_string(), name.to_string());

        AgentService::new_cluster_ip(
            name,
            "default",
            LabelSelector::from_labels(labels),
            vec![ServicePort {
                name: Some("grpc".to_string()),
                protocol: Protocol::GRPC,
                port: 50051,
                target_port: Some(IntOrString::Int(50051)),
                node_port: None,
            }],
        )
    }

    #[test]
    fn test_create_service() {
        let svc = make_service("triage");
        assert_eq!(svc.metadata.name, "triage");
        assert_eq!(svc.spec.type_, ServiceType::ClusterIP);
    }

    #[test]
    fn test_fqdn() {
        let svc = make_service("triage");
        assert_eq!(svc.fqdn(), "triage.default.svc.connector.local");
    }

    #[test]
    fn test_matches_agent() {
        let svc = make_service("triage");

        let mut matching = HashMap::new();
        matching.insert("app".to_string(), "triage".to_string());
        assert!(svc.matches_agent(&matching));

        let mut non_matching = HashMap::new();
        non_matching.insert("app".to_string(), "other".to_string());
        assert!(!svc.matches_agent(&non_matching));
    }

    #[test]
    fn test_controller_apply() {
        let mut controller = ServiceController::new();
        let svc = make_service("triage");

        controller.apply(svc).unwrap();

        let loaded = controller.get("default", "triage").unwrap();
        assert!(loaded.spec.cluster_ip.is_some());
    }

    #[test]
    fn test_controller_endpoints() {
        let mut controller = ServiceController::new();
        controller.apply(make_service("triage")).unwrap();

        let mut labels = HashMap::new();
        labels.insert("app".to_string(), "triage".to_string());

        let agents = vec![
            ("agent:001".to_string(), labels.clone(), true),
            ("agent:002".to_string(), labels.clone(), true),
            ("agent:003".to_string(), labels.clone(), false),
        ];

        controller.update_endpoints("default", "triage", &agents).unwrap();

        let endpoints = controller.get_endpoints("default", "triage").unwrap();
        assert_eq!(endpoints.subsets[0].addresses.len(), 2);
        assert_eq!(endpoints.subsets[0].not_ready_addresses.len(), 1);
    }

    #[test]
    fn test_resolve() {
        let mut controller = ServiceController::new();
        controller.apply(make_service("triage")).unwrap();

        let mut labels = HashMap::new();
        labels.insert("app".to_string(), "triage".to_string());

        let agents = vec![
            ("agent:001".to_string(), labels.clone(), true),
            ("agent:002".to_string(), labels.clone(), true),
        ];

        controller.update_endpoints("default", "triage", &agents).unwrap();

        let resolved = controller.resolve("default", "triage");
        assert_eq!(resolved.len(), 2);
        assert!(resolved.contains(&"agent:001".to_string()));
        assert!(resolved.contains(&"agent:002".to_string()));
    }

    #[test]
    fn test_resolve_one_round_robin() {
        let mut controller = ServiceController::new();
        controller.apply(make_service("triage")).unwrap();

        let mut labels = HashMap::new();
        labels.insert("app".to_string(), "triage".to_string());

        let agents = vec![
            ("agent:001".to_string(), labels.clone(), true),
            ("agent:002".to_string(), labels.clone(), true),
        ];

        controller.update_endpoints("default", "triage", &agents).unwrap();

        // Round-robin should cycle through endpoints
        let e0 = controller.resolve_one("default", "triage", 0).unwrap();
        let e1 = controller.resolve_one("default", "triage", 1).unwrap();
        let e2 = controller.resolve_one("default", "triage", 2).unwrap();

        assert_eq!(e0, e2); // Wraps around
        assert_ne!(e0, e1);
    }
}

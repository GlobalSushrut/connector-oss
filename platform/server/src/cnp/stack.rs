//! CNP Protocol Stack — Connector Native Protocol (L1-L7)
//!
//! FIX BUG-062: Full protocol implementation
//! L1: Codec (DAG-CBOR encoding)
//! L2: Transport (QUIC/WebSocket)
//! L3: Security (TLS 1.3, mTLS)
//! L4: Ports (logical addressing)
//! L5: Routing (cell-to-cell)
//! L6: Contracts (CLS interface)
//! L7: Cognitive (agent semantics)

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use serde::{Serialize, Deserialize};

// =============================================================================
// L1: Codec Layer — DAG-CBOR Encoding
// =============================================================================

pub mod codec {
    use super::*;
    
    /// DAG-CBOR encoded data
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct DagCborFrame {
        pub version: u8,
        pub data: Vec<u8>,
        pub cid: String, // Content identifier
    }
    
    impl DagCborFrame {
        pub fn encode<T: Serialize>(value: &T) -> Result<Self, CodecError> {
            // JSON stand-in until DAG-CBOR dependency is productized.
            let data = serde_json::to_vec(value).map_err(|_| CodecError::EncodeFailed)?;
            
            let cid = Self::compute_cid(&data);
            
            Ok(Self {
                version: 1,
                data,
                cid,
            })
        }
        
        pub fn decode<T: for<'de> Deserialize<'de>>(&self) -> Result<T, CodecError> {
            serde_json::from_slice(&self.data).map_err(|_| CodecError::DecodeFailed)
        }
        
        fn compute_cid(data: &[u8]) -> String {
            use sha2::{Sha256, Digest};
            let mut hasher = Sha256::new();
            hasher.update(data);
            format!("bafy2bzace{}", hex::encode(&hasher.finalize()[..16]))
        }
    }
    
    #[derive(Debug, Clone)]
    pub enum CodecError {
        EncodeFailed,
        DecodeFailed,
        InvalidCid,
    }
}

// =============================================================================
// L2: Transport Layer — QUIC/WebSocket
// =============================================================================

pub mod transport {
    use super::*;
    
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct CnpFrame {
        pub frame_id: String,
        pub stream_id: u64,
        pub payload: Vec<u8>,
        pub flags: FrameFlags,
        pub timestamp: i64,
    }
    
    #[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
    pub struct FrameFlags {
        pub fin: bool,      // Final frame
        pub ack: bool,      // Acknowledgment
        pub rst: bool,      // Reset
        pub priority: u8,   // Priority level
    }
    
    #[derive(Debug, Clone, Copy)]
    pub enum TransportMode {
        Quic,
        WebSocket,
        TcpFallback,
    }
}

// =============================================================================
// L3: Security Layer — TLS 1.3 + mTLS
// =============================================================================

pub mod security {
    use super::*;
    
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SecurityContext {
        pub tls_version: String,
        pub cipher_suite: String,
        pub peer_certificate: Vec<u8>,
        pub mutual_auth: bool,
        pub session_resumed: bool,
    }
    
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct CnpSecurity {
        pub context: SecurityContext,
        pub encryption_key: Vec<u8>,
        pub integrity_key: Vec<u8>,
    }
    
    /// Honesty label for CNP peer mTLS (P3.4 / P8.3).
    pub fn cnp_mtls_honesty() -> &'static str {
        if cnp_mtls_stub_allowed() {
            "lab_stub"
        } else {
            "fail_closed"
        }
    }

    pub fn cnp_mtls_stub_allowed() -> bool {
        std::env::var("CONNECTOR_CNP_ALLOW_MTLS_STUB")
            .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
            .unwrap_or(false)
    }

    impl CnpSecurity {
        /// Establish mTLS security context.
        ///
        /// Refuses fake success with empty crypto keys (U5.4). Real TLS key
        /// derivation is not wired — callers must not treat empty keys as authenticated.
        /// Lab break-glass: `CONNECTOR_CNP_ALLOW_MTLS_STUB=1` returns an explicitly
        /// unverified stub (`mutual_auth=false`, empty keys).
        pub fn establish_mtls(peer_cert: Vec<u8>) -> Result<Self, SecurityError> {
            if peer_cert.is_empty() {
                return Err(SecurityError::CertificateInvalid);
            }
            if !cnp_mtls_stub_allowed() {
                return Err(SecurityError::HandshakeFailed);
            }
            Ok(Self {
                context: SecurityContext {
                    tls_version: "TLSv1.3".to_string(),
                    cipher_suite: "TLS_AES_256_GCM_SHA384".to_string(),
                    peer_certificate: peer_cert,
                    // Stub: not mutual-auth proven — keys were not derived.
                    mutual_auth: false,
                    session_resumed: false,
                },
                encryption_key: vec![],
                integrity_key: vec![],
            })
        }

        /// True only when both keys are non-empty (real handshake path).
        pub fn keys_verified(&self) -> bool {
            !self.encryption_key.is_empty()
                && !self.integrity_key.is_empty()
                && self.context.mutual_auth
        }
    }
    
    #[derive(Debug, Clone)]
    pub enum SecurityError {
        HandshakeFailed,
        CertificateInvalid,
        CipherNotSupported,
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn establish_mtls_rejects_empty_cert() {
            assert!(matches!(
                CnpSecurity::establish_mtls(vec![]),
                Err(SecurityError::CertificateInvalid)
            ));
        }

        #[test]
        fn establish_mtls_fails_closed_without_stub_flag() {
            std::env::remove_var("CONNECTOR_CNP_ALLOW_MTLS_STUB");
            assert!(matches!(
                CnpSecurity::establish_mtls(vec![1, 2, 3]),
                Err(SecurityError::HandshakeFailed)
            ));
        }

        #[test]
        fn establish_mtls_stub_marks_unverified() {
            std::env::set_var("CONNECTOR_CNP_ALLOW_MTLS_STUB", "1");
            let sec = CnpSecurity::establish_mtls(vec![1, 2, 3]).expect("stub");
            assert!(!sec.context.mutual_auth);
            assert!(!sec.keys_verified());
            std::env::remove_var("CONNECTOR_CNP_ALLOW_MTLS_STUB");
        }
    }
}

// =============================================================================
// L4: Ports Layer — Logical Addressing
// =============================================================================

pub mod ports {
    use super::*;
    
    /// CNP Port (logical address)
    #[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
    pub struct CnpPort {
        pub port_number: u16,
        pub port_type: PortType,
        pub service_name: String,
        pub cell_id: String,
    }
    
    #[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, Serialize, Deserialize)]
    pub enum PortType {
        Control,    // Management/control plane
        Data,       // Data plane
        Consensus,  // Consensus traffic
        Health,     // Health checks
        Admin,      // Administrative
    }
    
    pub struct PortManager {
        ports: HashMap<u16, CnpPort>,
        allocations: HashMap<String, Vec<u16>>, // cell_id -> ports
    }
    
    impl PortManager {
        pub fn new() -> Self {
            Self {
                ports: HashMap::new(),
                allocations: HashMap::new(),
            }
        }
        
        pub fn allocate_port(&mut self, cell_id: &str, port_type: PortType) -> Option<u16> {
            // Find free port in range
            for port_num in 1024..65535 {
                if !self.ports.contains_key(&port_num) {
                    let port = CnpPort {
                        port_number: port_num,
                        port_type,
                        service_name: format!("{}-{}", cell_id, port_num),
                        cell_id: cell_id.to_string(),
                    };
                    
                    self.ports.insert(port_num, port.clone());
                    self.allocations.entry(cell_id.to_string())
                        .or_insert_with(Vec::new)
                        .push(port_num);
                    
                    return Some(port_num);
                }
            }
            None
        }
        
        pub fn lookup_port(&self, cell_id: &str, service: &str) -> Option<u16> {
            self.ports.values()
                .find(|p| p.cell_id == cell_id && p.service_name.contains(service))
                .map(|p| p.port_number)
        }
    }
}

// =============================================================================
// L5: Routing Layer — Cell-to-Cell Routing
// =============================================================================

pub mod routing {
    use super::*;
    
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Route {
        pub route_id: String,
        pub source_cell: String,
        pub dest_cell: String,
        pub next_hop: String,
        pub path: Vec<String>,
        pub metric: RouteMetric,
        pub ttl: u8,
    }
    
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RouteMetric {
        pub latency_ms: u64,
        pub bandwidth_mbps: u32,
        pub hop_count: u8,
        pub load_factor: f64,
    }
    
    pub struct RoutingTable {
        routes: HashMap<String, Vec<Route>>, // dest_cell -> routes
        local_cell_id: String,
    }
    
    impl RoutingTable {
        pub fn new(local_cell_id: String) -> Self {
            Self {
                routes: HashMap::new(),
                local_cell_id,
            }
        }
        
        pub fn local_cell_id(&self) -> &str {
            &self.local_cell_id
        }
        
        pub fn add_route(&mut self, route: Route) {
            let dest = route.dest_cell.clone();
            let routes = self.routes.entry(dest).or_insert_with(Vec::new);
            routes.push(route);
            // Sort by metric
            routes.sort_by(|a, b| a.metric.latency_ms.cmp(&b.metric.latency_ms));
        }
        
        pub fn get_best_route(&self, dest_cell: &str) -> Option<Route> {
            self.routes.get(dest_cell)?.first().cloned()
        }

        pub fn route_count(&self) -> usize {
            self.routes.values().map(|v| v.len()).sum()
        }
        
        pub fn route_packet(&self, dest_cell: &str, _packet: &[u8]) -> Result<String, RoutingError> {
            let route = self.get_best_route(dest_cell)
                .ok_or(RoutingError::NoRoute)?;
            Ok(route.next_hop.clone())
        }
    }
    
    #[derive(Debug, Clone)]
    pub enum RoutingError {
        NoRoute,
        LoopDetected,
        MaxHopsExceeded,
    }
}

// =============================================================================
// L6: Contracts Layer — CLS Interface
// =============================================================================

pub mod contracts {
    use super::*;
    
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ContractEnvelope {
        pub contract_id: String,
        pub contract_type: ContractType,
        pub payload: Vec<u8>,
        pub signature: Vec<u8>,
        pub sender: String,
        pub receiver: String,
    }
    
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    pub enum ContractType {
        Request,
        Response,
        Event,
        Query,
    }
    
    pub struct ContractRouter {
        handlers: HashMap<String, Box<dyn Fn(ContractEnvelope) + Send + Sync>>,
    }
    
    impl ContractRouter {
        pub fn new() -> Self {
            Self { handlers: HashMap::new() }
        }
        
        pub fn register_handler<F>(&mut self, contract_id: &str, handler: F)
        where F: Fn(ContractEnvelope) + Send + Sync + 'static {
            self.handlers.insert(contract_id.to_string(), Box::new(handler));
        }
        
        pub fn route_contract(&self, envelope: ContractEnvelope) -> Result<(), ContractError> {
            if let Some(handler) = self.handlers.get(&envelope.contract_id) {
                handler(envelope);
                Ok(())
            } else {
                Err(ContractError::NoHandler)
            }
        }
    }
    
    #[derive(Debug, Clone)]
    pub enum ContractError {
        NoHandler,
        InvalidSignature,
        ContractExpired,
    }
}

// =============================================================================
// L7: Cognitive Layer — Agent Semantics
// =============================================================================

pub mod cognitive {
    use super::*;
    
    /// Cognitive message (L7 payload)
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct CognitiveMessage {
        pub message_id: String,
        pub agent_pid: String,
        pub intent: Intent,
        pub payload: CognitivePayload,
        pub confidence: f64,
        pub timestamp: i64,
    }
    
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum Intent {
        Query,
        Command,
        Inform,
        Request,
        Response,
    }
    
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum CognitivePayload {
        Text(String),
        Structured(HashMap<String, String>),
        Binary(Vec<u8>),
        Reference(String), // CID reference
    }
    
    /// Intent classifier (simple version)
    pub fn classify_intent(text: &str) -> Intent {
        let lower = text.to_lowercase();
        if lower.starts_with("what") || lower.starts_with("how") || lower.contains("?") {
            Intent::Query
        } else if lower.starts_with("please") || lower.starts_with("can you") {
            Intent::Request
        } else if lower.starts_with("tell") || lower.starts_with("inform") {
            Intent::Inform
        } else {
            Intent::Command
        }
    }
}

// =============================================================================
// Session Management
// =============================================================================

pub mod session {
    use super::*;
    use std::time::{Duration, Instant};
    
    #[derive(Debug, Clone)]
    pub struct CnpSession {
        pub session_id: String,
        pub local_cell: String,
        pub remote_cell: String,
        pub established_at: Instant,
        pub last_activity: Instant,
        pub security: super::security::CnpSecurity,
        pub state: SessionState,
    }
    
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum SessionState {
        Handshaking,
        Established,
        Rekeying,
        Closing,
        Closed,
    }
    
    pub struct SessionManager {
        sessions: Arc<RwLock<HashMap<String, CnpSession>>>,
        max_sessions: usize,
        session_timeout: Duration,
    }
    
    impl SessionManager {
        pub fn new(max_sessions: usize) -> Self {
            Self {
                sessions: Arc::new(RwLock::new(HashMap::new())),
                max_sessions,
                session_timeout: Duration::from_secs(300),
            }
        }
        
        pub fn create_session(&self, session: CnpSession) -> Result<(), SessionError> {
            let mut sessions = self.sessions.write().unwrap();
            
            if sessions.len() >= self.max_sessions {
                return Err(SessionError::MaxSessionsReached);
            }
            
            sessions.insert(session.session_id.clone(), session);
            Ok(())
        }
        
        pub fn get_session(&self, session_id: &str) -> Option<CnpSession> {
            self.sessions.read().unwrap().get(session_id).cloned()
        }
        
        pub fn cleanup_expired(&self) -> usize {
            let now = Instant::now();
            let mut sessions = self.sessions.write().unwrap();
            
            let expired: Vec<String> = sessions.iter()
                .filter(|(_, s)| now.duration_since(s.last_activity) > self.session_timeout)
                .map(|(id, _)| id.clone())
                .collect();
            
            for id in &expired {
                sessions.remove(id);
            }
            
            expired.len()
        }
    }
    
    #[derive(Debug, Clone)]
    pub enum SessionError {
        MaxSessionsReached,
        SessionNotFound,
        HandshakeFailed,
    }
}

// =============================================================================
// CNP Stack — Main Orchestrator
// =============================================================================

pub struct CnpStack {
    /// L1: Codec
    pub codec: codec::DagCborFrame,
    /// L4: Port Manager
    pub ports: ports::PortManager,
    /// L5: Routing
    pub routing: routing::RoutingTable,
    /// L6: Contract Router
    pub contracts: contracts::ContractRouter,
    /// Session Manager
    pub sessions: session::SessionManager,
    /// Stack configuration
    config: CnpConfig,
}

#[derive(Debug, Clone)]
pub struct CnpConfig {
    pub max_sessions: usize,
    pub max_routes: usize,
    pub enable_mtls: bool,
    pub preferred_transport: transport::TransportMode,
}

impl Default for CnpConfig {
    fn default() -> Self {
        Self {
            max_sessions: 10000,
            max_routes: 1000,
            enable_mtls: true,
            preferred_transport: transport::TransportMode::Quic,
        }
    }
}

impl CnpStack {
    pub fn new(local_cell_id: String, config: CnpConfig) -> Self {
        Self {
            codec: codec::DagCborFrame {
                version: 1,
                data: vec![],
                cid: String::new(),
            },
            ports: ports::PortManager::new(),
            routing: routing::RoutingTable::new(local_cell_id),
            contracts: contracts::ContractRouter::new(),
            sessions: session::SessionManager::new(config.max_sessions),
            config,
        }
    }
    
    /// Process incoming CNP packet — local delivery or L5 static 1-hop forward.
    pub fn process_packet(&self, data: &[u8]) -> Result<ProcessResult, StackError> {
        crate::cnp::wire::route_inbound_bytes_for(data, self.routing.local_cell_id())
    }

    /// Seed static routes from `CONNECTOR_CNP_PEERS` (`cell=host:port`).
    pub fn seed_static_routes(&mut self) {
        let local = self.routing.local_cell_id().to_string();
        for (cell, addr) in crate::cnp::wire::peer_map() {
            if cell == local {
                continue;
            }
            self.routing.add_route(routing::Route {
                route_id: format!("static-{cell}"),
                source_cell: local.clone(),
                dest_cell: cell.clone(),
                next_hop: addr.clone(),
                path: vec![local.clone(), cell.clone()],
                metric: routing::RouteMetric {
                    latency_ms: 1,
                    bandwidth_mbps: 1000,
                    hop_count: 1,
                    load_factor: 0.0,
                },
                ttl: 64,
            });
        }
    }
    
    /// Send CNP packet. Local dest is delivered to this process inbox.
    /// Remote dest requires `CONNECTOR_CNP_PEERS` (`cell=host:port`) or a route
    /// whose `next_hop` is a `host:port`. Write failure is an error.
    pub fn send_packet(&self, dest_cell: &str, message: cognitive::CognitiveMessage) -> Result<(), StackError> {
        let local = self.routing.local_cell_id().to_string();
        let payload = serde_json::to_value(&message)
            .map_err(|_| StackError::CodecError(codec::CodecError::EncodeFailed))?;
        let mut env = crate::cnp::wire::WireEnvelope {
            from: local.clone(),
            to: dest_cell.to_string(),
            kind: "cognitive".into(),
            payload: payload.clone(),
            ts_ms: chrono::Utc::now().timestamp_millis(),
            principal_id: None,
            workload_id: None,
            cls_contract_hash: None,
            quantum_id: None,
            flow_lease_id: None,
            nonce: Some(uuid::Uuid::new_v4().to_string()),
            expires_at_ms: Some(chrono::Utc::now().timestamp_millis() + 60_000),
            digest_hex: None,
            signature: None,
            dna: None,
        };
        if let Some(dna) = crate::cnp::wire::try_mint_dna_for_payload(&payload, &local) {
            env.dna = Some(dna);
        }
        crate::cnp::wire::sign_wire_envelope(&mut env);
        let body = serde_json::to_vec(&env)
            .map_err(|_| StackError::CodecError(codec::CodecError::EncodeFailed))?;
        if let Err(e) = crate::cnp::wire::verify_wire_envelope(&env) {
            return Err(StackError::Transport(format!("cnp_authz:{e}")));
        }
        let frame = crate::cnp::wire::encode_frame(&body).map_err(StackError::Transport)?;
        if dest_cell == local || dest_cell == "local" {
            self.process_packet(&frame)?;
            return Ok(());
        }
        if let Some(addr) = crate::cnp::wire::lookup_peer(dest_cell) {
            return crate::cnp::wire::tcp_send(addr, &frame).map_err(StackError::Transport);
        }
        if let Some(route) = self.routing.get_best_route(dest_cell) {
            if let Some(addr) = crate::cnp::wire::parse_host_port(&route.next_hop) {
                return crate::cnp::wire::tcp_send(addr, &frame).map_err(StackError::Transport);
            }
        }
        Err(StackError::Transport(format!("no_peer:{dest_cell}")))
    }
}

#[derive(Debug, Clone)]
pub enum ProcessResult {
    Delivered,
    Forwarded(String),
    Dropped(String),
}

#[derive(Debug, Clone)]
pub enum StackError {
    CodecError(codec::CodecError),
    RoutingError(routing::RoutingError),
    ContractError(contracts::ContractError),
    SessionError(session::SessionError),
    Transport(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_dag_cbor_codec() {
        let data = vec![1u8, 2, 3, 4, 5];
        let frame = codec::DagCborFrame::encode(&data).unwrap();
        
        let decoded: Vec<u8> = frame.decode().unwrap();
        assert_eq!(decoded, data);
    }
    
    #[test]
    fn test_port_allocation() {
        let mut ports = ports::PortManager::new();
        let port_num = ports.allocate_port("cell-1", ports::PortType::Data);
        
        assert!(port_num.is_some());
        assert!(port_num.unwrap() >= 1024);
    }
    
    #[test]
    fn test_routing() {
        let mut routing = routing::RoutingTable::new("local".to_string());
        
        let route = routing::Route {
            route_id: "route-1".to_string(),
            source_cell: "local".to_string(),
            dest_cell: "remote".to_string(),
            next_hop: "remote".to_string(),
            path: vec!["local".to_string(), "remote".to_string()],
            metric: routing::RouteMetric {
                latency_ms: 50,
                bandwidth_mbps: 1000,
                hop_count: 1,
                load_factor: 0.5,
            },
            ttl: 64,
        };
        
        routing.add_route(route);
        
        let best = routing.get_best_route("remote");
        assert!(best.is_some());
    }
    
    #[test]
    fn test_intent_classification() {
        assert!(matches!(cognitive::classify_intent("What is this?"), cognitive::Intent::Query));
        assert!(matches!(cognitive::classify_intent("Please do this"), cognitive::Intent::Request));
        assert!(matches!(cognitive::classify_intent("Run command"), cognitive::Intent::Command));
    }

    #[test]
    fn process_packet_rejects_garbage() {
        let s = CnpStack::new("cell-a".into(), CnpConfig::default());
        assert!(s.process_packet(b"").is_err());
        assert!(s.process_packet(b"not-a-frame").is_err());
    }

    #[test]
    fn send_packet_local_lands_in_inbox() {
        let _guard = crate::cnp::wire::test_serial_lock();
        crate::cnp::wire::inbox_clear();
        let s = CnpStack::new("cell-a".into(), CnpConfig::default());
        let msg = cognitive::CognitiveMessage {
            message_id: "m1".into(),
            agent_pid: "pid-a".into(),
            intent: cognitive::Intent::Inform,
            payload: cognitive::CognitivePayload::Text("hello-wire".into()),
            confidence: 1.0,
            timestamp: 1,
        };
        s.send_packet("cell-a", msg).unwrap();
        let inbox = crate::cnp::wire::inbox_snapshot();
        assert!(inbox.iter().any(|v| format!("{v}").contains("hello-wire")));
    }

    #[test]
    fn seed_static_routes_from_peers_env() {
        let _guard = crate::cnp::wire::test_serial_lock();
        std::env::set_var("CONNECTOR_CNP_PEERS", "cell_b=127.0.0.1:9411");
        let mut s = CnpStack::new("cell_a".into(), CnpConfig::default());
        s.seed_static_routes();
        assert_eq!(s.routing.route_count(), 1);
        let hop = s.routing.get_best_route("cell_b").unwrap().next_hop;
        assert_eq!(hop, "127.0.0.1:9411");
        std::env::remove_var("CONNECTOR_CNP_PEERS");
    }

    #[test]
    fn send_packet_forwards_via_peers_env() {
        use std::io::Read;

        let _guard = crate::cnp::wire::test_serial_lock();
        crate::cnp::wire::inbox_clear();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind peer listener");
        listener.set_nonblocking(false).ok();
        let addr = listener.local_addr().expect("peer addr");
        std::env::set_var("CONNECTOR_CNP_PEERS", format!("cell_b={addr}"));

        let peer = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("peer accept");
            let mut hdr = [0u8; 8];
            stream.read_exact(&mut hdr).expect("read hdr");
            let len = u32::from_be_bytes(hdr[4..8].try_into().unwrap()) as usize;
            let mut body = vec![0u8; len];
            stream.read_exact(&mut body).expect("read body");
            let mut frame = Vec::with_capacity(8 + len);
            frame.extend_from_slice(&hdr);
            frame.extend_from_slice(&body);
            crate::cnp::wire::route_inbound_bytes_for(&frame, "cell_b").expect("peer deliver")
        });

        let mut s = CnpStack::new("cell_a".into(), CnpConfig::default());
        s.seed_static_routes();
        let msg = cognitive::CognitiveMessage {
            message_id: "m2".into(),
            agent_pid: "pid-a".into(),
            intent: cognitive::Intent::Inform,
            payload: cognitive::CognitivePayload::Text("l5-send-hop".into()),
            confidence: 1.0,
            timestamp: 2,
        };
        s.send_packet("cell_b", msg).expect("send forward");
        assert!(matches!(
            peer.join().expect("peer thread"),
            ProcessResult::Delivered
        ));
        let inbox = crate::cnp::wire::inbox_snapshot();
        assert!(
            inbox.iter().any(|v| format!("{v}").contains("l5-send-hop")),
            "send_packet forward should reach peer inbox"
        );
        std::env::remove_var("CONNECTOR_CNP_PEERS");
    }
}

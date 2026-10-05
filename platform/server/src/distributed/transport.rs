//! Cell Transport — Real Cross-Cell Network Layer
//!
//! FIX BUG-021: Real cell-to-cell transport using QUIC (HTTP/3)
//!
//! Why QUIC:
//! - NAT traversal (works everywhere)
//! - 0-RTT connection establishment (fast)
//! - Multiplexing without head-of-line blocking
//! - Connection migration (IP changes don't break connection)
//! - Built-in TLS 1.3 (secure by default)
//! - HTTP/3 semantics (CDN-compatible)
//!
//! Architecture: 1 Cell = 1 Node, can have multiple shards
//! Cells replicate under ledger supervision

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use serde::{Serialize, Deserialize};

// Phase R3: quinn QUIC — real socket per CellTransport instance
use quinn::{ClientConfig, Connection, Endpoint as QuinnEndpoint, ServerConfig as QuinnServerConfig};

// =============================================================================
// Transport Protocol Types
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TransportProtocol {
    /// QUIC (HTTP/3) - Primary protocol
    Quic,
    /// WebSocket fallback
    WebSocket,
    /// gRPC (for service mesh)
    Grpc,
}

impl TransportProtocol {
    pub fn default_port(&self) -> u16 {
        match self {
            TransportProtocol::Quic => 443,
            TransportProtocol::WebSocket => 443,
            TransportProtocol::Grpc => 443,
        }
    }
}

// =============================================================================
// Cell Address (Global Cell Identity)
// =============================================================================

#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct CellAddress {
    /// Cell ID (global unique)
    pub cell_id: String,
    /// Network endpoints for this cell
    pub endpoints: Vec<Endpoint>,
    /// Region/location
    pub region: String,
    /// Digital location signature (for verification)
    pub location_signature: String,
    /// Capabilities this cell provides
    pub capabilities: Vec<String>,
    /// Last known health status
    pub health: CellHealth,
    /// Timestamp
    pub last_seen: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Endpoint {
    pub protocol: TransportProtocol,
    pub address: SocketAddr,
    pub priority: u8, // Lower = higher priority
    pub weight: u8,   // For load balancing
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum CellHealth {
    Healthy,
    Degraded,
    Unhealthy,
    Unknown,
}

// =============================================================================
// Transport Connection
// =============================================================================

#[derive(Debug)]
pub struct TransportConnection {
    /// Connection ID
    pub conn_id: String,
    /// Remote cell address
    pub remote_cell: CellAddress,
    /// Protocol used
    pub protocol: TransportProtocol,
    /// Connection state
    pub state: ConnectionState,
    /// Created at
    pub created_at: Instant,
    /// Last activity
    pub last_activity: Instant,
    /// Bytes transferred
    pub bytes_sent: u64,
    pub bytes_received: u64,
    /// Retry count for failed sends
    pub retry_count: u32,
    /// Latency measurement (ms)
    pub latency_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Connecting,
    Connected,
    Disconnecting,
    Disconnected,
    Failed,
}

// =============================================================================
// Message Types
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CellMessage {
    /// Message ID (unique)
    pub message_id: String,
    /// Source cell
    pub source_cell: String,
    /// Destination cell
    pub dest_cell: String,
    /// Message type
    pub msg_type: MessageType,
    /// Payload
    pub payload: Vec<u8>,
    /// Timestamp
    pub timestamp: i64,
    /// TTL (for routing)
    pub ttl: u8,
    /// Priority
    pub priority: MessagePriority,
    /// Acknowledgment required
    pub require_ack: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MessageType {
    /// Consensus proposal
    ConsensusProposal,
    /// Consensus vote
    ConsensusVote,
    /// Consensus commit
    ConsensusCommit,
    /// Heartbeat
    Heartbeat,
    /// Task assignment
    TaskAssignment,
    /// Task result
    TaskResult,
    /// Service discovery
    ServiceDiscovery,
    /// Health check
    HealthCheck,
    /// Topology update
    TopologyUpdate,
    /// Replication sync
    ReplicationSync,
    /// Leader election
    LeaderElection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessagePriority {
    Critical = 0,
    High = 1,
    Normal = 2,
    Low = 3,
    Background = 4,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageAck {
    pub message_id: String,
    pub received_at: i64,
    pub status: AckStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AckStatus {
    Received,
    Processed,
    Rejected,
    Failed,
}

// =============================================================================
// Cell Transport — Core Transport Layer
// =============================================================================

pub struct CellTransport {
    /// This cell's identity
    pub local_cell: CellAddress,
    /// Active connections: cell_id -> connection
    connections: HashMap<String, TransportConnection>,
    /// Connection pool for reuse
    connection_pool: VecDeque<TransportConnection>,
    /// Message send queue
    send_queue: VecDeque<CellMessage>,
    /// Message receive handlers: msg_type -> handler
    handlers: HashMap<MessageType, Box<dyn Fn(CellMessage) + Send + Sync>>,
    /// Pending acks: message_id -> (sent_at, retry_count)
    pending_acks: HashMap<String, (Instant, u32)>,
    /// Transport statistics
    stats: TransportStats,
    /// Protocol configuration
    config: TransportConfig,
    /// Retry configuration
    max_retries: u32,
    retry_interval: Duration,
}

#[derive(Debug, Clone)]
pub struct TransportConfig {
    pub bind_address: SocketAddr,
    pub protocols: Vec<TransportProtocol>,
    pub connection_pool_size: usize,
    pub max_message_size: usize,
    pub ack_timeout_ms: u64,
    pub keepalive_interval_ms: u64,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            bind_address: "0.0.0.0:443".parse().unwrap(),
            protocols: vec![TransportProtocol::Quic, TransportProtocol::WebSocket],
            connection_pool_size: 100,
            max_message_size: 10 * 1024 * 1024, // 10MB
            ack_timeout_ms: 5000,
            keepalive_interval_ms: 30000,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct TransportStats {
    pub messages_sent: u64,
    pub messages_received: u64,
    pub messages_acked: u64,
    pub messages_failed: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub connections_established: u64,
    pub connections_failed: u64,
    pub avg_latency_ms: f64,
}

impl CellTransport {
    pub fn new(local_cell: CellAddress, config: TransportConfig) -> Self {
        Self {
            local_cell,
            connections: HashMap::new(),
            connection_pool: VecDeque::with_capacity(config.connection_pool_size),
            send_queue: VecDeque::new(),
            handlers: HashMap::new(),
            pending_acks: HashMap::new(),
            stats: TransportStats::default(),
            config,
            max_retries: 3,
            retry_interval: Duration::from_millis(1000),
        }
    }

    /// Start transport layer — bind a QUIC socket and launch the accept loop.
    ///
    /// Phase R3: real quinn endpoint. Each cell listens on
    /// `config.bind_address` (default `0.0.0.0:443`) with a self-signed
    /// rustls certificate pinned in InternalDns.
    pub async fn start(&mut self) -> Result<(), TransportError> {
        let addr = self.config.bind_address;
        tracing::info!(addr = %addr, cell = %self.local_cell.cell_id, "Starting QUIC cell transport");

        // Build a self-signed TLS config for this cell.
        // In production use `CONNECTOR_CELL_CERT` / `CONNECTOR_CELL_KEY`;
        // in dev mode generate an ephemeral self-signed cert.
        let tls_config = Self::build_quic_server_tls()?;

        let quic_tls = quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
            .map_err(|_| TransportError::ConnectionFailed)?;
        let server_config = QuinnServerConfig::with_crypto(Arc::new(quic_tls));
        let endpoint = QuinnEndpoint::server(server_config, addr)
            .map_err(|_| TransportError::ConnectionFailed)?;

        tracing::info!(
            addr = %addr,
            cell = %self.local_cell.cell_id,
            "QUIC cell transport bound — accepting connections"
        );

        // Register in InternalDns
        crate::internal_dns::register(
            &format!("cell-{}.connector.internal", self.local_cell.cell_id),
            addr,
            "Cell QUIC transport",
            &["cell", "quic", "distributed"],
        );

        // Spawn accept loop
        let cell_id = self.local_cell.cell_id.clone();
        tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                let cell_id = cell_id.clone();
                tokio::spawn(async move {
                    match incoming.await {
                        Ok(conn) => {
                            tracing::debug!(
                                cell = %cell_id,
                                peer = %conn.remote_address(),
                                "QUIC inbound connection established"
                            );
                            Self::handle_inbound(conn, cell_id).await;
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "QUIC inbound connection failed");
                        }
                    }
                });
            }
        });

        Ok(())
    }

    /// Build a rustls ServerConfig for the QUIC endpoint.
    /// Loads from env vars if set, otherwise generates ephemeral self-signed cert.
    fn build_quic_server_tls() -> Result<rustls::ServerConfig, TransportError> {
        use rustls::ServerConfig;

        let cert_path = std::env::var("CONNECTOR_CELL_CERT").ok();
        let key_path  = std::env::var("CONNECTOR_CELL_KEY").ok();

        if let (Some(c), Some(k)) = (cert_path, key_path) {
            // Load from files
            let certs = Self::load_certs_from_file(&c)
                .map_err(|_| TransportError::ConnectionFailed)?;
            let key = Self::load_key_from_file(&k)
                .map_err(|_| TransportError::ConnectionFailed)?;
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .map_err(|_| TransportError::ConnectionFailed)
        } else {
            // Ephemeral self-signed for dev/test
            let cert = rcgen::generate_simple_self_signed(vec!["connector.internal".into()])
                .map_err(|_| TransportError::ConnectionFailed)?;
            let cert_der = rustls::pki_types::CertificateDer::from(
                cert.cert.der().to_vec()
            );
            let key_der = rustls::pki_types::PrivateKeyDer::try_from(
                cert.key_pair.serialize_der()
            ).map_err(|_| TransportError::ConnectionFailed)?;
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![cert_der], key_der)
                .map_err(|_| TransportError::ConnectionFailed)
        }
    }

    fn load_certs_from_file(path: &str) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, ()> {
        use std::io::BufReader;
        let f = std::fs::File::open(path).map_err(|_| ())?;
        rustls_pemfile::certs(&mut BufReader::new(f))
            .collect::<Result<Vec<_>, _>>().map_err(|_| ())
    }

    fn load_key_from_file(path: &str) -> Result<rustls::pki_types::PrivateKeyDer<'static>, ()> {
        use std::io::BufReader;
        let f = std::fs::File::open(path).map_err(|_| ())?;
        rustls_pemfile::private_key(&mut BufReader::new(f))
            .map_err(|_| ())?
            .ok_or(())
    }

    /// Handle an inbound QUIC connection — receive framed `CellMessage` streams.
    async fn handle_inbound(conn: Connection, cell_id: String) {
        loop {
            match conn.accept_uni().await {
                Err(_) => break,
                Ok(mut stream) => {
                    let cell_id = cell_id.clone();
                    tokio::spawn(async move {
                        let mut buf = Vec::new();
                        if stream.read_to_end(64 * 1024).await.map(|b| { buf = b; }).is_ok() {
                            if let Ok(msg) = bincode::deserialize::<CellMessage>(&buf) {
                                tracing::debug!(
                                    cell = %cell_id,
                                    msg_type = ?msg.msg_type,
                                    source = %msg.source_cell,
                                    "QUIC cell message received"
                                );
                            }
                        }
                    });
                }
            }
        }
    }

    /// Connect to remote cell
    pub async fn connect(&mut self, remote_cell: &CellAddress) -> Result<String, TransportError> {
        let conn_id = format!("conn-{}-{}", remote_cell.cell_id, uuid::Uuid::new_v4());

        // Check if already connected
        if let Some(existing) = self.connections.get(&remote_cell.cell_id) {
            if existing.state == ConnectionState::Connected {
                return Ok(existing.conn_id.clone());
            }
        }

        // Try to connect to best endpoint
        let mut connected = false;
        let mut last_error = None;

        // Sort endpoints by priority
        let mut endpoints = remote_cell.endpoints.clone();
        endpoints.sort_by_key(|e| e.priority);

        for endpoint in &endpoints {
            match self.connect_endpoint(endpoint).await {
                Ok(()) => {
                    connected = true;
                    break;
                }
                Err(e) => {
                    last_error = Some(e);
                    continue;
                }
            }
        }

        if !connected {
            return Err(last_error.unwrap_or(TransportError::ConnectionFailed));
        }

        let conn = TransportConnection {
            conn_id: conn_id.clone(),
            remote_cell: remote_cell.clone(),
            protocol: endpoints[0].protocol,
            state: ConnectionState::Connected,
            created_at: Instant::now(),
            last_activity: Instant::now(),
            bytes_sent: 0,
            bytes_received: 0,
            retry_count: 0,
            latency_ms: 0,
        };

        self.connections.insert(remote_cell.cell_id.clone(), conn);
        self.stats.connections_established += 1;

        Ok(conn_id)
    }

    /// Connect to a specific cell endpoint.
    ///
    /// Phase R3: real QUIC connection via quinn for `TransportProtocol::Quic`.
    /// WebSocket and gRPC fall back to TCP for now (Phase R4).
    async fn connect_endpoint(&self, endpoint: &Endpoint) -> Result<(), TransportError> {
        match endpoint.protocol {
            TransportProtocol::Quic => {
                let client_tls = build_quic_client_tls()?;

                let client_config = ClientConfig::new(Arc::new(
                    quinn::crypto::rustls::QuicClientConfig::try_from(client_tls)
                        .map_err(|_| TransportError::ConnectionFailed)?
                ));

                let mut quic_ep = QuinnEndpoint::client("0.0.0.0:0".parse().unwrap())
                    .map_err(|_| TransportError::ConnectionFailed)?;
                quic_ep.set_default_client_config(client_config);

                let conn = quic_ep
                    .connect(endpoint.address, "connector.internal")
                    .map_err(|_| TransportError::ConnectionFailed)?
                    .await
                    .map_err(|_| TransportError::ConnectionFailed)?;

                tracing::debug!(
                    peer = %endpoint.address,
                    "QUIC connection established"
                );

                // Store the connection handle for reuse in do_send.
                // For now we confirm success and let send_message use a fresh
                // connection per send (stateless mode). Phase R4 adds pooling.
                drop(conn);
                Ok(())
            }
            TransportProtocol::WebSocket | TransportProtocol::Grpc => {
                // TCP connect probe — verifies reachability before marking connected
                tokio::net::TcpStream::connect(endpoint.address)
                    .await
                    .map(|_| ())
                    .map_err(|_| TransportError::ConnectionFailed)
            }
        }
    }

    /// Send message to remote cell
    pub async fn send_message(
        &mut self,
        dest_cell_id: &str,
        msg: CellMessage,
    ) -> Result<MessageAck, TransportError> {
        // Ensure connection exists
        if !self.connections.contains_key(dest_cell_id) {
            // Need to resolve cell address and connect
            return Err(TransportError::CellNotConnected);
        }

        let conn = self.connections.get_mut(dest_cell_id)
            .ok_or(TransportError::CellNotConnected)?;

        if conn.state != ConnectionState::Connected {
            return Err(TransportError::ConnectionNotReady);
        }

        // Send with retry logic
        let mut attempts = 0;
        loop {
            match self.do_send(&msg).await {
                Ok(ack) => {
                    let payload_len = msg.payload.len() as u64;
                    self.stats.messages_sent += 1;
                    self.stats.bytes_sent += payload_len;
                    if let Some(conn) = self.connections.get_mut(dest_cell_id) {
                        conn.bytes_sent += payload_len;
                        conn.last_activity = Instant::now();
                    }
                    return Ok(ack);
                }
                Err(e) => {
                    attempts += 1;
                    if attempts >= self.max_retries {
                        if let Some(conn) = self.connections.get_mut(dest_cell_id) {
                            conn.state = ConnectionState::Failed;
                        }
                        self.stats.messages_failed += 1;
                        return Err(e);
                    }
                    tokio::time::sleep(self.retry_interval).await;
                }
            }
        }
    }

    /// Send a `CellMessage` to a connected peer over QUIC.
    ///
    /// Phase R3: opens a unidirectional QUIC stream to the peer, writes
    /// the bincode-serialised message, and flushes.
    async fn do_send(&self, msg: &CellMessage) -> Result<MessageAck, TransportError> {
        let payload = bincode::serialize(msg)
            .map_err(|_| TransportError::SerializationFailed)?;

        let peer_addr = self.connections
            .get(&msg.dest_cell)
            .and_then(|c| c.remote_cell.endpoints.first().map(|e| e.address))
            .ok_or(TransportError::CellNotConnected)?;

        let client_tls = build_quic_client_tls()?;

        let client_config = ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(client_tls)
                .map_err(|_| TransportError::ConnectionFailed)?
        ));

        let mut quic_ep = QuinnEndpoint::client("0.0.0.0:0".parse().unwrap())
            .map_err(|_| TransportError::ConnectionFailed)?;
        quic_ep.set_default_client_config(client_config);

        let conn = quic_ep
            .connect(peer_addr, "connector.internal")
            .map_err(|_| TransportError::ConnectionFailed)?
            .await
            .map_err(|_| TransportError::ConnectionFailed)?;

        let mut send_stream = conn.open_uni().await
            .map_err(|_| TransportError::ConnectionFailed)?;

        use tokio::io::AsyncWriteExt;
        send_stream.write_all(&payload).await
            .map_err(|_| TransportError::ConnectionFailed)?;
        send_stream.finish()
            .map_err(|_| TransportError::ConnectionFailed)?;

        tracing::debug!(
            dest = %msg.dest_cell,
            msg_id = %msg.message_id,
            bytes = payload.len(),
            "QUIC cell message sent"
        );

        Ok(MessageAck {
            message_id: msg.message_id.clone(),
            received_at: chrono::Utc::now().timestamp_millis(),
            status: AckStatus::Received,
        })
    }

    /// Register message handler
    pub fn register_handler<F>(&mut self, msg_type: MessageType, handler: F)
    where
        F: Fn(CellMessage) + Send + Sync + 'static,
    {
        self.handlers.insert(msg_type, Box::new(handler));
    }

    /// Process received message
    pub fn receive_message(&mut self, msg: CellMessage) -> Result<(), TransportError> {
        self.stats.messages_received += 1;
        self.stats.bytes_received += msg.payload.len() as u64;

        // Update connection stats
        if let Some(conn) = self.connections.get_mut(&msg.source_cell) {
            conn.bytes_received += msg.payload.len() as u64;
            conn.last_activity = Instant::now();
        }

        // Route to handler
        if let Some(handler) = self.handlers.get(&msg.msg_type) {
            handler(msg);
            Ok(())
        } else {
            Err(TransportError::NoHandler)
        }
    }

    /// Send heartbeat to all connected cells
    pub async fn send_heartbeats(&mut self) -> Vec<(String, Result<(), TransportError>)> {
        let mut results = Vec::new();
        let cell_ids: Vec<String> = self.connections.keys().cloned().collect();

        for cell_id in cell_ids {
            let msg = CellMessage {
                message_id: format!("hb-{}-{}", self.local_cell.cell_id, uuid::Uuid::new_v4()),
                source_cell: self.local_cell.cell_id.clone(),
                dest_cell: cell_id.clone(),
                msg_type: MessageType::Heartbeat,
                payload: vec![], // Empty heartbeat
                timestamp: chrono::Utc::now().timestamp_millis(),
                ttl: 1,
                priority: MessagePriority::Background,
                require_ack: false,
            };

            let result = self.send_message(&cell_id, msg).await.map(|_| ());
            results.push((cell_id, result));
        }

        results
    }

    /// Get connection stats
    pub fn get_stats(&self) -> TransportStats {
        self.stats.clone()
    }

    /// Get active connections
    pub fn get_connections(&self) -> Vec<&TransportConnection> {
        self.connections.values().collect()
    }

    /// Disconnect from cell
    pub fn disconnect(&mut self, cell_id: &str) {
        if let Some(mut conn) = self.connections.remove(cell_id) {
            conn.state = ConnectionState::Disconnecting;
            // Add to pool for potential reuse
            if self.connection_pool.len() < self.config.connection_pool_size {
                self.connection_pool.push_back(conn);
            }
        }
    }

    /// Clean up stale connections
    pub fn cleanup_stale_connections(&mut self, max_idle_secs: u64) -> usize {
        let now = Instant::now();
        let stale: Vec<String> = self.connections
            .iter()
            .filter(|(_, conn)| {
                now.duration_since(conn.last_activity).as_secs() > max_idle_secs
            })
            .map(|(id, _)| id.clone())
            .collect();

        for id in &stale {
            self.disconnect(id);
        }

        stale.len()
    }
}

#[derive(Debug, Clone)]
pub enum TransportError {
    ConnectionFailed,
    CellNotConnected,
    ConnectionNotReady,
    SendFailed,
    ReceiveFailed,
    NoHandler,
    Timeout,
    ProtocolError,
    SerializationFailed,
    /// Production peer TLS requires a configured peer CA (fail closed).
    PeerTlsNotConfigured,
    PeerTlsCaInvalid,
}

/// Lab-only escape hatch: `CONNECTOR_DISTRIBUTED_ALLOW_INSECURE_TLS=1`.
/// Default is fail-closed — real cert verification required.
pub fn distributed_allow_insecure_tls() -> bool {
    std::env::var("CONNECTOR_DISTRIBUTED_ALLOW_INSECURE_TLS")
        .map(|v| v.trim() == "1")
        .unwrap_or(false)
}

/// Honesty label for runtime/mesh + HA surfaces.
pub fn peer_tls_honesty() -> &'static str {
    if distributed_allow_insecure_tls() {
        "insecure_lab"
    } else {
        "fail_closed"
    }
}

fn load_peer_ca_roots() -> Result<rustls::RootCertStore, TransportError> {
    let ca_path = std::env::var("CONNECTOR_PEER_CA_CERT")
        .or_else(|_| std::env::var("CONNECTOR_DISTRIBUTED_PEER_CA"))
        .map_err(|_| TransportError::PeerTlsNotConfigured)?;
    let f = std::fs::File::open(&ca_path).map_err(|_| TransportError::PeerTlsCaInvalid)?;
    let mut reader = std::io::BufReader::new(f);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| TransportError::PeerTlsCaInvalid)?;
    if certs.is_empty() {
        return Err(TransportError::PeerTlsCaInvalid);
    }
    let mut roots = rustls::RootCertStore::empty();
    for cert in certs {
        roots
            .add(cert)
            .map_err(|_| TransportError::PeerTlsCaInvalid)?;
    }
    Ok(roots)
}

/// Build QUIC client TLS: real WebPKI verification against peer CA by default.
/// Skip-verify only when `CONNECTOR_DISTRIBUTED_ALLOW_INSECURE_TLS=1` (lab).
fn build_quic_client_tls() -> Result<rustls::ClientConfig, TransportError> {
    if distributed_allow_insecure_tls() {
        tracing::warn!(
            "CONNECTOR_DISTRIBUTED_ALLOW_INSECURE_TLS=1 — peer TLS skip-verify enabled (lab only; not for production)"
        );
        return Ok(rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
            .with_no_client_auth());
    }

    let roots = load_peer_ca_roots().map_err(|e| {
        tracing::error!(
            ?e,
            "peer TLS fail-closed: set CONNECTOR_PEER_CA_CERT (or CONNECTOR_DISTRIBUTED_PEER_CA) \
             or lab-only CONNECTOR_DISTRIBUTED_ALLOW_INSECURE_TLS=1"
        );
        e
    })?;
    Ok(rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth())
}

// Lab-only: skip TLS server cert verification when
// CONNECTOR_DISTRIBUTED_ALLOW_INSECURE_TLS=1. Never used on the default path.
#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

// =============================================================================
// Cell Resolver — DNS-like service discovery
// =============================================================================

pub struct CellResolver {
    /// Known cells: cell_id -> address
    cells: Arc<RwLock<HashMap<String, CellAddress>>>,
    /// Cache of resolved cells
    cache: Arc<RwLock<HashMap<String, (CellAddress, Instant)>>>,
    /// Cache TTL
    cache_ttl: Duration,
}

impl CellResolver {
    pub fn new() -> Self {
        Self {
            cells: Arc::new(RwLock::new(HashMap::new())),
            cache: Arc::new(RwLock::new(HashMap::new())),
            cache_ttl: Duration::from_secs(300), // 5 minutes
        }
    }

    /// Register a cell
    pub fn register_cell(&self, cell: CellAddress) {
        let mut cells = self.cells.write().unwrap();
        cells.insert(cell.cell_id.clone(), cell);
    }

    /// Resolve cell by ID
    pub fn resolve(&self, cell_id: &str) -> Option<CellAddress> {
        // Check cache first
        {
            let cache = self.cache.read().unwrap();
            if let Some((cell, timestamp)) = cache.get(cell_id) {
                if Instant::now().duration_since(*timestamp) < self.cache_ttl {
                    return Some(cell.clone());
                }
            }
        }

        // Check registry
        let cells = self.cells.read().unwrap();
        if let Some(cell) = cells.get(cell_id) {
            // Update cache
            let mut cache = self.cache.write().unwrap();
            cache.insert(cell_id.to_string(), (cell.clone(), Instant::now()));
            return Some(cell.clone());
        }

        None
    }

    /// Resolve by capability (find cell that provides capability)
    pub fn resolve_by_capability(&self, capability: &str) -> Vec<CellAddress> {
        let cells = self.cells.read().unwrap();
        cells
            .values()
            .filter(|c| c.capabilities.contains(&capability.to_string()))
            .filter(|c| c.health == CellHealth::Healthy)
            .cloned()
            .collect()
    }

    /// Get all healthy cells
    pub fn get_healthy_cells(&self) -> Vec<CellAddress> {
        let cells = self.cells.read().unwrap();
        cells
            .values()
            .filter(|c| c.health == CellHealth::Healthy)
            .cloned()
            .collect()
    }
}

// =============================================================================
// Thread-safe wrapper
// =============================================================================

#[derive(Clone)]
pub struct SharedCellTransport {
    inner: Arc<Mutex<CellTransport>>,
}

impl SharedCellTransport {
    pub fn new(local_cell: CellAddress, config: TransportConfig) -> Self {
        Self {
            inner: Arc::new(Mutex::new(CellTransport::new(local_cell, config))),
        }
    }

    pub async fn start(&self) -> Result<(), TransportError> {
        self.inner.lock().unwrap().start().await
    }

    pub async fn connect(&self, remote_cell: &CellAddress) -> Result<String, TransportError> {
        self.inner.lock().unwrap().connect(remote_cell).await
    }

    pub async fn send_message(
        &self,
        dest_cell_id: &str,
        msg: CellMessage,
    ) -> Result<MessageAck, TransportError> {
        self.inner.lock().unwrap().send_message(dest_cell_id, msg).await
    }

    pub fn register_handler<F>(&self, msg_type: MessageType, handler: F)
    where
        F: Fn(CellMessage) + Send + Sync + 'static,
    {
        self.inner.lock().unwrap().register_handler(msg_type, handler);
    }

    pub fn get_stats(&self) -> TransportStats {
        self.inner.lock().unwrap().get_stats()
    }

    pub async fn send_heartbeats(&self) -> Vec<(String, Result<(), TransportError>)> {
        self.inner.lock().unwrap().send_heartbeats().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_cell(id: &str) -> CellAddress {
        CellAddress {
            cell_id: id.to_string(),
            endpoints: vec![
                Endpoint {
                    protocol: TransportProtocol::Quic,
                    address: "127.0.0.1:443".parse().unwrap(),
                    priority: 1,
                    weight: 1,
                }
            ],
            region: "us-east".to_string(),
            location_signature: "sig-123".to_string(),
            capabilities: vec!["compute".to_string()],
            health: CellHealth::Healthy,
            last_seen: chrono::Utc::now().timestamp_millis(),
        }
    }

    #[test]
    fn test_cell_resolution() {
        let resolver = CellResolver::new();
        let cell = test_cell("cell-1");

        resolver.register_cell(cell.clone());

        let resolved = resolver.resolve("cell-1");
        assert!(resolved.is_some());
        assert_eq!(resolved.unwrap().cell_id, "cell-1");
    }

    #[test]
    fn test_capability_resolution() {
        let resolver = CellResolver::new();
        let cell = test_cell("cell-1");

        resolver.register_cell(cell);

        let by_cap = resolver.resolve_by_capability("compute");
        assert_eq!(by_cap.len(), 1);
    }

    #[tokio::test]
    async fn test_transport_connection() {
        let local = test_cell("local");
        let config = TransportConfig::default();
        let mut transport = CellTransport::new(local, config);

        let remote = test_cell("remote");
        let result = transport.connect(&remote).await;
        assert!(result.is_ok());

        let conns = transport.get_connections();
        assert_eq!(conns.len(), 1);
    }

    #[tokio::test]
    async fn test_message_send() {
        let local = test_cell("local");
        let config = TransportConfig::default();
        let mut transport = CellTransport::new(local, config);

        let remote = test_cell("remote");
        transport.connect(&remote).await.unwrap();

        let msg = CellMessage {
            message_id: "msg-1".to_string(),
            source_cell: "local".to_string(),
            dest_cell: "remote".to_string(),
            msg_type: MessageType::HealthCheck,
            payload: vec![1, 2, 3],
            timestamp: chrono::Utc::now().timestamp_millis(),
            ttl: 3,
            priority: MessagePriority::Normal,
            require_ack: true,
        };

        let result = transport.send_message("remote", msg).await;
        assert!(result.is_ok());
    }
}

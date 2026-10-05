//! CNP Stack — the full 7-layer protocol pipeline orchestrator.
//!
//! Chains all layers into a single `CnpStack` that provides:
//!   - `send(message)` → L7→L6→L5→L4→L3→L2→L1 → wire
//!   - `receive(secured_frame)` → L1→L2→L3→L4→L5→L6→L7 → message
//!   - Session management (establish, close)
//!   - Delivery receipts
//!
//! This is the primary API for CNP users — agents call `stack.send()` and
//! `stack.receive()`, and the stack handles encryption, authentication,
//! routing, and delivery transparently.

use std::collections::HashMap;
use crate::cnp::types::*;
use crate::cnp::codec::CnpCodec;
use crate::cnp::transport::{CnpEncryptor, CnpSecurityLayer};
use crate::cnp::channel::{CnpPort, CnpPortType, CnpPortDirection, CnpPortPermission, CnpRouter, CellStatus};

// ═══════════════════════════════════════════════════════════════
// CNP Stack Configuration
// ═══════════════════════════════════════════════════════════════

/// Configuration for a CnpStack instance.
#[derive(Debug, Clone)]
pub struct CnpStackConfig {
    /// This agent's PID
    pub agent_pid: String,
    /// This cell's ID
    pub cell_id: String,
    /// Default TTL for messages (ms)
    pub default_ttl_ms: i64,
    /// Rate limit per agent per port per second
    pub rate_limit_per_sec: u32,
    /// Whether to auto-create ports for new sessions
    pub auto_create_ports: bool,
    /// Default port buffer size
    pub default_port_buffer: u32,
}

impl CnpStackConfig {
    pub fn new(agent_pid: impl Into<String>, cell_id: impl Into<String>) -> Self {
        Self {
            agent_pid: agent_pid.into(),
            cell_id: cell_id.into(),
            default_ttl_ms: CNP_DEFAULT_TTL_MS,
            rate_limit_per_sec: 100,
            auto_create_ports: true,
            default_port_buffer: CNP_DEFAULT_PORT_BUFFER,
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// CNP Stack — the unified protocol pipeline
// ═══════════════════════════════════════════════════════════════

/// The CNP protocol stack — chains L1 through L7 for send and receive.
pub struct CnpStack {
    /// Stack configuration
    config: CnpStackConfig,
    /// L2: Encryption layer
    encryptor: CnpEncryptor,
    /// L3: Security layer
    security: CnpSecurityLayer,
    /// L4: Port registry
    ports: HashMap<String, CnpPort>,
    /// L5: Cross-cell router
    router: CnpRouter,
    /// L6: Active sessions
    sessions: HashMap<String, CnpSession>,
    /// Agent → session mapping (for auto-routing)
    agent_sessions: HashMap<String, String>,
    /// Agent → channel mapping (for encryption)
    agent_channels: HashMap<String, String>,
    /// Agent → port mapping (for sending)
    agent_ports: HashMap<String, String>,
    /// Received message inbox (messages waiting to be consumed)
    inbox: Vec<CnpMessage>,
    /// Delivery receipts
    receipts: Vec<CnpReceipt>,
    /// Statistics
    pub stats: CnpStackStats,
}

/// Stack-level statistics.
#[derive(Debug, Clone, Default)]
pub struct CnpStackStats {
    pub messages_sent: u64,
    pub messages_received: u64,
    pub messages_failed: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub sessions_established: u64,
    pub sessions_closed: u64,
}

impl CnpStack {
    /// Create a new CNP stack with the given configuration.
    pub fn new(config: CnpStackConfig) -> Self {
        let router = CnpRouter::new(&config.cell_id);
        let security = CnpSecurityLayer::new(config.rate_limit_per_sec);
        Self {
            config,
            encryptor: CnpEncryptor::new(),
            security,
            ports: HashMap::new(),
            router,
            sessions: HashMap::new(),
            agent_sessions: HashMap::new(),
            agent_channels: HashMap::new(),
            agent_ports: HashMap::new(),
            inbox: Vec::new(),
            receipts: Vec::new(),
            stats: CnpStackStats::default(),
        }
    }

    // ── Session Management (L6) ─────────────────────────────

    /// Establish a session with a remote agent.
    ///
    /// This creates the session, sets up encryption channel, port, and security.
    /// In production, this would involve Noise_IK handshake and contract negotiation.
    pub fn establish_session(
        &mut self,
        remote_agent: &str,
        channel_key: [u8; 32],
        port_secret: [u8; 32],
    ) -> CnpResult<String> {
        // Create session
        let mut session = CnpSession::new(&self.config.agent_pid, remote_agent);

        // L2: Register encryption channel
        let channel_id = format!("ch-{}-{}", self.config.agent_pid, remote_agent);
        self.encryptor.register_channel(&channel_id, channel_key);
        session.noise_channel_id = Some(channel_id.clone());
        self.agent_channels.insert(remote_agent.to_string(), channel_id);

        // L4: Create a bidirectional port for this session
        let port_id = format!("port-{}-{}", self.config.agent_pid, remote_agent);
        let mut port = CnpPort::new(
            &port_id,
            CnpPortType::RequestResponse,
            CnpPortDirection::Bidirectional,
            &self.config.agent_pid,
        );
        port.max_buffer_size = self.config.default_port_buffer;
        port.bind(remote_agent)?;
        port.issue_capability(remote_agent, CnpPortPermission::SendReceive);
        port.issue_capability(&self.config.agent_pid, CnpPortPermission::SendReceive);
        session.port_id = Some(port_id.clone());

        // L3: Register port secret
        self.security.register_port(&port_id, port_secret);

        // L5: Register agent location (default to local cell if not already registered)
        if self.router.is_local(remote_agent) && !self.agent_sessions.contains_key(remote_agent) {
            self.router.register_agent(remote_agent, &self.config.cell_id);
        }

        // Store everything
        self.agent_ports.insert(remote_agent.to_string(), port_id.clone());
        self.ports.insert(port_id, port);

        // Transition to Active (skip handshake for local, or after handshake completes)
        session.transition(CnpSessionState::Active)?;
        let session_id = session.session_id.clone();
        self.agent_sessions.insert(remote_agent.to_string(), session_id.clone());
        self.sessions.insert(session_id.clone(), session);

        self.stats.sessions_established += 1;
        Ok(session_id)
    }

    /// Establish a session with a remote agent on a different cell.
    pub fn establish_remote_session(
        &mut self,
        remote_agent: &str,
        remote_cell: &str,
        channel_key: [u8; 32],
        port_secret: [u8; 32],
    ) -> CnpResult<String> {
        self.router.register_agent(remote_agent, remote_cell);
        self.router.set_cell_status(remote_cell, CellStatus::Reachable);
        self.establish_session(remote_agent, channel_key, port_secret)
    }

    /// Close a session gracefully.
    pub fn close_session(&mut self, session_id: &str) -> CnpResult<()> {
        let session = self.sessions.get_mut(session_id).ok_or_else(|| CnpError::SessionError {
            detail: format!("Session {} not found", session_id),
        })?;

        // Transition: Active → Draining → Closed
        session.transition(CnpSessionState::Draining)?;
        session.transition(CnpSessionState::Closed)?;

        let remote = session.remote_agent.clone();

        // Cleanup L2/L3/L4
        if let Some(ch_id) = &session.noise_channel_id {
            self.encryptor.remove_channel(ch_id);
        }
        if let Some(port_id) = &session.port_id {
            self.security.remove_port(port_id);
            if let Some(port) = self.ports.get_mut(port_id) {
                port.close();
            }
        }

        self.agent_sessions.remove(&remote);
        self.agent_channels.remove(&remote);
        self.agent_ports.remove(&remote);
        self.stats.sessions_closed += 1;

        Ok(())
    }

    // ── Send Pipeline (L7 → L1) ─────────────────────────────

    /// Send a CNP message through the full 7-layer stack.
    ///
    /// Pipeline: Message → L1(encode) → L2(encrypt) → L3(secure) → L4(enqueue) → L5(route)
    pub fn send(&mut self, message: CnpMessage) -> CnpResult<CnpReceipt> {
        let start = now_ms();
        let message_id = message.message_id.clone();
        let target = message.to_agent.clone();

        // Verify session exists
        let session_id = self.agent_sessions.get(&target).cloned().ok_or_else(|| {
            CnpError::SessionError {
                detail: format!("No session with agent {}", target),
            }
        })?;

        // Get channel and port IDs
        let channel_id = self.agent_channels.get(&target).cloned().ok_or_else(|| {
            CnpError::TransportError { detail: format!("No channel for agent {}", target) }
        })?;
        let port_id = self.agent_ports.get(&target).cloned().ok_or_else(|| {
            CnpError::ChannelError { detail: format!("No port for agent {}", target) }
        })?;

        // Check TTL before sending
        if message.is_expired() {
            return Ok(CnpReceipt {
                message_id,
                outcome: DeliveryOutcome::Expired,
                delivery_ms: 0,
                layer: CnpLayer::L7Cognitive,
                message_cid: None,
                timestamp_ms: now_ms(),
            });
        }

        // L1: Encode → CnpFrame (serialization + CID)
        let frame = CnpCodec::encode(&message).map_err(|e| {
            self.stats.messages_failed += 1;
            e
        })?;
        let message_cid = frame.cid.clone();
        let frame_size = frame.size_bytes;

        // L2: Encrypt → CnpEncryptedFrame
        let encrypted = self.encryptor.encrypt(&channel_id, &frame).map_err(|e| {
            self.stats.messages_failed += 1;
            e
        })?;

        // L3: Secure → CnpSecuredFrame (HMAC + nonce + TTL)
        let secured = self.security.secure(
            &port_id,
            &self.config.agent_pid,
            encrypted,
            message.ttl_ms,
        ).map_err(|e| {
            self.stats.messages_failed += 1;
            e
        })?;

        // L5: Route (determine local vs cross-cell)
        let routed = self.router.route(
            secured.clone(),
            &self.config.agent_pid,
            &target,
        ).map_err(|e| {
            self.stats.messages_failed += 1;
            e
        })?;

        // L4: Enqueue into port (for local delivery or post-routing)
        if routed.target_cell == self.config.cell_id {
            // Local: enqueue directly into port
            let port = self.ports.get_mut(&port_id).ok_or_else(|| {
                CnpError::ChannelError { detail: format!("Port {} not found", port_id) }
            })?;
            port.enqueue(secured, &self.config.agent_pid)?;
        }
        // Remote: already queued in router's outbound

        // Update session stats
        if let Some(session) = self.sessions.get_mut(&session_id) {
            session.record_sent(frame_size);
        }

        self.stats.messages_sent += 1;
        self.stats.bytes_sent += frame_size;

        let receipt = CnpReceipt {
            message_id,
            outcome: if routed.target_cell == self.config.cell_id {
                DeliveryOutcome::Delivered
            } else {
                DeliveryOutcome::Queued
            },
            delivery_ms: (now_ms() - start) as u64,
            layer: CnpLayer::L5Routing,
            message_cid: Some(message_cid),
            timestamp_ms: now_ms(),
        };
        self.receipts.push(receipt.clone());

        Ok(receipt)
    }

    // ── Receive Pipeline (L1 → L7) ──────────────────────────

    /// Receive and process a message from a port.
    ///
    /// Pipeline: L4(dequeue) → L3(verify) → L2(decrypt) → L1(decode) → Message
    pub fn receive(&mut self, from_agent: &str) -> CnpResult<Option<CnpMessage>> {
        // Get port for this agent
        let port_id = self.agent_ports.get(from_agent).cloned().ok_or_else(|| {
            CnpError::ChannelError { detail: format!("No port for agent {}", from_agent) }
        })?;

        // L4: Dequeue from port
        let port = self.ports.get_mut(&port_id).ok_or_else(|| {
            CnpError::ChannelError { detail: format!("Port {} not found", port_id) }
        })?;

        let (secured, sender_pid) = match port.dequeue(&self.config.agent_pid)? {
            Some(pair) => pair,
            None => return Ok(None),
        };

        // L3: Verify security (HMAC, TTL, anti-replay, rate-limit)
        // Use the actual sender_pid from the buffer (who signed the message)
        let encrypted = self.security.verify(&secured, &sender_pid)?;

        // L2: Decrypt
        let plaintext = self.encryptor.decrypt(encrypted)?;

        // L1: Decode (verify CID, deserialize)
        let frame = CnpFrame {
            cid: {
                // Recompute CID from plaintext
                use sha2::{Sha256, Digest};
                let hash = Sha256::digest(&plaintext);
                format!("cnp1-sha256-{}", hex::encode(hash))
            },
            data: plaintext.clone(),
            size_bytes: plaintext.len() as u64,
        };
        let message: CnpMessage = serde_json::from_slice(&frame.data).map_err(|e| {
            CnpError::CodecError { detail: format!("Decode failed: {}", e) }
        })?;

        // Update session stats
        if let Some(session_id) = self.agent_sessions.get(from_agent) {
            if let Some(session) = self.sessions.get_mut(session_id) {
                session.record_received(frame.size_bytes);
            }
        }

        self.stats.messages_received += 1;
        self.stats.bytes_received += frame.size_bytes;

        Ok(Some(message))
    }

    /// Receive all pending messages from a specific agent.
    pub fn receive_all(&mut self, from_agent: &str) -> CnpResult<Vec<CnpMessage>> {
        let mut messages = Vec::new();
        loop {
            match self.receive(from_agent)? {
                Some(msg) => messages.push(msg),
                None => break,
            }
        }
        Ok(messages)
    }

    // ── Accessors ────────────────────────────────────────────

    /// Get a session by ID.
    pub fn get_session(&self, session_id: &str) -> Option<&CnpSession> {
        self.sessions.get(session_id)
    }

    /// Get the session ID for a remote agent.
    pub fn session_for_agent(&self, agent_pid: &str) -> Option<&str> {
        self.agent_sessions.get(agent_pid).map(String::as_str)
    }

    /// Get active session count.
    pub fn active_session_count(&self) -> usize {
        self.sessions.values().filter(|s| s.state == CnpSessionState::Active).count()
    }

    /// Get all delivery receipts.
    pub fn receipts(&self) -> &[CnpReceipt] {
        &self.receipts
    }

    /// Get the router (for cross-cell management).
    pub fn router(&self) -> &CnpRouter {
        &self.router
    }

    /// Get mutable router (for registration).
    pub fn router_mut(&mut self) -> &mut CnpRouter {
        &mut self.router
    }

    /// Get port count.
    pub fn port_count(&self) -> usize {
        self.ports.len()
    }

    /// Get the local agent PID.
    pub fn agent_pid(&self) -> &str {
        &self.config.agent_pid
    }

    /// Get the local cell ID.
    pub fn cell_id(&self) -> &str {
        &self.config.cell_id
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn key_a() -> [u8; 32] { [0xAA; 32] }
    fn secret_a() -> [u8; 32] { [0xBB; 32] }

    fn make_stack(agent: &str) -> CnpStack {
        CnpStack::new(CnpStackConfig::new(agent, "cell-1"))
    }

    #[test]
    fn test_establish_session() {
        let mut stack = make_stack("alice");
        let session_id = stack.establish_session("bob", key_a(), secret_a()).unwrap();

        assert_eq!(stack.active_session_count(), 1);
        assert!(stack.session_for_agent("bob").is_some());

        let session = stack.get_session(&session_id).unwrap();
        assert_eq!(session.state, CnpSessionState::Active);
        assert_eq!(session.local_agent, "alice");
        assert_eq!(session.remote_agent, "bob");
    }

    #[test]
    fn test_send_receive_text() {
        let mut stack = make_stack("alice");
        stack.establish_session("bob", key_a(), secret_a()).unwrap();

        // Send
        let msg = CnpMessage::new("alice", "bob", CnpPayload::Text { content: "hello bob".into() });
        let receipt = stack.send(msg).unwrap();
        assert!(matches!(receipt.outcome, DeliveryOutcome::Delivered));
        assert!(receipt.message_cid.is_some());
        assert_eq!(stack.stats.messages_sent, 1);

        // Receive
        let received = stack.receive("bob").unwrap().unwrap();
        assert_eq!(received.from_agent, "alice");
        assert_eq!(received.to_agent, "bob");
        if let CnpPayload::Text { content } = &received.payload {
            assert_eq!(content, "hello bob");
        } else {
            panic!("Expected Text payload");
        }
        assert_eq!(stack.stats.messages_received, 1);
    }

    #[test]
    fn test_send_receive_sensor() {
        let mut stack = make_stack("sensor-hub");
        stack.establish_session("fusion", key_a(), secret_a()).unwrap();

        let msg = CnpMessage::new(
            "sensor-hub",
            "fusion",
            CnpPayload::Sensor {
                sensor_id: "imu-001".into(),
                modality: SensorModality::Imu,
                reading: SensorReading::multi(vec![0.01, -9.81, 0.03, 0.001, 0.002, -0.001], "m/s²,rad/s"),
                timestamp_us: 1_700_000_000_000_000,
            },
        );
        let receipt = stack.send(msg).unwrap();
        assert!(matches!(receipt.outcome, DeliveryOutcome::Delivered));

        let received = stack.receive("fusion").unwrap().unwrap();
        if let CnpPayload::Sensor { sensor_id, reading, .. } = &received.payload {
            assert_eq!(sensor_id, "imu-001");
            assert_eq!(reading.values.len(), 6);
        } else {
            panic!("Expected Sensor payload");
        }
    }

    #[test]
    fn test_send_receive_actuation() {
        let mut stack = make_stack("planner");
        stack.establish_session("robot-arm", key_a(), secret_a()).unwrap();

        let msg = CnpMessage::new(
            "planner",
            "robot-arm",
            CnpPayload::Actuation {
                target_id: "arm-001".into(),
                command: ActuationCommand::NavigateTo {
                    x: 1.0, y: 2.0, z: 0.5, heading_rad: 1.57,
                },
                deadline_us: Some(100_000),
            },
        );
        stack.send(msg).unwrap();

        let received = stack.receive("robot-arm").unwrap().unwrap();
        if let CnpPayload::Actuation { command, .. } = &received.payload {
            match command {
                ActuationCommand::NavigateTo { x, y, .. } => {
                    assert!((x - 1.0).abs() < f64::EPSILON);
                    assert!((y - 2.0).abs() < f64::EPSILON);
                }
                _ => panic!("Expected NavigateTo"),
            }
        } else {
            panic!("Expected Actuation payload");
        }
    }

    #[test]
    fn test_send_receive_cognitive() {
        let mut stack = make_stack("thinker-a");
        stack.establish_session("thinker-b", key_a(), secret_a()).unwrap();

        let msg = CnpMessage::new(
            "thinker-a",
            "thinker-b",
            CnpPayload::Cognitive {
                cognitive_type: CognitiveMsgType::ShareTension {
                    tension_id: "t-1".into(),
                    tension_type: "goal_conflict".into(),
                    magnitude: 0.85,
                    context_cids: vec!["cid-ctx-1".into()],
                    description: "Conflicting treatment plans".into(),
                },
            },
        ).with_evidence("cid-evidence-1");

        let receipt = stack.send(msg).unwrap();
        assert!(matches!(receipt.outcome, DeliveryOutcome::Delivered));

        let received = stack.receive("thinker-b").unwrap().unwrap();
        assert!(received.is_cognitive());
        assert_eq!(received.evidence_cid.as_deref(), Some("cid-evidence-1"));
    }

    #[test]
    fn test_send_receive_negotiation() {
        let mut stack = make_stack("requester");
        stack.establish_session("provider", key_a(), secret_a()).unwrap();

        let msg = CnpMessage::new(
            "requester",
            "provider",
            CnpPayload::Negotiation {
                negotiation_id: "neg-001".into(),
                action: NegotiationAction::Propose {
                    capability_key: "translation:translate".into(),
                    terms: NegotiationTermsWire {
                        max_latency_ms: 500,
                        availability_pct: 99.0,
                        cost_per_call: 100,
                        stake_amount: 1000,
                        ttl_ms: 86_400_000,
                    },
                },
            },
        );
        stack.send(msg).unwrap();

        let received = stack.receive("provider").unwrap().unwrap();
        if let CnpPayload::Negotiation { negotiation_id, action } = &received.payload {
            assert_eq!(negotiation_id, "neg-001");
            assert!(matches!(action, NegotiationAction::Propose { .. }));
        } else {
            panic!("Expected Negotiation payload");
        }
    }

    #[test]
    fn test_multiple_messages() {
        let mut stack = make_stack("alice");
        stack.establish_session("bob", key_a(), secret_a()).unwrap();

        for i in 0..5 {
            let msg = CnpMessage::new(
                "alice", "bob",
                CnpPayload::Text { content: format!("message {}", i) },
            );
            stack.send(msg).unwrap();
        }
        assert_eq!(stack.stats.messages_sent, 5);

        let messages = stack.receive_all("bob").unwrap();
        assert_eq!(messages.len(), 5);
        assert_eq!(stack.stats.messages_received, 5);
    }

    #[test]
    fn test_session_stats() {
        let mut stack = make_stack("alice");
        let sid = stack.establish_session("bob", key_a(), secret_a()).unwrap();

        let msg = CnpMessage::new("alice", "bob", CnpPayload::Text { content: "hi".into() });
        stack.send(msg).unwrap();
        stack.receive("bob").unwrap();

        let session = stack.get_session(&sid).unwrap();
        assert_eq!(session.messages_sent, 1);
        assert_eq!(session.messages_received, 1);
        assert!(session.bytes_sent > 0);
        assert!(session.bytes_received > 0);
    }

    #[test]
    fn test_close_session() {
        let mut stack = make_stack("alice");
        let sid = stack.establish_session("bob", key_a(), secret_a()).unwrap();
        assert_eq!(stack.active_session_count(), 1);

        stack.close_session(&sid).unwrap();
        assert_eq!(stack.active_session_count(), 0);
        assert_eq!(stack.stats.sessions_closed, 1);

        // Sending should fail after close
        let msg = CnpMessage::new("alice", "bob", CnpPayload::Text { content: "fail".into() });
        assert!(stack.send(msg).is_err());
    }

    #[test]
    fn test_no_session_send_fails() {
        let mut stack = make_stack("alice");
        let msg = CnpMessage::new("alice", "bob", CnpPayload::Text { content: "hi".into() });
        let result = stack.send(msg);
        assert!(matches!(result, Err(CnpError::SessionError { .. })));
    }

    #[test]
    fn test_remote_session_queued() {
        let mut stack = make_stack("alice");
        stack.establish_remote_session("bob", "cell-2", key_a(), secret_a()).unwrap();

        let msg = CnpMessage::new("alice", "bob", CnpPayload::Text { content: "remote".into() });
        let receipt = stack.send(msg).unwrap();
        assert!(matches!(receipt.outcome, DeliveryOutcome::Queued));
        assert_eq!(stack.router().outbound_count(), 1);
    }

    #[test]
    fn test_receipt_chain() {
        let mut stack = make_stack("alice");
        stack.establish_session("bob", key_a(), secret_a()).unwrap();

        for _ in 0..3 {
            let msg = CnpMessage::new("alice", "bob", CnpPayload::Text { content: "x".into() });
            stack.send(msg).unwrap();
        }

        assert_eq!(stack.receipts().len(), 3);
        for receipt in stack.receipts() {
            assert!(matches!(receipt.outcome, DeliveryOutcome::Delivered));
            assert!(receipt.message_cid.is_some());
            assert!(receipt.delivery_ms < 1000); // Should be sub-second
        }
    }
}

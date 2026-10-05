//! CNP Channel — L4 (Typed Port Channels) + L5 (Cross-Cell Routing).
//!
//! L4: Manages typed ports (MemoryShare, ToolDelegate, EventStream, RequestResponse,
//!     Broadcast, Pipeline) with direction, capability gating, and buffering.
//! L5: Routes messages across cells transparently — same API for local and remote.
//!
//! Together these layers provide the "structural plane" of CNP.

use std::collections::{HashMap, VecDeque};
use crate::cnp::types::*;

// ═══════════════════════════════════════════════════════════════
// L4: Port Channel Types
// ═══════════════════════════════════════════════════════════════

/// Port type — the kind of communication channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CnpPortType {
    /// Share memory packets between agents.
    MemoryShare,
    /// Delegate tool access to another agent.
    ToolDelegate,
    /// Subscribe to event streams.
    EventStream,
    /// Synchronous request-response.
    RequestResponse,
    /// One-to-many broadcast.
    Broadcast,
    /// Ordered pipeline chain.
    Pipeline,
}

/// Port direction — which way messages flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CnpPortDirection {
    Send,
    Receive,
    Bidirectional,
}

/// Port capability — what an agent is allowed to do on this port.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CnpPortCapability {
    pub port_id: String,
    pub holder_pid: String,
    pub permission: CnpPortPermission,
    pub max_message_size: usize,
    pub max_messages_per_minute: u32,
    pub allowed_payload_types: Vec<String>,
    pub expires_at: Option<i64>,
    /// Delegation depth (0 = original, incremented on each delegation)
    pub delegation_depth: u8,
}

impl CnpPortCapability {
    /// Attenuate this capability for delegation (can only restrict, never escalate).
    pub fn attenuate(
        &self,
        new_holder: &str,
        restrict_permission: Option<CnpPortPermission>,
        restrict_max_size: Option<usize>,
        restrict_rate: Option<u32>,
        restrict_expiry: Option<i64>,
    ) -> CnpResult<CnpPortCapability> {
        if self.delegation_depth >= CNP_MAX_DELEGATION_DEPTH {
            return Err(CnpError::ChannelError {
                detail: format!("Max delegation depth {} reached", CNP_MAX_DELEGATION_DEPTH),
            });
        }

        let permission = match restrict_permission {
            Some(p) => {
                // Can only restrict: Send+Receive → Send or Receive, not escalate
                if !self.permission.contains(&p) {
                    return Err(CnpError::SecurityError {
                        verdict: "Cannot escalate permission on delegation".into(),
                    });
                }
                p
            }
            None => self.permission,
        };

        let max_message_size = restrict_max_size
            .map(|s| s.min(self.max_message_size))
            .unwrap_or(self.max_message_size);

        let max_messages_per_minute = restrict_rate
            .map(|r| r.min(self.max_messages_per_minute))
            .unwrap_or(self.max_messages_per_minute);

        let expires_at = match (self.expires_at, restrict_expiry) {
            (Some(parent), Some(child)) => Some(parent.min(child)),
            (Some(parent), None) => Some(parent),
            (None, Some(child)) => Some(child),
            (None, None) => None,
        };

        Ok(CnpPortCapability {
            port_id: self.port_id.clone(),
            holder_pid: new_holder.to_string(),
            permission,
            max_message_size,
            max_messages_per_minute,
            allowed_payload_types: self.allowed_payload_types.clone(),
            expires_at,
            delegation_depth: self.delegation_depth + 1,
        })
    }

    /// Check if capability has expired.
    pub fn is_expired(&self) -> bool {
        self.expires_at.map_or(false, |exp| now_ms() > exp)
    }
}

/// Port permission levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CnpPortPermission {
    Send,
    Receive,
    SendReceive,
}

impl CnpPortPermission {
    /// Check if this permission contains/allows another.
    pub fn contains(&self, other: &CnpPortPermission) -> bool {
        match (self, other) {
            (CnpPortPermission::SendReceive, _) => true,
            (CnpPortPermission::Send, CnpPortPermission::Send) => true,
            (CnpPortPermission::Receive, CnpPortPermission::Receive) => true,
            _ => false,
        }
    }
}

use serde::{Serialize, Deserialize};

// ═══════════════════════════════════════════════════════════════
// L4: Port — a typed, capability-gated message channel
// ═══════════════════════════════════════════════════════════════

/// A CNP port — typed, directed, capability-gated channel between agents.
#[derive(Debug, Clone)]
pub struct CnpPort {
    pub port_id: String,
    pub port_type: CnpPortType,
    pub direction: CnpPortDirection,
    pub owner_pid: String,
    pub bound_agents: Vec<String>,
    pub buffered: bool,
    pub max_buffer_size: u32,
    pub closed: bool,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    /// Message buffer (for buffered ports)
    buffer: VecDeque<BufferedMessage>,
    /// Capabilities issued for this port
    capabilities: HashMap<String, CnpPortCapability>,
}

/// A message buffered in a port queue.
#[derive(Debug, Clone)]
struct BufferedMessage {
    pub secured_frame: CnpSecuredFrame,
    pub sender_pid: String,
    pub queued_at: i64,
}

impl CnpPort {
    /// Create a new port.
    pub fn new(
        port_id: impl Into<String>,
        port_type: CnpPortType,
        direction: CnpPortDirection,
        owner_pid: impl Into<String>,
    ) -> Self {
        Self {
            port_id: port_id.into(),
            port_type,
            direction,
            owner_pid: owner_pid.into(),
            bound_agents: Vec::new(),
            buffered: true,
            max_buffer_size: CNP_DEFAULT_PORT_BUFFER,
            closed: false,
            created_at: now_ms(),
            expires_at: None,
            buffer: VecDeque::new(),
            capabilities: HashMap::new(),
        }
    }

    /// Bind an agent to this port.
    pub fn bind(&mut self, agent_pid: &str) -> CnpResult<()> {
        if self.closed {
            return Err(CnpError::ChannelError { detail: "Port is closed".into() });
        }
        if !self.bound_agents.contains(&agent_pid.to_string()) {
            self.bound_agents.push(agent_pid.to_string());
        }
        Ok(())
    }

    /// Issue a capability for an agent on this port.
    pub fn issue_capability(
        &mut self,
        holder_pid: &str,
        permission: CnpPortPermission,
    ) -> CnpPortCapability {
        let cap = CnpPortCapability {
            port_id: self.port_id.clone(),
            holder_pid: holder_pid.to_string(),
            permission,
            max_message_size: CNP_MAX_MESSAGE_BYTES as usize,
            max_messages_per_minute: self.max_buffer_size * 4,
            allowed_payload_types: vec![],
            expires_at: self.expires_at,
            delegation_depth: 0,
        };
        self.capabilities.insert(holder_pid.to_string(), cap.clone());
        cap
    }

    /// Check if an agent has send permission.
    pub fn can_send(&self, agent_pid: &str) -> bool {
        if self.closed { return false; }
        // Owner always can based on direction
        if agent_pid == self.owner_pid {
            return matches!(self.direction, CnpPortDirection::Send | CnpPortDirection::Bidirectional);
        }
        // Bound agents check capabilities
        self.capabilities.get(agent_pid).map_or(false, |cap| {
            !cap.is_expired() && cap.permission.contains(&CnpPortPermission::Send)
        })
    }

    /// Check if an agent has receive permission.
    pub fn can_receive(&self, agent_pid: &str) -> bool {
        if self.closed { return false; }
        if agent_pid == self.owner_pid {
            return matches!(self.direction, CnpPortDirection::Receive | CnpPortDirection::Bidirectional);
        }
        self.capabilities.get(agent_pid).map_or(false, |cap| {
            !cap.is_expired() && cap.permission.contains(&CnpPortPermission::Receive)
        })
    }

    /// Enqueue a secured frame into the port buffer.
    pub fn enqueue(&mut self, frame: CnpSecuredFrame, sender_pid: &str) -> CnpResult<()> {
        if self.closed {
            return Err(CnpError::ChannelError { detail: "Port is closed".into() });
        }
        if !self.can_send(sender_pid) {
            return Err(CnpError::SecurityError {
                verdict: format!("Agent {} has no send permission on port {}", sender_pid, self.port_id),
            });
        }
        if self.buffer.len() as u32 >= self.max_buffer_size {
            return Err(CnpError::ChannelError {
                detail: format!("Port buffer full ({}/{})", self.buffer.len(), self.max_buffer_size),
            });
        }

        self.buffer.push_back(BufferedMessage {
            secured_frame: frame,
            sender_pid: sender_pid.to_string(),
            queued_at: now_ms(),
        });
        Ok(())
    }

    /// Dequeue next message for a receiver.
    /// Returns (secured_frame, sender_pid) so the caller can verify the HMAC
    /// against the actual sender.
    pub fn dequeue(&mut self, receiver_pid: &str) -> CnpResult<Option<(CnpSecuredFrame, String)>> {
        if !self.can_receive(receiver_pid) {
            return Err(CnpError::SecurityError {
                verdict: format!("Agent {} has no receive permission on port {}", receiver_pid, self.port_id),
            });
        }
        Ok(self.buffer.pop_front().map(|bm| (bm.secured_frame, bm.sender_pid)))
    }

    /// Get buffer length.
    pub fn buffer_len(&self) -> usize {
        self.buffer.len()
    }

    /// Close the port.
    pub fn close(&mut self) {
        self.closed = true;
    }

    /// Check if port is active (not closed, not expired).
    pub fn is_active(&self) -> bool {
        !self.closed && !self.expires_at.map_or(false, |exp| now_ms() > exp)
    }
}

// ═══════════════════════════════════════════════════════════════
// L5: Cross-Cell Router
// ═══════════════════════════════════════════════════════════════

/// Cell reachability status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CellStatus {
    Reachable,
    Degraded,
    Unreachable,
}

/// L5 Router — routes messages across cells with delivery guarantees.
pub struct CnpRouter {
    /// This cell's ID
    pub local_cell_id: String,
    /// Agent → cell mapping (which cell hosts which agent)
    agent_locations: HashMap<String, String>,
    /// Cell status tracking
    cell_status: HashMap<String, CellStatus>,
    /// Outbound queue: messages waiting for delivery
    outbound: VecDeque<CnpRoutedMessage>,
    /// Dead-letter queue: messages that failed delivery after max retries
    dead_letters: VecDeque<CnpRoutedMessage>,
    /// Delivered message IDs (for dedup)
    delivered: VecDeque<String>,
    /// Max delivered history size
    max_delivered_history: usize,
}

impl CnpRouter {
    pub fn new(local_cell_id: impl Into<String>) -> Self {
        Self {
            local_cell_id: local_cell_id.into(),
            agent_locations: HashMap::new(),
            cell_status: HashMap::new(),
            outbound: VecDeque::new(),
            dead_letters: VecDeque::new(),
            delivered: VecDeque::new(),
            max_delivered_history: 10_000,
        }
    }

    /// Register an agent's cell location.
    pub fn register_agent(&mut self, agent_pid: &str, cell_id: &str) {
        self.agent_locations.insert(agent_pid.to_string(), cell_id.to_string());
    }

    /// Update cell status.
    pub fn set_cell_status(&mut self, cell_id: &str, status: CellStatus) {
        self.cell_status.insert(cell_id.to_string(), status);
    }

    /// Is target agent local to this cell?
    pub fn is_local(&self, agent_pid: &str) -> bool {
        self.agent_locations.get(agent_pid)
            .map_or(true, |cell| cell == &self.local_cell_id)
    }

    /// Route a secured frame to the target agent.
    ///
    /// Returns a CnpRoutedMessage with routing metadata.
    /// If the agent is local, target_cell == local_cell_id.
    /// If remote, the message is queued for cross-cell delivery.
    pub fn route(
        &mut self,
        secured: CnpSecuredFrame,
        source_agent: &str,
        target_agent: &str,
    ) -> CnpResult<CnpRoutedMessage> {
        let target_cell = self.agent_locations
            .get(target_agent)
            .cloned()
            .unwrap_or_else(|| self.local_cell_id.clone());

        // Check cell reachability for remote messages
        if target_cell != self.local_cell_id {
            let status = self.cell_status.get(&target_cell).unwrap_or(&CellStatus::Reachable);
            if *status == CellStatus::Unreachable {
                return Err(CnpError::RoutingError {
                    detail: format!("Target cell {} is unreachable", target_cell),
                });
            }
        }

        let routed = CnpRoutedMessage {
            secured,
            source_cell: self.local_cell_id.clone(),
            target_cell,
            source_agent: source_agent.to_string(),
            target_agent: target_agent.to_string(),
            attempt: 1,
        };

        // Queue for cross-cell delivery if remote
        if routed.target_cell != self.local_cell_id {
            self.outbound.push_back(routed.clone());
        }

        Ok(routed)
    }

    /// Acknowledge delivery of a message (by message nonce).
    pub fn acknowledge(&mut self, message_nonce: u64) {
        let nonce_str = format!("nonce-{}", message_nonce);
        self.delivered.push_back(nonce_str);
        if self.delivered.len() > self.max_delivered_history {
            self.delivered.pop_front();
        }
        // Remove from outbound queue
        self.outbound.retain(|m| m.secured.nonce != message_nonce);
    }

    /// Retry failed deliveries. Returns messages that exceeded max retries (→ dead letter).
    pub fn retry_failed(&mut self) -> Vec<CnpRoutedMessage> {
        let mut dead = Vec::new();
        let mut remaining = VecDeque::new();

        while let Some(mut msg) = self.outbound.pop_front() {
            msg.attempt += 1;
            if msg.attempt > CNP_MAX_RETRIES {
                dead.push(msg.clone());
                self.dead_letters.push_back(msg);
            } else {
                remaining.push_back(msg);
            }
        }

        self.outbound = remaining;
        dead
    }

    /// Get pending outbound messages.
    pub fn outbound_count(&self) -> usize {
        self.outbound.len()
    }

    /// Get dead-letter count.
    pub fn dead_letter_count(&self) -> usize {
        self.dead_letters.len()
    }

    /// Drain dead-letter queue.
    pub fn drain_dead_letters(&mut self) -> Vec<CnpRoutedMessage> {
        self.dead_letters.drain(..).collect()
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

    fn make_secured_frame(nonce: u64) -> CnpSecuredFrame {
        CnpSecuredFrame {
            encrypted: CnpEncryptedFrame {
                channel_id: "ch-1".into(),
                ciphertext: vec![1, 2, 3],
                counter: 0,
            },
            port_id: "port-1".into(),
            signature: "sig".into(),
            nonce,
            ttl_ms: 30_000,
            timestamp_ms: now_ms(),
        }
    }

    // ── L4 Port Tests ──────────────────────────────────────────

    #[test]
    fn test_port_create_bind() {
        let mut port = CnpPort::new("p1", CnpPortType::RequestResponse, CnpPortDirection::Bidirectional, "owner");
        assert!(port.is_active());
        port.bind("agent-b").unwrap();
        assert_eq!(port.bound_agents.len(), 1);
    }

    #[test]
    fn test_port_capability_send_receive() {
        let mut port = CnpPort::new("p1", CnpPortType::RequestResponse, CnpPortDirection::Bidirectional, "owner");
        port.bind("agent-b").unwrap();
        port.issue_capability("agent-b", CnpPortPermission::SendReceive);

        assert!(port.can_send("owner"));
        assert!(port.can_receive("owner"));
        assert!(port.can_send("agent-b"));
        assert!(port.can_receive("agent-b"));
        assert!(!port.can_send("outsider"));
    }

    #[test]
    fn test_port_enqueue_dequeue() {
        let mut port = CnpPort::new("p1", CnpPortType::EventStream, CnpPortDirection::Send, "owner");
        port.bind("agent-b").unwrap();
        port.issue_capability("agent-b", CnpPortPermission::Receive);

        let frame = make_secured_frame(1);
        port.enqueue(frame, "owner").unwrap();
        assert_eq!(port.buffer_len(), 1);

        let received = port.dequeue("agent-b").unwrap();
        assert!(received.is_some());
        let (_, sender) = received.unwrap();
        assert_eq!(sender, "owner");
        assert_eq!(port.buffer_len(), 0);
    }

    #[test]
    fn test_port_closed_rejects() {
        let mut port = CnpPort::new("p1", CnpPortType::EventStream, CnpPortDirection::Send, "owner");
        port.close();
        assert!(!port.is_active());
        assert!(port.enqueue(make_secured_frame(1), "owner").is_err());
    }

    #[test]
    fn test_capability_attenuation() {
        let cap = CnpPortCapability {
            port_id: "p1".into(),
            holder_pid: "owner".into(),
            permission: CnpPortPermission::SendReceive,
            max_message_size: 65536,
            max_messages_per_minute: 1000,
            allowed_payload_types: vec![],
            expires_at: None,
            delegation_depth: 0,
        };

        // Delegate with restriction
        let child = cap.attenuate(
            "agent-b",
            Some(CnpPortPermission::Receive), // Restrict to receive-only
            Some(32768),                        // Smaller max size
            Some(500),                          // Lower rate
            None,
        ).unwrap();

        assert_eq!(child.holder_pid, "agent-b");
        assert_eq!(child.permission, CnpPortPermission::Receive);
        assert_eq!(child.max_message_size, 32768);
        assert_eq!(child.max_messages_per_minute, 500);
        assert_eq!(child.delegation_depth, 1);
    }

    #[test]
    fn test_capability_cannot_escalate() {
        let cap = CnpPortCapability {
            port_id: "p1".into(),
            holder_pid: "agent-b".into(),
            permission: CnpPortPermission::Receive,
            max_message_size: 65536,
            max_messages_per_minute: 1000,
            allowed_payload_types: vec![],
            expires_at: None,
            delegation_depth: 0,
        };

        // Try to escalate Receive → Send
        let result = cap.attenuate("agent-c", Some(CnpPortPermission::Send), None, None, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_max_delegation_depth() {
        let mut cap = CnpPortCapability {
            port_id: "p1".into(),
            holder_pid: "a".into(),
            permission: CnpPortPermission::SendReceive,
            max_message_size: 65536,
            max_messages_per_minute: 1000,
            allowed_payload_types: vec![],
            expires_at: None,
            delegation_depth: 0,
        };

        // Delegate through the chain
        for i in 0..CNP_MAX_DELEGATION_DEPTH {
            cap = cap.attenuate(&format!("agent-{}", i + 1), None, None, None, None).unwrap();
        }

        // Next delegation should fail
        assert!(cap.attenuate("too-deep", None, None, None, None).is_err());
    }

    // ── L5 Router Tests ────────────────────────────────────────

    #[test]
    fn test_router_local_delivery() {
        let mut router = CnpRouter::new("cell-1");
        router.register_agent("agent-a", "cell-1");
        router.register_agent("agent-b", "cell-1");

        let routed = router.route(make_secured_frame(1), "agent-a", "agent-b").unwrap();
        assert_eq!(routed.target_cell, "cell-1");
        assert!(router.is_local("agent-b"));
        assert_eq!(router.outbound_count(), 0); // Local = no outbound queue
    }

    #[test]
    fn test_router_remote_delivery() {
        let mut router = CnpRouter::new("cell-1");
        router.register_agent("agent-a", "cell-1");
        router.register_agent("agent-b", "cell-2");
        router.set_cell_status("cell-2", CellStatus::Reachable);

        let routed = router.route(make_secured_frame(1), "agent-a", "agent-b").unwrap();
        assert_eq!(routed.target_cell, "cell-2");
        assert!(!router.is_local("agent-b"));
        assert_eq!(router.outbound_count(), 1);
    }

    #[test]
    fn test_router_unreachable_cell() {
        let mut router = CnpRouter::new("cell-1");
        router.register_agent("agent-b", "cell-2");
        router.set_cell_status("cell-2", CellStatus::Unreachable);

        let result = router.route(make_secured_frame(1), "agent-a", "agent-b");
        assert!(matches!(result, Err(CnpError::RoutingError { .. })));
    }

    #[test]
    fn test_router_acknowledge() {
        let mut router = CnpRouter::new("cell-1");
        router.register_agent("agent-b", "cell-2");
        router.set_cell_status("cell-2", CellStatus::Reachable);

        router.route(make_secured_frame(42), "agent-a", "agent-b").unwrap();
        assert_eq!(router.outbound_count(), 1);

        router.acknowledge(42);
        assert_eq!(router.outbound_count(), 0);
    }

    #[test]
    fn test_router_retry_and_dead_letter() {
        let mut router = CnpRouter::new("cell-1");
        router.register_agent("agent-b", "cell-2");
        router.set_cell_status("cell-2", CellStatus::Reachable);

        router.route(make_secured_frame(1), "agent-a", "agent-b").unwrap();

        // Retry until max retries exceeded
        for _ in 0..CNP_MAX_RETRIES {
            let dead = router.retry_failed();
            if !dead.is_empty() { break; }
        }

        assert_eq!(router.dead_letter_count(), 1);
        let dead = router.drain_dead_letters();
        assert_eq!(dead.len(), 1);
    }
}

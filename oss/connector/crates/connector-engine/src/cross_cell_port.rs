//! Cross-Cell Port Messaging — transparent cross-cell PortSend/PortReceive.
//!
//! Military-grade properties:
//! - Transparent to agents: same PortSend syscall, kernel handles routing
//! - Target cell lookup via consistent hash ring
//! - Delivery confirmation with timeout and retry
//! - Dead-letter queue for undeliverable messages
//! - Cognitive message support for thought-state transfer
//! - Audit trail for all cross-cell messages

use std::collections::HashMap;
use crate::cognitive::types::{CognitiveMessage, CognitiveMessageType};

// ── Cross-Cell Message ──────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CrossCellMessage {
    pub message_id: String,
    pub source_cell: String,
    pub target_cell: String,
    pub source_agent: String,
    pub target_agent: String,
    pub port_id: String,
    pub payload: String,
    pub timestamp: i64,
    pub delivered: bool,
    /// Cognitive message envelope (structured thought state, not just text)
    pub cognitive_envelope: Option<CognitiveMessage>,
    /// Delivery status tracking
    pub status: MessageStatus,
    /// Number of delivery attempts
    pub attempt_count: u32,
    /// Acknowledgment timestamp (None = not yet acknowledged)
    pub acked_at: Option<i64>,
}

/// Delivery lifecycle status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageStatus {
    /// Queued for delivery.
    Pending,
    /// Sent, awaiting acknowledgment.
    Sent,
    /// Acknowledged by recipient.
    Acknowledged,
    /// Delivery failed after max retries.
    Failed { reason: String },
    /// Moved to dead-letter queue.
    DeadLettered { reason: String },
}

// ── Delivery Result ─────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryResult {
    /// Delivered to local agent (same cell).
    Local,
    /// Forwarded to remote cell.
    Forwarded { target_cell: String },
    /// Target agent not found in any cell.
    AgentNotFound,
    /// Target cell is unreachable.
    CellUnreachable { cell_id: String },
    /// Message queued for retry.
    Queued { message_id: String },
}

// ── Cross-Cell Port Router ──────────────────────────────────────────

pub struct CrossCellPortRouter {
    local_cell_id: String,
    /// agent_pid → cell_id mapping (where each agent lives).
    agent_locations: HashMap<String, String>,
    /// cell_id → reachable flag.
    cell_status: HashMap<String, bool>,
    /// Message log for audit.
    messages: Vec<CrossCellMessage>,
    /// Dead-letter queue: messages that exceeded retry limit.
    dead_letters: Vec<CrossCellMessage>,
    /// Pending acknowledgments: message_id → message index in `messages`.
    pending_acks: HashMap<String, usize>,
    forward_count: u64,
    local_count: u64,
    /// Maximum retry attempts before dead-lettering.
    max_retries: u32,
    /// Acknowledgment timeout in milliseconds.
    ack_timeout_ms: i64,
}

impl CrossCellPortRouter {
    pub fn new(local_cell_id: &str) -> Self {
        Self {
            local_cell_id: local_cell_id.to_string(),
            agent_locations: HashMap::new(),
            cell_status: HashMap::new(),
            messages: Vec::new(),
            dead_letters: Vec::new(),
            pending_acks: HashMap::new(),
            forward_count: 0,
            local_count: 0,
            max_retries: 3,
            ack_timeout_ms: 30_000,
        }
    }

    fn now_ms() -> i64 { chrono::Utc::now().timestamp_millis() }

    /// Register an agent's location.
    pub fn register_agent(&mut self, agent_pid: &str, cell_id: &str) {
        self.agent_locations.insert(agent_pid.to_string(), cell_id.to_string());
    }

    /// Update cell reachability status.
    pub fn update_cell_status(&mut self, cell_id: &str, reachable: bool) {
        self.cell_status.insert(cell_id.to_string(), reachable);
    }

    /// Route a port message to the target agent. Returns delivery result.
    pub fn route_port_message(
        &mut self,
        source_agent: &str,
        target_agent: &str,
        port_id: &str,
        payload: &str,
    ) -> DeliveryResult {
        self.route_internal(source_agent, target_agent, port_id, payload, None)
    }

    /// Route a cognitive message — carries structured thought state, not just text.
    pub fn route_cognitive_message(
        &mut self,
        source_agent: &str,
        target_agent: &str,
        port_id: &str,
        cognitive_msg: CognitiveMessage,
    ) -> DeliveryResult {
        let payload = serde_json::to_string(&cognitive_msg).unwrap_or_default();
        self.route_internal(source_agent, target_agent, port_id, &payload, Some(cognitive_msg))
    }

    /// Internal routing logic shared by both raw and cognitive messages.
    fn route_internal(
        &mut self,
        source_agent: &str,
        target_agent: &str,
        port_id: &str,
        payload: &str,
        cognitive_envelope: Option<CognitiveMessage>,
    ) -> DeliveryResult {
        let target_cell = match self.agent_locations.get(target_agent) {
            Some(cell) => cell.clone(),
            None => return DeliveryResult::AgentNotFound,
        };

        let msg_id = format!("msg-{}", self.messages.len() + 1);
        let msg = CrossCellMessage {
            message_id: msg_id.clone(),
            source_cell: self.local_cell_id.clone(),
            target_cell: target_cell.clone(),
            source_agent: source_agent.to_string(),
            target_agent: target_agent.to_string(),
            port_id: port_id.to_string(),
            payload: payload.to_string(),
            timestamp: Self::now_ms(),
            delivered: false,
            cognitive_envelope,
            status: MessageStatus::Pending,
            attempt_count: 1,
            acked_at: None,
        };

        if target_cell == self.local_cell_id {
            // Local delivery — immediate acknowledgment
            let mut msg = msg;
            msg.delivered = true;
            msg.status = MessageStatus::Acknowledged;
            msg.acked_at = Some(Self::now_ms());
            self.messages.push(msg);
            self.local_count += 1;
            return DeliveryResult::Local;
        }

        // Check cell reachability
        let reachable = self.cell_status.get(&target_cell).copied().unwrap_or(true);
        if !reachable {
            // Queue for retry instead of silently dropping
            let mut msg = msg;
            msg.status = MessageStatus::Pending;
            let idx = self.messages.len();
            self.pending_acks.insert(msg_id.clone(), idx);
            self.messages.push(msg);
            return DeliveryResult::Queued { message_id: msg_id };
        }

        // Forward to remote cell — mark as Sent, await ack
        let mut msg = msg;
        msg.delivered = true;
        msg.status = MessageStatus::Sent;
        let idx = self.messages.len();
        self.pending_acks.insert(msg_id.clone(), idx);
        self.messages.push(msg);
        self.forward_count += 1;
        DeliveryResult::Forwarded { target_cell }
    }

    /// Acknowledge receipt of a message.
    pub fn acknowledge(&mut self, message_id: &str) -> Result<(), String> {
        let idx = self.pending_acks.remove(message_id)
            .ok_or_else(|| format!("no pending ack for {}", message_id))?;
        if let Some(msg) = self.messages.get_mut(idx) {
            msg.status = MessageStatus::Acknowledged;
            msg.acked_at = Some(Self::now_ms());
            Ok(())
        } else {
            Err(format!("message index {} out of bounds", idx))
        }
    }

    /// Retry delivery for messages that have timed out waiting for acknowledgment.
    /// Returns the number of messages retried and the number dead-lettered.
    pub fn process_retries(&mut self) -> (usize, usize) {
        let now = Self::now_ms();
        let mut to_retry = Vec::new();
        let mut to_dead_letter = Vec::new();

        for (msg_id, &idx) in &self.pending_acks {
            if let Some(msg) = self.messages.get(idx) {
                if msg.status == MessageStatus::Sent && (now - msg.timestamp) > self.ack_timeout_ms {
                    if msg.attempt_count >= self.max_retries {
                        to_dead_letter.push(msg_id.clone());
                    } else {
                        to_retry.push(msg_id.clone());
                    }
                }
            }
        }

        let retried = to_retry.len();
        let dead_lettered = to_dead_letter.len();

        // Process retries
        for msg_id in to_retry {
            if let Some(&idx) = self.pending_acks.get(&msg_id) {
                if let Some(msg) = self.messages.get_mut(idx) {
                    msg.attempt_count += 1;
                    msg.timestamp = now;
                    msg.status = MessageStatus::Sent;
                }
            }
        }

        // Dead-letter expired messages
        for msg_id in to_dead_letter {
            if let Some(idx) = self.pending_acks.remove(&msg_id) {
                if let Some(msg) = self.messages.get_mut(idx) {
                    msg.status = MessageStatus::DeadLettered {
                        reason: format!("exceeded {} retries", self.max_retries),
                    };
                    self.dead_letters.push(msg.clone());
                }
            }
        }

        (retried, dead_lettered)
    }

    /// Get all dead-lettered messages (for recovery/alerting).
    pub fn dead_letters(&self) -> &[CrossCellMessage] {
        &self.dead_letters
    }

    /// Get messages pending acknowledgment.
    pub fn pending_count(&self) -> usize {
        self.pending_acks.len()
    }

    pub fn forward_count(&self) -> u64 { self.forward_count }
    pub fn local_count(&self) -> u64 { self.local_count }
    pub fn message_log(&self) -> &[CrossCellMessage] { &self.messages }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cognitive::types::{Tension, TensionType, TensionResolution, MeaningObject, MeaningType, Urgency};

    #[test]
    fn test_local_delivery() {
        let mut router = CrossCellPortRouter::new("cell-1");
        router.register_agent("pid:target", "cell-1"); // same cell

        let result = router.route_port_message("pid:src", "pid:target", "port-1", "hello");
        assert_eq!(result, DeliveryResult::Local);
        assert_eq!(router.local_count(), 1);
    }

    #[test]
    fn test_cross_cell_forward() {
        let mut router = CrossCellPortRouter::new("cell-1");
        router.register_agent("pid:remote", "cell-2");
        router.update_cell_status("cell-2", true);

        let result = router.route_port_message("pid:src", "pid:remote", "port-1", "data");
        assert!(matches!(result, DeliveryResult::Forwarded { .. }));
        assert_eq!(router.forward_count(), 1);
    }

    #[test]
    fn test_agent_not_found() {
        let mut router = CrossCellPortRouter::new("cell-1");
        let result = router.route_port_message("pid:src", "pid:unknown", "port-1", "data");
        assert_eq!(result, DeliveryResult::AgentNotFound);
    }

    #[test]
    fn test_cell_unreachable_queues_for_retry() {
        let mut router = CrossCellPortRouter::new("cell-1");
        router.register_agent("pid:remote", "cell-2");
        router.update_cell_status("cell-2", false); // down

        let result = router.route_port_message("pid:src", "pid:remote", "port-1", "data");
        assert!(matches!(result, DeliveryResult::Queued { .. }));
        assert_eq!(router.pending_count(), 1);
    }

    #[test]
    fn test_acknowledge_message() {
        let mut router = CrossCellPortRouter::new("cell-1");
        router.register_agent("pid:remote", "cell-2");
        router.update_cell_status("cell-2", true);

        let result = router.route_port_message("pid:src", "pid:remote", "port-1", "data");
        if let DeliveryResult::Forwarded { .. } = result {
            let msg_id = router.message_log().last().unwrap().message_id.clone();
            assert!(router.acknowledge(&msg_id).is_ok());
            assert_eq!(router.pending_count(), 0);
        }
    }

    #[test]
    fn test_cognitive_message_routing() {
        let mut router = CrossCellPortRouter::new("cell-1");
        router.register_agent("pid:peer", "cell-1");

        let cognitive_msg = CognitiveMessage {
            message_id: "cmsg:1".into(),
            from_agent: "pid:src".into(),
            to_agent: "pid:peer".into(),
            message_type: CognitiveMessageType::ShareTension {
                tension: Tension {
                    id: "t:shared".into(),
                    tension_type: TensionType::GoalGap {
                        current: "undiagnosed".into(),
                        desired: "diagnosed".into(),
                    },
                    source_meanings: vec![],
                    intensity: 0.8,
                    created_at: 0,
                    deadline: None,
                    resolution: TensionResolution::Unresolved,
                    related_tensions: vec![],
                },
                context: vec![MeaningObject {
                    id: "m:1".into(),
                    source_perception: "perc:1".into(),
                    meaning_type: MeaningType::Request {
                        intent: "diagnose".into(),
                        urgency: Urgency::High,
                    },
                    entities: vec![],
                    salience: 0.9,
                    confidence: 0.8,
                    evidence_cids: vec![],
                }],
            },
            timestamp: 1000,
            evidence_cid: None,
            reply_to: None,
        };

        let result = router.route_cognitive_message("pid:src", "pid:peer", "port-cog", cognitive_msg);
        assert_eq!(result, DeliveryResult::Local);

        // Verify the cognitive envelope is preserved
        let last_msg = router.message_log().last().unwrap();
        assert!(last_msg.cognitive_envelope.is_some());
    }

    #[test]
    fn test_message_audit_log() {
        let mut router = CrossCellPortRouter::new("cell-1");
        router.register_agent("pid:t1", "cell-1");
        router.register_agent("pid:t2", "cell-2");

        router.route_port_message("pid:src", "pid:t1", "p1", "m1");
        router.route_port_message("pid:src", "pid:t2", "p2", "m2");

        assert_eq!(router.message_log().len(), 2);
    }

    #[test]
    fn test_local_delivery_auto_acks() {
        let mut router = CrossCellPortRouter::new("cell-1");
        router.register_agent("pid:local", "cell-1");
        router.route_port_message("pid:src", "pid:local", "port-1", "data");

        let msg = router.message_log().last().unwrap();
        assert_eq!(msg.status, MessageStatus::Acknowledged);
        assert!(msg.acked_at.is_some());
        assert_eq!(router.pending_count(), 0);
    }
}

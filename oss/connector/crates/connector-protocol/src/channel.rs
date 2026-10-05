//! Channel Layer (Layer 2) — Noise_IK handshake, encrypted channels, transport bindings.
//!
//! All Connector Protocol channels use Noise_IK for mutual authentication
//! with perfect forward secrecy. Transport bindings support TCP, UDP, serial, CAN, IPC, and in-process.

use serde::{Deserialize, Serialize};

use crate::error::{ProtocolError, ProtoResult};
use crate::identity::EntityId;

// ── Transport Binding ───────────────────────────────────────────────

/// Transport protocol binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportBinding {
    /// noise+tcp — reliable, ordered (default for services/agents)
    Tcp,
    /// noise+udp — low-latency, unordered (real-time control)
    Udp,
    /// noise+quic — multiplexed streams (high-bandwidth)
    Quic,
    /// noise+serial — direct serial link (embedded devices)
    Serial,
    /// noise+can — CAN bus (automotive/industrial)
    Can,
    /// noise+ipc — Unix domain socket (same-host)
    Ipc,
    /// noise+mem — in-process (zero-copy)
    InProcess,
}

impl TransportBinding {
    /// Parse a transport binding from a URI scheme.
    pub fn from_uri(uri: &str) -> ProtoResult<(Self, String)> {
        if let Some(rest) = uri.strip_prefix("noise+tcp://") {
            Ok((Self::Tcp, rest.to_string()))
        } else if let Some(rest) = uri.strip_prefix("noise+udp://") {
            Ok((Self::Udp, rest.to_string()))
        } else if let Some(rest) = uri.strip_prefix("noise+quic://") {
            Ok((Self::Quic, rest.to_string()))
        } else if let Some(rest) = uri.strip_prefix("noise+serial://") {
            Ok((Self::Serial, rest.to_string()))
        } else if let Some(rest) = uri.strip_prefix("noise+can://") {
            Ok((Self::Can, rest.to_string()))
        } else if let Some(rest) = uri.strip_prefix("noise+ipc://") {
            Ok((Self::Ipc, rest.to_string()))
        } else if let Some(rest) = uri.strip_prefix("noise+mem://") {
            Ok((Self::InProcess, rest.to_string()))
        } else if let Some(rest) = uri.strip_prefix("noise://") {
            Ok((Self::Tcp, rest.to_string())) // default
        } else {
            Err(ProtocolError::Channel(format!("Unknown transport: {}", uri)))
        }
    }

    /// Whether this transport provides reliable delivery.
    pub fn is_reliable(&self) -> bool {
        matches!(self, Self::Tcp | Self::Quic | Self::Ipc | Self::InProcess)
    }

    /// Whether this transport supports real-time priority scheduling.
    pub fn supports_realtime(&self) -> bool {
        matches!(self, Self::Udp | Self::Can | Self::Serial | Self::InProcess)
    }
}

// ── Channel Config ──────────────────────────────────────────────────

/// Configuration for a Noise_IK channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelConfig {
    /// Cipher suite (default: ChaCha20-Poly1305)
    pub cipher: String,
    /// Key exchange (default: X25519, future: ML-KEM-768 hybrid)
    pub key_exchange: String,
    /// Rekey interval in seconds (default: 120)
    pub rekey_interval_secs: u64,
    /// Max messages before forced rekey
    pub rekey_max_messages: u64,
    /// Keepalive interval in seconds (default: 25)
    pub keepalive_secs: u64,
    /// Replay protection window size in seconds
    pub replay_window_secs: u64,
    /// Max message size before fragmentation
    pub max_message_size: u32,
}

impl Default for ChannelConfig {
    fn default() -> Self {
        Self {
            cipher: "ChaChaPoly".to_string(),
            key_exchange: "X25519".to_string(),
            rekey_interval_secs: 120,
            rekey_max_messages: u64::MAX, // 2^64 per Noise spec
            keepalive_secs: 25,
            replay_window_secs: 30,
            max_message_size: 65535,
        }
    }
}

// ── Channel State ───────────────────────────────────────────────────

/// State of a Noise channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelState {
    /// Initial state, no handshake yet.
    Init,
    /// Handshake in progress.
    Handshaking,
    /// Channel established, ready for messages.
    Established,
    /// Channel is rekeying.
    Rekeying,
    /// Channel closed.
    Closed,
    /// Channel error.
    Error,
}

/// Represents an established protocol channel between two entities.
#[derive(Debug, Clone)]
pub struct Channel {
    pub channel_id: String,
    pub local_entity: EntityId,
    pub remote_entity: EntityId,
    pub transport: TransportBinding,
    pub state: ChannelState,
    pub config: ChannelConfig,
    pub established_at: i64,
    pub messages_sent: u64,
    pub messages_received: u64,
    pub last_activity: i64,
    pub last_rekey: i64,
}

impl Channel {
    /// Create a new channel (in Init state).
    pub fn new(
        local: EntityId,
        remote: EntityId,
        transport: TransportBinding,
    ) -> Self {
        let now = chrono::Utc::now().timestamp_millis();
        Self {
            channel_id: uuid::Uuid::new_v4().to_string(),
            local_entity: local,
            remote_entity: remote,
            transport,
            state: ChannelState::Init,
            config: ChannelConfig::default(),
            established_at: 0,
            messages_sent: 0,
            messages_received: 0,
            last_activity: now,
            last_rekey: 0,
        }
    }

    /// Transition to Established after successful handshake.
    pub fn establish(&mut self) -> ProtoResult<()> {
        if self.state != ChannelState::Init && self.state != ChannelState::Handshaking {
            return Err(ProtocolError::Channel(
                format!("Cannot establish from state {:?}", self.state),
            ));
        }
        let now = chrono::Utc::now().timestamp_millis();
        self.state = ChannelState::Established;
        self.established_at = now;
        self.last_rekey = now;
        Ok(())
    }

    /// Record a sent message.
    pub fn on_send(&mut self) {
        self.messages_sent += 1;
        self.last_activity = chrono::Utc::now().timestamp_millis();
    }

    /// Record a received message.
    pub fn on_receive(&mut self) {
        self.messages_received += 1;
        self.last_activity = chrono::Utc::now().timestamp_millis();
    }

    /// Check if rekey is needed.
    pub fn needs_rekey(&self) -> bool {
        if self.state != ChannelState::Established {
            return false;
        }
        let now = chrono::Utc::now().timestamp_millis();
        let elapsed_secs = (now - self.last_rekey) / 1000;
        elapsed_secs as u64 >= self.config.rekey_interval_secs
            || self.messages_sent >= self.config.rekey_max_messages
    }

    /// Close the channel.
    pub fn close(&mut self) {
        self.state = ChannelState::Closed;
    }

    /// Check if channel is usable.
    pub fn is_established(&self) -> bool {
        self.state == ChannelState::Established
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::EntityClass;

    fn aid(name: &str) -> EntityId { EntityId::new(EntityClass::Agent, name) }
    fn mid(name: &str) -> EntityId { EntityId::new(EntityClass::Machine, name) }

    #[test]
    fn test_transport_from_uri() {
        let (t, addr) = TransportBinding::from_uri("noise+tcp://192.168.1.100:7100").unwrap();
        assert_eq!(t, TransportBinding::Tcp);
        assert_eq!(addr, "192.168.1.100:7100");

        let (t, _) = TransportBinding::from_uri("noise+udp://host:7100").unwrap();
        assert_eq!(t, TransportBinding::Udp);

        let (t, _) = TransportBinding::from_uri("noise+serial:///dev/ttyS0").unwrap();
        assert_eq!(t, TransportBinding::Serial);

        let (t, _) = TransportBinding::from_uri("noise+can://can0/0x100").unwrap();
        assert_eq!(t, TransportBinding::Can);

        let (t, _) = TransportBinding::from_uri("noise://default:7100").unwrap();
        assert_eq!(t, TransportBinding::Tcp); // default

        assert!(TransportBinding::from_uri("http://bad").is_err());
    }

    #[test]
    fn test_transport_properties() {
        assert!(TransportBinding::Tcp.is_reliable());
        assert!(!TransportBinding::Udp.is_reliable());
        assert!(TransportBinding::Udp.supports_realtime());
        assert!(TransportBinding::Can.supports_realtime());
        assert!(!TransportBinding::Tcp.supports_realtime());
    }

    #[test]
    fn test_channel_lifecycle() {
        let mut ch = Channel::new(aid("a1"), mid("m1"), TransportBinding::Tcp);
        assert_eq!(ch.state, ChannelState::Init);
        assert!(!ch.is_established());

        ch.establish().unwrap();
        assert!(ch.is_established());

        ch.on_send();
        ch.on_receive();
        assert_eq!(ch.messages_sent, 1);
        assert_eq!(ch.messages_received, 1);

        ch.close();
        assert_eq!(ch.state, ChannelState::Closed);
        assert!(!ch.is_established());
    }

    #[test]
    fn test_channel_establish_from_closed_fails() {
        let mut ch = Channel::new(aid("a1"), mid("m1"), TransportBinding::Tcp);
        ch.establish().unwrap();
        ch.close();
        assert!(ch.establish().is_err());
    }

    #[test]
    fn test_channel_config_defaults() {
        let config = ChannelConfig::default();
        assert_eq!(config.cipher, "ChaChaPoly");
        assert_eq!(config.key_exchange, "X25519");
        assert_eq!(config.keepalive_secs, 25);
        assert_eq!(config.max_message_size, 65535);
    }
}

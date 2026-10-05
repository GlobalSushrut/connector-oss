//! ProtocolManager — External communication subsystem.
//!
//! Groups protocol-related engines:
//! - `GatewayBridgeManager` — External API gateway for agent communication
//! - `NoiseChannelManager` — Encrypted agent-to-agent channels
//! - `NegotiationManager` — Agent contract negotiation

use crate::gateway_bridge::GatewayBridgeManager;
use crate::noise_channel::NoiseChannelManager;
use crate::negotiation::NegotiationManager;

/// ProtocolManager — unified external communication layer.
///
/// Consolidates all protocol-related engines into a single manager,
/// providing a cohesive API for gateway access, encrypted channels, and negotiation.
pub struct ProtocolManager {
    /// GatewayBridgeManager — external API gateway
    pub gateway: GatewayBridgeManager,
    /// NoiseChannelManager — encrypted agent-to-agent channels
    pub noise_channels: NoiseChannelManager,
    /// NegotiationManager — agent contract negotiation
    pub negotiation: NegotiationManager,
}

impl ProtocolManager {
    /// Create a new ProtocolManager with default configurations.
    pub fn new() -> Self {
        Self {
            gateway: GatewayBridgeManager::new(),
            noise_channels: NoiseChannelManager::new(),
            negotiation: NegotiationManager::new(5, 60_000), // 5 rounds, 60s timeout
        }
    }

    /// Create with custom negotiation parameters.
    pub fn with_negotiation(mut self, max_rounds: u32, timeout_ms: i64) -> Self {
        self.negotiation = NegotiationManager::new(max_rounds, timeout_ms);
        self
    }

    /// Add a noise channel.
    pub fn add_channel(&mut self, channel: crate::noise_channel::NoiseChannel) {
        self.noise_channels.add_channel(channel);
    }

    /// Get a channel by ID.
    pub fn get_channel(&self, channel_id: &str) -> Option<&crate::noise_channel::NoiseChannel> {
        self.noise_channels.get(channel_id)
    }

    /// Get a mutable channel by ID.
    pub fn get_channel_mut(&mut self, channel_id: &str) -> Option<&mut crate::noise_channel::NoiseChannel> {
        self.noise_channels.get_mut(channel_id)
    }

    /// Remove a channel.
    pub fn remove_channel(&mut self, channel_id: &str) -> Option<crate::noise_channel::NoiseChannel> {
        self.noise_channels.remove(channel_id)
    }

    /// Get active channel count.
    pub fn channel_count(&self) -> usize {
        self.noise_channels.channel_count()
    }

    /// Get gateway manager reference.
    pub fn gateway(&self) -> &GatewayBridgeManager {
        &self.gateway
    }

    /// Get mutable gateway manager reference.
    pub fn gateway_mut(&mut self) -> &mut GatewayBridgeManager {
        &mut self.gateway
    }

    /// Get noise channel manager reference.
    pub fn noise_channels(&self) -> &NoiseChannelManager {
        &self.noise_channels
    }

    /// Get mutable noise channel manager reference.
    pub fn noise_channels_mut(&mut self) -> &mut NoiseChannelManager {
        &mut self.noise_channels
    }

    /// Get negotiation manager reference.
    pub fn negotiation(&self) -> &NegotiationManager {
        &self.negotiation
    }

    /// Get mutable negotiation manager reference.
    pub fn negotiation_mut(&mut self) -> &mut NegotiationManager {
        &mut self.negotiation
    }
}

impl Default for ProtocolManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_manager_creation() {
        let manager = ProtocolManager::new();
        assert_eq!(manager.channel_count(), 0);
    }

    #[test]
    fn test_channel_count() {
        let manager = ProtocolManager::new();
        assert_eq!(manager.channel_count(), 0);
    }
}

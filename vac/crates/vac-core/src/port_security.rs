//! Port Security Hardening — authenticated messages, anti-replay, capability attenuation.
//!
//! Every port message MUST be authenticated (HMAC signature), replay-protected (nonce window),
//! and time-bounded (TTL). Port capabilities attenuate on delegation (can only restrict, never escalate).
//!
//! Research: OWASP ASI07 (Insecure Inter-Agent Comms), NIST SP 800-207 Zero Trust,
//! UCAN capability attenuation, Noise Protocol Framework

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

// ═══════════════════════════════════════════════════════════════
// Secure Port Message
// ═══════════════════════════════════════════════════════════════

/// Authenticated port message with anti-replay and TTL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurePortMessage {
    pub message_id: String,
    pub port_id: String,
    pub sender_pid: String,
    /// HMAC-SHA256 of (port_id + sender_pid + payload + nonce + timestamp)
    pub signature: String,
    pub payload: String,
    pub timestamp_ms: i64,
    pub nonce: u64,
    pub ttl_ms: i64,
}

// ═══════════════════════════════════════════════════════════════
// Port Permissions & Capability
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum PortPermission {
    Receive    = 1,
    Send       = 2,
    SendReceive = 3,
}

/// A capability token for a port — attenuates on delegation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortCapability {
    pub port_id: String,
    pub holder_pid: String,
    pub permission: PortPermission,
    pub max_message_size: usize,
    pub max_messages_per_minute: u32,
    pub allowed_message_types: Vec<String>,
    pub expires_at: Option<i64>,
}

impl PortCapability {
    /// Check if this capability can be attenuated to produce `child`.
    /// Attenuation can only RESTRICT, never escalate.
    pub fn can_attenuate_to(&self, child: &PortCapability) -> bool {
        if child.port_id != self.port_id {
            return false;
        }
        // Permission can only be equal or more restrictive
        if (child.permission as u8) > (self.permission as u8) {
            return false;
        }
        // Max message size can only decrease or stay same
        if child.max_message_size > self.max_message_size {
            return false;
        }
        // Rate limit can only decrease or stay same
        if child.max_messages_per_minute > self.max_messages_per_minute {
            return false;
        }
        // Expiry can only be sooner or equal
        match (self.expires_at, child.expires_at) {
            (Some(parent_exp), Some(child_exp)) if child_exp > parent_exp => return false,
            (Some(_), None) => return false, // child must have expiry if parent does
            _ => {}
        }
        // Allowed types must be subset of parent's (if parent has restrictions)
        if !self.allowed_message_types.is_empty() {
            let parent_types: HashSet<&String> = self.allowed_message_types.iter().collect();
            for t in &child.allowed_message_types {
                if !parent_types.contains(t) {
                    return false;
                }
            }
        }
        true
    }
}

// ═══════════════════════════════════════════════════════════════
// Port Security Validator
// ═══════════════════════════════════════════════════════════════

/// Port-level security: signature verification, anti-replay, TTL, rate limiting.
pub struct PortSecurityValidator {
    /// Shared secret per port for HMAC verification (port_id → secret)
    port_secrets: HashMap<String, String>,
    /// Nonce window: recently seen nonces per port (port_id → set of nonces)
    nonce_windows: HashMap<String, HashSet<u64>>,
    /// Nonce window timestamps (port_id → oldest nonce timestamp)
    nonce_window_start: HashMap<String, i64>,
    /// Rate tracking: (port_id, sender_pid) → (count_this_minute, minute_start_ms)
    rate_counters: HashMap<(String, String), (u32, i64)>,
    /// Nonce window duration (default: 60_000ms = 60s)
    nonce_window_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortSecurityVerdict {
    Valid,
    InvalidSignature,
    ReplayDetected,
    Expired,
    RateLimitExceeded,
    MessageTooLarge { max: usize, actual: usize },
    PermissionDenied { required: String },
}

impl PortSecurityValidator {
    pub fn new() -> Self {
        Self {
            port_secrets: HashMap::new(),
            nonce_windows: HashMap::new(),
            nonce_window_start: HashMap::new(),
            rate_counters: HashMap::new(),
            nonce_window_ms: 60_000,
        }
    }

    /// Register a port with its shared secret for HMAC verification.
    pub fn register_port(&mut self, port_id: &str, secret: &str) {
        self.port_secrets.insert(port_id.to_string(), secret.to_string());
    }

    /// Compute HMAC signature for a message (simplified HMAC-SHA256 simulation).
    pub fn compute_signature(secret: &str, port_id: &str, sender: &str, payload: &str, nonce: u64, timestamp: i64) -> String {
        // Deterministic hash: SHA-256-like using std hash (real impl would use ring/hmac)
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut h = DefaultHasher::new();
        secret.hash(&mut h);
        port_id.hash(&mut h);
        sender.hash(&mut h);
        payload.hash(&mut h);
        nonce.hash(&mut h);
        timestamp.hash(&mut h);
        format!("{:016x}", h.finish())
    }

    /// Validate a secure port message: signature, anti-replay, TTL, rate limit.
    pub fn validate(
        &mut self,
        msg: &SecurePortMessage,
        now_ms: i64,
        cap: Option<&PortCapability>,
    ) -> PortSecurityVerdict {
        // 1. Signature verification
        let secret = match self.port_secrets.get(&msg.port_id) {
            Some(s) => s.clone(),
            None => return PortSecurityVerdict::InvalidSignature,
        };
        let expected_sig = Self::compute_signature(
            &secret, &msg.port_id, &msg.sender_pid, &msg.payload, msg.nonce, msg.timestamp_ms,
        );
        if msg.signature != expected_sig {
            return PortSecurityVerdict::InvalidSignature;
        }

        // 2. TTL check
        if now_ms - msg.timestamp_ms > msg.ttl_ms {
            return PortSecurityVerdict::Expired;
        }

        // 3. Anti-replay (nonce window)
        let nonces = self.nonce_windows.entry(msg.port_id.clone()).or_default();
        let window_start = self.nonce_window_start.entry(msg.port_id.clone()).or_insert(now_ms);
        // Flush old nonces if window expired
        if now_ms - *window_start > self.nonce_window_ms {
            nonces.clear();
            *window_start = now_ms;
        }
        if nonces.contains(&msg.nonce) {
            return PortSecurityVerdict::ReplayDetected;
        }
        nonces.insert(msg.nonce);

        // 4. Rate limiting (if capability provided)
        if let Some(c) = cap {
            if c.max_messages_per_minute > 0 {
                let key = (msg.port_id.clone(), msg.sender_pid.clone());
                let entry = self.rate_counters.entry(key).or_insert((0, now_ms));
                if now_ms - entry.1 >= 60_000 {
                    entry.0 = 0;
                    entry.1 = now_ms;
                }
                entry.0 += 1;
                if entry.0 > c.max_messages_per_minute {
                    return PortSecurityVerdict::RateLimitExceeded;
                }
            }
            // Message size check
            if c.max_message_size > 0 && msg.payload.len() > c.max_message_size {
                return PortSecurityVerdict::MessageTooLarge {
                    max: c.max_message_size, actual: msg.payload.len(),
                };
            }
        }

        PortSecurityVerdict::Valid
    }
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_validator() -> PortSecurityValidator {
        let mut v = PortSecurityValidator::new();
        v.register_port("port_1", "secret_key_123");
        v
    }

    fn make_valid_msg(nonce: u64, timestamp: i64) -> SecurePortMessage {
        let sig = PortSecurityValidator::compute_signature(
            "secret_key_123", "port_1", "agent_a", "hello world", nonce, timestamp,
        );
        SecurePortMessage {
            message_id: format!("msg_{}", nonce),
            port_id: "port_1".into(),
            sender_pid: "agent_a".into(),
            signature: sig,
            payload: "hello world".into(),
            timestamp_ms: timestamp,
            nonce,
            ttl_ms: 30_000,
        }
    }

    #[test]
    fn test_valid_message_passes() {
        let mut v = make_validator();
        let msg = make_valid_msg(1, 1000);
        assert_eq!(v.validate(&msg, 1000, None), PortSecurityVerdict::Valid);
    }

    #[test]
    fn test_invalid_signature_rejected() {
        let mut v = make_validator();
        let mut msg = make_valid_msg(1, 1000);
        msg.signature = "bad_signature".into();
        assert_eq!(v.validate(&msg, 1000, None), PortSecurityVerdict::InvalidSignature);
    }

    #[test]
    fn test_replay_detected() {
        let mut v = make_validator();
        let msg = make_valid_msg(42, 1000);
        assert_eq!(v.validate(&msg, 1000, None), PortSecurityVerdict::Valid);
        // Same nonce again → replay
        let msg2 = make_valid_msg(42, 1000);
        assert_eq!(v.validate(&msg2, 1000, None), PortSecurityVerdict::ReplayDetected);
    }

    #[test]
    fn test_expired_ttl_rejected() {
        let mut v = make_validator();
        let msg = make_valid_msg(1, 1000);
        // now is 32 seconds later, TTL is 30s
        assert_eq!(v.validate(&msg, 32_000, None), PortSecurityVerdict::Expired);
    }

    #[test]
    fn test_rate_limit_exceeded() {
        let mut v = make_validator();
        let cap = PortCapability {
            port_id: "port_1".into(),
            holder_pid: "agent_a".into(),
            permission: PortPermission::Send,
            max_message_size: 0,
            max_messages_per_minute: 3,
            allowed_message_types: vec![],
            expires_at: None,
        };
        for i in 0..3 {
            let msg = make_valid_msg(i + 100, 1000);
            assert_eq!(v.validate(&msg, 1000, Some(&cap)), PortSecurityVerdict::Valid);
        }
        let msg = make_valid_msg(200, 1000);
        assert_eq!(v.validate(&msg, 1000, Some(&cap)), PortSecurityVerdict::RateLimitExceeded);
    }

    #[test]
    fn test_message_too_large() {
        let mut v = make_validator();
        let cap = PortCapability {
            port_id: "port_1".into(),
            holder_pid: "agent_a".into(),
            permission: PortPermission::Send,
            max_message_size: 5,
            max_messages_per_minute: 0,
            allowed_message_types: vec![],
            expires_at: None,
        };
        let msg = make_valid_msg(1, 1000); // payload "hello world" = 11 bytes
        assert_eq!(
            v.validate(&msg, 1000, Some(&cap)),
            PortSecurityVerdict::MessageTooLarge { max: 5, actual: 11 }
        );
    }

    #[test]
    fn test_capability_attenuation_valid() {
        let parent = PortCapability {
            port_id: "port_1".into(),
            holder_pid: "agent_a".into(),
            permission: PortPermission::SendReceive,
            max_message_size: 1024,
            max_messages_per_minute: 100,
            allowed_message_types: vec!["data".into(), "control".into()],
            expires_at: Some(99999),
        };
        let child = PortCapability {
            port_id: "port_1".into(),
            holder_pid: "agent_b".into(),
            permission: PortPermission::Send, // more restrictive
            max_message_size: 512,            // smaller
            max_messages_per_minute: 50,      // fewer
            allowed_message_types: vec!["data".into()], // subset
            expires_at: Some(50000),          // sooner
        };
        assert!(parent.can_attenuate_to(&child));
    }

    #[test]
    fn test_capability_attenuation_rejects_escalation() {
        let parent = PortCapability {
            port_id: "port_1".into(),
            holder_pid: "agent_a".into(),
            permission: PortPermission::Send,
            max_message_size: 512,
            max_messages_per_minute: 50,
            allowed_message_types: vec![],
            expires_at: Some(50000),
        };
        // Tries to escalate to SendReceive
        let child = PortCapability {
            port_id: "port_1".into(),
            holder_pid: "agent_b".into(),
            permission: PortPermission::SendReceive,
            max_message_size: 512,
            max_messages_per_minute: 50,
            allowed_message_types: vec![],
            expires_at: Some(50000),
        };
        assert!(!parent.can_attenuate_to(&child));
    }

    #[test]
    fn test_capability_rejects_larger_message_size() {
        let parent = PortCapability {
            port_id: "port_1".into(), holder_pid: "a".into(),
            permission: PortPermission::Send, max_message_size: 100,
            max_messages_per_minute: 50, allowed_message_types: vec![],
            expires_at: None,
        };
        let child = PortCapability {
            port_id: "port_1".into(), holder_pid: "b".into(),
            permission: PortPermission::Send, max_message_size: 200, // escalation!
            max_messages_per_minute: 50, allowed_message_types: vec![],
            expires_at: None,
        };
        assert!(!parent.can_attenuate_to(&child));
    }

    #[test]
    fn test_nonce_window_resets() {
        let mut v = make_validator();
        v.nonce_window_ms = 100; // 100ms window for testing
        let msg1 = make_valid_msg(1, 1000);
        assert_eq!(v.validate(&msg1, 1000, None), PortSecurityVerdict::Valid);
        // Same nonce after window expires → should be valid again
        let msg2 = make_valid_msg(1, 1000);
        assert_eq!(v.validate(&msg2, 1200, None), PortSecurityVerdict::Valid);
    }
}

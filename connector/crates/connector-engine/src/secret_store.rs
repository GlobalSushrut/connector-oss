//! Secret Isolation — kernel-only secret storage with TTL, redaction, and opaque handles.
//!
//! Secrets stored in `/s/secrets/{agent_pid}/`, kernel-only write.
//! Never appear in audit logs (redacted to `[REDACTED:secret_id]`).
//! Opaque handle pattern: agent receives handle, kernel injects at tool call time.
//!
//! Research: NVIDIA Agentic Sandboxing (2026) — secret injection approach,
//! OWASP ASI03 (Identity/Privilege Abuse), NIST SP 800-53 SC-12/SC-13

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ═══════════════════════════════════════════════════════════════
// Secret Entry
// ═══════════════════════════════════════════════════════════════

/// A stored secret with TTL and metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretEntry {
    pub secret_id: String,
    pub agent_pid: String,
    /// The actual secret value (never logged, never exposed to agents directly)
    value: String,
    pub created_at_ms: i64,
    pub expires_at_ms: Option<i64>,
    pub description: String,
}

/// Opaque handle that agents receive instead of the actual secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretHandle {
    pub handle_id: String,
    pub secret_id: String,
    pub agent_pid: String,
    pub namespace: String,
}

// ═══════════════════════════════════════════════════════════════
// Secret Store
// ═══════════════════════════════════════════════════════════════

/// Kernel-only secret storage with TTL, redaction, and opaque handles.
pub struct SecretStore {
    secrets: HashMap<String, SecretEntry>,
    handles: HashMap<String, SecretHandle>,
    next_handle_id: u64,
}

impl SecretStore {
    pub fn new() -> Self {
        Self {
            secrets: HashMap::new(),
            handles: HashMap::new(),
            next_handle_id: 1,
        }
    }

    /// Store a secret (kernel-only operation).
    pub fn store_secret(
        &mut self,
        secret_id: &str,
        agent_pid: &str,
        value: &str,
        ttl_ms: Option<i64>,
        now_ms: i64,
        description: &str,
    ) -> Result<(), String> {
        if self.secrets.contains_key(secret_id) {
            return Err(format!("Secret '{}' already exists", secret_id));
        }
        self.secrets.insert(secret_id.to_string(), SecretEntry {
            secret_id: secret_id.to_string(),
            agent_pid: agent_pid.to_string(),
            value: value.to_string(),
            created_at_ms: now_ms,
            expires_at_ms: ttl_ms.map(|t| now_ms + t),
            description: description.to_string(),
        });
        Ok(())
    }

    /// Issue an opaque handle for an agent to reference a secret.
    pub fn issue_handle(&mut self, secret_id: &str, agent_pid: &str) -> Result<SecretHandle, String> {
        let entry = self.secrets.get(secret_id)
            .ok_or_else(|| format!("Secret '{}' not found", secret_id))?;
        if entry.agent_pid != agent_pid {
            return Err(format!("Agent '{}' does not own secret '{}'", agent_pid, secret_id));
        }
        let handle_id = format!("sh_{}", self.next_handle_id);
        self.next_handle_id += 1;
        let handle = SecretHandle {
            handle_id: handle_id.clone(),
            secret_id: secret_id.to_string(),
            agent_pid: agent_pid.to_string(),
            namespace: format!("s/secrets/{}", agent_pid),
        };
        self.handles.insert(handle_id, handle.clone());
        Ok(handle)
    }

    /// Resolve a handle to the actual secret value (kernel-only, at tool call time).
    pub fn resolve_handle(&self, handle_id: &str, now_ms: i64) -> Result<String, String> {
        let handle = self.handles.get(handle_id)
            .ok_or_else(|| format!("Handle '{}' not found", handle_id))?;
        let entry = self.secrets.get(&handle.secret_id)
            .ok_or_else(|| format!("Secret '{}' not found (handle dangling)", handle.secret_id))?;
        // Check TTL
        if let Some(exp) = entry.expires_at_ms {
            if now_ms > exp {
                return Err(format!("Secret '{}' has expired", entry.secret_id));
            }
        }
        Ok(entry.value.clone())
    }

    /// Redact secrets from a string for audit logging.
    /// Replaces any known secret values with `[REDACTED:secret_id]`.
    pub fn redact_for_audit(&self, text: &str) -> String {
        let mut result = text.to_string();
        for entry in self.secrets.values() {
            if !entry.value.is_empty() && result.contains(&entry.value) {
                result = result.replace(&entry.value, &format!("[REDACTED:{}]", entry.secret_id));
            }
        }
        result
    }

    /// Check if text contains any known secret values (for exfiltration detection).
    pub fn contains_secret(&self, text: &str) -> Option<String> {
        for entry in self.secrets.values() {
            if !entry.value.is_empty() && text.contains(&entry.value) {
                return Some(entry.secret_id.clone());
            }
        }
        None
    }

    /// Purge expired secrets.
    pub fn purge_expired(&mut self, now_ms: i64) -> usize {
        let expired: Vec<String> = self.secrets.iter()
            .filter(|(_, e)| e.expires_at_ms.map_or(false, |exp| now_ms > exp))
            .map(|(id, _)| id.clone())
            .collect();
        let count = expired.len();
        for id in &expired {
            self.secrets.remove(id);
            // Remove associated handles
            self.handles.retain(|_, h| h.secret_id != *id);
        }
        count
    }

    pub fn secret_count(&self) -> usize { self.secrets.len() }
    pub fn handle_count(&self) -> usize { self.handles.len() }
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_store_and_resolve() {
        let mut store = SecretStore::new();
        store.store_secret("api_key_1", "agent_a", "sk-abc123secret", None, 1000, "OpenAI key").unwrap();
        let handle = store.issue_handle("api_key_1", "agent_a").unwrap();
        let value = store.resolve_handle(&handle.handle_id, 1000).unwrap();
        assert_eq!(value, "sk-abc123secret");
    }

    #[test]
    fn test_ttl_expiry() {
        let mut store = SecretStore::new();
        store.store_secret("temp_key", "agent_a", "secret_value", Some(5000), 1000, "Temp").unwrap();
        let handle = store.issue_handle("temp_key", "agent_a").unwrap();
        // Within TTL
        assert!(store.resolve_handle(&handle.handle_id, 5000).is_ok());
        // After TTL (1000 + 5000 = 6000 expiry)
        assert!(store.resolve_handle(&handle.handle_id, 7000).is_err());
    }

    #[test]
    fn test_redaction() {
        let mut store = SecretStore::new();
        store.store_secret("my_key", "agent_a", "SUPER_SECRET_VALUE", None, 1000, "Key").unwrap();
        let text = "Using API key SUPER_SECRET_VALUE to call service";
        let redacted = store.redact_for_audit(text);
        assert_eq!(redacted, "Using API key [REDACTED:my_key] to call service");
        assert!(!redacted.contains("SUPER_SECRET_VALUE"));
    }

    #[test]
    fn test_cross_agent_denied() {
        let mut store = SecretStore::new();
        store.store_secret("key_1", "agent_a", "secret", None, 1000, "A's key").unwrap();
        // Agent B trying to get handle for Agent A's secret
        let result = store.issue_handle("key_1", "agent_b");
        assert!(result.is_err());
    }

    #[test]
    fn test_purge_expired() {
        let mut store = SecretStore::new();
        store.store_secret("k1", "a", "v1", Some(100), 1000, "").unwrap();
        store.store_secret("k2", "a", "v2", Some(200), 1000, "").unwrap();
        store.store_secret("k3", "a", "v3", None, 1000, "").unwrap(); // No expiry
        store.issue_handle("k1", "a").unwrap();
        assert_eq!(store.secret_count(), 3);
        assert_eq!(store.handle_count(), 1);
        let purged = store.purge_expired(1201); // k1 expired (1000+100=1100), k2 expired (1000+200=1200)
        assert_eq!(purged, 2);
        assert_eq!(store.secret_count(), 1);
        assert_eq!(store.handle_count(), 0); // Handle for k1 also removed
    }
}

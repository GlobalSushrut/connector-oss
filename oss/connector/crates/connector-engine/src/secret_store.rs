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

/// Handle metadata safe to expose over the API — never carries a secret value.
///
/// Lifecycle fields are `None` when the backing secret is gone, so a dangling
/// handle is reported as dangling rather than as a handle with a zero TTL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretHandleView {
    pub handle_id: String,
    pub secret_id: String,
    pub agent_pid: String,
    pub namespace: String,
    pub created_at_ms: Option<i64>,
    pub expires_at_ms: Option<i64>,
    pub description: Option<String>,
    pub dangling: bool,
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

    /// Whether a secret id is already stored (no value leaked).
    pub fn has_secret(&self, secret_id: &str) -> bool {
        self.secrets.contains_key(secret_id)
    }

    /// Kernel-only plaintext read for platform restore / Talk wiring.
    /// Never return this over HTTP.
    pub fn get_secret_value(&self, secret_id: &str, now_ms: i64) -> Result<String, String> {
        let entry = self
            .secrets
            .get(secret_id)
            .ok_or_else(|| format!("Secret '{}' not found", secret_id))?;
        if let Some(exp) = entry.expires_at_ms {
            if now_ms > exp {
                return Err(format!("Secret '{}' has expired", entry.secret_id));
            }
        }
        Ok(entry.value.clone())
    }

    pub fn secret_ids_with_prefix(&self, prefix: &str) -> Vec<String> {
        let mut ids: Vec<String> = self
            .secrets
            .keys()
            .filter(|k| k.starts_with(prefix))
            .cloned()
            .collect();
        ids.sort();
        ids
    }

    /// Store a new secret or replace the value if the id already exists.
    pub fn upsert_secret(
        &mut self,
        secret_id: &str,
        agent_pid: &str,
        value: &str,
        ttl_ms: Option<i64>,
        now_ms: i64,
        description: &str,
    ) -> Result<(), String> {
        if self.secrets.contains_key(secret_id) {
            self.rotate_secret(secret_id, value, ttl_ms, now_ms)
        } else {
            self.store_secret(secret_id, agent_pid, value, ttl_ms, now_ms, description)
        }
    }

    /// Replace a secret's value in place, refreshing its TTL.
    ///
    /// Handles reference the secret id, so every handle already issued keeps
    /// working and resolves to the new value.
    pub fn rotate_secret(
        &mut self,
        secret_id: &str,
        new_value: &str,
        new_ttl_ms: Option<i64>,
        now_ms: i64,
    ) -> Result<(), String> {
        let entry = self
            .secrets
            .get_mut(secret_id)
            .ok_or_else(|| format!("Secret '{}' not found", secret_id))?;
        entry.value = new_value.to_string();
        entry.created_at_ms = now_ms;
        entry.expires_at_ms = new_ttl_ms.map(|t| now_ms + t);
        Ok(())
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

    /// FIX BUG-027: Revoke a secret by ID (removes secret and all associated handles).
    pub fn revoke_secret(&mut self, secret_id: &str) -> Result<(), String> {
        if self.secrets.remove(secret_id).is_none() {
            return Err(format!("Secret '{}' not found", secret_id));
        }
        // Remove all handles pointing to this secret
        self.handles.retain(|_, h| h.secret_id != secret_id);
        Ok(())
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

    /// Handles issued to one agent, with lifecycle metadata but no secret values.
    pub fn handles_for_agent(&self, agent_pid: &str) -> Vec<SecretHandleView> {
        let mut out: Vec<SecretHandleView> = self
            .handles
            .values()
            .filter(|h| h.agent_pid == agent_pid)
            .map(|h| {
                let entry = self.secrets.get(&h.secret_id);
                SecretHandleView {
                    handle_id: h.handle_id.clone(),
                    secret_id: h.secret_id.clone(),
                    agent_pid: h.agent_pid.clone(),
                    namespace: h.namespace.clone(),
                    created_at_ms: entry.map(|e| e.created_at_ms),
                    expires_at_ms: entry.and_then(|e| e.expires_at_ms),
                    description: entry.map(|e| e.description.clone()),
                    dangling: entry.is_none(),
                }
            })
            .collect();
        out.sort_by(|a, b| a.handle_id.cmp(&b.handle_id));
        out
    }

    /// Kernel-only snapshot including secret values (sealed at rest by the platform).
    pub fn to_persist_json(&self) -> serde_json::Value {
        serde_json::json!({
            "secrets": self.secrets,
            "handles": self.handles,
            "next_handle_id": self.next_handle_id,
        })
    }

    pub fn from_persist_json(v: serde_json::Value) -> Result<Self, String> {
        #[derive(Deserialize)]
        struct Blob {
            secrets: HashMap<String, SecretEntry>,
            handles: HashMap<String, SecretHandle>,
            next_handle_id: u64,
        }
        let blob: Blob = serde_json::from_value(v).map_err(|e| e.to_string())?;
        Ok(Self {
            secrets: blob.secrets,
            handles: blob.handles,
            next_handle_id: blob.next_handle_id.max(1),
        })
    }
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
    fn rotate_replaces_value_for_existing_handles() {
        let mut store = SecretStore::new();
        store.store_secret("api_key_1", "agent_a", "old-value", None, 1000, "key").unwrap();
        let handle = store.issue_handle("api_key_1", "agent_a").unwrap();

        store.rotate_secret("api_key_1", "new-value", None, 2000).unwrap();

        // The whole point of rotation: the handle issued before the rotation must
        // stop resolving to the compromised value.
        assert_eq!(store.resolve_handle(&handle.handle_id, 2000).unwrap(), "new-value");
        assert_eq!(store.secret_count(), 1);
    }

    #[test]
    fn rotate_refreshes_ttl_and_rejects_unknown_secret() {
        let mut store = SecretStore::new();
        store.store_secret("k", "agent_a", "v1", Some(1000), 1000, "key").unwrap();
        let handle = store.issue_handle("k", "agent_a").unwrap();
        assert!(store.resolve_handle(&handle.handle_id, 3000).is_err());

        store.rotate_secret("k", "v2", Some(1000), 3000).unwrap();
        assert_eq!(store.resolve_handle(&handle.handle_id, 3500).unwrap(), "v2");

        assert!(store.rotate_secret("missing", "v", None, 4000).is_err());
    }

    #[test]
    fn upsert_replaces_existing_without_already_exists() {
        let mut store = SecretStore::new();
        store
            .upsert_secret("llm/deepseek", "cnktr:platform", "old", None, 1000, "key")
            .unwrap();
        store
            .upsert_secret("llm/deepseek", "cnktr:platform", "new", None, 2000, "key")
            .unwrap();
        assert_eq!(store.secret_count(), 1);
        assert_eq!(
            store.get_secret_value("llm/deepseek", 2000).unwrap(),
            "new"
        );
        assert_eq!(store.secret_ids_with_prefix("llm/"), vec!["llm/deepseek"]);
    }

    #[test]
    fn handles_for_agent_lists_only_that_agent() {
        let mut store = SecretStore::new();
        store.store_secret("a_key", "agent_a", "v", None, 1000, "a key").unwrap();
        store.store_secret("b_key", "agent_b", "v", None, 1000, "b key").unwrap();
        store.issue_handle("a_key", "agent_a").unwrap();
        store.issue_handle("b_key", "agent_b").unwrap();

        let a = store.handles_for_agent("agent_a");
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].secret_id, "a_key");
        assert!(!a[0].dangling);
        assert_eq!(a[0].description.as_deref(), Some("a key"));
        assert!(store.handles_for_agent("agent_c").is_empty());
    }

    #[test]
    fn revoked_secret_leaves_no_stale_handle_metadata() {
        let mut store = SecretStore::new();
        store.store_secret("k", "agent_a", "v", None, 1000, "key").unwrap();
        store.issue_handle("k", "agent_a").unwrap();
        store.revoke_secret("k").unwrap();

        // Either the handle is gone, or it is reported as dangling — never as a
        // live handle with invented lifecycle values.
        for h in store.handles_for_agent("agent_a") {
            assert!(h.dangling);
            assert!(h.created_at_ms.is_none());
        }
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

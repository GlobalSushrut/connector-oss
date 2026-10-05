//! Secure Cache Layer — Mini Logic Redis with Security
//!
//! FIX BUG-065: Encrypted caching with access control, poisoning detection,
//! and side-channel protection. Lightweight in-memory cache for sensitive data.

use std::collections::HashMap;
use std::time::{Duration, Instant};
use rand::Rng;
use std::sync::{Arc, Mutex};
use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};

/// Secure cache entry with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureCacheEntry {
    /// Encrypted value
    pub encrypted_value: Vec<u8>,
    /// Entry nonce (unique per entry)
    pub nonce: Vec<u8>,
    /// Creation timestamp
    pub created_at: i64,
    /// Expiration timestamp
    pub expires_at: i64,
    /// Access control list (allowed agents/subjects)
    pub acl: Vec<String>,
    /// Content hash for integrity verification
    pub content_hash: String,
    /// Access count for LRU
    pub access_count: u64,
    /// Last accessed timestamp
    pub last_accessed: i64,
    /// Data classification level
    pub classification: DataClassification,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum DataClassification {
    Public,
    Internal,
    Confidential,
    Restricted,
}

impl DataClassification {
    pub fn encryption_required(&self) -> bool {
        matches!(self, DataClassification::Confidential | DataClassification::Restricted)
    }

    pub fn audit_required(&self) -> bool {
        matches!(self, DataClassification::Confidential | DataClassification::Restricted)
    }
}

/// Cache poisoning detection result
#[derive(Debug, Clone)]
pub enum PoisoningCheck {
    Clean,
    Suspicious(String),
    Poisoned(String),
}

#[derive(Debug, Clone)]
pub struct SideChannelProtection {
    pub timing_jitter: bool,
    pub min_jitter_us: u64,
    pub max_jitter_us: u64,
    pub constant_time_acl: bool,
}

impl Default for SideChannelProtection {
    fn default() -> Self {
        Self {
            timing_jitter: true,
            min_jitter_us: 10,
            max_jitter_us: 200,
            constant_time_acl: true,
        }
    }
}

/// Secure cache layer with encryption and access control
pub struct SecureCacheLayer {
    /// Internal cache storage
    cache: HashMap<String, SecureCacheEntry>,
    /// Encryption key (256-bit)
    encryption_key: [u8; 32],
    /// Maximum cache size
    max_size: usize,
    /// Default TTL
    default_ttl: Duration,
    /// Poisoning detection enabled
    poisoning_detection: bool,
    /// Suspicious patterns
    suspicious_patterns: Vec<String>,
    /// Access log for anomaly detection
    access_log: Vec<CacheAccessEvent>,
    /// Max access log size
    max_log_size: usize,
    /// Side-channel protection settings
    side_channel: SideChannelProtection,
}

#[derive(Debug, Clone)]
pub struct CacheAccessEvent {
    pub key: String,
    pub agent_pid: String,
    pub operation: CacheOperation,
    pub timestamp: i64,
    pub success: bool,
}

#[derive(Debug, Clone, Copy)]
pub enum CacheOperation {
    Read,
    Write,
    Delete,
}

impl SecureCacheLayer {
    pub fn new(encryption_key: [u8; 32], max_size: usize) -> Self {
        Self {
            cache: HashMap::with_capacity(max_size),
            encryption_key,
            max_size,
            default_ttl: Duration::from_secs(3600), // 1 hour
            poisoning_detection: true,
            suspicious_patterns: vec![
                "javascript:".to_string(),
                "<script>".to_string(),
                "eval(".to_string(),
                "base64".to_string(),
                "exec".to_string(),
            ],
            access_log: Vec::with_capacity(1000),
            max_log_size: 10000,
            side_channel: SideChannelProtection::default(),
        }
    }

    /// Store value in cache
    pub fn put(
        &mut self,
        key: String,
        value: &str,
        agent_pid: &str,
        classification: DataClassification,
        custom_acl: Option<Vec<String>>,
    ) -> Result<(), CacheError> {
        // Check poisoning
        if self.poisoning_detection {
            match self.check_poisoning(value) {
                PoisoningCheck::Clean => {}
                PoisoningCheck::Suspicious(reason) => {
                    eprintln!("[CACHE SECURITY] Suspicious pattern detected in key={}: {}", key, reason);
                    // Continue but log
                }
                PoisoningCheck::Poisoned(reason) => {
                    return Err(CacheError::PoisoningDetected(reason));
                }
            }
        }

        // Evict if at capacity
        if self.cache.len() >= self.max_size {
            self.evict_lru();
        }

        let now = chrono::Utc::now();
        let expires_at = now + chrono::Duration::from_std(self.default_ttl).unwrap_or(chrono::Duration::hours(1));

        // Calculate content hash
        let content_hash = self.compute_hash(value);

        // Encrypt if required
        let (encrypted_value, nonce) = if classification.encryption_required() {
            self.encrypt_value(value)?
        } else {
            (value.as_bytes().to_vec(), vec![0; 12])
        };

        // Build ACL
        let acl = custom_acl.unwrap_or_else(|| vec![agent_pid.to_string()]);

        let entry = SecureCacheEntry {
            encrypted_value,
            nonce,
            created_at: now.timestamp_millis(),
            expires_at: expires_at.timestamp_millis(),
            acl,
            content_hash,
            access_count: 0,
            last_accessed: now.timestamp_millis(),
            classification,
        };

        self.cache.insert(key.clone(), entry);

        // Log access if audit required
        if classification.audit_required() {
            self.log_access(key, agent_pid, CacheOperation::Write, true);
        }

        Ok(())
    }

    /// Retrieve value from cache
    pub fn get(
        &mut self,
        key: &str,
        agent_pid: &str,
    ) -> Result<Option<String>, CacheError> {
        // Remove expired entries
        self.cleanup_expired();

        let now = chrono::Utc::now().timestamp_millis();

        // Clone needed data before mutable ops
        let (acl, expires_at, encrypted_value, nonce, classification) = {
            if let Some(entry) = self.cache.get(key) {
                (entry.acl.clone(), entry.expires_at, entry.encrypted_value.clone(), entry.nonce.clone(), entry.classification)
            } else {
                return Ok(None);
            }
        };

        if !acl.contains(&agent_pid.to_string()) && !acl.contains(&"*".to_string()) {
            return Err(CacheError::AccessDenied);
        }

        if now > expires_at {
            self.cache.remove(key);
            return Ok(None);
        }

        let value = if classification.encryption_required() {
            self.decrypt_value(&encrypted_value, &nonce)?
        } else {
            String::from_utf8_lossy(&encrypted_value).to_string()
        };

        if let Some(entry) = self.cache.get_mut(key) {
            entry.access_count += 1;
            entry.last_accessed = now;
        }

        if classification.audit_required() {
            self.log_access(key.to_string(), agent_pid, CacheOperation::Read, true);
        }

        Ok(Some(value))
    }

    /// Delete entry from cache
    pub fn delete(&mut self, key: &str, agent_pid: &str) -> Result<bool, CacheError> {
        if let Some(entry) = self.cache.get(key) {
            // Check ACL
            if !entry.acl.contains(&agent_pid.to_string()) {
                return Err(CacheError::AccessDenied);
            }
            let audit_required = entry.classification.audit_required();
            self.cache.remove(key);
            if audit_required {
                self.log_access(key.to_string(), agent_pid, CacheOperation::Delete, true);
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Apply timing jitter to prevent timing attacks
    fn apply_timing_jitter(&self) {
        if self.side_channel.timing_jitter {
            let jitter = rand::thread_rng()
                .gen_range(self.side_channel.min_jitter_us..=self.side_channel.max_jitter_us);
            std::thread::sleep(std::time::Duration::from_micros(jitter));
        }
    }

    /// Constant-time string comparison to prevent timing attacks
    fn constant_time_compare(&self, a: &str, b: &str) -> bool {
        if a.len() != b.len() {
            return false;
        }
        let mut result = 0u8;
        for (x, y) in a.bytes().zip(b.bytes()) {
            result |= x ^ y;
        }
        result == 0
    }

    /// Check access control with side-channel protection
    fn check_acl_secure(&self, entry: &SecureCacheEntry, agent_pid: &str) -> bool {
        if self.side_channel.constant_time_acl {
            entry.acl.iter().any(|acl_agent| self.constant_time_compare(acl_agent, agent_pid))
        } else {
            entry.acl.contains(&agent_pid.to_string())
        }
    }

    /// Access cache entry with side-channel protection
    pub fn get_secure(&self, key: &str, agent_pid: &str) -> Result<String, CacheError> {
        self.apply_timing_jitter();

        let entry = self.cache.get(key)
            .ok_or(CacheError::KeyNotFound)?;

        // Check access control with constant-time comparison
        if !self.check_acl_secure(entry, agent_pid) {
            // Add jitter even on failure to prevent timing leaks
            self.apply_timing_jitter();
            return Err(CacheError::AccessDenied);
        }

        // Decrypt value
        let decrypted = self.decrypt_value(&entry.encrypted_value, &entry.nonce)
            .map_err(|_| CacheError::DecryptionFailed)?;

        Ok(decrypted)
    }

    /// Check for cache poisoning
    fn check_poisoning(&self, value: &str) -> PoisoningCheck {
        let value_lower = value.to_lowercase();

        // Check suspicious patterns
        for pattern in &self.suspicious_patterns {
            if value_lower.contains(pattern) {
                // Check if it's in a benign context (e.g., json content)
                if value_lower.contains("data:") || value_lower.contains("application/json") {
                    return PoisoningCheck::Suspicious(format!("Pattern '{}' found, may be benign", pattern));
                }
                return PoisoningCheck::Poisoned(format!("Malicious pattern detected: {}", pattern));
            }
        }

        // Check for unusual encoding
        if value.chars().filter(|c| *c == '%').count() > value.len() / 4 {
            return PoisoningCheck::Suspicious("High URL encoding ratio".to_string());
        }

        PoisoningCheck::Clean
    }

    /// Compute SHA-256 hash of content
    fn compute_hash(&self, content: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Encrypt value using AES-256-GCM
    fn encrypt_value(&self, value: &str) -> Result<(Vec<u8>, Vec<u8>), CacheError> {
        let cipher = Aes256Gcm::new_from_slice(&self.encryption_key)
            .map_err(|_| CacheError::EncryptionFailed)?;

        // Generate random nonce
        let nonce_bytes: [u8; 12] = rand::random();
        let nonce = Nonce::from_slice(&nonce_bytes);

        let encrypted = cipher
            .encrypt(nonce, value.as_bytes())
            .map_err(|_| CacheError::EncryptionFailed)?;

        Ok((encrypted, nonce_bytes.to_vec()))
    }

    /// Decrypt value using AES-256-GCM
    fn decrypt_value(&self, encrypted: &[u8], nonce_bytes: &[u8]) -> Result<String, CacheError> {
        if nonce_bytes.len() != 12 {
            return Err(CacheError::DecryptionFailed);
        }

        let cipher = Aes256Gcm::new_from_slice(&self.encryption_key)
            .map_err(|_| CacheError::DecryptionFailed)?;

        let nonce = Nonce::from_slice(nonce_bytes);

        let decrypted = cipher
            .decrypt(nonce, encrypted)
            .map_err(|_| CacheError::DecryptionFailed)?;

        String::from_utf8(decrypted)
            .map_err(|_| CacheError::DecryptionFailed)
    }

    /// Evict least recently used entry
    fn evict_lru(&mut self) {
        let now = chrono::Utc::now().timestamp_millis();

        if let Some((key_to_remove, _)) = self.cache
            .iter()
            .filter(|(_, entry)| entry.classification != DataClassification::Restricted)
            .min_by_key(|(_, entry)| entry.last_accessed) {
            let key = key_to_remove.clone();
            self.cache.remove(&key);
        }
    }

    /// Clean up expired entries
    fn cleanup_expired(&mut self) {
        let now = chrono::Utc::now().timestamp_millis();
        let expired: Vec<String> = self.cache
            .iter()
            .filter(|(_, entry)| now > entry.expires_at)
            .map(|(k, _)| k.clone())
            .collect();

        for key in expired {
            self.cache.remove(&key);
        }
    }

    /// Log access event
    fn log_access(&mut self, key: String, agent_pid: &str, operation: CacheOperation, success: bool) {
        let event = CacheAccessEvent {
            key,
            agent_pid: agent_pid.to_string(),
            operation,
            timestamp: chrono::Utc::now().timestamp_millis(),
            success,
        };

        self.access_log.push(event);

        // Trim log if too large
        if self.access_log.len() > self.max_log_size {
            self.access_log.remove(0);
        }
    }

    /// Get cache statistics
    pub fn stats(&self) -> CacheStats {
        CacheStats {
            total_entries: self.cache.len(),
            max_size: self.max_size,
            encrypted_entries: self.cache.values()
                .filter(|e| e.classification.encryption_required())
                .count(),
            public_entries: self.cache.values()
                .filter(|e| e.classification == DataClassification::Public)
                .count(),
        }
    }

    /// Clear all entries
    pub fn clear(&mut self, agent_pid: &str) -> Result<(), CacheError> {
        // Check if agent has permission
        // In production, check admin role
        self.cache.clear();
        self.access_log.clear();
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct CacheStats {
    pub total_entries: usize,
    pub max_size: usize,
    pub encrypted_entries: usize,
    pub public_entries: usize,
}

#[derive(Debug, Clone)]
pub enum CacheError {
    PoisoningDetected(String),
    AccessDenied,
    EncryptionFailed,
    DecryptionFailed,
    KeyNotFound,
    CacheFull,
}

impl std::fmt::Display for CacheError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CacheError::PoisoningDetected(reason) => write!(f, "Cache poisoning detected: {}", reason),
            CacheError::AccessDenied => write!(f, "Access denied to cache entry"),
            CacheError::EncryptionFailed => write!(f, "Encryption failed"),
            CacheError::DecryptionFailed => write!(f, "Decryption failed"),
            CacheError::KeyNotFound => write!(f, "Cache key not found"),
            CacheError::CacheFull => write!(f, "Cache is full"),
        }
    }
}

impl std::error::Error for CacheError {}

/// Thread-safe wrapper
#[derive(Clone)]
pub struct SharedSecureCache {
    inner: Arc<Mutex<SecureCacheLayer>>,
}

impl SharedSecureCache {
    pub fn new(encryption_key: [u8; 32], max_size: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(SecureCacheLayer::new(encryption_key, max_size))),
        }
    }

    pub fn put(
        &self,
        key: String,
        value: &str,
        agent_pid: &str,
        classification: DataClassification,
    ) -> Result<(), CacheError> {
        self.inner.lock().unwrap().put(key, value, agent_pid, classification, None)
    }

    pub fn get(&self, key: &str, agent_pid: &str) -> Result<Option<String>, CacheError> {
        self.inner.lock().unwrap().get(key, agent_pid)
    }

    pub fn delete(&self, key: &str, agent_pid: &str) -> Result<bool, CacheError> {
        self.inner.lock().unwrap().delete(key, agent_pid)
    }

    pub fn stats(&self) -> CacheStats {
        self.inner.lock().unwrap().stats()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        [0u8; 32] // Zero key for testing only
    }

    #[test]
    fn test_basic_cache_operations() {
        let mut cache = SecureCacheLayer::new(test_key(), 100);

        // Put and get
        cache.put("key1".to_string(), "value1", "agent_1", DataClassification::Public, None).unwrap();
        let value = cache.get("key1", "agent_1").unwrap();
        assert_eq!(value, Some("value1".to_string()));
    }

    #[test]
    fn test_access_control() {
        let mut cache = SecureCacheLayer::new(test_key(), 100);

        cache.put("key1".to_string(), "secret", "agent_1", DataClassification::Confidential, None).unwrap();

        // Agent 1 can access
        let value = cache.get("key1", "agent_1").unwrap();
        assert!(value.is_some());

        // Agent 2 cannot access
        let result = cache.get("key1", "agent_2");
        assert!(matches!(result, Err(CacheError::AccessDenied)));
    }

    #[test]
    fn test_poisoning_detection() {
        let mut cache = SecureCacheLayer::new(test_key(), 100);

        let result = cache.put(
            "key1".to_string(),
            "<script>alert('xss')</script>",
            "agent_1",
            DataClassification::Public,
            None,
        );

        assert!(matches!(result, Err(CacheError::PoisoningDetected(_))));
    }
}

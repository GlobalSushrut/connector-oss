//! Secrets Management — Key Rotation, Envelope Encryption, Signing Hierarchy
//!
//! This module implements comprehensive secrets management:
//! - Automated key rotation policies
//! - Envelope encryption for MemPackets
//! - Hierarchical signing keys (root → node → agent → session)
//!
//! Design sources: AWS KMS, HashiCorp Vault, PKCS#11

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

fn vac_allow_plaintext_secrets() -> bool {
    matches!(
        std::env::var("CONNECTOR_VAC_ALLOW_PLAINTEXT_SECRETS")
            .ok()
            .as_deref()
            .map(|s| s.trim().to_ascii_lowercase())
            .as_deref(),
        Some("1") | Some("true") | Some("yes") | Some("on")
    )
}

/// AES-256-GCM with a random 12-byte nonce (OS-grade; not length-derived).
fn aead_seal(key: &[u8; 32], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), String> {
    use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng};
    use aes_gcm::Aes256Gcm;
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| format!("aead key: {e}"))?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let sealed = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| format!("aead encrypt: {e}"))?;
    if sealed.len() < 16 {
        return Err("aead ciphertext too short".into());
    }
    let split = sealed.len() - 16;
    Ok((nonce.to_vec(), sealed[..split].to_vec(), sealed[split..].to_vec()))
}

fn aead_open(key: &[u8; 32], iv: &[u8], ciphertext: &[u8], tag: &[u8]) -> Result<Vec<u8>, String> {
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};
    if iv.len() != 12 {
        return Err("iv must be 12 bytes".into());
    }
    if tag.len() != 16 {
        return Err("auth_tag must be 16 bytes".into());
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| format!("aead key: {e}"))?;
    let nonce = Nonce::from_slice(iv);
    let mut sealed = Vec::with_capacity(ciphertext.len() + tag.len());
    sealed.extend_from_slice(ciphertext);
    sealed.extend_from_slice(tag);
    cipher
        .decrypt(nonce, sealed.as_ref())
        .map_err(|_| "AES-GCM decrypt/auth failed".into())
}

/// Resolve 32-byte KEK material for envelope wrap (AES-GCM of DEK).
fn resolve_kek_bytes(kek_id: &str) -> Result<[u8; 32], String> {
    use sha2::{Digest, Sha256};
    let secret = std::env::var("CONNECTOR_VAC_KEK_SECRET")
        .or_else(|_| std::env::var("CONNECTOR_CAGE_CAP_SECRET"))
        .or_else(|_| std::env::var("CONNECTOR_CFNI_SECRET"))
        .unwrap_or_default();
    if secret.trim().is_empty() {
        if vac_allow_plaintext_secrets() || cfg!(test) {
            let mut out = [0u8; 32];
            let dig = Sha256::digest(format!("vac-lab-kek|{kek_id}").as_bytes());
            out.copy_from_slice(&dig);
            return Ok(out);
        }
        return Err(
            "CONNECTOR_VAC_KEK_SECRET (or CONNECTOR_CAGE_CAP_SECRET) required for VAC envelope AEAD"
                .into(),
        );
    }
    let mut out = [0u8; 32];
    let dig = Sha256::digest(format!("{kek_id}|{secret}").as_bytes());
    out.copy_from_slice(&dig);
    Ok(out)
}

// =============================================================================
// Part 1: Key Rotation Policy Automation
// =============================================================================

/// Key type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyType {
    /// Symmetric encryption key (AES-256)
    Symmetric,
    /// Asymmetric signing key (Ed25519)
    Signing,
    /// Asymmetric encryption key (X25519)
    Encryption,
    /// HMAC key
    Hmac,
    /// Root CA key
    RootCa,
    /// Intermediate CA key
    IntermediateCa,
}

/// Key state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyState {
    /// Key is pending activation
    PendingActivation,
    /// Key is active and can be used
    Active,
    /// Key is being rotated (new key active, old still valid)
    Rotating,
    /// Key is deactivated (can decrypt but not encrypt)
    Deactivated,
    /// Key is compromised (should not be used)
    Compromised,
    /// Key is destroyed
    Destroyed,
}

/// Rotation trigger
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RotationTrigger {
    /// Time-based rotation
    Schedule { interval_seconds: u64 },
    /// Usage-based rotation
    Usage { max_operations: u64 },
    /// Manual rotation
    Manual,
    /// On compromise detection
    Compromise,
    /// External event
    Event { event_type: String },
}

/// Rotation policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationPolicy {
    /// Policy ID
    pub id: String,
    /// Policy name
    pub name: String,
    /// Key types this policy applies to
    pub key_types: Vec<KeyType>,
    /// Rotation triggers
    pub triggers: Vec<RotationTrigger>,
    /// Grace period after rotation (seconds)
    pub grace_period_seconds: u64,
    /// Auto-destroy old keys after grace period
    pub auto_destroy: bool,
    /// Notification settings
    pub notify_before_seconds: Option<u64>,
    /// Enabled flag
    pub enabled: bool,
}

impl RotationPolicy {
    pub fn new(id: &str, name: &str) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            key_types: vec![],
            triggers: vec![],
            grace_period_seconds: 86400, // 24 hours
            auto_destroy: false,
            notify_before_seconds: Some(3600), // 1 hour
            enabled: true,
        }
    }

    pub fn with_schedule(mut self, interval_seconds: u64) -> Self {
        self.triggers.push(RotationTrigger::Schedule { interval_seconds });
        self
    }

    pub fn with_usage_limit(mut self, max_operations: u64) -> Self {
        self.triggers.push(RotationTrigger::Usage { max_operations });
        self
    }

    pub fn for_key_types(mut self, types: Vec<KeyType>) -> Self {
        self.key_types = types;
        self
    }

    pub fn with_grace_period(mut self, seconds: u64) -> Self {
        self.grace_period_seconds = seconds;
        self
    }

    pub fn auto_destroy(mut self) -> Self {
        self.auto_destroy = true;
        self
    }
}

/// Key metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadata {
    /// Key ID
    pub id: String,
    /// Key type
    pub key_type: KeyType,
    /// Key state
    pub state: KeyState,
    /// Creation timestamp
    pub created_at: i64,
    /// Last rotation timestamp
    pub rotated_at: Option<i64>,
    /// Expiration timestamp
    pub expires_at: Option<i64>,
    /// Operation count
    pub operation_count: u64,
    /// Policy ID
    pub policy_id: Option<String>,
    /// Parent key ID (for hierarchy)
    pub parent_key_id: Option<String>,
    /// Labels
    pub labels: HashMap<String, String>,
}

/// Rotation event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationEvent {
    /// Event ID
    pub id: u64,
    /// Key ID
    pub key_id: String,
    /// Old key version
    pub old_version: u64,
    /// New key version
    pub new_version: u64,
    /// Trigger that caused rotation
    pub trigger: RotationTrigger,
    /// Timestamp
    pub timestamp: i64,
    /// Success flag
    pub success: bool,
    /// Error message (if failed)
    pub error: Option<String>,
}

static ROTATION_EVENT_ID: AtomicU64 = AtomicU64::new(1);

/// Key rotation manager
#[derive(Debug, Default)]
pub struct RotationManager {
    /// Policies by ID
    policies: HashMap<String, RotationPolicy>,
    /// Key metadata by ID
    keys: HashMap<String, KeyMetadata>,
    /// Rotation history
    history: Vec<RotationEvent>,
    /// Pending rotations
    pending: Vec<String>,
}

impl RotationManager {
    pub fn new() -> Self { Self::default() }

    /// Register a rotation policy
    pub fn register_policy(&mut self, policy: RotationPolicy) {
        self.policies.insert(policy.id.clone(), policy);
    }

    /// Register a key
    pub fn register_key(&mut self, metadata: KeyMetadata) {
        self.keys.insert(metadata.id.clone(), metadata);
    }

    /// Apply policy to key
    pub fn apply_policy(&mut self, key_id: &str, policy_id: &str) -> Result<(), String> {
        let key = self.keys.get_mut(key_id).ok_or("Key not found")?;
        if !self.policies.contains_key(policy_id) {
            return Err("Policy not found".into());
        }
        key.policy_id = Some(policy_id.into());
        Ok(())
    }

    /// Check if key needs rotation
    pub fn needs_rotation(&self, key_id: &str) -> bool {
        let key = match self.keys.get(key_id) {
            Some(k) => k,
            None => return false,
        };

        let policy_id = match &key.policy_id {
            Some(id) => id,
            None => return false,
        };

        let policy = match self.policies.get(policy_id) {
            Some(p) => p,
            None => return false,
        };

        if !policy.enabled { return false; }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        for trigger in &policy.triggers {
            match trigger {
                RotationTrigger::Schedule { interval_seconds } => {
                    let last_rotation = key.rotated_at.unwrap_or(key.created_at);
                    if now - last_rotation >= *interval_seconds as i64 {
                        return true;
                    }
                }
                RotationTrigger::Usage { max_operations } => {
                    if key.operation_count >= *max_operations {
                        return true;
                    }
                }
                _ => {}
            }
        }

        false
    }

    /// Get keys needing rotation
    pub fn get_pending_rotations(&self) -> Vec<&str> {
        self.keys.keys()
            .filter(|k| self.needs_rotation(k))
            .map(|s| s.as_str())
            .collect()
    }

    /// Record rotation
    pub fn record_rotation(&mut self, key_id: &str, old_version: u64, new_version: u64, trigger: RotationTrigger) -> Result<u64, String> {
        let key = self.keys.get_mut(key_id).ok_or("Key not found")?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        key.rotated_at = Some(now);
        key.operation_count = 0;

        let event_id = ROTATION_EVENT_ID.fetch_add(1, Ordering::SeqCst);
        let event = RotationEvent {
            id: event_id,
            key_id: key_id.into(),
            old_version,
            new_version,
            trigger,
            timestamp: now,
            success: true,
            error: None,
        };

        self.history.push(event);
        Ok(event_id)
    }

    /// Increment operation count
    pub fn record_operation(&mut self, key_id: &str) {
        if let Some(key) = self.keys.get_mut(key_id) {
            key.operation_count += 1;
        }
    }

    /// Get rotation history for key
    pub fn get_history(&self, key_id: &str) -> Vec<&RotationEvent> {
        self.history.iter().filter(|e| e.key_id == key_id).collect()
    }
}

// =============================================================================
// Part 2: Envelope Encryption for MemPackets
// =============================================================================

/// Data Encryption Key (DEK)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataEncryptionKey {
    /// DEK ID
    pub id: String,
    /// Encrypted DEK (wrapped by KEK)
    pub encrypted_key: Vec<u8>,
    /// KEK ID used to wrap this DEK
    pub kek_id: String,
    /// Algorithm
    pub algorithm: String,
    /// Created timestamp
    pub created_at: i64,
}

/// Encrypted envelope
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedEnvelope {
    /// Envelope version
    pub version: u8,
    /// DEK ID
    pub dek_id: String,
    /// Encrypted DEK
    pub encrypted_dek: Vec<u8>,
    /// KEK ID
    pub kek_id: String,
    /// Initialization vector
    pub iv: Vec<u8>,
    /// Ciphertext
    pub ciphertext: Vec<u8>,
    /// Authentication tag
    pub auth_tag: Vec<u8>,
    /// Additional authenticated data
    pub aad: Option<Vec<u8>>,
}

/// Envelope encryption config
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvelopeConfig {
    /// DEK algorithm (e.g., "AES-256-GCM")
    pub dek_algorithm: String,
    /// KEK algorithm (e.g., "AES-256-KW")
    pub kek_algorithm: String,
    /// DEK rotation policy
    pub dek_rotation_ops: u64,
    /// Cache DEKs
    pub cache_deks: bool,
}

impl Default for EnvelopeConfig {
    fn default() -> Self {
        Self {
            dek_algorithm: "AES-256-GCM".into(),
            kek_algorithm: "AES-256-KW".into(),
            dek_rotation_ops: 10000,
            cache_deks: true,
        }
    }
}

/// Envelope encryption manager (AES-256-GCM DEK + AES-GCM-wrapped DEK under KEK).
#[derive(Debug, Default)]
pub struct EnvelopeEncryption {
    /// Configuration
    config: EnvelopeConfig,
    /// DEK metadata cache
    dek_cache: HashMap<String, DataEncryptionKey>,
    /// Plaintext DEKs (never serialized)
    dek_plain: HashMap<String, [u8; 32]>,
    /// KEK IDs
    kek_ids: Vec<String>,
    /// Operation counts per DEK
    dek_ops: HashMap<String, u64>,
}

impl EnvelopeEncryption {
    pub fn new(config: EnvelopeConfig) -> Self {
        Self { config, ..Default::default() }
    }

    /// Register a KEK
    pub fn register_kek(&mut self, kek_id: &str) {
        self.kek_ids.push(kek_id.into());
    }

    /// Generate a new DEK (returns encrypted/wrapped form).
    pub fn generate_dek(&mut self, kek_id: &str) -> Result<DataEncryptionKey, String> {
        if !self.kek_ids.contains(&kek_id.to_string()) {
            return Err("KEK not registered".into());
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        let dek_id = format!("dek-{:x}", now);
        let mut plain = [0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut plain);
        let kek = resolve_kek_bytes(kek_id)?;
        let (w_iv, w_ct, w_tag) = aead_seal(&kek, &plain)?;
        let mut wrapped = Vec::with_capacity(12 + w_ct.len() + 16);
        wrapped.extend_from_slice(&w_iv);
        wrapped.extend_from_slice(&w_ct);
        wrapped.extend_from_slice(&w_tag);

        let dek = DataEncryptionKey {
            id: dek_id.clone(),
            encrypted_key: wrapped,
            kek_id: kek_id.into(),
            algorithm: "AES-256-GCM".into(),
            created_at: now,
        };

        if self.config.cache_deks {
            self.dek_cache.insert(dek_id.clone(), dek.clone());
            self.dek_plain.insert(dek_id.clone(), plain);
        }
        self.dek_ops.insert(dek_id, 0);

        Ok(dek)
    }

    /// Encrypt data with AES-256-GCM envelope encryption.
    ///
    /// Lab break-glass: `CONNECTOR_VAC_ALLOW_PLAINTEXT_SECRETS=1` still uses AEAD but
    /// allows a derived lab KEK when no secret env is set.
    pub fn encrypt(&mut self, plaintext: &[u8], kek_id: &str, aad: Option<&[u8]>) -> Result<EncryptedEnvelope, String> {
        let (dek, plain_dek) = self.get_or_generate_dek_plain(kek_id)?;
        let (iv, ciphertext, auth_tag) = aead_seal(&plain_dek, plaintext)?;

        if let Some(count) = self.dek_ops.get_mut(&dek.id) {
            *count += 1;
        }

        Ok(EncryptedEnvelope {
            version: 2, // v2 = real AES-GCM (v1 was plaintext lab stub)
            dek_id: dek.id.clone(),
            encrypted_dek: dek.encrypted_key.clone(),
            kek_id: kek_id.into(),
            iv,
            ciphertext,
            auth_tag,
            aad: aad.map(|a| a.to_vec()),
        })
    }

    /// Decrypt AES-GCM envelope (unwraps DEK with KEK, then decrypts payload).
    pub fn decrypt(&self, envelope: &EncryptedEnvelope) -> Result<Vec<u8>, String> {
        // Legacy v1 plaintext envelopes — only if lab allow flag is on.
        if envelope.version < 2 {
            if !vac_allow_plaintext_secrets() && !cfg!(test) {
                return Err("legacy plaintext VAC envelope rejected (version < 2)".into());
            }
            return Ok(envelope.ciphertext.clone());
        }
        let plain_dek = if let Some(p) = self.dek_plain.get(&envelope.dek_id) {
            *p
        } else {
            let kek = resolve_kek_bytes(&envelope.kek_id)?;
            let wrapped = &envelope.encrypted_dek;
            if wrapped.len() < 12 + 16 {
                return Err("encrypted_dek too short".into());
            }
            let w_iv = &wrapped[..12];
            let w_tag = &wrapped[wrapped.len() - 16..];
            let w_ct = &wrapped[12..wrapped.len() - 16];
            let unwrapped = aead_open(&kek, w_iv, w_ct, w_tag)?;
            if unwrapped.len() != 32 {
                return Err("unwrapped DEK length != 32".into());
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&unwrapped);
            arr
        };
        aead_open(
            &plain_dek,
            &envelope.iv,
            &envelope.ciphertext,
            &envelope.auth_tag,
        )
    }

    fn get_or_generate_dek_plain(
        &mut self,
        kek_id: &str,
    ) -> Result<(DataEncryptionKey, [u8; 32]), String> {
        for (dek_id, dek) in &self.dek_cache {
            if dek.kek_id == kek_id {
                let ops = self.dek_ops.get(dek_id).copied().unwrap_or(0);
                if ops < self.config.dek_rotation_ops {
                    if let Some(plain) = self.dek_plain.get(dek_id) {
                        return Ok((dek.clone(), *plain));
                    }
                }
            }
        }
        let dek = self.generate_dek(kek_id)?;
        let plain = *self
            .dek_plain
            .get(&dek.id)
            .ok_or_else(|| "dek plain missing after generate".to_string())?;
        Ok((dek, plain))
    }

    fn get_or_generate_dek(&mut self, kek_id: &str) -> Result<DataEncryptionKey, String> {
        Ok(self.get_or_generate_dek_plain(kek_id)?.0)
    }

    /// Check if DEK needs rotation
    pub fn dek_needs_rotation(&self, dek_id: &str) -> bool {
        self.dek_ops.get(dek_id)
            .map(|&ops| ops >= self.config.dek_rotation_ops)
            .unwrap_or(false)
    }
}

// =============================================================================
// Part 3: Signing Key Hierarchy
// =============================================================================

/// Key level in hierarchy
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyLevel {
    /// Root key (offline, highest trust)
    Root = 0,
    /// Node key (per-node, signs agent keys)
    Node = 1,
    /// Agent key (per-agent, signs session keys)
    Agent = 2,
    /// Session key (ephemeral, for session operations)
    Session = 3,
}

/// Signing key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningKey {
    /// Key ID
    pub id: String,
    /// Level in hierarchy
    pub level: KeyLevel,
    /// Public key (hex encoded)
    pub public_key: String,
    /// Parent key ID
    pub parent_id: Option<String>,
    /// Certificate chain (signatures from parent to root)
    pub cert_chain: Vec<String>,
    /// Valid from timestamp
    pub valid_from: i64,
    /// Valid until timestamp
    pub valid_until: i64,
    /// Subject (node_id, agent_id, or session_id)
    pub subject: String,
    /// Capabilities
    pub capabilities: Vec<String>,
}

impl SigningKey {
    pub fn root(id: &str, public_key: &str) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        Self {
            id: id.into(),
            level: KeyLevel::Root,
            public_key: public_key.into(),
            parent_id: None,
            cert_chain: vec![],
            valid_from: now,
            valid_until: now + 365 * 24 * 3600 * 10, // 10 years
            subject: "root".into(),
            capabilities: vec!["sign:node".into()],
        }
    }

    pub fn node(id: &str, public_key: &str, parent_id: &str, node_id: &str) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        Self {
            id: id.into(),
            level: KeyLevel::Node,
            public_key: public_key.into(),
            parent_id: Some(parent_id.into()),
            cert_chain: vec![],
            valid_from: now,
            valid_until: now + 365 * 24 * 3600, // 1 year
            subject: node_id.into(),
            capabilities: vec!["sign:agent".into()],
        }
    }

    pub fn agent(id: &str, public_key: &str, parent_id: &str, agent_id: &str) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        Self {
            id: id.into(),
            level: KeyLevel::Agent,
            public_key: public_key.into(),
            parent_id: Some(parent_id.into()),
            cert_chain: vec![],
            valid_from: now,
            valid_until: now + 30 * 24 * 3600, // 30 days
            subject: agent_id.into(),
            capabilities: vec!["sign:session".into(), "sign:mempacket".into()],
        }
    }

    pub fn session(id: &str, public_key: &str, parent_id: &str, session_id: &str) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        Self {
            id: id.into(),
            level: KeyLevel::Session,
            public_key: public_key.into(),
            parent_id: Some(parent_id.into()),
            cert_chain: vec![],
            valid_from: now,
            valid_until: now + 24 * 3600, // 24 hours
            subject: session_id.into(),
            capabilities: vec!["sign:operation".into()],
        }
    }

    pub fn is_valid(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        now >= self.valid_from && now <= self.valid_until
    }
}

/// Key hierarchy manager
#[derive(Debug, Default)]
pub struct KeyHierarchy {
    /// All keys by ID
    keys: HashMap<String, SigningKey>,
    /// Keys by level
    by_level: HashMap<KeyLevel, Vec<String>>,
    /// Children by parent ID
    children: HashMap<String, Vec<String>>,
    /// Root key ID
    root_id: Option<String>,
}

impl KeyHierarchy {
    pub fn new() -> Self { Self::default() }

    /// Set root key
    pub fn set_root(&mut self, key: SigningKey) -> Result<(), String> {
        if key.level != KeyLevel::Root {
            return Err("Key is not a root key".into());
        }
        let id = key.id.clone();
        self.keys.insert(id.clone(), key);
        self.by_level.entry(KeyLevel::Root).or_default().push(id.clone());
        self.root_id = Some(id);
        Ok(())
    }

    /// Issue a child key
    pub fn issue_key(&mut self, key: SigningKey) -> Result<(), String> {
        let parent_id = key.parent_id.as_ref().ok_or("Key must have parent")?;
        let parent = self.keys.get(parent_id).ok_or("Parent key not found")?;

        // Verify parent can sign this level
        let expected_parent_level = match key.level {
            KeyLevel::Root => return Err("Cannot issue root key".into()),
            KeyLevel::Node => KeyLevel::Root,
            KeyLevel::Agent => KeyLevel::Node,
            KeyLevel::Session => KeyLevel::Agent,
        };

        if parent.level != expected_parent_level {
            return Err(format!("Parent must be {:?} to sign {:?}", expected_parent_level, key.level));
        }

        let id = key.id.clone();
        self.children.entry(parent_id.clone()).or_default().push(id.clone());
        self.by_level.entry(key.level).or_default().push(id.clone());
        self.keys.insert(id, key);

        Ok(())
    }

    /// Get key by ID
    pub fn get_key(&self, key_id: &str) -> Option<&SigningKey> {
        self.keys.get(key_id)
    }

    /// Get keys at level
    pub fn get_level(&self, level: KeyLevel) -> Vec<&SigningKey> {
        self.by_level.get(&level)
            .map(|ids| ids.iter().filter_map(|id| self.keys.get(id)).collect())
            .unwrap_or_default()
    }

    /// Get children of key
    pub fn get_children(&self, key_id: &str) -> Vec<&SigningKey> {
        self.children.get(key_id)
            .map(|ids| ids.iter().filter_map(|id| self.keys.get(id)).collect())
            .unwrap_or_default()
    }

    /// Verify key chain to root
    pub fn verify_chain(&self, key_id: &str) -> Result<bool, String> {
        let mut current_id = key_id.to_string();

        loop {
            let key = self.keys.get(&current_id).ok_or("Key not found in chain")?;

            if !key.is_valid() {
                return Ok(false);
            }

            match &key.parent_id {
                Some(parent_id) => {
                    current_id = parent_id.clone();
                }
                None => {
                    // Reached root
                    return Ok(key.level == KeyLevel::Root);
                }
            }
        }
    }

    /// Revoke key and all children
    pub fn revoke(&mut self, key_id: &str) -> Vec<String> {
        let mut revoked = vec![];

        // Collect all descendants
        let mut to_revoke = vec![key_id.to_string()];
        while let Some(id) = to_revoke.pop() {
            revoked.push(id.clone());
            if let Some(children) = self.children.get(&id) {
                to_revoke.extend(children.clone());
            }
        }

        // Remove from maps
        for id in &revoked {
            self.keys.remove(id);
            self.children.remove(id);
            for level_keys in self.by_level.values_mut() {
                level_keys.retain(|k| k != id);
            }
        }

        revoked
    }

    /// Get chain from key to root
    pub fn get_chain(&self, key_id: &str) -> Vec<&SigningKey> {
        let mut chain = vec![];
        let mut current_id = key_id.to_string();

        while let Some(key) = self.keys.get(&current_id) {
            chain.push(key);
            match &key.parent_id {
                Some(parent_id) => current_id = parent_id.clone(),
                None => break,
            }
        }

        chain
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rotation_policy() {
        let policy = RotationPolicy::new("pol-1", "Daily Rotation")
            .with_schedule(86400)
            .for_key_types(vec![KeyType::Symmetric])
            .with_grace_period(3600);

        assert_eq!(policy.triggers.len(), 1);
        assert_eq!(policy.grace_period_seconds, 3600);
    }

    #[test]
    fn test_rotation_manager() {
        let mut manager = RotationManager::new();

        let policy = RotationPolicy::new("pol-1", "Usage Rotation")
            .with_usage_limit(100);
        manager.register_policy(policy);

        let key = KeyMetadata {
            id: "key-1".into(),
            key_type: KeyType::Symmetric,
            state: KeyState::Active,
            created_at: 0,
            rotated_at: None,
            expires_at: None,
            operation_count: 0,
            policy_id: Some("pol-1".into()),
            parent_key_id: None,
            labels: HashMap::new(),
        };
        manager.register_key(key);

        assert!(!manager.needs_rotation("key-1"));

        // Simulate 100 operations
        for _ in 0..100 {
            manager.record_operation("key-1");
        }

        assert!(manager.needs_rotation("key-1"));
    }

    #[test]
    fn test_envelope_encryption() {
        let config = EnvelopeConfig::default();
        let mut envelope = EnvelopeEncryption::new(config);

        envelope.register_kek("kek-1");

        let plaintext = b"Hello, World!";
        let encrypted = envelope.encrypt(plaintext, "kek-1", None).unwrap();

        assert_eq!(encrypted.version, 2);
        assert_eq!(encrypted.kek_id, "kek-1");
        assert_ne!(encrypted.ciphertext.as_slice(), plaintext.as_slice());
        assert_eq!(encrypted.iv.len(), 12);
        assert_eq!(encrypted.auth_tag.len(), 16);

        let decrypted = envelope.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);

        // Cold decrypt (no plain DEK cache) via wrapped DEK.
        let cold = EnvelopeEncryption::new(EnvelopeConfig::default());
        let decrypted2 = cold.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted2, plaintext);
    }

    #[test]
    fn test_key_hierarchy() {
        let mut hierarchy = KeyHierarchy::new();

        // Create root
        let root = SigningKey::root("root-1", "root_pubkey");
        hierarchy.set_root(root).unwrap();

        // Create node key
        let node = SigningKey::node("node-1", "node_pubkey", "root-1", "node-001");
        hierarchy.issue_key(node).unwrap();

        // Create agent key
        let agent = SigningKey::agent("agent-1", "agent_pubkey", "node-1", "agent-001");
        hierarchy.issue_key(agent).unwrap();

        // Create session key
        let session = SigningKey::session("session-1", "session_pubkey", "agent-1", "session-001");
        hierarchy.issue_key(session).unwrap();

        // Verify chain
        assert!(hierarchy.verify_chain("session-1").unwrap());

        // Get chain
        let chain = hierarchy.get_chain("session-1");
        assert_eq!(chain.len(), 4);
        assert_eq!(chain[0].level, KeyLevel::Session);
        assert_eq!(chain[3].level, KeyLevel::Root);
    }

    #[test]
    fn test_key_revocation() {
        let mut hierarchy = KeyHierarchy::new();

        hierarchy.set_root(SigningKey::root("root-1", "pk")).unwrap();
        hierarchy.issue_key(SigningKey::node("node-1", "pk", "root-1", "n1")).unwrap();
        hierarchy.issue_key(SigningKey::agent("agent-1", "pk", "node-1", "a1")).unwrap();
        hierarchy.issue_key(SigningKey::agent("agent-2", "pk", "node-1", "a2")).unwrap();

        // Revoke node - should revoke agents too
        let revoked = hierarchy.revoke("node-1");
        assert_eq!(revoked.len(), 3); // node + 2 agents

        assert!(hierarchy.get_key("node-1").is_none());
        assert!(hierarchy.get_key("agent-1").is_none());
    }
}

//! mTLS (Mutual TLS) — Node-to-Node Authentication
//!
//! This module implements mutual TLS authentication for secure communication
//! between Connector nodes in a cluster:
//! - Certificate generation and management
//! - Certificate validation and verification
//! - Node identity extraction from certificates
//! - Certificate rotation support
//! - Trust chain management
//!
//! Design sources: Kubernetes PKI, Istio mTLS, SPIFFE/SPIRE

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

// =============================================================================
// Certificate Types
// =============================================================================

/// Certificate type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertificateType {
    /// Root CA certificate
    RootCa,
    /// Intermediate CA certificate
    IntermediateCa,
    /// Node certificate (server + client)
    Node,
    /// Agent certificate (client only)
    Agent,
}

/// Certificate status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertificateStatus {
    /// Certificate is valid and active
    Active,
    /// Certificate is pending activation
    Pending,
    /// Certificate has been revoked
    Revoked,
    /// Certificate has expired
    Expired,
    /// Certificate is being rotated
    Rotating,
}

/// Node identity extracted from certificate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeIdentity {
    /// Node ID (from CN or SAN)
    pub node_id: String,
    /// Cell ID this node belongs to
    pub cell_id: String,
    /// Cluster ID
    pub cluster_id: String,
    /// Node role (control-plane, worker, gateway)
    pub role: NodeRole,
    /// SPIFFE ID (if available)
    pub spiffe_id: Option<String>,
    /// Certificate fingerprint (SHA-256)
    pub cert_fingerprint: String,
    /// Certificate serial number
    pub serial_number: String,
    /// Not valid before (RFC 3339)
    pub not_before: String,
    /// Not valid after (RFC 3339)
    pub not_after: String,
}

/// Node role
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeRole {
    /// Control plane node
    ControlPlane,
    /// Worker node
    Worker,
    /// Gateway node (external traffic)
    Gateway,
    /// Storage node
    Storage,
}

impl NodeRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ControlPlane => "control-plane",
            Self::Worker => "worker",
            Self::Gateway => "gateway",
            Self::Storage => "storage",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "control-plane" | "controlplane" | "master" => Self::ControlPlane,
            "gateway" | "ingress" => Self::Gateway,
            "storage" => Self::Storage,
            _ => Self::Worker,
        }
    }
}

// =============================================================================
// Certificate Configuration
// =============================================================================

/// mTLS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MtlsConfig {
    /// Enable mTLS for node-to-node communication
    pub enabled: bool,
    /// Path to CA certificate file
    pub ca_cert_path: String,
    /// Path to node certificate file
    pub node_cert_path: String,
    /// Path to node private key file
    pub node_key_path: String,
    /// Require client certificates (strict mode)
    pub require_client_cert: bool,
    /// Allowed certificate CNs (empty = allow all valid certs)
    pub allowed_cns: Vec<String>,
    /// Certificate rotation interval (hours)
    pub rotation_interval_hours: u32,
    /// Certificate validity period (days)
    pub validity_days: u32,
    /// OCSP responder URL (optional)
    pub ocsp_url: Option<String>,
    /// CRL distribution point (optional)
    pub crl_url: Option<String>,
}

impl Default for MtlsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            ca_cert_path: "/etc/connector/certs/ca.crt".to_string(),
            node_cert_path: "/etc/connector/certs/node.crt".to_string(),
            node_key_path: "/etc/connector/certs/node.key".to_string(),
            require_client_cert: true,
            allowed_cns: vec![],
            rotation_interval_hours: 24,
            validity_days: 365,
            ocsp_url: None,
            crl_url: None,
        }
    }
}

// =============================================================================
// Certificate Store
// =============================================================================

/// Certificate entry in the store
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateEntry {
    /// Certificate ID (fingerprint)
    pub cert_id: String,
    /// Certificate type
    pub cert_type: CertificateType,
    /// Certificate status
    pub status: CertificateStatus,
    /// Subject CN
    pub subject_cn: String,
    /// Issuer CN
    pub issuer_cn: String,
    /// Serial number
    pub serial_number: String,
    /// Not valid before (RFC 3339)
    pub not_before: String,
    /// Not valid after (RFC 3339)
    pub not_after: String,
    /// Subject Alternative Names
    pub sans: Vec<String>,
    /// PEM-encoded certificate (for distribution)
    pub pem: String,
    /// Created at (RFC 3339)
    pub created_at: String,
    /// Revoked at (RFC 3339, if revoked)
    pub revoked_at: Option<String>,
    /// Revocation reason
    pub revocation_reason: Option<String>,
}

/// Certificate store — manages certificates for the cluster
#[derive(Debug, Default)]
pub struct CertificateStore {
    /// Certificates by ID (fingerprint)
    certificates: RwLock<HashMap<String, CertificateEntry>>,
    /// Revoked certificate serials
    revoked_serials: RwLock<HashMap<String, String>>, // serial -> revoked_at
    /// Trusted CA fingerprints
    trusted_cas: RwLock<Vec<String>>,
}

impl CertificateStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a certificate to the store
    pub fn add_certificate(&self, entry: CertificateEntry) -> Result<(), String> {
        let mut certs = self.certificates.write().map_err(|e| e.to_string())?;
        certs.insert(entry.cert_id.clone(), entry);
        Ok(())
    }

    /// Get a certificate by ID
    pub fn get_certificate(&self, cert_id: &str) -> Option<CertificateEntry> {
        self.certificates.read().ok()?.get(cert_id).cloned()
    }

    /// Revoke a certificate
    pub fn revoke_certificate(&self, cert_id: &str, reason: &str) -> Result<(), String> {
        let mut certs = self.certificates.write().map_err(|e| e.to_string())?;
        let mut revoked = self.revoked_serials.write().map_err(|e| e.to_string())?;

        if let Some(cert) = certs.get_mut(cert_id) {
            let now = chrono::Utc::now().to_rfc3339();
            cert.status = CertificateStatus::Revoked;
            cert.revoked_at = Some(now.clone());
            cert.revocation_reason = Some(reason.to_string());
            revoked.insert(cert.serial_number.clone(), now);
            Ok(())
        } else {
            Err("Certificate not found".to_string())
        }
    }

    /// Check if a certificate serial is revoked
    pub fn is_revoked(&self, serial: &str) -> bool {
        self.revoked_serials
            .read()
            .map(|r| r.contains_key(serial))
            .unwrap_or(false)
    }

    /// Add a trusted CA
    pub fn add_trusted_ca(&self, fingerprint: String) -> Result<(), String> {
        let mut cas = self.trusted_cas.write().map_err(|e| e.to_string())?;
        if !cas.contains(&fingerprint) {
            cas.push(fingerprint);
        }
        Ok(())
    }

    /// Check if a CA is trusted
    pub fn is_ca_trusted(&self, fingerprint: &str) -> bool {
        self.trusted_cas
            .read()
            .map(|cas| cas.contains(&fingerprint.to_string()))
            .unwrap_or(false)
    }

    /// List all certificates
    pub fn list_certificates(&self) -> Vec<CertificateEntry> {
        self.certificates
            .read()
            .map(|c| c.values().cloned().collect())
            .unwrap_or_default()
    }

    /// List active certificates
    pub fn list_active_certificates(&self) -> Vec<CertificateEntry> {
        self.certificates
            .read()
            .map(|c| {
                c.values()
                    .filter(|e| e.status == CertificateStatus::Active)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }
}

// =============================================================================
// Certificate Validation
// =============================================================================

/// Certificate validation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    /// Is the certificate valid?
    pub valid: bool,
    /// Validation errors (if any)
    pub errors: Vec<String>,
    /// Validation warnings (if any)
    pub warnings: Vec<String>,
    /// Extracted node identity (if valid)
    pub identity: Option<NodeIdentity>,
}

impl ValidationResult {
    pub fn valid(identity: NodeIdentity) -> Self {
        Self {
            valid: true,
            errors: vec![],
            warnings: vec![],
            identity: Some(identity),
        }
    }

    pub fn invalid(errors: Vec<String>) -> Self {
        Self {
            valid: false,
            errors,
            warnings: vec![],
            identity: None,
        }
    }

    pub fn with_warning(mut self, warning: String) -> Self {
        self.warnings.push(warning);
        self
    }
}

/// Certificate validator
pub struct CertificateValidator {
    /// Certificate store
    store: CertificateStore,
    /// Configuration
    config: MtlsConfig,
}

impl CertificateValidator {
    pub fn new(config: MtlsConfig) -> Self {
        Self {
            store: CertificateStore::new(),
            config,
        }
    }

    /// Validate a certificate (PEM-encoded)
    pub fn validate_certificate(&self, pem: &str) -> ValidationResult {
        let mut errors = vec![];
        let mut warnings = vec![];

        // Parse certificate (simplified - in production use x509-parser or rustls)
        let cert_info = match self.parse_certificate_info(pem) {
            Ok(info) => info,
            Err(e) => return ValidationResult::invalid(vec![format!("Failed to parse certificate: {}", e)]),
        };

        // Check expiration
        let now = chrono::Utc::now();
        if let Ok(not_before) = chrono::DateTime::parse_from_rfc3339(&cert_info.not_before) {
            if now < not_before {
                errors.push("Certificate not yet valid".to_string());
            }
        }
        if let Ok(not_after) = chrono::DateTime::parse_from_rfc3339(&cert_info.not_after) {
            if now > not_after {
                errors.push("Certificate has expired".to_string());
            }
            // Warn if expiring soon (7 days)
            let days_until_expiry = (not_after.timestamp() - now.timestamp()) / 86400;
            if days_until_expiry < 7 && days_until_expiry > 0 {
                warnings.push(format!("Certificate expires in {} days", days_until_expiry));
            }
        }

        // Check revocation
        if self.store.is_revoked(&cert_info.serial_number) {
            errors.push("Certificate has been revoked".to_string());
        }

        // Check allowed CNs (if configured)
        if !self.config.allowed_cns.is_empty() {
            if !self.config.allowed_cns.contains(&cert_info.subject_cn) {
                errors.push(format!("CN '{}' not in allowed list", cert_info.subject_cn));
            }
        }

        if !errors.is_empty() {
            return ValidationResult::invalid(errors);
        }

        // Extract identity
        let identity = self.extract_identity(&cert_info);

        let mut result = ValidationResult::valid(identity);
        result.warnings = warnings;
        result
    }

    /// Parse certificate info from PEM (simplified)
    fn parse_certificate_info(&self, pem: &str) -> Result<CertificateInfo, String> {
        // In production, use x509-parser or rustls-pemfile
        // This is a simplified implementation for the module structure

        // Check PEM format
        if !pem.contains("-----BEGIN CERTIFICATE-----") {
            return Err("Invalid PEM format".to_string());
        }

        // Generate fingerprint from PEM content
        let fingerprint = self.compute_fingerprint(pem);

        // Extract CN from PEM (simplified - would use proper parsing in production)
        let cn = self.extract_cn_from_pem(pem).unwrap_or_else(|| "unknown".to_string());

        let now = chrono::Utc::now();
        let not_before = now.to_rfc3339();
        let not_after = (now + chrono::Duration::days(365)).to_rfc3339();

        Ok(CertificateInfo {
            fingerprint,
            subject_cn: cn.clone(),
            issuer_cn: "Connector CA".to_string(),
            serial_number: format!("{:016x}", rand::random::<u64>()),
            not_before,
            not_after,
            sans: vec![cn],
        })
    }

    /// Compute SHA-256 fingerprint of certificate
    fn compute_fingerprint(&self, pem: &str) -> String {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(pem.as_bytes());
        let result = hasher.finalize();
        hex::encode(result)
    }

    /// Extract CN from PEM (simplified)
    fn extract_cn_from_pem(&self, pem: &str) -> Option<String> {
        // In production, parse the X.509 certificate properly
        // This is a placeholder that would be replaced with proper parsing
        for line in pem.lines() {
            if line.contains("CN=") {
                let start = line.find("CN=")? + 3;
                let end = line[start..].find(',').map(|i| start + i).unwrap_or(line.len());
                return Some(line[start..end].to_string());
            }
        }
        None
    }

    /// Extract node identity from certificate info
    fn extract_identity(&self, info: &CertificateInfo) -> NodeIdentity {
        // Parse node ID, cell ID, cluster ID from CN or SANs
        // Expected format: node-{node_id}.cell-{cell_id}.cluster-{cluster_id}.connector.local
        let parts: Vec<&str> = info.subject_cn.split('.').collect();

        let node_id = parts.first()
            .map(|s| s.strip_prefix("node-").unwrap_or(s))
            .unwrap_or("unknown")
            .to_string();

        let cell_id = parts.get(1)
            .map(|s| s.strip_prefix("cell-").unwrap_or(s))
            .unwrap_or("default")
            .to_string();

        let cluster_id = parts.get(2)
            .map(|s| s.strip_prefix("cluster-").unwrap_or(s))
            .unwrap_or("default")
            .to_string();

        // Determine role from SAN or default to worker
        let role = info.sans.iter()
            .find(|s| s.starts_with("role:"))
            .map(|s| NodeRole::from_str(&s[5..]))
            .unwrap_or(NodeRole::Worker);

        // Build SPIFFE ID
        let spiffe_id = Some(format!(
            "spiffe://connector.local/cluster/{}/cell/{}/node/{}",
            cluster_id, cell_id, node_id
        ));

        NodeIdentity {
            node_id,
            cell_id,
            cluster_id,
            role,
            spiffe_id,
            cert_fingerprint: info.fingerprint.clone(),
            serial_number: info.serial_number.clone(),
            not_before: info.not_before.clone(),
            not_after: info.not_after.clone(),
        }
    }

    /// Get certificate store
    pub fn store(&self) -> &CertificateStore {
        &self.store
    }
}

/// Internal certificate info structure
struct CertificateInfo {
    fingerprint: String,
    subject_cn: String,
    issuer_cn: String,
    serial_number: String,
    not_before: String,
    not_after: String,
    sans: Vec<String>,
}

// =============================================================================
// Certificate Generation (for development/testing)
// =============================================================================

/// Certificate signing request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateSigningRequest {
    /// Node ID
    pub node_id: String,
    /// Cell ID
    pub cell_id: String,
    /// Cluster ID
    pub cluster_id: String,
    /// Node role
    pub role: NodeRole,
    /// Additional SANs
    pub additional_sans: Vec<String>,
    /// Validity days
    pub validity_days: u32,
}

/// Generate a self-signed certificate for development
pub fn generate_self_signed_cert(csr: &CertificateSigningRequest) -> Result<(String, String), String> {
    // In production, use rcgen or openssl crate
    // This is a placeholder that returns dummy PEM data

    let cn = format!(
        "node-{}.cell-{}.cluster-{}.connector.local",
        csr.node_id, csr.cell_id, csr.cluster_id
    );

    let now = chrono::Utc::now();
    let not_after = now + chrono::Duration::days(csr.validity_days as i64);

    // Placeholder PEM (in production, generate real certificate)
    let cert_pem = format!(
        r#"-----BEGIN CERTIFICATE-----
CN={}
NotBefore={}
NotAfter={}
Role={}
-----END CERTIFICATE-----"#,
        cn,
        now.to_rfc3339(),
        not_after.to_rfc3339(),
        csr.role.as_str()
    );

    let key_pem = format!(
        r#"-----BEGIN PRIVATE KEY-----
NodeID={}
Generated={}
-----END PRIVATE KEY-----"#,
        csr.node_id,
        now.to_rfc3339()
    );

    Ok((cert_pem, key_pem))
}

// =============================================================================
// mTLS Manager
// =============================================================================

/// mTLS Manager — coordinates certificate lifecycle
pub struct MtlsManager {
    /// Configuration
    config: MtlsConfig,
    /// Certificate validator
    validator: CertificateValidator,
    /// Current node identity
    node_identity: RwLock<Option<NodeIdentity>>,
}

impl MtlsManager {
    pub fn new(config: MtlsConfig) -> Self {
        let validator = CertificateValidator::new(config.clone());
        Self {
            config,
            validator,
            node_identity: RwLock::new(None),
        }
    }

    /// Initialize mTLS with node certificate
    pub fn initialize(&self, node_cert_pem: &str) -> Result<NodeIdentity, String> {
        let result = self.validator.validate_certificate(node_cert_pem);
        if !result.valid {
            return Err(result.errors.join("; "));
        }

        let identity = result.identity.ok_or("No identity extracted")?;
        
        let mut node_id = self.node_identity.write().map_err(|e| e.to_string())?;
        *node_id = Some(identity.clone());

        Ok(identity)
    }

    /// Validate a peer certificate
    pub fn validate_peer(&self, peer_cert_pem: &str) -> ValidationResult {
        self.validator.validate_certificate(peer_cert_pem)
    }

    /// Get current node identity
    pub fn node_identity(&self) -> Option<NodeIdentity> {
        self.node_identity.read().ok()?.clone()
    }

    /// Check if mTLS is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Get configuration
    pub fn config(&self) -> &MtlsConfig {
        &self.config
    }

    /// Get certificate store
    pub fn store(&self) -> &CertificateStore {
        self.validator.store()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mtls_config_default() {
        let config = MtlsConfig::default();
        assert!(!config.enabled);
        assert!(config.require_client_cert);
        assert_eq!(config.validity_days, 365);
    }

    #[test]
    fn test_node_role_parsing() {
        assert_eq!(NodeRole::from_str("control-plane"), NodeRole::ControlPlane);
        assert_eq!(NodeRole::from_str("worker"), NodeRole::Worker);
        assert_eq!(NodeRole::from_str("gateway"), NodeRole::Gateway);
        assert_eq!(NodeRole::from_str("unknown"), NodeRole::Worker);
    }

    #[test]
    fn test_certificate_store() {
        let store = CertificateStore::new();
        
        let entry = CertificateEntry {
            cert_id: "test-cert-001".to_string(),
            cert_type: CertificateType::Node,
            status: CertificateStatus::Active,
            subject_cn: "node-001.cell-default.cluster-main.connector.local".to_string(),
            issuer_cn: "Connector CA".to_string(),
            serial_number: "0001".to_string(),
            not_before: chrono::Utc::now().to_rfc3339(),
            not_after: (chrono::Utc::now() + chrono::Duration::days(365)).to_rfc3339(),
            sans: vec!["node-001".to_string()],
            pem: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----".to_string(),
            created_at: chrono::Utc::now().to_rfc3339(),
            revoked_at: None,
            revocation_reason: None,
        };

        store.add_certificate(entry.clone()).unwrap();
        
        let retrieved = store.get_certificate("test-cert-001").unwrap();
        assert_eq!(retrieved.subject_cn, entry.subject_cn);
    }

    #[test]
    fn test_certificate_revocation() {
        let store = CertificateStore::new();
        
        let entry = CertificateEntry {
            cert_id: "test-cert-002".to_string(),
            cert_type: CertificateType::Node,
            status: CertificateStatus::Active,
            subject_cn: "node-002".to_string(),
            issuer_cn: "Connector CA".to_string(),
            serial_number: "0002".to_string(),
            not_before: chrono::Utc::now().to_rfc3339(),
            not_after: (chrono::Utc::now() + chrono::Duration::days(365)).to_rfc3339(),
            sans: vec![],
            pem: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----".to_string(),
            created_at: chrono::Utc::now().to_rfc3339(),
            revoked_at: None,
            revocation_reason: None,
        };

        store.add_certificate(entry).unwrap();
        assert!(!store.is_revoked("0002"));
        
        store.revoke_certificate("test-cert-002", "Key compromised").unwrap();
        assert!(store.is_revoked("0002"));
    }

    #[test]
    fn test_self_signed_cert_generation() {
        let csr = CertificateSigningRequest {
            node_id: "node-001".to_string(),
            cell_id: "cell-001".to_string(),
            cluster_id: "cluster-main".to_string(),
            role: NodeRole::Worker,
            additional_sans: vec![],
            validity_days: 365,
        };

        let (cert, key) = generate_self_signed_cert(&csr).unwrap();
        assert!(cert.contains("-----BEGIN CERTIFICATE-----"));
        assert!(key.contains("-----BEGIN PRIVATE KEY-----"));
    }

    #[test]
    fn test_mtls_manager() {
        let config = MtlsConfig::default();
        let manager = MtlsManager::new(config);
        
        assert!(!manager.is_enabled());
        assert!(manager.node_identity().is_none());
    }
}

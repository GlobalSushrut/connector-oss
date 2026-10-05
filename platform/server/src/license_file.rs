/// Track 5A: License File Format
/// Ed25519-signed license file: parse, validate, verify signature, extract tier + features.
/// File path: $LICENSE_FILE env var or ./license.dat
///
/// Format (JSON envelope):
/// {
///   "payload": { ...LicensePayload... },
///   "signature": "<hex-encoded Ed25519 signature over canonical JSON of payload>"
/// }
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

// ── Ed25519 public key embedded at compile time ───────────────────────────────
// Set via build.rs reading CONNECTOR_SIGNING_PUBKEY env var, or embed the test key.
// In production, replace this with the real platform public key bytes.
const PLATFORM_PUBLIC_KEY_HEX: &str = env!("CONNECTOR_SIGNING_PUBKEY_HEX");

// ── License payload ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicensePayload {
    /// Unique license ID
    pub license_id: String,
    /// Customer / organisation name
    pub customer:   String,
    /// Tier name: "Indie", "Startup", "Growth", "Business", "Scale", "Enterprise", "Core", "Sovereign"
    pub tier:       String,
    /// Unix timestamp (seconds) — when does the license expire? None = perpetual.
    pub valid_until: Option<i64>,
    /// Machine fingerprint this license is locked to. None = floating.
    pub machine_fingerprint: Option<String>,
    /// Maximum number of agents. None = unlimited.
    pub max_agents: Option<usize>,
    /// Maximum events per month. None = unlimited.
    pub max_events: Option<usize>,
    /// Retention in days.
    pub retention_days: u32,
    /// Explicit feature overrides (additions or removals from tier default).
    #[serde(default)]
    pub features: Vec<String>,
    /// License issue timestamp (Unix seconds).
    pub issued_at: i64,
    /// Platform instance ID this was issued for.
    pub instance_id: String,
    /// Schema version.
    #[serde(default = "default_schema_version")]
    pub schema_version: String,
}

fn default_schema_version() -> String { "1".to_string() }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseFile {
    pub payload:   LicensePayload,
    /// Hex-encoded Ed25519 signature over the canonical JSON of `payload`.
    pub signature: String,
}

// ── Validation result ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ValidatedLicense {
    pub payload:          LicensePayload,
    pub tier:             crate::license::Tier,
    pub features:         HashSet<String>,
    pub is_expired:       bool,
    pub fingerprint_ok:   bool,
}

impl ValidatedLicense {
    pub fn has_feature(&self, feature: &str) -> bool {
        self.features.contains(feature)
    }

    pub fn to_license_info(&self) -> crate::license::LicenseInfo {
        let mut info = crate::license::LicenseInfo::for_tier(self.tier);
        info.instance_id   = self.payload.instance_id.clone();
        info.max_agents    = self.payload.max_agents;
        info.max_events    = self.payload.max_events;
        info.retention_days = self.payload.retention_days;
        info.valid_until   = self.payload.valid_until;
        info
    }
}

// ── Parse + validate ──────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum LicenseError {
    Io(String),
    Parse(String),
    InvalidSignature,
    Expired,
    FingerprintMismatch,
    UnknownTier(String),
}

impl std::fmt::Display for LicenseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e)              => write!(f, "License file I/O error: {e}"),
            Self::Parse(e)           => write!(f, "License parse error: {e}"),
            Self::InvalidSignature   => write!(f, "License signature invalid — file tampered or wrong key"),
            Self::Expired            => write!(f, "License expired"),
            Self::FingerprintMismatch => write!(f, "License locked to a different machine"),
            Self::UnknownTier(t)     => write!(f, "Unknown license tier: {t}"),
        }
    }
}

/// Load and validate a license file from disk.
/// Path: `$LICENSE_FILE` env var, or `./license.dat` as default.
pub fn load_and_validate(machine_fp: Option<&str>) -> Result<ValidatedLicense, LicenseError> {
    let path = std::env::var("LICENSE_FILE").unwrap_or_else(|_| "./license.dat".to_string());
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| LicenseError::Io(format!("{}: {}", path, e)))?;
    validate_from_str(&raw, machine_fp)
}

/// Validate a license from a JSON string (for testing / in-memory use).
pub fn validate_from_str(json: &str, machine_fp: Option<&str>) -> Result<ValidatedLicense, LicenseError> {
    let lf: LicenseFile = serde_json::from_str(json)
        .map_err(|e| LicenseError::Parse(e.to_string()))?;
    validate(lf, machine_fp)
}

/// Core validation: signature check → expiry → fingerprint → tier parse.
pub fn validate(lf: LicenseFile, machine_fp: Option<&str>) -> Result<ValidatedLicense, LicenseError> {
    // 1. Verify Ed25519 signature
    verify_signature(&lf)?;

    // 2. Expiry check
    let now_secs = chrono::Utc::now().timestamp();
    let is_expired = lf.payload.valid_until.map_or(false, |exp| now_secs > exp);

    // 3. Machine fingerprint check (soft: warn, not hard-fail for floating licenses)
    let fingerprint_ok = match (&lf.payload.machine_fingerprint, machine_fp) {
        (Some(locked), Some(actual)) => locked == actual,
        (Some(_locked), None)        => false,  // license locked but no fingerprint available
        (None, _)                    => true,   // floating license
    };

    // 4. Parse tier
    let tier = parse_tier(&lf.payload.tier)?;

    // 5. Build feature set from tier defaults + payload overrides
    let features = build_features(tier, &lf.payload.features);

    Ok(ValidatedLicense {
        payload:        lf.payload,
        tier,
        features,
        is_expired,
        fingerprint_ok,
    })
}

fn verify_signature(lf: &LicenseFile) -> Result<(), LicenseError> {
    use ed25519_dalek::{Signature, VerifyingKey};

    // Decode public key
    let pub_key_bytes = hex::decode(PLATFORM_PUBLIC_KEY_HEX)
        .map_err(|_| LicenseError::InvalidSignature)?;
    let pub_key_arr: [u8; 32] = pub_key_bytes.try_into()
        .map_err(|_| LicenseError::InvalidSignature)?;
    let verifying_key = VerifyingKey::from_bytes(&pub_key_arr)
        .map_err(|_| LicenseError::InvalidSignature)?;

    // Canonical payload bytes: deterministic JSON serialisation
    let payload_json = serde_json::to_string(&lf.payload)
        .map_err(|_| LicenseError::InvalidSignature)?;

    // Decode signature
    let sig_bytes = hex::decode(&lf.signature)
        .map_err(|_| LicenseError::InvalidSignature)?;
    let sig_arr: [u8; 64] = sig_bytes.try_into()
        .map_err(|_| LicenseError::InvalidSignature)?;
    let signature = Signature::from_bytes(&sig_arr);

    use ed25519_dalek::Verifier;
    verifying_key.verify(payload_json.as_bytes(), &signature)
        .map_err(|_| LicenseError::InvalidSignature)
}

fn parse_tier(tier_str: &str) -> Result<crate::license::Tier, LicenseError> {
    match tier_str {
        "Indie"      => Ok(crate::license::Tier::Indie),
        "Startup"    => Ok(crate::license::Tier::Startup),
        "Growth"     => Ok(crate::license::Tier::Growth),
        "Business"   => Ok(crate::license::Tier::Business),
        "Scale"      => Ok(crate::license::Tier::Scale),
        "Enterprise" => Ok(crate::license::Tier::Enterprise),
        "Core"       => Ok(crate::license::Tier::Core),
        "Sovereign"  => Ok(crate::license::Tier::Sovereign),
        other        => Err(LicenseError::UnknownTier(other.to_string())),
    }
}

fn build_features(tier: crate::license::Tier, overrides: &[String]) -> HashSet<String> {
    use crate::license::{Tier::*, Feature::*};
    // Default features per tier
    let mut feats: HashSet<String> = match tier {
        Sovereign | Core | Enterprise =>
            ["pdf_export", "alerting", "sso", "multi_cell", "knowledge_graph", "rag",
             "multi_agent", "experiments", "judgment_engine", "dispute_reports",
             "custom_compliance", "on_premise", "air_gapped", "dedicated_csm", "custom_branding"]
                .iter().map(|s| s.to_string()).collect(),
        Scale =>
            ["pdf_export", "alerting", "sso", "multi_cell", "knowledge_graph", "rag",
             "multi_agent", "experiments", "judgment_engine", "dispute_reports",
             "custom_compliance", "dedicated_csm"]
                .iter().map(|s| s.to_string()).collect(),
        Business =>
            ["pdf_export", "alerting", "sso", "knowledge_graph", "rag",
             "multi_agent", "experiments", "judgment_engine", "dispute_reports", "custom_compliance"]
                .iter().map(|s| s.to_string()).collect(),
        Growth =>
            ["pdf_export", "alerting", "knowledge_graph", "rag", "multi_agent",
             "experiments", "dispute_reports"]
                .iter().map(|s| s.to_string()).collect(),
        Startup =>
            ["pdf_export", "alerting", "knowledge_graph", "experiments"]
                .iter().map(|s| s.to_string()).collect(),
        Indie =>
            [].iter().map(|s: &&str| s.to_string()).collect(),
    };

    // Apply overrides: "+feature_name" adds, "-feature_name" removes
    for ov in overrides {
        if let Some(name) = ov.strip_prefix('+') {
            feats.insert(name.to_string());
        } else if let Some(name) = ov.strip_prefix('-') {
            feats.remove(name);
        } else {
            feats.insert(ov.clone());
        }
    }

    // Suppress unused import warnings
    let _ = (PdfExport, Alerting, Sso, CustomBranding, MultiCell, KnowledgeGraph, Rag,
             MultiAgent, Experiments, JudgmentEngine, DisputeReports, CustomCompliance,
             OnPremise, AirGapped, DedicatedCsm);

    feats
}

/// Generate a signed license file (used by the license server / keygen tool).
/// Requires the private key bytes.
pub fn sign_license(payload: LicensePayload, private_key_bytes: &[u8; 32]) -> Result<LicenseFile, String> {
    use ed25519_dalek::{SigningKey, Signer};

    let signing_key = SigningKey::from_bytes(private_key_bytes);
    let payload_json = serde_json::to_string(&payload)
        .map_err(|e| e.to_string())?;
    let signature = signing_key.sign(payload_json.as_bytes());
    Ok(LicenseFile {
        payload,
        signature: hex::encode(signature.to_bytes()),
    })
}

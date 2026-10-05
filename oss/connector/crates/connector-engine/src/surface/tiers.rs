//! Trust Tiers — T0-T3 verification layers per Books pattern
//!
//! Every surface has a trust tier indicating its verification level.

use serde::{Deserialize, Serialize};

/// Trust tier for surface data (following Books T0-T3 model)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum TrustTier {
    /// T0: Notarized — Kernel HMAC audit chain, authoritative, tamper-evident
    T0Notarized,
    /// T1: Recorded — Engine store audit log, may lag by flush interval
    T1Recorded,
    /// T2: Derived — Computed projections, statements, trust scores
    T2Derived,
    /// T3: Rendered — CLI/API output, ephemeral, for display only
    T3Rendered,
}

impl TrustTier {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::T0Notarized => "T0:NOTARIZED",
            Self::T1Recorded => "T1:RECORDED",
            Self::T2Derived => "T2:DERIVED",
            Self::T3Rendered => "T3:RENDERED",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::T0Notarized => "Kernel HMAC audit chain — authoritative, append-only, tamper-evident",
            Self::T1Recorded => "Engine store audit log — may lag by flush interval",
            Self::T2Derived => "Computed projections — statements, costs, trust scores",
            Self::T3Rendered => "CLI/API output — ephemeral, for display only",
        }
    }

    pub fn is_authoritative(&self) -> bool {
        matches!(self, Self::T0Notarized | Self::T1Recorded)
    }

    pub fn requires_verification(&self) -> bool {
        matches!(self, Self::T2Derived | Self::T3Rendered)
    }
}

/// Verification status for a surface
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TierVerification {
    pub tier: TrustTier,
    pub verified: bool,
    pub verification_method: VerificationMethod,
    pub verified_at: Option<i64>,
    pub verifier: Option<String>,
    pub chain_position: Option<u64>,
    pub hmac: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationMethod {
    None,
    HmacChain,
    MerkleProof,
    ScittReceipt,
    SignatureVerify,
    Reconciliation,
}

impl TierVerification {
    pub fn t0_notarized(hmac: &str, chain_position: u64) -> Self {
        Self {
            tier: TrustTier::T0Notarized,
            verified: true,
            verification_method: VerificationMethod::HmacChain,
            verified_at: Some(chrono::Utc::now().timestamp_millis()),
            verifier: Some("kernel".into()),
            chain_position: Some(chain_position),
            hmac: Some(hmac.to_string()),
        }
    }

    pub fn t1_recorded() -> Self {
        let node_id = std::env::var("CONNECTOR_NODE_ID").unwrap_or_else(|_| "local".into());
        Self {
            tier: TrustTier::T1Recorded,
            verified: true,
            verification_method: VerificationMethod::Reconciliation,
            verified_at: Some(chrono::Utc::now().timestamp_millis()),
            verifier: Some(format!("engine@{}", node_id)),
            chain_position: None,
            hmac: None,
        }
    }

    pub fn t2_derived() -> Self {
        Self {
            tier: TrustTier::T2Derived,
            verified: false,
            verification_method: VerificationMethod::None,
            verified_at: None,
            verifier: None,
            chain_position: None,
            hmac: None,
        }
    }

    pub fn t3_rendered() -> Self {
        Self {
            tier: TrustTier::T3Rendered,
            verified: false,
            verification_method: VerificationMethod::None,
            verified_at: None,
            verifier: None,
            chain_position: None,
            hmac: None,
        }
    }

    pub fn with_merkle_proof(mut self, verifier: &str) -> Self {
        self.verification_method = VerificationMethod::MerkleProof;
        self.verified = true;
        self.verified_at = Some(chrono::Utc::now().timestamp_millis());
        self.verifier = Some(verifier.to_string());
        self
    }
}

/// Surface with trust tier metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TieredSurface<T> {
    pub data: T,
    pub tier: TierVerification,
    pub source_tiers: Vec<TrustTier>,
}

impl<T> TieredSurface<T> {
    pub fn new(data: T, tier: TierVerification) -> Self {
        Self { data, tier, source_tiers: vec![] }
    }

    pub fn with_sources(mut self, sources: Vec<TrustTier>) -> Self {
        self.source_tiers = sources;
        self
    }

    /// Effective tier is the lowest of all source tiers
    pub fn effective_tier(&self) -> TrustTier {
        self.source_tiers.iter()
            .min()
            .copied()
            .unwrap_or(self.tier.tier)
    }

    pub fn is_authoritative(&self) -> bool {
        self.effective_tier().is_authoritative()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tier_ordering() {
        assert!(TrustTier::T0Notarized < TrustTier::T1Recorded);
        assert!(TrustTier::T1Recorded < TrustTier::T2Derived);
        assert!(TrustTier::T2Derived < TrustTier::T3Rendered);
    }

    #[test]
    fn test_tier_verification() {
        let v = TierVerification::t0_notarized("hmac123", 42);
        assert!(v.verified);
        assert_eq!(v.tier, TrustTier::T0Notarized);
    }

    #[test]
    fn test_tiered_surface() {
        let surface = TieredSurface::new("data", TierVerification::t2_derived())
            .with_sources(vec![TrustTier::T1Recorded, TrustTier::T2Derived]);
        assert_eq!(surface.effective_tier(), TrustTier::T1Recorded);
    }
}

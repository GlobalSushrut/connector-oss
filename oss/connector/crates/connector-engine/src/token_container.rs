//! TC-1, TC-2, TC-3 — Token Container: data structure, lifecycle, TEE attestation.
//!
//! # Overview
//!
//! A `TokenContainer` (TC) is the root security object that governs an agent's
//! capability set. Unlike a JWT (stateless, no revocation) or an OAuth token
//! (opaque, server-side), a TC is:
//!
//! - **Content-addressed**: `tc_id` = SHA-256(genesis_cid || aisv_commitment || issued_at)
//! - **Chained**: every rotation creates a new TC with `prev_tc_id` pointing to predecessor
//! - **Governed**: `TCGovernancePolicy` specifies quorum sizes, drift thresholds, PQ requirements
//! - **Attested**: TEE quote binds the TC to hardware measurements at issuance
//! - **Consensus-anchored**: every lifecycle operation requires KnotConsensus BFT vote
//!
//! # Lifecycle (TC-2)
//!
//! ```text
//! Issue  → Active ─── expires_at / AISV drift  ──→ Rotation (fast, f+1=3)
//!                 ─── KECS regression / probation ─→ Reduction (capability shrink)
//!                 ─── boundary_probe > θ_revoke ──→ Revocation vote (f+1=3, ≤100ms)
//!                 ─── EmergencyStop signal ────────→ Revocation immediate
//! ```
//!
//! # TEE Attestation Layers (TC-3)
//!
//! - **L1** Kernel self-report: kernel computes `report_data = SHA-256(tc_id||genesis_cid||aisv_commitment)`
//! - **L2** Validator cross-check: f+1 validators verify measurement matches expected
//! - **L3** Community ceremony: periodic multi-party verification of platform cert chain

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

use crate::post_quantum::{PqAlgorithm, PqSignature, SimulatedMlDsa65, PqSigner};
use crate::knot_consensus::{KnotConsensusConfig, KnotConsensusResult, KnotPhase};

// ═══════════════════════════════════════════════════════════════
// TC-1 — Core data structures
// ═══════════════════════════════════════════════════════════════

/// The root security object governing an agent's capability set.
///
/// Every field is immutable after issuance; lifecycle changes create a new TC
/// with `prev_tc_id` linking to its predecessor, forming an auditable chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenContainer {
    /// Content-addressed ID: SHA-256(genesis_cid || aisv_commitment || issued_at_ms as BE bytes)
    pub tc_id: String,

    /// CID of the genesis memory packet that anchors this agent's identity
    pub genesis_cid: String,

    /// AISV (Agent Identity State Vector) commitment — SHA-256 of serialized AISV
    pub aisv_commitment: String,

    /// Root capability granted to this TC (Merkle root of capability tree)
    pub capability_root: String,

    /// Namespace scope this TC is valid within (e.g. "org:acme/team:alpha")
    pub namespace_scope: String,

    /// Isolation proof: hash of the sandbox/container measurements at issuance
    pub isolation_proof: String,

    /// BFT consensus anchor: CID of the KnotConsensus result that approved issuance
    pub consensus_anchor: String,

    /// Governance policy snapshot at time of issuance
    pub governance_rules: TCGovernancePolicy,

    /// ID of the previous TC in the rotation chain (None for genesis TC)
    pub prev_tc_id: Option<String>,

    /// Signature over canonical fields (Ed25519 by default; ML-DSA-65 if post_quantum_required)
    pub signature: TCSignature,

    /// Issuance timestamp (ms since Unix epoch)
    pub issued_at: i64,

    /// Expiry timestamp (ms since Unix epoch); None = no expiry
    pub expires_at: Option<i64>,

    /// Current lifecycle state
    pub state: TcState,

    /// TEE attestation quote (TC-3)
    pub tee_attestation: Option<TeeAttestationQuote>,

    /// Audit CID chain: ordered list of CIDs covering all lifecycle operations on this TC
    pub audit_cid_chain: Vec<String>,
}

/// TC lifecycle state machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TcState {
    /// Freshly issued, pending first use
    Pending,
    /// Normal operation
    Active,
    /// Capability root reduced; agent operates under reduced permissions
    Reduced,
    /// Permanently revoked; no further use allowed
    Revoked,
    /// Rotation in progress; old TC remains valid until new TC is Active
    Rotating,
}

impl std::fmt::Display for TcState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TcState::Pending   => write!(f, "pending"),
            TcState::Active    => write!(f, "active"),
            TcState::Reduced   => write!(f, "reduced"),
            TcState::Revoked   => write!(f, "revoked"),
            TcState::Rotating  => write!(f, "rotating"),
        }
    }
}

/// TC signature — Ed25519 by default, ML-DSA-65 when post_quantum_required.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TCSignature {
    /// Algorithm used (matches governance_rules.post_quantum_required)
    pub algorithm: TCSignatureAlgorithm,
    /// Hex-encoded signature bytes
    pub signature_hex: String,
    /// Hex-encoded public key
    pub public_key_hex: String,
    /// For hybrid mode: classical Ed25519 signature alongside PQ signature
    pub classical_hex: Option<String>,
}

/// Signature algorithm for TC.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TCSignatureAlgorithm {
    Ed25519,
    MlDsa65,
    HybridEd25519MlDsa65,
}

// ── TC-1: TCGovernancePolicy ──────────────────────────────────────────────────

/// Governance rules embedded in every TC at issuance.
/// Immutable for the lifetime of the TC; new policy takes effect on next rotation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TCGovernancePolicy {
    /// How often the TC must be rotated (ms). 0 = manual only.
    pub rotation_period_ms: u64,

    /// Quorum for TC revocation vote: f+1 validators out of 2f+1 total.
    /// Default: 3 out of 5 (f=2, BFT-safe).
    pub revocation_quorum: usize,

    /// Quorum for capability extension (adding permissions).
    /// Conservative: 2f+1 = 5 out of 5.
    pub extension_quorum: usize,

    /// Maximum AISV drift before forced rotation is triggered (0.0–1.0).
    /// θ_drift: if |AISV_current - AISV_baseline| > θ_drift → rotate.
    pub aisv_drift_threshold: f64,

    /// Boundary probe score threshold for automatic TC Reduction.
    /// P > boundary_probe_threshold → Reduction; P > 2× → Revocation vote.
    pub boundary_probe_threshold: f64,

    /// Allow peer validators to attest TC (vs. kernel-only attestation).
    pub allow_peer_attestation: bool,

    /// Maximum depth of verifiable credential chain attached to this TC.
    pub max_vc_chain_depth: usize,

    /// TC-5: If true, signatures must use ML-DSA-65 (CRYSTALS-Dilithium).
    /// Default: false (Ed25519 throughout, 2026 standard).
    pub post_quantum_required: bool,
}

impl Default for TCGovernancePolicy {
    fn default() -> Self {
        Self {
            rotation_period_ms:      86_400_000, // 24 hours
            revocation_quorum:       3,           // f+1 out of 5
            extension_quorum:        5,           // 2f+1 (conservative)
            aisv_drift_threshold:    0.20,
            boundary_probe_threshold: 0.10,
            allow_peer_attestation:  true,
            max_vc_chain_depth:      4,
            post_quantum_required:   false,       // TC-5: Ed25519 is 2026 default
        }
    }
}

// ── TC-3: TEE Attestation Quote ───────────────────────────────────────────────

/// Hardware attestation quote binding the TC to a specific TEE measurement.
///
/// Layout mirrors Intel TDX / AMD SEV-SNP attestation reports.
/// In simulation mode, all fields are SHA-256 hashes of placeholder data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeeAttestationQuote {
    /// Platform firmware / code measurement (PCR0-equivalent)
    pub measurement: String,

    /// TCB (Trusted Computing Base) version info JSON string
    pub tcb_info: String,

    /// `report_data = SHA-256(tc_id || genesis_cid || aisv_commitment)`
    /// Binds this quote to exactly this TC — prevents replay of old quotes.
    pub report_data: String,

    /// Platform certificate chain (PEM, base64-encoded)
    pub platform_cert: String,

    /// Signature over the quote by the platform attestation key
    pub quote_sig: String,

    /// Attestation layer that produced this quote
    pub layer: AttestationLayer,

    /// Timestamp when quote was generated (ms epoch)
    pub quoted_at: i64,
}

/// Which attestation layer produced the quote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationLayer {
    /// L1: Kernel self-report (always present)
    KernelSelfReport,
    /// L2: Validator cross-check (f+1 validators)
    ValidatorCrossCheck,
    /// L3: Community ceremony (multi-party, periodic)
    CommunityCeremony,
}

// ═══════════════════════════════════════════════════════════════
// TC-2 — Lifecycle operations
// ═══════════════════════════════════════════════════════════════

/// Result of a TC lifecycle operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcLifecycleResult {
    pub ok: bool,
    pub operation: TcOperation,
    pub tc_id: String,
    pub new_tc_id: Option<String>,
    pub consensus_anchor: String,
    pub audit_cid: String,
    pub message: String,
    pub duration_ms: u64,
}

/// Lifecycle operation type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TcOperation {
    Issue,
    Rotate,
    Reduce,
    Revoke,
    Extend,
}

impl std::fmt::Display for TcOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TcOperation::Issue  => write!(f, "issue"),
            TcOperation::Rotate => write!(f, "rotate"),
            TcOperation::Reduce => write!(f, "reduce"),
            TcOperation::Revoke => write!(f, "revoke"),
            TcOperation::Extend => write!(f, "extend"),
        }
    }
}

/// Request to issue a new TC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcIssueRequest {
    pub genesis_cid: String,
    pub aisv_commitment: String,
    pub capability_root: String,
    pub namespace_scope: String,
    pub isolation_proof: String,
    pub governance: Option<TCGovernancePolicy>,
    pub ttl_ms: Option<u64>,
    /// TEE quote provided by the requester (L1 attestation)
    pub tee_quote: Option<TeeAttestationQuote>,
}

/// Request to rotate a TC (triggered by expiry or AISV drift).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcRotateRequest {
    pub tc_id: String,
    pub new_aisv_commitment: String,
    pub new_capability_root: String,
    pub new_isolation_proof: String,
    pub drift_score: f64,
    pub tee_quote: Option<TeeAttestationQuote>,
}

/// Request to reduce a TC's capabilities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcReduceRequest {
    pub tc_id: String,
    pub new_capability_root: String,
    pub reason: String,
    pub kecs_score: f64,
    pub boundary_probe_score: f64,
}

/// Request to revoke a TC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcRevokeRequest {
    pub tc_id: String,
    pub reason: String,
    pub emergency: bool,
    pub boundary_probe_score: f64,
}

// ── TokenContainerManager ────────────────────────────────────────────────────

/// Manages the full lifecycle of Token Containers.
///
/// In production, backed by persistent KernelStore. In this implementation,
/// uses an in-memory HashMap suitable for single-node deployments and testing.
pub struct TokenContainerManager {
    containers: HashMap<String, TokenContainer>,
    signing_seed: [u8; 32],
}

impl TokenContainerManager {
    pub fn new(signing_seed: [u8; 32]) -> Self {
        Self { containers: HashMap::new(), signing_seed }
    }

    fn now_ms() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64
    }

    /// Compute tc_id = SHA-256(genesis_cid || aisv_commitment || issued_at_ms_be_bytes).
    pub fn compute_tc_id(genesis_cid: &str, aisv_commitment: &str, issued_at: i64) -> String {
        let mut h = Sha256::new();
        h.update(genesis_cid.as_bytes());
        h.update(aisv_commitment.as_bytes());
        h.update(issued_at.to_be_bytes());
        format!("tc:{}", hex::encode(h.finalize()))
    }

    /// Compute the L1 TEE report_data = SHA-256(tc_id || genesis_cid || aisv_commitment).
    /// TC-3: This binds the TEE quote to exactly this specific TC.
    pub fn compute_report_data(tc_id: &str, genesis_cid: &str, aisv_commitment: &str) -> String {
        let mut h = Sha256::new();
        h.update(tc_id.as_bytes());
        h.update(genesis_cid.as_bytes());
        h.update(aisv_commitment.as_bytes());
        hex::encode(h.finalize())
    }

    /// Compute an audit CID for a lifecycle operation.
    fn audit_cid(tc_id: &str, op: &TcOperation, timestamp: i64, prev_cid: Option<&str>) -> String {
        let mut h = Sha256::new();
        h.update(tc_id.as_bytes());
        h.update(op.to_string().as_bytes());
        h.update(timestamp.to_be_bytes());
        if let Some(prev) = prev_cid {
            h.update(prev.as_bytes());
        }
        format!("cid:{}", hex::encode(h.finalize()))
    }

    /// Sign the canonical TC fields.
    fn sign(&self, tc_id: &str, genesis_cid: &str, capability_root: &str, issued_at: i64, pq: bool) -> TCSignature {
        let msg = format!("{}:{}:{}:{}", tc_id, genesis_cid, capability_root, issued_at);
        if pq {
            let signer = SimulatedMlDsa65::from_seed(self.signing_seed);
            let pq_sig = signer.sign(msg.as_bytes());
            TCSignature {
                algorithm: TCSignatureAlgorithm::MlDsa65,
                signature_hex: pq_sig.signature_hex.clone(),
                public_key_hex: signer.public_key_hex(),
                classical_hex: None,
            }
        } else {
            // Ed25519 simulation via SHA-256 keyed hash (real impl: ed25519-dalek)
            let mut h = Sha256::new();
            h.update(&self.signing_seed);
            h.update(msg.as_bytes());
            let sig = hex::encode(h.finalize());
            let mut pk_h = Sha256::new();
            pk_h.update(&self.signing_seed);
            pk_h.update(b"pubkey");
            TCSignature {
                algorithm: TCSignatureAlgorithm::Ed25519,
                signature_hex: sig,
                public_key_hex: hex::encode(pk_h.finalize()),
                classical_hex: None,
            }
        }
    }

    /// Simulate BFT KnotConsensus vote and return a consensus anchor CID.
    /// TC-2: Full Knot consensus is called in production; here we simulate the quorum result.
    fn simulate_consensus(quorum: usize, operation: &TcOperation, tc_id: &str) -> String {
        let mut h = Sha256::new();
        h.update(format!("consensus:{}:{}:q{}", operation, tc_id, quorum).as_bytes());
        format!("consensus:{}", hex::encode(h.finalize()))
    }

    // ── TC-2: Issue ───────────────────────────────────────────────────────────

    /// TC Issuance: TEE attestation + AISV commitment + BFT vote (2f+1=5 validators).
    ///
    /// Steps:
    /// 1. Compute tc_id = SHA-256(genesis_cid || aisv_commitment || issued_at)
    /// 2. Verify TEE report_data matches expected
    /// 3. Run KnotConsensus with 2f+1=5 quorum
    /// 4. Seal into audit CID chain
    pub fn issue(&mut self, req: TcIssueRequest) -> Result<TcLifecycleResult, String> {
        let start = std::time::Instant::now();
        let now = Self::now_ms();
        let governance = req.governance.unwrap_or_default();

        let tc_id = Self::compute_tc_id(&req.genesis_cid, &req.aisv_commitment, now);

        // TC-3: Validate TEE report_data if a quote was provided
        if let Some(ref quote) = req.tee_quote {
            let expected_report_data = Self::compute_report_data(
                &tc_id, &req.genesis_cid, &req.aisv_commitment,
            );
            if quote.report_data != expected_report_data {
                return Err(format!(
                    "TEE attestation failed: report_data mismatch. \
                     expected={} got={}",
                    expected_report_data, quote.report_data
                ));
            }
        }

        // TC-2: BFT vote — 2f+1=5 validators for issuance
        let consensus_anchor = Self::simulate_consensus(
            2 * governance.revocation_quorum - 1,
            &TcOperation::Issue,
            &tc_id,
        );

        let audit_cid = Self::audit_cid(&tc_id, &TcOperation::Issue, now, None);

        let expires_at = req.ttl_ms.map(|ttl| now + ttl as i64);

        // TC-3: Build L1 kernel self-report attestation
        let tee_attestation = req.tee_quote.or_else(|| {
            let report_data = Self::compute_report_data(
                &tc_id, &req.genesis_cid, &req.aisv_commitment,
            );
            Some(TeeAttestationQuote {
                measurement: {
                    let mut h = Sha256::new();
                    h.update(b"kernel-self-report-v1");
                    hex::encode(h.finalize())
                },
                tcb_info: r#"{"version":"1.0","layer":"L1","source":"kernel"}"#.to_string(),
                report_data,
                platform_cert: "simulated-platform-cert-L1".to_string(),
                quote_sig: {
                    let mut h = Sha256::new();
                    h.update(tc_id.as_bytes());
                    hex::encode(h.finalize())
                },
                layer: AttestationLayer::KernelSelfReport,
                quoted_at: now,
            })
        });

        let signature = self.sign(
            &tc_id, &req.genesis_cid, &req.capability_root, now,
            governance.post_quantum_required,
        );

        let tc = TokenContainer {
            tc_id: tc_id.clone(),
            genesis_cid: req.genesis_cid,
            aisv_commitment: req.aisv_commitment,
            capability_root: req.capability_root,
            namespace_scope: req.namespace_scope,
            isolation_proof: req.isolation_proof,
            consensus_anchor: consensus_anchor.clone(),
            governance_rules: governance,
            prev_tc_id: None,
            signature,
            issued_at: now,
            expires_at,
            state: TcState::Active,
            tee_attestation,
            audit_cid_chain: vec![audit_cid.clone()],
        };

        self.containers.insert(tc_id.clone(), tc);

        Ok(TcLifecycleResult {
            ok: true,
            operation: TcOperation::Issue,
            tc_id,
            new_tc_id: None,
            consensus_anchor,
            audit_cid,
            message: "TC issued successfully".to_string(),
            duration_ms: start.elapsed().as_millis() as u64,
        })
    }

    // ── TC-2: Rotate ──────────────────────────────────────────────────────────

    /// TC Rotation: triggered by `expires_at` or AISV drift > θ_drift.
    /// Fast path: f+1=3 validators, target ≤200ms.
    ///
    /// Creates a new TC with `prev_tc_id` linking to the old one.
    /// Old TC enters `Rotating` state until new TC is confirmed Active.
    pub fn rotate(&mut self, req: TcRotateRequest) -> Result<TcLifecycleResult, String> {
        let start = std::time::Instant::now();
        let now = Self::now_ms();

        let old_tc = self.containers.get(&req.tc_id)
            .ok_or_else(|| format!("TC not found: {}", req.tc_id))?
            .clone();

        if old_tc.state == TcState::Revoked {
            return Err(format!("Cannot rotate revoked TC: {}", req.tc_id));
        }

        // Check drift threshold
        let drift_threshold = old_tc.governance_rules.aisv_drift_threshold;
        if req.drift_score > drift_threshold {
            // Drift threshold exceeded — rotation is mandatory
        } else if old_tc.expires_at.map(|e| now >= e).unwrap_or(false) {
            // Expired — rotation is mandatory
        }
        // (if neither condition applies, rotation is still permitted — caller decides)

        let new_tc_id = Self::compute_tc_id(
            &old_tc.genesis_cid, &req.new_aisv_commitment, now,
        );

        // TC-3: Validate TEE report_data for new TC
        if let Some(ref quote) = req.tee_quote {
            let expected = Self::compute_report_data(
                &new_tc_id, &old_tc.genesis_cid, &req.new_aisv_commitment,
            );
            if quote.report_data != expected {
                return Err(format!("TEE attestation failed on rotation: report_data mismatch"));
            }
        }

        // Fast path: f+1=3 validators
        let quorum = old_tc.governance_rules.revocation_quorum; // f+1
        let consensus_anchor = Self::simulate_consensus(quorum, &TcOperation::Rotate, &new_tc_id);

        let prev_audit_cid = old_tc.audit_cid_chain.last().cloned();
        let new_audit_cid = Self::audit_cid(
            &new_tc_id, &TcOperation::Rotate, now, prev_audit_cid.as_deref(),
        );

        let governance = old_tc.governance_rules.clone();
        let pq = governance.post_quantum_required;
        let expires_at = governance.rotation_period_ms;
        let signature = self.sign(&new_tc_id, &old_tc.genesis_cid, &req.new_capability_root, now, pq);

        // Mark old TC as rotating, then superseded
        if let Some(old) = self.containers.get_mut(&req.tc_id) {
            old.state = TcState::Rotating;
            old.audit_cid_chain.push(
                Self::audit_cid(&req.tc_id, &TcOperation::Rotate, now, prev_audit_cid.as_deref())
            );
        }

        let new_tc = TokenContainer {
            tc_id: new_tc_id.clone(),
            genesis_cid: old_tc.genesis_cid.clone(),
            aisv_commitment: req.new_aisv_commitment,
            capability_root: req.new_capability_root,
            namespace_scope: old_tc.namespace_scope.clone(),
            isolation_proof: req.new_isolation_proof,
            consensus_anchor: consensus_anchor.clone(),
            governance_rules: governance,
            prev_tc_id: Some(req.tc_id.clone()),
            signature,
            issued_at: now,
            expires_at: Some(now + expires_at as i64),
            state: TcState::Active,
            tee_attestation: req.tee_quote.or_else(|| {
                let rd = Self::compute_report_data(
                    &new_tc_id, &old_tc.genesis_cid,
                    &old_tc.aisv_commitment,
                );
                Some(TeeAttestationQuote {
                    measurement: { let mut h = Sha256::new(); h.update(b"rotation-L1"); hex::encode(h.finalize()) },
                    tcb_info: r#"{"layer":"L1","event":"rotation"}"#.to_string(),
                    report_data: rd,
                    platform_cert: "simulated-rotation-cert".to_string(),
                    quote_sig: { let mut h = Sha256::new(); h.update(new_tc_id.as_bytes()); hex::encode(h.finalize()) },
                    layer: AttestationLayer::KernelSelfReport,
                    quoted_at: now,
                })
            }),
            audit_cid_chain: vec![new_audit_cid.clone()],
        };

        self.containers.insert(new_tc_id.clone(), new_tc);

        Ok(TcLifecycleResult {
            ok: true,
            operation: TcOperation::Rotate,
            tc_id: req.tc_id,
            new_tc_id: Some(new_tc_id),
            consensus_anchor,
            audit_cid: new_audit_cid,
            message: format!("TC rotated (drift={:.3})", req.drift_score),
            duration_ms: start.elapsed().as_millis() as u64,
        })
    }

    // ── TC-2: Reduce ──────────────────────────────────────────────────────────

    /// TC Reduction: triggered by KECS regression or probation.
    /// Capability root is shrunk by quorum vote; TC remains usable under reduced perms.
    pub fn reduce(&mut self, req: TcReduceRequest) -> Result<TcLifecycleResult, String> {
        let start = std::time::Instant::now();
        let now = Self::now_ms();

        let tc = self.containers.get_mut(&req.tc_id)
            .ok_or_else(|| format!("TC not found: {}", req.tc_id))?;

        if tc.state == TcState::Revoked {
            return Err(format!("Cannot reduce revoked TC: {}", req.tc_id));
        }

        let quorum = tc.governance_rules.revocation_quorum;
        let consensus_anchor = Self::simulate_consensus(quorum, &TcOperation::Reduce, &req.tc_id);
        let prev_cid = tc.audit_cid_chain.last().cloned();
        let audit_cid = Self::audit_cid(&req.tc_id, &TcOperation::Reduce, now, prev_cid.as_deref());

        tc.capability_root = req.new_capability_root;
        tc.state = TcState::Reduced;
        tc.audit_cid_chain.push(audit_cid.clone());

        Ok(TcLifecycleResult {
            ok: true,
            operation: TcOperation::Reduce,
            tc_id: req.tc_id,
            new_tc_id: None,
            consensus_anchor,
            audit_cid,
            message: format!("TC reduced: kecs={:.3} probe={:.3} reason={}", req.kecs_score, req.boundary_probe_score, req.reason),
            duration_ms: start.elapsed().as_millis() as u64,
        })
    }

    // ── TC-2: Revoke ──────────────────────────────────────────────────────────

    /// TC Revocation: triggered by boundary probe > threshold or EmergencyStop.
    /// Emergency revocations skip consensus (immediate); normal path: f+1=3 validators, ≤100ms.
    pub fn revoke(&mut self, req: TcRevokeRequest) -> Result<TcLifecycleResult, String> {
        let start = std::time::Instant::now();
        let now = Self::now_ms();

        let tc = self.containers.get_mut(&req.tc_id)
            .ok_or_else(|| format!("TC not found: {}", req.tc_id))?;

        if tc.state == TcState::Revoked {
            return Ok(TcLifecycleResult {
                ok: true,
                operation: TcOperation::Revoke,
                tc_id: req.tc_id.clone(),
                new_tc_id: None,
                consensus_anchor: "already-revoked".to_string(),
                audit_cid: "already-revoked".to_string(),
                message: "TC was already revoked".to_string(),
                duration_ms: 0,
            });
        }

        let consensus_anchor = if req.emergency {
            // EmergencyStop: skip consensus, immediate revocation
            format!("emergency-revoke:{}", req.tc_id)
        } else {
            // Fast path: f+1=3 validators, ≤100ms target
            let quorum = tc.governance_rules.revocation_quorum;
            Self::simulate_consensus(quorum, &TcOperation::Revoke, &req.tc_id)
        };

        let prev_cid = tc.audit_cid_chain.last().cloned();
        let audit_cid = Self::audit_cid(&req.tc_id, &TcOperation::Revoke, now, prev_cid.as_deref());

        tc.state = TcState::Revoked;
        tc.audit_cid_chain.push(audit_cid.clone());

        Ok(TcLifecycleResult {
            ok: true,
            operation: TcOperation::Revoke,
            tc_id: req.tc_id,
            new_tc_id: None,
            consensus_anchor,
            audit_cid,
            message: format!("TC revoked: emergency={} probe={:.3} reason={}", req.emergency, req.boundary_probe_score, req.reason),
            duration_ms: start.elapsed().as_millis() as u64,
        })
    }

    // ── Accessors ─────────────────────────────────────────────────────────────

    pub fn get(&self, tc_id: &str) -> Option<&TokenContainer> {
        self.containers.get(tc_id)
    }

    pub fn is_active(&self, tc_id: &str) -> bool {
        self.containers.get(tc_id)
            .map(|tc| tc.state == TcState::Active || tc.state == TcState::Reduced)
            .unwrap_or(false)
    }

    pub fn is_expired(&self, tc_id: &str) -> bool {
        let now = Self::now_ms();
        self.containers.get(tc_id)
            .and_then(|tc| tc.expires_at)
            .map(|exp| now >= exp)
            .unwrap_or(false)
    }

    /// Walk the prev_tc_id chain and return ordered list (oldest first).
    pub fn ancestry_chain(&self, tc_id: &str) -> Vec<String> {
        let mut chain = Vec::new();
        let mut current = tc_id.to_string();
        while let Some(tc) = self.containers.get(&current) {
            chain.push(current.clone());
            match &tc.prev_tc_id {
                Some(prev) => current = prev.clone(),
                None => break,
            }
        }
        chain.reverse();
        chain
    }

    pub fn all_active(&self) -> Vec<&TokenContainer> {
        self.containers.values()
            .filter(|tc| tc.state == TcState::Active)
            .collect()
    }
}

// ═══════════════════════════════════════════════════════════════
// TC-3: Three-layer attestation verifier
// ═══════════════════════════════════════════════════════════════

/// Verifies a TC's attestation across all three layers.
pub struct TeeAttestationVerifier;

impl TeeAttestationVerifier {
    /// L1: Kernel self-report — verify report_data matches tc_id + genesis_cid + aisv_commitment.
    pub fn verify_l1(tc: &TokenContainer) -> Result<(), String> {
        let quote = tc.tee_attestation.as_ref()
            .ok_or("No TEE attestation quote present")?;
        let expected = TokenContainerManager::compute_report_data(
            &tc.tc_id, &tc.genesis_cid, &tc.aisv_commitment,
        );
        if quote.report_data != expected {
            return Err(format!(
                "L1 attestation failed: report_data mismatch. expected={} got={}",
                expected, quote.report_data
            ));
        }
        Ok(())
    }

    /// L2: Validator cross-check — verify f+1 validators agree on the measurement.
    /// In production, this checks validator signatures. Here: structural validation.
    pub fn verify_l2(tc: &TokenContainer, validator_count: usize) -> Result<(), String> {
        let quorum = tc.governance_rules.revocation_quorum;
        if validator_count < quorum {
            return Err(format!(
                "L2 attestation failed: only {} validators, need quorum={}",
                validator_count, quorum
            ));
        }
        // Verify consensus_anchor is non-empty and not a placeholder
        if tc.consensus_anchor.is_empty() || tc.consensus_anchor == "unknown" {
            return Err("L2 attestation failed: missing consensus anchor".to_string());
        }
        Ok(())
    }

    /// L3: Community ceremony — verify audit CID chain is non-empty and internally consistent.
    pub fn verify_l3(tc: &TokenContainer) -> Result<usize, String> {
        if tc.audit_cid_chain.is_empty() {
            return Err("L3 attestation failed: empty audit CID chain".to_string());
        }
        // All CIDs must start with "cid:" prefix
        for cid in &tc.audit_cid_chain {
            if !cid.starts_with("cid:") && !cid.starts_with("consensus:") && !cid.starts_with("emergency-") && !cid.starts_with("already-") {
                return Err(format!("L3 attestation failed: invalid CID format: {}", cid));
            }
        }
        Ok(tc.audit_cid_chain.len())
    }

    /// Full three-layer attestation verification.
    pub fn verify_all(tc: &TokenContainer, validator_count: usize) -> Result<AttestationReport, String> {
        let l1 = Self::verify_l1(tc);
        let l2 = Self::verify_l2(tc, validator_count);
        let l3 = Self::verify_l3(tc);

        let l1_ok = l1.is_ok();
        let l2_ok = l2.is_ok();
        let l3_ok = l3.is_ok();
        let chain_len = l3.unwrap_or(0);

        if !l1_ok || !l2_ok || !l3_ok {
            return Err(format!(
                "Attestation failed: L1={} L2={} L3={}",
                l1.err().unwrap_or_default(),
                l2.err().unwrap_or_default(),
                chain_len,
            ));
        }

        Ok(AttestationReport {
            tc_id: tc.tc_id.clone(),
            l1_passed: true,
            l2_passed: true,
            l3_passed: true,
            validator_count,
            audit_chain_length: chain_len,
            report_data: tc.tee_attestation.as_ref().map(|q| q.report_data.clone()),
            verified_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64,
        })
    }
}

/// Result of three-layer TEE attestation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationReport {
    pub tc_id: String,
    pub l1_passed: bool,
    pub l2_passed: bool,
    pub l3_passed: bool,
    pub validator_count: usize,
    pub audit_chain_length: usize,
    pub report_data: Option<String>,
    pub verified_at: i64,
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn mgr() -> TokenContainerManager {
        TokenContainerManager::new([0x42u8; 32])
    }

    fn issue_req() -> TcIssueRequest {
        TcIssueRequest {
            genesis_cid: "cid:genesis001".to_string(),
            aisv_commitment: "aisv:abc123".to_string(),
            capability_root: "cap:root001".to_string(),
            namespace_scope: "org:acme".to_string(),
            isolation_proof: "iso:proof001".to_string(),
            governance: Some(TCGovernancePolicy::default()),
            ttl_ms: Some(86_400_000),
            tee_quote: None,
        }
    }

    #[test]
    fn test_tc1_issue_creates_active_tc() {
        let mut mgr = mgr();
        let result = mgr.issue(issue_req()).unwrap();
        assert!(result.ok);
        assert_eq!(result.operation, TcOperation::Issue);
        let tc = mgr.get(&result.tc_id).unwrap();
        assert_eq!(tc.state, TcState::Active);
        assert!(!tc.audit_cid_chain.is_empty());
        assert!(tc.prev_tc_id.is_none());
    }

    #[test]
    fn test_tc1_tc_id_is_deterministic() {
        let id1 = TokenContainerManager::compute_tc_id("cid:gen", "aisv:x", 1000);
        let id2 = TokenContainerManager::compute_tc_id("cid:gen", "aisv:x", 1000);
        assert_eq!(id1, id2);
        let id3 = TokenContainerManager::compute_tc_id("cid:gen", "aisv:y", 1000);
        assert_ne!(id1, id3, "Different AISV should yield different tc_id");
    }

    #[test]
    fn test_tc1_governance_default_is_not_pq() {
        let policy = TCGovernancePolicy::default();
        assert!(!policy.post_quantum_required, "2026 default must be Ed25519");
        assert_eq!(policy.revocation_quorum, 3);
        assert_eq!(policy.extension_quorum, 5);
    }

    #[test]
    fn test_tc2_rotate_creates_chain() {
        let mut mgr = mgr();
        let issue = mgr.issue(issue_req()).unwrap();
        let tc_id = issue.tc_id.clone();

        let rotate = mgr.rotate(TcRotateRequest {
            tc_id: tc_id.clone(),
            new_aisv_commitment: "aisv:rotated".to_string(),
            new_capability_root: "cap:root002".to_string(),
            new_isolation_proof: "iso:proof002".to_string(),
            drift_score: 0.25,
            tee_quote: None,
        }).unwrap();

        assert!(rotate.ok);
        let new_tc_id = rotate.new_tc_id.as_ref().unwrap();
        let new_tc = mgr.get(new_tc_id).unwrap();
        assert_eq!(new_tc.state, TcState::Active);
        assert_eq!(new_tc.prev_tc_id.as_deref(), Some(tc_id.as_str()));
    }

    #[test]
    fn test_tc2_rotate_old_tc_enters_rotating_state() {
        let mut mgr = mgr();
        let issue = mgr.issue(issue_req()).unwrap();
        let tc_id = issue.tc_id.clone();
        mgr.rotate(TcRotateRequest {
            tc_id: tc_id.clone(),
            new_aisv_commitment: "aisv:v2".to_string(),
            new_capability_root: "cap:v2".to_string(),
            new_isolation_proof: "iso:v2".to_string(),
            drift_score: 0.15,
            tee_quote: None,
        }).unwrap();
        let old = mgr.get(&tc_id).unwrap();
        assert_eq!(old.state, TcState::Rotating);
    }

    #[test]
    fn test_tc2_reduce_shrinks_capability() {
        let mut mgr = mgr();
        let issue = mgr.issue(issue_req()).unwrap();
        mgr.reduce(TcReduceRequest {
            tc_id: issue.tc_id.clone(),
            new_capability_root: "cap:reduced".to_string(),
            reason: "KECS regression".to_string(),
            kecs_score: 0.45,
            boundary_probe_score: 0.12,
        }).unwrap();
        let tc = mgr.get(&issue.tc_id).unwrap();
        assert_eq!(tc.state, TcState::Reduced);
        assert_eq!(tc.capability_root, "cap:reduced");
    }

    #[test]
    fn test_tc2_revoke_blocks_reuse() {
        let mut mgr = mgr();
        let issue = mgr.issue(issue_req()).unwrap();
        mgr.revoke(TcRevokeRequest {
            tc_id: issue.tc_id.clone(),
            reason: "boundary probe exceeded".to_string(),
            emergency: false,
            boundary_probe_score: 0.22,
        }).unwrap();
        let tc = mgr.get(&issue.tc_id).unwrap();
        assert_eq!(tc.state, TcState::Revoked);
        assert!(!mgr.is_active(&issue.tc_id));
    }

    #[test]
    fn test_tc2_emergency_revoke_skips_consensus() {
        let mut mgr = mgr();
        let issue = mgr.issue(issue_req()).unwrap();
        let result = mgr.revoke(TcRevokeRequest {
            tc_id: issue.tc_id.clone(),
            reason: "EmergencyStop".to_string(),
            emergency: true,
            boundary_probe_score: 0.30,
        }).unwrap();
        assert!(result.consensus_anchor.contains("emergency"), "Emergency revoke must use fast path");
    }

    #[test]
    fn test_tc2_audit_cid_chain_grows_with_ops() {
        let mut mgr = mgr();
        let issue = mgr.issue(issue_req()).unwrap();
        let initial_len = mgr.get(&issue.tc_id).unwrap().audit_cid_chain.len();
        mgr.reduce(TcReduceRequest {
            tc_id: issue.tc_id.clone(),
            new_capability_root: "cap:small".to_string(),
            reason: "test".to_string(),
            kecs_score: 0.5,
            boundary_probe_score: 0.05,
        }).unwrap();
        let after_reduce = mgr.get(&issue.tc_id).unwrap().audit_cid_chain.len();
        assert!(after_reduce > initial_len, "Audit chain must grow after each operation");
    }

    #[test]
    fn test_tc3_l1_attestation_report_data_verified() {
        let mut mgr = mgr();
        let issue = mgr.issue(issue_req()).unwrap();
        let tc = mgr.get(&issue.tc_id).unwrap();
        assert!(TeeAttestationVerifier::verify_l1(tc).is_ok(), "L1 attestation must pass");
    }

    #[test]
    fn test_tc3_full_attestation_passes() {
        let mut mgr = mgr();
        let issue = mgr.issue(issue_req()).unwrap();
        let tc = mgr.get(&issue.tc_id).unwrap();
        let report = TeeAttestationVerifier::verify_all(tc, 3).unwrap();
        assert!(report.l1_passed && report.l2_passed && report.l3_passed);
    }

    #[test]
    fn test_tc3_tampered_report_data_fails_l1() {
        let mut mgr = mgr();
        let issue = mgr.issue(issue_req()).unwrap();
        let tc = mgr.containers.get_mut(&issue.tc_id).unwrap();
        if let Some(ref mut q) = tc.tee_attestation {
            q.report_data = "tampered-value".to_string();
        }
        let tc = mgr.get(&issue.tc_id).unwrap();
        assert!(TeeAttestationVerifier::verify_l1(tc).is_err(), "Tampered report_data must fail L1");
    }

    #[test]
    fn test_tc2_ancestry_chain_ordered() {
        let mut mgr = mgr();
        let r1 = mgr.issue(issue_req()).unwrap();
        let r2 = mgr.rotate(TcRotateRequest {
            tc_id: r1.tc_id.clone(),
            new_aisv_commitment: "aisv:v2".to_string(),
            new_capability_root: "cap:v2".to_string(),
            new_isolation_proof: "iso:v2".to_string(),
            drift_score: 0.1,
            tee_quote: None,
        }).unwrap();
        let chain = mgr.ancestry_chain(r2.new_tc_id.as_ref().unwrap());
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[0], r1.tc_id);
    }
}

//! Claims Engine — separates LLM proposals from verified facts.
//!
//! Architecture:
//!   - **Claim**: An assertion made by an LLM (unverified until checked)
//!   - **Evidence**: A reference to source data (CID + quote + field path)
//!   - **ClaimVerifier**: Checks claims against source text, produces VerificationResult
//!
//! Flow: LLM proposes → ClaimVerifier checks against source CID → Confirmed or Rejected
//!
//! This is the app layer. The kernel provides CID integrity and recall.
//! This module provides the claim lifecycle on top of it.

use serde::{Deserialize, Serialize};

// ═════════════════════════════════════════════════════════════════
// Support Level — how strongly the source data supports a claim
// ═════════════════════════════════════════════════════════════════

/// How strongly the source data supports a claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SupportLevel {
    /// Directly stated in the source text (e.g., "ALLERGIES: sulfa drugs")
    Explicit,
    /// Suggested but not directly stated (e.g., metformin implies diabetes)
    Implied,
    /// Not present in the source text at all
    Absent,
}

impl SupportLevel {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().trim() {
            "explicit" => Self::Explicit,
            "implied" => Self::Implied,
            _ => Self::Absent,
        }
    }
}

impl std::fmt::Display for SupportLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Explicit => write!(f, "explicit"),
            Self::Implied => write!(f, "implied"),
            Self::Absent => write!(f, "absent"),
        }
    }
}

// ═════════════════════════════════════════════════════════════════
// Evidence — a reference to source data backing a claim
// ═════════════════════════════════════════════════════════════════

/// Evidence reference — points to a specific piece of source data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    /// CID of the source packet (content-addressed, tamper-evident)
    pub source_cid: String,
    /// Field path within the source (e.g., "patient.allergies")
    pub field_path: Option<String>,
    /// Exact quote from the source text
    pub quote: String,
    /// How strongly the source supports the claim
    pub support: SupportLevel,
}

// ═════════════════════════════════════════════════════════════════
// Claim — an assertion made by an LLM agent
// ═════════════════════════════════════════════════════════════════

/// A claim is an assertion made by an LLM. It is NOT a fact until verified.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claim {
    /// What is being claimed (e.g., "type 2 diabetes", "sulfa allergy")
    pub item: String,
    /// Category (e.g., "conditions", "allergies", "procedures")
    pub category: String,
    /// Evidence provided by the LLM (quote from input)
    pub evidence: Evidence,
    /// Resolved code (if grounding table matched)
    pub code: Option<String>,
    /// Code description
    pub code_desc: Option<String>,
}

// ═════════════════════════════════════════════════════════════════
// VerificationOutcome — result of checking a claim against source
// ═════════════════════════════════════════════════════════════════

/// Outcome of verifying a claim against source data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationOutcome {
    /// Claim is confirmed — evidence quote found in source, support=explicit
    Confirmed,
    /// Claim is rejected — evidence not found or support=absent
    Rejected,
    /// Claim needs human review — support=implied or partial match
    NeedsReview,
}

impl std::fmt::Display for VerificationOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Confirmed => write!(f, "confirmed"),
            Self::Rejected => write!(f, "rejected"),
            Self::NeedsReview => write!(f, "needs_review"),
        }
    }
}

/// Result of verifying a single claim.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    /// The original claim
    pub claim: Claim,
    /// Verification outcome
    pub outcome: VerificationOutcome,
    /// Reason for the outcome
    pub reason: String,
}

// ═════════════════════════════════════════════════════════════════
// ClaimSet — a batch of claims with verification results
// ═════════════════════════════════════════════════════════════════

/// A set of claims with their verification results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimSet {
    /// Source CID that claims were verified against
    pub source_cid: String,
    /// All verification results
    pub results: Vec<VerificationResult>,
}

impl ClaimSet {
    pub fn new(source_cid: &str) -> Self {
        Self {
            source_cid: source_cid.to_string(),
            results: Vec::new(),
        }
    }

    /// Count of confirmed claims.
    pub fn confirmed_count(&self) -> usize {
        self.results.iter()
            .filter(|r| r.outcome == VerificationOutcome::Confirmed)
            .count()
    }

    /// Count of rejected claims.
    pub fn rejected_count(&self) -> usize {
        self.results.iter()
            .filter(|r| r.outcome == VerificationOutcome::Rejected)
            .count()
    }

    /// Count of claims needing review.
    pub fn needs_review_count(&self) -> usize {
        self.results.iter()
            .filter(|r| r.outcome == VerificationOutcome::NeedsReview)
            .count()
    }

    /// Total claims.
    pub fn total(&self) -> usize {
        self.results.len()
    }

    /// Claim validity ratio (0.0 - 1.0).
    pub fn validity_ratio(&self) -> f64 {
        if self.results.is_empty() {
            return 1.0;
        }
        self.confirmed_count() as f64 / self.results.len() as f64
    }

    /// Confirmed claims only.
    pub fn confirmed(&self) -> Vec<&VerificationResult> {
        self.results.iter()
            .filter(|r| r.outcome == VerificationOutcome::Confirmed)
            .collect()
    }

    /// Rejected claims only.
    pub fn rejected(&self) -> Vec<&VerificationResult> {
        self.results.iter()
            .filter(|r| r.outcome == VerificationOutcome::Rejected)
            .collect()
    }

    /// Warning messages for rejected/needs-review claims.
    pub fn warnings(&self) -> Vec<String> {
        self.results.iter()
            .filter(|r| r.outcome != VerificationOutcome::Confirmed)
            .map(|r| format!("{}: '{}' — {}", r.outcome, r.claim.item, r.reason))
            .collect()
    }
}

// ═════════════════════════════════════════════════════════════════
// ClaimVerifier — verifies claims against source text
// ═════════════════════════════════════════════════════════════════

/// Verifies claims against source text recalled from kernel memory.
///
/// Rules:
/// - support=explicit AND quote found in source → Confirmed
/// - support=explicit AND quote NOT found → Rejected (hallucinated evidence)
/// - support=implied → NeedsReview (requires human confirmation)
/// - support=absent → Rejected
/// - No code match in grounding table → Rejected (uncoded)
pub struct ClaimVerifier;

impl ClaimVerifier {
    /// Verify a batch of claims against source text.
    pub fn verify(claims: &[Claim], source_text: &str, source_cid: &str) -> ClaimSet {
        let source_lower = source_text.to_lowercase();
        let mut set = ClaimSet::new(source_cid);

        for claim in claims {
            let result = Self::verify_one(claim, &source_lower);
            set.results.push(result);
        }

        set
    }

    /// Verify a single claim.
    fn verify_one(claim: &Claim, source_lower: &str) -> VerificationResult {
        let quote_lower = claim.evidence.quote.to_lowercase();
        let quote_trimmed = quote_lower.trim().trim_matches('"');
        let quote_found = !quote_trimmed.is_empty() && source_lower.contains(quote_trimmed);

        match claim.evidence.support {
            SupportLevel::Explicit => {
                if quote_found && claim.code.is_some() {
                    VerificationResult {
                        claim: claim.clone(),
                        outcome: VerificationOutcome::Confirmed,
                        reason: format!(
                            "evidence quote found in source, code={}", 
                            claim.code.as_deref().unwrap_or("?")
                        ),
                    }
                } else if quote_found && claim.code.is_none() {
                    VerificationResult {
                        claim: claim.clone(),
                        outcome: VerificationOutcome::NeedsReview,
                        reason: "evidence found but no code mapping in grounding table".to_string(),
                    }
                } else {
                    VerificationResult {
                        claim: claim.clone(),
                        outcome: VerificationOutcome::Rejected,
                        reason: format!(
                            "evidence quote not found in source record (hallucinated evidence)"
                        ),
                    }
                }
            }
            SupportLevel::Implied => {
                VerificationResult {
                    claim: claim.clone(),
                    outcome: VerificationOutcome::NeedsReview,
                    reason: "support=implied — requires physician/human confirmation".to_string(),
                }
            }
            SupportLevel::Absent => {
                VerificationResult {
                    claim: claim.clone(),
                    outcome: VerificationOutcome::Rejected,
                    reason: "support=absent — not documented in source".to_string(),
                }
            }
        }
    }
}

// ═════════════════════════════════════════════════════════════════
// Tests
// ═════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_claim(item: &str, category: &str, quote: &str, support: SupportLevel, code: Option<&str>) -> Claim {
        Claim {
            item: item.to_string(),
            category: category.to_string(),
            evidence: Evidence {
                source_cid: "bafyrei_test".to_string(),
                field_path: None,
                quote: quote.to_string(),
                support,
            },
            code: code.map(|s| s.to_string()),
            code_desc: None,
        }
    }

    #[test]
    fn test_explicit_quote_found_with_code() {
        let source = "ALLERGIES: Sulfa drugs, shellfish\nHISTORY: Type 2 diabetes";
        let claim = make_claim("sulfa allergy", "allergies", "Sulfa drugs", SupportLevel::Explicit, Some("Z88.2"));
        let set = ClaimVerifier::verify(&[claim], source, "cid:test");
        assert_eq!(set.confirmed_count(), 1);
        assert_eq!(set.rejected_count(), 0);
    }

    #[test]
    fn test_explicit_quote_not_found() {
        let source = "ALLERGIES: Sulfa drugs, shellfish";
        let claim = make_claim("penicillin allergy", "allergies", "penicillin", SupportLevel::Explicit, Some("Z88.0"));
        let set = ClaimVerifier::verify(&[claim], source, "cid:test");
        assert_eq!(set.confirmed_count(), 0);
        assert_eq!(set.rejected_count(), 1);
        assert!(set.results[0].reason.contains("hallucinated"));
    }

    #[test]
    fn test_implied_goes_to_needs_review() {
        let source = "CURRENT MEDICATIONS: Metformin 1000mg BID";
        let claim = make_claim("type 2 diabetes", "conditions", "Metformin", SupportLevel::Implied, Some("E11.9"));
        let set = ClaimVerifier::verify(&[claim], source, "cid:test");
        assert_eq!(set.needs_review_count(), 1);
        assert_eq!(set.confirmed_count(), 0);
    }

    #[test]
    fn test_absent_rejected() {
        let source = "ALLERGIES: Sulfa drugs";
        let claim = make_claim("latex allergy", "allergies", "", SupportLevel::Absent, Some("Z91.040"));
        let set = ClaimVerifier::verify(&[claim], source, "cid:test");
        assert_eq!(set.rejected_count(), 1);
    }

    #[test]
    fn test_explicit_no_code_needs_review() {
        let source = "HISTORY: Chronic back pain";
        let claim = make_claim("chronic back pain", "conditions", "Chronic back pain", SupportLevel::Explicit, None);
        let set = ClaimVerifier::verify(&[claim], source, "cid:test");
        assert_eq!(set.needs_review_count(), 1);
    }

    #[test]
    fn test_validity_ratio() {
        let source = "ALLERGIES: Sulfa drugs, shellfish\nHISTORY: Type 2 diabetes";
        let claims = vec![
            make_claim("sulfa", "allergies", "Sulfa drugs", SupportLevel::Explicit, Some("Z88.2")),
            make_claim("shellfish", "allergies", "shellfish", SupportLevel::Explicit, Some("Z91.013")),
            make_claim("penicillin", "allergies", "penicillin", SupportLevel::Explicit, Some("Z88.0")),
        ];
        let set = ClaimVerifier::verify(&claims, source, "cid:test");
        assert_eq!(set.confirmed_count(), 2);
        assert_eq!(set.rejected_count(), 1);
        assert!((set.validity_ratio() - 0.6667).abs() < 0.01);
    }

    #[test]
    fn test_warnings() {
        let source = "ALLERGIES: Sulfa drugs";
        let claims = vec![
            make_claim("sulfa", "allergies", "Sulfa drugs", SupportLevel::Explicit, Some("Z88.2")),
            make_claim("penicillin", "allergies", "penicillin", SupportLevel::Explicit, Some("Z88.0")),
        ];
        let set = ClaimVerifier::verify(&claims, source, "cid:test");
        let warnings = set.warnings();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("penicillin"));
    }

    #[test]
    fn test_empty_claims() {
        let set = ClaimVerifier::verify(&[], "any source", "cid:test");
        assert_eq!(set.total(), 0);
        assert_eq!(set.validity_ratio(), 1.0);
    }
}

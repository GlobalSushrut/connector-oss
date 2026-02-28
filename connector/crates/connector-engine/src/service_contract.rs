//! Service Contract — the fundamental unit of the agent economy.
//!
//! An agent publishes a ServiceContract to declare what it offers,
//! at what price, with what guarantees, and how much stake it bonds.
//!
//! Research: Google A2A Agent Cards (2025), AWS Lambda pricing model,
//! SCITT (IETF) attestation, Akash Network service specs

use serde::{Deserialize, Serialize};

// ═══════════════════════════════════════════════════════════════
// Capability Spec
// ═══════════════════════════════════════════════════════════════

/// Machine-readable specification of a single capability an agent provides.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CapabilitySpec {
    pub domain: String,
    pub action: String,
    pub version: String,
    pub parameters: Vec<String>,
}

impl CapabilitySpec {
    /// Canonical key for inverted index lookup: `{domain}:{action}`
    pub fn capability_key(&self) -> String {
        format!("{}:{}", self.domain, self.action)
    }

    /// Check if this capability matches a query (domain + action).
    pub fn matches(&self, domain: &str, action: &str) -> bool {
        self.domain == domain && self.action == action
    }
}

// ═══════════════════════════════════════════════════════════════
// Parameter Spec
// ═══════════════════════════════════════════════════════════════

/// Schema for an input or output parameter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParamSpec {
    pub name: String,
    pub param_type: String,
    pub required: bool,
    pub description: String,
}

// ═══════════════════════════════════════════════════════════════
// Service Level Agreement
// ═══════════════════════════════════════════════════════════════

/// SLA commitments a provider makes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceLevelAgreement {
    pub max_latency_ms: u64,
    pub availability_pct: f64,
    pub max_error_rate_pct: f64,
    pub max_concurrent: u32,
}

impl ServiceLevelAgreement {
    /// Validate SLA bounds are reasonable.
    pub fn validate(&self) -> Result<(), String> {
        if self.max_latency_ms == 0 {
            return Err("SLA max_latency_ms must be > 0".into());
        }
        if self.availability_pct < 0.0 || self.availability_pct > 100.0 {
            return Err("SLA availability_pct must be 0.0–100.0".into());
        }
        if self.max_error_rate_pct < 0.0 || self.max_error_rate_pct > 100.0 {
            return Err("SLA max_error_rate_pct must be 0.0–100.0".into());
        }
        Ok(())
    }

    /// Check if this SLA meets the requirements of a query.
    pub fn meets_requirements(&self, max_latency: Option<u64>, min_availability: Option<f64>) -> bool {
        if let Some(lat) = max_latency {
            if self.max_latency_ms > lat { return false; }
        }
        if let Some(avail) = min_availability {
            if self.availability_pct < avail { return false; }
        }
        true
    }
}

// ═══════════════════════════════════════════════════════════════
// Pricing Model
// ═══════════════════════════════════════════════════════════════

/// How an agent charges for its services.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PricingModel {
    /// Fixed cost per invocation
    PerInvocation { cost_per_call: u64 },
    /// Token-based pricing (LLM-style)
    PerToken { cost_per_input_token: u64, cost_per_output_token: u64 },
    /// Time-based subscription
    Subscription { cost_per_hour: u64, max_calls_per_hour: u32 },
    /// Price determined by negotiation/auction
    Auction,
}

impl PricingModel {
    /// Estimate cost for a single invocation (used for discovery ranking).
    pub fn estimated_cost_per_call(&self) -> u64 {
        match self {
            PricingModel::PerInvocation { cost_per_call } => *cost_per_call,
            PricingModel::PerToken { cost_per_input_token, cost_per_output_token } => {
                // Estimate: avg 500 input + 200 output tokens
                cost_per_input_token * 500 + cost_per_output_token * 200
            }
            PricingModel::Subscription { cost_per_hour, max_calls_per_hour } => {
                if *max_calls_per_hour == 0 { return u64::MAX; }
                cost_per_hour / (*max_calls_per_hour as u64)
            }
            PricingModel::Auction => 0, // Price unknown until negotiation
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Service Contract
// ═══════════════════════════════════════════════════════════════

/// The fundamental unit of the agent economy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceContract {
    pub contract_id: String,
    pub provider_pid: String,
    pub provider_did: Option<String>,
    pub capabilities: Vec<CapabilitySpec>,
    pub input_schema: Vec<ParamSpec>,
    pub output_schema: Vec<ParamSpec>,
    pub sla: ServiceLevelAgreement,
    pub pricing: PricingModel,
    /// Stake bonded — slashed on SLA violation (skin in the game)
    pub stake_amount: u64,
    pub published_at: i64,
    pub expires_at: i64,
    /// SCITT receipt for verified capabilities
    pub attestation: Option<String>,
}

impl ServiceContract {
    /// Validate the contract is well-formed.
    pub fn validate(&self, now_ms: i64) -> Result<(), String> {
        if self.contract_id.is_empty() {
            return Err("contract_id must not be empty".into());
        }
        if self.provider_pid.is_empty() {
            return Err("provider_pid must not be empty".into());
        }
        if self.capabilities.is_empty() {
            return Err("Must declare at least one capability".into());
        }
        if self.expires_at <= now_ms {
            return Err("Contract already expired".into());
        }
        self.sla.validate()?;
        Ok(())
    }

    /// Check if this contract provides a specific capability.
    pub fn provides(&self, domain: &str, action: &str) -> bool {
        self.capabilities.iter().any(|c| c.matches(domain, action))
    }

    /// Get all capability keys for inverted index.
    pub fn capability_keys(&self) -> Vec<String> {
        self.capabilities.iter().map(|c| c.capability_key()).collect()
    }

    /// Check if contract is expired.
    pub fn is_expired(&self, now_ms: i64) -> bool {
        now_ms >= self.expires_at
    }
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_contract(now: i64) -> ServiceContract {
        ServiceContract {
            contract_id: "sc_1".into(),
            provider_pid: "translator_agent".into(),
            provider_did: Some("did:key:z6Mk...".into()),
            capabilities: vec![
                CapabilitySpec {
                    domain: "translation".into(), action: "translate".into(),
                    version: "1.0".into(), parameters: vec!["source_lang".into(), "target_lang".into()],
                },
            ],
            input_schema: vec![ParamSpec {
                name: "text".into(), param_type: "string".into(),
                required: true, description: "Text to translate".into(),
            }],
            output_schema: vec![ParamSpec {
                name: "translated".into(), param_type: "string".into(),
                required: true, description: "Translated text".into(),
            }],
            sla: ServiceLevelAgreement {
                max_latency_ms: 500, availability_pct: 99.5,
                max_error_rate_pct: 0.5, max_concurrent: 10,
            },
            pricing: PricingModel::PerInvocation { cost_per_call: 100 },
            stake_amount: 1000,
            published_at: now,
            expires_at: now + 86_400_000, // 24h
            attestation: None,
        }
    }

    #[test]
    fn test_create_and_validate() {
        let c = make_contract(1000);
        assert!(c.validate(1000).is_ok());
    }

    #[test]
    fn test_validate_rejects_expired() {
        let c = make_contract(1000);
        assert!(c.validate(c.expires_at + 1).is_err());
    }

    #[test]
    fn test_validate_rejects_empty_capabilities() {
        let mut c = make_contract(1000);
        c.capabilities.clear();
        assert!(c.validate(1000).is_err());
    }

    #[test]
    fn test_sla_validation() {
        let mut sla = ServiceLevelAgreement {
            max_latency_ms: 0, availability_pct: 99.9,
            max_error_rate_pct: 0.1, max_concurrent: 5,
        };
        assert!(sla.validate().is_err()); // latency 0
        sla.max_latency_ms = 100;
        sla.availability_pct = 101.0;
        assert!(sla.validate().is_err()); // availability > 100
        sla.availability_pct = 99.9;
        assert!(sla.validate().is_ok());
    }

    #[test]
    fn test_capability_matching() {
        let c = make_contract(1000);
        assert!(c.provides("translation", "translate"));
        assert!(!c.provides("translation", "summarize"));
        assert!(!c.provides("analysis", "translate"));
    }

    #[test]
    fn test_pricing_models() {
        assert_eq!(
            PricingModel::PerInvocation { cost_per_call: 100 }.estimated_cost_per_call(),
            100
        );
        assert_eq!(
            PricingModel::Subscription { cost_per_hour: 3600, max_calls_per_hour: 100 }.estimated_cost_per_call(),
            36
        );
        assert_eq!(PricingModel::Auction.estimated_cost_per_call(), 0);

        let token_price = PricingModel::PerToken {
            cost_per_input_token: 1, cost_per_output_token: 2,
        };
        assert_eq!(token_price.estimated_cost_per_call(), 500 + 400); // 500*1 + 200*2
    }

    #[test]
    fn test_sla_meets_requirements() {
        let sla = ServiceLevelAgreement {
            max_latency_ms: 500, availability_pct: 99.9,
            max_error_rate_pct: 0.1, max_concurrent: 10,
        };
        assert!(sla.meets_requirements(Some(500), Some(99.0)));
        assert!(sla.meets_requirements(Some(1000), None));
        assert!(!sla.meets_requirements(Some(200), None)); // latency too high
        assert!(!sla.meets_requirements(None, Some(99.99))); // availability too low
    }

    #[test]
    fn test_capability_key_format() {
        let cap = CapabilitySpec {
            domain: "translation".into(), action: "translate".into(),
            version: "1.0".into(), parameters: vec![],
        };
        assert_eq!(cap.capability_key(), "translation:translate");
    }
}

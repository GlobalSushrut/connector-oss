//! ARC IFC — three independent algebras (Phase D / ARC-7).
//! Gate runs **three** checks — never a single “most restrictive” scalar across all three.

pub mod confidentiality;
pub mod dual_llm;
pub mod integrity;
pub mod provenance;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::error::{ConnectorError, DenialReason};

use super::flags::ArcFlags;
use super::runtime;
use super::transaction::TxState;

use confidentiality::{may_flow_labels as conf_flow, ConfVerdict};
use integrity::{may_flow_labels as integ_flow, IntegVerdict};
use provenance::{may_flow_labels as prov_flow, ProvVerdict};

pub const SCHEMA: &str = "connector.arc.ifc.v1";

/// Independent IFC labels carried on leases / payloads.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct IfcTriple {
    pub confidentiality: String,
    pub integrity: String,
    pub provenance: String,
}

impl IfcTriple {
    pub fn lab_default() -> Self {
        Self {
            confidentiality: "public".into(),
            integrity: "untrusted".into(),
            provenance: "pate_atu".into(),
        }
    }

    pub fn pii_untrusted(prov: impl Into<String>) -> Self {
        Self {
            confidentiality: "pii".into(),
            integrity: "untrusted".into(),
            provenance: prov.into(),
        }
    }

    pub fn external_sink() -> Self {
        Self {
            confidentiality: "public".into(),
            integrity: "untrusted".into(),
            provenance: "any".into(),
        }
    }

    pub fn system_sink() -> Self {
        Self {
            confidentiality: "secret".into(),
            integrity: "system".into(),
            provenance: "pate_atu".into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IfcCheckResult {
    pub confidentiality: ConfVerdict,
    pub integrity: IntegVerdict,
    pub provenance: ProvVerdict,
}

impl IfcCheckResult {
    pub fn ok(&self) -> bool {
        matches!(self.confidentiality, ConfVerdict::Allow)
            && matches!(self.integrity, IntegVerdict::Allow)
            && matches!(self.provenance, ProvVerdict::Allow)
    }

    pub fn to_json(&self) -> Value {
        json!({
            "schema": SCHEMA,
            "ok": self.ok(),
            "confidentiality": format!("{:?}", self.confidentiality),
            "integrity": format!("{:?}", self.integrity),
            "provenance": format!("{:?}", self.provenance),
            "honesty": "Three independent checks — not a collapsed scalar across conf/integ/prov",
        })
    }
}

/// Compose three algebras. Conf may deny while integ allows (and vice versa).
pub fn check_flow(data: &IfcTriple, sink: &IfcTriple) -> IfcCheckResult {
    IfcCheckResult {
        confidentiality: conf_flow(&data.confidentiality, &sink.confidentiality),
        integrity: integ_flow(&data.integrity, &sink.integrity),
        provenance: prov_flow(&data.provenance, &sink.provenance),
    }
}

/// When `CONNECTOR_ARC_IFC=1`, deny lease mint / effect if IFC fails.
pub fn assert_flow_or_deny(data: &IfcTriple, sink: &IfcTriple) -> Result<IfcCheckResult, ConnectorError> {
    let flags = ArcFlags::from_env();
    let result = check_flow(data, sink);
    if !flags.ifc {
        return Ok(result);
    }
    if result.ok() {
        return Ok(result);
    }
    Err(ConnectorError::new(
        DenialReason::PolicyDenied,
        format!(
            "arc_ifc: flow denied conf={:?} integ={:?} prov={:?}",
            result.confidentiality, result.integrity, result.provenance
        ),
    )
    .with_denied_resource("arc.ifc")
    .with_hint("PII→external and integrity write-up are denied independently (ARC-7)"))
}

/// D3: detokenize only post-Admit when IFC on (A9/A10).
/// Soft/off: allow. On: require a live post-admit AgencyTransaction for the agent.
pub fn assert_detokenize_post_admit(agent_id: &str) -> Result<(), ConnectorError> {
    let flags = ArcFlags::from_env();
    if !flags.ifc {
        return Ok(());
    }
    let live = runtime::transactions().list_for_agent(agent_id).into_iter().any(|tx| {
        matches!(
            tx.state,
            TxState::Validated
                | TxState::Reserved
                | TxState::Leased
                | TxState::Redeeming
                | TxState::EffectStarted
                | TxState::WaitingHitl
        )
    });
    if live {
        return Ok(());
    }
    Err(ConnectorError::new(
        DenialReason::PolicyDenied,
        "arc_ifc: detokenize refused — no post-Admit AgencyTransaction (detok only after Admit)",
    )
    .with_denied_resource("arc.ifc.detok")
    .with_hint("CONNECTOR_ARC_IFC=1 requires governor Admit before world detokenize"))
}

pub fn posture_json() -> Value {
    let flags = ArcFlags::from_env();
    json!({
        "schema": SCHEMA,
        "flag": "CONNECTOR_ARC_IFC",
        "enforced": flags.ifc,
        "algebras": ["confidentiality", "integrity", "provenance"],
        "compose": "three independent checks — never a single most-restrictive scalar",
        "dual_llm": dual_llm::SCHEMA,
        "detok_post_admit": flags.ifc,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use confidentiality::ConfLevel;
    use integrity::IntegLevel;

    #[test]
    fn conf_deny_integ_allow_independent() {
        // PII → public: conf denies; integ untrusted→untrusted allows.
        let data = IfcTriple {
            confidentiality: ConfLevel::Pii.as_str().into(),
            integrity: IntegLevel::Untrusted.as_str().into(),
            provenance: "pate_atu".into(),
        };
        let sink = IfcTriple::external_sink();
        let r = check_flow(&data, &sink);
        assert!(matches!(r.confidentiality, ConfVerdict::DenyWriteDown { .. }));
        assert!(matches!(r.integrity, IntegVerdict::Allow));
        assert!(!r.ok());
    }

    #[test]
    fn integ_deny_conf_allow_independent() {
        // public→secret conf allows; untrusted→system integ denies.
        let data = IfcTriple {
            confidentiality: ConfLevel::Public.as_str().into(),
            integrity: IntegLevel::Untrusted.as_str().into(),
            provenance: "pate_atu".into(),
        };
        let sink = IfcTriple {
            confidentiality: "secret".into(),
            integrity: "system".into(),
            provenance: "pate_atu".into(),
        };
        let r = check_flow(&data, &sink);
        assert!(matches!(r.confidentiality, ConfVerdict::Allow));
        assert!(matches!(r.integrity, IntegVerdict::DenyWriteUp { .. }));
        assert!(!r.ok());
    }

    #[test]
    fn allowed_internal_flow_ok() {
        let data = IfcTriple {
            confidentiality: "internal".into(),
            integrity: "verified".into(),
            provenance: "pate_atu".into(),
        };
        let sink = IfcTriple {
            confidentiality: "secret".into(),
            integrity: "user".into(),
            provenance: "pate".into(),
        };
        assert!(check_flow(&data, &sink).ok());
    }
}

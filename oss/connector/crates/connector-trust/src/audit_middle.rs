//! Distributed Intelligence audit middle format.
//!
//! SOC2-shaped control language for the AI world: admission, principal,
//! causal lineage, tool agency, and custody — portable across WitnessCtl,
//! TraceTramp, and the Connector node.

use serde::{Deserialize, Serialize};

use crate::custody::{CustodyReceiptV2, CustodyVerificationStatus};
use crate::CausalEnvelopeV2;

/// Schema id for the middle-format stream / export.
pub const DI_AUDIT_MIDDLE_SCHEMA: &str = "connector.di_audit_middle.v1";

/// One middle-format event — the unit auditors and SIEMs should consume.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DiAuditMiddleEvent {
    pub event_id: String,
    pub seq: u64,
    pub occurred_at_ms: i64,
    /// Principal / agent identity key.
    pub identity_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_pid: Option<String>,
    /// Action under audit (e.g. memory.write, api.call, tool.invoke).
    pub action: String,
    pub resource: String,
    /// allow | deny | hold | break_glass
    pub decision: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admission_ticket_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_mac: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integrity_mac: Option<String>,
    #[serde(default)]
    pub side_effects: Vec<String>,
    /// TraceTramp / Witness correlation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// Optional memory vector box super_key when the event touches memory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_super_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_cid: Option<String>,
    /// Adjacent moment commit id when the audited action produced/touched a moment (P6.4 / I-15).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub moment_id: Option<String>,
    /// SOC2-shaped + AI-extended control hits for this event.
    #[serde(default)]
    pub controls: Vec<DiControlHit>,
    #[serde(default = "schema_id")]
    pub schema: String,
    #[serde(default = "trust_v2")]
    pub contract_version: u32,
}

fn schema_id() -> String {
    DI_AUDIT_MIDDLE_SCHEMA.into()
}

fn trust_v2() -> u32 {
    2
}

/// Control result in SOC2-compatible language with DI extensions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DiControlHit {
    /// e.g. soc2.cc6.1.access_controls or di.admission.ticket_present
    pub control_id: String,
    pub passed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// soc2 | di | hipaa | eu_ai_act | …
    #[serde(default = "framework_soc2")]
    pub framework: String,
}

fn framework_soc2() -> String {
    "soc2".into()
}

/// Portable export: event stream + optional custody header + control summary.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DiAuditMiddleExport {
    pub schema: String,
    pub generated_at_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custody: Option<CustodyReceiptV2>,
    pub events: Vec<DiAuditMiddleEvent>,
    #[serde(default)]
    pub control_summary: Vec<DiControlHit>,
    /// Honesty: integrity never claimed without recompute.
    pub integrity_status: CustodyVerificationStatus,
}

impl DiAuditMiddleEvent {
    /// Lift a causal envelope into the middle format (shared fields).
    pub fn from_causal_envelope(env: &CausalEnvelopeV2, seq: u64) -> Self {
        Self {
            event_id: env.envelope_id.clone(),
            seq,
            occurred_at_ms: env.occurred_at_ms,
            identity_key: env.principal_id.clone(),
            tenant_id: env.tenant_id.clone(),
            session_id: env.session_id.clone(),
            agent_pid: None,
            action: env.action.clone(),
            resource: env.resource.clone(),
            decision: env.decision.clone(),
            admission_ticket_id: env.admission_ticket_id.clone(),
            input_digest: env.input_digest.clone(),
            output_digest: env.output_digest.clone(),
            previous_mac: env.previous_mac.clone(),
            integrity_mac: env.integrity_mac.clone(),
            side_effects: env.side_effects.clone(),
            trace_id: None,
            request_id: None,
            memory_super_key: None,
            memory_cid: None,
            moment_id: None,
            controls: default_di_controls(env),
            schema: DI_AUDIT_MIDDLE_SCHEMA.into(),
            contract_version: 2,
        }
    }

    /// Attach a moment adjacency ref (fluent).
    pub fn with_moment_id(mut self, moment_id: impl Into<String>) -> Self {
        self.moment_id = Some(moment_id.into());
        self
    }
}

fn default_di_controls(env: &CausalEnvelopeV2) -> Vec<DiControlHit> {
    vec![
        DiControlHit {
            control_id: "soc2.cc6.1.access_controls".into(),
            passed: !env.principal_id.is_empty(),
            message: Some("principal present on envelope".into()),
            framework: "soc2".into(),
        },
        DiControlHit {
            control_id: "soc2.cc6.2.authentication".into(),
            passed: !env.principal_id.is_empty(),
            message: None,
            framework: "soc2".into(),
        },
        DiControlHit {
            control_id: "di.admission.decision_recorded".into(),
            passed: matches!(
                env.decision.as_str(),
                "allow" | "deny" | "hold" | "break_glass"
            ),
            message: Some(format!("decision={}", env.decision)),
            framework: "di".into(),
        },
        DiControlHit {
            control_id: "di.admission.ticket_present".into(),
            passed: env.admission_ticket_id.is_some(),
            message: None,
            framework: "di".into(),
        },
        DiControlHit {
            control_id: "soc2.cc7.2.data_integrity".into(),
            passed: env.integrity_mac.is_some(),
            message: Some("integrity_mac present; independent recompute required for Verified".into()),
            framework: "soc2".into(),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CausalEnvelopeV2;

    #[test]
    fn envelope_lifts_with_di_controls() {
        let env = CausalEnvelopeV2 {
            envelope_id: "e1".into(),
            principal_id: "agent-1".into(),
            tenant_id: Some("acme".into()),
            workload_id: None,
            session_id: Some("s1".into()),
            delegation_chain: vec![],
            action: "memory.write".into(),
            resource: "/m/agent-1".into(),
            policy_revision: Some(1),
            decision: "allow".into(),
            admission_ticket_id: Some("adm_1".into()),
            input_digest: None,
            output_digest: None,
            side_effects: vec![],
            previous_mac: None,
            integrity_mac: Some("abc".into()),
            occurred_at_ms: 1,
            contract_version: 2,
        };
        let ev = DiAuditMiddleEvent::from_causal_envelope(&env, 1);
        assert_eq!(ev.schema, DI_AUDIT_MIDDLE_SCHEMA);
        assert!(ev.controls.iter().any(|c| c.control_id.starts_with("di.")));
        assert!(ev.moment_id.is_none());
        let with_m = ev.with_moment_id("mom_abc");
        assert_eq!(with_m.moment_id.as_deref(), Some("mom_abc"));
        let json = serde_json::to_value(&with_m).unwrap();
        assert_eq!(json["moment_id"], "mom_abc");
    }

    #[test]
    fn moment_id_optional_on_deserialize() {
        let raw = r#"{
            "event_id":"e1","seq":1,"occurred_at_ms":1,"identity_key":"a",
            "action":"x","resource":"/r","decision":"allow"
        }"#;
        let ev: DiAuditMiddleEvent = serde_json::from_str(raw).unwrap();
        assert!(ev.moment_id.is_none());
    }
}

//! SpendCease — hard cost/stop plane: ceilings, reserve-then-consume, Cease receipts.
//!
//! Schema family: `connector.spend_cease.v1`
//!
//! The LLM may still "want" to continue after Stop. Admit law + generation fence
//! make that desire powerless. See platform SPEND_CEASE.md.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const SPEND_CEILING_SCHEMA: &str = "connector.spend_ceiling.v1";
pub const HOP_RESERVATION_SCHEMA: &str = "connector.hop_reservation.v1";
pub const CEASE_RECEIPT_SCHEMA: &str = "connector.cease_receipt.v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SpendEnforcement {
    HardGate,
    SoftGate,
    Advisory,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CeaseReason {
    UserStop,
    BudgetExhausted,
    IterationCap,
    HitlCancel,
    Error,
    Timeout,
    Quarantine,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReservationState {
    Reserved,
    Committed,
    Released,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SpendCeilingV1 {
    pub schema: String,
    pub generation_id: String,
    pub quantum_id: String,
    pub agent_pid: String,
    pub max_usd: f64,
    pub max_tokens: u64,
    pub max_iterations: u64,
    pub reserved_usd: f64,
    pub consumed_usd: f64,
    pub reserved_tokens: u64,
    pub consumed_tokens: u64,
    pub iterations_completed: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub estimate_usd: Option<f64>,
    pub enforcement: SpendEnforcement,
    pub fail_closed: bool,
    pub policy_source: String,
    pub honesty: String,
}

impl SpendCeilingV1 {
    pub fn fresh(
        generation_id: impl Into<String>,
        quantum_id: impl Into<String>,
        agent_pid: impl Into<String>,
        max_usd: f64,
        max_tokens: u64,
        max_iterations: u64,
        policy_source: impl Into<String>,
    ) -> Self {
        Self {
            schema: SPEND_CEILING_SCHEMA.into(),
            generation_id: generation_id.into(),
            quantum_id: quantum_id.into(),
            agent_pid: agent_pid.into(),
            max_usd: max_usd.max(0.0),
            max_tokens: max_tokens.max(1),
            max_iterations: max_iterations.max(1),
            reserved_usd: 0.0,
            consumed_usd: 0.0,
            reserved_tokens: 0,
            consumed_tokens: 0,
            iterations_completed: 0,
            estimate_usd: None,
            enforcement: SpendEnforcement::HardGate,
            fail_closed: true,
            policy_source: policy_source.into(),
            honesty: "ceiling_at_admit_not_provider_marketing".into(),
        }
    }

    pub fn remaining_usd(&self) -> f64 {
        (self.max_usd - self.consumed_usd - self.reserved_usd).max(0.0)
    }

    pub fn remaining_tokens(&self) -> u64 {
        self.max_tokens
            .saturating_sub(self.consumed_tokens)
            .saturating_sub(self.reserved_tokens)
    }

    pub fn iterations_remaining(&self) -> u64 {
        self.max_iterations.saturating_sub(self.iterations_completed)
    }

    pub fn can_reserve(&self, usd: f64, tokens: u64) -> Result<(), &'static str> {
        if self.enforcement == SpendEnforcement::Advisory {
            return Ok(());
        }
        if self.iterations_remaining() == 0 {
            return Err("spend_iteration_cap");
        }
        if usd > self.remaining_usd() + f64::EPSILON {
            return Err("spend_usd_exhausted");
        }
        if tokens > self.remaining_tokens() {
            return Err("spend_tokens_exhausted");
        }
        Ok(())
    }

    pub fn reserve(&mut self, usd: f64, tokens: u64) -> Result<(), &'static str> {
        self.can_reserve(usd, tokens)?;
        if self.enforcement == SpendEnforcement::Advisory {
            return Ok(());
        }
        self.reserved_usd += usd.max(0.0);
        self.reserved_tokens = self.reserved_tokens.saturating_add(tokens);
        Ok(())
    }

    pub fn commit(&mut self, reserved_usd: f64, reserved_tokens: u64, actual_usd: f64, actual_tokens: u64) {
        self.reserved_usd = (self.reserved_usd - reserved_usd).max(0.0);
        self.reserved_tokens = self.reserved_tokens.saturating_sub(reserved_tokens);
        self.consumed_usd += actual_usd.max(0.0);
        self.consumed_tokens = self.consumed_tokens.saturating_add(actual_tokens);
        self.iterations_completed = self.iterations_completed.saturating_add(1);
    }

    pub fn release_reservation(&mut self, usd: f64, tokens: u64) {
        self.reserved_usd = (self.reserved_usd - usd).max(0.0);
        self.reserved_tokens = self.reserved_tokens.saturating_sub(tokens);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HopReservationV1 {
    pub schema: String,
    pub hop_id: String,
    pub generation_id: String,
    pub idempotency_key: String,
    pub projected_usd: f64,
    pub projected_tokens: u64,
    pub state: ReservationState,
    pub ttl_ms: i64,
    pub issued_at_ms: i64,
}

impl HopReservationV1 {
    pub fn new(
        generation_id: impl Into<String>,
        idempotency_key: impl Into<String>,
        projected_usd: f64,
        projected_tokens: u64,
        ttl_ms: i64,
    ) -> Self {
        let now = chrono::Utc::now().timestamp_millis();
        let key: String = idempotency_key.into();
        Self {
            schema: HOP_RESERVATION_SCHEMA.into(),
            hop_id: format!("hop_{}", uuid::Uuid::new_v4()),
            generation_id: generation_id.into(),
            idempotency_key: key,
            projected_usd,
            projected_tokens,
            state: ReservationState::Reserved,
            ttl_ms,
            issued_at_ms: now,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CeaseReceiptV1 {
    pub schema: String,
    pub receipt_id: String,
    pub agent_pid: String,
    pub generation_id_ceased: String,
    pub generation_id_next: String,
    pub reason: CeaseReason,
    pub final_consumed_usd: f64,
    pub final_consumed_tokens: u64,
    pub final_iterations: u64,
    pub hops_cancelled: u64,
    pub hops_completed: u64,
    pub workers_reaped: u64,
    pub context_tokens_voided: u64,
    pub provider_streams_aborted: u64,
    pub provider_cancel_api_used: bool,
    pub tokens_delivered: u64,
    pub tokens_billed_est: u64,
    pub cancel_tax_usd_est: f64,
    pub issued_at_ms: i64,
    pub node_seq: u64,
    pub honesty: String,
}

impl CeaseReceiptV1 {
    pub fn mint(
        agent_pid: impl Into<String>,
        generation_id_ceased: impl Into<String>,
        generation_id_next: impl Into<String>,
        reason: CeaseReason,
        ceiling: &SpendCeilingV1,
        node_seq: u64,
    ) -> Self {
        Self {
            schema: CEASE_RECEIPT_SCHEMA.into(),
            receipt_id: format!("cease_{}", uuid::Uuid::new_v4()),
            agent_pid: agent_pid.into(),
            generation_id_ceased: generation_id_ceased.into(),
            generation_id_next: generation_id_next.into(),
            reason,
            final_consumed_usd: ceiling.consumed_usd,
            final_consumed_tokens: ceiling.consumed_tokens,
            final_iterations: ceiling.iterations_completed,
            hops_cancelled: 0,
            hops_completed: ceiling.iterations_completed,
            workers_reaped: 0,
            context_tokens_voided: 0,
            provider_streams_aborted: 0,
            provider_cancel_api_used: false,
            tokens_delivered: 0,
            tokens_billed_est: 0,
            cancel_tax_usd_est: 0.0,
            issued_at_ms: chrono::Utc::now().timestamp_millis(),
            node_seq,
            honesty: "cease_stops_next_hop_cancel_tax_may_remain".into(),
        }
    }

    pub fn content_digest(&self) -> String {
        let bytes = serde_json::to_vec(self).unwrap_or_default();
        format!("{:x}", Sha256::digest(&bytes))
    }
}

/// Deterministic egress operation id for idempotent mint (retries collapse).
pub fn egress_operation_id(
    generation_id: &str,
    artifact_instance_id: &str,
    attempt_key: &str,
) -> String {
    let material = format!("egress_op|{generation_id}|{artifact_instance_id}|{attempt_key}");
    let h = format!("{:x}", Sha256::digest(material.as_bytes()));
    format!("eop_{}", &h[..32.min(h.len())])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserve_commit_release() {
        let mut c = SpendCeilingV1::fresh("g1", "q1", "agent_a", 1.0, 10_000, 5, "tenant");
        c.reserve(0.4, 1000).unwrap();
        assert!((c.remaining_usd() - 0.6).abs() < 1e-9);
        c.commit(0.4, 1000, 0.25, 800);
        assert!((c.consumed_usd - 0.25).abs() < 1e-9);
        assert_eq!(c.reserved_tokens, 0);
        assert_eq!(c.iterations_completed, 1);
        assert!(c.reserve(0.9, 100).is_err());
    }

    #[test]
    fn second_reservation_cannot_exceed_the_shared_ceiling() {
        let mut ceiling = SpendCeilingV1::fresh("g1", "q1", "shared", 1.0, 100, 5, "tenant");
        ceiling.reserve(0.6, 40).unwrap();
        assert_eq!(ceiling.reserve(0.5, 10).unwrap_err(), "spend_usd_exhausted");
    }

    #[test]
    fn iteration_cap() {
        let mut c = SpendCeilingV1::fresh("g1", "q1", "a", 100.0, 1_000_000, 2, "t");
        c.reserve(0.01, 10).unwrap();
        c.commit(0.01, 10, 0.01, 10);
        c.reserve(0.01, 10).unwrap();
        c.commit(0.01, 10, 0.01, 10);
        assert_eq!(c.can_reserve(0.01, 10), Err("spend_iteration_cap"));
    }

    #[test]
    fn egress_op_idempotent() {
        let a = egress_operation_id("g", "ainst", "retry");
        let b = egress_operation_id("g", "ainst", "retry");
        assert_eq!(a, b);
        assert_ne!(a, egress_operation_id("g", "ainst", "other"));
    }
}

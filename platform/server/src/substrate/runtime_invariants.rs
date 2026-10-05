//! Mechanical production invariants (INV-01 … INV-20) — CI-facing contracts.
//!
//! These tests encode laws the Talk/Effect runtime must keep. They do not prove
//! every call site; they freeze the contract surface so regressions fail loudly.

use serde_json::json;

pub const INVARIANT_SCHEMA: &str = "connector.runtime_invariants.v1";

pub fn catalog() -> serde_json::Value {
    json!({
        "schema": INVARIANT_SCHEMA,
        "invariants": [
            {"id": "INV-01", "law": "No global kernel/store lock held across await"},
            {"id": "INV-02", "law": "No hot Talk O(agents|packets) work"},
            {"id": "INV-03", "law": "Raw provider output has no effect authority"},
            {"id": "INV-04", "law": "No streamed bytes before stream governance"},
            {"id": "INV-05", "law": "Every effect auth binds final action digest"},
            {"id": "INV-06", "law": "Auth tokens/quanta/leases are single-use"},
            {"id": "INV-07", "law": "Snapshot/generation mismatch → DeferRedo"},
            {"id": "INV-08", "law": "Quarantine/revoke/FIX priority over ordinary work"},
            {"id": "INV-09", "law": "Every queue bounded with capacity"},
            {"id": "INV-10", "law": "Every remote call consumes one deadline"},
            {"id": "INV-11", "law": "Retries bounded, classified, jittered"},
            {"id": "INV-12", "law": "Every effect has stable idempotency identity"},
            {"id": "INV-13", "law": "Provider failure cannot fail liveness"},
            {"id": "INV-14", "law": "Tenant overload cannot steal reserved capacity"},
            {"id": "INV-15", "law": "Authority-critical events durable before ACK"},
            {"id": "INV-16", "law": "Runtime snapshot publication is atomic"},
            {"id": "INV-17", "law": "Same-session turns serialized"},
            {"id": "INV-18", "law": "Different sessions execute concurrently"},
            {"id": "INV-19", "law": "Streaming and non-streaming share invariants"},
            {"id": "INV-20", "law": "Unsupported worlds cannot be created by LLM text"},
        ],
        "modules": {
            "turn_envelope": "substrate::turn_envelope",
            "snapshot": "substrate::agent_runtime_snapshot",
            "session_owner": "concurrency::session_owner",
            "bulkheads": "concurrency::workload_bulkhead",
            "stream_gate": "substrate::governed_stream_gate",
            "effect_intent": "substrate::effect_intent",
            "authority_evidence": "substrate::authority_evidence",
        },
    })
}

/// GET /api/v1/substrate/runtime-invariants
pub async fn get_catalog() -> axum::Json<serde_json::Value> {
    axum::Json(crate::operator::honesty::operator_envelope(catalog()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::concurrency::session_owner::SessionOwnerRegistry;
    use crate::concurrency::workload_bulkhead::WorkloadBulkheads;
    use crate::substrate::agent_runtime_snapshot::{
        AgentRuntimeSnapshot, RuntimeSnapshotRegistry, AGENT_RUNTIME_SNAPSHOT_SCHEMA,
    };
    use crate::substrate::effect_intent::{auth_digest_for, EffectIntent};
    use crate::substrate::governed_stream_gate::chunk_projected_text;
    use crate::substrate::turn_envelope::{TurnDeadline, TurnEnvelope};

    #[test]
    fn inv_catalog_has_twenty() {
        let c = catalog();
        let n = c["invariants"].as_array().map(|a| a.len()).unwrap_or(0);
        assert_eq!(n, 20);
    }

    #[test]
    fn inv_16_snapshot_publish_atomic() {
        let reg = RuntimeSnapshotRegistry::new();
        let snap = AgentRuntimeSnapshot {
            schema: AGENT_RUNTIME_SNAPSHOT_SCHEMA.into(),
            principal_id: "p1".into(),
            tenant_id: "t1".into(),
            snapshot_version: 2,
            identity_generation: 1,
            charter_generation: 1,
            broker_generation: 1,
            quarantine_generation: 0,
            iac_epoch: 1,
            policy_bundle_id: "policy:p1".into(),
            who_am_i: "I am p1".into(),
            hard_charter: "rules".into(),
            vendor_brain_denial: "denial".into(),
            agent_name: "P1".into(),
            compiled_skills: vec![],
            compiled_rules: serde_json::json!({}),
            compiled_address_contracts: crate::substrate::agent_runtime_snapshot::CompiledAddressContracts::default(),
            compiled_tool_names: vec!["llm.chat".into()],
            static_llm_envelope: "env".into(),
            provider_route: None,
            memory_index_ref: "ns".into(),
            budget_profile: serde_json::json!({}),
            mission_profile: serde_json::json!({}),
            snapshot_hash: "h".into(),
            compiled_at_ms: 0,
        };
        reg.publish(snap);
        let a = reg.get("p1").unwrap();
        let b = reg.get("p1").unwrap();
        assert_eq!(a.snapshot_version, b.snapshot_version);
        assert_eq!(a.snapshot_hash, b.snapshot_hash);
    }

    #[tokio::test]
    async fn inv_17_same_session_serialized() {
        let reg = SessionOwnerRegistry::new();
        let _a = reg.acquire("sess-x").await;
        assert!(reg.try_acquire("sess-x").is_err());
    }

    #[tokio::test]
    async fn inv_18_different_sessions_concurrent() {
        let reg = SessionOwnerRegistry::new();
        let _a = reg.acquire("sess-a").await;
        assert!(reg.try_acquire("sess-b").is_ok());
    }

    #[test]
    fn inv_05_effect_auth_digest_stable() {
        let d1 = auth_digest_for("a", "o1", "admit", 3, "t1");
        let d2 = auth_digest_for("a", "o1", "admit", 3, "t1");
        assert_eq!(d1, d2);
        let intent = EffectIntent::from_workbench_order(
            "a",
            "s",
            "o1",
            "admit",
            "tool.x",
            serde_json::json!({}),
            3,
            Some("t1"),
        );
        assert_eq!(intent.auth_digest().unwrap(), d1);
    }

    #[test]
    fn inv_04_stream_chunks_only_projected() {
        // Gate only chunks post-projection text — never invents provider raw.
        let projected = "Safe operator text.";
        assert_eq!(chunk_projected_text(projected, 8).concat(), projected);
    }

    #[test]
    fn inv_09_bulkheads_bounded() {
        std::env::set_var("CONNECTOR_BULKHEAD_TALK", "2");
        let b = WorkloadBulkheads::from_env();
        let _p1 = b.try_acquire_talk().unwrap();
        let _p2 = b.try_acquire_talk().unwrap();
        assert!(b.try_acquire_talk().is_err());
        std::env::remove_var("CONNECTOR_BULKHEAD_TALK");
    }

    #[test]
    fn inv_10_turn_deadline_present() {
        let d = TurnDeadline::from_now(5_000, 1_000);
        let e = TurnEnvelope::mint_talk("t", "a", "s", 1, 1, 1, 0, d, "q");
        assert!(e.deadline.provider_budget_ms > 0);
        assert!(!e.deadline.expired());
    }
}

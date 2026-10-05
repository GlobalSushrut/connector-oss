//! Connector ARC — Augmented Agency Runtime (Phases A–H).
//!
//! Center: AgencyState → AgencyTransaction → ConsequenceLease → WorldlineCommit.
//! Extends governed_effect / PATE / BCR / CVR — does **not** invent a second admit stack.
//!
//! Docs: platform/docs/arch/CONNECTOR_ARC.md · CONNECTOR_ARC_IMPLEMENTATION_PLAN.md

pub mod aacr;
pub mod agency_state;
pub mod api;
pub mod authority_epoch;
pub mod autonomy_volume;
pub mod avsock;
pub mod bypass_inventory;
pub mod copg;
pub mod durable;
pub mod flags;
pub mod governor;
pub mod governor_input;
pub mod ifc;
pub mod lease;
pub mod lease_store;
pub mod memory;
pub mod observable;
pub mod proposal;
pub mod quarantine_proof;
pub mod runtime;
pub mod scheduler;
pub mod transaction;
pub mod transaction_store;
pub mod worldline;
pub mod worldline_store;

pub use agency_state::AgencyState;
pub use authority_epoch::AuthorityEpochStore;
pub use autonomy_volume::{AutonomyFacets, AutonomyVolume, EnforcementGrade, FacetDenial};
pub use avsock::{AvsockFrame, MessageClass};
pub use flags::ArcFlags;
pub use governor_input::GovernorInput;
pub use ifc::IfcTriple;
pub use lease::{ConsequenceLease, LeaseEffectHandle};
pub use memory::MemoryClass;
pub use observable::ObservableState;
pub use proposal::EffectProposal;
pub use scheduler::{IsolationRecommend, ScheduleDecision, ScheduleHint};
pub use transaction::{AgencyTransaction, TransitionError, TxState};
pub use transaction_store::TransactionStore;
pub use worldline::WorldlineCommit;

use serde_json::{json, Value};

/// Aggregate ARC posture for `/substrate/status`.
pub fn posture_json() -> Value {
    let flags = ArcFlags::from_env();
    let facets = AutonomyFacets::lab_partial_v0()
        .with_dit_enforced()
        .with_cgqp_enforced();
    let volume = AutonomyVolume::from_facets(facets.clone());
    let effective = AutonomyVolume::effective_meet(&facets);
    let obs = ObservableState::empty_placeholder();
    let agency = AgencyState::placeholder("unbound", &obs, &volume, 0, None);
    let partial = facets
        .iter_grades()
        .iter()
        .any(|(_, g)| *g == EnforcementGrade::Observed);
    json!({
        "schema": "connector.arc.v1",
        "role": "Agency virtualization — state-transition runtime for autonomous agency",
        "center": ["AgencyState", "AgencyTransaction", "ConsequenceLease", "WorldlineCommit"],
        "docs": [
            "platform/docs/arch/CONNECTOR_ARC.md",
            "platform/docs/arch/CONNECTOR_ARC_IMPLEMENTATION_PLAN.md",
        ],
        "flags": flags.to_json(),
        "agency_state_digest": agency.digest(),
        "hat_z_digest": obs.digest(),
        "autonomy_volume_digest": volume.digest(),
        "autonomy_facets": facets.to_json(),
        "effective_a": {
            "claim": effective.effective_claim,
            "digest": effective.digest(),
            "honesty": effective.honesty,
            "meet_excludes_observed": true,
        },
        "authority_epoch": {
            "honesty": "per-agent counter; sink must verify at redeem",
            "store": "in_process",
            "bumps_with": "IntelligenceCell::bump_epoch (quarantine/grant/revoke)",
        },
        "transaction_fsm": {
            "kernel": true,
            "happy_path": [
                "PROPOSED", "VALIDATED", "RESERVED", "LEASED", "REDEEMING",
                "EFFECT_STARTED", "SETTLED", "COMMITTED"
            ],
            "branches": [
                "DENIED", "WAITING_HITL", "REVOKED", "EXPIRED", "FAILED",
                "EFFECT_UNKNOWN", "COMPENSATING", "QUARANTINED", "ABORTED"
            ],
            "effect_unknown": "crash after EFFECT_STARTED before SETTLED — no blind retry",
        },
        "governor": {
            "input": "GovernorInput (typed hat Z only — no latent DIM private)",
            "admit_wired": true,
            "hooks": ["pate::admit_talk", "pate::admit_tool", "pate::admit_conp", "ops_runtime::preflight"],
            "stm": "PROPOSED→VALIDATED→RESERVED on Proceed when CONNECTOR_ARC_GOVERNOR=1",
            "b4": flags.to_json().get("b4").cloned().unwrap_or(json!("soft")),
            "honesty": "Flag off = Soft no-op; HARDEN without GOVERNOR = deny; Proceed reuses PATE NF³/binding",
        },
        "lease": {
            "schema": crate::substrate::arc::lease::SCHEMA,
            "wired_sinks": [
                crate::substrate::arc::lease::SINK_TOOL_DISPATCH,
                crate::substrate::arc::lease::SINK_LLM_CHAT,
                crate::substrate::arc::lease::SINK_CONP_COMMAND,
            ],
            "enforced": flags.lease,
            "open_leases": crate::substrate::arc::runtime::leases().len(),
            "compensate": "B0.4 Compensating edge + AAPI inverse when registered",
        },
        "ifc": crate::substrate::arc::ifc::posture_json(),
        "worldline": {
            "schema": crate::substrate::arc::worldline::SCHEMA,
            "commits": crate::substrate::arc::runtime::worldline().len(),
            "honesty": "WorldlineCommit authoritative for AgencyState reconstruct",
            "durable": crate::substrate::arc::durable::posture_json(),
            "copg": crate::substrate::arc::copg::posture_json(),
        },
        "avsock": crate::substrate::arc::avsock::posture_json(),
        "bypass_inventory": crate::substrate::arc::bypass_inventory::inventory_json(),
        "scheduler": crate::substrate::arc::scheduler::posture_json(),
        "memory": crate::substrate::arc::memory::posture_json(),
        "quarantine_proof": {
            "schema": crate::substrate::arc::quarantine_proof::SCHEMA,
            "honesty": "prove_unreachable after quarantine — else QUARANTINE_FAILED",
        },
        "runtime": {
            "open_transactions": crate::substrate::arc::runtime::transactions().len(),
            "open_leases": crate::substrate::arc::runtime::leases().len(),
            "worldline_commits": crate::substrate::arc::runtime::worldline().len(),
            "memory_records": crate::substrate::arc::memory::store().len(),
        },
        "admit_proof_schema": "connector.arc.admit_proof.v1",
        "lab_partial": partial,
        "honesty": if partial {
            "Autonomy facets include Observed stubs (N topology) — Effective A meet excludes Observed; C/G/D/I/T/Q/P Enforced"
        } else {
            "Facet grades Enforced/Effective only"
        },
        "usable_outcome": "In-envelope Talk/tools must succeed when ARC flags on — not deny-all theater",
        "phases": ["A", "B0", "B", "C", "D", "E", "F", "G", "H"],
    })
}

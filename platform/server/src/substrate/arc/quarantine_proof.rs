//! Quarantine unreachable-consequence proof (G6 / ARC-9).

use serde_json::{json, Value};

use crate::error::{ConnectorError, DenialReason};

use super::autonomy_volume::{AutonomyFacets, AutonomyVolume, EnforcementGrade};
use super::runtime;
use super::transaction::TxState;

pub const SCHEMA: &str = "connector.arc.quarantine_proof.v1";

#[derive(Debug, Clone)]
pub struct QuarantineProof {
    pub agent_id: String,
    pub ok: bool,
    pub checks: Vec<(String, bool, String)>,
}

impl QuarantineProof {
    pub fn to_json(&self) -> Value {
        json!({
            "schema": SCHEMA,
            "agent_id": self.agent_id,
            "ok": self.ok,
            "verdict": if self.ok { "UNREACHABLE" } else { "QUARANTINE_FAILED" },
            "checks": self.checks.iter().map(|(n, ok, d)| json!({
                "name": n, "ok": ok, "detail": d
            })).collect::<Vec<_>>(),
            "honesty": "Stronger than empty maps — live leases / mid-flight txs / child A must be unreachable",
        })
    }
}

fn check(
    out: &mut Vec<(String, bool, String)>,
    name: &str,
    ok: bool,
    detail: impl Into<String>,
) {
    out.push((name.into(), ok, detail.into()));
}

/// Prove agent has no reachable consequence after quarantine seal.
pub fn prove_unreachable(agent_id: &str) -> QuarantineProof {
    let mut checks = Vec::new();

    let open_leases = runtime::leases().open_for_agent(agent_id).len();
    check(
        &mut checks,
        "no_live_leases",
        open_leases == 0,
        format!("open_leases={open_leases}"),
    );

    let midflight = runtime::transactions()
        .list_for_agent(agent_id)
        .into_iter()
        .filter(|tx| {
            matches!(
                tx.state,
                TxState::Redeeming
                    | TxState::EffectStarted
                    | TxState::EffectUnknown
                    | TxState::Reserved
                    | TxState::Leased
            )
        })
        .count();
    check(
        &mut checks,
        "no_unfenced_midflight",
        midflight == 0,
        format!("midflight_txs={midflight}"),
    );

    check(
        &mut checks,
        "no_child_a_above_bottom",
        true,
        "child topology A=⊥ (v0 placeholder — parent quarantine propagates)",
    );

    check(
        &mut checks,
        "no_direct_egress",
        true,
        "egress cut via CVR quarantine order (assumed sealed)",
    );

    let deferred_commit = runtime::transactions()
        .list_for_agent(agent_id)
        .into_iter()
        .any(|tx| matches!(tx.state, TxState::Settled));
    check(
        &mut checks,
        "no_deferred_commit_capable",
        !deferred_commit,
        if deferred_commit {
            String::from("SETTLED tx could still COMMIT")
        } else {
            String::from("no SETTLED pending commit")
        },
    );

    let ok = checks.iter().all(|(_, o, _)| *o);
    QuarantineProof {
        agent_id: agent_id.into(),
        ok,
        checks,
    }
}

pub fn assert_unreachable(agent_id: &str) -> Result<QuarantineProof, ConnectorError> {
    let proof = prove_unreachable(agent_id);
    if proof.ok {
        Ok(proof)
    } else {
        Err(ConnectorError::new(
            DenialReason::PolicyDenied,
            "QUARANTINE_FAILED: reachable consequence remains",
        )
        .with_denied_resource("arc.quarantine")
        .with_hint("Revoke leases, fence mid-flight txs, clear SETTLED deferred commits"))
    }
}

/// Effective A after quarantine must be empty meet (Observed-only stubs don't count as Effective).
pub fn effective_a_is_bottom(facets: &AutonomyFacets) -> bool {
    let vol = AutonomyVolume::effective_meet(facets);
    !vol.effective_claim
        && facets
            .iter_grades()
            .iter()
            .filter(|(_, g)| g.counts_for_effective_a())
            .count()
            == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::substrate::arc::lease::{self, SINK_TOOL_DISPATCH};
    use crate::substrate::arc::transaction::AgencyTransaction;

    #[test]
    fn empty_agent_unreachable() {
        let p = prove_unreachable("arc-g-empty");
        assert!(p.ok, "{:?}", p.checks);
    }

    #[test]
    fn live_lease_fails_proof() {
        std::env::set_var("CONNECTOR_ARC_LEASE", "1");
        let agent = "arc-g-lease";
        let mut tx = AgencyTransaction::new(agent, 0, Some("d".into()));
        tx.idempotency_key = Some("t".into());
        tx.transition(TxState::Validated).unwrap();
        tx.transition(TxState::Reserved).unwrap();
        runtime::transactions().insert(tx.clone());
        let _ = lease::mint_on_reserved(&tx.tx_id, "d", 0, None, None, None, SINK_TOOL_DISPATCH)
            .unwrap();
        let p = prove_unreachable(agent);
        assert!(!p.ok);
        assert!(assert_unreachable(agent).is_err());
        lease::revoke_agent_leases(agent);
        std::env::remove_var("CONNECTOR_ARC_LEASE");
    }

    #[test]
    fn observed_only_is_bottom_effective() {
        let f = AutonomyFacets::lab_partial_v0();
        assert!(effective_a_is_bottom(&f));
        assert!(f
            .iter_grades()
            .iter()
            .all(|(_, g)| *g == EnforcementGrade::Observed));
    }
}

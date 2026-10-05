//! Production, bank-control, and military-court gate.
//!
//! Bank-control means the self-hosted membrane is fail-closed: production
//! posture, a real JWT secret, and no break-glass. It is not a PCI, regulator,
//! or counsel certification.
//!
//! Military-court means the host-attach report already computed
//! `military_court_ready`. This module never sets that flag itself.
//! `CLAIM_MILITARY_COURT=1` is refused when the report is missing or false.
//!
//! See `platform/docs/arch/COURT_GRADE_CLAIMS.md`.

use serde_json::{json, Value};

use super::runtime_adapter::{self, RuntimeKind};

const BREAK_GLASS: &[&str] = &[
    "CONNECTOR_DEV_AUTH_BYPASS",
    "CONNECTOR_ALLOW_IN_PROCESS_EFFECTS",
    "CONNECTOR_ALLOW_SUBPROCESS_ISOLATION",
    "CONNECTOR_ALLOW_ISOLATION_DOWNGRADE",
    "CONNECTOR_ALLOW_GUEST_EGRESS",
    "CONNECTOR_ALLOW_HOST_MCP_BROKER",
    "CONNECTOR_HOST_MCP_BROKER",
    "CONNECTOR_LLM_STUB",
    "CONNECTOR_LLM_STUB_ALLOW_IN_PROD",
    "CONNECTOR_KERNEL_EGRESS_DEGRADED",
    "CONNECTOR_DISTRIBUTED_ALLOW_INSECURE_TLS",
    "CONNECTOR_CAPS_ALLOW_MOCK",
    "CONNECTOR_PLAYGROUND",
];

#[derive(Debug, Clone)]
pub struct GateInput {
    pub playground: bool,
    pub productionish: bool,
    pub jwt_secret_ok: bool,
    pub break_glass: Vec<String>,
    pub attach_report_present: bool,
    pub attach_military_ready: bool,
    pub claim_military: bool,
    pub firecracker_ready: bool,
    pub openshell_ready: bool,
}

pub fn live() -> Value {
    let playground = env_on("CONNECTOR_PLAYGROUND")
        || matches!(
            std::env::var("CONNECTOR_PRESET")
                .unwrap_or_default()
                .trim()
                .to_ascii_lowercase()
                .as_str(),
            "playground" | "trial" | "saas-trial"
        );
    let preset = std::env::var("CONNECTOR_PRESET").unwrap_or_default();
    let preset_l = preset.trim().to_ascii_lowercase();
    let productionish = crate::connector_profile::is_productionish_env()
        || matches!(
            preset_l.as_str(),
            "production" | "prod" | "airgap" | "defense-strict" | "unbypassable" | "staging"
        );
    let jwt = std::env::var("CONNECTOR_JWT_SECRET").unwrap_or_default();
    let jwt_secret_ok = jwt.trim().len() >= 32;
    let break_glass: Vec<String> = BREAK_GLASS
        .iter()
        .filter(|k| env_on(k))
        .map(|k| (*k).to_string())
        .collect();
    let kernel_soft = std::env::var("CONNECTOR_KERNEL_ENFORCE")
        .map(|v| matches!(v.trim(), "0" | "false" | "off"))
        .unwrap_or(false);
    let mut break_glass = break_glass;
    if kernel_soft {
        break_glass.push("CONNECTOR_KERNEL_ENFORCE=0".into());
    }
    let (attach_report_present, attach_military_ready) = read_attach_report();
    let probes = runtime_adapter::probe_all();
    evaluate(GateInput {
        playground,
        productionish,
        jwt_secret_ok,
        break_glass,
        attach_report_present,
        attach_military_ready,
        claim_military: env_on("CLAIM_MILITARY_COURT"),
        firecracker_ready: probes
            .iter()
            .any(|p| p.kind == RuntimeKind::Firecracker && p.ready),
        openshell_ready: probes
            .iter()
            .any(|p| p.kind == RuntimeKind::OpenShell && p.ready),
    })
}

pub fn evaluate(input: GateInput) -> Value {
    let mut bank_blockers: Vec<String> = Vec::new();
    if input.playground {
        bank_blockers.push("playground_or_trial".into());
    }
    if !input.productionish {
        bank_blockers.push("not_production_posture".into());
    }
    if !input.jwt_secret_ok {
        bank_blockers.push("CONNECTOR_JWT_SECRET_missing_or_short".into());
    }
    for hatch in &input.break_glass {
        bank_blockers.push(format!("break_glass:{hatch}"));
    }
    let bank_control_ready = bank_blockers.is_empty();

    let mut military_blockers = bank_blockers.clone();
    if !input.attach_report_present {
        military_blockers.push("host_attach_report_missing".into());
    } else if !input.attach_military_ready {
        military_blockers.push("host_attach_report_not_ready".into());
    }
    if !input.firecracker_ready {
        military_blockers.push("firecracker_not_ready".into());
    }
    if !input.openshell_ready {
        military_blockers.push("openshell_supervisor_not_bound".into());
    }
    let military_court_ready = military_blockers.is_empty();
    let claim_refused = input.claim_military && !military_court_ready;

    json!({
        "schema": "connector.production_gate.v1",
        "bank_control_ready": bank_control_ready,
        "bank_blockers": bank_blockers,
        "military_court_ready": military_court_ready,
        "military_blockers": military_blockers,
        "claim_military": input.claim_military,
        "claim_refused": claim_refused,
        "attach_report_present": input.attach_report_present,
        "attach_report_says_ready": input.attach_military_ready,
        "firecracker_ready": input.firecracker_ready,
        "openshell_ready": input.openshell_ready,
        "honesty": "bank_control_ready is a fail-closed self-host membrane, not a PCI or regulator certificate. military_court_ready requires that membrane plus a host-attach report, a ready Firecracker probe, and a bound OpenShell supervisor. This process does not invent those proofs. Partner SIL certification stays with the partner.",
    })
}

fn read_attach_report() -> (bool, bool) {
    let path = std::env::var("CONNECTOR_HOST_ATTACH_REPORT")
        .unwrap_or_else(|_| "/tmp/connector-host-attach-proofs.json".into());
    let Ok(raw) = std::fs::read_to_string(&path) else {
        return (false, false);
    };
    let Ok(v) = serde_json::from_str::<Value>(&raw) else {
        return (true, false);
    };
    let ready = v
        .get("military_court_ready")
        .and_then(|b| b.as_bool())
        .unwrap_or(false);
    (true, ready)
}

fn env_on(key: &str) -> bool {
    std::env::var(key)
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn closed() -> GateInput {
        GateInput {
            playground: false,
            productionish: true,
            jwt_secret_ok: true,
            break_glass: vec![],
            attach_report_present: true,
            attach_military_ready: true,
            claim_military: false,
            firecracker_ready: true,
            openshell_ready: true,
        }
    }

    #[test]
    fn playground_is_not_bank_or_military() {
        let mut g = closed();
        g.playground = true;
        let v = evaluate(g);
        assert_eq!(v.get("bank_control_ready").and_then(|b| b.as_bool()), Some(false));
        assert_eq!(v.get("military_court_ready").and_then(|b| b.as_bool()), Some(false));
    }

    #[test]
    fn break_glass_blocks_bank_control() {
        let mut g = closed();
        g.break_glass = vec!["CONNECTOR_ALLOW_IN_PROCESS_EFFECTS".into()];
        let v = evaluate(g);
        assert_eq!(v.get("bank_control_ready").and_then(|b| b.as_bool()), Some(false));
    }

    #[test]
    fn short_jwt_secret_blocks_bank_control() {
        let mut g = closed();
        g.jwt_secret_ok = false;
        let v = evaluate(g);
        assert_eq!(v.get("bank_control_ready").and_then(|b| b.as_bool()), Some(false));
    }

    #[test]
    fn military_claim_without_attach_is_refused() {
        let mut g = closed();
        g.attach_report_present = false;
        g.attach_military_ready = false;
        g.claim_military = true;
        let v = evaluate(g);
        assert_eq!(v.get("military_court_ready").and_then(|b| b.as_bool()), Some(false));
        assert_eq!(v.get("claim_refused").and_then(|b| b.as_bool()), Some(true));
    }

    #[test]
    fn full_evidence_is_the_only_military_ready_path() {
        let v = evaluate(closed());
        assert_eq!(v.get("bank_control_ready").and_then(|b| b.as_bool()), Some(true));
        assert_eq!(v.get("military_court_ready").and_then(|b| b.as_bool()), Some(true));
        assert_eq!(v.get("claim_refused").and_then(|b| b.as_bool()), Some(false));
    }

    #[test]
    fn openshell_unbound_blocks_military_even_when_attach_file_is_ready() {
        let mut g = closed();
        g.openshell_ready = false;
        let v = evaluate(g);
        assert_eq!(v.get("bank_control_ready").and_then(|b| b.as_bool()), Some(true));
        assert_eq!(v.get("military_court_ready").and_then(|b| b.as_bool()), Some(false));
    }
}

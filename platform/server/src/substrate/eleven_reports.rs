//! Three Connector-controlled reports. Each lists the same eleven fingers.
//!
//! A row is `followed` only when this report's evidence says that finger acted.
//! A live pinned process is `supervised`. Missing evidence is `absent`.
//! These reports do not admit, do not write the seven-backend board, and do
//! not issue a court seal.

use axum::extract::{Path, State};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::state::{PlatformState, SharedState};

pub const SCHEMA: &str = "connector.eleven_reports.v1";
pub const COMPLIANCE_REPORT_TYPE: &str = "connector_controlled_workflow";
pub const EXISTING_NODE_REPORT_TYPE: &str = "NODE_GENERATED_CONTROL_EVIDENCE";

pub const FINGER_IDS: [&str; 11] = [
    "iam",
    "spire",
    "openshell",
    "opa",
    "firecracker",
    "otel",
    "cosign",
    "traffic",
    "brain",
    "broker",
    "orchestrate",
];

const SEVEN: [&str; 7] = [
    "iam",
    "spire",
    "openshell",
    "opa",
    "firecracker",
    "otel",
    "cosign",
];

fn row(id: &str, state: &str, detail: &str) -> Value {
    json!({
        "id": id,
        "state": state,
        "seven_backend": false,
        "acceptance_passed": false,
        "detail": detail,
    })
}

fn evidence_state(followed: bool, supervised: bool) -> &'static str {
    if followed {
        "followed"
    } else if supervised {
        "supervised"
    } else {
        "absent"
    }
}

/// Seven rows follow deploy-verify readiness. Traffic and the three intelligence
/// processes are supervised only while their pinned process is up.
pub fn system_fingers(
    seven_ready: &[(&str, bool)],
    traffic_ready: bool,
    intel_ready: &[(&str, bool)],
) -> Vec<Value> {
    let mut out = Vec::with_capacity(11);
    for id in SEVEN {
        let ready = seven_ready
            .iter()
            .find(|(name, _)| *name == id)
            .map(|(_, ready)| *ready)
            .unwrap_or(false);
        out.push(row(
            id,
            evidence_state(ready, false),
            if ready {
                "The seven-backend reading has this operation."
            } else {
                "No completed operation is stored for this finger."
            },
        ));
    }
    out.push(row(
        "traffic",
        evidence_state(false, traffic_ready),
        if traffic_ready {
            "The pinned traffic process is supervised. Forwarding is still per request."
        } else {
            "No supervised traffic process."
        },
    ));
    for id in ["brain", "broker", "orchestrate"] {
        let ready = intel_ready
            .iter()
            .find(|(name, _)| *name == id)
            .map(|(_, ready)| *ready)
            .unwrap_or(false);
        out.push(row(
            id,
            evidence_state(false, ready),
            if ready {
                "The pinned process is supervised. It has not been cited on a task by this report."
            } else {
                "The pinned process is not running."
            },
        ));
    }
    out
}

pub struct AgentFacts {
    pub operator_sub: bool,
    pub workload_id: bool,
    pub policy_pushed: bool,
    pub runtime_handle: bool,
    pub trace_id: bool,
    pub cosign_ready: bool,
    pub traffic_ready: bool,
    pub brain_ready: bool,
    pub broker_ready: bool,
    pub orchestrate_ready: bool,
    pub brain_followed: bool,
    pub broker_followed: bool,
    pub orchestrate_followed: bool,
}

pub fn agent_fingers(facts: &AgentFacts) -> Vec<Value> {
    vec![
        row(
            "iam",
            evidence_state(facts.operator_sub, false),
            "Followed when this task spine has an operator subject.",
        ),
        row(
            "spire",
            evidence_state(facts.workload_id, false),
            "Followed when this task spine has a workload id.",
        ),
        row(
            "openshell",
            evidence_state(facts.policy_pushed, false),
            "Followed when Connector stored a successful policy push for this agent.",
        ),
        row(
            "opa",
            evidence_state(facts.policy_pushed, false),
            "Follows the OpenShell policy push. Connector does not run a second policy engine.",
        ),
        row(
            "firecracker",
            evidence_state(facts.runtime_handle, false),
            "Followed when this task spine has a runtime handle.",
        ),
        row(
            "otel",
            evidence_state(facts.trace_id, false),
            "Followed when this task spine has a trace id.",
        ),
        row(
            "cosign",
            evidence_state(false, facts.cosign_ready),
            "Supply-chain verification is a node reading, not this agent's effect.",
        ),
        row(
            "traffic",
            evidence_state(false, facts.traffic_ready),
            "Supervised while the pinned process is up. A forward is a separate request.",
        ),
        row(
            "brain",
            evidence_state(facts.brain_followed, facts.brain_ready),
            "Followed when a recall dispatch wrote a mempacket for this agent.",
        ),
        row(
            "broker",
            evidence_state(facts.broker_followed, facts.broker_ready),
            "Followed when a model dispatch wrote a mempacket for this agent.",
        ),
        row(
            "orchestrate",
            evidence_state(facts.orchestrate_followed, facts.orchestrate_ready),
            "Followed when a flow dispatch wrote a mempacket for this agent.",
        ),
    ]
}

fn envelope(kind: &str, body: Value) -> Value {
    json!({
        "schema": SCHEMA,
        "kind": kind,
        "report_type": COMPLIANCE_REPORT_TYPE,
        "connector_controlled": true,
        "seven_backend": false,
        "acceptance_passed": false,
        "production_eligible": false,
        "court_seal": false,
        "body": body,
        "honesty": "Connector assembled this report from stored readings. A supervised process has not followed the task. This is not a court seal, a certification, or a statement that a model answer was correct.",
    })
}

pub fn system_report(state: &PlatformState) -> Value {
    let board = crate::substrate::cvr::deployment_verify::live(
        state,
        crate::substrate::cvr::deployment_verify::DeployProfile::LinuxKvm,
    );
    let seven_ready = ready_pairs(board.get("backends"));
    let traffic = crate::substrate::agentgateway::status();
    let intel = crate::substrate::intelligence_plane::status();
    let fingers = system_fingers(
        &seven_ready,
        traffic.get("ready").and_then(|v| v.as_bool()).unwrap_or(false),
        &ready_pairs(intel.get("backends")),
    );
    envelope(
        "system",
        json!({
            "fingers": fingers,
            "finger_ids": FINGER_IDS,
            "deploy_verify_schema": board.get("schema").cloned().unwrap_or(Value::Null),
        }),
    )
}

pub fn agent_report(state: &PlatformState, agent_pid: &str) -> Value {
    let atu = folder(state, crate::substrate::pate::ATU_FOLDER, &format!("latest:{agent_pid}"));
    let policy = folder(
        state,
        crate::substrate::cvr::runtime_adapter::POLICY_GEN_FOLDER,
        &format!("latest:{agent_pid}"),
    );
    let spine = atu.as_ref().and_then(|row| row.get("spine"));
    let present = |key: &str| {
        spine
            .and_then(|row| row.get(key))
            .and_then(|v| v.as_str())
            .is_some_and(|s| !s.trim().is_empty())
    };
    let intel = crate::substrate::intelligence_plane::status();
    let intel_ready = ready_pairs(intel.get("backends"));
    let ready = |id: &str| {
        intel_ready
            .iter()
            .find(|(name, _)| *name == id)
            .map(|(_, ready)| *ready)
            .unwrap_or(false)
    };
    let facts = AgentFacts {
        operator_sub: present("operator_sub"),
        workload_id: present("workload_id"),
        policy_pushed: policy
            .as_ref()
            .and_then(|row| row.get("pushed"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        runtime_handle: present("runtime_handle"),
        trace_id: present("trace_id"),
        cosign_ready: crate::substrate::cvr::runtime_adapter::cosign_status()
            .get("verified")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        traffic_ready: crate::substrate::agentgateway::status()
            .get("ready")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        brain_ready: ready("brain"),
        broker_ready: ready("broker"),
        orchestrate_ready: ready("orchestrate"),
        brain_followed: crate::substrate::intelligence_plane::role_followed(state, agent_pid, "brain"),
        broker_followed: crate::substrate::intelligence_plane::role_followed(state, agent_pid, "broker"),
        orchestrate_followed: crate::substrate::intelligence_plane::role_followed(
            state,
            agent_pid,
            "orchestrate",
        ),
    };
    let fingers = agent_fingers(&facts);
    let workspace = workspace_view(agent_pid);
    let mempacket_cid = latest_mempacket_cid(state, agent_pid);
    envelope(
        "agent",
        json!({
            "agent_pid": agent_pid,
            "task_id": atu.as_ref().and_then(|row| row.get("task_id")).cloned().unwrap_or(Value::Null),
            "verdict": atu.as_ref().and_then(|row| row.get("verdict")).cloned().unwrap_or(Value::Null),
            "effect_kind": atu.as_ref().and_then(|row| row.get("effect_kind")).cloned().unwrap_or(Value::Null),
            "broker_epoch": atu.as_ref().and_then(|row| row.get("broker_epoch")).cloned().unwrap_or(Value::Null),
            "spine": spine.cloned().unwrap_or(Value::Null),
            "admits": false,
            "capability_ref": spine.and_then(|row| row.get("aapi_ref")).cloned().unwrap_or(Value::Null),
            "mempacket_cid": mempacket_cid,
            "workspace": workspace,
            "fingers": fingers,
            "finger_ids": FINGER_IDS,
        }),
    )
}

pub fn compliance_report(state: &PlatformState, agent_pid: Option<&str>) -> Value {
    let system = system_report(state);
    let agent = agent_pid.map(|pid| agent_report(state, pid));
    let alignment = agent_pid.and_then(|pid| crate::kernel::witnessctl_align::load_alignment(state, pid));
    let wc_status = alignment
        .as_ref()
        .and_then(|row| row.get("status"))
        .and_then(|v| v.as_str())
        .unwrap_or("pending_wc_unavailable");
    envelope(
        "compliance",
        json!({
            "witnessctl_status": wc_status,
            "witnessctl_session_id": alignment.as_ref().and_then(|row| row.get("session_id")).cloned().unwrap_or(Value::Null),
            "agent_report": agent.unwrap_or(Value::Null),
            "system_report": system,
            "fingers": system_fingers_of_report(&system),
            "finger_ids": FINGER_IDS,
        }),
    )
}

fn system_fingers_of_report(report: &Value) -> Value {
    report
        .pointer("/body/fingers")
        .cloned()
        .unwrap_or(Value::Null)
}

fn ready_pairs(rows: Option<&Value>) -> Vec<(&str, bool)> {
    rows.and_then(|v| v.as_array())
        .map(|rows| {
            rows.iter()
                .filter_map(|row| {
                    let id = row.get("id")?.as_str()?;
                    let ready = row.get("ready").and_then(|v| v.as_bool()).unwrap_or(false);
                    Some((id, ready))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn folder(state: &PlatformState, name: &str, key: &str) -> Option<Value> {
    let store = state.engine_store.lock().ok()?;
    store.folder_get(name, key).ok().flatten()
}

fn workspace_view(agent_pid: &str) -> Value {
    match crate::kernel::nsfs::nsfs_root(agent_pid) {
        Ok(root) => {
            let path = root.display().to_string();
            let denied = crate::kernel::address_cage::foreign_nsfs_open_denied(
                "agent_foreign_report_probe",
                &path,
            );
            json!({
                "present": true,
                "foreign_open_denied": denied,
            })
        }
        Err(reason) => json!({
            "present": false,
            "foreign_open_denied": false,
            "detail": reason,
        }),
    }
}

fn latest_mempacket_cid(state: &PlatformState, agent_pid: &str) -> Value {
    let Ok(kernel) = state.kernel.lock() else {
        return Value::Null;
    };
    let mut best: Option<(i64, String)> = None;
    for packet in kernel.all_packets() {
        let subject = packet.subject_id.as_str();
        let principal = packet.provenance.source.principal_id.as_str();
        if subject != agent_pid && principal != agent_pid {
            continue;
        }
        let ts = packet.index.ts;
        let cid = packet.index.packet_cid.to_string();
        if best.as_ref().map(|(seen, _)| ts >= *seen).unwrap_or(true) {
            best = Some((ts, cid));
        }
    }
    best.map(|(_, cid)| Value::String(cid))
        .unwrap_or(Value::Null)
}

/// GET /api/v1/reports/agent/:agent_pid
pub async fn get_agent_report(
    State(state): State<SharedState>,
    Path(agent_pid): Path<String>,
) -> Json<Value> {
    Json(agent_report(state.as_ref(), &agent_pid))
}

/// GET /api/v1/reports/system
pub async fn get_system_report(State(state): State<SharedState>) -> Json<Value> {
    Json(system_report(state.as_ref()))
}

#[derive(Debug, Deserialize)]
pub struct ComplianceBody {
    #[serde(default)]
    pub agent_pid: Option<String>,
}

/// POST /api/v1/reports/compliance
pub async fn post_compliance_report(
    State(state): State<SharedState>,
    Json(body): Json<ComplianceBody>,
) -> Json<Value> {
    Json(compliance_report(
        state.as_ref(),
        body.agent_pid.as_deref().map(str::trim).filter(|s| !s.is_empty()),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(rows: &[Value]) -> Vec<&str> {
        rows.iter().filter_map(|row| row["id"].as_str()).collect()
    }

    #[test]
    fn system_report_lists_eleven_and_does_not_pass() {
        let seven = [
            ("iam", true),
            ("spire", false),
            ("openshell", true),
            ("opa", true),
            ("firecracker", false),
            ("otel", false),
            ("cosign", true),
        ];
        let intel = [("brain", true), ("broker", false), ("orchestrate", false)];
        let rows = system_fingers(&seven, true, &intel);
        assert_eq!(ids(&rows), FINGER_IDS);
        assert_eq!(rows.iter().find(|r| r["id"] == "iam").unwrap()["state"], "followed");
        assert_eq!(rows.iter().find(|r| r["id"] == "spire").unwrap()["state"], "absent");
        assert_eq!(rows.iter().find(|r| r["id"] == "traffic").unwrap()["state"], "supervised");
        assert_eq!(rows.iter().find(|r| r["id"] == "brain").unwrap()["state"], "supervised");
        assert_eq!(rows.iter().find(|r| r["id"] == "broker").unwrap()["state"], "absent");
        for row in &rows {
            assert_eq!(row["seven_backend"], false);
            assert_eq!(row["acceptance_passed"], false);
        }
        let report = envelope("system", json!({"fingers": rows}));
        assert_eq!(report["acceptance_passed"], false);
        assert_eq!(report["production_eligible"], false);
        assert_eq!(report["court_seal"], false);
        assert_eq!(report["report_type"], COMPLIANCE_REPORT_TYPE);
        assert_ne!(COMPLIANCE_REPORT_TYPE, EXISTING_NODE_REPORT_TYPE);
        assert!(!report.to_string().contains("CONNECTOR READY"));
        let board = crate::substrate::cvr::backends::assemble(
            &[],
            &json!({"present": false, "verified": false, "reason": "not_installed"}),
        );
        assert_eq!(board["backends"].as_array().unwrap().len(), 7);
    }

    #[test]
    fn agent_report_follows_only_its_own_spine() {
        let rows = agent_fingers(&AgentFacts {
            operator_sub: true,
            workload_id: false,
            policy_pushed: true,
            runtime_handle: false,
            trace_id: true,
            cosign_ready: true,
            traffic_ready: true,
            brain_ready: false,
            broker_ready: true,
            orchestrate_ready: false,
            brain_followed: true,
            broker_followed: false,
            orchestrate_followed: false,
        });
        assert_eq!(ids(&rows), FINGER_IDS);
        assert_eq!(rows[0]["state"], "followed");
        assert_eq!(rows[1]["state"], "absent");
        assert_eq!(rows[2]["state"], "followed");
        assert_eq!(rows[3]["state"], "followed");
        assert_eq!(rows[6]["state"], "supervised");
        assert_eq!(rows[7]["state"], "supervised");
        assert_eq!(rows[8]["state"], "followed");
        assert_eq!(rows[9]["state"], "supervised");
        let quiet = agent_fingers(&AgentFacts {
            operator_sub: false,
            workload_id: false,
            policy_pushed: false,
            runtime_handle: false,
            trace_id: false,
            cosign_ready: false,
            traffic_ready: false,
            brain_ready: false,
            broker_ready: false,
            orchestrate_ready: false,
            brain_followed: false,
            broker_followed: false,
            orchestrate_followed: false,
        });
        assert!(quiet.iter().all(|row| row["state"] == "absent"));
    }
}

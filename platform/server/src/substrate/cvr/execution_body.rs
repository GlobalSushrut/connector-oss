//! ExecutionBody — AgentCell or MicroCell bound to a logical agent (I1).

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use super::host_probe::probe_host;
use super::profile::{
    assert_profile_ready, posture_triad_for, resolve_for_agent, IsolationProfile, ResolvedIsolation,
};
use crate::state::PlatformState;

pub const BODY_FOLDER: &str = "cvr_execution_bodies";
pub const BODY_SCHEMA: &str = "connector.cvr.execution_body.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionBodyKind {
    Logical,
    AgentCell,
    MicroCellShared,
    MicroCellDedicated,
}

impl ExecutionBodyKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Logical => "logical",
            Self::AgentCell => "agentcell",
            Self::MicroCellShared => "microcell_shared",
            Self::MicroCellDedicated => "microcell_dedicated",
        }
    }

    pub fn from_profile(p: IsolationProfile) -> Self {
        match p {
            IsolationProfile::V0 => Self::Logical,
            IsolationProfile::V1 | IsolationProfile::V2 => Self::AgentCell,
            IsolationProfile::V3 => Self::MicroCellShared,
            IsolationProfile::V4 => Self::MicroCellDedicated,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionBody {
    pub schema: String,
    pub agent_pid: String,
    pub execution_id: String,
    pub agentcell_id: Option<String>,
    pub microcell_id: Option<String>,
    pub kind: ExecutionBodyKind,
    pub profile: String,
    pub intent: String,
    pub requested: String,
    pub applied: String,
    pub effective: String,
    pub degraded: bool,
    pub backend: Option<String>,
    pub bound_at_ms: i64,
    pub reason: String,
}

impl ExecutionBody {
    pub fn to_json(&self) -> Value {
        serde_json::to_value(self).unwrap_or(json!({"ok": false}))
    }
}

/// Bind an execution body at agent start. Fails closed when MicroCell required and unavailable.
pub fn bind_on_start(
    state: &PlatformState,
    agent_pid: &str,
) -> Result<ExecutionBody, Value> {
    let resolved = resolve_for_agent(state, agent_pid);
    let probe = probe_host();
    assert_profile_ready(&resolved, &probe)?;

    let triad = posture_triad_for(&resolved, &probe);
    let applied = triad
        .get("applied")
        .and_then(|v| v.as_str())
        .unwrap_or("none");
    let effective = triad
        .get("effective")
        .and_then(|v| v.as_str())
        .unwrap_or("unavailable");
    let degraded = effective == "degraded";

    // If required MicroCell unavailable and not degraded-allowed, assert already erred.
    // Degraded path: fall to AgentCell while labeling.
    let (kind, profile_applied) = if degraded {
        (ExecutionBodyKind::AgentCell, IsolationProfile::V2)
    } else {
        (
            ExecutionBodyKind::from_profile(resolved.profile),
            resolved.profile,
        )
    };

    if kind == ExecutionBodyKind::MicroCellDedicated || kind == ExecutionBodyKind::MicroCellShared {
        if !probe.microcell_ready() {
            return Err(json!({
                "ok": false,
                "status": 503,
                "error": "START_REFUSED",
                "denial_reason": "microcell_not_ready",
                "host_probe": probe.to_json(),
            }));
        }
    }

    let execution_id = format!("ex-{}", Uuid::new_v4().simple());
    let agentcell_id = if matches!(
        kind,
        ExecutionBodyKind::AgentCell
            | ExecutionBodyKind::MicroCellShared
            | ExecutionBodyKind::MicroCellDedicated
    ) {
        Some(format!("ac-{}", &Uuid::new_v4().simple().to_string()[..12]))
    } else {
        None
    };
    // microcell_id assigned by shared pool acquire or dedicated create below.
    let mut microcell_id: Option<String> = None;

    // Real Firecracker MicroCell when profile requires it.
    let mut applied_effective = (applied.to_string(), effective.to_string());
    let mut kind = kind;
    let mut profile_applied = profile_applied;
    let mut degraded = degraded;
    let mut pool_meta: Option<Value> = None;
    let resource = super::resources::resolve_for_agent(state, agent_pid);

    if matches!(
        kind,
        ExecutionBodyKind::MicroCellShared | ExecutionBodyKind::MicroCellDedicated
    ) {
        let bind_result = if kind == ExecutionBodyKind::MicroCellDedicated {
            // E2: always 1:1 — never reuse a shared guest.
            let mc_id = format!("mc-d-{}", &Uuid::new_v4().simple().to_string()[..12]);
            super::backend::FirecrackerBackend
                .create_and_start_with_resources(state, &mc_id, agent_pid, true, resource)
                .map(|v| {
                    microcell_id = Some(mc_id);
                    (v, None)
                })
        } else {
            // E1: shared pool — N AgentCells per guest.
            super::shared_pool::acquire_shared(state, agent_pid, resource).map(|(inst, entry)| {
                microcell_id = Some(inst.microcell_id.clone());
                (
                    json!({
                        "ok": true,
                        "microcell": inst.to_json(),
                        "backend": "firecracker",
                        "applied": true,
                        "shared": true,
                    }),
                    Some(entry.to_json()),
                )
            })
        };

        match bind_result {
            Ok((v, pool)) => {
                pool_meta = pool;
                let _ = v;
                applied_effective = (
                    resolved.profile.as_str().into(),
                    if kind == ExecutionBodyKind::MicroCellShared {
                        "hardened_microcell_shared".into()
                    } else {
                        "hardened_microcell_dedicated".into()
                    },
                );
            }
            Err(e) => {
                if resolved.allow_degraded && !resolved.required {
                    kind = ExecutionBodyKind::AgentCell;
                    profile_applied = IsolationProfile::V2;
                    microcell_id = None;
                    degraded = true;
                    applied_effective = ("V2".into(), "degraded".into());
                    tracing::warn!(
                        agent_pid,
                        error = %e,
                        "MicroCell start failed — degraded to Hardened AgentCell"
                    );
                } else {
                    return Err(e);
                }
            }
        }
    }

    let has_microcell = microcell_id.is_some();
    let mut reason = resolved.reason.clone();
    if let Some(ref p) = pool_meta {
        reason = format!(
            "{reason} · shared_occupants={}",
            p.get("occupants")
                .and_then(|v| v.as_array())
                .map(|a| a.len())
                .unwrap_or(0)
        );
    }
    let body = ExecutionBody {
        schema: BODY_SCHEMA.into(),
        agent_pid: agent_pid.to_string(),
        execution_id,
        agentcell_id,
        microcell_id,
        kind,
        profile: profile_applied.as_str().into(),
        intent: resolved.intent.as_str().into(),
        requested: resolved.profile.as_str().into(),
        applied: applied_effective.0,
        effective: applied_effective.1,
        degraded,
        backend: if has_microcell {
            Some("firecracker".into())
        } else {
            None
        },
        bound_at_ms: chrono::Utc::now().timestamp_millis(),
        reason,
    };

    persist_body(state, &body)?;
    if let Some(ref ac) = body.agentcell_id {
        let _ = super::agent_cell::create_record(state, agent_pid, ac, &body.execution_id);
    }
    Ok(body)
}

pub fn persist_body(state: &PlatformState, body: &ExecutionBody) -> Result<(), Value> {
    let mut es = state.engine_store.lock().map_err(|e| {
        json!({"ok": false, "error": "engine_store_lock", "detail": format!("{e}")})
    })?;
    es.folder_put(BODY_FOLDER, &body.agent_pid, &body.to_json())
        .map_err(|e| json!({"ok": false, "error": "body_persist", "detail": format!("{e}")}))?;
    Ok(())
}

pub fn load_body(state: &PlatformState, agent_pid: &str) -> Option<ExecutionBody> {
    let es = state.engine_store.lock().ok()?;
    let v = es.folder_get(BODY_FOLDER, agent_pid).ok().flatten()?;
    serde_json::from_value(v).ok()
}

pub fn posture_for_agent(state: &PlatformState, agent_pid: &str) -> Value {
    let resolved = resolve_for_agent(state, agent_pid);
    let probe = probe_host();
    let triad = posture_triad_for(&resolved, &probe);
    let body = load_body(state, agent_pid);
    let resource = super::resources::resolve_for_agent(state, agent_pid);
    let dedicated = resolved.profile.requires_dedicated_microcell();
    json!({
        "schema": "connector.cvr.agent_isolation.v1",
        "agent_pid": agent_pid,
        "resolution": resolved.to_json(),
        "posture": triad,
        "resources": resource.to_json(dedicated),
        "auto_policy": super::auto_policy::AutoPolicyTable::load().to_json(),
        "regime": super::regime::get_regime(state, agent_pid).as_str(),
        "auto_revival_forbidden": super::regime::get_regime(state, agent_pid).blocks_auto_revival(),
        "execution_body": body.as_ref().map(|b| b.to_json()),
        "host_probe": probe.to_json(),
        "promote": "POST /agents/:pid/isolation/promote",
    })
}

/// Gate used by harden start — MicroCell profiles must be ready.
pub fn assert_cvr_ready_for_start(
    state: &PlatformState,
    agent_pid: &str,
) -> Result<ResolvedIsolation, Value> {
    let resolved = resolve_for_agent(state, agent_pid);
    let probe = probe_host();
    assert_profile_ready(&resolved, &probe)?;
    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_from_v4() {
        assert_eq!(
            ExecutionBodyKind::from_profile(IsolationProfile::V4),
            ExecutionBodyKind::MicroCellDedicated
        );
    }
}

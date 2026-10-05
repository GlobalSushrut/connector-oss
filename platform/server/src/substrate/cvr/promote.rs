//! Promote AgentCell → MicroCell without minting a new `agent_pid` (Phase F1).
//!
//! Identity, DIM, mission, and grants persist. Only the execution body changes.

use serde_json::{json, Value};
use uuid::Uuid;

use super::execution_body::{
    load_body, persist_body, ExecutionBody, ExecutionBodyKind, BODY_SCHEMA,
};
use super::host_probe::probe_host;
use super::profile::{assert_profile_ready, IsolationIntent, IsolationProfile, resolve_for_agent};
use super::regime::{assert_may_auto_start, get_regime};
use super::resources;
use crate::state::PlatformState;

/// Target MicroCell density for promotion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromoteTarget {
    Shared,
    Dedicated,
}

impl PromoteTarget {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().replace('_', "-").as_str() {
            "shared" | "shared-microvm" | "v3" | "microcell_shared" => Some(Self::Shared),
            "dedicated" | "dedicated-microvm" | "v4" | "microcell_dedicated" => {
                Some(Self::Dedicated)
            }
            _ => None,
        }
    }

    pub fn profile(self) -> IsolationProfile {
        match self {
            Self::Shared => IsolationProfile::V3,
            Self::Dedicated => IsolationProfile::V4,
        }
    }

    pub fn kind(self) -> ExecutionBodyKind {
        match self {
            Self::Shared => ExecutionBodyKind::MicroCellShared,
            Self::Dedicated => ExecutionBodyKind::MicroCellDedicated,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Shared => "shared",
            Self::Dedicated => "dedicated",
        }
    }
}

/// Promote existing AgentCell body to MicroCell. Same `agent_pid`.
pub fn promote_to_microcell(
    state: &PlatformState,
    agent_pid: &str,
    target: PromoteTarget,
) -> Result<Value, Value> {
    assert_may_auto_start(state, agent_pid)?;

    let regime = get_regime(state, agent_pid);
    if regime.blocks_effect() && !matches!(regime, super::regime::OsRegime::Paused) {
        return Err(json!({
            "ok": false,
            "error": "PROMOTE_REFUSED",
            "denial_reason": "regime_blocks_promote",
            "regime": regime.as_str(),
        }));
    }

    let probe = probe_host();
    let mut resolved = resolve_for_agent(state, agent_pid);
    // Force target profile for readiness check.
    resolved.profile = target.profile();
    resolved.body_kind = match target {
        PromoteTarget::Shared => "microcell_shared",
        PromoteTarget::Dedicated => "microcell_dedicated",
    };
    resolved.intent = match target {
        PromoteTarget::Shared => IsolationIntent::SharedMicrovm,
        PromoteTarget::Dedicated => IsolationIntent::DedicatedMicrovm,
    };
    resolved.reason = format!("promote → {} MicroCell (same agent_pid)", target.as_str());
    assert_profile_ready(&resolved, &probe)?;

    let prior = load_body(state, agent_pid);
    if let Some(ref b) = prior {
        if matches!(
            b.kind,
            ExecutionBodyKind::MicroCellShared | ExecutionBodyKind::MicroCellDedicated
        ) {
            // Already on MicroCell — allow shared→dedicated upgrade only.
            if b.kind == ExecutionBodyKind::MicroCellDedicated
                || (b.kind == ExecutionBodyKind::MicroCellShared && target == PromoteTarget::Shared)
            {
                return Ok(json!({
                    "ok": true,
                    "promoted": false,
                    "reason": "already_microcell",
                    "execution_body": b.to_json(),
                    "agent_pid": agent_pid,
                }));
            }
        }
    }

    let resource = resources::resolve_for_agent(state, agent_pid);
    let (microcell_id, pool_meta) = if target == PromoteTarget::Dedicated {
        let mc_id = format!("mc-d-{}", &Uuid::new_v4().simple().to_string()[..12]);
        super::backend::FirecrackerBackend.create_and_start_with_resources(
            state, &mc_id, agent_pid, true, resource,
        )?;
        (mc_id, None)
    } else {
        let (inst, entry) = super::shared_pool::acquire_shared(state, agent_pid, resource)?;
        (inst.microcell_id, Some(entry.to_json()))
    };

    let now = chrono::Utc::now().timestamp_millis();
    let agentcell_id = prior
        .as_ref()
        .and_then(|b| b.agentcell_id.clone())
        .unwrap_or_else(|| format!("ac-{}", &Uuid::new_v4().simple().to_string()[..12]));
    let execution_id = prior
        .as_ref()
        .map(|b| b.execution_id.clone())
        .unwrap_or_else(|| format!("ex-{}", Uuid::new_v4().simple()));

    // Ensure AgentCell record exists (density path inside guest).
    let _ = super::agent_cell::create_record(state, agent_pid, &agentcell_id, &execution_id);

    let body = ExecutionBody {
        schema: BODY_SCHEMA.into(),
        agent_pid: agent_pid.to_string(),
        execution_id,
        agentcell_id: Some(agentcell_id),
        microcell_id: Some(microcell_id.clone()),
        kind: target.kind(),
        profile: target.profile().as_str().into(),
        intent: resolved.intent.as_str().into(),
        requested: target.profile().as_str().into(),
        applied: target.profile().as_str().into(),
        effective: if target == PromoteTarget::Shared {
            "hardened_microcell_shared".into()
        } else {
            "hardened_microcell_dedicated".into()
        },
        degraded: false,
        backend: Some("firecracker".into()),
        bound_at_ms: now,
        reason: resolved.reason.clone(),
    };
    persist_body(state, &body)?;

    // Stamp agent_meta isolation intent — identity unchanged.
    if let Ok(mut es) = state.engine_store.lock() {
        if let Ok(Some(mut meta)) = es.folder_get("agent_meta", agent_pid) {
            if let Some(obj) = meta.as_object_mut() {
                obj.insert(
                    "isolation".into(),
                    json!(match target {
                        PromoteTarget::Shared => "shared-microvm",
                        PromoteTarget::Dedicated => "dedicated-microvm",
                    }),
                );
                obj.insert("promoted_to_microcell_at_ms".into(), json!(now));
                obj.insert("promoted_microcell_id".into(), json!(microcell_id));
            }
            let _ = es.folder_put("agent_meta", agent_pid, &meta);
        }
    }

    Ok(json!({
        "ok": true,
        "promoted": true,
        "agent_pid": agent_pid,
        "target": target.as_str(),
        "prior_kind": prior.as_ref().map(|b| b.kind.as_str()),
        "execution_body": body.to_json(),
        "shared_pool": pool_meta,
        "persisted": {
            "identity": true,
            "dim": true,
            "mission": true,
            "grants": true,
            "honesty": "Same agent_pid — promotion changes execution body only",
        },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_targets() {
        assert_eq!(PromoteTarget::parse("v4"), Some(PromoteTarget::Dedicated));
        assert_eq!(PromoteTarget::parse("shared-microvm"), Some(PromoteTarget::Shared));
    }
}

//! Agent Reaper — background task that enforces lifecycle invariants.
//!
//! Analogous to Linux `init`'s role of reaping orphaned/zombie processes.
//!
//! Responsibilities:
//! 1. Reap zombies: remove `Terminated | Completed | Failed` older than grace period.
//! 2. Enforce cap: if `agents > cap`, suspend oldest idle, then terminate oldest suspended **with progeny**.
//! 3. Heartbeat eviction: `Running` with stale `last_active_at` → downgrade.
//!
//! OPS-09: force-termination uses `terminate_with_progeny` — never `remove_agent` alone
//! for live agents under cap pressure (orphaned `agent_lifecycle::AgentRegistry` is not consulted).

use std::sync::Arc;
use std::time::Duration;
use tokio::time::interval;
use vac_core::types::AgentStatus;

use crate::state::PlatformState;

/// Grace period (seconds) before a zombie agent is reaped.
const ZOMBIE_GRACE_SECS: i64 = 300; // 5 minutes
/// How often the reaper runs.
const REAPER_INTERVAL_SECS: u64 = 30;
/// Max age (seconds) for a Running agent without activity before demotion.
const IDLE_DEMOTION_SECS: i64 = 1800; // 30 minutes

pub fn spawn(state: Arc<PlatformState>) {
    let interval_secs = std::env::var("CONNECTOR_REAPER_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(REAPER_INTERVAL_SECS);

    tokio::spawn(async move {
        let mut tick = interval(Duration::from_secs(interval_secs));
        tracing::info!(interval_secs, "AgentReaper started");
        loop {
            tick.tick().await;
            run_one_pass(&state);
        }
    });
}

fn run_one_pass(state: &Arc<PlatformState>) {
    let now_ms = chrono::Utc::now().timestamp_millis();
    let cap = crate::services::agents::resolved_kernel_agent_cap(state);

    let mut reaped = 0usize;
    let mut demoted = 0usize;
    let mut suspended_for_cap = 0usize;
    let mut force_terminated = 0usize;

    // ── Phase 1: Zombie reaping ──
    let zombies: Vec<String> = {
        let k = match state.kernel.lock() {
            Ok(k) => k,
            Err(_) => return,
        };
        k.agents()
            .iter()
            .filter(|(_, acb)| {
                matches!(
                    acb.status,
                    AgentStatus::Terminated | AgentStatus::Completed | AgentStatus::Failed
                )
            })
            .filter(|(_, acb)| now_ms.saturating_sub(acb.last_active_at) > ZOMBIE_GRACE_SECS * 1000)
            .map(|(pid, _)| pid.clone())
            .collect()
    };

    if !zombies.is_empty() {
        if let Ok(mut k) = state.kernel.lock() {
            for pid in &zombies {
                k.remove_agent(pid);
                reaped += 1;
            }
        }
    }

    // ── Phase 2: Heartbeat-based idle demotion ──
    let stale_running: Vec<String> = {
        let k = match state.kernel.lock() {
            Ok(k) => k,
            Err(_) => return,
        };
        k.agents()
            .iter()
            .filter(|(_, acb)| matches!(acb.status, AgentStatus::Running))
            .filter(|(_, acb)| {
                now_ms.saturating_sub(acb.last_active_at) > IDLE_DEMOTION_SECS * 1000
            })
            .map(|(pid, _)| pid.clone())
            .collect()
    };

    if !stale_running.is_empty() {
        for pid in &stale_running {
            let _ = crate::substrate::agent_lifecycle_gate::dispatch_system_lifecycle(
                state,
                pid,
                crate::services::intelligence_authority::LifecycleOp::Pause,
                "reaper",
                "idle demotion",
            );
            demoted += 1;
        }
    }

    // ── Phase 3: Cap pressure relief ──
    let over_cap = {
        let k = match state.kernel.lock() {
            Ok(k) => k,
            Err(_) => return,
        };
        (k.agents().len() as u32).saturating_sub(cap) as usize
    };

    if over_cap > 0 {
        // Suspend oldest Running agents (by last_active_at ascending)
        {
            let running: Vec<(String, i64)> = {
                let k = match state.kernel.lock() {
                    Ok(k) => k,
                    Err(_) => return,
                };
                let mut running: Vec<(String, i64)> = k
                    .agents()
                    .iter()
                    .filter(|(_, a)| matches!(a.status, AgentStatus::Running | AgentStatus::Waiting))
                    .map(|(p, a)| (p.clone(), a.last_active_at))
                    .collect();
                running.sort_by_key(|(_, ts)| *ts);
                running
            };

            for (pid, _) in running.iter().take(over_cap) {
                let _ = crate::substrate::agent_lifecycle_gate::dispatch_system_lifecycle(
                    state,
                    pid,
                    crate::services::intelligence_authority::LifecycleOp::Pause,
                    "reaper",
                    "cap pressure suspend",
                );
                suspended_for_cap += 1;
            }
        }

        // Still over cap? Terminate oldest suspended **with progeny** (OPS-09).
        let still_over = {
            let k = match state.kernel.lock() {
                Ok(k) => k,
                Err(_) => return,
            };
            (k.agents().len() as u32).saturating_sub(cap) as usize
        };
        if still_over > 0 {
            let to_remove: Vec<String> = {
                let k = match state.kernel.lock() {
                    Ok(k) => k,
                    Err(_) => return,
                };
                let mut suspended: Vec<(String, i64)> = k
                    .agents()
                    .iter()
                    .filter(|(_, a)| matches!(a.status, AgentStatus::Suspended))
                    .map(|(p, a)| (p.clone(), a.last_active_at))
                    .collect();
                suspended.sort_by_key(|(_, ts)| *ts);
                suspended
                    .iter()
                    .take(still_over)
                    .map(|(p, _)| p.clone())
                    .collect()
            };
            for pid in &to_remove {
                let killed = crate::substrate::agent_progeny::terminate_with_progeny(
                    state,
                    pid,
                    "reaper_cap_pressure",
                );
                force_terminated += killed.len().max(1);
            }
        }
    }

    if reaped + demoted + suspended_for_cap + force_terminated > 0 {
        tracing::info!(
            reaped,
            demoted,
            suspended_for_cap,
            force_terminated,
            cap,
            "AgentReaper pass complete (progeny-aware)"
        );
    }
}

//! Mission trajectory budgets — cumulative blast / commitments / effects.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::state::PlatformState;

pub const TRAJECTORY_SCHEMA: &str = "connector.trajectory_budget.v1";
pub const TRAJECTORY_FOLDER: &str = "mission_trajectory_budgets";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrajectoryBudget {
    pub schema: String,
    pub mission_id: String,
    pub agent_pid: String,
    pub effect_count: u32,
    pub max_effects: u32,
    pub cumulative_value: f64,
    pub blast_radius: f32,
    pub commitments: u32,
    pub max_commitments: u32,
    pub delegation_depth: u32,
    pub max_delegation_depth: u32,
    pub data_exposure_bytes: u64,
    pub max_data_exposure_bytes: u64,
    pub exhausted: bool,
}

impl TrajectoryBudget {
    pub fn fresh(mission_id: &str, agent_pid: &str) -> Self {
        Self {
            schema: TRAJECTORY_SCHEMA.into(),
            mission_id: mission_id.into(),
            agent_pid: agent_pid.into(),
            effect_count: 0,
            max_effects: 64,
            cumulative_value: 0.0,
            blast_radius: 0.0,
            commitments: 0,
            max_commitments: 8,
            delegation_depth: 0,
            max_delegation_depth: 3,
            data_exposure_bytes: 0,
            max_data_exposure_bytes: 8 * 1024 * 1024,
            exhausted: false,
        }
    }

    /// Narrow ceilings from an authoring [`BudgetSpec`] (never widens).
    pub fn apply_budget_spec(&mut self, budget: &connector_native_contract::BudgetSpec) {
        if let Some(calls) = budget.max_calls {
            let c = calls.min(u64::from(u32::MAX)) as u32;
            self.max_effects = self.max_effects.min(c.max(1));
        }
        if let Some(bytes) = budget.max_bytes {
            self.max_data_exposure_bytes = self.max_data_exposure_bytes.min(bytes.max(1));
        }
        // max_hops is enforced on the proxy plane; record as commitment-like soft cap.
        if let Some(hops) = budget.max_hops {
            self.max_commitments = self.max_commitments.min(hops.max(1));
        }
        self.exhausted = self.effect_count >= self.max_effects
            || self.commitments >= self.max_commitments
            || self.delegation_depth > self.max_delegation_depth
            || self.data_exposure_bytes > self.max_data_exposure_bytes;
    }

    pub fn record_effect(&mut self, blast: f32, value: f64, bytes: u64, commits: bool) {
        self.effect_count = self.effect_count.saturating_add(1);
        self.blast_radius = self.blast_radius.max(blast);
        self.cumulative_value += value;
        self.data_exposure_bytes = self.data_exposure_bytes.saturating_add(bytes);
        if commits {
            self.commitments = self.commitments.saturating_add(1);
        }
        self.exhausted = self.effect_count >= self.max_effects
            || self.commitments >= self.max_commitments
            || self.delegation_depth > self.max_delegation_depth
            || self.data_exposure_bytes > self.max_data_exposure_bytes;
    }

    pub fn bump_delegation(&mut self) {
        self.delegation_depth = self.delegation_depth.saturating_add(1);
        if self.delegation_depth > self.max_delegation_depth {
            self.exhausted = true;
        }
    }
}

pub fn load_or_create(state: &PlatformState, mission_id: &str, agent_pid: &str) -> TrajectoryBudget {
    if let Ok(es) = state.engine_store.lock() {
        if let Ok(Some(v)) = es.folder_get(TRAJECTORY_FOLDER, mission_id) {
            if let Ok(b) = serde_json::from_value::<TrajectoryBudget>(v) {
                return b;
            }
        }
    }
    TrajectoryBudget::fresh(mission_id, agent_pid)
}

pub fn save(state: &PlatformState, budget: &TrajectoryBudget) {
    if let Ok(mut es) = state.engine_store.lock() {
        let _ = es.folder_put(
            TRAJECTORY_FOLDER,
            &budget.mission_id,
            &serde_json::to_value(budget).unwrap_or(Value::Null),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use connector_native_contract::BudgetSpec;

    #[test]
    fn apply_budget_spec_never_widens() {
        let mut tb = TrajectoryBudget::fresh("m1", "a1");
        assert_eq!(tb.max_effects, 64);
        let mut b = BudgetSpec::new("b");
        b.max_calls = Some(4);
        b.max_bytes = Some(100);
        b.max_hops = Some(2);
        tb.apply_budget_spec(&b);
        assert_eq!(tb.max_effects, 4);
        assert_eq!(tb.max_data_exposure_bytes, 100);
        assert_eq!(tb.max_commitments, 2);
        // Second apply with higher caps must not widen.
        let mut b2 = BudgetSpec::new("b2");
        b2.max_calls = Some(100);
        tb.apply_budget_spec(&b2);
        assert_eq!(tb.max_effects, 4);
    }
}

pub fn to_json(b: &TrajectoryBudget) -> Value {
    serde_json::to_value(b).unwrap_or(json!({ "ok": false }))
}

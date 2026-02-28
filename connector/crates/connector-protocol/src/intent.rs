//! Intent Layer (Layer 7) — Goal decomposition, coordination patterns.
//!
//! AI agents express goals which are decomposed into capability requests.

use serde::{Deserialize, Serialize};

use crate::identity::EntityId;

// ── Coordination Pattern ────────────────────────────────────────────

/// How multiple actions are coordinated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoordinationPattern {
    /// A → B → C (pipeline)
    Sequential,
    /// A + B + C (fan-out, barrier wait)
    Parallel,
    /// if condition then A else B
    Conditional,
    /// on event(X) → do Y
    Reactive,
    /// majority(validators) agree before execution
    Consensus,
}

// ── Capability Request ──────────────────────────────────────────────

/// A single decomposed capability request from an intent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityRequest {
    pub capability_id: String,
    pub target_entity: Option<EntityId>,
    pub params: serde_json::Value,
    pub priority: u8,
    pub timeout_ms: u64,
    pub depends_on: Vec<usize>,
}

// ── Intent ──────────────────────────────────────────────────────────

/// A high-level goal expressed by an agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Intent {
    pub intent_id: String,
    pub agent: EntityId,
    pub goal: String,
    pub coordination: CoordinationPattern,
    pub steps: Vec<CapabilityRequest>,
    pub created_at: i64,
}

impl Intent {
    /// Create a new intent.
    pub fn new(agent: EntityId, goal: &str, coordination: CoordinationPattern) -> Self {
        Self {
            intent_id: uuid::Uuid::new_v4().to_string(),
            agent,
            goal: goal.to_string(),
            coordination,
            steps: Vec::new(),
            created_at: chrono::Utc::now().timestamp_millis(),
        }
    }

    /// Add a step to the intent.
    pub fn add_step(&mut self, step: CapabilityRequest) {
        self.steps.push(step);
    }

    /// Number of steps.
    pub fn step_count(&self) -> usize {
        self.steps.len()
    }

    /// Get execution order based on coordination pattern.
    pub fn execution_order(&self) -> Vec<Vec<usize>> {
        match self.coordination {
            CoordinationPattern::Sequential => {
                self.steps.iter().enumerate().map(|(i, _)| vec![i]).collect()
            }
            CoordinationPattern::Parallel => {
                if self.steps.is_empty() {
                    vec![]
                } else {
                    vec![self.steps.iter().enumerate().map(|(i, _)| i).collect()]
                }
            }
            CoordinationPattern::Conditional | CoordinationPattern::Reactive | CoordinationPattern::Consensus => {
                // Dependencies determine order
                let mut waves: Vec<Vec<usize>> = Vec::new();
                let mut scheduled = vec![false; self.steps.len()];
                loop {
                    let mut wave = Vec::new();
                    for (i, step) in self.steps.iter().enumerate() {
                        if scheduled[i] { continue; }
                        if step.depends_on.iter().all(|&d| d < self.steps.len() && scheduled[d]) {
                            wave.push(i);
                        }
                    }
                    if wave.is_empty() { break; }
                    for &i in &wave { scheduled[i] = true; }
                    waves.push(wave);
                }
                waves
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::EntityClass;

    fn aid(n: &str) -> EntityId { EntityId::new(EntityClass::Agent, n) }

    fn step(cap: &str, deps: Vec<usize>) -> CapabilityRequest {
        CapabilityRequest {
            capability_id: cap.to_string(),
            target_entity: None,
            params: serde_json::json!({}),
            priority: 2,
            timeout_ms: 5000,
            depends_on: deps,
        }
    }

    #[test]
    fn test_intent_creation() {
        let intent = Intent::new(aid("planner"), "mill bracket", CoordinationPattern::Sequential);
        assert_eq!(intent.goal, "mill bracket");
        assert_eq!(intent.step_count(), 0);
    }

    #[test]
    fn test_sequential_decomposition() {
        let mut intent = Intent::new(aid("p"), "task", CoordinationPattern::Sequential);
        intent.add_step(step("machine.tool_change", vec![]));
        intent.add_step(step("machine.spindle_on", vec![]));
        intent.add_step(step("machine.move_axis", vec![]));

        let order = intent.execution_order();
        assert_eq!(order.len(), 3);
        assert_eq!(order[0], vec![0]);
        assert_eq!(order[1], vec![1]);
        assert_eq!(order[2], vec![2]);
    }

    #[test]
    fn test_parallel_decomposition() {
        let mut intent = Intent::new(aid("p"), "task", CoordinationPattern::Parallel);
        intent.add_step(step("sensor.read", vec![]));
        intent.add_step(step("sensor.read", vec![]));
        intent.add_step(step("sensor.read", vec![]));

        let order = intent.execution_order();
        assert_eq!(order.len(), 1);
        assert_eq!(order[0], vec![0, 1, 2]);
    }

    #[test]
    fn test_dependency_based_decomposition() {
        let mut intent = Intent::new(aid("p"), "task", CoordinationPattern::Conditional);
        intent.add_step(step("sensor.read", vec![]));         // 0: no deps
        intent.add_step(step("actuator.move", vec![0]));      // 1: depends on 0
        intent.add_step(step("sensor.read", vec![]));         // 2: no deps
        intent.add_step(step("actuator.stop", vec![1, 2]));   // 3: depends on 1,2

        let order = intent.execution_order();
        assert_eq!(order.len(), 3);
        assert!(order[0].contains(&0) && order[0].contains(&2)); // wave 0: {0,2}
        assert_eq!(order[1], vec![1]);                            // wave 1: {1}
        assert_eq!(order[2], vec![3]);                            // wave 2: {3}
    }

    #[test]
    fn test_intent_serde() {
        let mut intent = Intent::new(aid("p"), "goal", CoordinationPattern::Reactive);
        intent.add_step(step("safety.emergency_stop", vec![]));
        let json = serde_json::to_string(&intent).unwrap();
        let parsed: Intent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.goal, "goal");
        assert_eq!(parsed.step_count(), 1);
    }
}

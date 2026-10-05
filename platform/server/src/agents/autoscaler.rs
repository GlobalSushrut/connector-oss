//! Agent Auto-Scaler — Elastic Scaling with Warm Pool
//! FIX BUG-072

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScalingPolicy {
    pub policy_id: String,
    pub agent_type: String,
    pub min_instances: u32,
    pub max_instances: u32,
    pub scale_up_threshold: f32,
    pub scale_down_threshold: f32,
    pub warm_pool_size: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScalingAction { ScaleUp, ScaleDown, Maintain }

pub struct AutoScaler {
    policies: Arc<RwLock<HashMap<String, ScalingPolicy>>>,
    warm_pool: VecDeque<String>,
    instance_counts: Arc<RwLock<HashMap<String, u32>>>,
    last_scale: Arc<RwLock<HashMap<String, i64>>>,
}

impl AutoScaler {
    pub fn new() -> Self {
        Self {
            policies: Arc::new(RwLock::new(HashMap::new())),
            warm_pool: VecDeque::new(),
            instance_counts: Arc::new(RwLock::new(HashMap::new())),
            last_scale: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn register_policy(&self, policy: ScalingPolicy) {
        self.policies.write().unwrap().insert(policy.policy_id.clone(), policy);
    }

    pub fn evaluate(&self, policy_id: &str, current_load: f32) -> (ScalingAction, u32) {
        let policy = match self.policies.read().unwrap().get(policy_id).cloned() {
            Some(p) => p,
            None => return (ScalingAction::Maintain, 0),
        };
        let current = *self.instance_counts.read().unwrap().get(&policy.agent_type).unwrap_or(&policy.min_instances);

        if current_load > policy.scale_up_threshold && current < policy.max_instances {
            (ScalingAction::ScaleUp, (current + 1).min(policy.max_instances))
        } else if current_load < policy.scale_down_threshold && current > policy.min_instances {
            (ScalingAction::ScaleDown, (current - 1).max(policy.min_instances))
        } else {
            (ScalingAction::Maintain, current)
        }
    }

    pub fn prewarm(&mut self, agent_type: &str, count: u32) {
        for _ in 0..count {
            self.warm_pool.push_back(format!("warm-{}", uuid::Uuid::new_v4()));
        }
        println!("[AUTO-SCALER] Pre-warmed {} {} agents", count, agent_type);
    }

    pub fn acquire_warm(&mut self) -> Option<String> {
        self.warm_pool.pop_front()
    }
}

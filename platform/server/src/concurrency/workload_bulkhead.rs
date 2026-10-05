//! Workload bulkheads — separate concurrency limits per plane.
//!
//! Talk must not starve /health by sharing one unbounded spawn_blocking pool
//! with Control mutations and Effect Admit work.

use std::sync::Arc;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
        .max(1)
}

pub struct WorkloadBulkheads {
    pub talk: Arc<Semaphore>,
    pub effect: Arc<Semaphore>,
    pub control: Arc<Semaphore>,
    talk_cap: usize,
    effect_cap: usize,
    control_cap: usize,
}

impl Default for WorkloadBulkheads {
    fn default() -> Self {
        Self::from_env()
    }
}

impl WorkloadBulkheads {
    pub fn from_env() -> Self {
        let talk_cap = env_usize("CONNECTOR_BULKHEAD_TALK", 8);
        let effect_cap = env_usize("CONNECTOR_BULKHEAD_EFFECT", 4);
        let control_cap = env_usize("CONNECTOR_BULKHEAD_CONTROL", 2);
        Self {
            talk: Arc::new(Semaphore::new(talk_cap)),
            effect: Arc::new(Semaphore::new(effect_cap)),
            control: Arc::new(Semaphore::new(control_cap)),
            talk_cap,
            effect_cap,
            control_cap,
        }
    }

    pub async fn acquire_talk(&self) -> Result<OwnedSemaphorePermit, String> {
        self.talk
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| "talk_bulkhead_closed".to_string())
    }

    pub fn try_acquire_talk(&self) -> Result<OwnedSemaphorePermit, String> {
        self.talk.clone().try_acquire_owned().map_err(|_| {
            format!(
                "talk_bulkhead_full: cap={} — retry or shed load",
                self.talk_cap
            )
        })
    }

    pub async fn acquire_effect(&self) -> Result<OwnedSemaphorePermit, String> {
        self.effect
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| "effect_bulkhead_closed".to_string())
    }

    pub fn try_acquire_effect(&self) -> Result<OwnedSemaphorePermit, String> {
        self.effect.clone().try_acquire_owned().map_err(|_| {
            format!(
                "effect_bulkhead_full: cap={} — retry Admit later",
                self.effect_cap
            )
        })
    }

    pub fn status_json(&self) -> serde_json::Value {
        serde_json::json!({
            "talk_cap": self.talk_cap,
            "talk_available": self.talk.available_permits(),
            "effect_cap": self.effect_cap,
            "effect_available": self.effect.available_permits(),
            "control_cap": self.control_cap,
            "control_available": self.control.available_permits(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn talk_bulkhead_limits() {
        std::env::set_var("CONNECTOR_BULKHEAD_TALK", "1");
        let b = WorkloadBulkheads::from_env();
        let _p = b.try_acquire_talk().expect("first");
        assert!(b.try_acquire_talk().is_err());
        std::env::remove_var("CONNECTOR_BULKHEAD_TALK");
    }
}

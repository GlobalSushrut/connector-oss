//! Orchestrator — DAG-based agent pipeline execution with auto-restart.
//!
//! The systemd equivalent for agents: resolves dependency graphs,
//! executes in topological order, handles failures with backoff and retry.
//!
//! Research: systemd unit dependencies, Airflow DAG scheduler,
//! Kubernetes pod lifecycle, Temporal workflow engine

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};

// ═══════════════════════════════════════════════════════════════
// Task Definition
// ═══════════════════════════════════════════════════════════════

/// State of an orchestrated task.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaskState {
    Pending,
    Ready,
    Running,
    Completed,
    Failed,
    Retrying,
    Skipped,
}

/// A single task in the orchestration DAG.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrchestratorTask {
    pub task_id: String,
    pub agent_pid: String,
    pub capability_key: String,
    pub depends_on: Vec<String>,
    pub state: TaskState,
    pub max_retries: u32,
    pub retry_count: u32,
    pub backoff_base_ms: u64,
    pub started_at: Option<i64>,
    pub completed_at: Option<i64>,
    pub error: Option<String>,
    pub result: Option<String>,
}

impl OrchestratorTask {
    pub fn new(task_id: &str, agent_pid: &str, capability_key: &str) -> Self {
        Self {
            task_id: task_id.to_string(),
            agent_pid: agent_pid.to_string(),
            capability_key: capability_key.to_string(),
            depends_on: Vec::new(),
            state: TaskState::Pending,
            max_retries: 3,
            retry_count: 0,
            backoff_base_ms: 1000,
            started_at: None,
            completed_at: None,
            error: None,
            result: None,
        }
    }

    pub fn with_dependency(mut self, dep: &str) -> Self {
        self.depends_on.push(dep.to_string());
        self
    }

    pub fn with_retries(mut self, max: u32, backoff_ms: u64) -> Self {
        self.max_retries = max;
        self.backoff_base_ms = backoff_ms;
        self
    }

    /// Compute next retry delay with exponential backoff.
    pub fn next_retry_delay_ms(&self) -> u64 {
        let shift = (self.retry_count as u32).min(10);
        self.backoff_base_ms.saturating_mul(1u64.checked_shl(shift).unwrap_or(u64::MAX))
    }

    pub fn can_retry(&self) -> bool {
        self.retry_count < self.max_retries
    }
}

// ═══════════════════════════════════════════════════════════════
// Execution Plan
// ═══════════════════════════════════════════════════════════════

/// An execution wave — tasks that can run in parallel.
#[derive(Debug, Clone)]
pub struct ExecutionWave {
    pub wave_index: usize,
    pub task_ids: Vec<String>,
}

// ═══════════════════════════════════════════════════════════════
// Orchestrator
// ═══════════════════════════════════════════════════════════════

/// DAG-based orchestrator for multi-agent pipelines.
pub struct Orchestrator {
    tasks: HashMap<String, OrchestratorTask>,
    insertion_order: Vec<String>,
}

impl Orchestrator {
    pub fn new() -> Self {
        Self {
            tasks: HashMap::new(),
            insertion_order: Vec::new(),
        }
    }

    /// Add a task to the orchestration DAG.
    pub fn add_task(&mut self, task: OrchestratorTask) -> Result<(), String> {
        if self.tasks.contains_key(&task.task_id) {
            return Err(format!("Task {} already exists", task.task_id));
        }
        // Validate dependencies exist
        for dep in &task.depends_on {
            if !self.tasks.contains_key(dep) {
                return Err(format!("Dependency {} not found for task {}", dep, task.task_id));
            }
        }
        let id = task.task_id.clone();
        self.tasks.insert(id.clone(), task);
        self.insertion_order.push(id);
        Ok(())
    }

    /// Compute execution waves via topological sort (Kahn's algorithm).
    pub fn compute_waves(&self) -> Result<Vec<ExecutionWave>, String> {
        let mut in_degree: HashMap<&str, usize> = HashMap::new();
        let mut dependents: HashMap<&str, Vec<&str>> = HashMap::new();

        for (id, task) in &self.tasks {
            in_degree.entry(id.as_str()).or_insert(0);
            for dep in &task.depends_on {
                *in_degree.entry(id.as_str()).or_insert(0) += 1;
                dependents.entry(dep.as_str()).or_default().push(id.as_str());
            }
        }

        let mut waves = Vec::new();
        let mut queue: VecDeque<&str> = in_degree.iter()
            .filter(|(_, &deg)| deg == 0)
            .map(|(&id, _)| id)
            .collect();

        // Sort queue for deterministic ordering
        let mut sorted: Vec<&str> = queue.drain(..).collect();
        sorted.sort();
        queue.extend(sorted);

        let mut processed = 0;

        while !queue.is_empty() {
            let wave_tasks: Vec<String> = queue.drain(..).map(|s| s.to_string()).collect();
            processed += wave_tasks.len();

            // Find next wave
            let mut next: Vec<&str> = Vec::new();
            for task_id in &wave_tasks {
                if let Some(deps) = dependents.get(task_id.as_str()) {
                    for dep in deps {
                        let deg = in_degree.get_mut(dep).unwrap();
                        *deg -= 1;
                        if *deg == 0 {
                            next.push(dep);
                        }
                    }
                }
            }
            next.sort();
            next.dedup();

            waves.push(ExecutionWave {
                wave_index: waves.len(),
                task_ids: wave_tasks,
            });

            queue.extend(next);
        }

        if processed != self.tasks.len() {
            return Err("Cycle detected in task dependencies".into());
        }

        Ok(waves)
    }

    /// Mark a task as started.
    pub fn start_task(&mut self, task_id: &str, now_ms: i64) -> Result<(), String> {
        // Check all dependencies are completed (immutable borrow first)
        let deps: Vec<String> = self.tasks.get(task_id)
            .ok_or_else(|| format!("Task {} not found", task_id))?
            .depends_on.clone();
        for dep in &deps {
            let dep_task = self.tasks.get(dep)
                .ok_or_else(|| format!("Dependency {} not found", dep))?;
            if dep_task.state != TaskState::Completed {
                return Err(format!("Dependency {} is {:?}, not Completed", dep, dep_task.state));
            }
        }
        // Now mutate
        let task = self.tasks.get_mut(task_id).unwrap();
        task.state = TaskState::Running;
        task.started_at = Some(now_ms);
        Ok(())
    }

    /// Mark a task as completed.
    pub fn complete_task(&mut self, task_id: &str, result: &str, now_ms: i64) -> Result<(), String> {
        let task = self.tasks.get_mut(task_id)
            .ok_or_else(|| format!("Task {} not found", task_id))?;
        if task.state != TaskState::Running && task.state != TaskState::Retrying {
            return Err(format!("Task {} is {:?}, not Running/Retrying", task_id, task.state));
        }
        task.state = TaskState::Completed;
        task.completed_at = Some(now_ms);
        task.result = Some(result.to_string());
        Ok(())
    }

    /// Mark a task as failed. Returns true if it can be retried.
    pub fn fail_task(&mut self, task_id: &str, error: &str, now_ms: i64) -> Result<bool, String> {
        let task = self.tasks.get_mut(task_id)
            .ok_or_else(|| format!("Task {} not found", task_id))?;
        task.error = Some(error.to_string());
        if task.can_retry() {
            task.retry_count += 1;
            task.state = TaskState::Retrying;
            Ok(true)
        } else {
            task.state = TaskState::Failed;
            task.completed_at = Some(now_ms);
            Ok(false)
        }
    }

    /// Skip downstream tasks when an upstream task fails permanently.
    pub fn skip_dependents(&mut self, failed_task_id: &str) -> Vec<String> {
        let mut to_skip: Vec<String> = Vec::new();
        let mut queue: VecDeque<String> = VecDeque::new();
        queue.push_back(failed_task_id.to_string());

        while let Some(tid) = queue.pop_front() {
            // Find all tasks that depend on tid
            for (id, task) in &self.tasks {
                if task.depends_on.contains(&tid) && task.state == TaskState::Pending {
                    to_skip.push(id.clone());
                    queue.push_back(id.clone());
                }
            }
        }

        for id in &to_skip {
            if let Some(task) = self.tasks.get_mut(id) {
                task.state = TaskState::Skipped;
                task.error = Some(format!("Skipped: upstream {} failed", failed_task_id));
            }
        }
        to_skip
    }

    /// Get tasks ready to run (all deps completed, state = Pending).
    pub fn ready_tasks(&self) -> Vec<&OrchestratorTask> {
        self.tasks.values().filter(|t| {
            t.state == TaskState::Pending && t.depends_on.iter().all(|dep| {
                self.tasks.get(dep).map(|d| d.state == TaskState::Completed).unwrap_or(false)
            })
        }).collect()
    }

    /// Check if the entire DAG is complete.
    pub fn is_complete(&self) -> bool {
        self.tasks.values().all(|t| {
            matches!(t.state, TaskState::Completed | TaskState::Failed | TaskState::Skipped)
        })
    }

    /// Summary of current state.
    pub fn summary(&self) -> OrchestratorSummary {
        let mut s = OrchestratorSummary::default();
        for t in self.tasks.values() {
            s.total += 1;
            match t.state {
                TaskState::Pending => s.pending += 1,
                TaskState::Ready => s.ready += 1,
                TaskState::Running => s.running += 1,
                TaskState::Completed => s.completed += 1,
                TaskState::Failed => s.failed += 1,
                TaskState::Retrying => s.retrying += 1,
                TaskState::Skipped => s.skipped += 1,
            }
        }
        s
    }

    // ── Accessors ───────────────────────────────────────────
    pub fn get_task(&self, id: &str) -> Option<&OrchestratorTask> { self.tasks.get(id) }
    pub fn task_count(&self) -> usize { self.tasks.len() }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OrchestratorSummary {
    pub total: usize,
    pub pending: usize,
    pub ready: usize,
    pub running: usize,
    pub completed: usize,
    pub failed: usize,
    pub retrying: usize,
    pub skipped: usize,
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_linear_pipeline() {
        let mut orch = Orchestrator::new();
        orch.add_task(OrchestratorTask::new("ingest", "agent_a", "data:ingest")).unwrap();
        orch.add_task(OrchestratorTask::new("process", "agent_b", "data:process")
            .with_dependency("ingest")).unwrap();
        orch.add_task(OrchestratorTask::new("output", "agent_c", "data:export")
            .with_dependency("process")).unwrap();

        let waves = orch.compute_waves().unwrap();
        assert_eq!(waves.len(), 3);
        assert_eq!(waves[0].task_ids, vec!["ingest"]);
        assert_eq!(waves[1].task_ids, vec!["process"]);
        assert_eq!(waves[2].task_ids, vec!["output"]);
    }

    #[test]
    fn test_parallel_tasks() {
        let mut orch = Orchestrator::new();
        orch.add_task(OrchestratorTask::new("start", "a", "t:a")).unwrap();
        orch.add_task(OrchestratorTask::new("branch_a", "b", "t:a")
            .with_dependency("start")).unwrap();
        orch.add_task(OrchestratorTask::new("branch_b", "c", "t:a")
            .with_dependency("start")).unwrap();
        orch.add_task(OrchestratorTask::new("join", "d", "t:a")
            .with_dependency("branch_a").with_dependency("branch_b")).unwrap();

        let waves = orch.compute_waves().unwrap();
        assert_eq!(waves.len(), 3);
        assert_eq!(waves[0].task_ids, vec!["start"]);
        assert_eq!(waves[1].task_ids.len(), 2); // branch_a, branch_b in parallel
        assert_eq!(waves[2].task_ids, vec!["join"]);
    }

    #[test]
    fn test_cycle_detection() {
        let mut orch = Orchestrator::new();
        orch.add_task(OrchestratorTask::new("a", "x", "t:a")).unwrap();
        orch.add_task(OrchestratorTask::new("b", "y", "t:a").with_dependency("a")).unwrap();
        // Manually inject a cycle: a depends on b (after both are added)
        orch.tasks.get_mut("a").unwrap().depends_on.push("b".to_string());
        let result = orch.compute_waves();
        assert!(result.is_err());
    }

    #[test]
    fn test_task_lifecycle() {
        let mut orch = Orchestrator::new();
        orch.add_task(OrchestratorTask::new("t1", "a", "t:a")).unwrap();
        orch.add_task(OrchestratorTask::new("t2", "b", "t:a").with_dependency("t1")).unwrap();

        // t1 is ready (no deps)
        assert_eq!(orch.ready_tasks().len(), 1);
        orch.start_task("t1", 1000).unwrap();
        orch.complete_task("t1", "ok", 2000).unwrap();

        // Now t2 is ready
        assert_eq!(orch.ready_tasks().len(), 1);
        orch.start_task("t2", 3000).unwrap();
        orch.complete_task("t2", "ok", 4000).unwrap();

        assert!(orch.is_complete());
        let s = orch.summary();
        assert_eq!(s.completed, 2);
    }

    #[test]
    fn test_retry_with_backoff() {
        let mut orch = Orchestrator::new();
        orch.add_task(OrchestratorTask::new("t1", "a", "t:a").with_retries(3, 100)).unwrap();
        orch.start_task("t1", 1000).unwrap();

        // First failure → retry
        let can_retry = orch.fail_task("t1", "timeout", 2000).unwrap();
        assert!(can_retry);
        assert_eq!(orch.get_task("t1").unwrap().state, TaskState::Retrying);
        assert_eq!(orch.get_task("t1").unwrap().retry_count, 1);

        // Backoff: 100 * 2^1 = 200ms
        assert_eq!(orch.get_task("t1").unwrap().next_retry_delay_ms(), 200);
    }

    #[test]
    fn test_max_retries_exhausted() {
        let mut orch = Orchestrator::new();
        orch.add_task(OrchestratorTask::new("t1", "a", "t:a").with_retries(1, 100)).unwrap();
        orch.start_task("t1", 1000).unwrap();

        // First failure → can retry
        assert!(orch.fail_task("t1", "err1", 2000).unwrap());
        // Mark as running again for second attempt
        orch.tasks.get_mut("t1").unwrap().state = TaskState::Running;
        // Second failure → no more retries
        assert!(!orch.fail_task("t1", "err2", 3000).unwrap());
        assert_eq!(orch.get_task("t1").unwrap().state, TaskState::Failed);
    }

    #[test]
    fn test_skip_dependents_on_failure() {
        let mut orch = Orchestrator::new();
        orch.add_task(OrchestratorTask::new("t1", "a", "t:a").with_retries(0, 100)).unwrap();
        orch.add_task(OrchestratorTask::new("t2", "b", "t:a").with_dependency("t1")).unwrap();
        orch.add_task(OrchestratorTask::new("t3", "c", "t:a").with_dependency("t2")).unwrap();

        orch.start_task("t1", 1000).unwrap();
        orch.fail_task("t1", "crash", 2000).unwrap();

        let skipped = orch.skip_dependents("t1");
        assert_eq!(skipped.len(), 2); // t2 and t3 both skipped
        assert_eq!(orch.get_task("t2").unwrap().state, TaskState::Skipped);
        assert_eq!(orch.get_task("t3").unwrap().state, TaskState::Skipped);
        assert!(orch.is_complete());
    }

    #[test]
    fn test_cannot_start_before_deps() {
        let mut orch = Orchestrator::new();
        orch.add_task(OrchestratorTask::new("t1", "a", "t:a")).unwrap();
        orch.add_task(OrchestratorTask::new("t2", "b", "t:a").with_dependency("t1")).unwrap();
        // t2 cannot start before t1 is complete
        let result = orch.start_task("t2", 1000);
        assert!(result.is_err());
    }

    #[test]
    fn test_summary() {
        let mut orch = Orchestrator::new();
        orch.add_task(OrchestratorTask::new("t1", "a", "t:a")).unwrap();
        orch.add_task(OrchestratorTask::new("t2", "b", "t:a").with_dependency("t1")).unwrap();
        orch.add_task(OrchestratorTask::new("t3", "c", "t:a").with_dependency("t1")).unwrap();

        let s = orch.summary();
        assert_eq!(s.total, 3);
        assert_eq!(s.pending, 3);

        orch.start_task("t1", 1000).unwrap();
        let s = orch.summary();
        assert_eq!(s.running, 1);
        assert_eq!(s.pending, 2);
    }

    #[test]
    fn test_duplicate_task_rejected() {
        let mut orch = Orchestrator::new();
        orch.add_task(OrchestratorTask::new("t1", "a", "t:a")).unwrap();
        let result = orch.add_task(OrchestratorTask::new("t1", "b", "t:b"));
        assert!(result.is_err());
    }
}

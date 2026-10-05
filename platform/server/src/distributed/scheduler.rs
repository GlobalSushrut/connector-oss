//! Mini K8s-like Cross-Cell Scheduler
//!
//! FIX BUG-021: Real distributed task scheduling with placement logic,
//! resource-aware allocation, and failover handling. Lightweight implementation
//! focused on multi-cell agent workloads.

use std::collections::{HashMap, VecDeque, BTreeMap};
use std::sync::{Arc, Mutex};
use serde::{Serialize, Deserialize};
use uuid::Uuid;

/// Cell (node) in the distributed cluster
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cell {
    pub cell_id: String,
    pub address: String,
    pub status: CellStatus,
    pub capacity: CellCapacity,
    pub allocated: CellAllocated,
    pub labels: HashMap<String, String>,
    pub last_heartbeat: i64,
    pub zone: String,  // Availability zone/region
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum CellStatus {
    Ready,
    NotReady,
    SchedulingDisabled,
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
pub struct CellCapacity {
    pub cpu_millicores: u32,      // e.g., 4000 = 4 cores
    pub memory_mb: u64,
    pub agent_slots: u32,
    pub network_bandwidth_mbps: u32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
pub struct CellAllocated {
    pub cpu_millicores: u32,
    pub memory_mb: u64,
    pub agent_count: u32,
}

impl Cell {
    /// Check if cell has capacity for a task
    pub fn has_capacity(&self, requirements: &ResourceRequirements) -> bool {
        let cpu_available = self.capacity.cpu_millicores - self.allocated.cpu_millicores;
        let memory_available = self.capacity.memory_mb - self.allocated.memory_mb;
        let agents_available = self.capacity.agent_slots - self.allocated.agent_count;

        cpu_available >= requirements.cpu_millicores &&
        memory_available >= requirements.memory_mb &&
        agents_available >= 1
    }

    /// Calculate remaining capacity percentage
    pub fn capacity_remaining_pct(&self) -> f64 {
        let cpu_remaining = (self.capacity.cpu_millicores - self.allocated.cpu_millicores) as f64;
        let memory_remaining = (self.capacity.memory_mb - self.allocated.memory_mb) as f64;

        let cpu_pct = cpu_remaining / self.capacity.cpu_millicores as f64;
        let memory_pct = if self.capacity.memory_mb > 0 {
            memory_remaining / self.capacity.memory_mb as f64
        } else {
            1.0
        };

        (cpu_pct + memory_pct) / 2.0
    }
}

/// Resource requirements for a task
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ResourceRequirements {
    pub cpu_millicores: u32,
    pub memory_mb: u64,
    pub gpu_count: u32,
    pub storage_mb: u64,
}

/// Task (agent workload) to schedule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Task {
    pub task_id: String,
    pub task_type: TaskType,
    pub requirements: ResourceRequirements,
    pub priority: TaskPriority,
    pub constraints: TaskConstraints,
    pub payload: serde_json::Value,
    pub created_at: i64,
    pub scheduled_at: Option<i64>,
    pub cell_id: Option<String>,
    pub status: TaskStatus,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum TaskType {
    AgentExecution,
    DataProcessing,
    ModelInference,
    ComplianceCheck,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Ord, PartialOrd, Eq)]
pub enum TaskPriority {
    Critical = 0,
    High = 1,
    Normal = 2,
    Low = 3,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TaskConstraints {
    pub zone_preference: Option<String>,
    pub cell_selector: HashMap<String, String>,  // Label selector
    pub anti_affinity: Vec<String>,  // Don't co-locate with these task types
    pub min_capacity_pct: Option<f64>,  // Minimum cell capacity remaining
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum TaskStatus {
    Pending,
    Scheduled,
    Running,
    Completed,
    Failed,
    Evicted,
}

/// Mini K8s-like Scheduler
pub struct MiniScheduler {
    /// All known cells
    cells: HashMap<String, Cell>,
    /// Pending task queue
    pending_queue: VecDeque<Task>,
    /// Running tasks: cell_id -> list of tasks
    running_tasks: HashMap<String, Vec<Task>>,
    /// Task history for tracking
    task_history: Vec<Task>,
    /// Maximum history size
    max_history: usize,
    /// Scheduling strategy
    strategy: SchedulingStrategy,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum SchedulingStrategy {
    /// Spread tasks across cells evenly
    Spread,
    /// Pack tasks into cells to maximize utilization
    BinPack,
    /// Prefer cells in the same zone as the requester
    ZoneAware,
}

impl MiniScheduler {
    pub fn new(strategy: SchedulingStrategy) -> Self {
        Self {
            cells: HashMap::new(),
            pending_queue: VecDeque::new(),
            running_tasks: HashMap::new(),
            task_history: Vec::with_capacity(1000),
            max_history: 10000,
            strategy,
        }
    }

    /// Register a new cell in the cluster
    pub fn register_cell(&mut self, cell: Cell) {
        let cell_id = cell.cell_id.clone();
        self.cells.insert(cell_id.clone(), cell);
        self.running_tasks.entry(cell_id).or_insert_with(Vec::new);
    }

    /// Update cell status from heartbeat
    pub fn update_cell_heartbeat(&mut self, cell_id: &str) {
        if let Some(cell) = self.cells.get_mut(cell_id) {
            cell.last_heartbeat = chrono::Utc::now().timestamp_millis();
            if cell.status == CellStatus::Unknown {
                cell.status = CellStatus::Ready;
            }
        }
    }

    /// Mark cell as unavailable
    pub fn mark_cell_unavailable(&mut self, cell_id: &str) {
        if let Some(cell) = self.cells.get_mut(cell_id) {
            cell.status = CellStatus::NotReady;

            // Reschedule running tasks
            if let Some(tasks) = self.running_tasks.remove(cell_id) {
                for mut task in tasks {
                    task.status = TaskStatus::Pending;
                    task.cell_id = None;
                    self.pending_queue.push_front(task);
                }
            }
        }
    }

    /// Submit a task for scheduling
    pub fn submit_task(&mut self, mut task: Task) -> String {
        let task_id = format!("task-{}", Uuid::new_v4());
        task.task_id = task_id.clone();
        task.status = TaskStatus::Pending;
        self.pending_queue.push_back(task);
        task_id
    }

    /// Run scheduling cycle
    pub fn schedule(&mut self) -> Vec<SchedulingResult> {
        let mut results = Vec::new();
        let now = chrono::Utc::now().timestamp_millis();

        // Clean up stale cells (no heartbeat for 30 seconds)
        let stale_threshold = now - 30000;
        let stale_cells: Vec<String> = self.cells
            .iter()
            .filter(|(_, cell)| cell.last_heartbeat < stale_threshold && cell.status == CellStatus::Ready)
            .map(|(id, _)| id.clone())
            .collect();

        for cell_id in stale_cells {
            self.mark_cell_unavailable(&cell_id);
        }

        // Process pending queue
        let mut to_schedule: Vec<Task> = Vec::new();
        while let Some(task) = self.pending_queue.pop_front() {
            to_schedule.push(task);
        }

        // Sort by priority (higher priority first)
        to_schedule.sort_by_key(|t| t.priority);

        for task in to_schedule {
            match self.find_best_cell(&task) {
                Some(cell_id) => {
                    // Allocate resources
                    if let Some(cell) = self.cells.get_mut(&cell_id) {
                        cell.allocated.cpu_millicores += task.requirements.cpu_millicores;
                        cell.allocated.memory_mb += task.requirements.memory_mb;
                        cell.allocated.agent_count += 1;
                    }

                    // Update task
                    let mut scheduled_task = task.clone();
                    scheduled_task.cell_id = Some(cell_id.clone());
                    scheduled_task.status = TaskStatus::Scheduled;
                    scheduled_task.scheduled_at = Some(now);

                    // Track running task
                    self.running_tasks
                        .entry(cell_id.clone())
                        .or_insert_with(Vec::new)
                        .push(scheduled_task.clone());

                    results.push(SchedulingResult {
                        task_id: scheduled_task.task_id.clone(),
                        cell_id: cell_id.clone(),
                        status: SchedulingStatus::Scheduled,
                    });

                    self.add_to_history(scheduled_task);
                }
                None => {
                    // No cell available, requeue
                    let task_id = task.task_id.clone();
                    let mut requeued = task;
                    requeued.status = TaskStatus::Pending;
                    self.pending_queue.push_back(requeued);

                    results.push(SchedulingResult {
                        task_id,
                        cell_id: String::new(),
                        status: SchedulingStatus::NoCapacity,
                    });
                }
            }
        }

        results
    }

    /// Find best cell for a task based on strategy
    fn find_best_cell(&self, task: &Task) -> Option<String> {
        let ready_cells: Vec<&Cell> = self.cells
            .values()
            .filter(|c| c.status == CellStatus::Ready && c.has_capacity(&task.requirements))
            .collect();

        if ready_cells.is_empty() {
            return None;
        }

        let candidates: Vec<&Cell> = ready_cells
            .into_iter()
            .filter(|c| self.matches_constraints(c, &task.constraints))
            .collect();

        if candidates.is_empty() {
            return None;
        }

        match self.strategy {
            SchedulingStrategy::Spread => {
                // Choose cell with least load
                candidates
                    .into_iter()
                    .min_by_key(|c| self.running_tasks.get(&c.cell_id).map(|t| t.len()).unwrap_or(0))
                    .map(|c| c.cell_id.clone())
            }
            SchedulingStrategy::BinPack => {
                // Choose cell with most load (but still has capacity)
                candidates
                    .into_iter()
                    .max_by(|a, b| {
                        let a_load = a.allocated.agent_count as f64 / a.capacity.agent_slots as f64;
                        let b_load = b.allocated.agent_count as f64 / b.capacity.agent_slots as f64;
                        a_load.partial_cmp(&b_load).unwrap()
                    })
                    .map(|c| c.cell_id.clone())
            }
            SchedulingStrategy::ZoneAware => {
                // Prefer cells in requested zone, then least loaded
                let preferred_zone = task.constraints.zone_preference.as_deref();

                let zone_matches: Vec<&Cell> = candidates
                    .iter()
                    .filter(|c| preferred_zone.map(|z| c.zone == z).unwrap_or(true))
                    .copied()
                    .collect();

                if !zone_matches.is_empty() {
                    zone_matches
                        .into_iter()
                        .min_by_key(|c| self.running_tasks.get(&c.cell_id).map(|t| t.len()).unwrap_or(0))
                        .map(|c| c.cell_id.clone())
                } else {
                    candidates
                        .into_iter()
                        .min_by_key(|c| self.running_tasks.get(&c.cell_id).map(|t| t.len()).unwrap_or(0))
                        .map(|c| c.cell_id.clone())
                }
            }
        }
    }

    /// Check if cell matches task constraints
    fn matches_constraints(&self, cell: &Cell, constraints: &TaskConstraints) -> bool {
        // Check label selector
        for (key, value) in &constraints.cell_selector {
            if cell.labels.get(key) != Some(value) {
                return false;
            }
        }

        // Check minimum capacity
        if let Some(min_pct) = constraints.min_capacity_pct {
            if cell.capacity_remaining_pct() < min_pct {
                return false;
            }
        }

        true
    }

    /// Mark task as completed
    pub fn complete_task(&mut self, task_id: &str, cell_id: &str) -> Result<(), SchedulerError> {
        if let Some(tasks) = self.running_tasks.get_mut(cell_id) {
            if let Some(pos) = tasks.iter().position(|t| t.task_id == task_id) {
                let task = tasks.remove(pos);

                // Release resources
                if let Some(cell) = self.cells.get_mut(cell_id) {
                    cell.allocated.cpu_millicores =
                        cell.allocated.cpu_millicores.saturating_sub(task.requirements.cpu_millicores);
                    cell.allocated.memory_mb =
                        cell.allocated.memory_mb.saturating_sub(task.requirements.memory_mb);
                    cell.allocated.agent_count =
                        cell.allocated.agent_count.saturating_sub(1);
                }

                return Ok(());
            }
        }

        Err(SchedulerError::TaskNotFound)
    }

    /// Get cluster statistics
    pub fn cluster_stats(&self) -> ClusterStats {
        let total_cells = self.cells.len();
        let ready_cells = self.cells.values().filter(|c| c.status == CellStatus::Ready).count();
        let total_capacity: CellCapacity = self.cells.values().map(|c| c.capacity).fold(
            CellCapacity::default(),
            |acc, c| CellCapacity {
                cpu_millicores: acc.cpu_millicores + c.cpu_millicores,
                memory_mb: acc.memory_mb + c.memory_mb,
                agent_slots: acc.agent_slots + c.agent_slots,
                network_bandwidth_mbps: 0,
            },
        );
        let total_allocated: CellAllocated = self.cells.values().map(|c| c.allocated).fold(
            CellAllocated::default(),
            |acc, a| CellAllocated {
                cpu_millicores: acc.cpu_millicores + a.cpu_millicores,
                memory_mb: acc.memory_mb + a.memory_mb,
                agent_count: acc.agent_count + a.agent_count,
            },
        );

        ClusterStats {
            total_cells,
            ready_cells,
            pending_tasks: self.pending_queue.len(),
            running_tasks: self.running_tasks.values().map(|v| v.len()).sum(),
            total_capacity,
            total_allocated,
        }
    }

    /// Get cell details
    pub fn get_cell(&self, cell_id: &str) -> Option<&Cell> {
        self.cells.get(cell_id)
    }

    /// List all cells
    pub fn list_cells(&self) -> Vec<&Cell> {
        self.cells.values().collect()
    }

    /// Add task to history
    fn add_to_history(&mut self, task: Task) {
        self.task_history.push(task);
        if self.task_history.len() > self.max_history {
            self.task_history.remove(0);
        }
    }
}

#[derive(Debug, Clone)]
pub struct SchedulingResult {
    pub task_id: String,
    pub cell_id: String,
    pub status: SchedulingStatus,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SchedulingStatus {
    Scheduled,
    NoCapacity,
    ConstraintViolation,
}

#[derive(Debug, Clone)]
pub struct ClusterStats {
    pub total_cells: usize,
    pub ready_cells: usize,
    pub pending_tasks: usize,
    pub running_tasks: usize,
    pub total_capacity: CellCapacity,
    pub total_allocated: CellAllocated,
}

#[derive(Debug, Clone)]
pub enum SchedulerError {
    TaskNotFound,
    CellNotFound,
    InsufficientResources,
}

impl std::fmt::Display for SchedulerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SchedulerError::TaskNotFound => write!(f, "Task not found"),
            SchedulerError::CellNotFound => write!(f, "Cell not found"),
            SchedulerError::InsufficientResources => write!(f, "Insufficient resources"),
        }
    }
}

impl std::error::Error for SchedulerError {}

/// Thread-safe wrapper
#[derive(Clone)]
pub struct SharedMiniScheduler {
    inner: Arc<Mutex<MiniScheduler>>,
}

impl SharedMiniScheduler {
    pub fn new(strategy: SchedulingStrategy) -> Self {
        Self {
            inner: Arc::new(Mutex::new(MiniScheduler::new(strategy))),
        }
    }

    pub fn register_cell(&self, cell: Cell) {
        self.inner.lock().unwrap().register_cell(cell);
    }

    pub fn submit_task(&self, task: Task) -> String {
        self.inner.lock().unwrap().submit_task(task)
    }

    pub fn schedule(&self) -> Vec<SchedulingResult> {
        self.inner.lock().unwrap().schedule()
    }

    pub fn cluster_stats(&self) -> ClusterStats {
        self.inner.lock().unwrap().cluster_stats()
    }

    pub fn complete_task(&self, task_id: &str, cell_id: &str) -> Result<(), SchedulerError> {
        self.inner.lock().unwrap().complete_task(task_id, cell_id)
    }

    pub fn mark_cell_unavailable(&self, cell_id: &str) {
        self.inner.lock().unwrap().mark_cell_unavailable(cell_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_cell(id: &str, capacity: u32) -> Cell {
        Cell {
            cell_id: id.to_string(),
            address: format!("127.0.0.1:8{id}"),
            status: CellStatus::Ready,
            capacity: CellCapacity {
                cpu_millicores: capacity * 1000,
                memory_mb: capacity as u64 * 1024,
                agent_slots: capacity,
                network_bandwidth_mbps: 1000,
            },
            allocated: CellAllocated::default(),
            labels: HashMap::new(),
            last_heartbeat: chrono::Utc::now().timestamp_millis(),
            zone: "zone-a".to_string(),
        }
    }

    fn test_task(priority: TaskPriority) -> Task {
        Task {
            task_id: String::new(),
            task_type: TaskType::AgentExecution,
            requirements: ResourceRequirements {
                cpu_millicores: 500,
                memory_mb: 512,
                ..Default::default()
            },
            priority,
            constraints: TaskConstraints::default(),
            payload: serde_json::json!({}),
            created_at: chrono::Utc::now().timestamp_millis(),
            scheduled_at: None,
            cell_id: None,
            status: TaskStatus::Pending,
        }
    }

    #[test]
    fn test_basic_scheduling() {
        let mut scheduler = MiniScheduler::new(SchedulingStrategy::Spread);

        // Register cells
        scheduler.register_cell(test_cell("cell-1", 4));
        scheduler.register_cell(test_cell("cell-2", 4));

        // Submit task
        let task = test_task(TaskPriority::Normal);
        let task_id = scheduler.submit_task(task);

        // Schedule
        let results = scheduler.schedule();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, SchedulingStatus::Scheduled);
        assert!(!results[0].cell_id.is_empty());
    }

    #[test]
    fn test_spread_strategy() {
        let mut scheduler = MiniScheduler::new(SchedulingStrategy::Spread);

        scheduler.register_cell(test_cell("cell-1", 4));
        scheduler.register_cell(test_cell("cell-2", 4));

        // Submit 4 tasks
        for _ in 0..4 {
            scheduler.submit_task(test_task(TaskPriority::Normal));
        }

        let results = scheduler.schedule();

        // Should spread across both cells
        let cell1_count = results.iter().filter(|r| r.cell_id == "cell-1").count();
        let cell2_count = results.iter().filter(|r| r.cell_id == "cell-2").count();

        assert!(cell1_count > 0 && cell2_count > 0, "Should spread tasks");
    }

    #[test]
    fn test_capacity_limit() {
        let mut scheduler = MiniScheduler::new(SchedulingStrategy::Spread);

        // Register small cell
        scheduler.register_cell(test_cell("cell-1", 1));

        // Submit 3 tasks
        for _ in 0..3 {
            scheduler.submit_task(test_task(TaskPriority::Normal));
        }

        let results = scheduler.schedule();

        // Only 1 should be scheduled, 2 should be pending
        let scheduled = results.iter().filter(|r| r.status == SchedulingStatus::Scheduled).count();
        let pending = results.iter().filter(|r| r.status == SchedulingStatus::NoCapacity).count();

        assert_eq!(scheduled, 1);
        assert_eq!(pending, 2);
    }

    #[test]
    fn test_failover() {
        let mut scheduler = MiniScheduler::new(SchedulingStrategy::Spread);

        scheduler.register_cell(test_cell("cell-1", 4));
        scheduler.register_cell(test_cell("cell-2", 4));

        // Schedule a task
        let task_id = scheduler.submit_task(test_task(TaskPriority::Normal));
        scheduler.schedule();

        // Mark cell unavailable
        scheduler.mark_cell_unavailable("cell-1");

        // Task should be rescheduled
        let results = scheduler.schedule();
        assert!(results.iter().any(|r| r.cell_id == "cell-2"));
    }
}

//! Per-Task Cost Tracking — Operation-level resource accounting
//!
//! This module implements fine-grained cost tracking at the operation level:
//! - Per-operation cost metrics (CPU, memory, I/O, tokens)
//! - Cost aggregation by operation type, agent, session
//! - Budget enforcement with cost limits
//! - Cost attribution and chargeback
//!
//! Design sources: Cloud billing, eBPF cost tracking, token metering

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::process::Pid;

// =============================================================================
// Cost Types
// =============================================================================

/// Cost unit type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CostUnit {
    /// CPU time (nanoseconds)
    CpuNanos,
    /// Memory (bytes)
    MemoryBytes,
    /// I/O read (bytes)
    IoReadBytes,
    /// I/O write (bytes)
    IoWriteBytes,
    /// Network send (bytes)
    NetSendBytes,
    /// Network receive (bytes)
    NetRecvBytes,
    /// LLM tokens (input)
    TokensInput,
    /// LLM tokens (output)
    TokensOutput,
    /// Tool invocations
    ToolCalls,
    /// Syscall count
    Syscalls,
    /// Custom unit
    Custom,
}

/// Operation type for cost attribution
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OperationType {
    /// Category (e.g., "memory", "llm", "tool", "io")
    pub category: String,
    /// Specific operation (e.g., "mem_write", "gpt4_completion", "web_search")
    pub operation: String,
}

impl OperationType {
    pub fn new(category: &str, operation: &str) -> Self {
        Self {
            category: category.into(),
            operation: operation.into(),
        }
    }

    /// Memory operations
    pub fn mem_read() -> Self { Self::new("memory", "mem_read") }
    pub fn mem_write() -> Self { Self::new("memory", "mem_write") }
    pub fn mem_alloc() -> Self { Self::new("memory", "mem_alloc") }
    pub fn mem_free() -> Self { Self::new("memory", "mem_free") }

    /// LLM operations
    pub fn llm_completion(model: &str) -> Self { Self::new("llm", model) }
    pub fn llm_embedding(model: &str) -> Self { Self::new("llm", &format!("{}_embed", model)) }

    /// Tool operations
    pub fn tool_call(tool: &str) -> Self { Self::new("tool", tool) }

    /// I/O operations
    pub fn io_read() -> Self { Self::new("io", "read") }
    pub fn io_write() -> Self { Self::new("io", "write") }

    /// Network operations
    pub fn net_send() -> Self { Self::new("network", "send") }
    pub fn net_recv() -> Self { Self::new("network", "recv") }

    /// Syscall operations
    pub fn syscall(name: &str) -> Self { Self::new("syscall", name) }
}

// =============================================================================
// Cost Record
// =============================================================================

/// Cost record ID counter
static COST_RECORD_ID: AtomicU64 = AtomicU64::new(1);

/// Single cost record for an operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostRecord {
    /// Record ID
    pub id: u64,
    /// Operation type
    pub operation: OperationType,
    /// Agent PID
    pub agent_pid: Pid,
    /// Session ID (if applicable)
    pub session_id: Option<String>,
    /// Cost breakdown by unit
    pub costs: HashMap<CostUnit, u64>,
    /// Start timestamp (epoch nanos)
    pub started_at: u64,
    /// Duration (nanos)
    pub duration_nanos: u64,
    /// Success flag
    pub success: bool,
    /// Error message (if failed)
    pub error: Option<String>,
    /// Metadata
    pub metadata: HashMap<String, String>,
}

impl CostRecord {
    pub fn new(operation: OperationType, agent_pid: Pid) -> Self {
        Self {
            id: COST_RECORD_ID.fetch_add(1, Ordering::SeqCst),
            operation,
            agent_pid,
            session_id: None,
            costs: HashMap::new(),
            started_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64,
            duration_nanos: 0,
            success: true,
            error: None,
            metadata: HashMap::new(),
        }
    }

    pub fn with_session(mut self, session_id: &str) -> Self {
        self.session_id = Some(session_id.into());
        self
    }

    pub fn add_cost(&mut self, unit: CostUnit, amount: u64) {
        *self.costs.entry(unit).or_insert(0) += amount;
    }

    pub fn set_duration(&mut self, duration: Duration) {
        self.duration_nanos = duration.as_nanos() as u64;
    }

    pub fn set_error(&mut self, error: &str) {
        self.success = false;
        self.error = Some(error.into());
    }

    pub fn add_metadata(&mut self, key: &str, value: &str) {
        self.metadata.insert(key.into(), value.into());
    }

    /// Get total cost for a unit
    pub fn get_cost(&self, unit: CostUnit) -> u64 {
        self.costs.get(&unit).copied().unwrap_or(0)
    }
}

// =============================================================================
// Cost Tracker (per-operation)
// =============================================================================

/// Active operation tracker
pub struct OperationTracker {
    record: CostRecord,
    start_time: Instant,
}

impl OperationTracker {
    pub fn start(operation: OperationType, agent_pid: Pid) -> Self {
        Self {
            record: CostRecord::new(operation, agent_pid),
            start_time: Instant::now(),
        }
    }

    pub fn with_session(mut self, session_id: &str) -> Self {
        self.record = self.record.with_session(session_id);
        self
    }

    pub fn add_cost(&mut self, unit: CostUnit, amount: u64) {
        self.record.add_cost(unit, amount);
    }

    pub fn add_metadata(&mut self, key: &str, value: &str) {
        self.record.add_metadata(key, value);
    }

    pub fn finish(mut self) -> CostRecord {
        self.record.set_duration(self.start_time.elapsed());
        self.record
    }

    pub fn finish_with_error(mut self, error: &str) -> CostRecord {
        self.record.set_duration(self.start_time.elapsed());
        self.record.set_error(error);
        self.record
    }
}

// =============================================================================
// Cost Aggregation
// =============================================================================

/// Aggregated costs
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AggregatedCosts {
    /// Total by cost unit
    pub by_unit: HashMap<CostUnit, u64>,
    /// Total by operation type
    pub by_operation: HashMap<String, HashMap<CostUnit, u64>>,
    /// Operation count
    pub operation_count: u64,
    /// Success count
    pub success_count: u64,
    /// Failure count
    pub failure_count: u64,
    /// Total duration (nanos)
    pub total_duration_nanos: u64,
}

impl AggregatedCosts {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_record(&mut self, record: &CostRecord) {
        // Aggregate by unit
        for (unit, amount) in &record.costs {
            *self.by_unit.entry(*unit).or_insert(0) += amount;
        }

        // Aggregate by operation
        let op_key = format!("{}:{}", record.operation.category, record.operation.operation);
        let op_costs = self.by_operation.entry(op_key).or_default();
        for (unit, amount) in &record.costs {
            *op_costs.entry(*unit).or_insert(0) += amount;
        }

        // Counts
        self.operation_count += 1;
        if record.success {
            self.success_count += 1;
        } else {
            self.failure_count += 1;
        }

        self.total_duration_nanos += record.duration_nanos;
    }

    pub fn get_total(&self, unit: CostUnit) -> u64 {
        self.by_unit.get(&unit).copied().unwrap_or(0)
    }

    pub fn merge(&mut self, other: &AggregatedCosts) {
        for (unit, amount) in &other.by_unit {
            *self.by_unit.entry(*unit).or_insert(0) += amount;
        }
        for (op, costs) in &other.by_operation {
            let entry = self.by_operation.entry(op.clone()).or_default();
            for (unit, amount) in costs {
                *entry.entry(*unit).or_insert(0) += amount;
            }
        }
        self.operation_count += other.operation_count;
        self.success_count += other.success_count;
        self.failure_count += other.failure_count;
        self.total_duration_nanos += other.total_duration_nanos;
    }
}

// =============================================================================
// Cost Budget
// =============================================================================

/// Cost budget for an agent or session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostBudget {
    /// Budget ID
    pub id: String,
    /// Limits by cost unit
    pub limits: HashMap<CostUnit, u64>,
    /// Current usage
    pub usage: HashMap<CostUnit, u64>,
    /// Budget period start
    pub period_start: i64,
    /// Budget period duration (seconds)
    pub period_seconds: u64,
    /// Action when budget exceeded
    pub exceed_action: BudgetExceedAction,
    /// Alert threshold (percentage)
    pub alert_threshold: f64,
}

/// Action when budget is exceeded
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetExceedAction {
    /// Log warning only
    Warn,
    /// Throttle operations
    Throttle,
    /// Block operations
    Block,
    /// Terminate agent
    Terminate,
}

impl Default for BudgetExceedAction {
    fn default() -> Self {
        Self::Warn
    }
}

impl CostBudget {
    pub fn new(id: &str) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        Self {
            id: id.into(),
            limits: HashMap::new(),
            usage: HashMap::new(),
            period_start: now,
            period_seconds: 3600, // 1 hour default
            exceed_action: BudgetExceedAction::Warn,
            alert_threshold: 0.8,
        }
    }

    pub fn with_limit(mut self, unit: CostUnit, limit: u64) -> Self {
        self.limits.insert(unit, limit);
        self
    }

    pub fn with_period(mut self, seconds: u64) -> Self {
        self.period_seconds = seconds;
        self
    }

    pub fn with_action(mut self, action: BudgetExceedAction) -> Self {
        self.exceed_action = action;
        self
    }

    /// Record usage
    pub fn record_usage(&mut self, unit: CostUnit, amount: u64) {
        *self.usage.entry(unit).or_insert(0) += amount;
    }

    /// Check if budget exceeded for a unit
    pub fn is_exceeded(&self, unit: CostUnit) -> bool {
        if let (Some(&limit), Some(&usage)) = (self.limits.get(&unit), self.usage.get(&unit)) {
            usage > limit
        } else {
            false
        }
    }

    /// Check if any budget exceeded
    pub fn any_exceeded(&self) -> bool {
        self.limits.keys().any(|unit| self.is_exceeded(*unit))
    }

    /// Get usage percentage for a unit
    pub fn usage_percentage(&self, unit: CostUnit) -> f64 {
        if let (Some(&limit), Some(&usage)) = (self.limits.get(&unit), self.usage.get(&unit)) {
            if limit > 0 {
                return (usage as f64) / (limit as f64);
            }
        }
        0.0
    }

    /// Check if alert threshold reached
    pub fn alert_reached(&self, unit: CostUnit) -> bool {
        self.usage_percentage(unit) >= self.alert_threshold
    }

    /// Get remaining budget
    pub fn remaining(&self, unit: CostUnit) -> Option<u64> {
        if let (Some(&limit), usage) = (self.limits.get(&unit), self.usage.get(&unit).copied().unwrap_or(0)) {
            Some(limit.saturating_sub(usage))
        } else {
            None
        }
    }

    /// Reset usage (for new period)
    pub fn reset(&mut self) {
        self.usage.clear();
        self.period_start = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
    }
}

// =============================================================================
// Cost Tracker Manager
// =============================================================================

/// Cost tracking manager
#[derive(Debug, Default)]
pub struct CostTracker {
    /// Cost records (recent, limited size)
    records: Vec<CostRecord>,
    /// Maximum records to keep
    max_records: usize,
    /// Aggregated costs by agent
    by_agent: HashMap<Pid, AggregatedCosts>,
    /// Aggregated costs by session
    by_session: HashMap<String, AggregatedCosts>,
    /// Budgets by agent
    agent_budgets: HashMap<Pid, CostBudget>,
    /// Global aggregated costs
    global: AggregatedCosts,
}

impl CostTracker {
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
            max_records: 10000,
            by_agent: HashMap::new(),
            by_session: HashMap::new(),
            agent_budgets: HashMap::new(),
            global: AggregatedCosts::new(),
        }
    }

    pub fn with_max_records(mut self, max: usize) -> Self {
        self.max_records = max;
        self
    }

    /// Record a cost
    pub fn record(&mut self, record: CostRecord) -> Result<(), BudgetExceeded> {
        // Check budget
        if let Some(budget) = self.agent_budgets.get_mut(&record.agent_pid) {
            for (unit, amount) in &record.costs {
                budget.record_usage(*unit, *amount);
            }

            // Check if exceeded
            for unit in record.costs.keys() {
                if budget.is_exceeded(*unit) {
                    return Err(BudgetExceeded {
                        agent_pid: record.agent_pid.clone(),
                        unit: *unit,
                        limit: budget.limits.get(unit).copied().unwrap_or(0),
                        usage: budget.usage.get(unit).copied().unwrap_or(0),
                        action: budget.exceed_action,
                    });
                }
            }
        }

        // Aggregate by agent
        self.by_agent
            .entry(record.agent_pid.clone())
            .or_default()
            .add_record(&record);

        // Aggregate by session
        if let Some(ref session_id) = record.session_id {
            self.by_session
                .entry(session_id.clone())
                .or_default()
                .add_record(&record);
        }

        // Global aggregation
        self.global.add_record(&record);

        // Store record
        self.records.push(record);
        if self.records.len() > self.max_records {
            self.records.remove(0);
        }

        Ok(())
    }

    /// Set budget for an agent
    pub fn set_budget(&mut self, agent_pid: Pid, budget: CostBudget) {
        self.agent_budgets.insert(agent_pid, budget);
    }

    /// Get budget for an agent
    pub fn get_budget(&self, agent_pid: &Pid) -> Option<&CostBudget> {
        self.agent_budgets.get(agent_pid)
    }

    /// Get mutable budget
    pub fn get_budget_mut(&mut self, agent_pid: &Pid) -> Option<&mut CostBudget> {
        self.agent_budgets.get_mut(agent_pid)
    }

    /// Get costs for an agent
    pub fn get_agent_costs(&self, agent_pid: &Pid) -> Option<&AggregatedCosts> {
        self.by_agent.get(agent_pid)
    }

    /// Get costs for a session
    pub fn get_session_costs(&self, session_id: &str) -> Option<&AggregatedCosts> {
        self.by_session.get(session_id)
    }

    /// Get global costs
    pub fn get_global_costs(&self) -> &AggregatedCosts {
        &self.global
    }

    /// Get recent records
    pub fn recent_records(&self, limit: usize) -> &[CostRecord] {
        let start = self.records.len().saturating_sub(limit);
        &self.records[start..]
    }

    /// Get records for an agent
    pub fn agent_records(&self, agent_pid: &Pid) -> Vec<&CostRecord> {
        self.records.iter()
            .filter(|r| &r.agent_pid == agent_pid)
            .collect()
    }

    /// Get records by operation type
    pub fn operation_records(&self, category: &str, operation: &str) -> Vec<&CostRecord> {
        self.records.iter()
            .filter(|r| r.operation.category == category && r.operation.operation == operation)
            .collect()
    }

    /// Get cost breakdown by operation for an agent
    pub fn agent_operation_breakdown(&self, agent_pid: &Pid) -> HashMap<String, HashMap<CostUnit, u64>> {
        self.by_agent.get(agent_pid)
            .map(|agg| agg.by_operation.clone())
            .unwrap_or_default()
    }

    /// Clear all records (keep aggregations)
    pub fn clear_records(&mut self) {
        self.records.clear();
    }

    /// Reset all (including aggregations)
    pub fn reset(&mut self) {
        self.records.clear();
        self.by_agent.clear();
        self.by_session.clear();
        self.global = AggregatedCosts::new();
    }
}

/// Budget exceeded error
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetExceeded {
    pub agent_pid: Pid,
    pub unit: CostUnit,
    pub limit: u64,
    pub usage: u64,
    pub action: BudgetExceedAction,
}

// =============================================================================
// Cost Pricing
// =============================================================================

/// Cost pricing for chargeback
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostPricing {
    /// Price per unit (in smallest currency unit, e.g., cents)
    pub prices: HashMap<CostUnit, f64>,
    /// Currency code
    pub currency: String,
}

impl Default for CostPricing {
    fn default() -> Self {
        let mut prices = HashMap::new();
        // Example pricing
        prices.insert(CostUnit::CpuNanos, 0.000000001); // $0.001 per CPU second
        prices.insert(CostUnit::MemoryBytes, 0.0000000001); // $0.0001 per MB-second
        prices.insert(CostUnit::TokensInput, 0.00001); // $0.01 per 1K input tokens
        prices.insert(CostUnit::TokensOutput, 0.00003); // $0.03 per 1K output tokens
        prices.insert(CostUnit::ToolCalls, 0.001); // $0.001 per tool call

        Self {
            prices,
            currency: "USD".into(),
        }
    }
}

impl CostPricing {
    pub fn calculate(&self, costs: &AggregatedCosts) -> f64 {
        let mut total = 0.0;
        for (unit, amount) in &costs.by_unit {
            if let Some(&price) = self.prices.get(unit) {
                total += (*amount as f64) * price;
            }
        }
        total
    }

    pub fn calculate_record(&self, record: &CostRecord) -> f64 {
        let mut total = 0.0;
        for (unit, amount) in &record.costs {
            if let Some(&price) = self.prices.get(unit) {
                total += (*amount as f64) * price;
            }
        }
        total
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_operation_tracker() {
        let mut tracker = OperationTracker::start(
            OperationType::mem_write(),
            "pid:001".into(),
        );

        tracker.add_cost(CostUnit::CpuNanos, 1000);
        tracker.add_cost(CostUnit::MemoryBytes, 4096);
        tracker.add_metadata("key", "value");

        let record = tracker.finish();

        assert_eq!(record.operation.category, "memory");
        assert_eq!(record.operation.operation, "mem_write");
        assert_eq!(record.get_cost(CostUnit::CpuNanos), 1000);
        assert_eq!(record.get_cost(CostUnit::MemoryBytes), 4096);
        assert!(record.success);
    }

    #[test]
    fn test_cost_aggregation() {
        let mut agg = AggregatedCosts::new();

        let mut record1 = CostRecord::new(OperationType::mem_read(), "pid:001".into());
        record1.add_cost(CostUnit::CpuNanos, 100);
        record1.add_cost(CostUnit::MemoryBytes, 1024);

        let mut record2 = CostRecord::new(OperationType::mem_write(), "pid:001".into());
        record2.add_cost(CostUnit::CpuNanos, 200);
        record2.add_cost(CostUnit::MemoryBytes, 2048);

        agg.add_record(&record1);
        agg.add_record(&record2);

        assert_eq!(agg.get_total(CostUnit::CpuNanos), 300);
        assert_eq!(agg.get_total(CostUnit::MemoryBytes), 3072);
        assert_eq!(agg.operation_count, 2);
    }

    #[test]
    fn test_cost_budget() {
        let mut budget = CostBudget::new("budget-001")
            .with_limit(CostUnit::TokensInput, 1000)
            .with_limit(CostUnit::TokensOutput, 500)
            .with_action(BudgetExceedAction::Block);

        budget.record_usage(CostUnit::TokensInput, 800);
        assert!(!budget.is_exceeded(CostUnit::TokensInput));
        assert!(budget.alert_reached(CostUnit::TokensInput)); // 80% threshold

        budget.record_usage(CostUnit::TokensInput, 300);
        assert!(budget.is_exceeded(CostUnit::TokensInput));

        assert_eq!(budget.remaining(CostUnit::TokensOutput), Some(500));
    }

    #[test]
    fn test_cost_tracker() {
        let mut tracker = CostTracker::new();

        // Set budget
        let budget = CostBudget::new("agent-budget")
            .with_limit(CostUnit::CpuNanos, 10000)
            .with_action(BudgetExceedAction::Warn);
        tracker.set_budget("pid:001".into(), budget);

        // Record costs
        let mut record = CostRecord::new(OperationType::syscall("mem_write"), "pid:001".into());
        record.add_cost(CostUnit::CpuNanos, 500);
        tracker.record(record).unwrap();

        let agent_costs = tracker.get_agent_costs(&"pid:001".into()).unwrap();
        assert_eq!(agent_costs.get_total(CostUnit::CpuNanos), 500);
        assert_eq!(agent_costs.operation_count, 1);
    }

    #[test]
    fn test_budget_exceeded() {
        let mut tracker = CostTracker::new();

        // Budget of 3 tool calls
        let budget = CostBudget::new("agent-budget")
            .with_limit(CostUnit::ToolCalls, 3)
            .with_action(BudgetExceedAction::Block);
        tracker.set_budget("pid:001".into(), budget);

        // First three calls succeed (usage goes to 1, 2, 3)
        let mut r1 = CostRecord::new(OperationType::tool_call("search"), "pid:001".into());
        r1.add_cost(CostUnit::ToolCalls, 1);
        assert!(tracker.record(r1).is_ok());

        let mut r2 = CostRecord::new(OperationType::tool_call("search"), "pid:001".into());
        r2.add_cost(CostUnit::ToolCalls, 1);
        assert!(tracker.record(r2).is_ok());

        let mut r3 = CostRecord::new(OperationType::tool_call("search"), "pid:001".into());
        r3.add_cost(CostUnit::ToolCalls, 1);
        assert!(tracker.record(r3).is_ok());

        // Fourth call exceeds budget (usage would go to 4, limit is 3)
        let mut r4 = CostRecord::new(OperationType::tool_call("search"), "pid:001".into());
        r4.add_cost(CostUnit::ToolCalls, 1);
        let result = tracker.record(r4);
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert_eq!(err.unit, CostUnit::ToolCalls);
        assert_eq!(err.action, BudgetExceedAction::Block);
    }

    #[test]
    fn test_cost_pricing() {
        let pricing = CostPricing::default();

        let mut record = CostRecord::new(OperationType::llm_completion("gpt4"), "pid:001".into());
        record.add_cost(CostUnit::TokensInput, 1000);
        record.add_cost(CostUnit::TokensOutput, 500);

        let cost = pricing.calculate_record(&record);
        // 1000 * 0.00001 + 500 * 0.00003 = 0.01 + 0.015 = 0.025
        assert!((cost - 0.025).abs() < 0.0001);
    }
}

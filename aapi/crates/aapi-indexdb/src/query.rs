//! Query capabilities for IndexDB

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{IndexDbError, IndexDbResult};
use crate::models::*;
use crate::store::IndexDbStore;

/// Query builder for VĀKYA records
#[derive(Debug, Clone, Default)]
pub struct VakyaQuery {
    /// Filter by actor principal
    pub karta_pid: Option<String>,
    /// Filter by actor type
    pub karta_type: Option<String>,
    /// Filter by resource ID (prefix match)
    pub karma_rid_prefix: Option<String>,
    /// Filter by action (exact or prefix)
    pub kriya_action: Option<String>,
    /// Filter by trace ID
    pub trace_id: Option<String>,
    /// Filter by time range start
    pub from_time: Option<DateTime<Utc>>,
    /// Filter by time range end
    pub to_time: Option<DateTime<Utc>>,
    /// Maximum results
    pub limit: Option<u32>,
    /// Offset for pagination
    pub offset: Option<u32>,
    /// Order by field
    pub order_by: Option<OrderBy>,
    /// Order direction
    pub order_dir: Option<OrderDirection>,
}

impl VakyaQuery {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn by_actor(mut self, pid: impl Into<String>) -> Self {
        self.karta_pid = Some(pid.into());
        self
    }

    pub fn by_resource(mut self, rid_prefix: impl Into<String>) -> Self {
        self.karma_rid_prefix = Some(rid_prefix.into());
        self
    }

    pub fn by_action(mut self, action: impl Into<String>) -> Self {
        self.kriya_action = Some(action.into());
        self
    }

    pub fn by_trace(mut self, trace_id: impl Into<String>) -> Self {
        self.trace_id = Some(trace_id.into());
        self
    }

    pub fn from(mut self, time: DateTime<Utc>) -> Self {
        self.from_time = Some(time);
        self
    }

    pub fn to(mut self, time: DateTime<Utc>) -> Self {
        self.to_time = Some(time);
        self
    }

    pub fn limit(mut self, limit: u32) -> Self {
        self.limit = Some(limit);
        self
    }

    pub fn offset(mut self, offset: u32) -> Self {
        self.offset = Some(offset);
        self
    }

    pub fn order_by(mut self, field: OrderBy, dir: OrderDirection) -> Self {
        self.order_by = Some(field);
        self.order_dir = Some(dir);
        self
    }

    /// Build SQL WHERE clause
    pub fn build_where_clause(&self) -> (String, Vec<String>) {
        let mut conditions = Vec::new();
        let mut params = Vec::new();

        if let Some(ref pid) = self.karta_pid {
            conditions.push("karta_pid = ?".to_string());
            params.push(pid.clone());
        }

        if let Some(ref karta_type) = self.karta_type {
            conditions.push("karta_type = ?".to_string());
            params.push(karta_type.clone());
        }

        if let Some(ref rid) = self.karma_rid_prefix {
            conditions.push("karma_rid LIKE ?".to_string());
            params.push(format!("{}%", rid));
        }

        if let Some(ref action) = self.kriya_action {
            if action.ends_with('*') {
                conditions.push("kriya_action LIKE ?".to_string());
                params.push(format!("{}%", &action[..action.len()-1]));
            } else {
                conditions.push("kriya_action = ?".to_string());
                params.push(action.clone());
            }
        }

        if let Some(ref trace_id) = self.trace_id {
            conditions.push("trace_id = ?".to_string());
            params.push(trace_id.clone());
        }

        if let Some(ref from) = self.from_time {
            conditions.push("created_at >= ?".to_string());
            params.push(from.to_rfc3339());
        }

        if let Some(ref to) = self.to_time {
            conditions.push("created_at < ?".to_string());
            params.push(to.to_rfc3339());
        }

        let where_clause = if conditions.is_empty() {
            "1=1".to_string()
        } else {
            conditions.join(" AND ")
        };

        (where_clause, params)
    }

    /// Build ORDER BY clause
    pub fn build_order_clause(&self) -> String {
        let field = match self.order_by {
            Some(OrderBy::CreatedAt) => "created_at",
            Some(OrderBy::VakyaId) => "vakya_id",
            Some(OrderBy::Actor) => "karta_pid",
            Some(OrderBy::Action) => "kriya_action",
            None => "created_at",
        };

        let dir = match self.order_dir {
            Some(OrderDirection::Asc) => "ASC",
            Some(OrderDirection::Desc) | None => "DESC",
        };

        format!("{} {}", field, dir)
    }

    /// Build LIMIT/OFFSET clause
    pub fn build_limit_clause(&self) -> String {
        let limit = self.limit.unwrap_or(100);
        let offset = self.offset.unwrap_or(0);
        format!("LIMIT {} OFFSET {}", limit, offset)
    }
}

/// Order by field
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrderBy {
    CreatedAt,
    VakyaId,
    Actor,
    Action,
}

/// Order direction
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrderDirection {
    Asc,
    Desc,
}

/// Query result with pagination info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryResult<T> {
    /// Result items
    pub items: Vec<T>,
    /// Total count (if available)
    pub total: Option<u64>,
    /// Current offset
    pub offset: u32,
    /// Current limit
    pub limit: u32,
    /// Has more results
    pub has_more: bool,
}

impl<T> QueryResult<T> {
    pub fn new(items: Vec<T>, offset: u32, limit: u32) -> Self {
        let has_more = items.len() as u32 >= limit;
        Self {
            items,
            total: None,
            offset,
            limit,
            has_more,
        }
    }

    pub fn with_total(mut self, total: u64) -> Self {
        self.total = Some(total);
        self.has_more = (self.offset as u64 + self.items.len() as u64) < total;
        self
    }
}

/// Aggregation query for analytics
#[derive(Debug, Clone, Default)]
pub struct AggregationQuery {
    /// Group by field
    pub group_by: Option<AggregateField>,
    /// Time bucket size (for time-based aggregation)
    pub time_bucket: Option<TimeBucket>,
    /// Filter criteria
    pub filter: VakyaQuery,
}

/// Fields to aggregate by
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AggregateField {
    Actor,
    Action,
    Resource,
    ReasonCode,
    EffectBucket,
}

/// Time bucket sizes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeBucket {
    Minute,
    Hour,
    Day,
    Week,
    Month,
}

/// Aggregation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregationResult {
    /// Group key
    pub key: String,
    /// Count
    pub count: u64,
    /// Additional metrics
    pub metrics: std::collections::HashMap<String, f64>,
}

/// Trace reconstruction query
#[derive(Debug, Clone)]
pub struct TraceQuery {
    /// Trace ID to reconstruct
    pub trace_id: String,
    /// Include effects
    pub include_effects: bool,
    /// Include receipts
    pub include_receipts: bool,
}

/// Reconstructed trace
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceReconstruction {
    /// Trace ID
    pub trace_id: String,
    /// All VĀKYA records in the trace
    pub vakyas: Vec<VakyaRecord>,
    /// Effects grouped by VĀKYA ID
    pub effects: std::collections::HashMap<String, Vec<EffectRecord>>,
    /// Receipts by VĀKYA ID
    pub receipts: std::collections::HashMap<String, ReceiptRecord>,
    /// Trace timeline
    pub timeline: Vec<TraceEvent>,
}

/// Event in a trace timeline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceEvent {
    /// Event timestamp
    pub timestamp: DateTime<Utc>,
    /// Event type
    pub event_type: TraceEventType,
    /// VĀKYA ID
    pub vakya_id: String,
    /// Span ID
    pub span_id: Option<String>,
    /// Parent span ID
    pub parent_span_id: Option<String>,
    /// Event details
    pub details: serde_json::Value,
}

/// Types of trace events
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TraceEventType {
    VakyaSubmitted,
    VakyaExecuted,
    EffectCaptured,
    ReceiptIssued,
}

/// Replay query for action replay
#[derive(Debug, Clone)]
pub struct ReplayQuery {
    /// Start from this VĀKYA ID
    pub from_vakya_id: Option<String>,
    /// End at this VĀKYA ID
    pub to_vakya_id: Option<String>,
    /// Filter by actor
    pub actor: Option<String>,
    /// Filter by resource
    pub resource: Option<String>,
    /// Time range
    pub from_time: Option<DateTime<Utc>>,
    pub to_time: Option<DateTime<Utc>>,
}

/// Replay result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayResult {
    /// VĀKYA records to replay
    pub vakyas: Vec<VakyaRecord>,
    /// Original effects for comparison
    pub original_effects: Vec<EffectRecord>,
    /// Replay instructions
    pub instructions: Vec<ReplayInstruction>,
}

/// Instruction for replaying an action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayInstruction {
    /// VĀKYA ID
    pub vakya_id: String,
    /// Action to replay
    pub action: String,
    /// Target resource
    pub resource: String,
    /// Expected before state
    pub expected_before: Option<serde_json::Value>,
    /// Expected after state
    pub expected_after: Option<serde_json::Value>,
    /// Replay mode
    pub mode: ReplayMode,
}

/// Replay modes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayMode {
    /// Execute the action
    Execute,
    /// Dry run (no side effects)
    DryRun,
    /// Verify only (check current state matches expected)
    Verify,
}

/// Rollback query
#[derive(Debug, Clone)]
pub struct RollbackQuery {
    /// VĀKYA ID to rollback
    pub vakya_id: String,
    /// Cascade to dependent actions
    pub cascade: bool,
}

/// Rollback plan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollbackPlan {
    /// VĀKYA IDs to rollback (in order)
    pub vakya_ids: Vec<String>,
    /// Rollback instructions
    pub instructions: Vec<RollbackInstruction>,
    /// Estimated impact
    pub impact: RollbackImpact,
}

/// Rollback instruction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollbackInstruction {
    /// VĀKYA ID
    pub vakya_id: String,
    /// Effect ID
    pub effect_id: String,
    /// Rollback action
    pub action: serde_json::Value,
    /// Can be automatically executed
    pub auto_executable: bool,
}

/// Rollback impact assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollbackImpact {
    /// Number of effects to rollback
    pub effect_count: usize,
    /// Resources affected
    pub resources: Vec<String>,
    /// Dependent VĀKYA IDs
    pub dependents: Vec<String>,
    /// Risk level
    pub risk_level: RiskLevel,
}

/// Risk levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vakya_query_builder() {
        let query = VakyaQuery::new()
            .by_actor("user:alice")
            .by_action("file.*")
            .limit(50);

        let (where_clause, params) = query.build_where_clause();
        assert!(where_clause.contains("karta_pid = ?"));
        assert!(where_clause.contains("kriya_action LIKE ?"));
        assert_eq!(params.len(), 2);
    }

    #[test]
    fn test_query_result_pagination() {
        let items = vec![1, 2, 3, 4, 5];
        let result = QueryResult::new(items, 0, 5);
        
        assert!(result.has_more);
        
        let result = result.with_total(5);
        assert!(!result.has_more);
    }

    #[test]
    fn test_order_clause() {
        let query = VakyaQuery::new()
            .order_by(OrderBy::CreatedAt, OrderDirection::Desc);
        
        let order = query.build_order_clause();
        assert_eq!(order, "created_at DESC");
    }
}

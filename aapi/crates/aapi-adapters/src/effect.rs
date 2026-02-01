//! Effect capture for adapters

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::collections::HashMap;

use aapi_core::types::EffectBucket;

/// Captured effect from an action execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapturedEffect {
    /// Unique effect ID
    pub effect_id: String,
    /// Associated VĀKYA ID
    pub vakya_id: String,
    /// Effect bucket type
    pub bucket: EffectBucket,
    /// Target resource identifier
    pub target: String,
    /// Target resource type
    pub target_type: Option<String>,
    /// State before the action
    pub before: Option<StateSnapshot>,
    /// State after the action
    pub after: Option<StateSnapshot>,
    /// Computed delta
    pub delta: Option<StateDelta>,
    /// Whether this effect can be reversed
    pub reversible: bool,
    /// Instructions for reversal
    pub reversal: Option<ReversalInstructions>,
    /// Effect timestamp
    pub timestamp: DateTime<Utc>,
    /// Additional metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

impl CapturedEffect {
    pub fn new(vakya_id: impl Into<String>, bucket: EffectBucket, target: impl Into<String>) -> Self {
        Self {
            effect_id: uuid::Uuid::new_v4().to_string(),
            vakya_id: vakya_id.into(),
            bucket,
            target: target.into(),
            target_type: None,
            before: None,
            after: None,
            delta: None,
            reversible: false,
            reversal: None,
            timestamp: Utc::now(),
            metadata: HashMap::new(),
        }
    }

    pub fn with_before(mut self, state: StateSnapshot) -> Self {
        self.before = Some(state);
        self
    }

    pub fn with_after(mut self, state: StateSnapshot) -> Self {
        self.after = Some(state);
        self
    }

    pub fn with_delta(mut self, delta: StateDelta) -> Self {
        self.delta = Some(delta);
        self
    }

    pub fn reversible(mut self, instructions: ReversalInstructions) -> Self {
        self.reversible = true;
        self.reversal = Some(instructions);
        self
    }

    pub fn with_metadata(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.metadata.insert(key.into(), value);
        self
    }

    /// Compute delta from before/after states
    pub fn compute_delta(&mut self) {
        if let (Some(before), Some(after)) = (&self.before, &self.after) {
            self.delta = Some(StateDelta::compute(before, after));
        }
    }
}

/// Snapshot of state at a point in time
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateSnapshot {
    /// Content hash
    pub hash: String,
    /// Size in bytes
    pub size: Option<u64>,
    /// Content type
    pub content_type: Option<String>,
    /// Actual content (if small enough to capture)
    pub content: Option<serde_json::Value>,
    /// Timestamp of snapshot
    pub timestamp: DateTime<Utc>,
    /// Additional properties
    pub properties: HashMap<String, serde_json::Value>,
}

impl StateSnapshot {
    /// Create a snapshot from bytes
    pub fn from_bytes(data: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = hex::encode(hasher.finalize());

        Self {
            hash,
            size: Some(data.len() as u64),
            content_type: None,
            content: None,
            timestamp: Utc::now(),
            properties: HashMap::new(),
        }
    }

    /// Create a snapshot from JSON value
    pub fn from_json(value: &serde_json::Value) -> Self {
        let json_bytes = serde_json::to_vec(value).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(&json_bytes);
        let hash = hex::encode(hasher.finalize());

        Self {
            hash,
            size: Some(json_bytes.len() as u64),
            content_type: Some("application/json".to_string()),
            content: Some(value.clone()),
            timestamp: Utc::now(),
            properties: HashMap::new(),
        }
    }

    /// Create a snapshot with just a hash (for large content)
    pub fn from_hash(hash: impl Into<String>, size: u64) -> Self {
        Self {
            hash: hash.into(),
            size: Some(size),
            content_type: None,
            content: None,
            timestamp: Utc::now(),
            properties: HashMap::new(),
        }
    }

    /// Create a snapshot indicating non-existence
    pub fn not_exists() -> Self {
        Self {
            hash: "NOT_EXISTS".to_string(),
            size: None,
            content_type: None,
            content: None,
            timestamp: Utc::now(),
            properties: HashMap::new(),
        }
    }

    pub fn with_content_type(mut self, content_type: impl Into<String>) -> Self {
        self.content_type = Some(content_type.into());
        self
    }

    pub fn with_property(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.properties.insert(key.into(), value);
        self
    }
}

/// Delta between two states
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateDelta {
    /// Type of change
    pub change_type: ChangeType,
    /// Hash of before state
    pub before_hash: String,
    /// Hash of after state
    pub after_hash: String,
    /// Size change in bytes
    pub size_delta: Option<i64>,
    /// JSON patch (RFC 6902) if applicable
    pub json_patch: Option<Vec<JsonPatchOp>>,
    /// Human-readable summary
    pub summary: Option<String>,
}

impl StateDelta {
    /// Compute delta between two snapshots
    pub fn compute(before: &StateSnapshot, after: &StateSnapshot) -> Self {
        let change_type = if before.hash == "NOT_EXISTS" {
            ChangeType::Created
        } else if after.hash == "NOT_EXISTS" {
            ChangeType::Deleted
        } else if before.hash == after.hash {
            ChangeType::Unchanged
        } else {
            ChangeType::Modified
        };

        let size_delta = match (before.size, after.size) {
            (Some(b), Some(a)) => Some(a as i64 - b as i64),
            _ => None,
        };

        // Compute JSON patch if both are JSON
        let json_patch = match (&before.content, &after.content) {
            (Some(b), Some(a)) => Some(compute_json_patch(b, a)),
            _ => None,
        };

        Self {
            change_type,
            before_hash: before.hash.clone(),
            after_hash: after.hash.clone(),
            size_delta,
            json_patch,
            summary: None,
        }
    }
}

/// Type of change
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChangeType {
    Created,
    Modified,
    Deleted,
    Unchanged,
}

/// JSON Patch operation (RFC 6902)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonPatchOp {
    pub op: String,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
}

/// Compute JSON patch between two values (simplified)
fn compute_json_patch(before: &serde_json::Value, after: &serde_json::Value) -> Vec<JsonPatchOp> {
    let mut ops = Vec::new();
    compute_json_patch_recursive("", before, after, &mut ops);
    ops
}

fn compute_json_patch_recursive(
    path: &str,
    before: &serde_json::Value,
    after: &serde_json::Value,
    ops: &mut Vec<JsonPatchOp>,
) {
    use serde_json::Value;

    match (before, after) {
        (Value::Object(b), Value::Object(a)) => {
            // Check for removed keys
            for key in b.keys() {
                if !a.contains_key(key) {
                    ops.push(JsonPatchOp {
                        op: "remove".to_string(),
                        path: format!("{}/{}", path, key),
                        value: None,
                        from: None,
                    });
                }
            }
            // Check for added or modified keys
            for (key, after_val) in a {
                let new_path = format!("{}/{}", path, key);
                if let Some(before_val) = b.get(key) {
                    if before_val != after_val {
                        compute_json_patch_recursive(&new_path, before_val, after_val, ops);
                    }
                } else {
                    ops.push(JsonPatchOp {
                        op: "add".to_string(),
                        path: new_path,
                        value: Some(after_val.clone()),
                        from: None,
                    });
                }
            }
        }
        (Value::Array(b), Value::Array(a)) => {
            // Simplified: just replace if different
            if b != a {
                ops.push(JsonPatchOp {
                    op: "replace".to_string(),
                    path: path.to_string(),
                    value: Some(Value::Array(a.clone())),
                    from: None,
                });
            }
        }
        _ => {
            if before != after {
                ops.push(JsonPatchOp {
                    op: "replace".to_string(),
                    path: path.to_string(),
                    value: Some(after.clone()),
                    from: None,
                });
            }
        }
    }
}

/// Instructions for reversing an effect
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReversalInstructions {
    /// Reversal method
    pub method: ReversalMethod,
    /// Data needed for reversal
    pub data: serde_json::Value,
    /// Human-readable description
    pub description: Option<String>,
}

/// Method for reversing an effect
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReversalMethod {
    /// Restore from captured before state
    RestoreState,
    /// Apply inverse operation
    InverseOperation,
    /// Delete created resource
    Delete,
    /// Recreate deleted resource
    Recreate,
    /// Custom reversal logic
    Custom,
}

/// Effect capturer for building effects during execution
pub struct EffectCapturer {
    vakya_id: String,
    effects: Vec<CapturedEffect>,
}

impl EffectCapturer {
    pub fn new(vakya_id: impl Into<String>) -> Self {
        Self {
            vakya_id: vakya_id.into(),
            effects: Vec::new(),
        }
    }

    /// Start capturing an effect
    pub fn start(&self, bucket: EffectBucket, target: impl Into<String>) -> EffectBuilder {
        EffectBuilder::new(self.vakya_id.clone(), bucket, target)
    }

    /// Add a completed effect
    pub fn add(&mut self, effect: CapturedEffect) {
        self.effects.push(effect);
    }

    /// Get all captured effects
    pub fn finish(self) -> Vec<CapturedEffect> {
        self.effects
    }
}

/// Builder for constructing effects
pub struct EffectBuilder {
    effect: CapturedEffect,
}

impl EffectBuilder {
    pub fn new(vakya_id: String, bucket: EffectBucket, target: impl Into<String>) -> Self {
        Self {
            effect: CapturedEffect::new(vakya_id, bucket, target),
        }
    }

    pub fn target_type(mut self, target_type: impl Into<String>) -> Self {
        self.effect.target_type = Some(target_type.into());
        self
    }

    pub fn before(mut self, state: StateSnapshot) -> Self {
        self.effect.before = Some(state);
        self
    }

    pub fn after(mut self, state: StateSnapshot) -> Self {
        self.effect.after = Some(state);
        self
    }

    pub fn reversible(mut self, method: ReversalMethod, data: serde_json::Value) -> Self {
        self.effect.reversible = true;
        self.effect.reversal = Some(ReversalInstructions {
            method,
            data,
            description: None,
        });
        self
    }

    pub fn metadata(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.effect.metadata.insert(key.into(), value);
        self
    }

    pub fn build(mut self) -> CapturedEffect {
        self.effect.compute_delta();
        self.effect
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_snapshot_from_bytes() {
        let data = b"hello world";
        let snapshot = StateSnapshot::from_bytes(data);
        
        assert!(!snapshot.hash.is_empty());
        assert_eq!(snapshot.size, Some(11));
    }

    #[test]
    fn test_state_snapshot_from_json() {
        let value = serde_json::json!({"key": "value"});
        let snapshot = StateSnapshot::from_json(&value);
        
        assert!(!snapshot.hash.is_empty());
        assert_eq!(snapshot.content_type, Some("application/json".to_string()));
    }

    #[test]
    fn test_delta_compute_created() {
        let before = StateSnapshot::not_exists();
        let after = StateSnapshot::from_bytes(b"new content");
        
        let delta = StateDelta::compute(&before, &after);
        assert_eq!(delta.change_type, ChangeType::Created);
    }

    #[test]
    fn test_delta_compute_deleted() {
        let before = StateSnapshot::from_bytes(b"old content");
        let after = StateSnapshot::not_exists();
        
        let delta = StateDelta::compute(&before, &after);
        assert_eq!(delta.change_type, ChangeType::Deleted);
    }

    #[test]
    fn test_delta_compute_modified() {
        let before = StateSnapshot::from_bytes(b"old");
        let after = StateSnapshot::from_bytes(b"new");
        
        let delta = StateDelta::compute(&before, &after);
        assert_eq!(delta.change_type, ChangeType::Modified);
    }

    #[test]
    fn test_json_patch() {
        let before = serde_json::json!({"a": 1, "b": 2});
        let after = serde_json::json!({"a": 1, "b": 3, "c": 4});
        
        let patch = compute_json_patch(&before, &after);
        assert!(!patch.is_empty());
    }

    #[test]
    fn test_effect_builder() {
        let effect = EffectBuilder::new(
            "vakya-123".to_string(),
            EffectBucket::Update,
            "file:/test.txt",
        )
        .target_type("file")
        .before(StateSnapshot::from_bytes(b"old"))
        .after(StateSnapshot::from_bytes(b"new"))
        .reversible(ReversalMethod::RestoreState, serde_json::json!({"backup": "path"}))
        .build();

        assert!(effect.reversible);
        assert!(effect.delta.is_some());
    }
}

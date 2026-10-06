use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

use crate::types::DriftEvent;

/// Schema inferred from JSON values
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct InferredSchema {
    pub schema_type: String, // "object", "array", "string", "number", "boolean", "null"
    pub properties: Option<HashMap<String, InferredSchema>>,
    pub items: Option<Box<InferredSchema>>,
    pub required: Vec<String>,
    pub example: Option<Value>,
}

/// Per-endpoint schema snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointSchema {
    pub host: String,
    pub path: String,
    pub method: String,
    pub request_schema: InferredSchema,
    pub response_schema: InferredSchema,
    pub status_codes: Vec<u16>,
}

/// Infer schema from any JSON value
pub fn infer_schema(value: &Value) -> InferredSchema {
    match value {
        Value::Null => InferredSchema {
            schema_type: "null".to_string(),
            ..Default::default()
        },
        Value::Bool(_) => InferredSchema {
            schema_type: "boolean".to_string(),
            example: Some(value.clone()),
            ..Default::default()
        },
        Value::Number(n) => InferredSchema {
            schema_type: if n.is_i64() { "integer".to_string() } else { "number".to_string() },
            example: Some(value.clone()),
            ..Default::default()
        },
        Value::String(s) => {
            let t = if looks_like_date(s) {
                "date-time"
            } else if looks_like_uuid(s) {
                "uuid"
            } else if looks_like_email(s) {
                "email"
            } else {
                "string"
            };
            InferredSchema {
                schema_type: t.to_string(),
                example: Some(value.clone()),
                ..Default::default()
            }
        }
        Value::Array(arr) => {
            // Infer schema from first non-null element, or merge all
            let items = arr.iter().find(|v| !v.is_null()).map(infer_schema);
            InferredSchema {
                schema_type: "array".to_string(),
                items: items.map(Box::new),
                ..Default::default()
            }
        }
        Value::Object(map) => {
            let mut props = HashMap::new();
            let mut required = Vec::new();
            for (k, v) in map {
                props.insert(k.clone(), infer_schema(v));
                required.push(k.clone());
            }
            InferredSchema {
                schema_type: "object".to_string(),
                properties: Some(props),
                required,
                ..Default::default()
            }
        }
    }
}

fn looks_like_date(s: &str) -> bool {
    // ISO 8601 patterns
    s.len() >= 10 && s.contains('-') && (s.contains('T') || s.contains(':'))
}

fn looks_like_uuid(s: &str) -> bool {
    s.len() == 36 && s.chars().filter(|&c| c == '-').count() == 4
}

fn looks_like_email(s: &str) -> bool {
    s.contains('@') && s.contains('.')
}

/// Detect drift between two schemas
pub fn detect_drift(prev: &InferredSchema, curr: &InferredSchema, path: &str) -> Vec<DriftEvent> {
    let mut drifts = Vec::new();
    detect_drift_inner(prev, curr, path, &mut drifts);
    drifts
}

fn detect_drift_inner(prev: &InferredSchema, curr: &InferredSchema, path: &str, drifts: &mut Vec<DriftEvent>) {
    use chrono::Utc;

    // Type change
    if prev.schema_type != curr.schema_type {
        drifts.push(DriftEvent {
            drift_type: "type_changed".to_string(),
            field_path: path.to_string(),
            from_type: Some(prev.schema_type.clone()),
            to_type: Some(curr.schema_type.clone()),
            detected_at: Utc::now(),
        });
    }

    // Check property changes for objects
    if let (Some(prev_props), Some(curr_props)) = (&prev.properties, &curr.properties) {
        // New fields added
        for (key, curr_schema) in curr_props {
            let child_path = format!("{}.{}", path, key);
            if let Some(prev_schema) = prev_props.get(key) {
                // Existing field - recurse
                detect_drift_inner(prev_schema, curr_schema, &child_path, drifts);
            } else {
                // New field
                drifts.push(DriftEvent {
                    drift_type: "new_field_added".to_string(),
                    field_path: child_path,
                    from_type: None,
                    to_type: Some(curr_schema.schema_type.clone()),
                    detected_at: Utc::now(),
                });
            }
        }

        // Fields removed
        for key in prev_props.keys() {
            if !curr_props.contains_key(key) {
                let child_path = format!("{}.{}", path, key);
                drifts.push(DriftEvent {
                    drift_type: "field_removed".to_string(),
                    field_path: child_path,
                    from_type: Some(prev_props[key].schema_type.clone()),
                    to_type: None,
                    detected_at: Utc::now(),
                });
            }
        }
    }

    // Check array items
    if let (Some(prev_items), Some(curr_items)) = (&prev.items, &curr.items) {
        detect_drift_inner(prev_items, curr_items, &format!("{}[]", path), drifts);
    }
}

/// Convert InferredSchema to JSON Schema format
pub fn to_json_schema(schema: &InferredSchema) -> Value {
    let mut obj = serde_json::Map::new();
    obj.insert("type".to_string(), Value::String(schema.schema_type.clone()));

    if let Some(props) = &schema.properties {
        let mut props_obj = serde_json::Map::new();
        for (k, v) in props {
            props_obj.insert(k.clone(), to_json_schema(v));
        }
        obj.insert("properties".to_string(), Value::Object(props_obj));
    }

    if let Some(items) = &schema.items {
        obj.insert("items".to_string(), to_json_schema(items));
    }

    if !schema.required.is_empty() {
        obj.insert("required".to_string(),
            Value::Array(schema.required.iter().map(|s| Value::String(s.clone())).collect()));
    }

    Value::Object(obj)
}

/// Merge two schemas (union of properties, broader types)
pub fn merge_schemas(a: &InferredSchema, b: &InferredSchema) -> InferredSchema {
    if a.schema_type != b.schema_type {
        // Different types - return a more permissive "anyOf" style
        // For simplicity, just keep the newer one
        return b.clone();
    }

    match (a.schema_type.as_str(), &a.properties, &b.properties) {
        ("object", Some(a_props), Some(b_props)) => {
            let mut merged_props = a_props.clone();
            for (k, v) in b_props {
                if let Some(existing) = merged_props.get(k) {
                    merged_props.insert(k.clone(), merge_schemas(existing, v));
                } else {
                    merged_props.insert(k.clone(), v.clone());
                }
            }

            let mut required: Vec<String> = a.required.iter().cloned().collect();
            for r in &b.required {
                if !required.contains(r) {
                    required.push(r.clone());
                }
            }

            InferredSchema {
                schema_type: "object".to_string(),
                properties: Some(merged_props),
                required,
                example: b.example.clone().or_else(|| a.example.clone()),
                ..Default::default()
            }
        }
        _ => b.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_infer_simple() {
        let v = json!({"name": "Alice", "age": 30, "active": true});
        let schema = infer_schema(&v);
        assert_eq!(schema.schema_type, "object");
        assert!(schema.properties.is_some());
        let props = schema.properties.unwrap();
        assert_eq!(props["name"].schema_type, "string");
        assert_eq!(props["age"].schema_type, "integer");
        assert_eq!(props["active"].schema_type, "boolean");
    }

    #[test]
    fn test_detect_new_field() {
        let old = json!({"name": "Alice"});
        let new = json!({"name": "Alice", "email": "a@example.com"});
        let prev = infer_schema(&old);
        let curr = infer_schema(&new);
        let drifts = detect_drift(&prev, &curr, "root");
        assert_eq!(drifts.len(), 1);
        assert_eq!(drifts[0].drift_type, "new_field_added");
        assert_eq!(drifts[0].field_path, "root.email");
    }
}

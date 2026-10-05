//! Label Selectors
//!
//! Kubernetes-compatible label selection for grouping and filtering agents.
//!
//! # Example
//!
//! ```yaml
//! selector:
//!   matchLabels:
//!     app: triage
//!     tier: frontend
//!   matchExpressions:
//!   - key: environment
//!     operator: In
//!     values: [production, staging]
//!   - key: deprecated
//!     operator: DoesNotExist
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Label selector (like K8s LabelSelector)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LabelSelector {
    /// Equality-based requirements
    #[serde(default)]
    pub match_labels: HashMap<String, String>,
    /// Set-based requirements
    #[serde(default)]
    pub match_expressions: Vec<LabelSelectorRequirement>,
}

impl LabelSelector {
    /// Create a selector from simple label matches
    pub fn from_labels(labels: HashMap<String, String>) -> Self {
        Self {
            match_labels: labels,
            match_expressions: Vec::new(),
        }
    }

    /// Check if labels match this selector
    pub fn matches(&self, labels: &HashMap<String, String>) -> bool {
        // Check matchLabels (all must match)
        for (key, value) in &self.match_labels {
            match labels.get(key) {
                Some(v) if v == value => continue,
                _ => return false,
            }
        }

        // Check matchExpressions (all must match)
        for expr in &self.match_expressions {
            if !expr.matches(labels) {
                return false;
            }
        }

        true
    }

    /// Check if selector is empty (matches everything)
    pub fn is_empty(&self) -> bool {
        self.match_labels.is_empty() && self.match_expressions.is_empty()
    }

    /// Convert to string representation (for display)
    pub fn to_selector_string(&self) -> String {
        let mut parts = Vec::new();

        for (k, v) in &self.match_labels {
            parts.push(format!("{}={}", k, v));
        }

        for expr in &self.match_expressions {
            parts.push(expr.to_string());
        }

        parts.join(",")
    }

    /// Parse from string (e.g., "app=triage,tier=frontend")
    pub fn parse(s: &str) -> Result<Self, String> {
        let mut match_labels = HashMap::new();
        let mut match_expressions = Vec::new();

        for part in s.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }

            if part.contains(" in ") || part.contains(" notin ") {
                // Set-based expression
                match_expressions.push(LabelSelectorRequirement::parse(part)?);
            } else if part.contains("!=") {
                // NotEquals
                let mut split = part.splitn(2, "!=");
                let key = split.next().unwrap().trim();
                let value = split.next().ok_or("Missing value after !=")?;
                match_expressions.push(LabelSelectorRequirement {
                    key: key.to_string(),
                    operator: LabelSelectorOperator::NotIn,
                    values: vec![value.trim().to_string()],
                });
            } else if part.contains('=') {
                // Equals
                let mut split = part.splitn(2, '=');
                let key = split.next().unwrap().trim();
                let value = split.next().ok_or("Missing value after =")?;
                match_labels.insert(key.to_string(), value.trim().to_string());
            } else if part.starts_with('!') {
                // DoesNotExist
                match_expressions.push(LabelSelectorRequirement {
                    key: part[1..].to_string(),
                    operator: LabelSelectorOperator::DoesNotExist,
                    values: Vec::new(),
                });
            } else {
                // Exists
                match_expressions.push(LabelSelectorRequirement {
                    key: part.to_string(),
                    operator: LabelSelectorOperator::Exists,
                    values: Vec::new(),
                });
            }
        }

        Ok(Self { match_labels, match_expressions })
    }
}

/// Label selector requirement (set-based)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabelSelectorRequirement {
    /// Label key
    pub key: String,
    /// Operator
    pub operator: LabelSelectorOperator,
    /// Values (for In/NotIn)
    #[serde(default)]
    pub values: Vec<String>,
}

impl LabelSelectorRequirement {
    /// Check if labels match this requirement
    pub fn matches(&self, labels: &HashMap<String, String>) -> bool {
        match &self.operator {
            LabelSelectorOperator::In => {
                match labels.get(&self.key) {
                    Some(v) => self.values.contains(v),
                    None => false,
                }
            }
            LabelSelectorOperator::NotIn => {
                match labels.get(&self.key) {
                    Some(v) => !self.values.contains(v),
                    None => true, // key not present = not in values
                }
            }
            LabelSelectorOperator::Exists => {
                labels.contains_key(&self.key)
            }
            LabelSelectorOperator::DoesNotExist => {
                !labels.contains_key(&self.key)
            }
        }
    }

    /// Parse from string (e.g., "env in (prod, staging)")
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();

        if let Some(idx) = s.find(" in ") {
            let key = s[..idx].trim().to_string();
            let values_str = s[idx + 4..].trim();
            let values = parse_values(values_str)?;
            return Ok(Self {
                key,
                operator: LabelSelectorOperator::In,
                values,
            });
        }

        if let Some(idx) = s.find(" notin ") {
            let key = s[..idx].trim().to_string();
            let values_str = s[idx + 7..].trim();
            let values = parse_values(values_str)?;
            return Ok(Self {
                key,
                operator: LabelSelectorOperator::NotIn,
                values,
            });
        }

        Err(format!("Cannot parse label expression: {}", s))
    }
}

fn parse_values(s: &str) -> Result<Vec<String>, String> {
    let s = s.trim();
    let s = s.strip_prefix('(').unwrap_or(s);
    let s = s.strip_suffix(')').unwrap_or(s);
    Ok(s.split(',').map(|v| v.trim().to_string()).collect())
}

impl std::fmt::Display for LabelSelectorRequirement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.operator {
            LabelSelectorOperator::In => {
                write!(f, "{} in ({})", self.key, self.values.join(", "))
            }
            LabelSelectorOperator::NotIn => {
                write!(f, "{} notin ({})", self.key, self.values.join(", "))
            }
            LabelSelectorOperator::Exists => {
                write!(f, "{}", self.key)
            }
            LabelSelectorOperator::DoesNotExist => {
                write!(f, "!{}", self.key)
            }
        }
    }
}

/// Label selector operator
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LabelSelectorOperator {
    /// Value must be in set
    In,
    /// Value must not be in set
    NotIn,
    /// Key must exist
    Exists,
    /// Key must not exist
    DoesNotExist,
}

/// Well-known labels (like K8s well-known labels)
pub mod well_known {
    /// Application name
    pub const APP_NAME: &str = "app.connector.io/name";
    /// Application instance
    pub const APP_INSTANCE: &str = "app.connector.io/instance";
    /// Application version
    pub const APP_VERSION: &str = "app.connector.io/version";
    /// Application component
    pub const APP_COMPONENT: &str = "app.connector.io/component";
    /// Application part-of
    pub const APP_PART_OF: &str = "app.connector.io/part-of";
    /// Managed by
    pub const APP_MANAGED_BY: &str = "app.connector.io/managed-by";

    /// Cell hostname
    pub const CELL_HOSTNAME: &str = "connector.io/cell-hostname";
    /// Cell region
    pub const CELL_REGION: &str = "connector.io/cell-region";
    /// Cell zone
    pub const CELL_ZONE: &str = "connector.io/cell-zone";
    /// Cell instance type
    pub const CELL_INSTANCE_TYPE: &str = "connector.io/cell-instance-type";

    /// Agent model
    pub const AGENT_MODEL: &str = "connector.io/agent-model";
    /// Agent framework
    pub const AGENT_FRAMEWORK: &str = "connector.io/agent-framework";
    /// Agent role
    pub const AGENT_ROLE: &str = "connector.io/agent-role";
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_labels(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn test_match_labels() {
        let selector = LabelSelector {
            match_labels: make_labels(&[("app", "triage"), ("tier", "frontend")]),
            match_expressions: Vec::new(),
        };

        // Exact match
        assert!(selector.matches(&make_labels(&[
            ("app", "triage"),
            ("tier", "frontend"),
        ])));

        // Extra labels OK
        assert!(selector.matches(&make_labels(&[
            ("app", "triage"),
            ("tier", "frontend"),
            ("version", "v1"),
        ])));

        // Missing label
        assert!(!selector.matches(&make_labels(&[
            ("app", "triage"),
        ])));

        // Wrong value
        assert!(!selector.matches(&make_labels(&[
            ("app", "triage"),
            ("tier", "backend"),
        ])));
    }

    #[test]
    fn test_match_expressions_in() {
        let selector = LabelSelector {
            match_labels: HashMap::new(),
            match_expressions: vec![
                LabelSelectorRequirement {
                    key: "env".to_string(),
                    operator: LabelSelectorOperator::In,
                    values: vec!["prod".to_string(), "staging".to_string()],
                },
            ],
        };

        assert!(selector.matches(&make_labels(&[("env", "prod")])));
        assert!(selector.matches(&make_labels(&[("env", "staging")])));
        assert!(!selector.matches(&make_labels(&[("env", "dev")])));
        assert!(!selector.matches(&make_labels(&[])));
    }

    #[test]
    fn test_match_expressions_notin() {
        let selector = LabelSelector {
            match_labels: HashMap::new(),
            match_expressions: vec![
                LabelSelectorRequirement {
                    key: "env".to_string(),
                    operator: LabelSelectorOperator::NotIn,
                    values: vec!["dev".to_string()],
                },
            ],
        };

        assert!(selector.matches(&make_labels(&[("env", "prod")])));
        assert!(selector.matches(&make_labels(&[]))); // key not present = OK
        assert!(!selector.matches(&make_labels(&[("env", "dev")])));
    }

    #[test]
    fn test_match_expressions_exists() {
        let selector = LabelSelector {
            match_labels: HashMap::new(),
            match_expressions: vec![
                LabelSelectorRequirement {
                    key: "version".to_string(),
                    operator: LabelSelectorOperator::Exists,
                    values: Vec::new(),
                },
            ],
        };

        assert!(selector.matches(&make_labels(&[("version", "v1")])));
        assert!(selector.matches(&make_labels(&[("version", "")])));
        assert!(!selector.matches(&make_labels(&[])));
    }

    #[test]
    fn test_match_expressions_does_not_exist() {
        let selector = LabelSelector {
            match_labels: HashMap::new(),
            match_expressions: vec![
                LabelSelectorRequirement {
                    key: "deprecated".to_string(),
                    operator: LabelSelectorOperator::DoesNotExist,
                    values: Vec::new(),
                },
            ],
        };

        assert!(selector.matches(&make_labels(&[])));
        assert!(selector.matches(&make_labels(&[("app", "test")])));
        assert!(!selector.matches(&make_labels(&[("deprecated", "true")])));
    }

    #[test]
    fn test_parse_simple() {
        let selector = LabelSelector::parse("app=triage,tier=frontend").unwrap();
        assert_eq!(selector.match_labels.get("app"), Some(&"triage".to_string()));
        assert_eq!(selector.match_labels.get("tier"), Some(&"frontend".to_string()));
    }

    #[test]
    fn test_parse_in_expression() {
        let req = LabelSelectorRequirement::parse("env in (prod, staging)").unwrap();
        assert_eq!(req.key, "env");
        assert_eq!(req.operator, LabelSelectorOperator::In);
        assert_eq!(req.values, vec!["prod", "staging"]);
    }

    #[test]
    fn test_empty_selector_matches_all() {
        let selector = LabelSelector::default();
        assert!(selector.is_empty());
        assert!(selector.matches(&make_labels(&[("any", "label")])));
        assert!(selector.matches(&make_labels(&[])));
    }

    #[test]
    fn test_to_selector_string() {
        let selector = LabelSelector {
            match_labels: make_labels(&[("app", "triage")]),
            match_expressions: vec![
                LabelSelectorRequirement {
                    key: "env".to_string(),
                    operator: LabelSelectorOperator::In,
                    values: vec!["prod".to_string()],
                },
            ],
        };
        let s = selector.to_selector_string();
        assert!(s.contains("app=triage"));
        assert!(s.contains("env in (prod)"));
    }
}

//! Provenance lineage — derived values retain parents; gate checks acceptable ancestry.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ProvenanceLineage {
    /// Digests of parent observations / packets (oldest first).
    pub parents: Vec<String>,
    /// Digest of this node.
    pub node: String,
    /// Optional class tag (e.g. pate_atu, memory, broker).
    pub class: String,
}

impl ProvenanceLineage {
    pub fn leaf(class: impl Into<String>, material: &str) -> Self {
        let class = class.into();
        let node = hex_digest(&json!({ "class": class, "material": material }));
        Self {
            parents: Vec::new(),
            node,
            class,
        }
    }

    pub fn derive(&self, class: impl Into<String>, material: &str) -> Self {
        let class = class.into();
        let mut parents = self.parents.clone();
        parents.push(self.node.clone());
        let node = hex_digest(&json!({
            "class": class,
            "material": material,
            "parents": parents,
        }));
        Self {
            parents,
            node,
            class,
        }
    }

    pub fn as_label(&self) -> String {
        if self.node.is_empty() {
            "unknown".into()
        } else {
            format!("{}:{}", self.class, &self.node[..8.min(self.node.len())])
        }
    }
}

fn hex_digest(v: &Value) -> String {
    format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(v).unwrap_or_default())
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvVerdict {
    Allow,
    DenyMissingParent { required: String },
    DenyEmpty,
    DenyUnknown,
}

/// Sink accepts flow if every required parent is present in data lineage,
/// or if sink requires no specific parents (`required_parents` empty) and data has a node.
pub fn may_flow(data: &ProvenanceLineage, required_parents: &[String]) -> ProvVerdict {
    if data.node.is_empty() && data.class.is_empty() {
        return ProvVerdict::DenyEmpty;
    }
    for req in required_parents {
        if req.is_empty() {
            continue;
        }
        if !data.parents.iter().any(|p| p == req) && data.node != *req {
            return ProvVerdict::DenyMissingParent {
                required: req.clone(),
            };
        }
    }
    ProvVerdict::Allow
}

/// Label form used on IfcTriple.provenance (class or class:prefix).
pub fn may_flow_labels(data_label: &str, sink_accepts: &str) -> ProvVerdict {
    if data_label.is_empty() || data_label == "unknown" {
        return ProvVerdict::DenyUnknown;
    }
    // Sink "any" / "lab" / matching class prefix accepts.
    let sink = sink_accepts.trim().to_ascii_lowercase();
    if sink.is_empty() || sink == "any" || sink == "lab" || sink == "*" {
        return ProvVerdict::Allow;
    }
    let data = data_label.trim().to_ascii_lowercase();
    if data == sink || data.starts_with(&sink) || sink.starts_with(&data) {
        ProvVerdict::Allow
    } else if data.starts_with("pate") && sink.contains("pate") {
        ProvVerdict::Allow
    } else {
        ProvVerdict::DenyMissingParent {
            required: sink_accepts.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lineage_derive_retains_parent() {
        let root = ProvenanceLineage::leaf("obs", "hello");
        let child = root.derive("tool", "args");
        assert_eq!(child.parents, vec![root.node.clone()]);
        assert_ne!(child.node, root.node);
    }

    #[test]
    fn missing_parent_denied() {
        let leaf = ProvenanceLineage::leaf("obs", "x");
        let v = may_flow(&leaf, &["missing-parent-digest".into()]);
        assert!(matches!(v, ProvVerdict::DenyMissingParent { .. }));
    }
}

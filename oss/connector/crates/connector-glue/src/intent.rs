//! GlueIntent - Transport-neutral intent representation

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::{Verb, Noun, Selector};

/// A transport-neutral intent object representing developer action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlueIntent {
    /// The action verb (run, remember, recall, etc.)
    pub verb: Verb,
    /// The target noun (agent, memory, tool, etc.)
    pub noun: Noun,
    /// Target identifier
    pub target: String,
    /// Selectors (@agent, #session, ns:...)
    pub selectors: Vec<Selector>,
    /// Modifiers (policy, timeout, etc.)
    pub modifiers: HashMap<String, serde_json::Value>,
    /// Scope/namespace
    pub scope: Option<String>,
    /// Policy context
    pub policy_context: Option<String>,
    /// Input parameters
    pub inputs: HashMap<String, serde_json::Value>,
}

impl GlueIntent {
    pub fn new(verb: Verb, noun: Noun, target: impl Into<String>) -> Self {
        Self {
            verb,
            noun,
            target: target.into(),
            selectors: Vec::new(),
            modifiers: HashMap::new(),
            scope: None,
            policy_context: None,
            inputs: HashMap::new(),
        }
    }

    pub fn with_selector(mut self, selector: Selector) -> Self {
        self.selectors.push(selector);
        self
    }

    pub fn with_modifier<K: Into<String>, V: Serialize>(mut self, key: K, value: V) -> Self {
        if let Ok(v) = serde_json::to_value(value) {
            self.modifiers.insert(key.into(), v);
        }
        self
    }

    pub fn with_scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = Some(scope.into());
        self
    }

    pub fn with_policy(mut self, policy: impl Into<String>) -> Self {
        self.policy_context = Some(policy.into());
        self
    }

    pub fn with_input<K: Into<String>, V: Serialize>(mut self, key: K, value: V) -> Self {
        if let Ok(v) = serde_json::to_value(value) {
            self.inputs.insert(key.into(), v);
        }
        self
    }

    /// Convert to canonical string representation
    pub fn to_canonical(&self) -> String {
        let mut parts = vec![
            self.verb.as_str().to_string(),
            self.noun.as_str().to_string(),
            self.target.clone(),
        ];
        for sel in &self.selectors {
            parts.push(sel.to_string());
        }
        parts.join(" ")
    }
}

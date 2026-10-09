//! relay.yaml parser and policy enforcement helpers.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::types::{BudgetPolicy, PolicyConfig};

/// Top-level relay.yaml structure.
#[derive(Debug, Deserialize)]
pub struct RelayYaml {
    pub version:   Option<String>,
    pub functions: Vec<FunctionDef>,
}

#[derive(Debug, Deserialize)]
pub struct FunctionDef {
    pub name:         String,
    pub uri:          String,
    pub description:  Option<String>,
    pub policy:       Option<PolicyConfig>,
    pub instructions: Option<String>,
    pub identity:     Option<IdentityDef>,
    pub health:       Option<HealthDef>,
}

#[derive(Debug, Deserialize)]
pub struct IdentityDef {
    pub sponsor_email:           Option<String>,
    pub auto_register_passport:  Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct HealthDef {
    pub path:          Option<String>,
    pub interval_secs: Option<u64>,
}

/// Parse a relay.yaml file from disk.
pub fn parse_file(path: &Path) -> Result<RelayYaml> {
    let content = std::fs::read_to_string(path)?;
    let yaml: RelayYaml = serde_yaml::from_str(&content)?;
    Ok(yaml)
}

/// Parse relay.yaml from a string (API body upload).
pub fn parse_str(content: &str) -> Result<RelayYaml> {
    let yaml: RelayYaml = serde_yaml::from_str(content)?;
    Ok(yaml)
}

/// Enforce model allow-list: return true if the requested model is permitted.
pub fn model_allowed(policy: &PolicyConfig, model: &str) -> bool {
    match &policy.allowed_models {
        Some(list) if !list.is_empty() => list.iter().any(|m| m == model),
        _ => true,
    }
}

/// Enforce tool allow/deny lists.
/// Returns (allowed_tools, denied_tools) from a proposed set of tool names.
pub fn filter_tools(policy: &PolicyConfig, requested: &[String]) -> (Vec<String>, Vec<String>) {
    let mut allowed = Vec::new();
    let mut denied  = Vec::new();

    for tool in requested {
        let explicitly_denied = policy.deny_tools
            .as_ref()
            .map(|d| d.iter().any(|dt| tool.starts_with(dt.as_str())))
            .unwrap_or(false);

        let explicitly_allowed = policy.tools
            .as_ref()
            .map(|a| a.iter().any(|at| tool.starts_with(at.as_str())))
            .unwrap_or(true); // allow-all if no list specified

        if explicitly_denied || !explicitly_allowed {
            denied.push(tool.clone());
        } else {
            allowed.push(tool.clone());
        }
    }

    (allowed, denied)
}

/// Check if the per-call token limit would be exceeded.
pub fn check_token_budget(policy: &PolicyConfig, tokens_estimated: i32) -> bool {
    match policy.budget.as_ref().and_then(|b| b.per_call_tokens) {
        Some(limit) => tokens_estimated <= limit,
        None => true,
    }
}

/// Default policy with sensible safe limits.
pub fn default_policy() -> PolicyConfig {
    PolicyConfig {
        allowed_models: None,
        budget: Some(BudgetPolicy {
            per_call_tokens: Some(4000),
            per_day_usd:     Some(50.0),
            per_month_usd:   None,
            on_exceed:       Some("deny".into()),
        }),
        tools:          None,
        deny_tools:     Some(vec!["exec".into(), "git_commit".into(), "file_write".into()]),
        require_role:   None,
        hipaa:          Some(false),
        pii_redact:     Some(false),
        timeout_secs:   Some(30),
        require_approval_above_risk: None,
    }
}

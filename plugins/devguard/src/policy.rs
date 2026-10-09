//! Policy compiler — compiles devguard.yaml → Connector AAPI rules.
//!
//! DevGuard's policy format (roles, assignments, RBAC) is application-level.
//! This module compiles it into generic Connector admission rules.
//! The compiled rules are submitted to Connector via POST /api/v1/admission/rules.

use crate::config::{DevGuardConfig, ResolvedRole};
use anyhow::Result;

/// Compiled policy ready to be submitted to Connector.
#[derive(Debug, Clone)]
pub struct CompiledPolicy {
    pub fingerprint: String,
    pub admission_rules: Vec<serde_json::Value>,
}

/// Compile a DevGuardConfig + resolved role into Connector admission rules.
pub fn compile(config: &DevGuardConfig, resolved: &ResolvedRole) -> Result<CompiledPolicy> {
    let mut rules = Vec::new();
    let rc = &resolved.config;

    // File read rules
    for pattern in &rc.files.read {
        rules.push(serde_json::json!({
            "type": "file_read",
            "pattern": pattern,
            "verdict": "allow",
        }));
    }

    // File write rules
    for pattern in &rc.files.write {
        rules.push(serde_json::json!({
            "type": "file_write",
            "pattern": pattern,
            "verdict": "allow",
        }));
    }

    // File hidden rules (deny read + write)
    for pattern in &rc.files.hidden {
        rules.push(serde_json::json!({
            "type": "file_read",
            "pattern": pattern,
            "verdict": "deny",
            "reason": "hidden by policy",
        }));
        rules.push(serde_json::json!({
            "type": "file_write",
            "pattern": pattern,
            "verdict": "deny",
            "reason": "hidden by policy",
        }));
    }

    // Command allow rules
    for pattern in &rc.execution.allow {
        rules.push(serde_json::json!({
            "type": "command_exec",
            "pattern": pattern,
            "verdict": "allow",
        }));
    }

    // Command deny rules
    for pattern in &rc.execution.deny {
        rules.push(serde_json::json!({
            "type": "command_exec",
            "pattern": pattern,
            "verdict": "deny",
            "reason": "denied by policy",
        }));
    }

    // Command approval rules
    for pattern in &rc.execution.require_approval {
        rules.push(serde_json::json!({
            "type": "command_exec",
            "pattern": pattern,
            "verdict": "require_approval",
        }));
    }

    // Branch rules
    for pattern in &rc.branches.deny {
        rules.push(serde_json::json!({
            "type": "git_push",
            "pattern": pattern,
            "verdict": "deny",
            "reason": "branch protected by policy",
        }));
    }

    // Network rules
    for host in &rc.network.allow {
        rules.push(serde_json::json!({
            "type": "network",
            "host": host,
            "verdict": "allow",
        }));
    }
    for host in &rc.network.deny {
        rules.push(serde_json::json!({
            "type": "network",
            "host": host,
            "verdict": "deny",
        }));
    }

    Ok(CompiledPolicy {
        fingerprint: config.fingerprint(),
        admission_rules: rules,
    })
}

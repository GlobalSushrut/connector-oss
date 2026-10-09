//! Risk Engine — scores every CanonicalAction against the resolved role policy.

use crate::action::*;
use crate::config::{RoleConfig, DevGuardConfig};
use std::path::Path;

pub mod file_risk;
pub mod command_risk;
pub mod git_risk;
pub mod network_risk;

/// Assess risk of a CanonicalAction against a compiled role.
pub fn assess(action: &CanonicalAction, role: &RoleConfig, config: &DevGuardConfig) -> RiskAssessment {
    match action {
        CanonicalAction::FileRead { path } => file_risk::assess_file_read(path, role),
        CanonicalAction::FileWrite { path, lines_changed, .. } => file_risk::assess_file_write(path, *lines_changed, role),
        CanonicalAction::FileDelete { path } => file_risk::assess_file_delete(path, role),
        CanonicalAction::FileRename { from, to } => file_risk::assess_file_rename(from, to, role),
        CanonicalAction::PatchApply { path, lines_added, lines_removed, .. } =>
            file_risk::assess_patch(path, *lines_added, *lines_removed, role),
        CanonicalAction::CommandExec { command, .. } => command_risk::assess_command(command, role, config),
        CanonicalAction::GitOp { operation, args } => git_risk::assess_git(operation, args, role, config),
        CanonicalAction::NetworkRequest { host, port, .. } => network_risk::assess_network(host, *port, role),
        CanonicalAction::SecretAccess { key_name, .. } => network_risk::assess_secret(key_name, role),
        CanonicalAction::PackageInstall { package, .. } => command_risk::assess_package(package, role),
        CanonicalAction::DeployAction { command, .. } => command_risk::assess_deploy(command, role),
        CanonicalAction::LlmCall { cost_usd, .. } => network_risk::assess_llm(*cost_usd, role),
        CanonicalAction::SearchCode { .. } | CanonicalAction::ContextRequest { .. } => low_risk("Read-only"),
        CanonicalAction::ToolInvoke { tool_name, .. } => command_risk::assess_tool_invoke(tool_name),
        CanonicalAction::SessionStart { .. } | CanonicalAction::SessionStop { .. } => low_risk("Lifecycle"),
    }
}

// ── Shared helpers ────────────────────────────────────────────────────────

pub fn low_risk(reason: &str) -> RiskAssessment {
    RiskAssessment {
        level: RiskLevel::Low, score: 5,
        reasons: vec![reason.into()], affected_paths: vec![],
        requires_approval: false, approval_from: vec![],
    }
}

pub fn low_risk_path(reason: &str, path: &Path) -> RiskAssessment {
    RiskAssessment {
        level: RiskLevel::Low, score: 5,
        reasons: vec![reason.into()], affected_paths: vec![path.to_path_buf()],
        requires_approval: false, approval_from: vec![],
    }
}

pub fn score_to_level(score: u8) -> RiskLevel {
    match score {
        0..=25 => RiskLevel::Low,
        26..=50 => RiskLevel::Medium,
        51..=75 => RiskLevel::High,
        _ => RiskLevel::Critical,
    }
}

pub fn matches_any(value: &str, patterns: &[String]) -> bool {
    for p in patterns {
        if p == "*" { return true; }
        if let Ok(glob) = glob::Pattern::new(p) {
            if glob.matches(value) { return true; }
        }
        // Handle trailing wildcard: "cargo*" matches "cargo build"
        if p.ends_with('*') {
            let prefix = p.trim_end_matches('*');
            if value.starts_with(prefix) { return true; }
        }
    }
    false
}

pub fn is_sensitive_path(path: &str) -> bool {
    let sensitive = ["auth", "billing", "payment", "infra", "migration",
        "security", "secrets", "deploy", "prod", ".env", "key", "pem", "credentials"];
    sensitive.iter().any(|s| path.to_lowercase().contains(s))
}

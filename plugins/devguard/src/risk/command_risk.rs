//! Command execution risk assessment.

use crate::action::*;
use crate::config::{RoleConfig, DevGuardConfig};
use super::{matches_any, score_to_level};

pub fn assess_command(command: &str, role: &RoleConfig, config: &DevGuardConfig) -> RiskAssessment {
    // 1. Extracted hard-stop classifier from exec_guard.
    if let Some((verdict, reason, _network)) = crate::guard_patterns::classify_command(command) {
        let score = match verdict {
            crate::guard_patterns::PatternVerdict::Deny => 100,
            crate::guard_patterns::PatternVerdict::Flagged => 95,
        };
        return RiskAssessment {
            level: RiskLevel::Critical,
            score,
            reasons: vec![format!("Dangerous command pattern: {}", reason)],
            affected_paths: vec![],
            requires_approval: false,
            approval_from: vec![],
        };
    }

    // 2. Explicit deny (non-wildcard) always wins
    let explicit_deny = role.execution.deny.iter()
        .filter(|p| *p != "*")
        .any(|p| {
            if let Ok(glob) = glob::Pattern::new(p) { glob.matches(command) }
            else if p.ends_with('*') { command.starts_with(p.trim_end_matches('*')) }
            else { command == *p }
        });
    if explicit_deny {
        return RiskAssessment {
            level: RiskLevel::Critical, score: 95,
            reasons: vec![format!("'{}' explicitly denied", command)],
            affected_paths: vec![], requires_approval: false, approval_from: vec![],
        };
    }

    // 3. Check allow list — explicit allow overrides wildcard deny
    let in_allow = matches_any(command, &role.execution.allow);

    // 4. Require-approval list
    if matches_any(command, &role.execution.require_approval) {
        return RiskAssessment {
            level: RiskLevel::High, score: 65,
            reasons: vec![format!("'{}' requires approval", command)],
            affected_paths: vec![], requires_approval: true,
            approval_from: vec!["senior".into()],
        };
    }

    // 5. If in allow list → allowed (with risk scoring)
    if in_allow {
        let mut score: u8 = 10;
        let mut reasons = vec!["In allow list".into()];

        if command.starts_with("sudo ") { score += 40; reasons.push("sudo elevation".into()); }
        if command.contains('|') { score += 10; reasons.push("Piped command".into()); }
        if command.contains(" &") || command.ends_with('&') { score += 10; reasons.push("Background process".into()); }
        if is_network_command(command) { score += 15; reasons.push("Network egress".into()); }

        return RiskAssessment {
            level: score_to_level(score), score, reasons,
            affected_paths: vec![], requires_approval: false, approval_from: vec![],
        };
    }

    // 6. Wildcard deny or deny-by-default
    let has_wildcard_deny = role.execution.deny.iter().any(|p| p == "*");
    if has_wildcard_deny {
        return RiskAssessment {
            level: RiskLevel::High, score: 75,
            reasons: vec![format!("'{}' not in allow list (deny-all policy)", command)],
            affected_paths: vec![], requires_approval: false, approval_from: vec![],
        };
    }

    // 7. Not in any list — deny by default
    RiskAssessment {
        level: RiskLevel::High, score: 75,
        reasons: vec![format!("'{}' not in allow list (deny-by-default)", command)],
        affected_paths: vec![], requires_approval: false, approval_from: vec![],
    }
}

pub fn assess_package(package: &str, role: &RoleConfig) -> RiskAssessment {
    let mut score: u8 = 35;
    let mut reasons = vec![format!("Package install: {}", package)];
    if package.contains("..") || package.starts_with('/') {
        score = 90; reasons.push("Suspicious package path".into());
    }
    RiskAssessment {
        level: score_to_level(score), score, reasons,
        affected_paths: vec![], requires_approval: score >= 50,
        approval_from: if score >= 50 { vec!["senior".into()] } else { vec![] },
    }
}

pub fn assess_deploy(command: &str, role: &RoleConfig) -> RiskAssessment {
    // All deploy actions are at least HIGH risk
    let mut score: u8 = 70;
    let mut reasons = vec![format!("Deploy action: {}", command)];

    if command.contains("production") || command.contains("prod") {
        score = 95; reasons.push("Production target".into());
    }
    if command.contains("destroy") || command.contains("delete") {
        score = 90; reasons.push("Destructive operation".into());
    }

    RiskAssessment {
        level: score_to_level(score), score, reasons,
        affected_paths: vec![], requires_approval: true,
        approval_from: vec!["tech_lead".into(), "ops_lead".into()],
    }
}

pub fn assess_tool_invoke(tool_name: &str) -> RiskAssessment {
    RiskAssessment {
        level: RiskLevel::Low, score: 15,
        reasons: vec![format!("Tool invocation: {}", tool_name)],
        affected_paths: vec![], requires_approval: false, approval_from: vec![],
    }
}

fn is_network_command(cmd: &str) -> bool {
    crate::guard_patterns::has_network_egress(cmd) || cmd.contains("http ")
}

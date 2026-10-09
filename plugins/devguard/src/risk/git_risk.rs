//! Git operation risk assessment.

use crate::action::*;
use crate::config::{RoleConfig, DevGuardConfig};
use super::{matches_any, score_to_level};

pub fn assess_git(op: &GitOperation, args: &[String], role: &RoleConfig, config: &DevGuardConfig) -> RiskAssessment {
    let branch = extract_branch(args);
    let mut score: u8 = 20;
    let mut reasons = vec![format!("Git {:?}", op)];

    // Check branch permissions
    if let Some(ref b) = branch {
        if matches_any(b, &role.branches.deny) {
            return RiskAssessment {
                level: RiskLevel::Critical, score: 95,
                reasons: vec![format!("Branch '{}' denied by policy", b)],
                affected_paths: vec![], requires_approval: false, approval_from: vec![],
            };
        }
        if !role.branches.allow.is_empty() && !matches_any(b, &role.branches.allow) {
            return RiskAssessment {
                level: RiskLevel::High, score: 80,
                reasons: vec![format!("Branch '{}' not in allowlist", b)],
                affected_paths: vec![], requires_approval: false, approval_from: vec![],
            };
        }
        // Protected branches (global)
        if matches_any(b, &config.git.protected_branches) {
            score += 30;
            reasons.push(format!("Protected branch: {}", b));
        }
    }

    match op {
        GitOperation::ForcePush => {
            if config.git.no_force_push {
                return RiskAssessment {
                    level: RiskLevel::Critical, score: 100,
                    reasons: vec!["Force push denied by policy".into()],
                    affected_paths: vec![], requires_approval: false, approval_from: vec![],
                };
            }
            score = 90;
            reasons.push("Force push".into());
        }
        GitOperation::Push => { score += 20; reasons.push("Push".into()); }
        GitOperation::Reset => { score += 40; reasons.push("Hard reset".into()); }
        GitOperation::Rebase => { score += 25; reasons.push("Rebase".into()); }
        GitOperation::Merge => { score += 15; reasons.push("Merge".into()); }
        GitOperation::BranchDelete => { score += 30; reasons.push("Branch delete".into()); }
        GitOperation::Tag => { score += 10; reasons.push("Tag".into()); }
        GitOperation::Commit => { score += 5; }
        GitOperation::BranchCreate | GitOperation::Checkout => { score += 5; }
    }

    RiskAssessment {
        level: score_to_level(score), score, reasons,
        affected_paths: vec![],
        requires_approval: score >= 60,
        approval_from: if score >= 60 { vec!["senior".into()] } else { vec![] },
    }
}

fn extract_branch(args: &[String]) -> Option<String> {
    if args.len() < 2 { return None; }
    match args[1].as_str() {
        "push" => {
            // "git push origin main" or "git push main"
            if args.len() >= 4 { Some(args[3].clone()) }
            else if args.len() == 3 { Some(args[2].clone()) }
            else { None }
        }
        "checkout" => {
            if args.len() >= 4 && args[2] == "-b" { Some(args[3].clone()) }
            else if args.len() >= 3 { Some(args[2].clone()) }
            else { None }
        }
        "branch" | "merge" | "rebase" => {
            if args.len() >= 3 { Some(args[2].clone()) } else { None }
        }
        _ => {
            // Last arg is often the branch/ref
            if args.len() >= 3 { Some(args.last()?.clone()) } else { None }
        }
    }
}

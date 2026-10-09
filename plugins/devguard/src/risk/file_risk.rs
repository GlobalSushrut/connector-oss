//! File operation risk assessment.

use crate::action::*;
use crate::config::RoleConfig;
use super::{matches_any, is_sensitive_path, score_to_level, low_risk_path};
use std::path::Path;

pub fn assess_file_read(path: &Path, role: &RoleConfig) -> RiskAssessment {
    let ps = path.to_string_lossy();
    if matches_any(&ps, &role.files.hidden) {
        return RiskAssessment {
            level: RiskLevel::Critical, score: 95,
            reasons: vec![format!("'{}' hidden by policy", ps)],
            affected_paths: vec![path.to_path_buf()],
            requires_approval: false, approval_from: vec![],
        };
    }
    if matches_any(&ps, &role.files.read) {
        return low_risk_path("Allowed read", path);
    }
    RiskAssessment {
        level: RiskLevel::Medium, score: 40,
        reasons: vec![format!("'{}' not in read allowlist", ps)],
        affected_paths: vec![path.to_path_buf()],
        requires_approval: false, approval_from: vec![],
    }
}

pub fn assess_file_write(path: &Path, lines: u32, role: &RoleConfig) -> RiskAssessment {
    let ps = path.to_string_lossy();
    if matches_any(&ps, &role.files.hidden) {
        return RiskAssessment {
            level: RiskLevel::Critical, score: 100,
            reasons: vec![format!("Write to hidden '{}'", ps)],
            affected_paths: vec![path.to_path_buf()],
            requires_approval: false, approval_from: vec![],
        };
    }
    if matches_any(&ps, &role.files.read_only) {
        return RiskAssessment {
            level: RiskLevel::High, score: 80,
            reasons: vec![format!("Write to read-only '{}'", ps)],
            affected_paths: vec![path.to_path_buf()],
            requires_approval: false, approval_from: vec![],
        };
    }
    if matches_any(&ps, &role.files.suggest_only) {
        return RiskAssessment {
            level: RiskLevel::High, score: 70,
            reasons: vec![format!("'{}' is suggest-only", ps)],
            affected_paths: vec![path.to_path_buf()],
            requires_approval: true, approval_from: vec!["reviewer".into()],
        };
    }
    if !matches_any(&ps, &role.files.write) {
        return RiskAssessment {
            level: RiskLevel::High, score: 75,
            reasons: vec![format!("'{}' not in write allowlist", ps)],
            affected_paths: vec![path.to_path_buf()],
            requires_approval: false, approval_from: vec![],
        };
    }

    let mut score: u8 = 10;
    let mut reasons = vec!["In write allowlist".into()];
    if lines > 500 { score += 25; reasons.push(format!("{} lines (large)", lines)); }
    else if lines > 200 { score += 15; reasons.push(format!("{} lines (medium)", lines)); }
    if let Some(max) = role.files.max_lines_per_file {
        if lines > max {
            return RiskAssessment {
                level: RiskLevel::High, score: 80,
                reasons: vec![format!("{} lines exceeds max {}", lines, max)],
                affected_paths: vec![path.to_path_buf()],
                requires_approval: true, approval_from: vec!["senior".into()],
            };
        }
    }
    if is_sensitive_path(&ps) { score += 20; reasons.push("Sensitive path".into()); }
    RiskAssessment {
        level: score_to_level(score), score, reasons,
        affected_paths: vec![path.to_path_buf()],
        requires_approval: score >= 60,
        approval_from: if score >= 60 { vec!["senior".into()] } else { vec![] },
    }
}

pub fn assess_file_delete(path: &Path, role: &RoleConfig) -> RiskAssessment {
    let ps = path.to_string_lossy();
    if matches_any(&ps, &role.files.no_delete) {
        return RiskAssessment {
            level: RiskLevel::Critical, score: 100,
            reasons: vec![format!("Delete of protected '{}'", ps)],
            affected_paths: vec![path.to_path_buf()],
            requires_approval: false, approval_from: vec![],
        };
    }
    RiskAssessment {
        level: RiskLevel::High, score: 70,
        reasons: vec![format!("File deletion: '{}'", ps)],
        affected_paths: vec![path.to_path_buf()],
        requires_approval: true, approval_from: vec!["senior".into()],
    }
}

pub fn assess_file_rename(from: &Path, to: &Path, role: &RoleConfig) -> RiskAssessment {
    let ts = to.to_string_lossy();
    let mut score: u8 = 30;
    let mut reasons = vec![format!("Rename → {}", ts)];
    if !matches_any(&ts, &role.files.write) { score += 40; reasons.push("Target not writable".into()); }
    RiskAssessment {
        level: score_to_level(score), score, reasons,
        affected_paths: vec![from.to_path_buf(), to.to_path_buf()],
        requires_approval: score >= 60,
        approval_from: if score >= 60 { vec!["senior".into()] } else { vec![] },
    }
}

pub fn assess_patch(path: &Path, added: u32, removed: u32, role: &RoleConfig) -> RiskAssessment {
    let ps = path.to_string_lossy();
    let total = added + removed;
    let mut score: u8 = 15;
    let mut reasons = vec![format!("+{} -{} on {}", added, removed, ps)];
    if !matches_any(&ps, &role.files.write) { score += 50; reasons.push("Not writable".into()); }
    if total > 500 { score += 20; reasons.push("Large patch".into()); }
    if is_sensitive_path(&ps) { score += 20; reasons.push("Sensitive path".into()); }
    RiskAssessment {
        level: score_to_level(score), score, reasons,
        affected_paths: vec![path.to_path_buf()],
        requires_approval: score >= 60,
        approval_from: if score >= 60 { vec!["senior".into()] } else { vec![] },
    }
}

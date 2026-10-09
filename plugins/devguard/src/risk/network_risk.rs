//! Network, secret, and LLM risk assessment.

use crate::action::*;
use crate::config::RoleConfig;
use super::{matches_any, score_to_level};

pub fn assess_network(host: &str, port: u16, role: &RoleConfig) -> RiskAssessment {
    // Deny-list first
    if matches_any(host, &role.network.deny) {
        return RiskAssessment {
            level: RiskLevel::Critical, score: 90,
            reasons: vec![format!("Host '{}' denied", host)],
            affected_paths: vec![], requires_approval: false, approval_from: vec![],
        };
    }
    if !role.network.allow.is_empty() && !matches_any(host, &role.network.allow) {
        return RiskAssessment {
            level: RiskLevel::High, score: 75,
            reasons: vec![format!("Host '{}' not in allowlist", host)],
            affected_paths: vec![], requires_approval: false, approval_from: vec![],
        };
    }
    RiskAssessment {
        level: RiskLevel::Low, score: 10,
        reasons: vec![format!("{}:{} allowed", host, port)],
        affected_paths: vec![], requires_approval: false, approval_from: vec![],
    }
}

pub fn assess_secret(key_name: &str, role: &RoleConfig) -> RiskAssessment {
    if role.secrets.allowed_via_broker.is_empty() || role.secrets.is_none() {
        return RiskAssessment {
            level: RiskLevel::Critical, score: 100,
            reasons: vec![format!("No secret access — '{}' denied", key_name)],
            affected_paths: vec![], requires_approval: false, approval_from: vec![],
        };
    }
    if matches_any(key_name, &role.secrets.allowed_via_broker) {
        return RiskAssessment {
            level: RiskLevel::Medium, score: 40,
            reasons: vec![format!("Secret '{}' via broker (reference only)", key_name)],
            affected_paths: vec![], requires_approval: false, approval_from: vec![],
        };
    }
    RiskAssessment {
        level: RiskLevel::High, score: 80,
        reasons: vec![format!("Secret '{}' not in allowed broker list", key_name)],
        affected_paths: vec![], requires_approval: false, approval_from: vec![],
    }
}

pub fn assess_llm(cost_usd: f64, role: &RoleConfig) -> RiskAssessment {
    if cost_usd > role.budget.max_cost_usd_per_day * 0.5 {
        return RiskAssessment {
            level: RiskLevel::High, score: 70,
            reasons: vec![format!("LLM call ${:.4} — over 50% of daily budget", cost_usd)],
            affected_paths: vec![], requires_approval: true,
            approval_from: vec!["tech_lead".into()],
        };
    }
    RiskAssessment {
        level: RiskLevel::Low, score: 5,
        reasons: vec![format!("LLM call ${:.4}", cost_usd)],
        affected_paths: vec![], requires_approval: false, approval_from: vec![],
    }
}

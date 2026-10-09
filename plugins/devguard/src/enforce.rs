//! Enforcement Engine — takes a CanonicalAction + resolved role → Decision.
//!
//! This is the single point where all DevGuard governance decisions are made.
//! The flow: Action → Risk Assessment → Verdict → Audit Record → Decision.

use crate::action::*;
use crate::config::{DevGuardConfig, RoleConfig, ResolvedRole};
use crate::risk;
use chrono::Utc;

/// Evaluate a CanonicalAction and return a full Decision.
pub fn evaluate(
    action: &CanonicalAction,
    resolved: &ResolvedRole,
    config: &DevGuardConfig,
    session_id: &str,
) -> Decision {
    let role_config = &resolved.config;
    let risk_assessment = risk::assess(action, role_config, config);

    let verdict = determine_verdict(&risk_assessment, config);
    let fingerprint = config.fingerprint();

    Decision {
        action: action.clone(),
        verdict,
        risk: risk_assessment,
        policy_fingerprint: fingerprint,
        timestamp: Utc::now(),
        session_id: session_id.to_string(),
        identity: resolved.identity.clone(),
        role: resolved.role_name.clone(),
    }
}

/// Convert a RiskAssessment into a Verdict based on enforcement config.
fn determine_verdict(risk: &RiskAssessment, config: &DevGuardConfig) -> Verdict {
    // audit_only mode — allow everything but record
    if config.enforcement.mode == "audit_only" {
        return Verdict::Allow;
    }

    match risk.level {
        RiskLevel::Critical => {
            // Critical = always deny
            Verdict::Deny {
                reason: risk.reasons.join("; "),
            }
        }
        RiskLevel::High => {
            if risk.requires_approval {
                Verdict::RequireApproval {
                    from: risk.approval_from.clone(),
                    reason: risk.reasons.join("; "),
                }
            } else if risk.score >= 75 {
                // High score without approval path = deny
                Verdict::Deny {
                    reason: risk.reasons.join("; "),
                }
            } else {
                Verdict::HoldForReview {
                    reason: risk.reasons.join("; "),
                }
            }
        }
        RiskLevel::Medium => {
            if risk.requires_approval {
                Verdict::RequireApproval {
                    from: risk.approval_from.clone(),
                    reason: risk.reasons.join("; "),
                }
            } else {
                Verdict::Allow
            }
        }
        RiskLevel::Low => Verdict::Allow,
    }
}

/// Batch evaluate multiple actions (e.g., a whole tool_use response).
pub fn evaluate_batch(
    actions: &[CanonicalAction],
    resolved: &ResolvedRole,
    config: &DevGuardConfig,
    session_id: &str,
) -> Vec<Decision> {
    actions.iter()
        .map(|a| evaluate(a, resolved, config, session_id))
        .collect()
}

/// Quick check: is this action allowed? (for pre-flight checks)
pub fn is_allowed(
    action: &CanonicalAction,
    resolved: &ResolvedRole,
    config: &DevGuardConfig,
) -> bool {
    let risk = risk::assess(action, &resolved.config, config);
    let verdict = determine_verdict(&risk, config);
    verdict.is_allowed()
}

/// Format a Decision for human display.
pub fn format_decision(decision: &Decision) -> String {
    let icon = match &decision.verdict {
        Verdict::Allow => "✓",
        Verdict::Deny { .. } => "✗",
        Verdict::RequireApproval { .. } => "⏳",
        Verdict::HoldForReview { .. } => "⏸",
    };
    let verdict_str = match &decision.verdict {
        Verdict::Allow => "ALLOW".to_string(),
        Verdict::Deny { reason } => format!("DENY: {}", reason),
        Verdict::RequireApproval { from, reason } => format!("NEEDS APPROVAL from {}: {}", from.join(", "), reason),
        Verdict::HoldForReview { reason } => format!("HELD: {}", reason),
    };
    format!("{} [{}] {} | Risk: {} ({})",
        icon,
        decision.role,
        verdict_str,
        decision.risk.level,
        decision.risk.score,
    )
}

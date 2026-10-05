//! translator.rs - Human-readable translations for surface outputs.
//!
//! This module provides the `WhyTranslator`, a system for converting internal
//! system states, codes, and signals into plain-language explanations suitable
//! for a non-technical audience.

use super::contract::SurfaceContract;
use super::document::{ComplianceState, HealthState, SurfaceDocument};
use super::package::{WhyLine, RiskLine, RiskLevel};

/// A trait for translating internal data into human-readable lines.
pub trait Translator {
    fn translate_why(&self, contract: &SurfaceContract, doc: &SurfaceDocument) -> WhyLine;
    fn translate_risk(&self, contract: &SurfaceContract, doc: &SurfaceDocument) -> RiskLine;
}

/// The standard implementation of the `WhyTranslator`.
pub struct StandardTranslator;

impl StandardTranslator {
    pub fn new() -> Self {
        Self
    }
}

impl Default for StandardTranslator {
    fn default() -> Self {
        Self::new()
    }
}

impl StandardTranslator {
    /// Map a raw signal text to a specific, actionable explanation.
    /// Covers all 10 event categories from the surface output spec (§7).
    fn enrich_signal(text: &str, agent_name: &str) -> String {
        // --- Evidence / Audit chain (Category 5, SR-004) ---
        if text.contains("Evidence verification incomplete") || text == "Evidence verification incomplete" {
            return "Audit chain has 0 receipts — no signed operations have been recorded for \
                    this subject yet. If this is a new agent, run a tool call first. \
                    If this is a decision record, ensure it was stored via \
                    POST /api/v1/disputes/record. \
                    Chain 1 (Audit) and Chain 2 (Evidence) are both unestablished."
                .to_string();
        }

        // --- Health states (Category 7) ---
        if text.contains("UNHEALTHY") || text == "Health status: UNHEALTHY" {
            return format!(
                "{} is unhealthy — error rate > 20% or budget > 95%. \
                 GuardPipeline CircuitBreaker (layer 4) is OPEN; tool calls are blocked. \
                 Trust dimension D5 (operational_health) is critically reduced. \
                 Immediate operator attention required: `connectorctl inspect {}`.",
                agent_name, agent_name
            );
        }
        if text.contains("DEGRADED") || text == "Health status: DEGRADED" {
            return format!(
                "{} is degraded — error rate exceeded 5% threshold. \
                 AdaptiveThreshold z-score: (error_rate – μ) / σ > 2.0. \
                 Trust D5 reduced. Check recent operation failures: \
                 `connectorctl trace {}`.",
                agent_name, agent_name
            );
        }

        // --- Compliance (Category 6) ---
        if text.contains("NonCompliant") || text.contains("NON_COMPLIANT") || text.contains("Compliance: NonCompliant") {
            return format!(
                "{} is non-compliant with operational policy. \
                 Policy Chain (Chain 7) has active deny decisions. \
                 Deploy gate is BLOCKED (requires T≥70 AND chain_valid). \
                 Resolve findings: `connectorctl inspect {}`.",
                agent_name, agent_name
            );
        }
        if text.contains("Compliance: PARTIAL") || text.contains("Compliance: Partial") {
            return format!(
                "{} has partial compliance coverage — one or more Cedar policy checks \
                 have outstanding findings. Trust D2 (authorization_coverage) is reduced. \
                 Review: `connectorctl risk {}`.",
                agent_name, agent_name
            );
        }

        // --- Budget / cost (Category 2, PL-003/PL-004) ---
        if text.contains("budget_exceeded") || (text.contains("Budget") && text.contains("exhaust")) {
            return format!(
                "{} budget hard limit reached — token spend exhausted configured threshold. \
                 KECS probation may be active (spectral_param u_i=0, excluded from consensus). \
                 Trust D5 = 0. Reset: increase CONNECTOR_AGENT_TOKEN_BUDGET or deregister.",
                agent_name
            );
        }

        // --- Guard Pipeline blocks (Category 1) ---
        if text.contains("injection") || text.contains("Injection") {
            return format!(
                "Semantic injection detected — ContentFilter (GuardPipeline layer 3) \
                 scored input > 0.75 threshold. Input was blocked pre-LLM. \
                 Audit Chain (Chain 1) has a tamper-evident record of this block. \
                 Investigate prompt source for agent {}.",
                agent_name
            );
        }
        if text.contains("circuit") || text.contains("Circuit") {
            return format!(
                "CircuitBreaker (GuardPipeline layer 4) is OPEN for {} — \
                 consecutive failure threshold exceeded. \
                 Tool calls are blocked until cooldown expires. \
                 Entropy spike likely — check: `connectorctl trace {}`.",
                agent_name, agent_name
            );
        }
        if text.contains("HITL") || text.contains("human approval") {
            return format!(
                "Human-in-the-loop (HITL) gate triggered for {} — \
                 action requires manual approval before execution. \
                 GuardPipeline layer 5 is holding the request. \
                 Check HITL queue: `connectorctl inspect {}`.",
                agent_name, agent_name
            );
        }

        // --- Trust / KECS / Knot (Category 3) ---
        if text.contains("KECS") || text.contains("kecs") {
            return format!(
                "KECS confidence (trust dim 6) has dropped — \
                 K = Σ(w_i·metric_i) is below threshold. \
                 Agent {} may be approaching probation (u_i=0, excluded from consensus). \
                 Check expertise recency and audit depth.",
                agent_name
            );
        }
        if text.contains("Knot") || text.contains("knot") || text.contains("consensus") {
            return format!(
                "KnotConsensus failure for {} — \
                 Yang-Baxter strand overlap YB = |sᵢ∩sⱼ|/|sᵢ∪sⱼ| below threshold. \
                 Multi-cell agreement not reached. Check for Sybil pattern or cell isolation.",
                agent_name
            );
        }
        if text.contains("entropy") || text.contains("Entropy") {
            return format!(
                "Entropy spike detected for {} — \
                 Von Neumann entropy Δ = S_t – S_(t–1) exceeded 0.3 baseline. \
                 Anomalous state transition. AdaptiveThreshold will tighten baselines. \
                 z-score: (value – μ) / σ > 2.0.",
                agent_name
            );
        }
        if text.contains("tamper") || text.contains("Tamper") || text.contains("HMAC") {
            return format!(
                "CRITICAL: Audit chain tamper detected for {} — \
                 HMAC mismatch at a chain position. Chain 1 (Audit) integrity is broken. \
                 Trust D1 = 0. Deploy gate BLOCKED. \
                 Export evidence: `connectorctl prove {}`.",
                agent_name, agent_name
            );
        }

        // --- Multi-agent (Category 4) ---
        if text.contains("Sybil") || text.contains("sybil") {
            return "Sybil detection triggered — multiple agents share >95% Yang-Baxter \
                    strand overlap, indicating coordinated manipulation. \
                    KnotConsensus is BLOCKED. Affected cells isolated (u_i=0)."
                .to_string();
        }
        if text.contains("rollback") || text.contains("Rollback") {
            return format!(
                "Saga rollback initiated for pipeline involving {} — \
                 a step failed and compensating transactions are running. \
                 Chain 9 (Consensus) has a FAIL record for this round.",
                agent_name
            );
        }

        // --- Surface / rendering fallbacks (Category 10) ---
        if text.contains("not found") || text.contains("not in registry") || text.contains("unavailable") {
            return format!(
                "{} was not found in the agent registry. \
                 The subject may be deregistered, mistyped, or the platform API \
                 (default: http://localhost:9091) may be unreachable. \
                 Start the platform: `connectorctl start`.",
                agent_name
            );
        }

        // Default: return the signal text as-is (already specific enough)
        text.to_string()
    }

    /// Extract a clean detail sentence from a judgment text that contains decision context.
    /// judgment examples:
    ///   "BLOCKED — network.request | by agent agent_abc | 2h ago"
    ///   "Decision c7e1306d: BLOCKED | agent=agent_xyz | action=network.request target=foo"
    fn parse_decision_context(judgment: &str) -> String {
        // Try to extract agent and action from "agent={pid}" and "action={act}" patterns
        let agent = judgment.split("agent=").nth(1)
            .map(|s| s.split(|c| c == '|' || c == ' ').next().unwrap_or(""))
            .filter(|s| !s.is_empty())
            .map(|s| {
                let short = &s[..s.len().min(20)];
                format!("Agent {}. ", short)
            })
            .unwrap_or_default();

        let action = judgment.split("action=").nth(1)
            .map(|s| s.split(|c| c == '|' || c == '\n').next().unwrap_or("").trim())
            .filter(|s| !s.is_empty())
            .map(|s| format!("Operation: {}. ", s))
            .unwrap_or_default();

        format!("{}{}", agent, action)
    }

    /// Format a why explanation for a raw `decision:{outcome}|agent=...|action=...` status.
    fn format_decision_why(judgment: &str, _name: &str) -> String {
        let outcome_part = judgment.split("decision:").nth(1)
            .map(|s| s.split('|').next().unwrap_or("").trim())
            .unwrap_or("recorded");

        let agent = judgment.split("agent=").nth(1)
            .map(|s| s.split('|').next().unwrap_or("").trim())
            .map(|s| &s[..s.len().min(24)])
            .unwrap_or("unknown");

        let action = judgment.split("action=").nth(1)
            .map(|s| s.split('|').next().unwrap_or("").trim())
            .unwrap_or("unknown");

        let outcome_label = match outcome_part {
            "blocked" | "denied" | "rejected" => "BLOCKED by governance policy",
            "allowed" | "approved" => "ALLOWED by governance policy",
            other => other,
        };

        format!(
            "Decision outcome: {} — \
             operation `{}` attempted by agent `{}`. \
             Record is stored in the disputes log with a tamper-evident audit entry.",
            outcome_label, action, agent
        )
    }
}

impl Translator for StandardTranslator {
    /// Translates the primary reason for a decision into a `WhyLine` using contract signals.
    ///
    /// Resolution priority (spec §7):
    ///   1. Judgment text contains BLOCKED / ALLOWED / DENIED  → decision context
    ///   2. First Cross signal (Critical)                      → enriched cross text
    ///   3. First Warning signal                               → enriched warning text
    ///   4. All Check signals                                  → "Operating normally"
    fn translate_why(&self, contract: &SurfaceContract, _doc: &SurfaceDocument) -> WhyLine {
        let name = &contract.subject.display;
        let judgment = &contract.judgment.text;

        // Priority 1 — decision record context embedded in judgment text
        if judgment.contains("BLOCKED") || judgment.contains("DENIED") {
            let detail = Self::parse_decision_context(judgment);
            return WhyLine {
                explanation: format!(
                    "Action was blocked by governance policy. {}\
                     Run `connectorctl prove {}` to view the evidence chain.",
                    detail, contract.subject.inspect
                ),
                source_link: None,
            };
        }
        if judgment.contains("ALLOWED") {
            let detail = Self::parse_decision_context(judgment);
            return WhyLine {
                explanation: format!(
                    "Action was permitted by governance policy. {}\
                     Record is stored and tamper-evident.",
                    detail
                ),
                source_link: None,
            };
        }
        // decision: prefix in judgment (unformatted raw status)
        if judgment.contains("decision:") {
            return WhyLine {
                explanation: Self::format_decision_why(judgment, name),
                source_link: None,
            };
        }

        // Priority 2 — Cross signal (definitive failure) takes precedence
        let cross = contract.signals.iter()
            .find(|s| matches!(s.icon, super::contract::SignalIcon::Cross));
        let source_link = contract.signals.iter().find_map(|s| s.link.clone());
        if let Some(signal) = cross {
            return WhyLine { explanation: Self::enrich_signal(&signal.text, name), source_link };
        }

        // Priority 3 — judgment text when it is more specific than generic evidence signals
        // Generic format ends with "— surface query" or "— state not available"
        let judgment_is_generic = judgment.ends_with("— surface query")
            || judgment.ends_with("— state not available")
            || judgment.is_empty();
        if !judgment_is_generic {
            let explanation = if judgment.contains("not found") || judgment.contains("unavailable") {
                format!("{}. Run `connectorctl inspect {}` to investigate.", judgment, contract.subject.inspect)
            } else {
                judgment.clone()
            };
            return WhyLine { explanation, source_link };
        }

        // Priority 4 — Warning/Info signal
        let primary = contract.signals.iter()
            .find(|s| !matches!(s.icon, super::contract::SignalIcon::Check));

        let explanation = if let Some(signal) = primary {
            Self::enrich_signal(&signal.text, name)
        } else {
            format!("{} is operating within normal parameters.", name)
        };

        WhyLine { explanation, source_link }
    }

    /// Translates signals and state into a `RiskLine` using real contract data.
    fn translate_risk(&self, contract: &SurfaceContract, _doc: &SurfaceDocument) -> RiskLine {
        let cross_signal = contract
            .signals
            .iter()
            .find(|signal| matches!(signal.icon, super::contract::SignalIcon::Cross));

        if cross_signal.is_some()
            || matches!(contract.state.health, HealthState::Unhealthy)
            || matches!(contract.state.compliance, ComplianceState::NonCompliant)
        {
            let summary = cross_signal
                .map(|s| s.text.clone())
                .or_else(|| {
                    if matches!(contract.state.compliance, ComplianceState::NonCompliant) {
                        Some(format!("{} is non-compliant with active policy.", contract.subject.display))
                    } else {
                        Some(format!("{} is unhealthy and needs operator attention.", contract.subject.display))
                    }
                })
                .unwrap_or_default();
            return RiskLine { level: RiskLevel::High, summary };
        }

        let warn_signal = contract
            .signals
            .iter()
            .find(|signal| matches!(signal.icon, super::contract::SignalIcon::Warning));

        if warn_signal.is_some()
            || matches!(contract.state.health, HealthState::Degraded)
            || matches!(contract.state.compliance, ComplianceState::Partial)
        {
            let summary = warn_signal
                .map(|s| s.text.clone())
                .or_else(|| {
                    if matches!(contract.state.compliance, ComplianceState::Partial) {
                        Some(format!("{} has partial compliance coverage.", contract.subject.display))
                    } else {
                        Some(format!("{} is degraded; monitor closely.", contract.subject.display))
                    }
                })
                .unwrap_or_default();
            return RiskLine { level: RiskLevel::Medium, summary };
        }

        let ok_signal = contract
            .signals
            .iter()
            .find(|signal| matches!(signal.icon, super::contract::SignalIcon::Check));

        let summary = ok_signal
            .map(|s| s.text.clone())
            .unwrap_or_else(|| format!("{} is operating within normal parameters.", contract.subject.display));

        RiskLine { level: RiskLevel::Low, summary }
    }
}

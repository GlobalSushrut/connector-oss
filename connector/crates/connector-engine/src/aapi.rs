//! Action Authorization Engine — exposes AAPI's full potential.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyEffect { Allow, Deny, RequireApproval }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub effect: PolicyEffect,
    pub action_pattern: String,
    pub resource_pattern: Option<String>,
    pub roles: Vec<String>,
    pub priority: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionPolicy {
    pub id: String,
    pub name: String,
    pub rules: Vec<PolicyRule>,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub allowed: bool,
    pub effect: String,
    pub reason: String,
    pub matched_rule: Option<String>,
    pub requires_approval: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetTracker {
    pub agent_pid: String,
    pub resource: String,
    pub limit: f64,
    pub used: f64,
}

impl BudgetTracker {
    pub fn remaining(&self) -> f64 {
        (self.limit - self.used).max(0.0)
    }
    pub fn consume(&mut self, amount: f64) -> bool {
        if self.used + amount <= self.limit {
            self.used += amount;
            true
        } else {
            false
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuedCapability {
    pub token_id: String,
    pub issuer: String,
    pub subject: String,
    pub actions: Vec<String>,
    pub resources: Vec<String>,
    pub issued_at: i64,
    pub expires_at: i64,
    pub parent_token_id: Option<String>,
    pub revoked: bool,
}

impl IssuedCapability {
    pub fn is_valid(&self) -> bool {
        !self.revoked && chrono::Utc::now().timestamp_millis() <= self.expires_at
    }
    pub fn covers_action(&self, a: &str) -> bool {
        self.actions.iter().any(|p| glob_match(p, a))
    }
    pub fn covers_resource(&self, r: &str) -> bool {
        self.resources.iter().any(|p| glob_match(p, r))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionEntry {
    pub record_id: String,
    pub intent: String,
    pub action: String,
    pub target: String,
    pub agent_pid: String,
    pub outcome: String,
    pub confidence: Option<f64>,
    pub evidence_cids: Vec<String>,
    pub regulations: Vec<String>,
    pub duration_ms: Option<u64>,
    pub timestamp: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InteractionEntry {
    pub id: String,
    pub agent_pid: String,
    pub itype: String,
    pub target: String,
    pub operation: String,
    pub status: String,
    pub duration_ms: u64,
    pub tokens: Option<u64>,
    pub cost_usd: Option<f64>,
    pub timestamp: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceConfig {
    pub regulations: Vec<String>,
    pub data_classification: Option<String>,
    pub retention_days: u64,
    pub requires_human_review: bool,
}

fn glob_match(pat: &str, val: &str) -> bool {
    if pat == "*" || pat == val { return true; }
    if pat.ends_with('*') {
        return val.starts_with(&pat[..pat.len() - 1]);
    }
    if pat.starts_with('*') {
        return val.ends_with(&pat[1..]);
    }
    false
}

fn now_ms() -> i64 { chrono::Utc::now().timestamp_millis() }
fn new_id() -> String { uuid::Uuid::new_v4().to_string() }

// ═══════════════════════════════════════════════════════════════
// ActionEngine
// ═══════════════════════════════════════════════════════════════

pub struct ActionEngine {
    policies: Vec<ActionPolicy>,
    budgets: HashMap<String, BudgetTracker>,
    capabilities: Vec<IssuedCapability>,
    actions: Vec<ActionEntry>,
    interactions: Vec<InteractionEntry>,
    pub compliance: Option<ComplianceConfig>,
    pub default_deny: bool,
}

impl Default for ActionEngine {
    fn default() -> Self { Self::new() }
}

impl ActionEngine {
    pub fn new() -> Self {
        Self {
            policies: vec![],
            budgets: HashMap::new(),
            capabilities: vec![],
            actions: vec![],
            interactions: vec![],
            compliance: None,
            default_deny: false,
        }
    }

    pub fn enterprise() -> Self {
        Self { default_deny: true, ..Self::new() }
    }

    // ── Policy Management ──

    pub fn add_policy(&mut self, id: &str, name: &str, rules: Vec<PolicyRule>) {
        self.policies.push(ActionPolicy {
            id: id.into(),
            name: name.into(),
            rules,
            enabled: true,
        });
    }

    pub fn remove_policy(&mut self, id: &str) {
        self.policies.retain(|p| p.id != id);
    }

    pub fn policy_count(&self) -> usize {
        self.policies.len()
    }

    pub fn evaluate_policy(
        &self, action: &str, resource: &str, role: Option<&str>,
    ) -> PolicyDecision {
        for pol in &self.policies {
            if !pol.enabled { continue; }
            let mut rules: Vec<&PolicyRule> = pol.rules.iter().collect();
            rules.sort_by(|a, b| b.priority.cmp(&a.priority));
            for r in rules {
                if !glob_match(&r.action_pattern, action) { continue; }
                if let Some(ref rp) = r.resource_pattern {
                    if !glob_match(rp, resource) { continue; }
                }
                if !r.roles.is_empty() {
                    match role {
                        Some(rl) if r.roles.contains(&rl.to_string()) => {},
                        _ => continue,
                    }
                }
                let (allowed, eff) = match r.effect {
                    PolicyEffect::Allow => (true, "allow"),
                    PolicyEffect::Deny => (false, "deny"),
                    PolicyEffect::RequireApproval => (false, "require_approval"),
                };
                return PolicyDecision {
                    allowed,
                    effect: eff.into(),
                    reason: format!("{} by '{}'", eff, pol.name),
                    matched_rule: Some(r.action_pattern.clone()),
                    requires_approval: r.effect == PolicyEffect::RequireApproval,
                };
            }
        }
        let (a, e) = if self.default_deny {
            (false, "deny")
        } else {
            (true, "allow")
        };
        PolicyDecision {
            allowed: a,
            effect: e.into(),
            reason: "default".into(),
            matched_rule: None,
            requires_approval: false,
        }
    }

    pub fn authorize_tool(
        &self, agent_pid: &str, action: &str, resource: &str, role: Option<&str>,
    ) -> PolicyDecision {
        // Budget check
        let bk = format!("{}:calls", agent_pid);
        if let Some(b) = self.budgets.get(&bk) {
            if b.remaining() <= 0.0 {
                return PolicyDecision {
                    allowed: false,
                    effect: "deny".into(),
                    reason: "budget exhausted".into(),
                    matched_rule: None,
                    requires_approval: false,
                };
            }
        }
        // Capability check
        if !self.capabilities.is_empty() {
            let has_cap = self.capabilities.iter().any(|c| {
                c.subject == agent_pid
                    && c.is_valid()
                    && c.covers_action(action)
                    && c.covers_resource(resource)
            });
            if !has_cap
                && self.capabilities.iter().any(|c| c.subject == agent_pid)
            {
                return PolicyDecision {
                    allowed: false,
                    effect: "deny".into(),
                    reason: "no capability".into(),
                    matched_rule: None,
                    requires_approval: false,
                };
            }
        }
        self.evaluate_policy(action, resource, role)
    }

    // ── Budget Management ──

    pub fn create_budget(&mut self, pid: &str, res: &str, limit: f64) {
        let key = format!("{}:{}", pid, res);
        self.budgets.insert(key, BudgetTracker {
            agent_pid: pid.into(),
            resource: res.into(),
            limit,
            used: 0.0,
        });
    }

    pub fn consume_budget(&mut self, pid: &str, res: &str, amount: f64) -> bool {
        let key = format!("{}:{}", pid, res);
        self.budgets.get_mut(&key).map(|b| b.consume(amount)).unwrap_or(true)
    }

    pub fn check_budget(&self, pid: &str, res: &str) -> f64 {
        let key = format!("{}:{}", pid, res);
        self.budgets.get(&key).map(|b| b.remaining()).unwrap_or(f64::MAX)
    }

    pub fn budget_count(&self) -> usize {
        self.budgets.len()
    }

    // ── Capability Delegation (UCAN-style) ──

    pub fn issue_capability(
        &mut self, issuer: &str, subject: &str,
        actions: Vec<String>, resources: Vec<String>, ttl_hours: u64,
    ) -> IssuedCapability {
        let now = now_ms();
        let cap = IssuedCapability {
            token_id: new_id(),
            issuer: issuer.into(),
            subject: subject.into(),
            actions,
            resources,
            issued_at: now,
            expires_at: now + (ttl_hours as i64 * 3_600_000),
            parent_token_id: None,
            revoked: false,
        };
        self.capabilities.push(cap.clone());
        cap
    }

    pub fn delegate_capability(
        &mut self, parent_id: &str, new_subject: &str, remove_actions: &[&str],
    ) -> Option<IssuedCapability> {
        let parent = self.capabilities.iter()
            .find(|c| c.token_id == parent_id && c.is_valid())?
            .clone();
        let actions: Vec<String> = parent.actions.iter()
            .filter(|a| !remove_actions.contains(&a.as_str()))
            .cloned()
            .collect();
        let cap = IssuedCapability {
            token_id: new_id(),
            issuer: parent.subject.clone(),
            subject: new_subject.into(),
            actions,
            resources: parent.resources.clone(),
            issued_at: now_ms(),
            expires_at: parent.expires_at,
            parent_token_id: Some(parent_id.into()),
            revoked: false,
        };
        self.capabilities.push(cap.clone());
        Some(cap)
    }

    pub fn revoke_capability(&mut self, id: &str) {
        if let Some(c) = self.capabilities.iter_mut().find(|c| c.token_id == id) {
            c.revoked = true;
        }
    }

    pub fn verify_capability(&self, id: &str) -> Option<bool> {
        self.capabilities.iter().find(|c| c.token_id == id).map(|c| c.is_valid())
    }

    pub fn capability_count(&self) -> usize {
        self.capabilities.len()
    }

    // ── Action Records (audit trail) ──

    pub fn record_action(
        &mut self, intent: &str, action: &str, target: &str, agent_pid: &str,
        outcome: &str, evidence: Vec<String>, confidence: Option<f64>,
        regulations: Vec<String>,
    ) -> ActionEntry {
        let entry = ActionEntry {
            record_id: new_id(),
            intent: intent.into(),
            action: action.into(),
            target: target.into(),
            agent_pid: agent_pid.into(),
            outcome: outcome.into(),
            confidence,
            evidence_cids: evidence,
            regulations,
            duration_ms: None,
            timestamp: now_ms(),
        };
        self.actions.push(entry.clone());
        entry
    }

    pub fn list_actions(&self, agent_pid: Option<&str>) -> Vec<&ActionEntry> {
        match agent_pid {
            Some(p) => self.actions.iter().filter(|a| a.agent_pid == p).collect(),
            None => self.actions.iter().collect(),
        }
    }

    pub fn action_count(&self) -> usize {
        self.actions.len()
    }

    // ── Interaction Logging (machine-world audit) ──

    pub fn log_interaction(
        &mut self, agent_pid: &str, itype: &str, target: &str,
        op: &str, status: &str, dur_ms: u64,
        tokens: Option<u64>, cost: Option<f64>,
    ) -> InteractionEntry {
        let entry = InteractionEntry {
            id: new_id(),
            agent_pid: agent_pid.into(),
            itype: itype.into(),
            target: target.into(),
            operation: op.into(),
            status: status.into(),
            duration_ms: dur_ms,
            tokens,
            cost_usd: cost,
            timestamp: now_ms(),
        };
        self.interactions.push(entry.clone());
        entry
    }

    pub fn list_interactions(&self, agent_pid: Option<&str>) -> Vec<&InteractionEntry> {
        match agent_pid {
            Some(p) => self.interactions.iter().filter(|i| i.agent_pid == p).collect(),
            None => self.interactions.iter().collect(),
        }
    }

    pub fn interaction_count(&self) -> usize {
        self.interactions.len()
    }

    // ── Compliance ──

    pub fn set_compliance(&mut self, config: ComplianceConfig) {
        self.compliance = Some(config);
    }

    // ── Policy Templates ──

    pub fn add_hipaa_policy(&mut self) {
        self.add_policy("hipaa", "HIPAA Guard", vec![
            PolicyRule {
                effect: PolicyEffect::Deny,
                action_pattern: "*.delete".into(),
                resource_pattern: Some("ehr:*".into()),
                roles: vec![],
                priority: 100,
            },
            PolicyRule {
                effect: PolicyEffect::RequireApproval,
                action_pattern: "ehr.update_*".into(),
                resource_pattern: None,
                roles: vec![],
                priority: 90,
            },
            PolicyRule {
                effect: PolicyEffect::Allow,
                action_pattern: "ehr.read_*".into(),
                resource_pattern: None,
                roles: vec!["doctor".into(), "nurse".into()],
                priority: 80,
            },
        ]);
    }

    pub fn add_financial_policy(&mut self) {
        self.add_policy("financial", "Financial Guard", vec![
            PolicyRule {
                effect: PolicyEffect::RequireApproval,
                action_pattern: "trade.*".into(),
                resource_pattern: None,
                roles: vec![],
                priority: 100,
            },
            PolicyRule {
                effect: PolicyEffect::Deny,
                action_pattern: "*.delete".into(),
                resource_pattern: Some("ledger:*".into()),
                roles: vec![],
                priority: 100,
            },
            PolicyRule {
                effect: PolicyEffect::Allow,
                action_pattern: "report.read_*".into(),
                resource_pattern: None,
                roles: vec![],
                priority: 50,
            },
        ]);
    }
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── Glob ──

    #[test]
    fn glob_exact() { assert!(glob_match("ehr.read", "ehr.read")); }
    #[test]
    fn glob_star() { assert!(glob_match("*", "anything")); }
    #[test]
    fn glob_prefix() { assert!(glob_match("ehr.*", "ehr.read")); }
    #[test]
    fn glob_suffix() { assert!(glob_match("*.delete", "ehr.delete")); }
    #[test]
    fn glob_no_match() { assert!(!glob_match("ehr.*", "trade.buy")); }

    // ── Default policies ──

    #[test]
    fn default_allow() {
        let e = ActionEngine::new();
        assert!(e.evaluate_policy("test.read", "res:1", None).allowed);
    }

    #[test]
    fn default_deny_enterprise() {
        let e = ActionEngine::enterprise();
        assert!(!e.evaluate_policy("test.read", "res:1", None).allowed);
    }

    // ── Policy evaluation ──

    #[test]
    fn policy_deny_delete() {
        let mut e = ActionEngine::new();
        e.add_policy("p1", "No deletes", vec![PolicyRule {
            effect: PolicyEffect::Deny,
            action_pattern: "*.delete".into(),
            resource_pattern: None,
            roles: vec![],
            priority: 10,
        }]);
        assert!(!e.evaluate_policy("ehr.delete", "res:1", None).allowed);
        assert!(e.evaluate_policy("ehr.read", "res:1", None).allowed);
    }

    #[test]
    fn policy_role_required() {
        let mut e = ActionEngine::new();
        e.add_policy("p1", "Doctors only", vec![PolicyRule {
            effect: PolicyEffect::Allow,
            action_pattern: "ehr.read_*".into(),
            resource_pattern: None,
            roles: vec!["doctor".into()],
            priority: 10,
        }]);
        assert!(e.evaluate_policy("ehr.read_vitals", "res:1", Some("doctor")).allowed);
        // No role → falls through to default allow (no deny rule)
        assert!(e.evaluate_policy("ehr.read_vitals", "res:1", None).allowed);
    }

    #[test]
    fn policy_require_approval() {
        let mut e = ActionEngine::new();
        e.add_policy("p1", "Approve updates", vec![PolicyRule {
            effect: PolicyEffect::RequireApproval,
            action_pattern: "ehr.update_*".into(),
            resource_pattern: None,
            roles: vec![],
            priority: 10,
        }]);
        let d = e.evaluate_policy("ehr.update_allergy", "res:1", None);
        assert!(!d.allowed);
        assert!(d.requires_approval);
    }

    #[test]
    fn policy_resource_pattern() {
        let mut e = ActionEngine::new();
        e.add_policy("p1", "Protect EHR", vec![PolicyRule {
            effect: PolicyEffect::Deny,
            action_pattern: "*.delete".into(),
            resource_pattern: Some("ehr:*".into()),
            roles: vec![],
            priority: 10,
        }]);
        assert!(!e.evaluate_policy("data.delete", "ehr:patient:1", None).allowed);
        // Different resource → no match → default allow
        assert!(e.evaluate_policy("data.delete", "logs:1", None).allowed);
    }

    #[test]
    fn policy_priority_ordering() {
        let mut e = ActionEngine::new();
        e.add_policy("p1", "Mixed", vec![
            PolicyRule { effect: PolicyEffect::Allow, action_pattern: "ehr.*".into(),
                resource_pattern: None, roles: vec![], priority: 50 },
            PolicyRule { effect: PolicyEffect::Deny, action_pattern: "ehr.delete".into(),
                resource_pattern: None, roles: vec![], priority: 100 },
        ]);
        // Higher priority deny should win
        assert!(!e.evaluate_policy("ehr.delete", "res:1", None).allowed);
    }

    #[test]
    fn remove_policy() {
        let mut e = ActionEngine::enterprise();
        e.add_policy("p1", "Allow reads", vec![PolicyRule {
            effect: PolicyEffect::Allow,
            action_pattern: "*.read".into(),
            resource_pattern: None,
            roles: vec![],
            priority: 10,
        }]);
        assert!(e.evaluate_policy("ehr.read", "res:1", None).allowed);
        e.remove_policy("p1");
        assert!(!e.evaluate_policy("ehr.read", "res:1", None).allowed);
    }

    // ── HIPAA template ──

    #[test]
    fn hipaa_blocks_delete() {
        let mut e = ActionEngine::new();
        e.add_hipaa_policy();
        assert!(!e.evaluate_policy("ehr.delete", "ehr:patient:1", None).allowed);
    }

    #[test]
    fn hipaa_requires_approval_for_update() {
        let mut e = ActionEngine::new();
        e.add_hipaa_policy();
        let d = e.evaluate_policy("ehr.update_allergy", "res:1", None);
        assert!(d.requires_approval);
    }

    #[test]
    fn hipaa_allows_doctor_read() {
        let mut e = ActionEngine::new();
        e.add_hipaa_policy();
        assert!(e.evaluate_policy("ehr.read_vitals", "res:1", Some("doctor")).allowed);
    }

    // ── Budget ──

    #[test]
    fn budget_create_and_consume() {
        let mut e = ActionEngine::new();
        e.create_budget("pid:bot", "tokens", 1000.0);
        assert_eq!(e.check_budget("pid:bot", "tokens"), 1000.0);
        assert!(e.consume_budget("pid:bot", "tokens", 400.0));
        assert_eq!(e.check_budget("pid:bot", "tokens"), 600.0);
    }

    #[test]
    fn budget_exhaustion() {
        let mut e = ActionEngine::new();
        e.create_budget("pid:bot", "tokens", 100.0);
        assert!(e.consume_budget("pid:bot", "tokens", 100.0));
        assert!(!e.consume_budget("pid:bot", "tokens", 1.0));
        assert_eq!(e.check_budget("pid:bot", "tokens"), 0.0);
    }

    #[test]
    fn budget_no_limit_returns_max() {
        let e = ActionEngine::new();
        assert_eq!(e.check_budget("pid:bot", "tokens"), f64::MAX);
    }

    // ── Capabilities ──

    #[test]
    fn issue_and_verify_capability() {
        let mut e = ActionEngine::new();
        let cap = e.issue_capability(
            "pid:admin", "pid:bot",
            vec!["ehr.read_*".into()], vec!["ehr:*".into()], 24,
        );
        assert!(e.verify_capability(&cap.token_id).unwrap());
        assert_eq!(e.capability_count(), 1);
    }

    #[test]
    fn revoke_capability() {
        let mut e = ActionEngine::new();
        let cap = e.issue_capability(
            "pid:admin", "pid:bot",
            vec!["ehr.read_*".into()], vec!["ehr:*".into()], 24,
        );
        e.revoke_capability(&cap.token_id);
        assert!(!e.verify_capability(&cap.token_id).unwrap());
    }

    #[test]
    fn delegate_capability_attenuates() {
        let mut e = ActionEngine::new();
        let cap = e.issue_capability(
            "pid:admin", "pid:bot",
            vec!["ehr.read_*".into(), "ehr.update_*".into()],
            vec!["ehr:*".into()], 24,
        );
        let sub = e.delegate_capability(&cap.token_id, "pid:sub", &["ehr.update_*"]).unwrap();
        assert_eq!(sub.actions, vec!["ehr.read_*".to_string()]);
        assert!(sub.parent_token_id.is_some());
        assert_eq!(e.capability_count(), 2);
    }

    #[test]
    fn capability_covers_action() {
        let mut e = ActionEngine::new();
        let cap = e.issue_capability(
            "pid:admin", "pid:bot",
            vec!["ehr.read_*".into()], vec!["ehr:*".into()], 24,
        );
        assert!(cap.covers_action("ehr.read_vitals"));
        assert!(!cap.covers_action("ehr.delete"));
    }

    // ── Action Records ──

    #[test]
    fn record_and_list_actions() {
        let mut e = ActionEngine::new();
        e.record_action(
            "Update allergy", "ehr.update_allergy", "ehr:patient:1",
            "pid:bot", "success", vec!["bafy123".into()], Some(0.95),
            vec!["hipaa".into()],
        );
        e.record_action(
            "Read vitals", "ehr.read_vitals", "ehr:patient:2",
            "pid:other", "success", vec![], None, vec![],
        );
        assert_eq!(e.action_count(), 2);
        assert_eq!(e.list_actions(Some("pid:bot")).len(), 1);
        assert_eq!(e.list_actions(None).len(), 2);
    }

    // ── Interactions ──

    #[test]
    fn log_and_list_interactions() {
        let mut e = ActionEngine::new();
        e.log_interaction(
            "pid:bot", "llm_inference", "api.openai.com",
            "chat.completions", "success", 1500, Some(700), Some(0.01),
        );
        e.log_interaction(
            "pid:bot", "tool_call", "database",
            "query", "success", 12, None, None,
        );
        assert_eq!(e.interaction_count(), 2);
        assert_eq!(e.list_interactions(Some("pid:bot")).len(), 2);
        assert_eq!(e.list_interactions(Some("pid:other")).len(), 0);
    }

    // ── authorize_tool (integrated) ──

    #[test]
    fn authorize_tool_with_budget_exhausted() {
        let mut e = ActionEngine::new();
        e.create_budget("pid:bot", "calls", 0.0);
        let d = e.authorize_tool("pid:bot", "ehr.read", "res:1", None);
        assert!(!d.allowed);
        assert_eq!(d.reason, "budget exhausted");
    }

    #[test]
    fn authorize_tool_no_capability() {
        let mut e = ActionEngine::new();
        e.issue_capability(
            "pid:admin", "pid:bot",
            vec!["ehr.read_*".into()], vec!["ehr:*".into()], 24,
        );
        let d = e.authorize_tool("pid:bot", "ehr.delete", "ehr:1", None);
        assert!(!d.allowed);
        assert_eq!(d.reason, "no capability");
    }

    #[test]
    fn authorize_tool_with_valid_capability() {
        let mut e = ActionEngine::new();
        e.issue_capability(
            "pid:admin", "pid:bot",
            vec!["ehr.read_*".into()], vec!["ehr:*".into()], 24,
        );
        let d = e.authorize_tool("pid:bot", "ehr.read_vitals", "ehr:patient:1", None);
        assert!(d.allowed);
    }

    // ── Financial template ──

    #[test]
    fn financial_requires_approval_for_trade() {
        let mut e = ActionEngine::new();
        e.add_financial_policy();
        let d = e.evaluate_policy("trade.buy", "res:1", None);
        assert!(d.requires_approval);
    }

    #[test]
    fn financial_denies_ledger_delete() {
        let mut e = ActionEngine::new();
        e.add_financial_policy();
        assert!(!e.evaluate_policy("data.delete", "ledger:tx:1", None).allowed);
    }

    // ── Compliance ──

    #[test]
    fn compliance_config() {
        let mut e = ActionEngine::new();
        e.set_compliance(ComplianceConfig {
            regulations: vec!["hipaa".into(), "eu_ai_act".into()],
            data_classification: Some("phi".into()),
            retention_days: 2555,
            requires_human_review: false,
        });
        assert!(e.compliance.is_some());
        assert_eq!(e.compliance.as_ref().unwrap().regulations.len(), 2);
    }
}

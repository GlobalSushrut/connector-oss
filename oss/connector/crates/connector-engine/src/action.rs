//! Action Interface — universal control for anything.
//!
//! Inspired by: POSIX syscalls, ROS2 Actions (Goal/Result/Feedback),
//! OPC UA (industrial typed methods), WASI (capability-based), SCADA (safety-critical).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Parameter types — maps to JSON Schema + extends for physical control.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Param {
    String, Integer, Float, Boolean,
    Array(Box<Param>), Object,
    Enum(Vec<std::string::String>),
    Optional(Box<Param>), Binary,
}

impl Param {
    pub fn schema_type(&self) -> &'static str {
        match self {
            Param::String | Param::Enum(_) => "string",
            Param::Integer => "integer",
            Param::Float => "number",
            Param::Boolean => "boolean",
            Param::Array(_) => "array",
            Param::Object => "object",
            Param::Optional(inner) => inner.schema_type(),
            Param::Binary => "string",
        }
    }

    pub fn to_json_schema(&self) -> serde_json::Value {
        match self {
            Param::String => serde_json::json!({"type": "string"}),
            Param::Integer => serde_json::json!({"type": "integer"}),
            Param::Float => serde_json::json!({"type": "number"}),
            Param::Boolean => serde_json::json!({"type": "boolean"}),
            Param::Array(inner) => serde_json::json!({"type": "array", "items": inner.to_json_schema()}),
            Param::Object => serde_json::json!({"type": "object"}),
            Param::Enum(v) => serde_json::json!({"type": "string", "enum": v}),
            Param::Optional(inner) => inner.to_json_schema(),
            Param::Binary => serde_json::json!({"type": "string", "contentEncoding": "base64"}),
        }
    }
}

/// Safety constraints on a parameter (SCADA-inspired interlocks).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ParamConstraints {
    pub min: Option<f64>,
    pub max: Option<f64>,
    pub pattern: Option<std::string::String>,
    pub max_length: Option<usize>,
}

/// Effect type — absorbs AAPI EffectBucket.
/// Categorizes what this action does to the world.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum EffectType {
    /// No side effect (pure computation, read-only)
    #[default]
    None,
    /// Creates new state
    Create,
    /// Reads existing state (no mutation)
    Read,
    /// Updates existing state
    Update,
    /// Deletes state
    Delete,
    /// External side effect (email, API call, physical action)
    External,
}

impl EffectType {
    pub fn is_mutating(&self) -> bool { matches!(self, Self::Create | Self::Update | Self::Delete | Self::External) }
    pub fn as_str(&self) -> &'static str {
        match self { Self::None => "none", Self::Create => "create", Self::Read => "read", Self::Update => "update", Self::Delete => "delete", Self::External => "external" }
    }
}

/// Rollback strategy — absorbs AAPI RollbackStrategy.
/// What to do if the action fails or postconditions aren't met.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RollbackStrategy {
    /// No rollback (fire and forget)
    None,
    /// Automatically reverse the action
    AutoReverse,
    /// Escalate to human for manual intervention
    HumanReview,
    /// Retry up to N times with backoff
    Retry { max_retries: u32, backoff_ms: u64 },
    /// Accept the failure and log it
    AcceptAndLog,
}

impl Default for RollbackStrategy {
    fn default() -> Self { Self::None }
}

/// A postcondition assertion — absorbs AAPI Pratyaya postconditions.
/// Declares what should be true after the action runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Postcondition {
    /// Human-readable description
    pub description: std::string::String,
    /// Machine-checkable assertion (JSONPath, CEL, regex)
    pub assertion: Option<std::string::String>,
    /// Whether this postcondition is required or advisory
    #[serde(default = "default_true")]
    pub required: bool,
}

fn default_true() -> bool { true }

/// A typed parameter for an action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionParam {
    pub name: std::string::String,
    pub param_type: Param,
    pub description: std::string::String,
    pub required: bool,
    pub default: Option<serde_json::Value>,
    pub constraints: Option<ParamConstraints>,
}

/// Enterprise rules — all optional. Layer 0 needs none.
/// Absorbs: AAPI Adhikarana (authority), ExecutionConstraints, Pratyaya (postconditions),
/// ComplianceContext, ApprovalLane, Budget, AuthorityContext.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ActionRules {
    // --- V3 Kriya absorption ---
    /// Effect type (absorbs AAPI EffectBucket: None/Create/Read/Update/Delete/External)
    pub effect: EffectType,
    /// Whether this action is idempotent (safe to retry)
    pub idempotent: bool,

    // --- V7 Adhikarana absorption: authorization ---
    /// Require human approval (absorbs ApprovalLane::Sync)
    pub require_approval: bool,
    /// Require two independent approvers (absorbs ApprovalLane::MultiParty)
    pub two_person: bool,
    /// Roles allowed to invoke (absorbs Adhikarana.required_role)
    pub allowed_roles: Vec<std::string::String>,
    /// Roles explicitly denied
    pub denied_roles: Vec<std::string::String>,
    /// Required capability scopes (absorbs Adhikarana.scopes)
    pub scopes: Vec<std::string::String>,

    // --- V7 Adhikarana absorption: execution constraints ---
    /// Data classification (absorbs ExecutionConstraints.data_classification)
    pub data_classification: Option<std::string::String>,
    /// Max invocations per minute (absorbs Budget with resource="calls")
    pub rate_limit: Option<u32>,
    /// Max cost per invocation in USD (absorbs ExecutionConstraints.max_cost_usd)
    pub max_cost_usd: Option<f64>,
    /// Max tokens per invocation (absorbs ExecutionConstraints.max_tokens)
    pub max_tokens: Option<u64>,
    /// Max chained action calls (absorbs ExecutionConstraints.max_tool_calls)
    pub max_chain_depth: Option<u32>,
    /// Execution timeout in ms (absorbs TtlConstraint.max_duration_ms)
    pub timeout_ms: Option<u64>,

    // --- V7 Adhikarana absorption: context constraints ---
    /// Required environment: "production", "staging", "dev" (absorbs AuthorityContext.environment)
    pub environment: Option<std::string::String>,
    /// Jurisdiction constraint: "US", "EU", "UK" (absorbs ComplianceContext.jurisdiction)
    pub jurisdiction: Option<std::string::String>,

    // --- V8 Pratyaya absorption: postconditions ---
    /// Rollback strategy (absorbs Pratyaya.rollback)
    pub rollback: RollbackStrategy,
    /// Postconditions (absorbs Pratyaya.postconditions)
    pub postconditions: Vec<Postcondition>,
    /// Whether partial success is acceptable (absorbs Pratyaya.allow_partial)
    pub allow_partial: bool,

    // --- VakyaMeta.compliance absorption ---
    /// Compliance frameworks (absorbs ComplianceContext.regulations)
    pub compliance: Vec<std::string::String>,
    /// Audit retention in days (absorbs ComplianceContext.retention_days)
    pub retention_days: Option<u64>,

    // --- Physical safety (SCADA/ROS2) ---
    /// Safety interlock expression
    pub interlock: Option<std::string::String>,
    /// Whether effects can be reversed
    pub reversible: bool,
}

/// Result of an action execution (ROS2-inspired: Success/Error/Pending/Feedback).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status")]
pub enum ActionResult {
    Success { data: serde_json::Value },
    Error { code: std::string::String, message: std::string::String },
    PendingApproval { approver: std::string::String, reason: std::string::String },
    Feedback { progress: f64, message: std::string::String },
}

impl ActionResult {
    pub fn success(data: serde_json::Value) -> Self { Self::Success { data } }
    pub fn text(s: impl Into<std::string::String>) -> Self { Self::Success { data: serde_json::json!(s.into()) } }
    pub fn json(v: serde_json::Value) -> Self { Self::Success { data: v } }
    pub fn error(code: impl Into<std::string::String>, msg: impl Into<std::string::String>) -> Self { Self::Error { code: code.into(), message: msg.into() } }
    pub fn pending(approver: impl Into<std::string::String>, reason: impl Into<std::string::String>) -> Self { Self::PendingApproval { approver: approver.into(), reason: reason.into() } }
    pub fn feedback(progress: f64, msg: impl Into<std::string::String>) -> Self { Self::Feedback { progress, message: msg.into() } }
    pub fn is_success(&self) -> bool { matches!(self, Self::Success { .. }) }
}

/// Runtime context passed to action handlers.
#[derive(Debug, Clone)]
pub struct ActionContext {
    values: HashMap<std::string::String, serde_json::Value>,
    pub agent_id: Option<std::string::String>,
    pub role: Option<std::string::String>,
}

impl ActionContext {
    pub fn new() -> Self { Self { values: HashMap::new(), agent_id: None, role: None } }
    pub fn set(&mut self, key: &str, value: serde_json::Value) { self.values.insert(key.to_string(), value); }
    pub fn get(&self, key: &str) -> Option<&serde_json::Value> { self.values.get(key) }
    pub fn get_str(&self, key: &str) -> Option<&str> { self.values.get(key).and_then(|v| v.as_str()) }
    pub fn get_i64(&self, key: &str) -> Option<i64> { self.values.get(key).and_then(|v| v.as_i64()) }
    pub fn get_f64(&self, key: &str) -> Option<f64> { self.values.get(key).and_then(|v| v.as_f64()) }
    pub fn get_bool(&self, key: &str) -> Option<bool> { self.values.get(key).and_then(|v| v.as_bool()) }
    pub fn from_json(value: &serde_json::Value) -> Self {
        let mut ctx = Self::new();
        if let Some(obj) = value.as_object() { for (k, v) in obj { ctx.set(k, v.clone()); } }
        ctx
    }
}

/// An action that an agent can perform on any target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Action {
    pub name: std::string::String,
    pub description: std::string::String,
    pub target: Option<std::string::String>,
    pub domain: Option<std::string::String>,
    pub operation: Option<std::string::String>,
    pub params: Vec<ActionParam>,
    pub returns: Option<Param>,
    pub feedback: Vec<ActionParam>,
    pub rules: ActionRules,
}

impl Action {
    pub fn new(name: &str) -> ActionBuilder {
        let (domain, operation) = name.split_once('.').map(|(d, o)| (Some(d.to_string()), Some(o.to_string()))).unwrap_or((None, None));
        ActionBuilder { name: name.to_string(), description: String::new(), target: None, domain, operation, params: Vec::new(), returns: None, feedback: Vec::new(), rules: ActionRules::default() }
    }

    pub fn to_json_schema(&self) -> serde_json::Value {
        serde_json::json!({"type": "function", "function": {"name": self.name, "description": self.description, "parameters": self.params_schema()}})
    }

    pub fn to_tool_binding(&self, namespace: &str) -> serde_json::Value {
        let d = self.domain.as_deref().unwrap_or("action");
        serde_json::json!({"tool_id": self.name, "namespace_path": format!("{}/actions/{}", namespace, d), "allowed_actions": [format!("{}.{}", d, self.operation.as_deref().unwrap_or(&self.name))], "data_classification": self.rules.data_classification.as_deref().unwrap_or("public"), "requires_approval": self.rules.require_approval})
    }

    pub fn to_kriya(&self) -> serde_json::Value {
        let d = self.domain.as_deref().unwrap_or("action");
        let o = self.operation.as_deref().unwrap_or(&self.name);
        serde_json::json!({"action": format!("{}.{}", d, o), "domain": d, "verb": o, "expected_effect": self.rules.effect.as_str(), "idempotent": self.rules.idempotent})
    }

    /// Generate full AAPI Adhikarana (authority context) from rules.
    pub fn to_adhikarana(&self) -> serde_json::Value {
        let mut adh = serde_json::json!({
            "approval_lane": if self.rules.two_person { "multi_party" } else if self.rules.require_approval { "sync" } else { "none" },
            "scopes": self.rules.scopes,
        });
        if let Some(ref env) = self.rules.environment {
            adh["context"] = serde_json::json!({"environment": env});
        }
        if let Some(ref j) = self.rules.jurisdiction {
            adh["jurisdiction"] = serde_json::json!(j);
        }
        let mut constraints = serde_json::Map::new();
        if let Some(t) = self.rules.max_tokens { constraints.insert("max_tokens".into(), serde_json::json!(t)); }
        if let Some(c) = self.rules.max_cost_usd { constraints.insert("max_cost_usd".into(), serde_json::json!(c)); }
        if let Some(ms) = self.rules.timeout_ms { constraints.insert("max_execution_ms".into(), serde_json::json!(ms)); }
        if let Some(mc) = self.rules.max_chain_depth { constraints.insert("max_tool_calls".into(), serde_json::json!(mc)); }
        if let Some(ref dc) = self.rules.data_classification { constraints.insert("data_classification".into(), serde_json::json!(dc)); }
        constraints.insert("requires_approval".into(), serde_json::json!(self.rules.require_approval));
        adh["execution_constraints"] = serde_json::Value::Object(constraints);
        adh
    }

    /// Generate AAPI Pratyaya (expected effect declaration) from rules.
    pub fn to_pratyaya(&self) -> Option<serde_json::Value> {
        if self.rules.postconditions.is_empty() && self.rules.rollback == RollbackStrategy::None {
            return Option::None;
        }
        let postconds: Vec<serde_json::Value> = self.rules.postconditions.iter().map(|p| {
            serde_json::json!({"description": p.description, "assertion": p.assertion, "required": p.required})
        }).collect();
        let rollback = match &self.rules.rollback {
            RollbackStrategy::None => "none",
            RollbackStrategy::AutoReverse => "auto_reverse",
            RollbackStrategy::HumanReview => "human_review",
            RollbackStrategy::Retry { .. } => "retry",
            RollbackStrategy::AcceptAndLog => "accept_failure",
        };
        Some(serde_json::json!({"postconditions": postconds, "rollback": rollback, "allow_partial": self.rules.allow_partial}))
    }

    /// Generate AAPI ComplianceContext from rules.
    pub fn to_compliance(&self) -> Option<serde_json::Value> {
        if self.rules.compliance.is_empty() && self.rules.data_classification.is_none() {
            return Option::None;
        }
        Some(serde_json::json!({
            "regulations": self.rules.compliance,
            "data_classification": self.rules.data_classification,
            "requires_human_review": self.rules.require_approval,
            "retention_days": self.rules.retention_days.unwrap_or(0),
            "jurisdiction": self.rules.jurisdiction,
        }))
    }

    pub fn validate_params(&self, ctx: &ActionContext) -> Result<(), std::string::String> {
        for p in &self.params {
            if p.required && ctx.get(&p.name).is_none() { return Err(format!("Missing required parameter: '{}'", p.name)); }
            if let (Some(v), Some(c)) = (ctx.get(&p.name), &p.constraints) {
                if let Some(num) = v.as_f64() {
                    if let Some(min) = c.min { if num < min { return Err(format!("'{}' value {} below minimum {}", p.name, num, min)); } }
                    if let Some(max) = c.max { if num > max { return Err(format!("'{}' value {} above maximum {}", p.name, num, max)); } }
                }
                if let Some(s) = v.as_str() {
                    if let Some(ml) = c.max_length { if s.len() > ml { return Err(format!("'{}' length {} exceeds max {}", p.name, s.len(), ml)); } }
                }
            }
        }
        Ok(())
    }

    pub fn is_role_allowed(&self, role: &str) -> bool {
        if self.rules.denied_roles.iter().any(|r| r == role) { return false; }
        if self.rules.allowed_roles.is_empty() { return true; }
        self.rules.allowed_roles.iter().any(|r| r == role)
    }

    pub fn needs_approval(&self) -> bool { self.rules.require_approval || self.rules.two_person }

    fn params_schema(&self) -> serde_json::Value {
        let mut props = serde_json::Map::new();
        let mut req = Vec::new();
        for p in &self.params {
            let mut s = p.param_type.to_json_schema();
            if let Some(obj) = s.as_object_mut() {
                obj.insert("description".into(), serde_json::json!(p.description));
                if let Some(c) = &p.constraints {
                    if let Some(v) = c.min { obj.insert("minimum".into(), serde_json::json!(v)); }
                    if let Some(v) = c.max { obj.insert("maximum".into(), serde_json::json!(v)); }
                    if let Some(v) = &c.pattern { obj.insert("pattern".into(), serde_json::json!(v)); }
                    if let Some(v) = c.max_length { obj.insert("maxLength".into(), serde_json::json!(v)); }
                }
            }
            props.insert(p.name.clone(), s);
            if p.required { req.push(serde_json::json!(p.name)); }
        }
        serde_json::json!({"type": "object", "properties": props, "required": req})
    }
}

/// Fluent builder for Action.
pub struct ActionBuilder {
    name: std::string::String, description: std::string::String, target: Option<std::string::String>,
    domain: Option<std::string::String>, operation: Option<std::string::String>,
    params: Vec<ActionParam>, returns: Option<Param>, feedback: Vec<ActionParam>, rules: ActionRules,
}

impl ActionBuilder {
    pub fn describe(mut self, d: &str) -> Self { self.description = d.to_string(); self }
    pub fn target(mut self, t: &str) -> Self { self.target = Some(t.to_string()); self }
    pub fn domain(mut self, d: &str) -> Self { self.domain = Some(d.to_string()); self }
    pub fn param(mut self, name: &str, pt: Param, desc: &str) -> Self {
        self.params.push(ActionParam { name: name.into(), param_type: pt, description: desc.into(), required: true, default: None, constraints: None }); self
    }
    pub fn optional(mut self, name: &str, pt: Param, desc: &str, def: serde_json::Value) -> Self {
        self.params.push(ActionParam { name: name.into(), param_type: pt, description: desc.into(), required: false, default: Some(def), constraints: None }); self
    }
    pub fn constrained_param(mut self, name: &str, pt: Param, desc: &str, c: ParamConstraints) -> Self {
        self.params.push(ActionParam { name: name.into(), param_type: pt, description: desc.into(), required: true, default: None, constraints: Some(c) }); self
    }
    pub fn feedback_param(mut self, name: &str, pt: Param, desc: &str) -> Self {
        self.feedback.push(ActionParam { name: name.into(), param_type: pt, description: desc.into(), required: false, default: None, constraints: None }); self
    }
    pub fn returns(mut self, r: Param) -> Self { self.returns = Some(r); self }
    // --- V3 Kriya absorption ---
    pub fn effect(mut self, e: EffectType) -> Self { self.rules.effect = e; self }
    pub fn idempotent(mut self) -> Self { self.rules.idempotent = true; self }
    // --- V7 Adhikarana absorption: authorization ---
    pub fn data_class(mut self, c: &str) -> Self { self.rules.data_classification = Some(c.into()); self }
    pub fn require_approval(mut self) -> Self { self.rules.require_approval = true; self }
    pub fn two_person(mut self) -> Self { self.rules.two_person = true; self }
    pub fn allowed_roles(mut self, r: &[&str]) -> Self { self.rules.allowed_roles = r.iter().map(|s| s.to_string()).collect(); self }
    pub fn denied_roles(mut self, r: &[&str]) -> Self { self.rules.denied_roles = r.iter().map(|s| s.to_string()).collect(); self }
    pub fn scopes(mut self, s: &[&str]) -> Self { self.rules.scopes = s.iter().map(|s| s.to_string()).collect(); self }
    // --- V7 Adhikarana absorption: execution constraints ---
    pub fn rate_limit(mut self, n: u32) -> Self { self.rules.rate_limit = Some(n); self }
    pub fn max_cost(mut self, usd: f64) -> Self { self.rules.max_cost_usd = Some(usd); self }
    pub fn max_tokens(mut self, t: u64) -> Self { self.rules.max_tokens = Some(t); self }
    pub fn max_chain_depth(mut self, d: u32) -> Self { self.rules.max_chain_depth = Some(d); self }
    pub fn timeout_ms(mut self, ms: u64) -> Self { self.rules.timeout_ms = Some(ms); self }
    // --- V7 Adhikarana absorption: context constraints ---
    pub fn environment(mut self, e: &str) -> Self { self.rules.environment = Some(e.into()); self }
    pub fn jurisdiction(mut self, j: &str) -> Self { self.rules.jurisdiction = Some(j.into()); self }
    // --- V8 Pratyaya absorption ---
    pub fn rollback(mut self, r: RollbackStrategy) -> Self { self.rules.rollback = r; self }
    pub fn postcondition(mut self, desc: &str, assertion: Option<&str>) -> Self {
        self.rules.postconditions.push(Postcondition { description: desc.into(), assertion: assertion.map(|s| s.into()), required: true }); self
    }
    pub fn allow_partial(mut self) -> Self { self.rules.allow_partial = true; self }
    // --- VakyaMeta.compliance absorption ---
    pub fn compliance(mut self, f: &[&str]) -> Self { self.rules.compliance = f.iter().map(|s| s.to_string()).collect(); self }
    pub fn retention_days(mut self, d: u64) -> Self { self.rules.retention_days = Some(d); self }
    // --- Physical safety ---
    pub fn reversible(mut self) -> Self { self.rules.reversible = true; self }
    pub fn interlock(mut self, expr: &str) -> Self { self.rules.interlock = Some(expr.into()); self }
    pub fn build(self) -> Action {
        Action { name: self.name, description: self.description, target: self.target, domain: self.domain, operation: self.operation, params: self.params, returns: self.returns, feedback: self.feedback, rules: self.rules }
    }
}

impl std::fmt::Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "⚡ {}", self.name)?;
        if let Some(t) = &self.target { write!(f, " → {}", t)?; }
        write!(f, " — {}", self.description)?;
        if !self.params.is_empty() {
            write!(f, " (")?;
            for (i, p) in self.params.iter().enumerate() {
                if i > 0 { write!(f, ", ")?; }
                write!(f, "{}: {}", p.name, p.param_type.schema_type())?;
                if !p.required { write!(f, "?")?; }
            }
            write!(f, ")")?;
        }
        if self.rules.require_approval { write!(f, " 🔐")?; }
        if self.rules.two_person { write!(f, " 👥")?; }
        if let Some(dc) = &self.rules.data_classification { write!(f, " 🔒{}", dc)?; }
        Ok(())
    }
}

impl std::fmt::Display for ActionResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ActionResult::Success { data } => write!(f, "✅ {}", data),
            ActionResult::Error { code, message } => write!(f, "💥 [{}] {}", code, message),
            ActionResult::PendingApproval { approver, reason } => write!(f, "⏳ {} — {}", approver, reason),
            ActionResult::Feedback { progress, message } => write!(f, "📊 {:.0}% {}", progress * 100.0, message),
        }
    }
}

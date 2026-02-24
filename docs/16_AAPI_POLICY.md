# AAPI Policy

> PolicyRule, MetaRules engine, BudgetTracker, IssuedCapability
> Source: `aapi/crates/aapi-metarules/`, `connector/crates/connector-engine/src/aapi.rs`

---

## PolicyRule

```rust
// connector-engine/src/aapi.rs
pub struct PolicyRule {
    pub rule_id:          String,
    pub effect:           PolicyEffect,
    pub action_pattern:   String,   // glob: "memory.*", "tool.call", "*"
    pub resource_pattern: String,   // glob: "ns:triage", "ehr:*", "*"
    pub roles:            Vec<String>,  // roles this rule applies to
    pub conditions:       Vec<PolicyCondition>,
    pub priority:         i32,      // higher = evaluated first
}

pub enum PolicyEffect {
    Allow,
    Deny,
    RequireApproval,  // human-in-the-loop gate
}
```

---

## ActionPolicy

A named collection of rules applied to an agent or pipeline:

```rust
pub struct ActionPolicy {
    pub policy_id: String,
    pub name:      String,
    pub rules:     Vec<PolicyRule>,
    pub default:   PolicyEffect,  // effect when no rule matches
}
```

---

## PolicyDecision

```rust
pub struct PolicyDecision {
    pub allowed:      bool,
    pub effect:       PolicyEffect,
    pub matched_rule: Option<String>,  // rule_id that matched
    pub reason:       String,
    pub requires_approval: bool,
}
```

---

## MetaRules Engine (aapi-metarules)

The MetaRules engine evaluates `PolicyRule` lists against incoming VAKYA tokens:

```
Evaluation order:
  1. Sort rules by priority (descending)
  2. For each rule, check:
     a. action_pattern matches Vakya.kriya (V3)
     b. resource_pattern matches Vakya.karma (V2)
     c. roles contains agent's role
     d. all conditions satisfied
  3. First matching rule wins
  4. If no rule matches → apply ActionPolicy.default
```

**Deny is absolute**: a `Deny` rule with higher priority than an `Allow` rule always wins.

---

## FederatedPolicyEngine (aapi-federation)

Three-level policy hierarchy for distributed deployments:

```
Level 1: Local policy   (this cell's ActionPolicy)
Level 2: Cluster policy (shared across cells in a cluster)
Level 3: Federation policy (shared across organizations)

Evaluation: local → cluster → federation
Federation Deny is absolute — overrides local Allow at any level
```

```rust
pub struct FederatedPolicyEngine {
    local:      ActionPolicy,
    cluster:    Option<ActionPolicy>,
    federation: Option<ActionPolicy>,
}

impl FederatedPolicyEngine {
    pub fn evaluate(&self, vakya: &Vakya) -> PolicyDecision
    // Returns first Deny found at any level (federation Deny is absolute)
    // Returns Allow only if all levels allow
    // Returns RequireApproval if any level requires it
}
```

---

## BudgetTracker

Enforces resource limits per agent:

```rust
pub struct BudgetTracker {
    pub agent_pid:        String,
    pub token_budget:     u64,       // max tokens per pipeline run
    pub tokens_used:      u64,
    pub cost_budget_usd:  Option<f64>,
    pub cost_used_usd:    f64,
    pub action_budget:    u32,       // max actions per run
    pub actions_used:     u32,
}

impl BudgetTracker {
    pub fn check_tokens(&self, requested: u64) -> Result<(), BudgetError>
    pub fn check_cost(&self, requested: f64) -> Result<(), BudgetError>
    pub fn check_actions(&self) -> Result<(), BudgetError>
    pub fn consume_tokens(&mut self, n: u64)
    pub fn consume_cost(&mut self, usd: f64)
    pub fn consume_action(&mut self)
}
```

---

## RequireApproval Gate

When a `PolicyRule` has `effect: RequireApproval`:

1. Action is **suspended** — not executed yet
2. An `ApprovalRequest` event is published to the event bus
3. Human (or automated approver) calls `action.approve` verb
4. On approval: action executes, `ActionRecord` written
5. On rejection: `PolicyDecision { allowed: false }` returned, audit logged

```yaml
# connector.yaml — require approval for prescriptions
policies:
  prescribe_policy:
    rules:
      - effect: require_approval
        action: tool.call
        resource: "tool:prescribe_medication"
        roles: [doctor_ai]
```

---

## ActionEngine (connector-engine)

```rust
// connector-engine/src/aapi.rs
pub struct ActionEngine {
    policies:       Vec<ActionPolicy>,
    budget_tracker: BudgetTracker,
    issued_caps:    Vec<IssuedCapability>,
}

impl ActionEngine {
    pub fn evaluate(&mut self, vakya: &Vakya) -> PolicyDecision
    pub fn issue_capability(&mut self, vakya: &Vakya) -> IssuedCapability
    pub fn check_budget(&self, tokens: u64, cost: f64) -> Result<(), BudgetError>
}
```

---

## ComplianceConfig

```rust
pub struct ComplianceConfig {
    pub frameworks:  Vec<String>,   // ["hipaa", "soc2", "gdpr", "eu_ai_act"]
    pub jurisdiction: Option<String>,
    pub retention_days: u64,
    pub require_signing: bool,
    pub require_audit_trail: bool,
}
```

`ComplianceConfig` is passed to `DualDispatcher` and enforces framework-specific rules at the action evaluation layer.

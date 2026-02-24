# Dual Dispatcher

> DualDispatcher, Firewall, InstructionPlane, BehaviorAnalyzer
> Source: `connector/crates/connector-engine/src/dispatcher.rs`, `firewall.rs`, `behavior.rs`

---

## DualDispatcher

The central router for all agent operations. Every `agent.run()` and `pipeline.run()` call goes through `DualDispatcher`. It routes memory ops to Ring 1 (VAC MemoryKernel) and action ops to Ring 2 (AAPI ActionEngine).

```rust
pub struct DualDispatcher<'k> {
    pipeline_id:  String,
    compliance:   Vec<String>,
    security:     DispatcherSecurity,
    // Kernel: owned or borrowed (shared across agents)
    kernel:       KernelMode<'k>,   // Owned(MemoryKernel) | Borrowed(&'k mut MemoryKernel)
    // Sub-systems
    firewall:     AgentFirewall,
    behavior:     BehaviorAnalyzer,
    checkpoint:   CheckpointManager,
    action_engine: ActionEngine,
    instruction:  InstructionPlane,
    llm_router:   LlmRouter,
}
```

**Dual mode**:
- `DualDispatcher::new(pipeline_id)` — owns the kernel (single-pipeline use)
- `DualDispatcher::with_kernel(pipeline_id, &mut kernel)` — borrows shared kernel (multi-agent pipelines)

---

## DispatcherSecurity

```rust
pub struct DispatcherSecurity {
    pub signing_enabled:      bool,
    pub scitt:                bool,
    pub require_mfa:          bool,
    pub max_delegation_depth: u8,
    pub data_classification:  Option<String>,
    pub jurisdiction:         Option<String>,
    pub retention_days:       u64,
}
```

---

## Operation Flow

Every operation passes through this sequence:

```
1. Firewall.evaluate(input)
   → ThreatScorer computes weighted signal scores
   → Verdict: Allow | Warn | Review | Block
   → Block → return EngineError::InstructionBlocked

2. InstructionPlane.validate(operation, source, actor)
   → Checks typed schema (domain.verb format)
   → Default-deny: unknown operations rejected
   → Actor gating: operation must be in actor's allowed list
   → Fail → return EngineError::InstructionBlocked

3. BehaviorAnalyzer.record(agent_pid, operation)
   → Sliding window anomaly detection
   → Anomaly → add warning to output (does not block by default)

4. CheckpointManager.on_write(packet)
   → Write-through persist to store (if write_through=true)
   → WAL entry appended

5. Ring 1: MemoryKernel.dispatch(SyscallRequest)
   → Returns SyscallResult { outcome, audit_entry, value }

6. Ring 2: ActionEngine.evaluate(vakya)
   → Returns PolicyDecision { allowed, effect, reason }

7. AutoVakya.build(agent_pid, operation, pipeline_id)
   → Builds and signs VAKYA token
   → vakya_id stored in SyscallRequest and MemPacket
```

---

## AgentFirewall

```rust
// connector-engine/src/firewall.rs
pub struct AgentFirewall {
    config:  FirewallConfig,
    scorer:  ThreatScorer,
    log:     Vec<FirewallEvent>,
}

pub struct ThreatScorer {
    weights: SignalWeights,
    thresholds: VerdictThresholds,
}

pub enum Verdict {
    Allow,   // score < warn threshold
    Warn,    // score >= warn threshold
    Review,  // score >= review threshold (flag for human review)
    Block,   // score >= block threshold
}
```

### Signal Weights (defaults)

| Signal | Default Weight | What it detects |
|--------|---------------|-----------------|
| `injection` | 0.35 | Prompt injection patterns |
| `pii` | 0.30 | PII in output (SSN, credit card, email, phone, DOB, medical record) |
| `anomaly` | 0.20 | Behavioral anomaly from BehaviorAnalyzer |
| `policy_violation` | 0.25 | Explicit policy rule violation |
| `rate_pressure` | 0.15 | Rate limit approaching |
| `boundary_crossing` | 0.10 | Cross-namespace access attempt |

### Verdict Thresholds (defaults)

| Verdict | Default Threshold |
|---------|-----------------|
| Warn | 0.3 |
| Review | 0.6 |
| Block | 0.8 |

### Presets

```rust
FirewallConfig::default()  // block_injection=true, standard weights
FirewallConfig::strict()   // lower thresholds, more PII types
FirewallConfig::hipaa()    // PHI-specific PII types, strict thresholds
```

### FirewallConfig

```rust
pub struct FirewallConfig {
    pub block_injection_by_default: bool,  // default: true
    pub injection_threshold:        f64,
    pub pii_types:                  HashSet<String>,  // ssn|credit_card|email|phone|dob|medical_record
    pub pii_threshold:              f64,
    pub blocked_tools:              Vec<String>,
    pub max_calls_per_minute:       u32,
    pub max_input_length:           usize,
    pub weights:                    SignalWeights,
    pub thresholds:                 VerdictThresholds,
}
```

---

## InstructionPlane

Default-deny typed schema validation for all operations:

```rust
// connector-engine/src/instruction.rs
pub struct InstructionPlane {
    schemas:  HashMap<String, InstructionSchema>,  // domain.verb → schema
    actors:   HashMap<String, ActorPermissions>,   // actor_name → allowed ops
}
```

**10 standard schemas** (registered automatically):

| Schema | Allowed Sources |
|--------|----------------|
| `memory.write` | tool, self |
| `memory.read` | tool, self, user |
| `memory.seal` | self |
| `knowledge.query` | tool, self, user |
| `knowledge.ingest` | tool, self |
| `knowledge.seed` | self |
| `chat.send` | user, self |
| `chat.receive` | self |
| `tool.call` | self |
| `tool.register` | self |

Actors are auto-registered in `InstructionPlane` when `register_actor()` is called on `DualDispatcher`.

---

## BehaviorAnalyzer

Sliding window anomaly detection:

```rust
// connector-engine/src/behavior.rs
pub struct BehaviorAnalyzer {
    config:   BehaviorConfig,
    windows:  HashMap<String, BehaviorWindow>,  // agent_pid → window
}

pub struct BehaviorConfig {
    pub window_ms:              i64,    // default: 60_000 (1 minute)
    pub baseline_sample_size:   usize,  // default: 100
    pub anomaly_threshold:      f64,    // default: 0.7
    pub max_actions_per_window: u32,    // default: 100
    pub max_tool_diversity:     usize,  // default: 20
    pub max_error_rate:         f64,    // default: 0.3
    pub max_data_volume:        u64,    // default: 10MB
    pub detect_contamination:   bool,   // default: true
}
```

**Anomaly signals tracked per window**:
- Action count vs `max_actions_per_window`
- Tool diversity (unique tools called) vs `max_tool_diversity`
- Error rate vs `max_error_rate`
- Data volume vs `max_data_volume`
- Contamination patterns (cross-namespace data leakage)

---

## ActorConfig

```rust
pub struct ActorConfig {
    pub name:             String,
    pub role:             String,       // "writer" | "reader" | "tool_agent" | "supervisor"
    pub namespace:        String,
    pub instructions:     Option<String>,
    pub allowed_tools:    Vec<String>,
    pub require_approval: Vec<String>,  // tool IDs requiring human approval
    pub memory_from:      Vec<String>,  // namespaces this actor can read from
    pub allowed_data:     Vec<String>,  // data classifications allowed
}
```

---

## Cross-Boundary Detection

```rust
// Namespace boundary crossing is detected when:
// owned_ns = format!("{}:{}", namespace, agent_pid)
// incoming namespace != owned_ns && no AccessGrant exists
// → signals boundary_crossing in ThreatScorer
```

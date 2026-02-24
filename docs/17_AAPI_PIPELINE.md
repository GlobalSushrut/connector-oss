# AAPI Pipeline

> VakyaPipeline, SagaCoordinator, rollback, federation
> Source: `aapi/crates/aapi-pipeline/`, `aapi/crates/aapi-federation/`

---

## VakyaPipeline

A multi-step action pipeline where each step has a VAKYA token and optional dependencies:

```rust
// aapi-pipeline
pub struct VakyaPipeline {
    pub pipeline_id: String,
    pub steps:       Vec<PipelineStep>,
    pub saga:        SagaCoordinator,
}

pub struct PipelineStep {
    pub step_id:      String,
    pub vakya:        Vakya,           // authorization token for this step
    pub depends_on:   Vec<String>,     // step_ids that must complete first
    pub route:        RouteTarget,
    pub timeout_ms:   Option<u64>,
    pub retry_count:  u32,
}

pub enum RouteTarget {
    Local,                             // execute on this cell
    Remote { cell_id: String },        // forward to another cell
    Adaptive,                          // VakyaRouter decides
}
```

---

## VakyaRouter

Routes steps to the correct cell:

```rust
pub struct VakyaRouter {
    // Resolution order:
    // 1. Adapter location (if adapter is registered on a specific cell)
    // 2. Agent location (if agent is registered on a specific cell)
    // 3. Consistent hash fallback (hash(step_id) → cell)
}
```

---

## SagaCoordinator

Manages distributed transactions with guaranteed rollback on failure:

```rust
pub struct SagaCoordinator {
    pub completed_steps: Vec<String>,  // step_ids completed so far
    pub rollback_log:    Vec<RollbackEntry>,
}

pub struct RollbackEntry {
    pub step_id:     String,
    pub vakya_id:    String,
    pub rollback_fn: String,  // name of registered rollback handler
    pub context:     serde_json::Value,
}
```

**Rollback order**: reverse of completion order (last completed → first rolled back).

```
Steps completed: [triage, diagnosis, prescribe]
On failure at "dispense":
  → rollback prescribe  (VakyaRollback event)
  → rollback diagnosis  (VakyaRollback event)
  → rollback triage     (VakyaRollback event)
```

Each rollback publishes a `VakyaRollback` `ReplicationOp` to the event bus, which is consumed by the cell that executed the original step.

---

## Pipeline Execution Flow

```
VakyaPipeline.run()
  │
  ├─ Topological sort of steps by depends_on
  │
  ├─ For each step (in dependency order):
  │    ├─ FederatedPolicyEngine.evaluate(step.vakya)
  │    │    → Deny: abort pipeline, begin rollback
  │    │    → RequireApproval: suspend, wait for ApprovalResponse
  │    │    → Allow: continue
  │    │
  │    ├─ VakyaRouter.route(step) → RouteTarget
  │    │
  │    ├─ If Local:
  │    │    → ClusterGateway.execute(step)
  │    │    → SagaCoordinator.record_completed(step_id)
  │    │
  │    └─ If Remote:
  │         → RemoteAdapter.forward(step) via EventBus
  │         → Wait for VakyaReply (timeout_ms)
  │         → SagaCoordinator.record_completed(step_id)
  │
  └─ All steps complete → PipelineResult { ok: true, ... }
```

---

## ClusterGateway

Full execution pipeline for each step on a cell:

```
1. Validate VAKYA token (signature, expiry, slots)
2. FederatedPolicyEngine.evaluate() — local + cluster + federation
3. RequireApproval gate (if needed)
4. Pre-obligations (audit log, SCITT receipt)
5. Route to adapter / execute action
6. Post-obligations (write ActionRecord, update BudgetTracker)
7. Pratyaya verify (check postconditions from V8 slot)
8. Write ActionRecord to aapi-indexdb
```

---

## RemoteAdapter

Implements the `Adapter` trait but forwards via the event bus:

```rust
pub struct RemoteAdapter {
    bus:       Arc<dyn EventBus>,
    cell_id:   String,
    timeout:   Duration,
}

impl Adapter for RemoteAdapter {
    fn execute(&self, vakya: &Vakya) -> Result<ActionResult, AdapterError> {
        // Publish VakyaForward to bus with reply_topic
        // Wait for VakyaReply on reply_topic (timeout)
        // Return result or timeout error
    }
}
```

---

## aapi-federation

### FederatedPolicyEngine

```rust
pub struct FederatedPolicyEngine {
    local:      ActionPolicy,
    cluster:    Option<ActionPolicy>,
    federation: Option<ActionPolicy>,
}
// Federation Deny is absolute — cannot be overridden by local Allow
```

### CrossCellCapabilityVerifier

Verifies UCAN-compatible delegation chains across cells:

```rust
pub struct CrossCellCapabilityVerifier {
    trusted_roots: Vec<String>,  // trusted root public keys
}

impl CrossCellCapabilityVerifier {
    pub fn verify(&self, chain: &DelegationChain) -> Result<(), VerifyError>
    // Walks each DelegationHop, verifies Ed25519 signature
    // Checks attenuation (each hop can only restrict, never expand)
    // Checks depth <= max_delegation_depth
    // Checks no hop is expired
}
```

### ScittExchange

Cross-organization attestation:

```rust
pub struct ScittExchange {
    pub receipt_id:   String,
    pub payload_cid:  Cid,
    pub issuer:       String,
    pub issued_at:    i64,
    pub signature:    Vec<u8>,
}
// Stored in redb `scitt` table
// Provides cross-org proof that a packet existed at a specific time
```

---

## ReplicationOp (AAPI extensions)

8 AAPI-specific ops added to `vac-bus::ReplicationOp`:

| Op | Purpose |
|----|---------|
| `VakyaForward` | Forward a step to a remote cell |
| `VakyaReply` | Reply from remote cell with result |
| `VakyaRollback` | Trigger rollback of a completed step |
| `PolicyUpdate` | Propagate policy change to all cells |
| `AdapterAnnounce` | Register adapter on a cell |
| `AdapterDeregister` | Remove adapter from a cell |
| `ApprovalRequest` | Request human approval |
| `ApprovalResponse` | Human approval/rejection response |

# Agent OS — Linux Revolution Coding Checklist
# Sourced from: LINUX_REVOLUTION.md, DISTRIBUTED_SCALABILITY.md, SECURITY_ISOLATION.md, FIREWALL_SECURITY.md, TOOL_ARCH.md

## Phase L1 — The Foundation: Make the OS Self-Aware
> Goal: signal delivery + observable telemetry. No new crates needed.

### L1.1 — Signal System
- [ ] Add `AgentSignal` enum to `vac-core/src/types.rs` (14 variants)
- [ ] Add `SignalAction` enum + `SignalHandler` struct to `vac-core/src/types.rs`
- [ ] Add `signal_handlers: HashMap<String, SignalAction>` field to `AgentControlBlock`
- [ ] Add `SyscallPayload::SendSignal { target_pid, signal }` variant to `vac-core/src/kernel.rs`
- [ ] Add `SyscallPayload::RegisterSignalHandler { signal_type, action }` variant to `vac-core/src/kernel.rs`
- [ ] Add `MemoryKernelOp::SendSignal` + `MemoryKernelOp::RegisterSignalHandler` to `vac-core/src/types.rs`
- [ ] Implement `handle_send_signal()` in `vac-core/src/kernel.rs` — delivers to target ACB
- [ ] Implement `handle_register_signal_handler()` in `vac-core/src/kernel.rs`
- [ ] Add `ReplicationOp::SignalDeliver { target_pid, signal_cbor }` to `vac-bus/src/types.rs`
- [ ] Update `op_type()` + `is_vac_op()` in `vac-bus/src/types.rs`
- [ ] Write 15 tests in `vac-core/src/kernel.rs`:
  - signal delivery to running agent
  - default action: Terminate kills agent
  - default action: Suspend transitions phase to Suspended
  - signal with custom handler
  - signal to non-existent agent → KernelError
  - TokenBudgetWarning signal delivery
  - SecurityAlert signal delivery
  - MemoryPressure signal delivery
  - PeerDown signal delivery
  - ApprovalGranted signal delivery
  - Custom signal with payload
  - handler overwrite (re-register)
  - signal to terminated agent ignored
  - bulk signal broadcast
  - signal audit entry created

### L1.2 — Semantic Telemetry
- [ ] Add `natural_language: String` field to `KernelAuditEntry` in `vac-core/src/types.rs`
- [ ] Add `business_impact: Option<String>` field to `KernelAuditEntry`
- [ ] Add `remediation_hint: Option<String>` field to `KernelAuditEntry`
- [ ] Add `causal_chain: Vec<String>` field to `KernelAuditEntry` (CIDs of preceding events)
- [ ] Add `severity: TelemetrySeverity` enum + field to `KernelAuditEntry`
- [ ] Create `TelemetrySeverity` enum (Debug/Info/Warn/Error/Critical/Fatal) in `vac-core/src/types.rs`
- [ ] Add `gen_ai_attrs: Option<GenAiAttributes>` struct + field for OTel attrs
- [ ] Create `GenAiAttributes` struct (system, operation, agent_id, token_input, token_output, model, threat_score)
- [ ] Update `kernel.rs` audit entry creation: populate `natural_language` from op context
- [ ] Update `audit_export.rs` to include new fields in all export formats
- [ ] Write 10 tests:
  - MemWrite audit has `natural_language` describing write
  - MemRead failure audit has `remediation_hint`
  - AccessDenied audit has `business_impact`
  - `severity` = Error on access-denied events
  - `severity` = Info on successful read/write
  - causal_chain links parent → child CIDs
  - GenAiAttributes populated on LLM-related ops
  - audit export includes new fields
  - severity ordering correct
  - OTel attribute names follow gen_ai.* convention

---

## Phase L2 — Compute Fairness: Stop Agent Starvation

### L2.1 — Token Budget System
- [ ] Add `AgentPriority` enum (RealTime/High/Normal/Background/Idle) to `vac-core/src/types.rs`
- [ ] Add `TokenBudget` struct to `vac-core/src/types.rs` (daily_limit, hourly_limit, burst_limit, used_today, used_this_hour, cost_center, reset_at_daily, reset_at_hourly)
- [ ] Add `token_budget: Option<TokenBudget>` field to `AgentControlBlock`
- [ ] Add `agent_priority: AgentPriority` field to `AgentControlBlock` (replace bare `priority: u8`)
- [ ] Add `SyscallPayload::SetTokenBudget { budget }` variant
- [ ] Add `SyscallPayload::RecordTokenUsage { input_tokens, output_tokens, cost_usd, model }` variant
- [ ] Implement `handle_set_token_budget()` in `kernel.rs`
- [ ] Implement `handle_record_token_usage()` — increments counters, fires signal if > 80% / 100%
- [ ] Add `token_budget_enforce()` helper — returns `Err` if budget exhausted before LLM call
- [ ] Wire `RecordTokenUsage` into `DualDispatcher` after every LLM call in `dispatcher.rs`
- [ ] Write 10 tests:
  - budget set and retrieved from ACB
  - usage recorded increments counters
  - usage exceeds daily → TokenBudgetExhausted signal fired
  - usage at 80% → TokenBudgetWarning signal fired
  - hourly reset works
  - daily reset works
  - burst_limit enforced per-request
  - enforcement blocks LLM call when exhausted
  - cost_usd tracked per provider
  - cost_center field populated

### L2.2 — LLM Scheduler (FIFO + Round Robin)
- [ ] Create `vac-core/src/scheduler.rs` — new file
- [ ] Define `LlmRequest` struct (request_id, agent_pid, priority, payload, enqueued_at, deadline_ms)
- [ ] Define `LlmScheduler` struct (queues per priority, active_requests, policy, virtual_runtime map)
- [ ] Define `SchedulingPolicy` enum (Fifo, RoundRobin, Cfs)
- [ ] Implement `LlmScheduler::enqueue()` — adds request to correct priority queue
- [ ] Implement `LlmScheduler::next()` — returns next request per policy (FIFO: highest priority first; RR: round-robin within priority)
- [ ] Implement `LlmScheduler::complete()` — removes from active, updates virtual runtime
- [ ] Implement `LlmScheduler::queue_depth()` — total pending requests
- [ ] Add `pub mod scheduler;` to `vac-core/src/lib.rs`
- [ ] Write 10 tests in `scheduler.rs`:
  - FIFO: RealTime before Normal
  - FIFO: arrival order within same priority
  - RR: equal requests get equal turns
  - enqueue + next returns correct request
  - complete removes from active
  - empty queue returns None
  - queue_depth correct
  - virtual_runtime updated on complete (CFS mode)
  - multiple priorities coexist
  - 100 requests enqueued + drained in order

### L2.3 — ComputeCgroup FinOps
- [ ] Add `ComputeCgroup` struct to `vac-core/src/types.rs` (name, token_quota_daily, token_quota_hourly, compute_weight, cost_center, children: Vec<String>)
- [ ] Add `ComputeUsageRecord` struct (agent_pid, model, input_tokens, output_tokens, cost_usd, latency_ms, cgroup, timestamp, cid)
- [ ] Add `SyscallPayload::RegisterCgroup { cgroup }` + `SyscallPayload::RecordComputeUsage { record }` variants
- [ ] Store `ComputeUsageRecord` in VAC namespace `sys:compute:usage` via kernel
- [ ] Write 8 tests:
  - cgroup registered and stored
  - usage record stored in sys:compute:usage namespace
  - cost_usd accumulated correctly
  - quota enforced at cgroup level
  - nested cgroups (parent limit covers children)
  - usage record has CID (content-addressed)
  - usage query by cost_center
  - usage query by model

---

## Phase L3 — Identity & Protocols: Connect to the Ecosystem

### L3.1 — Agent DID + Agent Card
- [ ] Create `aapi-federation/src/identity.rs` — new file
- [ ] Define `AgentCapability` struct (domain, actions, data_types, rate_limits)
- [ ] Define `ServiceEndpoint` struct (id, type_, url)
- [ ] Define `AuthMethod` struct (type_, public_key_multibase)
- [ ] Define `AgentCard` struct (did, name, description, version, capabilities, supported_protocols, authentication, service_endpoints, public_key, scitt_receipt, created_at, expires_at)
- [ ] Implement `AgentCard::generate_did(cell_id, agent_pid) -> String` — `did:connector:{cell_id}:{agent_pid}`
- [ ] Implement `AgentCard::sign(&self, keypair) -> Vec<u8>` using Ed25519
- [ ] Implement `AgentCard::verify(&self) -> bool`
- [ ] Define `AgentRegistry` struct wrapping a namespace reference
- [ ] Implement `AgentRegistry::register()` — store card in `sys:registry:agents` namespace
- [ ] Implement `AgentRegistry::lookup_by_did()` — read from namespace
- [ ] Implement `AgentRegistry::discover_by_capability()` — scan namespace for matching domain/action
- [ ] Add `pub mod identity;` to `aapi-federation/src/lib.rs`
- [ ] Write 12 tests:
  - DID generated correctly from cell_id + agent_pid
  - AgentCard serializes/deserializes
  - sign + verify round-trip
  - tampered card fails verify
  - register + lookup_by_did
  - lookup non-existent DID returns None
  - discover_by_capability finds matching agents
  - discover_by_capability returns empty for no match
  - expired card detected
  - scitt_receipt field populated
  - supported_protocols field present
  - card stored in correct namespace

### L3.2 — MCP Bridge
- [ ] Create `connector/crates/connector-protocols/` new crate directory
- [ ] Create `connector/crates/connector-protocols/Cargo.toml`
- [ ] Create `connector/crates/connector-protocols/src/lib.rs` with `pub mod mcp; pub mod a2a; pub mod error;`
- [ ] Create `connector/crates/connector-protocols/src/error.rs`
- [ ] Create `connector/crates/connector-protocols/src/mcp.rs`
- [ ] Define `McpTool` struct (name, description, input_schema) from ToolBinding
- [ ] Define `McpResource` struct (uri, name, description, mime_type) — maps to VAC namespace CIDs
- [ ] Define `McpRequest` / `McpResponse` types (JSON-RPC 2.0 format)
- [ ] Implement `McpBridge::tools_list()` — returns agent's ToolBindings as McpTools
- [ ] Implement `McpBridge::tools_call()` — translates to `SyscallPayload::ToolDispatch`, routes through `AgentFirewall`
- [ ] Implement `McpBridge::resources_list()` — returns namespace packets as McpResources
- [ ] Implement `McpBridge::resources_read()` — translates to `SyscallPayload::MemRead`
- [ ] Write 15 tests:
  - ToolBinding → McpTool conversion
  - tools_list returns correct count
  - tools_call routes through firewall
  - blocked tool call returns MCP error
  - resources_list returns namespace CIDs
  - resources_read returns correct packet content
  - invalid tool name → McpError
  - MCP JSON-RPC request parsed correctly
  - MCP JSON-RPC response serialized correctly
  - firewall injection blocked in tools_call
  - rate limit enforced
  - audit entry created on tool call
  - auth token validated
  - schema mismatch → McpError
  - parallel tool calls handled

### L3.3 — A2A Bridge
- [ ] Create `connector/crates/connector-protocols/src/a2a.rs`
- [ ] Define `A2ATask` struct (id, sender_did, capability, payload, deadline_ms, reply_endpoint)
- [ ] Define `A2ATaskResult` struct (task_id, status, result_cbor, audit_cid)
- [ ] Define `A2ATaskStatus` enum (Submitted/Working/Completed/Failed/Cancelled)
- [ ] Implement `A2ABridge::receive_task()` — verify sender DID, route to VakyaRouter, return result
- [ ] Implement `A2ABridge::delegate_task()` — lookup target agent card, send A2A task via HTTP
- [ ] Implement `A2ABridge::serve_agent_card()` — returns AgentCard for a given agent_pid
- [ ] Wire DelegationChain verification into `receive_task()`
- [ ] Write 15 tests:
  - receive_task routes to correct adapter
  - invalid sender DID rejected
  - expired DelegationChain rejected
  - task result has audit_cid
  - task status transitions correctly
  - delegate_task serializes correctly
  - serve_agent_card returns correct card
  - task with deadline enforced
  - failed task returns A2ATaskStatus::Failed
  - cancelled task returns A2ATaskStatus::Cancelled
  - task replay (same id) idempotent
  - delegation depth limit enforced
  - firewall gates incoming tasks
  - capability mismatch rejected
  - audit entry on every received task

---

## Phase L4 — Context & Self-Healing: Make the OS Resilient

### L4.1 — Context Manager (LLM Snapshots)
- [ ] Create `connector-engine/src/context_manager.rs` — new file
- [ ] Define `SnapshotType` enum (TextBased, LogitsBased)
- [ ] Define `ContextSnapshot` struct (agent_pid, request_id, snapshot_type, partial_output, messages_so_far, tokens_consumed, created_at, cid)
- [ ] Define `ContextManager` struct (active_snapshots HashMap, namespace String)
- [ ] Implement `ContextManager::snapshot()` — saves current LLM state
- [ ] Implement `ContextManager::restore()` — reconstructs LlmRequest from snapshot
- [ ] Implement `ContextManager::compress()` — truncates/summarizes partial_output
- [ ] Implement `ContextManager::evict_to_store()` — writes snapshot to VAC namespace `sys:context:snapshots`
- [ ] Implement `ContextManager::resume_from_store()` — retrieves snapshot from VAC namespace
- [ ] Add `pub mod context_manager;` to `connector-engine/src/lib.rs`
- [ ] Write 10 tests:
  - snapshot created with correct fields
  - restore returns reconstructable request
  - compress reduces tokens_consumed
  - evict writes to sys:context:snapshots namespace
  - resume_from_store retrieves correct snapshot
  - snapshot has CID (content-addressed)
  - two agents have independent snapshots
  - stale snapshot (expired) detected
  - TextBased snapshot for closed-source model
  - snapshot survives round-trip serialization

### L4.2 — System Watchdog
- [ ] Create `connector-engine/src/watchdog.rs` — new file
- [ ] Define `WatchdogCondition` enum (8 variants: CellHeartbeatMissed, AgentErrorRateHigh, TokenBudgetExhausted, MemoryQuotaExceeded, ClusterPartitionDetected, StabilityIndexLow, ThreatScoreElevated, Custom)
- [ ] Define `WatchdogAction` enum (8 variants: RestartAgent, SuspendAgent, EvictToTier, TriggerMerkleSync, SendSignal, NotifyHuman, ExecuteVakya, Custom)
- [ ] Define `WatchdogRule` struct (name, condition, action, cooldown, last_triggered)
- [ ] Define `WatchdogState` struct (agent_statuses, cell_metrics, threat_scores)
- [ ] Define `SystemWatchdog` struct (rules, state, dispatcher ref)
- [ ] Implement `SystemWatchdog::add_rule()` — register a rule
- [ ] Implement `SystemWatchdog::evaluate()` — evaluate all rules, fire matching actions
- [ ] Implement `SystemWatchdog::apply_action()` — dispatch the action
- [ ] Implement default rules: MemoryQuotaExceeded → EvictToTier, ThreatScoreElevated → SendSignal
- [ ] Add `pub mod watchdog;` to `connector-engine/src/lib.rs`
- [ ] Write 12 tests:
  - rule added and stored
  - MemoryQuotaExceeded triggers EvictToTier
  - ThreatScoreElevated triggers SendSignal
  - cooldown prevents duplicate firing
  - TokenBudgetExhausted triggers SuspendAgent
  - CellHeartbeatMissed triggers TriggerMerkleSync
  - StabilityIndexLow triggers NotifyHuman
  - custom condition with closure
  - custom action with closure
  - 5 rules evaluated in one pass
  - action fires signal via SignalDeliver
  - rule with no match does nothing

### L4.3 — Adaptive Router
- [ ] Add `WorkloadType` enum (Interactive/Batch/Background/Realtime) to `aapi-pipeline/src/router.rs`
- [ ] Add `WorkloadProfile` struct (workload_type, avg_tokens, avg_latency_ms, priority, deadline_ms)
- [ ] Add `CellMetrics` struct (cell_id, active_agents, queue_depth, avg_inference_latency_ms, token_throughput, load)
- [ ] Extend `VakyaRouter` to hold `cell_metrics: HashMap<String, CellMetrics>`
- [ ] Implement `VakyaRouter::update_cell_metrics()` — parse from Heartbeat ReplicationOp
- [ ] Implement `VakyaRouter::route_adaptive()` — Interactive→lowest latency, Batch→highest throughput, Realtime→preempt Background
- [ ] Write 10 tests:
  - Interactive routes to lowest latency cell
  - Batch routes to highest throughput cell
  - Realtime fires Suspend signals to Background agents
  - cell_metrics updated from Heartbeat
  - no metrics falls back to ring hash
  - all-equal cells fall back to ring hash
  - deadline-exceeded → re-route
  - dead cell not selected
  - metrics staleness detected (no heartbeat > 90s)
  - load > 90% cell excluded

---

## Phase L5 — Economic Primitives + Marketplace + Extension Hooks

### L5.1 — Agent Payment Protocol (AP2)
- [ ] Create `aapi-federation/src/payment.rs` — new file
- [ ] Define `MandateType` enum (CartMandate, IntentMandate, PaymentMandate)
- [ ] Define `PaymentMandate` struct (mandate_id, issuer_did, agent_did, mandate_type, max_amount, currency, merchant_constraints, category_constraints, expires_at, signature, scitt_receipt)
- [ ] Implement `PaymentMandate::sign()` using Ed25519 (reuse `DelegationChain::sign_proof` pattern)
- [ ] Implement `PaymentMandate::verify()` — check signature + expiry + amount bounds
- [ ] Add `SyscallPayload::PaymentRequest { mandate_id, amount, merchant, currency }` to `kernel.rs`
- [ ] Implement `handle_payment_request()` in `kernel.rs` — verifies mandate, creates audit entry
- [ ] Wire `AgentFirewall` check: amount ≤ mandate.max_amount, merchant in constraints
- [ ] Add `pub mod payment;` to `aapi-federation/src/lib.rs`
- [ ] Write 10 tests:
  - mandate sign + verify round-trip
  - tampered mandate fails verify
  - expired mandate rejected
  - amount over max_amount rejected by firewall
  - merchant not in constraints rejected
  - PaymentMandate serializes/deserializes
  - CartMandate type correct
  - IntentMandate type correct
  - audit entry created on payment request
  - scitt_receipt field populated

### L5.2 — Agent Marketplace
- [ ] Create `aapi-federation/src/marketplace.rs` — new file
- [ ] Define `PricingModel` enum (Free/PerCall/PerToken/Subscription)
- [ ] Define `AgentPricing` struct (model, rate, currency)
- [ ] Define `AgentHealth` struct (status, uptime_pct, avg_latency_ms, error_rate)
- [ ] Define `AgentListing` struct (card, provider_org, pricing, health, scitt_receipt)
- [ ] Define `AgentMarketplace` struct (local_registry ref, federation ref)
- [ ] Implement `AgentMarketplace::discover()` — local first, federation fallback
- [ ] Implement `AgentMarketplace::publish_listing()` — add to sys:marketplace namespace
- [ ] Implement `AgentMarketplace::verify_listing()` — Ed25519 + SCITT check
- [ ] Add `pub mod marketplace;` to `aapi-federation/src/lib.rs`
- [ ] Write 10 tests:
  - publish_listing stores in correct namespace
  - discover returns local match
  - discover falls back to federation
  - verify_listing passes valid card
  - tampered listing fails verify
  - pricing model serializes correctly
  - health struct populated
  - capability filter in discover
  - expired listing excluded
  - free tier listing has no pricing

### L5.3 — Kernel Extension Hooks
- [ ] Create `vac-core/src/extensions.rs` — new file
- [ ] Define `HookDecision` enum (Allow/Deny(String)/Modify(SyscallPayload))
- [ ] Define `KernelHook` enum (PreSyscall/PostSyscall/OnAgentRegister/OnAgentTerminate/OnMemWrite/OnAuditEntry/OnThreatDetected/OnTokenBudgetExhausted)
- [ ] Define `KernelExtension` trait (name(), version(), hooks())
- [ ] Define `ExtensionRegistry` struct (extensions: Vec<Box<dyn KernelExtension>>)
- [ ] Implement `ExtensionRegistry::load()` — verify + register extension
- [ ] Implement `ExtensionRegistry::fire_pre_syscall()` — runs all PreSyscall hooks, first Deny wins
- [ ] Implement `ExtensionRegistry::fire_post_syscall()` — runs all PostSyscall hooks
- [ ] Implement `ExtensionRegistry::fire_on_mem_write()` — runs OnMemWrite hooks
- [ ] Wire `fire_pre_syscall()` into `MemoryKernel::dispatch()` before execution
- [ ] Wire `fire_post_syscall()` into `MemoryKernel::dispatch()` after execution
- [ ] Add `pub mod extensions;` to `vac-core/src/lib.rs`
- [ ] Write 10 tests:
  - extension loaded and hooks registered
  - PreSyscall Allow passes through
  - PreSyscall Deny blocks syscall
  - PreSyscall Modify changes payload
  - PostSyscall fires after success
  - OnMemWrite fires on every write
  - OnAuditEntry fires on audit log
  - two extensions both fire
  - extension with Deny has priority over Allow
  - extension unloaded cleanly

---

## Test Count Targets

| Phase | New Tests | Cumulative |
|-------|-----------|------------|
| L1.1 Signal System | 15 | 15 |
| L1.2 Semantic Telemetry | 10 | 25 |
| L2.1 Token Budget | 10 | 35 |
| L2.2 LLM Scheduler | 10 | 45 |
| L2.3 Compute Cgroup | 8 | 53 |
| L3.1 Agent DID + Card | 12 | 65 |
| L3.2 MCP Bridge | 15 | 80 |
| L3.3 A2A Bridge | 15 | 95 |
| L4.1 Context Manager | 10 | 105 |
| L4.2 System Watchdog | 12 | 117 |
| L4.3 Adaptive Router | 10 | 127 |
| L5.1 Payment Protocol | 10 | 137 |
| L5.2 Marketplace | 10 | 147 |
| L5.3 Extension Hooks | 10 | 157 |
| **TOTAL NEW** | **157** | **157** |

---

## Files Modified / Created

### Modified
- `vac-core/src/types.rs` — AgentSignal, SignalAction, SignalHandler, AgentPriority, TokenBudget, ComputeCgroup, TelemetrySeverity, GenAiAttributes, KernelAuditEntry fields
- `vac-core/src/kernel.rs` — SendSignal, RegisterSignalHandler, SetTokenBudget, RecordTokenUsage, RegisterCgroup, RecordComputeUsage, PaymentRequest handlers + tests
- `vac-bus/src/types.rs` — ReplicationOp::SignalDeliver variant
- `connector-engine/src/dispatcher.rs` — wire RecordTokenUsage after LLM calls
- `aapi-federation/src/lib.rs` — add identity, payment, marketplace modules
- `aapi-pipeline/src/router.rs` — WorkloadType, WorkloadProfile, CellMetrics, adaptive routing
- `vac-core/src/lib.rs` — add scheduler, extensions modules
- `connector-engine/src/lib.rs` — add context_manager, watchdog modules

### Created (new files)
- `vac-core/src/scheduler.rs`
- `vac-core/src/extensions.rs`
- `connector-engine/src/context_manager.rs`
- `connector-engine/src/watchdog.rs`
- `aapi-federation/src/identity.rs`
- `aapi-federation/src/payment.rs`
- `aapi-federation/src/marketplace.rs`
- `connector/crates/connector-protocols/Cargo.toml`
- `connector/crates/connector-protocols/src/lib.rs`
- `connector/crates/connector-protocols/src/error.rs`
- `connector/crates/connector-protocols/src/mcp.rs`
- `connector/crates/connector-protocols/src/a2a.rs`

---

## Progress Tracking

- [ ] L1.1 Signal System ............. 0/15 tests
- [ ] L1.2 Semantic Telemetry ......... 0/10 tests
- [ ] L2.1 Token Budget ............... 0/10 tests
- [ ] L2.2 LLM Scheduler .............. 0/10 tests
- [ ] L2.3 Compute Cgroup ............. 0/8 tests
- [ ] L3.1 Agent DID + Card ........... 0/12 tests
- [ ] L3.2 MCP Bridge ................. 0/15 tests
- [ ] L3.3 A2A Bridge ................. 0/15 tests
- [ ] L4.1 Context Manager ............ 0/10 tests
- [ ] L4.2 System Watchdog ............ 0/12 tests
- [ ] L4.3 Adaptive Router ............ 0/10 tests
- [ ] L5.1 Payment Protocol ........... 0/10 tests
- [ ] L5.2 Marketplace ................ 0/10 tests
- [ ] L5.3 Extension Hooks ............ 0/10 tests

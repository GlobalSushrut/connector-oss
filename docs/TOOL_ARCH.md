# TOOL_ARCH.md — Agent Operating Substrate: Capability Computer + Cryptographic Execution Contracts

> **The one-line definition:**
> "Agent OS = capability microkernel + sandboxed runners + cryptographic chain-of-custody for every action."

---

## Table of Contents

1. [The Fundamental Problem — Why "Tool Calling" Is the Wrong Abstraction](#1-the-fundamental-problem)
2. [Research Foundations](#2-research-foundations)
3. [The Capability Taxonomy — Everything the Agent Can Do](#3-the-capability-taxonomy)
4. [The 5 Core Rust Traits — The Mathematical Skeleton](#4-the-5-core-rust-traits)
5. [The Execution Contract — Three-Phase Cryptographic Agreement](#5-the-execution-contract)
6. [The Cryptographic Burn — Permanent Execution Proof](#6-the-cryptographic-burn)
7. [Runner Architecture — Environment-Agnostic Execution](#7-runner-architecture)
8. [Capability Token System — UCAN-Style Delegation with Attenuation](#8-capability-token-system)
9. [Integration with Existing Architecture — Where This Fits](#9-integration-with-existing-architecture)
10. [New Crate: connector-caps — Design and Modules](#10-new-crate-connector-caps)
11. [End-to-End Example — Canva Workflow as Capability Chain](#11-end-to-end-example-canva-workflow)
12. [End-to-End Example — Hospital Agent Prescribing Medication](#12-end-to-end-example-hospital-agent)
13. [Implementation Plan — Crates, Phases, Tests](#13-implementation-plan)
14. [Industry Comparison — What Nobody Else Has](#14-industry-comparison)

---

## 1. The Fundamental Problem

### Why "Tool Calling" Is Wrong

Every major agent framework today — LangChain, CrewAI, OpenAI Agents SDK, Anthropic Computer Use, MCP — treats external actions as **tool calls**:

```
agent.call_tool("search_web", {"query": "latest AI news"})
→ returns string
```

This model has five fatal flaws:

| Flaw | Description | Real Consequence |
|------|-------------|-----------------|
| **No isolation** | Tool runs in same process/context as agent | Malicious tool poisons agent memory |
| **No contract** | No formal agreement on what the tool will do | Agent thinks it read a file; tool deleted it |
| **No proof** | No cryptographic record of what happened | Can't audit, can't verify, can't replay |
| **No scope** | Tool can access anything unless manually restricted | Finance agent reads health records |
| **Brand-tied** | Code says "call Canva API" not "export asset" | Swap vendor → rewrite agent |

### The Root Cause

The root cause is thinking at the **brand/product layer** instead of the **capability layer**:

```
Wrong: "The agent uses Canva, GitHub, Slack, Postgres"
Right: "The agent needs: ExportAsset, ReadFile, WriteFile, SendMessage, QueryRows"
```

Once you think in capabilities, the brand becomes irrelevant. Canva is just:
- `OpenUrl` + `Click` + `Type` + `ExportAsset`

Linux is just:
- `ReadFile` + `WriteFile` + `RunProcess` + `ListDir`

GitHub is just:
- `ReadFile` + `WriteFile` + `CallApi` + `ListDir`

Your system needs to be **below the use-case layer** — it only knows capabilities, not brands.

### What Real AIOS Needs

The AIOS paper (COLM 2025, agiresearch) correctly identifies that LLM agents need OS-level resource management: scheduling, context management, memory isolation. But it stops short of the crucial layer:

**Every action the agent takes in the real world must be:**
1. **Safe** — scoped by capability tokens, enforced by sandboxed runners
2. **Reproducible** — inputs content-addressed, outputs content-addressed
3. **Provable** — cryptographically signed receipt for every execution
4. **Contractual** — agent declares intent, kernel grants or denies, both parties sign

This document defines that layer.

---

## 2. Research Foundations

The architecture synthesizes 10 research sources:

### 2.1 AIOS: LLM Agent Operating System (COLM 2025)
- **Key insight**: Agents need OS-level kernel isolation — separate LLM resources from agent resources
- **What we take**: The kernel-as-scheduler metaphor, agent isolation model
- **What we add**: Capability-typed syscalls, execution contracts, cryptographic proofs

### 2.2 UCAN — User Controlled Authorization Networks
- **Key insight**: Capability tokens with delegation chains. Every delegation can only ATTENUATE (narrow), never AMPLIFY capabilities
- **What we take**: Token structure, delegation chain verification, attenuation rule
- **What we add**: Runtime execution receipts attached to tokens, SCITT integration

### 2.3 seL4 / Fuchsia Zircon — Capability-Based Microkernels
- **Key insight**: In seL4, processes only access resources they hold capability handles for. Zircon: all OS resources are capability objects
- **What we take**: Default-deny capability model; no ambient authority; every resource access requires explicit capability
- **What we add**: Agent-specific capability categories (Browser, API, Filesystem)

### 2.4 Nix Derivations — Reproducible, Content-Addressed Builds
- **Key insight**: `drv_hash = hash(inputs + build_script + env_vars)` → output path is deterministic. Given same inputs, output is always the same.
- **What we take**: Content-addressing of inputs; deterministic derivation IDs; hermetic sandbox
- **What we add**: Runtime execution (not just builds); LLM-aware "non-determinism tracking"

### 2.5 SCITT RFC 9334 — Supply Chain Integrity, Transparency, Trust
- **Key insight**: An append-only transparency log with signed statements and cryptographic receipts. IETF standard.
- **What we take**: Receipt structure; append-only log; Merkle inclusion proofs; external verifiability
- **What we add**: Runtime agent execution as "supply chain events"

### 2.6 Anthropic Computer Use / OpenAI CUA (2025-2026)
- **Key insight**: Agents can control OS + browser. Real use-case demand is massive.
- **What they lack**: No capability tokens, no sandbox contracts, no cryptographic proofs, no chain of custody
- **What we add**: Everything above, wrapped around the same execution surface

### 2.7 "Provably Honest Agents" (arXiv, 2025)
- **Key insight**: Agents can produce proof-of-compute receipts (R1CS/SNARK) that prove they executed the correct policy
- **What we take**: The concept of execution receipts as proofs; signed policy adherence
- **What we add**: Ed25519 signing (practical) as simpler alternative to ZK proofs; SCITT as the transparency layer

### 2.8 Autonomous Agents on Blockchains (arXiv 2601.04583)
- **Key insight**: Blockchain enables programmable self-executing agreements; verifiable policy enforcement; reproducible evaluation
- **What we take**: The execution contract metaphor; hash-chained receipts; interface layer between agent and world
- **What we add**: No distributed consensus needed — kernel is single source of truth, SCITT for external verification

### 2.9 Blockchain Chain-of-Custody (B-CoC, Tokenomics 2019)
- **Key insight**: SHA-256 hashed evidence, signed identities, append-only blockchain log for chain of custody
- **What we take**: Chain-of-custody as a first-class primitive; device-signed evidence capture
- **What we add**: Agent-specific chain (not just evidence but execution context, policy decisions, postcondition verification)

### 2.10 Deterministic AI Architecture (2025)
- **Key insight**: Run fingerprinting — hash all runtime dependencies (config, data, libraries, env) and pin to model artifact
- **What we take**: Inputs-hash + env-hash = execution fingerprint; pinning for reproducibility
- **What we add**: Output-hash; full contract sealing; chain linkage

---

## 3. The Capability Taxonomy

### 3.1 Design Principle

A **capability** is an atomic, typed, environment-agnostic operation that:
- Has a formal **schema** (typed input parameters)
- Has a formal **output schema** (typed result)
- Has a defined **risk level** (Low → Critical)
- Is either **reversible** or **irreversible**
- Requires a specific **runner category** to execute

The agent never calls "Canva" or "Linux". It requests capabilities. The kernel routes to the appropriate runner.

### 3.2 Six Capability Categories

```
CAP_CATEGORY
├── Filesystem      (fs.*)
├── Network         (net.*)
├── Process         (proc.*)
├── Browser         (browser.*)
├── Storage         (store.*)
└── Crypto          (crypto.*)
```

### 3.3 Complete Capability Table

#### Category: Filesystem (`fs.*`)

| Capability ID | Description | Params | Risk | Reversible |
|--------------|-------------|--------|------|------------|
| `fs.read` | Read file bytes | path: String | Low | Yes |
| `fs.write` | Write bytes to file | path: String, bytes: Bytes, mode: WriteMode | Medium | No |
| `fs.append` | Append bytes to file | path: String, bytes: Bytes | Low | No |
| `fs.delete` | Delete file or directory | path: String, recursive: bool | High | No |
| `fs.list` | List directory entries | path: String, pattern: Option<Glob> | Low | Yes |
| `fs.stat` | Get file metadata | path: String | Low | Yes |
| `fs.move` | Move/rename file | src: String, dst: String | Medium | Yes |
| `fs.copy` | Copy file | src: String, dst: String | Low | Yes |
| `fs.mkdir` | Create directory | path: String, recursive: bool | Low | Yes |
| `fs.watch` | Watch path for changes | path: String, events: Vec<FsEvent> | Low | Yes |

#### Category: Network (`net.*`)

| Capability ID | Description | Params | Risk | Reversible |
|--------------|-------------|--------|------|------------|
| `net.fetch` | HTTP GET request | url: Url, headers: Headers | Low | Yes |
| `net.post` | HTTP POST request | url: Url, body: Bytes, headers: Headers | Medium | No |
| `net.put` | HTTP PUT request | url: Url, body: Bytes, headers: Headers | Medium | No |
| `net.delete` | HTTP DELETE request | url: Url, headers: Headers | High | No |
| `net.stream` | Open streaming connection | url: Url, protocol: StreamProto | Medium | Yes |
| `net.dns` | DNS lookup | hostname: String | Low | Yes |
| `net.socket` | Raw TCP/UDP socket | host: String, port: u16, proto: Proto | High | Yes |

#### Category: Process (`proc.*`)

| Capability ID | Description | Params | Risk | Reversible |
|--------------|-------------|--------|------|------------|
| `proc.run` | Spawn subprocess | cmd: String, args: Vec<String>, env: Env | High | No |
| `proc.run_script` | Run script content | interpreter: String, script: String, env: Env | Critical | No |
| `proc.kill` | Kill process by PID | pid: u32, signal: Signal | High | No |
| `proc.signal` | Send signal to process | pid: u32, signal: Signal | Medium | No |
| `proc.list` | List running processes | filter: Option<String> | Low | Yes |
| `proc.pipe` | Pipe between processes | stages: Vec<ProcStage> | High | No |
| `proc.env_read` | Read environment variable | key: String | Low | Yes |
| `proc.env_write` | Set environment variable | key: String, value: String | Medium | No |

#### Category: Browser (`browser.*`)

| Capability ID | Description | Params | Risk | Reversible |
|--------------|-------------|--------|------|------------|
| `browser.open` | Open URL in browser | url: Url | Low | Yes |
| `browser.click` | Click DOM element | selector: Selector | Medium | No |
| `browser.type` | Type text into element | selector: Selector, text: String | Medium | No |
| `browser.screenshot` | Take screenshot | selector: Option<Selector> | Low | Yes |
| `browser.scroll` | Scroll page | direction: Direction, amount: f32 | Low | Yes |
| `browser.select` | Select dropdown option | selector: Selector, value: String | Medium | No |
| `browser.upload` | Upload file to form element | selector: Selector, path: String | High | No |
| `browser.download` | Download file from URL | url: Url, dest: String | Medium | No |
| `browser.eval` | Evaluate JavaScript | script: String | Critical | No |
| `browser.wait` | Wait for selector/condition | condition: WaitCondition, timeout_ms: u64 | Low | Yes |
| `browser.extract` | Extract DOM content | selector: Selector, format: ExtractFmt | Low | Yes |
| `browser.export_asset` | Export asset in format | format: AssetFormat, dest: String | Medium | No |
| `browser.close` | Close browser tab/window | target: BrowserTarget | Low | Yes |

#### Category: Storage (`store.*`)

| Capability ID | Description | Params | Risk | Reversible |
|--------------|-------------|--------|------|------------|
| `store.get` | Get value by key | namespace: String, key: String | Low | Yes |
| `store.put` | Put key-value pair | namespace: String, key: String, value: Bytes | Medium | No |
| `store.delete` | Delete key | namespace: String, key: String | High | No |
| `store.list` | List keys by prefix | namespace: String, prefix: String | Low | Yes |
| `store.query` | Query with filter | namespace: String, query: Query | Low | Yes |

#### Category: Crypto (`crypto.*`)

| Capability ID | Description | Params | Risk | Reversible |
|--------------|-------------|--------|------|------------|
| `crypto.sign` | Sign bytes with named key | key_ref: String, data: Bytes | Medium | Yes |
| `crypto.verify` | Verify signature | public_key: Bytes, data: Bytes, sig: Bytes | Low | Yes |
| `crypto.encrypt` | Encrypt bytes | key_ref: String, data: Bytes, algo: EncAlgo | Medium | Yes |
| `crypto.decrypt` | Decrypt bytes | key_ref: String, data: Bytes | High | Yes |
| `crypto.hash` | Hash bytes | algo: HashAlgo, data: Bytes | Low | Yes |
| `crypto.keygen` | Generate new keypair | algo: KeyAlgo, label: String | Medium | No |
| `crypto.seal` | Seal secret in vault | label: String, value: Bytes | Low | No |
| `crypto.unseal` | Unseal named secret | label: String | High | Yes |

### 3.4 Capability Risk Model

```
RiskLevel::Low      → no approval needed, rate-limit only
RiskLevel::Medium   → policy check, logged, may require scope token
RiskLevel::High     → explicit capability token required, always logged
RiskLevel::Critical → requires human-in-the-loop approval + SCITT receipt
```

---

## 4. The 5 Core Rust Traits

These 5 traits define the entire universe. Everything else is an implementation.

### Trait 1: `Capability`

```rust
/// An atomic, typed, environment-agnostic operation.
pub trait Capability: Send + Sync {
    /// Unique dotted-path ID: "fs.read", "browser.click", etc.
    fn id(&self) -> CapabilityId;

    /// Which category this belongs to.
    fn category(&self) -> CapCategory;

    /// JSON Schema for parameters (used for validation before execution).
    fn params_schema(&self) -> &serde_json::Value;

    /// JSON Schema for the output (used for postcondition checking).
    fn output_schema(&self) -> &serde_json::Value;

    /// Inherent risk of this capability.
    fn risk_level(&self) -> RiskLevel;

    /// Can the effect be rolled back?
    fn reversible(&self) -> bool;

    /// Which runner categories can execute this capability.
    fn supported_runners(&self) -> Vec<RunnerCategory>;

    /// Minimum sandbox requirements for safe execution.
    fn sandbox_requirements(&self) -> SandboxRequirements;
}
```

### Trait 2: `Runner`

```rust
/// A sandboxed execution environment.
/// Linux is a Runner. A container is a Runner. A browser is a Runner.
/// They all speak the same language.
#[async_trait]
pub trait Runner: Send + Sync {
    /// Unique runner identifier: "linux", "container", "wasm", "browser", "http", "remote"
    fn runner_id(&self) -> RunnerId;

    /// Which capability category this runner handles.
    fn category(&self) -> RunnerCategory;

    /// Which specific capabilities this runner can execute.
    fn supported_capabilities(&self) -> Vec<CapabilityId>;

    /// Execute a capability request inside the sandbox.
    /// Returns the raw output bytes + execution metadata.
    async fn execute(
        &self,
        request: ExecRequest,
        sandbox: &SandboxConfig,
    ) -> Result<ExecResult, RunnerError>;

    /// Verify the runner's integrity (e.g., container digest, WASM hash).
    fn runner_digest(&self) -> [u8; 32];

    /// Health check — is this runner available?
    async fn health_check(&self) -> RunnerHealth;
}

/// The full execution request passed to a runner.
pub struct ExecRequest {
    pub contract_id: ContractId,       // links back to the contract
    pub capability_id: CapabilityId,
    pub params: serde_json::Value,     // validated against capability.params_schema()
    pub params_hash: [u8; 32],         // sha256(canonical_json(params))
    pub agent_pid: String,
    pub sandbox: SandboxConfig,
    pub timeout_ms: u64,
    pub token: CapabilityToken,        // authorization proof
}

/// The full execution result from a runner.
pub struct ExecResult {
    pub output: Bytes,                 // raw output bytes
    pub output_hash: [u8; 32],         // sha256(output)
    pub output_cid: Cid,               // CID(output) — content-addressed
    pub exit_code: i32,
    pub duration_ms: u64,
    pub stderr: Option<Bytes>,         // for process runners
    pub side_effects: Vec<SideEffect>, // detected side effects (file writes, net calls)
    pub resource_usage: ResourceUsage, // actual CPU/mem/net used
}
```

### Trait 3: `Policy`

```rust
/// The authorization gate. Every capability request passes through here.
pub trait Policy: Send + Sync {
    /// Evaluate whether a capability request should be allowed.
    fn evaluate(&self, request: &CapRequest) -> PolicyDecision;

    /// Record a policy decision to the audit trail.
    fn record_decision(
        &self,
        request: &CapRequest,
        decision: &PolicyDecision,
    ) -> PolicyAuditEntry;
}

pub enum PolicyDecision {
    /// Allow execution. Optionally constrain further.
    Allow {
        constraints: ExecutionConstraints,
        token: CapabilityToken,
    },
    /// Deny execution with reason.
    Deny {
        reason: DenyReason,
        rule_id: String,
    },
    /// Execution requires explicit human approval before proceeding.
    RequireApproval {
        approver: String,
        context: ApprovalContext,
        deadline_ms: u64,
    },
    /// Defer until condition is true (rate limit recovery, etc.)
    Defer {
        condition: DeferCondition,
        retry_after_ms: u64,
    },
}
```

### Trait 4: `ExecutionContract` (struct, not trait)

```rust
/// The cryptographic execution contract — a three-phase, signed agreement
/// between the agent, the kernel, and reality.
///
/// PHASE 1: Offer  — agent declares what it wants (pre-execution)
/// PHASE 2: Grant  — kernel authorizes with token + constraints (pre-execution)
/// PHASE 3: Receipt — execution result + postcondition verification (post-execution)
///
/// This is NOT a smart contract (Solidity code).
/// This is a TYPED, SIGNED RECORD of what was agreed and what actually happened.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionContract {
    // ── IDENTITY ─────────────────────────────────────────────────────────────
    /// Content ID of this contract (computed from offer fields before execution).
    pub contract_id: Cid,

    /// CID of the previous contract in the execution journal (hash chain).
    pub prev_contract_id: Option<Cid>,

    // ── PHASE 1: OFFER ────────────────────────────────────────────────────────
    /// Which capability the agent is requesting.
    pub capability_id: CapabilityId,

    /// Which agent is making the request.
    pub agent_pid: String,

    /// Content-addressed parameters (CID of canonical CBOR of params).
    pub params_cid: Cid,

    /// SHA-256 of canonical JSON of params — for fast verification.
    pub params_hash: [u8; 32],

    /// Pre-conditions that MUST be true before execution starts.
    pub preconditions: Vec<Condition>,

    /// Constraints the agent accepts for this execution.
    pub constraints: ExecutionConstraints,

    /// Post-conditions that MUST be true after execution completes.
    pub postconditions: Vec<Postcondition>,

    /// What to do if postconditions fail.
    pub rollback: Option<RollbackStrategy>,

    /// Vakya ID — links this contract to the AAPI grammar record.
    pub vakya_id: Option<String>,

    // ── PHASE 2: GRANT ────────────────────────────────────────────────────────
    /// Policy decision that authorized this execution.
    pub policy_decision: PolicyDecision,

    /// The capability token issued for this execution.
    pub capability_token: CapabilityToken,

    /// Which runner was selected.
    pub runner_id: RunnerId,

    /// Digest of the runner binary/container at execution time.
    pub runner_digest: [u8; 32],

    /// Timestamp when the grant was issued (Unix ms).
    pub granted_at: u64,

    // ── PHASE 3: RECEIPT ─────────────────────────────────────────────────────
    /// SHA-256 of the actual inputs as received by the runner.
    pub inputs_hash: [u8; 32],

    /// SHA-256 of raw output bytes.
    pub outputs_hash: [u8; 32],

    /// CID of the output — allows content-addressed retrieval.
    pub output_cid: Option<Cid>,

    /// Exit code from the runner.
    pub exit_code: i32,

    /// Wall-clock duration of execution.
    pub duration_ms: u64,

    /// Detected side effects beyond the declared capability scope.
    pub undeclared_side_effects: Vec<SideEffect>,

    /// Were all postconditions satisfied?
    pub postconditions_verified: bool,

    /// Detail on any failed postconditions.
    pub postcondition_failures: Vec<PostconditionFailure>,

    /// Resource consumption during execution.
    pub resource_usage: ResourceUsage,

    // ── SEAL ─────────────────────────────────────────────────────────────────
    /// When execution completed and this contract was sealed (Unix ms).
    pub sealed_at: u64,

    /// Ed25519 signature over canonical CBOR of all above fields.
    /// Signed by the kernel's identity key.
    pub signature: [u8; 64],

    /// Public key that produced the signature.
    pub signer_key: [u8; 32],

    /// SCITT receipt CID if this contract was submitted to a transparency log.
    pub scitt_receipt_cid: Option<Cid>,
}
```

### Trait 5: `ExecutionStore`

```rust
/// Append-only, hash-chained journal of execution contracts.
/// Like a blockchain ledger, but for agent actions.
pub trait ExecutionStore: Send + Sync {
    /// Append a sealed contract. Returns its CID.
    /// Error if the prev_contract_id chain link is broken.
    fn append(&mut self, contract: ExecutionContract) -> Result<Cid, StoreError>;

    /// Retrieve a contract by CID.
    fn get(&self, cid: &Cid) -> Option<&ExecutionContract>;

    /// Walk the chain backwards from `tip` to `root` (or `from_cid`).
    fn chain_since(&self, from_cid: Option<&Cid>) -> Vec<&ExecutionContract>;

    /// Verify the entire hash chain is unbroken.
    fn verify_chain(&self) -> ChainVerificationResult;

    /// Current Merkle root over all contract CIDs.
    fn merkle_root(&self) -> [u8; 32];

    /// Total number of contracts in the journal.
    fn len(&self) -> usize;

    /// Latest contract CID (tip of the chain).
    fn tip(&self) -> Option<&Cid>;

    /// Query contracts by agent_pid.
    fn by_agent(&self, agent_pid: &str) -> Vec<&ExecutionContract>;

    /// Query contracts by capability_id.
    fn by_capability(&self, cap_id: &CapabilityId) -> Vec<&ExecutionContract>;
}
```

---

## 5. The Execution Contract — Three-Phase Cryptographic Agreement

### 5.1 Overview

The Execution Contract is NOT a smart contract in the Ethereum sense (executable code on a consensus network). It is a **typed, signed, three-phase agreement** between:

- **The Agent** — declares what it wants (capability + params + constraints it accepts)
- **The Kernel** — grants or denies, issues capability token, selects runner
- **Reality** — what actually happened (verified outputs, side effects, postconditions)

Each phase is cryptographically committed:

```
PHASE 1: OFFER
─────────────────────────────────────────────────────────────
  contract_id = CID( CBOR({
      capability_id,       // "fs.write"
      agent_pid,           // "agent:dr-smith:001"
      params_hash,         // sha256(canonical_json(params))
      preconditions,       // ["file /workspace/input.csv exists"]
      constraints,         // {allowed_paths: ["/workspace/**"], max_duration_ms: 5000}
      postconditions,      // ["file /workspace/output.csv exists", "no other files modified"]
      rollback,            // Some(RollbackStrategy::DeleteCreated)
      nonce,               // random u64 to prevent replay
      offered_at           // unix_ms
  }))

  ↓ contract_id is deterministic from the offer. Agent knows it before execution.

PHASE 2: GRANT
─────────────────────────────────────────────────────────────
  policy.evaluate(request) → PolicyDecision::Allow { constraints, token }

  token = CapabilityToken {
      issued_to: agent_pid,
      capabilities: ["fs.write"],
      constraints: { paths: ["/workspace/output.csv"], max_bytes: 10_000 },
      expires_at: now + 30_000,
      proof_chain: [kernel_delegation_cid],
      signature: kernel_ed25519_sign(token_cbor)
  }

  runner = select_runner(capability_id) → LinuxRunner

  ↓ runner_digest = sha256(runner_binary) — pins the exact runner at grant time

PHASE 3: RECEIPT (sealed after execution)
─────────────────────────────────────────────────────────────
  exec_result = runner.execute(request, sandbox)

  // Verify postconditions
  postconditions_verified = verify_all_postconditions(exec_result, postconditions)

  // Seal the contract
  contract.inputs_hash  = sha256(actual_params_cbor)
  contract.outputs_hash = sha256(exec_result.output)
  contract.output_cid   = CID(exec_result.output)
  contract.duration_ms  = exec_result.duration_ms
  contract.exit_code    = exec_result.exit_code
  contract.sealed_at    = now_unix_ms()

  // Hash chain link
  contract.prev_contract_id = journal.tip()

  // Sign everything
  contract.signature = kernel_key.sign( canonical_cbor(contract_without_signature) )

  // Append to journal
  journal.append(contract)
```

### 5.2 Contract ID Computation

The `contract_id` is computed from the OFFER phase only — before execution. This means:

1. **The agent can predict its own contract_id** before execution starts
2. **Two identical requests from the same agent at different times get different IDs** (nonce)
3. **The contract_id is a commitment** — changing any offer field changes the ID

```rust
fn compute_contract_id(offer: &ContractOffer) -> Cid {
    let cbor = to_canonical_cbor(offer);  // deterministic field ordering
    let hash = sha256(&cbor);
    Cid::new_v1(SHA2_256, hash)
}
```

### 5.3 Hash Chain Structure

```
contract_0 (genesis)
  prev_contract_id: None
  contract_id: CID_0
  signature: sig_0

contract_1
  prev_contract_id: Some(CID_0)   ← links to contract_0
  contract_id: CID_1
  signature: sig_1

contract_2
  prev_contract_id: Some(CID_1)   ← links to contract_1
  contract_id: CID_2
  signature: sig_2

...

journal.merkle_root = merkle_root([CID_0, CID_1, CID_2, ...])
```

**Verification**: To verify the chain is unbroken, walk backwards:
- `contract_n.prev_contract_id == contract_(n-1).contract_id` ✓
- `verify_signature(contract_n.signature, contract_n.signer_key)` ✓
- `contract_(n-1).contract_id == CID(canonical_cbor(contract_(n-1)))` ✓

If any link is broken (contract deleted, modified, inserted), the chain fails.

---

## 6. The Cryptographic Burn

### 6.1 What "Burn" Means

In blockchain terminology, "burning" = sending tokens to an address nobody controls. It's **permanently, cryptographically irreversible**.

We use this concept for **execution events**: once an agent executes a capability, that event is **burned into the execution journal**. It cannot be deleted, modified, or denied.

This is NOT simply logging. Logs can be deleted. The cryptographic burn cannot be undone because:

1. **Content-addressed**: `contract_id = CID(contract_data)` — changing data changes the CID
2. **Signed**: `signature = ed25519_sign(contract_cbor)` — signature is invalid if data changes
3. **Hash-chained**: `contract_n.prev_contract_id = CID_(n-1)` — deleting any contract breaks the chain
4. **Merkle-rooted**: `journal.merkle_root` is published externally (SCITT) — rolling back the journal changes the root

### 6.2 Comparison to Other Permanent Record Systems

| System | Immutability Mechanism | What's Recorded | Scope |
|--------|----------------------|----------------|-------|
| **Git** | SHA hash of tree+parent | Code changes | Software supply chain |
| **Ethereum** | Blockchain consensus | Token transfers, smart contract calls | Financial state |
| **Certificate Transparency** | Merkle tree + append-only log | TLS certificates | Web PKI |
| **SCITT RFC 9334** | Signed statements + receipts | Artifact provenance | Any supply chain |
| **Our Execution Journal** | CID + Ed25519 + hash chain | Agent capability executions | Agent actions in the world |

**What makes ours unique**: We record not just WHAT happened but:
- The **typed contract** the agent agreed to (capability + constraints + postconditions)
- The **cryptographic commitment** to inputs (params_hash, inputs_hash)
- The **cryptographic commitment** to outputs (outputs_hash, output_cid)
- The **policy decision** that authorized execution
- The **postcondition verification** result
- The **chain link** to every previous action by this agent

### 6.3 The Three Invariants

**Invariant 1 — Existence**:
> If an agent executed capability `C` with params `P`, there exists exactly one `ExecutionContract` with `capability_id = C` and `params_hash = sha256(P)`.

**Invariant 2 — Integrity**:
> For any `ExecutionContract` in the journal, `verify_signature(contract.signature, contract.signer_key, canonical_cbor(contract))` returns `true`.

**Invariant 3 — Continuity**:
> For any two consecutive contracts `c_n` and `c_(n+1)` in the journal, `c_(n+1).prev_contract_id == c_n.contract_id`.

### 6.4 External Verifiability via SCITT

For high-risk operations (RiskLevel::Critical), the contract is submitted to a SCITT transparency log:

```
kernel.journal.merkle_root
    → SCITT signed statement (COSE_Sign1)
    → SCITT transparency receipt
    → stored as contract.scitt_receipt_cid

Anyone can verify:
    scitt_receipt.verify_inclusion(contract_id, journal.merkle_root) → true
```

This means a regulator, an auditor, or an end-user can independently verify that a specific agent action happened, without trusting the system that ran the agent.

---

## 7. Runner Architecture

### 7.1 Design Principle

A `Runner` is a sandboxed execution environment. It:
- Speaks one language: `execute(ExecRequest) → ExecResult`
- Knows nothing about agents, contracts, or policies
- Enforces its own sandbox (filesystem scope, network rules, resource limits)
- Returns a deterministic result given the same inputs

Runners are **plugins**. Adding a new execution environment = implementing the `Runner` trait.

### 7.2 Seven Runner Implementations

#### `LinuxRunner`
Executes process-based capabilities inside a Linux sandbox:
- **Sandbox**: Linux namespaces (pid, net, mnt, user) + cgroups (CPU/memory limits) + seccomp (syscall allowlist)
- **Capabilities**: `proc.*`, `fs.*` (scoped to workspace)
- **FS scope**: Only the declared `allowed_paths` are bind-mounted
- **Network**: Blocked by default; `net.*` capabilities require explicit allowlist

```
Execution:
  1. Create new Linux namespace (unshare)
  2. Mount only /workspace (read/write) + /tmp (tmpfs)
  3. Apply seccomp filter (allowlist: read, write, open, stat, exit_group, ...)
  4. Apply cgroup limits (max_cpu_percent, max_memory_bytes)
  5. Exec subprocess
  6. Collect stdout/stderr
  7. Capture side effects (inotify watch on /workspace)
  8. Destroy namespace on exit
```

#### `ContainerRunner`
Executes inside an OCI container using youki (CNCF Sandbox Rust runtime):
- **Sandbox**: Full OCI container isolation
- **Capabilities**: All categories with explicit enable
- **Image verification**: Container image digest must match `runner_digest`
- **Use case**: Untrusted code execution, language runtimes

```
Execution:
  1. Verify container image digest
  2. Create container with seccomp profile
  3. Mount workspace volume (read/write scoped)
  4. Run command inside container
  5. Collect output, resource usage
  6. Destroy container on exit
```

#### `WasmRunner`
Executes WebAssembly modules via wasmtime with WASI:
- **Sandbox**: Memory-isolated WASM sandbox (no direct syscalls)
- **Capabilities**: `fs.*` (WASI filesystem), `net.*` (WASI sockets, if enabled)
- **Determinism**: Given same WASM binary + same inputs → same outputs (truly reproducible)
- **Use case**: Safe plugin execution, cross-platform code

```
Execution:
  1. Verify WASM module hash
  2. Create wasmtime Store with WASI context
  3. Configure WASI: preopened dirs, allowed env vars, net access
  4. Call WASM entry point with params
  5. Collect return value + stdout
```

#### `BrowserRunner`
Controls a headless browser (Chromium via CDP):
- **Capabilities**: `browser.*`
- **Network scope**: Only allowlisted domains
- **State isolation**: Fresh browser profile per execution session
- **Use case**: Web automation, "Computer Use" style operations

```
Execution:
  1. Launch headless Chromium with restricted profile
  2. Apply network domain allowlist (via CDP Network.setBlockedURLs)
  3. Execute browser capability (click, type, extract, etc.)
  4. Capture screenshot as evidence
  5. Hash screenshot bytes → evidence_cid
  6. Terminate browser session on completion
```

#### `HttpRunner`
Makes typed HTTP requests against allowlisted endpoints:
- **Capabilities**: `net.fetch`, `net.post`, `net.put`, `net.delete`
- **Network scope**: MUST be in `allowed_domains` allowlist
- **Auth**: Named secret references (never raw credentials in params)
- **Use case**: REST API calls, webhooks

```
Execution:
  1. Validate URL against allowed_domains allowlist
  2. Resolve named secrets (never expose raw values)
  3. Execute HTTP request with timeout
  4. Hash response body → output_hash
  5. Return response body + status code
```

#### `RemoteRunner`
Executes commands on a remote machine via SSH:
- **Capabilities**: `proc.*`, `fs.*` (on the remote machine)
- **Identity**: SSH key from named secret vault
- **Audit**: All remote commands logged locally AND remotely
- **Use case**: DevOps automation, remote server management

#### `MockRunner`
Testing-only runner:
- Returns deterministic mock outputs
- Verifies that sandbox config was properly constructed
- Used in unit tests to test the contract lifecycle without real execution

### 7.3 Runner Selection

```
capability_request.capability_id
    → capability.supported_runners()
    → policy.preferred_runner()
    → runner_registry.select(runner_category, context)

Example:
    "browser.click" → [BrowserRunner]     → BrowserRunner (only option)
    "fs.write"      → [LinuxRunner, ContainerRunner, WasmRunner]
                    → policy selects LinuxRunner (lowest overhead for trusted workloads)
                    → ContainerRunner (if untrusted source)
```

### 7.4 SandboxConfig

```rust
pub struct SandboxConfig {
    // Filesystem scope (applied to all runners with FS access)
    pub allowed_paths: Vec<GlobPattern>,    // e.g., ["/workspace/**", "/tmp/**"]
    pub readonly_paths: Vec<GlobPattern>,   // subset of allowed_paths that are read-only
    pub denied_paths: Vec<GlobPattern>,     // explicit denials (overrides allowed)

    // Network scope
    pub allowed_domains: Vec<String>,       // e.g., ["api.openai.com", "*.github.com"]
    pub allowed_ports: Vec<u16>,            // e.g., [443, 80]
    pub network_disabled: bool,             // kill switch

    // Resource limits
    pub max_duration_ms: u64,               // wall-clock timeout
    pub max_output_bytes: u64,              // truncate oversized outputs
    pub max_memory_bytes: u64,              // OOM kill threshold
    pub max_cpu_percent: f32,               // CPU throttle

    // Secrets (named references only — never raw values)
    pub allowed_secrets: Vec<String>,       // secret labels the runner can access

    // Environment
    pub env_vars: HashMap<String, String>,  // explicit env passthrough
    pub clear_env: bool,                    // start from empty env
}
```

---

## 8. Capability Token System

### 8.1 Design Principle

Every capability execution requires a **CapabilityToken**. A token is:
- **Issued by** the kernel (or a trusted delegator)
- **Bound to** a specific agent + specific capabilities + specific constraints
- **Time-limited** (expires_at)
- **Delegation-chain verified** (UCAN-style: each link can only narrow capabilities)
- **Signed** with Ed25519

### 8.2 Token Structure

```rust
pub struct CapabilityToken {
    /// Unique token identifier.
    pub token_id: Cid,

    /// Who this token is issued to.
    pub issued_to: String,   // agent_pid

    /// When this token expires (Unix ms).
    pub expires_at: u64,

    /// The specific capabilities granted (subset of what the issuer has).
    pub capabilities: Vec<CapabilityGrant>,

    /// The proof chain (delegation chain leading to kernel root).
    pub proof_chain: Vec<DelegationProof>,

    /// Ed25519 signature of canonical CBOR of above fields.
    pub signature: [u8; 64],

    /// Issuer's public key.
    pub issuer_key: [u8; 32],
}

pub struct CapabilityGrant {
    pub capability_id: CapabilityId,
    pub constraints: GrantConstraints,  // attenuated constraints
}

pub struct GrantConstraints {
    pub allowed_paths: Option<Vec<GlobPattern>>,
    pub allowed_domains: Option<Vec<String>>,
    pub max_calls_per_minute: Option<u32>,
    pub max_output_bytes: Option<u64>,
    pub allowed_args: Option<serde_json::Value>,  // JSON Schema subset
    pub not_before: Option<u64>,
    pub not_after: Option<u64>,
}
```

### 8.3 Delegation Chain and Attenuation

The fundamental rule (from UCAN):

> **A token can only be as powerful as the token it was derived from. Never more.**

```
Root Token (kernel)
├── capabilities: [fs.*, net.*, browser.*, proc.*]
├── constraints: {}  (no restrictions)
└── issued_to: "kernel-root"

    ↓ delegate to agent runtime

Agent Runtime Token
├── capabilities: [fs.read, fs.write, net.fetch, browser.*]
├── constraints: { allowed_paths: ["/workspace/**"], allowed_domains: ["api.openai.com"] }
└── issued_to: "agent-runtime:v1"

    ↓ delegate to specific agent for one task

Task Token (single execution)
├── capabilities: [fs.write]
├── constraints: { allowed_paths: ["/workspace/output.csv"], max_output_bytes: 100_000 }
└── issued_to: "agent:dr-smith:001"
└── expires_at: now + 30_000ms
```

**Key property**: The task token cannot read outside `/workspace/output.csv` even though the agent runtime token allows all of `/workspace/**`. Constraints can only narrow.

### 8.4 Token Verification

```rust
fn verify_token(token: &CapabilityToken, request: &CapRequest) -> Result<(), TokenError> {
    // 1. Check expiry
    if now_unix_ms() > token.expires_at {
        return Err(TokenError::Expired);
    }

    // 2. Verify signature
    let canonical = to_canonical_cbor_without_sig(token);
    if !ed25519_verify(&token.issuer_key, &canonical, &token.signature) {
        return Err(TokenError::InvalidSignature);
    }

    // 3. Verify the requested capability is in the token
    let grant = token.capabilities.iter()
        .find(|g| g.capability_id == request.capability_id)
        .ok_or(TokenError::CapabilityNotGranted)?;

    // 4. Verify request params satisfy constraints
    verify_constraints(&grant.constraints, &request.params)?;

    // 5. Walk delegation chain (each link must be valid + must attenuate)
    for proof in &token.proof_chain {
        verify_delegation_hop(proof)?;
    }

    Ok(())
}
```

---

## 9. Integration with Existing Architecture

### 9.1 How the Capability System Maps to Existing Primitives

The existing architecture already has primitives that map perfectly to the capability system. We are EXTENDING, not replacing.

| New Concept | Maps To (Existing) | Gap |
|-------------|-------------------|-----|
| `Capability` | `Action` in `connector-engine/action.rs` | Formal taxonomy + runner mapping |
| `ExecutionContract` (offer) | `Vakya` in `aapi-core/vakya.rs` | Karta/Karana/Karma = agent/cap/target |
| `ExecutionContract` (receipt) | `ActionRecord` in `aapi-core/types.rs` | inputs_hash, outputs_hash, chain link |
| `Policy` | `aapi-metarules` PolicyEngine | CapabilityToken issuance |
| `Runner` | `aapi-adapters` (file, http, remote) | Formal trait + sandbox config |
| `ExecutionStore` (journal) | `aapi-indexdb` + `KernelStore` | Hash-chain + merkle root |
| `CapabilityToken` | `DelegationChain` in `vac-core/types.rs` | Cap-specific attenuation |
| SCITT integration | `scitt_receipt_cid` on `KernelAuditEntry` | Contract-level SCITT |

### 9.2 Vakya as the Contract Offer

The existing Vakya 8-slot grammar already encodes the contract offer:

```
Vakya Slot → ExecutionContract Field
────────────────────────────────────
V1: Karta        → agent_pid (WHO is acting)
V2: Karma        → target (WHAT is being acted on — file path, URL, etc.)
V3: Karana       → capability_id (HOW — the tool/instrument)
V4: Sampradana   → (for delegation: WHO receives the output)
V5: Apadana      → preconditions (what must be true first)
V6: Adhikarana   → constraints (execution context, scope)
V7: Anuvada      → rollback/undo strategy
V8: Pratyaya     → postconditions (expected effects to verify)
```

This means: **building a Vakya IS building the contract offer**. The capability system is the runtime enforcement of what the Vakya declared.

### 9.3 DualDispatcher Integration

The `DualDispatcher` in `connector-engine/dispatcher.rs` currently routes to VAC kernel + AAPI. It will be extended to route through the capability microkernel:

```
Current flow:
  DualDispatcher.execute(request)
    → VAC kernel (memory write)
    → AAPI (action record)

New flow:
  DualDispatcher.execute(request)
    → CapabilityMicrokernel.request(cap_request)
        → Policy.evaluate()           [authorization]
        → Runner.execute()            [sandboxed execution]
        → ExecutionContract.seal()    [cryptographic burn]
        → ExecutionStore.append()     [journal]
    → VAC kernel (store output as MemPacket)
    → AAPI (record Vakya + ActionRecord with contract_id linkage)
```

### 9.4 Security Ring Integration

The capability system occupies a new sub-ring within Ring 2 (Action Kernel):

```
Ring 0: Cryptographic Foundation (SHA-256, Merkle, Ed25519, SCITT, CID)
Ring 1: Memory Kernel (MemPacket, syscalls, tiers, audit)
Ring 2: Action Kernel
  ├── 2a: AAPI Grammar (Vakya, RBAC, ActionRecord)           ← EXISTING
  └── 2b: Capability Microkernel (NEW)
       ├── Capability taxonomy (40 caps, 6 categories)
       ├── CapabilityToken (UCAN-style delegation)
       ├── ExecutionContract (3-phase agreement)
       ├── Runner abstraction (7 runners)
       └── ExecutionJournal (hash-chained, SCITT-linked)
Ring 3: Connector Engine (bridge, dispatch, trust, output)
Ring 4: Developer API (Connector, Agent, Pipeline)
```

---

## 10. New Crate: `connector-caps`

### 10.1 Crate Overview

```
connector/crates/connector-caps/
├── Cargo.toml
└── src/
    ├── lib.rs           — module declarations + re-exports
    ├── capability.rs    — Capability trait + 40 concrete types + CapabilityRegistry
    ├── token.rs         — CapabilityToken, CapabilityGrant, GrantConstraints, delegation
    ├── contract.rs      — ExecutionContract, ContractOffer, ContractReceipt, ContractId
    ├── runner.rs        — Runner trait, ExecRequest, ExecResult, 7 runner stubs
    ├── sandbox.rs       — SandboxConfig, ResourceLimits, NetworkScope, FilesystemScope
    ├── journal.rs       — ExecutionStore trait, InMemoryExecutionJournal, ChainVerification
    ├── policy.rs        — Policy trait, PolicyDecision, DenyReason, CapPolicyEngine
    ├── verify.rs        — verify_token(), verify_chain(), verify_contract(), replay_contract()
    └── error.rs         — CapError enum
```

### 10.2 `lib.rs`

```rust
//! connector-caps — Capability Microkernel
//!
//! The universal execution substrate for AI agents.
//! Turns the entire computer + internet into typed capabilities
//! the agent can request, use, and prove.
//!
//! ## Core Concepts
//!
//! - **Capability**: An atomic, typed, environment-agnostic operation
//! - **Runner**: A sandboxed execution environment (Linux, Container, Browser, HTTP, WASM)
//! - **Policy**: The authorization gate (UCAN-style capability tokens)
//! - **ExecutionContract**: Three-phase cryptographic agreement (Offer → Grant → Receipt)
//! - **ExecutionJournal**: Hash-chained, SCITT-linkable append-only record
//!
//! ## The One Syscall
//!
//! ```
//! CAP_CALL(capability, args, context) -> (result, proof: ExecutionContract)
//! ```
//!
//! That's the entire interface. Everything else is implementation.

pub mod capability;
pub mod token;
pub mod contract;
pub mod runner;
pub mod sandbox;
pub mod journal;
pub mod policy;
pub mod verify;
pub mod error;

pub use capability::*;
pub use token::*;
pub use contract::*;
pub use runner::*;
pub use sandbox::*;
pub use journal::*;
pub use policy::*;
pub use verify::*;
pub use error::CapError;
```

### 10.3 Module Responsibilities

#### `capability.rs` (~150 lines)
- `CapabilityId` newtype (e.g., `"fs.write"`)
- `CapCategory` enum (6 variants)
- `RiskLevel` enum (Low/Medium/High/Critical)
- `Capability` trait (7 methods)
- `BuiltinCapability` enum — 40 variants (one per row in §3.3)
- `CapabilityRegistry` — maps CapabilityId → Arc<dyn Capability>

#### `token.rs` (~120 lines)
- `CapabilityToken` struct
- `CapabilityGrant` + `GrantConstraints`
- `DelegationProof` struct
- `issue_token(agent, capabilities, constraints) → CapabilityToken`
- `attenuate(parent: &CapabilityToken, sub_capabilities, sub_constraints) → CapabilityToken`
- `verify_token(token, request) → Result<(), TokenError>`

#### `contract.rs` (~200 lines)
- `ContractOffer` struct (Phase 1 fields)
- `ContractGrant` struct (Phase 2 fields)
- `ContractReceipt` struct (Phase 3 fields)
- `ExecutionContract` struct (all 3 phases + seal)
- `compute_contract_id(offer: &ContractOffer) → Cid`
- `seal_contract(offer, grant, result, prev_cid, signer_key) → ExecutionContract`
- `ContractBuilder` — builder pattern for constructing contracts

#### `runner.rs` (~180 lines)
- `Runner` trait (6 methods)
- `RunnerCategory` enum (7 variants)
- `RunnerRegistry` — maps RunnerCategory → Arc<dyn Runner>
- `ExecRequest` + `ExecResult` structs
- `SideEffect` enum
- `ResourceUsage` struct
- `MockRunner` (always included, for tests)
- Stub impls: `LinuxRunnerStub`, `ContainerRunnerStub`, `BrowserRunnerStub`, `HttpRunnerStub`

#### `sandbox.rs` (~80 lines)
- `SandboxConfig` struct (with builder)
- `NetworkScope` struct
- `FilesystemScope` struct
- `ResourceLimits` struct
- Default sandboxes: `SandboxConfig::strict()`, `SandboxConfig::permissive()`, `SandboxConfig::readonly()`

#### `journal.rs` (~120 lines)
- `ExecutionStore` trait (9 methods)
- `InMemoryExecutionJournal` — Vec + HashMap, for testing
- `ChainVerificationResult` enum (Valid / BrokenAt(index) / InvalidSignature(cid))
- `compute_merkle_root(contract_cids: &[Cid]) → [u8; 32]`

#### `policy.rs` (~100 lines)
- `Policy` trait (2 methods)
- `PolicyDecision` enum (Allow/Deny/RequireApproval/Defer)
- `DenyReason` enum
- `CapPolicyEngine` — default policy implementation
  - Checks RiskLevel → token requirement
  - Checks token validity (delegates to `verify_token`)
  - Checks rate limits
  - Checks agent phase (existing ELS from Phase 8)

#### `verify.rs` (~80 lines)
- `verify_contract(contract: &ExecutionContract) → bool` — signature check
- `verify_chain(journal: &dyn ExecutionStore) → ChainVerificationResult`
- `verify_token(token, request) → Result<(), TokenError>`
- `replay_contract(contract_id: &Cid, journal: &dyn ExecutionStore) → ReplayResult`

### 10.4 Cargo.toml Dependencies

```toml
[dependencies]
vac-core = { path = "../../vac/crates/vac-core" }
aapi-core = { path = "../../aapi/crates/aapi-core" }

serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
ciborium = "0.2"
cid = { version = "0.11", features = ["serde"] }
multihash = "0.19"
sha2 = "0.10"
ed25519-dalek = { version = "2.1", features = ["rand_core"] }
uuid = { version = "1.6", features = ["v4", "serde"] }
chrono = { version = "0.4", features = ["serde"] }
thiserror = "1.0"
async-trait = "0.1"
tokio = { version = "1.35", features = ["full"] }
bytes = "1.5"

[dev-dependencies]
tempfile = "3.14"
```

### 10.5 Test Plan (25 tests)

```
capability_tests:
  test_builtin_capability_ids_are_unique
  test_capability_risk_levels
  test_capability_registry_lookup
  test_capability_supported_runners_nonempty

token_tests:
  test_issue_token
  test_token_expiry_check
  test_token_signature_verify
  test_token_attenuation_narrows_only
  test_token_attenuation_cannot_amplify
  test_delegation_chain_verify

contract_tests:
  test_compute_contract_id_deterministic
  test_compute_contract_id_changes_on_param_change
  test_seal_contract_all_fields_populated
  test_contract_signature_verify
  test_contract_chain_link

journal_tests:
  test_journal_append_and_retrieve
  test_journal_chain_verify_valid
  test_journal_chain_verify_detects_deletion
  test_journal_chain_verify_detects_modification
  test_journal_merkle_root_changes_on_append
  test_journal_query_by_agent
  test_journal_query_by_capability

policy_tests:
  test_policy_allows_low_risk_without_token
  test_policy_denies_high_risk_without_token
  test_policy_deny_reason_in_decision
```

---

## 11. End-to-End Example — Canva Workflow as Capability Chain

An agent creates a product poster on Canva. Every action is a capability call with a signed contract.

### Agent Code (Developer View)

```rust
let agent = Connector::new()
    .llm("anthropic", "claude-3-5-sonnet", api_key)
    .build()
    .agent("designer")
    .capabilities(vec![
        "browser.open", "browser.click",
        "browser.type", "browser.export_asset"
    ])
    .sandbox(SandboxConfig::builder()
        .allowed_domains(vec!["canva.com", "*.canva.com"])
        .allowed_paths(vec!["/workspace/assets/**"])
        .max_duration_ms(120_000)
        .build())
    .run("Create a product poster for ConnectorOS", "user:alice");
```

### What Happens Internally

**Step 1**: Agent requests `browser.open`

```
ContractOffer {
    capability_id: "browser.open",
    agent_pid: "designer:alice:001",
    params_hash: sha256({"url": "https://canva.com"}),
    constraints: { allowed_domains: ["canva.com", "*.canva.com"] },
    postconditions: [{ condition: "page_loaded", check: "url_contains('canva.com')" }],
    nonce: 0x1a2b3c4d,
    offered_at: 1740527400000
}
→ contract_id_0 = CID(cbor(offer_0))

Policy: Allow { token: TOKEN_0 }
Runner: BrowserRunner

ExecResult: { output_cid: CID(screenshot_bytes), exit_code: 0, duration_ms: 1240 }

ExecutionContract_0 sealed:
  prev_contract_id: None          ← genesis
  inputs_hash: sha256(params)
  outputs_hash: sha256(screenshot)
  postconditions_verified: true
  signature: sig_0
```

**Step 2**: Agent requests `browser.click` (chains to contract_0)

```
ContractOffer {
    capability_id: "browser.click",
    params_hash: sha256({"selector": "#create-new-design"}),
    ...
    nonce: 0x2b3c4d5e
}
→ contract_id_1 = CID(cbor(offer_1))

ExecutionContract_1:
  prev_contract_id: Some(contract_id_0)  ← chains to step 1
  ...
  signature: sig_1
```

**Step 3**: `browser.type` → contract_2 (prev: contract_id_1)

**Step 4**: `browser.export_asset` → contract_3 (prev: contract_id_2)

```
ExecResult: {
    output_cid: CID(poster_png_bytes),  ← content-addressed PNG
    outputs_hash: sha256(poster.png),
    exit_code: 0,
    duration_ms: 3400
}
```

### Final Execution Journal

```
journal.contracts = [contract_0, contract_1, contract_2, contract_3]
journal.tip = contract_id_3
journal.merkle_root = merkle_root([cid_0, cid_1, cid_2, cid_3])
```

### Auditing the Workflow

```rust
// "Prove what the agent did to create this poster"
let chain = journal.chain_since(None);
for contract in &chain {
    println!("[{}] {} → output: {}",
        contract.capability_id,
        if contract.postconditions_verified { "✓" } else { "✗" },
        contract.output_cid.as_ref().map(|c| c.to_string()).unwrap_or("none".into())
    );
}

// Output:
// [browser.open]         ✓  → output: bafyreib...1
// [browser.click]        ✓  → output: bafyreib...2
// [browser.type]         ✓  → output: bafyreib...3
// [browser.export_asset] ✓  → output: bafyreib...4  ← this is the PNG

// Verify the chain is unbroken
assert_eq!(journal.verify_chain(), ChainVerificationResult::Valid);
```

---

## 12. End-to-End Example — Hospital Agent Prescribing Medication

This example shows the `RequireApproval` policy decision and `RiskLevel::Critical`.

```rust
let pharmacy_agent = Connector::new()
    .build()
    .agent("pharmacy-ai")
    .capabilities(vec!["store.put", "net.post"])  // write to prescription DB + notify pharmacy
    .hipaa("US")
    .build();

pharmacy_agent.run(
    "Prescribe amoxicillin 500mg 3x daily for patient P-847",
    "doctor:dr-chen:session-447"
);
```

**Internally**, when the agent tries to `store.put` (write prescription record):

```
CapabilityId: "store.put"
RiskLevel: Critical  (patient data write + HIGH data_classification)

Policy evaluates:
→ PolicyDecision::RequireApproval {
    approver: "doctor:dr-chen",
    context: ApprovalContext {
        description: "Agent requests: store.put on patients/P-847/prescriptions",
        evidence_cid: CID(proposed_prescription_json),
        risk_reason: "Critical: patient medical record mutation",
        requires_hitl: true,
    },
    deadline_ms: 300_000  // 5 minutes
  }

→ Execution PAUSED. Agent cannot proceed without human approval.

Doctor reviews:
    approve(approval_token: ApprovalToken)
    → ApprovalToken { approver: "doctor:dr-chen", signature: sig, timestamp: ... }

ExecutionContract sealed with approval_token in proof_chain:
    policy_decision.RequireApproval.approval_token = ApprovalToken { ... }
    ← cryptographic proof that a human approved this specific prescription
```

**Result**: The prescription is **provably human-approved**. The execution contract contains:
- The exact prescription params (content-addressed)
- The doctor's digital signature approving those exact params
- The timestamp of approval
- The output (prescription record CID after write)
- The SCITT receipt (published to external transparency log)

This is a **legal-grade audit trail** for every medication prescribed by any AI agent. It satisfies FDA 21 CFR Part 11, HIPAA, and EU AI Act Article 14 (human oversight).

---

## 13. Implementation Plan

### Phase C1: Core Types and Traits (~300 lines, 10 tests)
**New crate**: `connector-caps`

Files: `capability.rs`, `token.rs`, `sandbox.rs`, `error.rs`

- Define all 5 core traits
- Implement `BuiltinCapability` for all 40 capabilities
- Implement `CapabilityRegistry`
- Implement `CapabilityToken` + `issue_token()` + `verify_token()`
- Implement `SandboxConfig` builder
- Tests: capability registry, token issuance, token verification, token attenuation

### Phase C2: Execution Contract (~200 lines, 8 tests)
Files: `contract.rs`, `verify.rs`

- Implement `ExecutionContract` struct
- Implement `compute_contract_id()` (deterministic CID from offer)
- Implement `seal_contract()` (Ed25519 signing over canonical CBOR)
- Implement `verify_contract()`
- Tests: contract ID determinism, seal/verify roundtrip, chain link, signature tamper detection

### Phase C3: Execution Journal (~120 lines, 7 tests)
Files: `journal.rs`

- Implement `ExecutionStore` trait
- Implement `InMemoryExecutionJournal`
- Implement `verify_chain()` (walk backwards, check each link)
- Implement `compute_merkle_root()`
- Tests: append/retrieve, chain verify valid, chain verify broken, merkle root changes

### Phase C4: Policy Engine (~100 lines, 5 tests) 
Files: `policy.rs`

- Implement `Policy` trait
- Implement `CapPolicyEngine` (risk-level → token requirement)
- Implement `RequireApproval` path
- Tests: allow low-risk, deny high-risk no-token, require approval critical, rate limit defer

### Phase C5: Runner Stubs (~180 lines)
Files: `runner.rs`

- Implement `Runner` trait
- Implement `MockRunner` (fully functional for tests)
- Implement stubs: `LinuxRunnerStub`, `BrowserRunnerStub`, `HttpRunnerStub`
- `RunnerRegistry` with selection logic

### Phase C6: Integration with connector-engine
Files: `connector-engine/src/cap_dispatcher.rs` (~150 lines)

- `CapabilityMicrokernel` struct wrapping: policy + runner_registry + journal
- Wire into `DualDispatcher`: `execute_capability()` method
- Link `ExecutionContract.vakya_id` to AAPI ActionRecord
- Link `ExecutionContract.output_cid` to VAC MemPacket write

### Summary

| Phase | Lines | Tests | Files |
|-------|-------|-------|-------|
| C1: Core types + traits | ~300 | 10 | capability.rs, token.rs, sandbox.rs, error.rs |
| C2: Execution contract | ~200 | 8 | contract.rs, verify.rs |
| C3: Execution journal | ~120 | 7 | journal.rs |
| C4: Policy engine | ~100 | 5 | policy.rs |
| C5: Runner stubs | ~180 | 5 | runner.rs |
| C6: Engine integration | ~150 | — | cap_dispatcher.rs |
| **Total** | **~1,050** | **35** | **7 new files** |

---

## 14. Industry Comparison — What Nobody Else Has

| Capability | Connector | Anthropic Computer Use | OpenAI CUA | LangChain Tools | MCP |
|------------|-----------|----------------------|------------|-----------------|-----|
| **Capability taxonomy** (typed, atomic, formal) | ✅ 40 caps, 6 categories | ❌ implicit | ❌ implicit | ❌ function schemas | ❌ tool schemas |
| **Capability tokens** (UCAN-style delegation) | ✅ attenuation chain | ❌ | ❌ | ❌ | ❌ |
| **Execution contract** (3-phase: offer/grant/receipt) | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Cryptographic burn** (Ed25519 + hash chain) | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Sandbox enforcement** (filesystem scope, net allowlist, cgroups) | ✅ (per runner) | ⚠️ BIC only | ⚠️ partial | ❌ | ❌ |
| **Reproducible execution** (content-addressed inputs + outputs) | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Postcondition verification** (post-execution checks) | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Chain of custody** (hash-chained, auditable) | ✅ | ❌ | ❌ | ❌ | ❌ |
| **SCITT integration** (external transparency log) | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Human-in-the-loop approval** (cryptographically signed) | ✅ | ⚠️ pause only | ⚠️ pause only | ❌ | ❌ |
| **Runner abstraction** (swap Linux/Container/Browser/WASM) | ✅ 7 runners | ❌ | ❌ | ❌ | ❌ |
| **Compliance-ready** (HIPAA/SOC2/EU AI Act evidence) | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Integration with memory kernel** (action + memory unified) | ✅ | ❌ | ❌ | ❌ | ❌ |

### What This Unlocks

This architecture enables use-cases impossible with any other framework:

1. **Legal-grade AI audit**: Regulators can independently verify what an AI agent did to a patient's record, what inputs it had, and who approved it — without trusting the hospital's IT system.

2. **Reproducible AI debugging**: "The agent failed on Tuesday" → replay contract_id_47 with the same inputs_hash → get identical output → confirm the bug.

3. **Agent insurance/liability**: "Did the AI cause this financial loss?" → walk the execution journal → find the capability call that caused the trade → verify the params_hash matches the order → prove causation.

4. **Cross-org agent trust**: Hospital A's agent delegates to Hospital B's agent. Hospital B's CapabilityToken is derived from Hospital A's (UCAN delegation). The action is provably authorized by Hospital A.

5. **Capability marketplace**: Runners are plugins. Someone builds `QuantumComputingRunner`. It implements the `Runner` trait. Agents gain quantum capabilities without knowing anything about quantum hardware. The contract system provides the same trust guarantees.

---

## Appendix A: The One Syscall

The entire capability system reduces to one syscall:

```
CAP_CALL(capability_id, params, context) → (output, proof)
```

Where:
- `capability_id` = a string like `"fs.read"` or `"browser.click"`
- `params` = JSON matching the capability's param schema
- `context` = agent identity + session + token chain
- `output` = the result bytes (content-addressed by output_cid)
- `proof` = an `ExecutionContract` — the cryptographic burn

**Everything else in this document is the implementation of that one syscall.**

---

## Appendix B: Glossary

| Term | Definition |
|------|-----------|
| **Capability** | An atomic, typed, environment-agnostic operation an agent can request |
| **CapabilityToken** | UCAN-style signed authorization to use specific capabilities with constraints |
| **ContractId** | CID of the canonical CBOR of the contract offer (computed before execution) |
| **Cryptographic Burn** | An irreversible, signed, hash-chained record of an execution event |
| **ExecutionContract** | Three-phase cryptographic agreement: Offer + Grant + Receipt |
| **ExecutionJournal** | Hash-chained, append-only store of all ExecutionContracts |
| **Runner** | A sandboxed execution environment (Linux, Container, Browser, HTTP, WASM) |
| **Attenuation** | Narrowing a CapabilityToken's scope during delegation (never widening) |
| **Postcondition** | A verifiable claim about the world state after execution completes |
| **SCITT** | IETF RFC 9334 — Supply Chain Integrity, Transparency and Trust (external audit log) |
| **Offer** | Phase 1 of ExecutionContract — what the agent declares it wants |
| **Grant** | Phase 2 of ExecutionContract — what the kernel authorizes |
| **Receipt** | Phase 3 of ExecutionContract — what actually happened, cryptographically sealed |
| **params_hash** | SHA-256 of the canonical JSON of execution parameters |
| **output_cid** | CID of the raw output bytes — content-addresses the execution result |
| **chain_root** | Merkle root over all contract CIDs in the journal |

---

*Research sources: AIOS (COLM 2025), UCAN spec (ucan-wg/spec), seL4 whitepaper, Fuchsia Zircon docs, Nix CA derivations, SCITT RFC 9334, Anthropic Computer Use, OpenAI CUA, "Provably Honest Agents" (arXiv 2025), "Autonomous Agents on Blockchains" (arXiv 2601.04583), Blockchain CoC (Tokenomics 2019 DAGSTUHL), Deterministic AI Architecture (kubiya.ai 2025)*

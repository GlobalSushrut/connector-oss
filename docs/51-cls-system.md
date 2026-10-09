# 51 — CLS: The Connector Contract Language System

> **Status: Built and operational. Not required today.**  
> CLS ships in `connector-engine/src/cls/`. The compiler, registry, executor, and template system are implemented and tested. You do not need CLS to run Connector today. You will need it when you have more than one agent, more than one contract version, or more than one node.

---

## What CLS Is

CCL (Connector Contract Language) is the syntax for writing a single governance contract. CLS (Connector Language System) is the runtime environment that makes contracts into infrastructure.

The distinction matters:

| Layer | What it is | Analogy |
|-------|-----------|---------|
| CCL | The language you write contracts in | JavaScript source code |
| CLS | The system that compiles, addresses, versions, links, and executes contracts | V8 engine + npm registry + module system |

A CCL file describes one agent's governance rules. CLS is the system that turns thousands of CCL files into a coherent, versionable, auditable governance network.

---

## The 7-Module Compiler Pipeline

Every CCL contract passes through the full CLS compiler before it can be deployed. The pipeline is implemented in `connector-engine/src/cls/`:

```
Source Text
    │
    ▼
[ccl_lexer.rs]      Tokenization
    │                66 reserved keywords, 6 token categories
    │                Error recovery, Span tracking
    ▼
[ccl_parser.rs]     Recursive descent parsing → AST
    │                ContractNode, 7 block types, 14 step operations
    │                Predicate precedence climbing
    ▼
[ccl_sema.rs]       Semantic analysis — 11 validation passes
    │                name, tool, memory, state, event, branch,
    │                type, exhaustiveness, reachability,
    │                termination, budget
    ▼
[ccl_lower.rs]      AST → ContractIR (DAG)
    │                Predicate, budget, governance,
    │                state machine lowering
    ▼
[ccl_opt.rs]        6 optimization passes
    │                dead step elimination, constant folding,
    │                branch simplification, step fusion,
    │                predicate normalization
    ▼
[ccl_verify.rs]     Final verification
    │                state machine, IR structure, budget,
    │                governance, interface, node consistency
    ▼
[ccl_emit.rs]       Code emission
                     SolutionContract with CID (cls1-sha256-*)
                     Ed25519 signature
                     Full pipeline: compile_ccl()
```

The output of the compiler is a `SolutionContract`:
- A canonical JSON representation of the compiled contract
- A `cls1-sha256-*` CID computed from that canonical form
- An Ed25519 signature from the node's keypair
- The optimization-applied IR ready for the executor

### Using the Compiler

```rust
use connector_engine::cls::{compile_ccl_default, compile_ccl};

// Simplest path
let contract = compile_ccl_default(source_code)?;
println!("Contract CID: {}", contract.cid);  // cls1-sha256-a3f7b2...

// With config
let config = CompileConfig {
    optimize: true,
    strict_termination: true,
    allowed_tools: vec!["search", "write_memory"],
};
let contract = compile_ccl(source_code, config)?;
```

---

## The Contract Registry

`registry.rs` implements a content-addressed registry for compiled contracts.

**Key property:** A contract stored in the CLS registry cannot be silently modified. The `cls1-sha256-*` CID is computed from the contract's canonical content. Any change to the contract — even a single character — produces a different CID, which is a different contract.

```
Deploy contract → Registry assigns CID → Node stores by CID
Retrieve contract → Fetch by CID → Verify CID matches content
Execute contract → Executor loads by CID → Audit logs CID, not name
```

This means:
- `version 1.0` of a contract is not a string. It is `cls1-sha256-a3f7b2c8d9`.
- If you change the contract, the CID changes. The old contract still exists unchanged in the registry.
- Every agent's audit trail references a contract CID. You can reconstruct exactly what rules governed any decision at any point in time.

### Registry Operations

```rust
// Register a compiled contract
let cid = registry.register(compiled_contract)?;

// Retrieve by CID
let contract = registry.get(&cid)?;

// List all versions of a named contract
let versions = registry.list_versions("medical-summarizer")?;
// Returns: [(name, cid, deployed_at, active), ...]

// Check what CID is currently active for an agent
let active_cid = registry.active_for_agent(&agent_pid)?;
```

---

## Contract Templates

`templates.rs` provides reusable contract blueprints for common governance patterns. Templates are parameterized CCL fragments that compile to full contracts.

Built-in templates:
- `HipaaMinimumNecessary` — PHI namespace restriction + audit
- `Soc2AuditTrail` — Decision recording + receipt generation
- `BudgetConstrained` — Hard token and cost limits
- `HitlEscalation` — Human review gate at configurable confidence threshold
- `NamespaceIsolated` — Single-tenant namespace fencing
- `MultiAgentDelegate` — Coordinator → specialist delegation chain

```rust
use connector_engine::cls::templates::HipaaMinimumNecessary;

let contract_source = HipaaMinimumNecessary {
    agent_name: "patient-qa-agent",
    phi_namespace: "/p/hospital-a/",
    allowed_tools: vec!["search", "summarize"],
    hitl_confidence_threshold: 0.70,
    audit_regulation_tags: vec!["hipaa", "minimum_necessary"],
}.render();

let contract = compile_ccl_default(&contract_source)?;
```

---

## The CLS Executor

`executor.rs` runs compiled contracts at agent runtime. The executor:

1. Loads the contract by CID from the registry
2. Initializes the state machine to the entry state
3. For each incoming request, evaluates predicates and advances the state machine
4. Dispatches step operations (`call`, `write`, `read`, `emit`, `branch`, `require`, `check_budget`, `await_hitl`)
5. Journals every state transition with the contract CID
6. Halts on budget exhaustion, policy violation, or terminal state

The executor is deterministic. Given the same contract CID and the same input, it always produces the same execution path. This is verifiable by a third party without running Connector.

---

## Why This Matters at Scale

Today, with one agent and one contract, you barely notice CLS exists. As you scale:

| Scale | What breaks without CLS |
|-------|------------------------|
| 10 agents | You lose track of which agent is running which contract version |
| 100 agents | Contract deployments become coordination nightmares |
| 1,000 agents | A bug in one contract version affects hundreds of agents — you cannot identify which ones |
| 10,000 agents | You cannot audit a historical decision without knowing what contract version governed it |

CLS solves all of these with one mechanism: content addressing. Every contract is its CID. Every agent's audit trail references CIDs. Every decision is traceable to an immutable contract version.

---

## The Future: CLS as Governance Bytecode

The long-term vision for CLS is as the universal governance bytecode for AI systems — the equivalent of WebAssembly for governed agent behavior. Any system that wants to deploy a governed AI agent would:

1. Write a CCL contract describing the rules
2. Compile it with the CLS compiler → get a `cls1-sha256-*` CID
3. Publish the CID to a public registry
4. Any Connector node anywhere can verify the CID, fetch the contract, and run the agent with identical governance guarantees

A compliance officer at a hospital could say: *"We run agents governed by contract `cls1-sha256-a3f7b2c8d9`. Here is the compiled IR. Here are 10,000 audit entries all referencing that CID."* No ambiguity. No trust required. The math speaks.

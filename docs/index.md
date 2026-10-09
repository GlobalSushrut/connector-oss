# Connector Documentation Library

> **One constitution. A growing technical library. One sovereign operating substrate for distributed intelligence.**  
> From first boot to production-grade governed agents — this is the complete technical library for operators, developers, and system builders.

---

## How to Read This Library

Begin with the constitutional preamble. It defines why Connector exists, which mechanisms belong in the substrate, which behavior belongs in workflows, and which principles implementation and product claims may not silently violate.

The numbered technical library then moves from first use through architecture, theory, APIs, workflows, first-party systems, and operations. Read linearly if you are new. Jump to a specialized section if you already understand the constitutional model.

```
Section 0 — Constitution              Chapter 00       Origin, purpose, primitives, design laws
Section 1 — Getting Started          Chapters 01–05    Product, YAML, Python, CCL
Section 2 — Workflow Library         Chapters 06–10    100 workflow patterns across 5 domains
Section 3 — Architecture             Chapters 11–19    9-ring system model, diagrams, data flow
Section 4 — Theory & Mathematics     Chapters 20–23    Cryptography, cognitive theory, formal methods
Section 5 — Infrastructure Design    Chapters 24–25    Internal topology and external deployment
Section 6 — API, Routes & CLI        Chapters 26–32    Every endpoint and connectorctl verb
Section 7 — Tutorials                Chapters 33–40    End-to-end worked examples
Section 8 — Builder's Guide          Chapters 41–50    Extend, embed, and build on top of Connector
```

---

## Section 0 — Constitution

### [00 — Constitutional Preamble](00-constitutional-preamble.md)
Why the maker is building Connector, why mature distributed intelligence requires an operating substrate, and why local sovereignty, developer access, adversarial honesty, and cryptographic custody are constitutional requirements. Defines the ten substrate primitives, the kernel/workflow boundary, the role of TraceTramp, WitnessCtl, DevGuard and the other planned institutions, the universality test, and the permanent architecture laws every roadmap and implementation must follow.

### [Connector truth story (0 → today → future)](CONNECTOR_TRUTH_STORY.md)
Honest product narrative: what Connector is made of, what you can market today, how agents change when they run on it, what is still left (L4 Final GO / L5 mesh), and copy blocks that must not overclaim.

### [Substrate map](architecture/substrate-map.md)
Maps the ten constitutional primitives to existing crates/modules and the shared `connector-trust` v2 contracts.

### [Route security inventory](architecture/route-security-inventory.json)
### [Admission matrix](architecture/admission-matrix.md)
Machine-readable route/security inventory and known hardening gaps.

### [AI-world readiness](architecture/ai-world-readiness.md)
Recovery, HA honesty, modest-hardware, federation, and adversarial CI properties.

### [HA and federation](architecture/ha-federation.md)
Active/passive and federation operator env — no automatic multi-master claims. Includes **cell mesh** honesty for L5.

### [Mesh membership](architecture/mesh-membership.md)
Product membership = vac-cluster CRDT; local heartbeat wired; SWIM library-only (P8.4).

### [Cell SPIFFE-ish identity](architecture/cell-spiffe-identity.md)
URI `spiffe://{trust_domain}/cell/{cell_id}` + `GET /runtime/mesh` `spiffe_id` (P8.3).

### [Plugin verify 2A.9](PLUGIN_VERIFY_2A9.md)
Hub certification checklist mapped to `connectorctl plugin verify` section headers.

### [Soak evidence](SOAK_EVIDENCE.md)
CI/lab make targets + adversarial scripts as P6.11 evidence pointers.

### [Secondary plugins (deferred)](architecture/secondary-plugins-deferred.md)
Why Conductor/AgentLoop and peers are next-phase, not current gaps.

### [Cage URI stability](architecture/cage-uri-stability.md)
Stable `/plugin/<slug>` and `<slug>.cnktros` across isolation backend swap.

### [Hub workflow `.cpkg` publish](HUB_WORKFLOW_PUBLISH.md)
Workflow package publish contract + honesty stub API (`implemented: false`).

### [Brand and assets](BRAND_AND_ASSETS.md)
Knot + cnktros lockup, diagram map, concept-UI honesty. OSS purple shield is crate-only. Do not claim Firecracker-by-default from mock dashboards.

### [World cage, vendor cut, and native browser](WORLD_CAGE_AND_BROWSER.md)
Operator and architecture source for world isolation on this node: Landlock child pores (default DROP), LLM vendor HTTPS cut once a session is connected, and the Connector-native **browser** world (document GET on a granted origin). Same cage for Talk, MCP, HAL, HTTP APIs, and `/v1` clients. How to enable it, grant addresses, inspect APIs, and what you must not claim (not Firecracker-by-default, not Chromium computer-use, not a coding-agent product).

### [Memory Vector Box + DI audit middle](architecture/memory-vector-box-and-di-audit.md)
Universal memory container (super_key + identity_key), SOC2-shaped distributed-intelligence audit middle format, and data-context / relational containers.

---

## Section 1 — Getting Started

*Five documents. Enough to run a governed agent, configure it with YAML, call it from Python, and encode its behavior in a CCL contract.*

### [Architecture map (repo root)](../ARCHITECTURE.md)
Short index of kernel, OSS crates, AGOS artifacts, UI, and doc entry points (lives next to **`CONNECTOR_OS_ROADMAP.md`**).

### [01 — Quickstart](01-quickstart.md)
Install the Connector node. Boot your first governed agent. Run the five essential `connectorctl` commands. See a real governance decision in 10 minutes. Covers platform prerequisites, Docker and bare-metal install paths, environment variables, health verification, and the first live API call.

### [SELFHOST_LINUX — Boring production install](SELFHOST_LINUX.md)
Single-node Linux path: `make package` → FHS install → systemd `connector-platform` → doctor / support-bundle / node-upgrade. Explicitly non-HA.

### [CONNECTORCTL_COMMAND_AUDIT — Truthful CLI surface](CONNECTORCTL_COMMAND_AUDIT.md)
Namespace grammar (`node|data|workload|govern|substrate|access`), evidence contract, and removed soft-lie commands.

### [02 — Product Overview](02-product-overview.md)
What Connector is and why it exists. The three-layer product model: Node (the daemon), Glue (the developer surface), and Workloads (agents, pipelines, memory running on top). The governed AI problem — uncontrolled tool calls, silent data leakage, no audit trail, unprovable reasoning — and how Connector solves it structurally. Mental model: Connector is a layer between your LLM and the world, not a wrapper around one.

### [03 — YAML Configuration](03-yaml-configs.md)
Complete reference for every YAML configuration file Connector reads. Node config (`connector.yaml`), agent manifest (`agent.yaml`), policy definitions (`policies/`), memory namespace declarations, tool allowlist, budget constraints, network rules, and secret references. Annotated examples for minimal, standard, and production configurations. How YAML configuration maps to runtime behavior and which fields can be hot-reloaded without restart.

### [04 — Python SDK](04-python-sdk.md)
The `ConnectorPlatform` Python client — every method, signature, return type, and error. Agent lifecycle (`create_agent`, `start_agent`, `stop_agent`). Memory operations (`write_memory`, `get_agent_memory`, `get_interference`). Governed chat (`invoke_chat_raw`). Firewall inspection (`firewall_inspect`). Decision recording (`record_decision`). Books and journal (`get_books_journal`, `list_audit_receipts`, `generate_proof`). Cost and budget (`get_agent_cost`, `get_budget_status`). Complete examples for each method group.

### [05 — CCL Contracts](05-ccl-contracts.md)
The Connector Contract Language. Grammar, keywords, and block types. Writing a contract: `contract`, `intent`, `memory`, `tools`, `state`, `events`, `governance`, `budget`. Step operations: `call`, `write`, `read`, `emit`, `branch`, `require`, `check_budget`, `await_hitl`. Predicate syntax and type system. The full compile pipeline: lex → parse → sema → lower → optimize → verify → emit. CID-addressed contracts (`cls1-sha256-*`) and Ed25519 signatures. Deploying a contract to a live node. Versioning and hot-swap.

---

## Section 2 — Workflow Library

*One hundred workflow patterns organized across five domains. Each pattern names the CCL contract shape, YAML config, Python call sequence, and connectorctl verification commands.*

### [06 — Workflow Library Index](06-workflow-library.md)
The master index of 100 workflow patterns across all domains. Each entry: pattern name, domain, required rings, contract sketch, estimated token cost, compliance tags (HIPAA, SOC2, GDPR, EU-AI-Act). Organized as a lookup table. Links to domain chapters 07–10. Covers creation, validation, execution, audit, and teardown lifecycle for any workflow.

### [07 — Governance and Compliance Workflows](07-workflows-governance-compliance.md)
Twenty-five workflow patterns for regulated environments. HIPAA minimum necessary enforcement. SOC2 audit trail generation. GDPR right-to-erasure agent. EU AI Act Article 13 transparency output. Multi-jurisdiction policy stacking. Automated compliance report generation. Decision ledger attestation. Regulatory hold workflows. Incident response chain. Each pattern includes full CCL contract, YAML overrides, and audit verification steps.

### [08 — Data Privacy and PHI Workflows](08-workflows-data-privacy.md)
Twenty-five workflow patterns for data-sensitive systems. Selective context construction (full internal state → minimal LLM exposure). PII detection and redaction pipeline. Namespace isolation between patients, customers, or tenants. Identity-aware execution without identity exposure to LLM. Cryptographic proof of data minimization. PHI access logging. Cross-border data residency enforcement. Anonymization chains. De-identification with re-linkage prevention.

### [09 — DevOps and Deterministic Execution Workflows](09-workflows-devops-execution.md)
Twenty-five workflow patterns for infrastructure automation. Governed deployment pipelines (validate → update → restart → verify). Dependency-ordered multi-step workflows. Hash-verified deterministic execution. Rollback on failure with audit trail. Cost-bounded compute jobs. Constraint-checked tool invocation. Schema-validated API calls. Canary release governance. Infrastructure drift detection. Execution replay and forensic reconstruction.

### [10 — Multi-Agent Coordination Workflows](10-workflows-multiagent.md)
Twenty-five workflow patterns for agent networks. Agent delegation chains with proof-of-authority. Consensus voting workflows. Parallel agent fan-out with result aggregation. Specialist agent routing (medical, legal, financial domains). Agent-to-agent memory sharing with namespace fencing. Conflict resolution between competing agent decisions. Human-in-the-loop escalation networks. Peer agent trust negotiation. Cross-cell agent coordination.

---

## Section 3 — Architecture

*Nine chapters. One overview plus eight chapters mapping the nine concentric rings of the Connector system. Every ring is a distinct enforcement boundary.*

### [11 — Architecture Overview: The 9-Ring Model](11-architecture-overview.md)
The conceptual architecture of Connector as nine concentric enforcement rings. Every request entering the system passes through every ring in sequence. No ring can be skipped. Each ring operates independently and fails closed. Full system topology diagram: external caller → Ring 1 (Identity) → Ring 2 (Network) → Ring 3 (Firewall) → Ring 4 (Memory) → Ring 5 (Governance) → Ring 6 (Reasoning) → Ring 7 (Execution) → Ring 8 (Audit) → Ring 9 (Surface). Data flow diagrams for the four primary paths: chat, memory write, tool dispatch, proof generation.

### [12 — Ring 1: Identity and Boot](12-ring-1-identity-boot.md)
Node identity: how a Connector node proves it is what it claims to be. The 12-stage boot sequence: IDENTITY → CONFIG → SECRETS → STORAGE → KERNEL → POLICIES → SCHEDULER → CAPABILITIES → RESTORE → SERVICES → ACCESS → READY. Ed25519 node keypair generation and storage. Trust anchors and root-of-trust establishment. systemd `Type=notify` and readiness signaling. Kubernetes liveness, readiness, and startup probes. Graceful shutdown and connection draining. `binary_id.rs` — binary attestation and tamper detection.

### [13 — Ring 2: Network and Gateway](13-ring-2-network-gateway.md)
How requests enter the Connector node. Protocol gateway: HTTP/1.1, HTTP/2, WebSocket. Internal DNS (`internal_dns/`). Session stickiness and connection affinity. mTLS termination and certificate management. Auth middleware: API keys, bearer tokens, agent PIDs. Rate limiting and global quota enforcement. Cross-cell port routing (`cross_cell_port.rs`). Network topology for distributed deployments. The distributed module and cell discovery protocol.

### [14 — Ring 3: Firewall and Guard Pipeline](14-ring-3-firewall-guard.md)
The five-layer guard pipeline that every message passes through. Layer 1: Semantic injection detection (prompt injection scoring). Layer 2: PII and PHI content guard (`content_guard.rs`). Layer 3: Tool command validation and namespace policy. Layer 4: Budget and cost enforcement. Layer 5: Behavioral anomaly and instruction drift detection. `firewall_inspect` API — what it returns and how to read it. `firewall_events.rs` — event stream from the pipeline. How each layer contributes to the final `decision_id`. Fail-closed behavior and safe denial responses.

### [15 — Ring 4: Memory Kernel](15-ring-4-memory-kernel.md)
The Connector memory system. CID-addressed memory packets (`memory_format.rs`). CBOR encoding and DAG structure. The redb persistent store (`redb_store.rs`) and SQLite fallback. Memory namespaces: `/p/` (private/PHI), `/m/` (agent memory), `/s/` (system). Write operations: packet ingestion, deduplication, CID assignment. Read operations: semantic recall, exact lookup, range scan. Contradiction detection (`get_interference`). Memory stability under noise: how 31 writes of contradictory data still enforce a single instruction. Memory tree traversal and position tracking (books position).

### [16 — Ring 5: Policy and Governance Engine](16-ring-5-policy-governance.md)
The policy engine at the heart of Connector. Policy rule structure: conditions, actions, priorities. Runtime policy evaluation: how a request is matched against active policies. CCL contract execution: how deployed contracts govern agent behavior. Decision recording (`record_decision`): every governance outcome becomes a ledger entry with `decision_id`. HITL (human-in-the-loop) queue: when policy requires human review. `formal_verify.rs` — mathematical verification of policy consistency. Regulation tags: how HIPAA, SOC2, GDPR tags attach to decisions. Budget governance: token, cost, and time limits enforced at the policy layer.

### [17 — Ring 6: Reasoning and LLM Interface](17-ring-6-reasoning-llm.md)
How Connector mediates between your code and the LLM. The governed chat path (`/v1/chat/completions`): how it differs from raw LLM calls. Context construction: the selective exposure model — what the LLM sees vs. what the system knows. LLM router (`llm_router.rs`): model selection, fallback, cost routing. Grounding verification (`grounding.rs`): checking that LLM outputs are grounded in documented facts. Claims verification. The cognitive substrate (`cognitive/`): 11-layer reasoning pipeline — perception → meaning → tension → possibility → evaluation → commitment → plan → action → reflection. Dehallucination: how Connector refuses to fabricate when evidence is absent.

### [18 — Ring 7: Tool Execution](18-ring-7-tool-execution.md)
Controlled tool execution. Tool bridge and MCP integration. Tool allowlist enforcement: what tools an agent may call and under what conditions. Schema validation: every tool call argument is type-checked and range-checked before dispatch. Dependency ordering: multi-step workflows enforce prerequisite completion. Deterministic execution: same intent → same execution plan → same hash. `saga_bridge.rs` — distributed transaction patterns with rollback. Execution receipts: every tool dispatch produces a signed receipt with CID. Tool escalation prevention: namespace policy stops unauthorized tool access. `formal_verify.rs` — proof that execution plan matches declared intent.

### [World cage (Linux slice of Ring 7)](WORLD_CAGE_AND_BROWSER.md)
How world sockets actually leave this node: dest-pinned Landlock children, pore table, vendor cut, browser explorer. Complements Ring 7 policy with a process/network boundary. MicroCell/Firecracker remains a separate isolation plane — see [agent isolation architecture](../platform/docs/arch/CONNECTOR_AGENT_ISOLATION.md).

### [19 — Ring 8 and 9: Audit Chain and Surface](19-ring-8-9-audit-surface.md)
**Ring 8 — Audit and Books:** The integrity-chained journal. Every decision, memory write, tool call, and LLM invocation produces a journal entry. Entries are currently SHA-256 hash-linked (keyed HMAC + recompute verification is the hardening target). `books.rs` — the ledger data model. Sequence numbers, CIDs, and position tracking. `list_audit_receipts` and `generate_proof` — cryptographic proof of compliance. Forensic reconstruction: replaying a complete session from the journal. **Ring 9 — Surface and Output:** The SOE (Surface Output Engine). Role-based rendering: Developer, Operator, Auditor, Executive. `soe1-sha256-*` CID addressing for surface documents. Receipt chains for every render. Export formats: JSON, Markdown, HTML, CSV, YAML. Compliance report generation.

---

## Section 4 — Theory and Mathematics

*Four chapters covering the internal intellectual property: the cryptographic foundations, the cognitive science basis, and the formal verification methods that make Connector's claims provable rather than aspirational.*

### [20 — CID, DAG, and CBOR](20-theory-cid-dag-cbor.md)
Content-addressed identifiers across the Connector system. How a CID is computed: SHA-256 of canonical CBOR-encoded content. DAG (directed acyclic graph) structure of memory packets and contract IR. CBOR encoding: why binary over JSON for kernel data. The three CID namespaces: `mem1-` (memory packets), `cls1-` (compiled CCL contracts), `soe1-` (surface documents). CID collision properties and integrity guarantees. How DAG structure enables partial verification without reading the full graph. Prolly tree structure for ordered memory ranges.

### [21 — Cryptographic Proofs: HMAC Chains, Merkle Trees, and Ed25519](21-theory-cryptographic-proofs.md)
The full cryptographic stack. HMAC-SHA256 journal chains: how each entry authenticates the previous. Chain break detection. Ed25519 keypairs: node identity, contract signing, surface receipts. Merkle tree structure over memory namespaces: path proofs without revealing full state. `fips_crypto.rs` — FIPS-compliant primitives. Post-quantum readiness (`post_quantum.rs`). How `generate_proof` assembles a complete cryptographic proof-of-compliance from journal + receipts + chain verification. Verifying a proof without running Connector.

### [22 — Cognitive Substrate: Theory and Implementation](22-theory-cognitive-substrate.md)
The research foundations of the Connector reasoning engine. Soar cognitive architecture: goals, operators, impasses. BDI (Belief-Desire-Intention): how agents form intentions from beliefs. ACT-R: procedural and declarative memory separation. Global Workspace Theory: how the system broadcasts high-priority signals to specialized modules. Active Inference and the Free Energy Principle: reasoning as minimizing surprise. The 11-layer Connector cognitive pipeline mapped to these theories. `tension.rs` — pressure-driven cognition: no tension, no thought. `commitment.rs` — how commitments persist and survive contradiction. `reflection.rs` — learning from expected vs. actual outcomes.

### [23 — Formal Verification and Determinism Proofs](23-theory-formal-verification.md)
How Connector makes its governance claims mathematically verifiable. `formal_verify.rs` — the verification engine. CCL semantic analysis: the 11-pass validator (name, tool, memory, state, event, branch, type, exhaustiveness, reachability, termination, budget). Termination proofs for CCL contracts. Determinism proof: given the same intent, the same execution plan is produced with the same hash. Policy consistency checking: detecting contradictions between policy rules before deployment. The formal semantics of CCL: operational semantics of each step operation. Model checking for state machine completeness.

---

## Section 5 — Infrastructure Design

*Two chapters. One for internal system wiring. One for external deployment topology.*

### [24 — Internal Infrastructure Design](24-infra-internal.md)
How the platform server is wired internally. Module dependency graph: `connector-engine` (core runtime) → `connector-api` (HTTP layer) → `connector-cli` (operator surface) → `connector-server` (binary). The `connector-glue` crate: the unified developer surface spanning CLI, API, Rust, and external clients. Internal IPC: how the boot system, policy engine, memory kernel, and firewall communicate. Background task scheduler. Storage zones (`storage_zone.rs`): memory, journal, receipts, secrets. KMS integration (`kms/`). Secrets broker (`secret_store.rs`). The `knot` consensus system for distributed state. Watchdog and circuit breaker patterns.

### [25 — External Deployment Topology](25-infra-external.md)
Deploying Connector in production environments. Single-node (operator-managed): bare metal, VM, or container. Multi-node cluster: cell topology, discovery, cross-cell routing. Cloud deployments: AWS, GCP, Azure reference architectures. Kubernetes manifests: Deployment, Service, PersistentVolumeClaim, ConfigMap, Secret, HPA. systemd unit file and installation script. Network policy: what ports Connector exposes, what it calls out to. TLS termination options: internal CA, Let's Encrypt, bring-your-own cert. License server topology: the two-system split (customer-hosted `connector-platform` + owner-hosted `connector-license-server`). Data residency and sovereignty requirements.

---

## Section 6 — API, Routes, and CLI

*Seven chapters. Every HTTP endpoint, every connectorctl verb, complete request/response schemas.*

### [26 — API Overview: Conventions, Auth, and Versioning](26-api-overview.md)
API versioning (`/api/v1/`, `/api/v2/`). Authentication: API key header, bearer token, agent PID auth. Response envelope: `V2Response<T>` — `data`, `error`, `actions`. Error format: `code`, `message`, `hint`, `regulation`. Content types. Rate limiting headers. Pagination: `page`, `limit`, `cursor`. Idempotency keys for write operations. The `audit_cid` field present on every mutating response. How `decision_id` flows from governance decisions into API responses. Health endpoint (`GET /health`) and maturity check (`GET /health/maturity`).

### [27 — API: Agent Lifecycle](27-api-agents.md)
All agent endpoints. `POST /api/v1/agents` — create agent. `GET /api/v1/agents` — list with filters. `GET /api/v1/agents/:pid` — inspect agent state. `POST /api/v1/agents/:pid/start` — start agent. `POST /api/v1/agents/:pid/stop` — graceful stop. `GET /api/v1/agents/:pid/cost` — token and cost summary. `GET /api/v1/agents/:pid/policy/check` — evaluate policy against agent. `POST /api/v1/chat/completions` (governed) — the primary LLM interface. `GET /api/v1/agents/:pid/trace` — recent decision trace. Full request/response schemas for every endpoint.

### [28 — API: Memory Kernel](28-api-memory.md)
Memory read and write endpoints. `POST /api/v1/memory/write` — ingest a memory packet, returns CID. `GET /api/v1/memory/:cid` — retrieve by content address. `POST /api/v1/memory/search` — semantic search with embedding. `GET /api/v1/memory/:pid/tree` — full memory tree for agent. `GET /api/v1/memory/:pid/stats` — packet counts, namespace breakdown. `POST /api/v1/memory/interference` — detect contradictions between namespaces. `DELETE /api/v1/memory/:cid` — remove packet (audit-logged). Memory packet schema: `content`, `namespace`, `cid`, `packet_type`, `agent_pid`, `timestamp`. CID addressing behavior and deduplication.

### [29 — API: Firewall and Guard](29-api-firewall.md)
Firewall inspection endpoints. `POST /api/v1/firewall/inspect` — run content through the 5-layer guard pipeline. `GET /api/v1/firewall/events` — stream firewall events. `GET /api/v1/agents/:pid/firewall/summary` — aggregated firewall stats for agent. Response fields: `blocked`, `final_decision`, `layers_evaluated`, `injection_score`, `pii_detected`, `namespace_violations`, `budget_status`, `behavioral_flags`, `audit_cid`. How to read a firewall response during a live demo. Configuring firewall sensitivity thresholds. Custom firewall rule injection.

### [30 — API: Governance, Decisions, and HITL](30-api-governance.md)
Policy and decision endpoints. `POST /api/v1/decisions` — record a governance decision, returns `decision_id`. `GET /api/v1/decisions/:id` — retrieve decision with rationale. `GET /api/v1/agents/:pid/decisions` — decision history for agent. `GET /api/v1/hitl/queue` — pending human review items. `POST /api/v1/hitl/:id/approve` — approve a queued decision. `POST /api/v1/hitl/:id/deny` — deny with reason. `GET /api/v1/agents/:pid/policy/check` — evaluate a proposed action against active policies. Decision schema: `decision_id`, `action`, `target`, `outcome`, `rationale`, `confidence`, `regulations`, `audit_cid`.

### [31 — API: Audit, Books, and Proof](31-api-audit.md)
The complete audit system API. `GET /api/v1/books/journal` — paginated integrity-chained journal. `GET /api/v1/books/position` — current journal head position. `GET /api/v1/receipts` — list execution receipts. `GET /api/v1/receipts/:id` — single receipt with tool call detail. `POST /api/v1/proof/generate` — generate cryptographic compliance proof. `POST /api/v1/compliance/verify` — verify a proof bundle. `GET /api/v1/claims/verify` — verify LLM output claims against journal. `GET /api/v1/grounding/check` — verify reasoning is grounded in documented evidence. Journal entry schema: `seq`, `cid`, `prev_hmac`, `hmac`, `event_type`, `payload`, `timestamp`.

### [32 — connectorctl: Complete CLI Reference](32-connectorctl.md)
Every connectorctl verb and noun. The operating grammar: 12 verbs, 10 nouns, pronoun-like selectors. **Verbs:** `health`, `doctor`, `show`, `inspect`, `trace`, `explain`, `prove`, `review`, `cost`, `agents`. **Invocations and flags:** `connectorctl health` (node status), `connectorctl doctor --verbose` (diagnostics), `connectorctl agents` (list all), `connectorctl inspect <pid>` (full agent state), `connectorctl show agent <pid>` (formatted summary), `connectorctl trace agent <pid> --last 5m` (recent decisions), `connectorctl trace agent <pid> --memory` (memory writes), `connectorctl explain <decision_id>` (governance decision detail), `connectorctl prove agent <pid>` (cryptographic proof), `connectorctl review agent <pid>` (policy + instruction review), `connectorctl cost <pid>` (token and budget summary). **Plugins:** Connector Hub (`.cpkg`) and **`connectorctl tier`** (thermal scheduler) are documented in ch. 32. **Ops:** `status --json` / `doctor --json` expose `process_env_operator_display_line` (also under `phase_5_operator` from `GET /api/v1/plugins/status`); repo **`make kernel-prod-preflight`**. Output contract format. Using connectorctl in CI/CD pipelines. Scripting with `--json` output flag.

---

## Section 7 — Tutorials

*Eight end-to-end tutorials. Each is a complete worked example: goal, config, code, commands, verification.*

### [33 — Tutorial 1: Build Your First Governed Agent](33-tutorial-first-agent.md)
From zero to a governed agent in production. Install Connector. Write `agent.yaml`. Create the agent via API. Write a governed chat request. Read the `audit_cid` from the response. Run `connectorctl inspect <pid>`. Run `connectorctl explain <decision_id>`. Understand what happened in the firewall. See the journal entry. Verify the integrity chain. Expected output at every step. Common errors and fixes.

### [34 — Tutorial 2: Memory Ingestion and Recall Patterns](34-tutorial-memory-patterns.md)
Multi-wave memory ingestion. Writing 30 facts from different sources into different namespaces. Semantic recall: asking a question and getting memory-grounded answers. Testing contradiction detection: writing conflicting facts and observing the interference detection. Memory stability under noise: 31 conflicting writes, one instruction survives. Memory tree inspection. Namespace fencing: proving that `/p/` content never appears in `/m/` context. Complete Python code for each pattern.

### [35 — Tutorial 3: Custom Firewall Rules](35-tutorial-firewall-rules.md)
Configuring the 5-layer guard pipeline for a specific domain. Writing YAML policy rules that trigger firewall interventions. Testing injection detection with real payloads. Configuring PII field detection beyond defaults. Adding custom namespace violation rules. Budget threshold configuration. Testing with `firewall_inspect` API before going live. Behavioral drift detection: baseline vs. anomalous calls. Reading firewall events in real time. Using `connectorctl trace agent <pid> --last 5m` to verify rule firing.

### [36 — Tutorial 4: Writing and Deploying CCL Contracts](36-tutorial-ccl-workflows.md)
Writing a complete CCL contract for a medical records summarization agent. Step-by-step: contract declaration, intent block, memory bindings, tool allowlist, state machine, event handlers, governance block with HITL escalation, budget block. Compiling: `compile_ccl_default(source)`. Reading the emitted CID. Deploying to a live node. Testing the contract in stub mode. Triggering a HITL queue event. Hot-swapping a running contract. Versioning and rollback. What happens when the contract rejects a step.

### [37 — Tutorial 5: Audit Trail and Cryptographic Proof](37-tutorial-audit-proof.md)
The complete forensic workflow. Run an agent through a multi-step task. Retrieve the journal with `get_books_journal`. Read each entry: seq, HMAC, event type, payload. Verify the integrity chain manually (Python code included). Retrieve all receipts with `list_audit_receipts`. Generate a proof bundle with `generate_proof`. Verify the proof without running Connector (standalone verifier code). Export to compliance report. Using `connectorctl prove agent <pid>` and `connectorctl explain <decision_id>` live. This tutorial is the foundation for all regulatory audit responses.

### [38 — Tutorial 6: Multi-Agent Coordination](38-tutorial-multiagent.md)
Coordinating three agents: a coordinator, a specialist, and a validator. Coordinator agent routes requests to the specialist. Specialist returns structured output. Validator checks the output against policy before the result is surfaced. Delegation chain with proof-of-authority. Memory sharing: specialist writes to `/m/shared/` namespace. Namespace fencing: validator cannot read coordinator's private memory. Conflict resolution: what happens when specialist and validator disagree. Full Python orchestration code and CCL contracts for each agent role.

### [39 — Tutorial 7: Human-in-the-Loop Workflows](39-tutorial-hitl.md)
Building a governed system that pauses for human review. HITL policy rule: when confidence < 0.7, escalate. Triggering the HITL queue from a CCL `await_hitl` step. Polling the HITL queue with `GET /api/v1/hitl/queue`. Building a simple review UI (HTML + fetch calls to the API). Approving and denying items. Audit trail of human decisions. Timeout handling: what happens if no human reviews within the deadline. Multi-approver consensus: requiring two humans to approve. Using HITL for regulatory compliance gates.

### [40 — Tutorial 8: Building a HIPAA-Compliant Medical AI System](40-tutorial-compliance.md)
A complete, production-grade governed medical AI system. Patient records in `/p/` namespace. Selective context construction: what the LLM sees vs. what the system knows. PII guard: preventing patient contact information from reaching the LLM or the output. Decision recording with HIPAA regulation tag on every interaction. HITL escalation for treatment recommendations. Cryptographic proof of data minimization. Audit trail for HIPAA audit response. Cost tracking. Multi-patient namespace isolation. Running the system through the Demo 5 scenarios and reading the forensic output.

### [99 — Gateway SDK Examples](99-gateway-sdk-examples.md)
Minimal, copy-paste integrations for OpenAI SDK, LangChain, LangGraph, and CrewAI against Connector's OpenAI-compatible gateway URL (`/v1`) with quick verification steps.

---

## Section 8 — Builder's Guide

*Ten chapters for developers building on top of Connector. How to extend the system, embed it, control real executions, and ship products built on governed AI infrastructure.*

### [41 — Builder Overview: Extension Points and Product Shapes](41-builder-overview.md)
The architecture of extensibility. What Connector exposes for builders: the API (HTTP), Glue (unified developer surface), Python SDK, CCL (contracts), and the plugin system. Three shapes of building on Connector: (1) Embed — use Connector as the governance layer inside your existing product. (2) Extend — add custom firewall layers, memory adapters, or surface renderers. (3) Build — use Connector as the complete runtime and build your product as a workload on top. Which shape fits your use case. The Glue concept: language-first, not wrapper-first. Builder design principles: every action is auditable, every claim is verifiable, every extension inherits the ring model.

### [42 — Builder: Tool Bridge and MCP Integration](42-builder-tool-bridge.md)
Registering tools with the Connector tool bridge. MCP (Model Context Protocol) integration: how Connector wraps MCP servers to enforce governance on every tool call. Writing a tool schema: name, description, parameters (JSON Schema), allowed namespaces, required policy tags. Tool registration API: `POST /api/v1/tools/mcp/register`. Testing a registered tool with `POST /api/v1/tools/mcp/invoke`. How the tool bridge enforces schema validation, namespace policy, and budget limits before dispatch. Execution receipt generation. Building an MCP server that Connector can govern. DevGuard integration: governing AI coding agents (Cursor, Windsurf, Claude Code, GitHub Copilot, Kiro) through the universal hook system.

### [43 — Builder: Custom Memory Adapters](43-builder-memory-adapters.md)
Writing a custom memory backend. The `MemoryStore` trait: `write`, `read`, `search`, `delete`, `tree`, `stats`. Implementing for PostgreSQL, Redis, Pinecone, Weaviate, or any vector store. CID computation contract: your adapter must compute the same `mem1-sha256-*` CID as the default redb store. Namespace fencing requirement: adapters must enforce namespace isolation or the ring model breaks. Registering your adapter in `connector.yaml`. Testing with the memory interference detection system. Performance characteristics: what the kernel expects in terms of write and recall latency. Adapter certification checklist.

### [44 — Builder: Custom Firewall Guard Layers](44-builder-firewall-layers.md)
Extending the 5-layer guard pipeline with custom layers. The `GuardLayer` trait: `name`, `evaluate(input) -> GuardResult`. `GuardResult` fields: `blocked`, `score`, `reason`, `tags`, `modifications`. Layer ordering and how scores combine. Writing a domain-specific guard: medical terminology classifier, financial regulation scanner, code safety checker. Registering layers via `connector.yaml` plugin config. Hot-reload of guard layers without node restart. Testing layers in isolation with the `firewall_inspect` endpoint. Performance budget: guard layers must return within 50ms or the pipeline fails closed. Audit: every layer evaluation is journaled.

### [45 — Builder: Extending CCL](45-builder-ccl-extensions.md)
The CCL extension system. Adding custom step operations beyond the 14 built-ins. The `StepOp` registration API. Writing a custom semantic analysis pass for the CCL compiler. Adding custom predicate functions. Domain-specific CCL vocabularies: medical CCL extensions, financial workflow extensions. The CCL IR (intermediate representation): how to write a custom emitter that targets a different runtime. Testing CCL extensions with the 115-test suite. Maintaining forward compatibility: extension versioning and deprecation. Publishing a CCL extension as a Connector plugin.

### [46 — Builder: RAG and Retrieval Patterns](46-builder-rag-retrieval.md)
Building retrieval-augmented generation on top of Connector's governed memory. Why Connector RAG differs from naive RAG: every retrieved chunk has a CID, every retrieval is journaled, retrieved content passes through the firewall before reaching the LLM. Writing retrieval pipelines: semantic search → namespace filter → firewall inspect → context construction → governed chat. Embedding management: how Connector stores and indexes embeddings alongside memory packets. Grounding verification: after the LLM responds, `grounding.rs` checks that outputs are traceable to retrieved content. Hallucination prevention: refusing to answer when retrieval returns nothing. Governed RAG for HIPAA (PHI-restricted retrieval) and SOC2 (audit-logged retrieval).

### [47 — Builder: Real Execution Control](47-builder-real-execution-control.md)
How to block, gate, and control real executions. The difference between an LLM suggestion and a Connector execution: suggestions are validated, gated, and audited before anything real happens. Execution gates: CCL `require` predicates that must pass before a step runs. HITL gates: requiring human approval before destructive operations. Budget gates: hard limits on cost, tokens, and time. Namespace gates: execution constrained to declared scope. Blocking patterns: deny-by-default tool policy with explicit allowlist. Execution dry-run: `exec/dry-run` endpoint to validate without running. Rollback: how `saga_bridge.rs` implements compensating transactions. The determinism guarantee: two identical intents produce identical execution plans with the same cryptographic hash.

### [48 — Builder: Custom Surface Engine](48-builder-surface-engine.md)
Building custom operator surfaces using the SOE (Surface Output Engine). The `SurfaceRenderable` trait. Writing a custom renderer for your domain: clinical dashboard, security operations center, financial audit view. Role-based rendering: `Developer`, `Operator`, `Auditor`, `Executive` — each sees a different view of the same data. Surface CID (`soe1-sha256-*`): every rendered surface is content-addressed and receipt-chained. The `SurfaceBuilder` fluent API: `agent("id").view().judgment_ok().stats().build()`. Export formats: integrating your surface with downstream reporting systems. Streaming surfaces: real-time operator dashboards using the `SurfaceBus`. Custom compliance surface for your specific regulatory framework.

### [49 — Builder: Plugin System and Extensions](49-builder-plugin-system.md)
The Connector plugin model. Plugin types: guard layer plugins, memory adapter plugins, CCL extension plugins, surface renderer plugins, tool bridge plugins. Plugin manifest: `connector-plugin.yaml` — name, version, type, entry point, required permissions, API compatibility version. Plugin loading: how `connector.yaml` references plugins and how the node loads them at boot. Plugin isolation: plugins run in a sandboxed execution context (`sandbox.rs` — IsolationLevel, ResourceLimits, SandboxCapability). Plugin audit: every plugin invocation is journaled with the plugin name and version. Writing a plugin test suite. The plugin certification process. Publishing to the Connector plugin registry.

### [AGOS — Plugin authoring (`plugin.toml`, `agos.v1`)](agos/plugin-authoring.md)
Connector OS **AGOS** community plugins: **`plugin.toml`**, **`agos-sdk` / `agos-abi`**, **`cargo connector new`**, **`connectorctl plugin verify`**, and a **hello world under 30 lines** of manifest + Rust. Links to **`PLUGIN_CONTRACT.md`** and the roadmap certification gate (§2A.9).

### [AGOS — ABI versioning (`agos.v1` / `agos.v2`)](agos/abi-versioning.md)
Deprecation policy, kernel **`supported_contract_ids`**, staged rollouts, and handshake rules when **`agos.v2`** ships.

### [AGOS — Workflow builder contract (CLS / P3.3)](agos/workflow-builder-contract.md)
Substrate-only CLS authoring laws, tool → platform mapping, sample `substrate_memory_moment`, and **round-trip honesty** (`GET /api/v1/workflows/:id/builder-round-trip` → `round_trip: planned|partial|ok`; `partial` when session CLS fingerprint exists).

### [50 — Builder: Production Deployment Guide](50-builder-production-guide.md)
Taking a Connector-based system from prototype to production. Pre-production checklist: identity keypair rotation, secrets in KMS not plaintext, TLS everywhere, backup and restore tested, HITL queue monitored, journal retention policy set. Operational runbook: how to respond to a chain break alert, a firewall bypass attempt, a budget exhaustion event, a node crash. Scaling: horizontal scaling patterns, stateless vs. stateful components. Observability: metrics endpoints, log format, distributed tracing integration. License server integration: tier enforcement and entitlement management. Security hardening: network policy, SELinux/AppArmor profiles, secret rotation schedule. Incident response: using the journal and proof system to reconstruct exactly what happened. Handing the system to a compliance officer: what to show, what to export, what to keep.

---

## Section 9 — Future Architecture

*Five chapters describing capabilities that are **built and working today** but not required for initial deployment. These are the forward foundation of Connector — the infrastructure layers that become essential as governed AI moves from single-node to planetary scale. Read these to understand where the system is heading and why the architecture was designed this way from the start.*

### [51 — CLS: The Connector Contract Language System](51-cls-system.md)
The full CLS (Connector Language System) — the layer above CCL. Where CCL is the syntax for writing a single contract, CLS is the runtime that links contracts into networks, versions them, addresses them by CID, routes execution across them, and enforces inter-contract governance. The 7-module compiler pipeline (lex → parse → sema → lower → optimize → verify → emit) already ships in `connector-engine/src/cls/`. The `registry.rs` — a content-addressed contract registry where every deployed contract is stored by `cls1-sha256-*` CID and can never be silently modified. Contract templates. Inter-contract calls. Why CLS matters when you have 10,000 agents each running a different contract version. The future: CLS as the universal governance bytecode for AI systems.

### [52 — Glue: The Unified Developer Surface](52-glue-developer-surface.md)
Glue is the unified language for building on Connector. Not an SDK — a semantic surface that spans CLI, API, Rust native, Python, and any external client. Built in `connector-glue/` with a complete verb/noun/selector grammar: `glue.run(target).with_memory(ns).under_policy(name).audit()`. Why Glue exists: the SDK model fails because it creates wrappers, not contracts. Glue creates a single semantic intent that compiles down to governed execution regardless of caller language. The Glue `runtime.rs` — session management, intent tracking, audit threading. CNP (Connector Native Protocol) handles: `cnp_session`, `cnp_port`, `cnp_capability`, `cnp_message`, `cnp_route`. The future: Glue as the standard interface for any system that wants to call a governed AI agent, from a bash script to a distributed microservice mesh.

### [53 — Global Agent Distribution Network](53-global-agent-distribution.md)
How Connector agents distribute across a global network of nodes while maintaining governance guarantees. The distributed subsystem in `platform/server/src/distributed/`: topology, scheduling, leader election, failure detection, service registry, traffic management, transport. A `CellInfo` is a governed node in the network. Agents can migrate between cells. The governance contract travels with the agent — a migrated agent runs the same CCL contract on the destination node. Cross-cell memory: how the memory kernel federates across cells with CID-addressed deduplication. The `knot` consensus system: distributed agreement on governance decisions. Topology links and path health scoring. The future: a planet-scale network of governed AI nodes where any agent can run anywhere without losing its audit trail, its memory, or its policy.

### [54 — Agent DNS: Discovery, Routing, and Identity](54-agent-dns-discovery.md)
As the number of governed agents grows, finding the right agent for a task becomes a routing problem. The `internal_dns/` module is the foundation of agent-addressable naming. Agent identity in a distributed network: a governed agent has a stable identity (its `pid` derived from its keypair) that persists across restarts and migrations. Agent discovery: querying the network for agents by capability, domain, policy tag, or namespace. The `TopologyDiscovery` and `SharedTopologyDiscovery` structures — maintaining a live map of which agents are where and what they can do. Routing by trust: agents route requests to peers whose trust level matches the required policy. The `reputation.rs` module — agents build trust scores through verified interactions. The future: a DNS-like system where `medical-summarizer.agents.connector` resolves to the nearest governed medical agent with verified HIPAA compliance.

### [55 — Edge Agent Deployment and CDN-Style Distribution](55-edge-agent-deployment.md)
Governed AI agents deployed at the edge — close to users, data, and decision points — while the governance contract and audit trail remain anchored to the origin network. The sandbox model (`sandbox.rs`): `IsolationLevel` (None, Process, Container, VM, Hardware), `ResourceLimits`, `SandboxCapability`, `SandboxViolation`. An edge agent runs in a sandboxed environment with attenuated capabilities — it can only do what the deployed contract permits, even if the edge node is compromised. Edge memory: what can be cached locally (public context, tool schemas) vs. what must always go to origin (PHI, audit journal, proof generation). The traffic manager and transport layer in `distributed/`: how edge agents report decisions back to the origin audit chain in real time. The future: a CDN-like network of governed AI inference points where every request is locally fast, globally audited, and cryptographically provable — Connector as the governance layer for edge AI.

---

## Section 10 — Storage, Knowledge, Compliance, and the 9 Chains

*Seven chapters covering the data architecture that underlies everything, the full compliance framework, and the nine chain structures that make every Connector claim provable. These are the internal mechanics that turn governance from a policy document into a mathematical guarantee.*

### [56 — Namespace and Storage Architecture](56-namespace-storage.md)
The full data topology of a Connector node. Every piece of data lives in a namespace. Namespaces are not folders — they are governed address spaces with security levels, integrity levels, access controls, and HMAC-chained isolation. The four primary namespaces: `/p/` (private — PHI, PII, confidential data; never exposed to LLM), `/m/` (agent memory — working facts, observations, context written during agent operation), `/k/` (knowledge — compiled, curated, expert-reviewed facts that seed agents), `/s/` (system — node configuration, policy state, internal coordination). Sub-namespace patterns: tenant isolation (`/p/hospital-a/patients/`), agent isolation (`/m/agent-01/session/`), knowledge domains (`/k/medical/cardiology/`). Storage tiers: hot (redb in-memory+disk), warm (SQLite), cold (archive). Data standardization: `MemPacket` schema — `content`, `cid`, `namespace`, `packet_type`, `agent_pid`, `timestamp`, `hmac`, `embedding`. How CID addressing enables deduplication across namespaces without copying data.

### [57 — Knowledge System: The `/k/` Namespace and Knowledge Forms](57-knowledge-system.md)
The knowledge system is what separates a governed AI system from a chatbot with a system prompt. The `/k/` namespace holds curated, compiled, expert-reviewed knowledge that agents draw on before reasoning — not retrieved from an LLM's training weights but from documented, auditable sources. The 8 Knowledge Forms from `cognitive/types.rs`: `Factual` (verified observations with confidence), `Procedural` (step-by-step methods with preconditions and postconditions), `Structural` (relationship graphs between entities), `Causal` (cause → effect with probability), `Analogical` (pattern mapping between domains), `Counterfactual` (what would have happened under different conditions), `Temporal` (time-ordered knowledge with validity windows), `Normative` (rules and enforcement levels). The Knowledge Engine: `ingest()` (add observations, detect contradictions), `retrieve()` (4-way retrieval with RRF fusion and token budget), `compile()` (cache expensive reasoning as compiled knowledge packets with CID). Knowledge seeds: pre-trained knowledge loaded at agent creation. Growth events: how knowledge evolves from interference analysis. Hyperbolic embeddings in `chain_tree.rs` for knowledge recall. Knowledge provenance: every fact has a traceable source, confidence score, and last-verified timestamp.

### [58 — Compliance Framework: HIPAA, SOC2, GDPR, EU AI Act](58-compliance-framework.md)
How Connector addresses each major regulatory framework structurally — not through policy documents but through the system's architecture. **HIPAA:** Minimum necessary principle enforced by namespace policy (`/p/` never reaches LLM). PHI access logging in the audit journal. Business Associate Agreement technical controls. Audit trail with 6-year retention path. `generate_proof` produces HIPAA audit response bundles. **SOC2:** All five Trust Service Criteria (Security, Availability, Processing Integrity, Confidentiality, Privacy) mapped to Connector subsystems. `compliance.rs` — the compliance service layer. Automated evidence collection for SOC2 Type II. **GDPR:** Right to erasure: CID removal from namespace + journal tombstone. Data minimization by default (selective context construction). Data residency: namespace-to-cell binding for EU data. Consent management through governance decisions. **EU AI Act:** Article 13 transparency: every LLM output includes `audit_cid` for traceability. High-risk AI system requirements: human oversight via HITL, accuracy monitoring via grounding verification, robustness via the firewall pipeline. Logging obligations: the audit journal satisfies Article 12. Risk management documentation: CCL contracts are machine-readable risk documentation. **Multi-framework:** How a single agent interaction can simultaneously satisfy HIPAA, SOC2, and EU AI Act requirements — the unified compliance proof bundle.

### [59 — The 9 Chains: System Overview](59-chains-overview.md)
Connector's governance guarantees are implemented as nine distinct chain structures. A chain is a sequence of linked, cryptographically-connected nodes where each node references its predecessor. Breaking a chain is detectable. Extending a chain requires authorization. Reading a chain produces a complete, ordered history. The 9 chains: (1) **Audit Chain** — integrity-linked journal of every system event. (2) **Memory Chain** — CID-linked sequence of memory packet writes per namespace. (3) **Dehallucination Chain** — grounding validation nodes linking LLM outputs to verified source packets. (4) **Compliance Chain** — regulation-tagged decision nodes forming the compliance ledger. (5) **Governance Chain** — CCL contract execution steps forming the policy enforcement record. (6) **Execution Chain** — tool dispatch receipts forming the action ledger. (7) **Trust Chain** — reputation score updates forming the trust history per agent. (8) **Proof Chain** — hierarchical attestation tree (`proof_chain.rs`) linking all other chains into a single verifiable bundle. (9) **Isolation Chain** — namespace access events forming the security perimeter audit. How the 9 chains relate: the Proof Chain is the root that anchors all others. Every `generate_proof` call traverses all 9 chains and produces a single bundle that proves everything simultaneously.

### [60 — Chains 1–3: Audit, Memory, and Dehallucination](60-chains-audit-memory-dehall.md)
Deep documentation of the first three chains. **Audit Chain:** The primary integrity-linked journal in `books.rs`. Entry schema: `seq` (monotonically increasing), `cid` (content address of entry), `prev_hmac` (HMAC of previous entry), `hmac` (HMAC of this entry using prev as key), `event_type`, `payload`, `timestamp`. Chain verification: any break in the HMAC sequence is immediately detectable. `t0_chain_verified` flag in the books response. `causal_chain` field — how journal entries reference each other causally, not just sequentially. **Memory Chain:** Every write to a namespace produces a chained memory entry. The chain is per-namespace: `/p/` has its own chain, `/m/` has its own, `/k/` has its own. Chain hash in `namespace_isolation.rs`: each access event extends the namespace chain. `IsolationChain` and `ChainLink` structures. Chain break detection: `handle_chain_breach()`. `verify_all_chains()` — operator command to check integrity of all namespace chains simultaneously. **Dehallucination Chain:** `ChainNodeType::Dehallucination` in `chain_tree.rs`. `DehallData` structure: links an LLM output node to one or more `Memory` nodes that verify it. When an LLM makes a claim, the dehallucination chain records: the claim, the source memory packets that support it (by CID), the grounding score, and whether the chain validates or breaks. A broken dehallucination chain means the LLM output was not grounded — the system refuses to surface it.

### [61 — Chains 4–6: Compliance, Governance, and Execution](61-chains-compliance-governance-execution.md)
Deep documentation of chains four through six. **Compliance Chain:** Built in `compliance.rs` and `services/`. Every governance decision that carries a regulation tag (`hipaa`, `soc2`, `gdpr`, `eu-ai-act`) is added to the compliance chain. The chain is queryable by regulation: "show me all HIPAA-tagged decisions in the last 30 days." Each compliance chain node: `decision_id`, `regulation_tags`, `action`, `outcome`, `agent_pid`, `timestamp`, `audit_cid`. Compliance chain export: `POST /api/v1/compliance/export` produces a regulation-specific evidence bundle. **Governance Chain:** The CCL contract execution record. Each `StepOp` executed by the CLS executor produces a governance chain node: which step, which contract CID, which input, which output, which state transition. The governance chain is the machine-readable proof that the agent followed its contract. Divergence detection: if an agent's behavior does not match what the governance chain predicts, the system detects a policy violation. **Execution Chain:** Every tool dispatch produces a signed execution receipt (`audit_receipts.rs`). Receipts chain: each receipt references the previous receipt's CID for that agent. `verify_receipt_chain()` — validates that all tool calls form an unbroken, authorized chain. The execution chain enables forensic reconstruction: given any session, you can replay every tool call in exact order with exact parameters.

### [62 — Chains 7–9: Trust, Isolation, and Proof](62-chains-trust-isolation-proof.md)
Deep documentation of chains seven through nine. **Trust Chain:** `reputation.rs` maintains a trust score time series for each agent. Each score update is a trust chain node: what interaction produced the update, the delta, the new score, the validator. Trust chain verification: the entire history of how an agent's trust score evolved is auditable. An agent cannot fake a high trust score — the chain shows every interaction that produced it. **Isolation Chain:** `namespace_isolation.rs` — `IsolationChain` with `trust_chain: Vec<ChainLink>`. Every access to a namespace produces a chain link: agent PID, operation, namespace, timestamp, `chain_hash`. `verify_chains()` checks all namespace isolation chains. A broken isolation chain means a namespace boundary may have been violated — the system alerts immediately. `intact_chains` vs `broken_chains` in `IsolationSummary`. **Proof Chain:** `proof_chain.rs` — `ProofChainTree` with `ProofNode` types: `Leaf` (raw evidence), `Aggregate` (rollup of multiple leaves), `CrossReference` (link to another chain), `Temporal` (time-bounded proof). `add_proof()`, `verify_chain()`, `compress_delta()` (delta compression for large chains), `compress_merkle_prune()` (Merkle pruning while preserving verifiability), `create_sparse_index()` (efficient traversal of long chains). Storage tiers: hot, warm, cold — old proof nodes are archived but remain verifiable. The proof chain is the root that anchors all 8 other chains: a single `generate_proof` call produces a `ProofChainTree` that contains or references every chain for the requested agent and time range.

---

## Section 11 — Deployment, LLM Integrations, and Observability

*Three operational chapters covering how to run Connector in production, integrate with any LLM provider or external tool, and connect to observability platforms.*

### [63 — Hosting and Deployment](63-hosting-deployment.md)
Deployment patterns: single-node, high-availability, multi-region, edge mesh. Docker, Docker Compose, Kubernetes StatefulSet with cloud provider reference architectures (AWS, GCP, Azure). systemd service with security hardening. Production `connector.yaml` configuration including TLS, HSM, cluster mode, webhooks, backup. Security hardening checklist. RPO/RTO targets. Monitoring metrics and critical alerts.

### [64 — LLM and Tool Integrations](64-llm-tool-integrations.md)
LLM provider support: OpenAI, Anthropic, Ollama, Azure OpenAI, AWS Bedrock, Google Vertex. LLM Router configuration with retry, fallback, circuit breaker. Ollama local deployment. MCP Tool Bridges: filesystem, GitHub, PostgreSQL, Slack, custom APIs. Tool dispatch through Connector's 9-ring enforcement. Custom tool bridge development. Framework integrations: LangChain, LlamaIndex, CrewAI, AutoGen. Security model for tool calls.

### [65 — Observability and Monitoring Integrations](65-observability-integrations.md)
Observability architecture: SystemWatchdog, ReputationEngine, BehaviorAnalyzer. Supported tools: Splunk, Datadog, Prometheus, Grafana, New Relic, Elastic, PagerDuty, Slack. Webhook configuration for each platform. Event types: budget, injection, trust, chain, audit. Prometheus metrics endpoint. Grafana dashboard examples. OpenTelemetry traces. CloudWatch and Stackdriver integration. Alerting rules. Webhook HMAC signature verification.

---

## Section 12 — Orchestration and Extended Frameworks

*Two chapters covering workflow orchestration platforms and extended LLM/memory framework integrations.*

### [66 — Orchestration and Workflow Integrations](66-orchestration-integrations.md)
Integration with workflow orchestration platforms: OpenClaw (autonomous agent runtime), Dify (visual LLM app builder), n8n (business automation), Temporal (durable execution), Apache Airflow (data pipelines). Native DAG orchestrator (`orchestrator.rs`). Hybrid orchestration patterns where external tools handle business logic and Connector provides governance layer. Architecture diagrams, adapter code, and comparison matrix.

### [67 — LLM Frameworks and Memory Systems](67-llm-frameworks-memory.md)
Extended framework coverage: MEM0 (user-specific memory), Zep (conversation memory), LangGraph (stateful workflows), Vercel AI SDK (TypeScript web apps), AutoGen (multi-agent conversations). Vector database integrations: Weaviate, Pinecone, Chroma. Memory system comparison matrix. Migration guides from pure frameworks to governed Connector-backed implementations. Best practices for combining external memory with Connector's 9-ring enforcement.

---

## Section 13 — DevGuard and Real Execution Control

*Four chapters on DevGuard for coding agent governance, building execution workflows, and real-world system control beyond recommendations.*

### [68 — DevGuard Overview](68-devguard-overview.md)
DevGuard plugin architecture for governing coding agents (Claude Code, Cursor, Windsurf, Kiro). FS Guard for file visibility rules, Exec Guard for command safety, Secret Broker for credential protection. Session management, CLI commands (`connectorctl guard claude`), policy YAML structure. Real-world CI/CD use case. DevGuard is an **institution on the OS**, not the OS — the same world cage covers every agent; recipe in [World cage](WORLD_CAGE_AND_BROWSER.md).

### [69 — DevGuard Workflows](69-devguard-workflows.md)
Building execution workflows on DevGuard: safe dependency updates, automated refactoring, security audit and fix, documentation sync, CI/CD integration. Multi-stage approval pipelines. Workflow execution API. Best practices for progressive approval and rollback strategy.

### [70 — Real Execution Control](70-real-execution-control.md)
Moving from AI advice to AI action. Execution modes (advisory, semi-autonomous, autonomous). Execution bridges (SSH, API, K8s, Database). Safety mechanisms (dry run, two-phase commit, rollback, circuit breaker). Human-in-the-loop for critical actions. Real execution examples for server maintenance, database operations, Kubernetes operations.

### [71 — Execution Use Cases](71-execution-use-cases.md)
Production use cases: self-healing infrastructure, incident response automation, cost optimization, database maintenance, certificate management. Real-world examples with workflow definitions for infrastructure remediation and automated response.

---

## Section 14 — Real Tools Control

*Four chapters covering specific tool integrations for security, operating systems, healthcare, and industrial control systems.*

### [72 — Cyber Navigation and Security Tools](72-cyber-navigation-tools.md)
Security tool integration with governance: Nmap for network scanning, Nessus/OpenVAS for vulnerability scanning, Metasploit for penetration testing (strictly controlled), SIEM integration (Splunk/Elastic/Wazuh), network traffic analysis (Wireshark), forensics tools (Volatility). Security governance model, compliance scanning, incident response tools. Tool capability matrix.

### [73 — OS and Linux Tools](73-os-linux-tools.md)
Operating system control through Connector: process management, file system operations, service management (systemd), package management (apt/yum/pip/npm), network configuration, disk/storage management, user/permission management, monitoring and metrics. Command safety matrix. Best practices for least privilege and dry-run testing.

### [74 — HMS Healthcare Systems](74-hms-control-systems.md)
Healthcare Management System integration: HL7 v2.x and FHIR R4 handling, EHR integration (Epic), medical device integration (HL7 FHIR), clinical decision support, lab and radiology systems. Patient privacy controls, minimum necessary enforcement, consent management. HIPAA audit trail, emergency override (break-glass access), compliance reporting.

### [75 — Power Grid and Industrial Control](75-powergrid-industrial-control.md)
Critical infrastructure control: safety-first governance model (recommendation only, never autonomous control), SCADA integration (DNP3, Modbus, IEC 61850), power grid management (load forecasting, fault prediction), energy management system (EMS), industrial IoT, predictive maintenance. ICS cybersecurity, OT/IT gateway security.

---

## File List

```
docs/
├── index.md                                    ← This file
│
├── 01-quickstart.md
├── 02-product-overview.md
├── 03-yaml-configs.md
├── 04-python-sdk.md
├── 05-ccl-contracts.md
│
├── 06-workflow-library.md
├── 07-workflows-governance-compliance.md
├── 08-workflows-data-privacy.md
├── 09-workflows-devops-execution.md
├── 10-workflows-multiagent.md
│
├── 11-architecture-overview.md
├── 12-ring-1-identity-boot.md
├── 13-ring-2-network-gateway.md
├── 14-ring-3-firewall-guard.md
├── 15-ring-4-memory-kernel.md
├── 16-ring-5-policy-governance.md
├── 17-ring-6-reasoning-llm.md
├── 18-ring-7-tool-execution.md
├── WORLD_CAGE_AND_BROWSER.md               ← Landlock pores, vendor cut, browser world
├── BRAND_AND_ASSETS.md                     ← knot lockup, diagram map, concept-UI honesty
├── 19-ring-8-9-audit-surface.md
│
├── 20-theory-cid-dag-cbor.md
├── 21-theory-cryptographic-proofs.md
├── 22-theory-cognitive-substrate.md
├── 23-theory-formal-verification.md
│
├── 24-infra-internal.md
├── 25-infra-external.md
│
├── 26-api-overview.md
├── 27-api-agents.md
├── 28-api-memory.md
├── 29-api-firewall.md
├── 30-api-governance.md
├── 31-api-audit.md
├── 32-connectorctl.md
│
├── 33-tutorial-first-agent.md
├── 34-tutorial-memory-patterns.md
├── 35-tutorial-firewall-rules.md
├── 36-tutorial-ccl-workflows.md
├── 37-tutorial-audit-proof.md
├── 38-tutorial-multiagent.md
├── 39-tutorial-hitl.md
├── 40-tutorial-compliance.md
│
├── 41-builder-overview.md
├── 42-builder-tool-bridge.md
├── 43-builder-memory-adapters.md
├── 44-builder-firewall-layers.md
├── 45-builder-ccl-extensions.md
├── 46-builder-rag-retrieval.md
├── 47-builder-real-execution-control.md
├── 48-builder-surface-engine.md
├── 49-builder-plugin-system.md
├── agos/plugin-authoring.md
├── agos/abi-versioning.md
├── agos/workflow-builder-contract.md
├── 50-builder-production-guide.md
│
├── 51-cls-system.md
├── 52-glue-developer-surface.md
├── 53-global-agent-distribution.md
├── 54-agent-dns-discovery.md
├── 55-edge-agent-deployment.md
│
├── 56-namespace-storage.md
├── 57-knowledge-system.md
├── 58-compliance-framework.md
├── 59-chains-overview.md
├── 60-chains-audit-memory-dehall.md
├── 61-chains-compliance-governance-execution.md
├── 62-chains-trust-isolation-proof.md
│
├── 63-hosting-deployment.md
├── 64-llm-tool-integrations.md
├── 65-observability-integrations.md
│
├── 66-orchestration-integrations.md
├── 67-llm-frameworks-memory.md
│
├── 68-devguard-overview.md
├── 69-devguard-workflows.md
├── 70-real-execution-control.md
├── 71-execution-use-cases.md
│
├── 72-cyber-navigation-tools.md
├── 73-os-linux-tools.md
├── 74-hms-control-systems.md
└── 75-powergrid-industrial-control.md
```

---

## Section 9 — AgentLoop Plugin

*AgentLoop is Cloudflare for the agentic web — the infrastructure layer for AI agent routing, discovery, policy enforcement, and observability. Three documents: a full operator guide, competitive moat analysis, and live build status.*

### [87 — AgentLoop Guide](87-agentloop-guide.md)
What AgentLoop is and why it exists. The Cloudflare analogy explained. Full walkthrough of all four layers: Agent DNS (the `agent://` address space, FQAN format, AgentCard, version routing policies), Agent Mesh (circuit breakers, HMAC receipt chaining, policy-at-every-hop, weighted routing), Agent Workers (all six worker types, MCP manifests, auto-DNS registration), and the full Observability layer (Design → Ship → Debug → Optimize). Complete API reference for all 47 endpoints. Environment variables, Prometheus metrics reference, and pricing tiers.

### [88 — AgentLoop Market Position & Moat](88-agentloop-moat.md)
Use cases with concrete, named outcomes for five buyer personas: Platform/Infra teams, ML/AI teams, Security/Compliance teams, Product teams, and Enterprise architects. Full competitive matrix against LangSmith, Istio/Envoy, Cloudflare Workers, and AWS App Mesh — with a specific explanation of why each falls short. The three structural moats: kernel moat (ConnectorOS), network moat (FQAN lock-in), and data moat (compounding network effects). Market timing analysis and investor positioning.

### [89 — AgentLoop Build Status](89-agentloop-status.md)
Current implementation status for every module, infrastructure file, enterprise hardening feature, and database table. Complete API endpoint count (47). All 13 Prometheus metrics. Pending Phase 2 items (mTLS, UCAN, tunnel WebSocket handler, Grafana dashboard). Local development instructions. Current `cargo check` output.

---

*78 documents. Complete library from quickstart to critical infrastructure control — including the AgentLoop agent mesh platform.*

# Connector 7+1 agentic infrastructure

**Status:** Product architecture and integration target. The seven existing backends have code, deployment gates, and operational evidence paths. The `+1` agentgateway traffic plane is a researched target and is **not integrated in this tree yet**. See [CURRENT_STATE.md](CURRENT_STATE.md) for what runs today. The operator workspace over those stores is [UNIVERSAL_AGENT_WORKSPACE_ARCHITECTURE.md](UNIVERSAL_AGENT_WORKSPACE_ARCHITECTURE.md).

Connector is not another model framework. It is the government between intelligence and consequence:

```text
Intelligence
  → Identity
  → Authority
  → Context and memory
  → PATE admission
  → Runtime enforcement
  → External effect
  → Receipt
  → Memory consequence
  → Forensic reconstruction
```

The eight external projects and standards below supply proven infrastructure. Connector supplies the identity continuity, authority, one admission decision, bounded agency, consequence tracking, human control, and reconstruction that make those projects one governed product.

No backend mints Connector Allow. **PATE is the only admission authority.**

---

## The product in one picture

```text
Existing agents                         Connector-built agents
Cursor / Claude Code / Codex            LLM + purpose + work surface
Enterprise A2A agents                   Character + knowledge + memory
SaaS / MCP / API clients                Workflow + state
          │                                      │
          └──────────────┬───────────────────────┘
                         ▼
             +1  agentgateway traffic plane
             LLM · MCP · A2A · HTTP · gRPC
                         │
                         ▼
        Connector identity · contract · grant · PATE
             spend · HITL · generation · cease
                         │
        ┌────────────────┼────────────────┐
        ▼                ▼                ▼
   OpenShell/OPA    Firecracker       External tools
   policy boundary   MicroCell         SaaS · APIs · agents
        │                │                │
        └────────────────┼────────────────┘
                         ▼
       OpenTelemetry · receipts · memory · explain
                         │
          SPIRE workload identity · cosign supply chain
                         │
                Keycloak operator identity
```

Operators use Connector. They do not administer these projects individually.

---

## The 7+1 external pillars

| Pillar | Industry project or standard | What it brings | Connector’s responsibility | Current truth |
| --- | --- | --- | --- | --- |
| 1 | Keycloak and OIDC/OAuth/JWT/SCIM | Human login, SSO, federation, roles, groups, token lifecycle, enterprise identity | Verify the operator and bind the verified subject to an action without treating it as the agent or as authority | **PARTIAL/HAVE.** OIDC and JWKS verification exist. A real verified callback is deployment evidence. |
| 2 | SPIFFE/SPIRE | Short-lived, attested workload identity and mTLS-ready SVIDs | Fetch the SVID from SPIRE, keep workload identity separate from operator and intelligence identity, and bind it into evidence | **PARTIAL.** Real X.509 fetch exists. Connector does not issue SVIDs. |
| 3 | NVIDIA OpenShell | Agent-oriented sandbox and execution boundary | Compile the Connector contract into an OpenShell projection, push policy, bind a runtime handle, and record enforcement outcome | **PARTIAL.** Real CLI integration and stored policy-push evidence exist. Missing OpenShell is `not_installed`. |
| 4 | OPA/Rego inside OpenShell | Network and L7 policy enforcement at the runtime boundary | Keep OPA inside OpenShell, interpret a real `denied by policy` result, and let deny win after PATE Proceed | **PARTIAL.** Connector deliberately does not run a second `opa eval`. |
| 5 | Firecracker and jailer | Hardware-isolated microVM execution with a small attack surface | Select the MicroCell posture, issue an execution ticket, control lifecycle through microd, and pause it on Cease | **PARTIAL.** KVM and create/start/pause/destroy evidence paths exist on Linux. |
| 6 | OpenTelemetry and W3C Trace Context | Vendor-neutral traces, metrics, logs, propagation, and OTLP export | Join transport/runtime traces to the Connector task and consequence without inventing evidence | **PARTIAL.** Export acceptance can become deployment evidence. Some joins remain agent-latest rather than receipt-keyed. |
| 7 | Sigstore cosign | Supply-chain artifact and blob verification | Verify pinned software and artifacts, record the exact result, and keep artifact verification separate from Connector’s Ed25519 effect signature | **PARTIAL.** Real `cosign verify-blob` integration exists. Verification is not a certification. |
| +1 | Linux Foundation agentgateway | Unified data plane for LLM, MCP, A2A, HTTP, and gRPC traffic; TLS, OAuth/JWT, federation, routing, rate limits, retries, and telemetry | Use agentgateway for traffic, call Connector for fail-closed admission, and complete the same task after the observed response | **TARGET.** Not installed, supervised, or included in the current 7/7 verdict. |

The first seven remain the production enforcement and evidence foundation. Agentgateway adds the missing interoperable agentic traffic plane; it does not replace any of them.

---

## What the `+1` brings to the software

[agentgateway](https://github.com/agentgateway/agentgateway) is an Apache-2.0 Linux Foundation Agentic AI Foundation project. It gives Connector one standards-aware front door instead of separate custom gateways for every model, tool, agent, and API.

### One ingress and egress plane

It can front:

- OpenAI-compatible model clients;
- Anthropic-style model clients;
- MCP clients and federated MCP servers;
- A2A agents and task traffic;
- ordinary REST APIs;
- gRPC services;
- local stdio MCP servers behind a controlled process boundary.

This makes Connector usable by coding agents, chatbots, custom applications, enterprise agent platforms, SaaS automation, data tools, and remote agents without teaching each system a private Connector protocol.

### Protocol-aware enforcement

Agentgateway understands MCP methods and A2A traffic rather than seeing only opaque HTTP bytes. Connector can therefore receive a normalized request such as:

```text
agent_pid
operator identity
workload identity
protocol and version
tool or remote-agent name
effect archetype
arguments digest
target
idempotency key
trace context
```

Connector evaluates the request using the intelligence principal, contract, WorldGrant, live generation, spend ceiling, HITL state, and PATE.

```text
PATE Proceed
    → agentgateway may forward

PATE Ask / Defer / Quarantine / Block
    → agentgateway denies

Connector unavailable or request unknown
    → fail closed
```

Agentgateway may independently narrow or deny traffic. It may never upgrade a non-Proceed result.

### Federation without authority leakage

A coding agent can see a single Connector MCP endpoint while Connector federates several servers behind it. Tool discovery still is not permission:

```text
discovered
  ≠ bound to this intelligence
  ≠ granted
  ≠ admitted
  ≠ executed
```

The operator can add GitHub, ticketing, databases, observability, cloud, browser, or internal tools as separate scoped integrations. Connector presents them as one tool catalog while retaining per-tool contracts, grants, runtime requirements, and evidence.

### Enterprise traffic controls

The traffic plane can add:

- TLS and mTLS;
- JWT, API-key, and OAuth authentication;
- MCP OAuth discovery and token exchange;
- rate limits and timeouts;
- connection pooling and load balancing;
- request-size limits;
- target health;
- OpenTelemetry export;
- fail-closed external authorization;
- protocol and capability negotiation.

These are transport and enforcement controls. They are not Connector intelligence identity or PATE authority.

### A safe route for external agent ecosystems

The intended integration paths are:

| External system | Connection to Connector |
| --- | --- |
| Cursor, Claude Code, Codex, or another coding agent | Connector model endpoint plus a scoped MCP/DevGuard workspace connection |
| Custom chatbot or application | OpenAI/Anthropic-compatible brain endpoint; effects return through MCP or typed APIs |
| LangGraph, Dapr Agents, CrewAI, Semantic Kernel, ADK | A2A for agent delegation and MCP for tools |
| Microsoft Copilot Studio, ServiceNow, SAP Joule, Salesforce Agentforce, AWS or Vertex agents | A2A Agent Card/task integration plus MCP tools using enterprise OAuth |
| Internal REST or gRPC service | Typed effect adapter with contract, grant, idempotency, and PATE |
| SaaS event source | Verified webhook or CloudEvents proposal; never direct Allow |
| Browser or computer-use agent | Isolated browser session with action/origin policy and PATE on material actions |
| Industrial or robotic system | CONP adapter over a deterministic controller; no direct LLM safety authority |

Pointing an external agent only at Connector’s model endpoint creates a **model-only** connection. It does not govern that product’s independent shell, filesystem, browser, network, or tools. Those effects must also return through Connector.

---

## What Connector uniquely contributes

The external projects are strong infrastructure, but they do not become Connector by being installed together.

### 1. Intelligence identity continuity

Connector mints `IntelligencePrincipalV2` and `AgentIdentityEnvelopeV2`. The agent remains the same intelligence when its model, sandbox, machine, session, or provider changes.

```text
operator JWT subject  ≠  workload SPIFFE ID
workload SPIFFE ID    ≠  intelligence ID
intelligence ID       ≠  model name
intelligence ID       ≠  OpenShell sandbox ID
```

### 2. Explicit authority

`AgentContractV2` declares purpose and boundaries. WorldGrants declare allowed reach. Attenuation and tombstones narrow or revoke authority. Memory, confidence, experience, an A2A Agent Card, an MCP tool description, and a model request cannot create or widen a grant.

### 3. One admission government

PATE returns:

- `proceed`;
- `ask_hitl`;
- `defer_redo`;
- `quarantine`;
- `block`.

OpenShell, OPA, Firecracker, Keycloak, SPIRE, agentgateway, and the model enforce or inform. None of them mints Connector Allow.

### 4. Bounded agency

Every governed task can be bounded by:

- live generation;
- opaque context token;
- contract digest;
- WorldGrant revision;
- filesystem and network reach;
- spend, token, and iteration ceilings;
- HITL;
- expiry;
- idempotency;
- one execution attempt;
- runtime posture.

### 5. Governed cognition

Connector distinguishes:

```text
source file
  → interpreted knowledge
  → learned memory
  → selected Mempacket
  → temporary active context
```

The Agent Library makes character, instructions, knowledge, memory, state, Mempackets, and active context inspectable without pretending an uploaded file was sent to the model.

### 6. Cross-layer Cease

Cease increments the generation, voids context tokens, releases reservations, aborts held streams, seals the memory epoch, pushes runtime fan-out, and writes `CeaseReceiptV1`. A stale continuation is denied even when the model says to continue.

### 7. Reconstructible consequence

Connector joins what exists:

```text
identity
  → contract
  → grant
  → PATE task
  → runtime
  → observed effect
  → trace
  → receipt
  → memory consequence
  → cease or compensation
```

Missing links remain `absent`. A transport 2xx, provider response, gateway health check, or configured tool is not proof of an external effect.

---

## The twelve operations of a governed agent

Every critical task—credential rotation, deployment, refund, clinical order, filing, infrastructure change, or delegated robot task—reduces to the same product operations:

1. Connect a brain.
2. Define purpose and work surface.
3. Mint intelligence identity.
4. Compile the contract and runtime projection.
5. Delegate explicit authority.
6. Open a bounded generation.
7. Normalize a proposal from a model, agent, event, or human.
8. Admit, escalate, defer, quarantine, or block.
9. Enforce and execute through agentgateway and the selected runtime.
10. Observe and verify the result.
11. Commit the receipt and memory consequence.
12. Continue, Cease, quarantine, compensate, or enter a safe state.

Agentgateway strengthens operations 1, 7, 9, and 10. The seven backends strengthen identity, enforcement, isolation, telemetry, and supply chain. Connector owns the complete lifecycle.

---

## What an operator gets

The operator sees one Connector product:

### SETUP

- connect an existing agent or build a new agent;
- link an LLM brain;
- choose a workspace, sandbox, MicroCell, remote tool, API, or agent;
- authenticate using enterprise identity;
- probe and register integrations;
- scope contracts, grants, spend, network, filesystem, and HITL;
- run a no-effect test before enabling effects;
- see all seven backend evidence rows and the separate agentgateway integration-plane row.

### RUN

- talk to the governed intelligence;
- submit a task;
- see whether it is configured, admitted, waiting for a person, executed, reconstructed, or ceased;
- use coding agents, SaaS tools, databases, APIs, browsers, and remote agents through one bounded integration plane.

### WATCH

- inspect model, MCP, A2A, API, runtime, spend, and effect traffic;
- distinguish transport success from observed consequence;
- inspect active context and Mempacket composition;
- follow a receipt-keyed chain when one exists;
- see absent evidence honestly.

### FIX

- approve or deny a digest-bound action;
- understand the agent, tool, target, spend, expiry, and consequence;
- resolve failed integrations;
- quarantine or Cease;
- recover without silently replaying a non-idempotent effect.

### Agent Library

- manage character, instructions, knowledge sources, collections, memory, state, and context;
- inspect selected and rejected memory when the server recorded the reason;
- see how much knowledge is stored versus activated for the live generation.

The operator never needs to run OpenShell, OPA, SPIRE, Firecracker, OTel, cosign, Keycloak, or agentgateway directly.

---

## What “complete agentic infrastructure” means here

It means Connector can provide one supported path for:

- replaceable model brains;
- existing external agents;
- Connector-built agents;
- tools and data through MCP;
- remote agents through A2A;
- typed REST and gRPC effects;
- coding workspaces;
- durable knowledge and memory;
- runtime state and checkpoints;
- event and webhook proposals;
- human approval;
- spend and iteration limits;
- sandbox and MicroVM enforcement;
- workload and operator identity;
- artifact verification;
- traces and receipts;
- Cease, quarantine, and recovery;
- forensic reconstruction.

It does **not** mean every route is already mediated, every model answer is correct, every deployment is secure, or the product is certified. Connector’s defensible promise is narrower:

> For a named build, production posture, and declared effect inventory, each Connector-managed external effect attempt must either traverse the governed chain or be refused before execution.

That statement requires:

- `production_ready`: live services and operational evidence;
- `effect_mediated`: this effect produced one valid governed chain;
- `inventory_complete`: every registered effect path is mediated or structurally disabled.

Operator API mutating routes and plugin-cage mutations now satisfy `inventory_complete`: each one closes a PATE task or is refused before execution, or it is a declared non-effect. `production_ready` stays live seven-backend evidence. `effect_mediated` stays per effect. The agentgateway v1.6.0 registry index digest is pinned. Connector-side proofs run in the acceptance report. The suite has not passed, so integration stays TARGET. No UI or document should claim Connector Ready.

---

## Integration acceptance

The `+1` becomes a required production component only after:

- an exact agentgateway version and digest are pinned and verified;
- Connector installs and supervises it;
- a dead process immediately makes its row not ready;
- Connector’s policy adapter fails closed;
- MCP discovery does not admit;
- a mutating tool cannot reach its target before PATE Proceed;
- HITL Ask appears in FIX and target invocation remains zero;
- approval produces one external mutation, one task completion, one spend settlement, and one trace join;
- gateway retries cannot duplicate a non-idempotent mutation;
- A2A discovery, authentication, task, stream, cancellation, grant, and local effect admission are verified;
- direct unregistered egress remains denied;
- Cease rejects stale traffic;
- tokens, prompts, tool secrets, and SPIRE private material are absent from normal logs;
- the operator can complete the journey without opening agentgateway’s admin UI or using a terminal.

Until then, the existing seven-backend verdict stays separate and agentgateway reports `not_installed`, `partial`, or `target`.

---

## Final product definition

```text
Connector
  = intelligence identity
  + contract and authority
  + governed context and memory
  + one PATE admission
  + bounded execution
  + human command
  + reconstructible consequence

7 backends
  = enterprise identity
  + workload identity
  + sandbox
  + runtime policy
  + hardware isolation
  + telemetry
  + supply-chain verification

+1 agentgateway
  = interoperable agentic traffic
  + model, tool, agent, API, and gRPC federation

Together
  = one self-hosted governed-agent product
```

The model reasons. The external projects provide proven infrastructure. Connector decides what may become real, limits it, stops it, and preserves the evidence of what actually happened.

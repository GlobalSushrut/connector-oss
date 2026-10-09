# 54 — Agent DNS: Discovery, Routing, and Identity

> **Status: Built and operational. Not required today.**  
> `internal_dns/`, `reputation.rs`, `agent_index.rs`, and `TopologyDiscovery` ship in the codebase today. You do not need agent DNS when you have one node and five agents. You need it when agents must find each other across a network without hardcoded addresses — the same problem the internet solved with DNS in 1983, now solved for governed AI agents.

---

## The Problem: Hardcoded Agent Addresses Do Not Scale

Today, when Agent A wants to talk to Agent B, you configure the connection explicitly: a URL, a PID, an API key. This works for small systems.

It breaks at scale for the same reason IP addresses break at scale: the world changes. Agents restart. They migrate. New specialist agents are deployed. Old ones are decommissioned. You want to route to "the nearest HIPAA-compliant medical summarizer" not to "the agent at `pid=ag_a3f7b2` on node `192.168.1.47`."

Agent DNS solves this. It is a discovery, routing, and identity system for governed agents — a name resolution system where the names carry governance semantics.

---

## Agent Identity: Stable Across Restarts and Migrations

A governed agent's identity is not its process ID or its IP address. It is derived from its governance contract and its declared capabilities.

When an agent is created, it receives:

1. **A stable `agent_pid`** — derived from the node keypair + agent name + contract CID. The PID is stable: the same agent redeployed on a new node has the same PID if it runs the same contract.

2. **A capability set** — declared in the agent manifest and verified against the CCL contract. The capabilities are not self-reported — they are derived from what the contract actually permits.

3. **A trust score** — initialized from the node's trust level and updated through verified interactions. Stored and updated in `reputation.rs`.

This stable identity means:

```
Agent "patient-qa-v2" on Cell A  ──── migrates ────►  Agent "patient-qa-v2" on Cell B
       Same PID                                              Same PID
       Same contract CID                                     Same contract CID
       Same trust score                                      Same trust score (transferred)
       Same audit thread                                     Continuous audit thread
```

Other agents that were communicating with "patient-qa-v2" continue without reconfiguration. The address changed. The identity did not.

---

## The Agent Index

`agent_index.rs` is the local directory that every Connector node maintains — a fast lookup table mapping agent identities to their current location, capabilities, and status:

```
agent_pid: ag_a3f7b2c8d9e1
├── name: patient-qa-agent
├── contract_cid: cls1-sha256-d4e8f1a3b2
├── cell: cell-us-east-01
├── capabilities: [medical-nlp, hipaa-compliant, phi-namespace-read]
├── namespaces: [/p/hospital-a/patients/]
├── status: running
├── trust_score: 0.94
├── last_seen: 2026-04-14T00:15:32Z
└── governance_tags: [hipaa, minimum-necessary, audit-required]
```

The index is synchronized across the network via the `TopologyDiscovery` system. Each cell maintains a full or partial view of the network's agents depending on its role (full view for coordinator cells, namespace-scoped view for specialist cells).

---

## Discovery: Finding the Right Agent

The agent DNS query is not "give me the agent at this address." It is "give me an agent that satisfies these governance requirements."

### Discovery Query Structure

```rust
pub struct AgentDiscoveryQuery {
    // What the agent must be able to do
    pub required_capabilities: Vec<String>,
    
    // What governance tags the agent must carry
    pub required_governance_tags: Vec<String>,
    
    // What namespace the agent must have access to
    pub required_namespace: Option<String>,
    
    // What contract the agent must be running
    pub required_contract_cid: Option<Cid>,
    
    // Minimum acceptable trust score
    pub min_trust_score: f32,
    
    // Routing preference
    pub routing_preference: RoutingPreference,
}

pub enum RoutingPreference {
    Nearest,          // Lowest latency
    MostTrusted,      // Highest trust score
    LeastLoaded,      // Lowest current workload
    SameCell,         // Prefer same cell as caller
    RequireCell(CellId), // Must be specific cell (for data residency)
}
```

### Discovery Response

```rust
pub struct AgentDiscoveryResult {
    pub agent_pid: String,
    pub cell: CellId,
    pub latency_estimate_ms: f64,
    pub trust_score: f32,
    pub contract_cid: Cid,
    pub capabilities_matched: Vec<String>,
    pub governance_verified: bool,  // Connector verified, not self-reported
}
```

`governance_verified: true` means Connector has cryptographically verified that this agent is actually running the claimed contract, not just that it reported doing so.

---

## Routing: Trust-Based, Not Address-Based

Traditional routing routes by address. Agent DNS routes by trust.

When Agent A receives a discovery result for Agent B, it does not simply connect. The routing layer applies governance rules:

```
Agent A's contract says:
  "May delegate to agents with trust_score >= 0.80
   and governance_tag = hipaa-compliant
   and contract_cid in APPROVED_CONTRACTS"
```

If Agent B's discovered properties satisfy these rules, the connection is permitted and governed. If not, it is refused — and the refusal is journaled.

This means that a compromised or misconfigured agent cannot receive delegated requests from governed agents, even if it knows the right address. Routing is governed, not just authorized.

### The CNP Route Handle

```rust
// Agent A discovers and connects to the best matching specialist
let route = glue.cnp_route(CnpRouteContract {
    required_capabilities: vec!["medical-nlp", "hipaa-compliant"],
    required_governance_tags: vec!["hipaa"],
    min_trust_score: 0.80,
    routing_preference: RoutingPreference::Nearest,
})?;

// The route is governed — every message through it is audited
let response = route.send(GovernedMessage {
    content: query,
    audit_thread: current_thread,
    max_response_tokens: 500,
}).await?;
```

The `CnpRouteContract` is itself governed by the caller's CCL contract. An agent cannot create a route to another agent if its own contract does not declare that delegation capability.

---

## Reputation: Trust Scores That Update Through Interaction

`reputation.rs` maintains a trust score for each agent in the network. The score is not static — it updates based on verified behavior:

**Trust increases when:**
- An agent's responses are grounded (verified by `grounding.rs`)
- An agent's claims are verified against its audit trail
- An agent correctly handles HITL escalations
- An agent's decisions consistently match its declared governance contract

**Trust decreases when:**
- An agent produces ungrounded outputs
- An agent's audit trail has gaps or anomalies
- An agent's firewall detects behavioral drift
- An agent fails to escalate when its confidence threshold requires it

Trust scores are shared across the network. When Cell A updates an agent's trust score, that update propagates to all cells that route requests to that agent. A malfunctioning agent's trust score drops across the entire network — requests are rerouted to better agents automatically.

---

## The Future: Agent DNS as Internet Infrastructure for AI

Imagine a world where:

- A hospital says: "I need a HIPAA-compliant summarizer with trust score ≥ 0.90 and contract `cls1-sha256-a3f7b2`"
- The agent network resolves this query the way DNS resolves a domain name — finding the nearest, most trusted, appropriately governed agent
- The connection is governed end-to-end by CNP
- Every interaction is audited, chained, and provable

This is not science fiction. The infrastructure exists in the codebase today. What scales it to internet-level is:

1. **Public CLS registries** — so anyone can verify a contract CID
2. **Cross-organization trust federation** — so Hospital A's agents can route to Hospital B's agents under mutual governance
3. **Agent name service** — human-readable names like `cardiac-specialist.stanford-hospital.agents.connector` that resolve to governed agent PIDs

The technical primitives — stable identity, capability-based discovery, trust-scored routing, governed connections — are all built. The internet-scale deployment of those primitives is the future being built toward.

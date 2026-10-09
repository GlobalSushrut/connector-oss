# 53 — Global Agent Distribution Network

> **Status: Built and operational. Not required today.**  
> The distributed subsystem ships in `platform/server/src/distributed/` with topology management, leader election, failure detection, service registry, traffic management, and transport. Today you run one Connector node. Tomorrow you run a network of governed nodes spanning multiple regions, clouds, and trust boundaries.

---

## The Fundamental Problem

A single governed AI agent running on a single Connector node is powerful. It has memory, governance, an audit trail, and cryptographic proof of every decision.

But AI systems in production are never one agent. They are networks of agents:

- A hospital system with 50 departments, each with its own agents
- A global financial firm with agents in New York, London, Singapore, and Frankfurt — each under different regulatory regimes
- A software company with a coordinator agent routing to dozens of specialist agents
- A research network with agents that need to collaborate across institutional boundaries

Each of these scenarios requires agents to be distributed across multiple Connector nodes while maintaining the governance guarantees that make Connector valuable. A distributed agent that loses its audit trail when it migrates is not a governed agent.

The Global Agent Distribution Network is the answer.

---

## The Cell Model

A **Cell** is a single Connector node participating in a distributed network. Each cell has:

- A stable identity (Ed25519 keypair, same as node identity)
- A declared set of capabilities (what agent types it can run, what memory namespaces it holds)
- A trust level (how much other cells trust its attestations)
- A health score (computed from recent topology checks)

```
┌─────────────────────────────────────────────────────────┐
│                    Connector Network                     │
│                                                         │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐          │
│  │  Cell A  │    │  Cell B  │    │  Cell C  │          │
│  │ us-east  │◄──►│ eu-west  │◄──►│ ap-south │          │
│  │          │    │          │    │          │          │
│  │ Agents:  │    │ Agents:  │    │ Agents:  │          │
│  │ medical  │    │ legal    │    │ finance  │          │
│  │ research │    │ compliance│   │ trading  │          │
│  └──────────┘    └──────────┘    └──────────┘          │
│       │               │               │                 │
│       └───────────────┴───────────────┘                 │
│                  Shared: Topology, Audit                 │
└─────────────────────────────────────────────────────────┘
```

Cells are implemented in `platform/server/src/distributed/`:

| Module | Role |
|--------|------|
| `topology.rs` | Network map: cells, links, path health |
| `scheduler.rs` | Agent placement across cells |
| `leader_election.rs` | Distributed consensus on network state |
| `failure_detector.rs` | Health monitoring, cell failure detection |
| `service_registry.rs` | What capabilities are available where |
| `traffic_manager.rs` | Request routing across the network |
| `transport.rs` | Low-level cell-to-cell communication |

---

## Topology: The Living Map

`topology.rs` maintains a real-time map of the agent network:

```rust
pub struct TopologyLink {
    pub source_cell: CellId,
    pub target_cell: CellId,
    pub latency_ms: f64,
    pub health: LinkHealth,
    pub last_verified: Timestamp,
    pub trust_score: f32,
}

pub enum LinkHealth {
    Excellent,  // < 10ms, 0 failures
    Good,       // < 50ms, rare failures
    Fair,       // < 200ms, occasional failures
    Poor,       // > 200ms or frequent failures
    Failed,     // No response
}

pub struct NetworkPath {
    pub cells: Vec<CellId>,
    pub total_latency_ms: f64,
    pub health: PathHealth,
    pub governance_compatible: bool,  // Key field
}
```

`governance_compatible` is critical. A path between two cells is only considered usable if both cells run compatible CCL versions and the governance contracts can be honored end-to-end. A faster path that breaks governance guarantees is never preferred over a slower path that maintains them.

`TopologyDiscovery` runs continuously, probing cells and updating the map. `SharedTopologyDiscovery` provides a thread-safe view that multiple subsystems can read simultaneously.

---

## Agent Migration: Governance Travels With the Agent

When an agent migrates from Cell A to Cell B, three things must travel with it:

**1. The governance contract (by CID)**  
The contract CID is stable. Cell B fetches the contract from the CLS registry using the same CID. The agent runs under identical governance rules on the new cell. If Cell B does not have the contract, migration is refused.

**2. The memory state (by namespace)**  
The agent's memory is stored by CID-addressed packets. Migration transfers the packet set by CID list — Cell B fetches only what it doesn't already have. Deduplication is free. Memory integrity is preserved because CIDs are content-addressed.

**3. The audit thread**  
The audit journal is HMAC-chained. The chain cannot be broken. When an agent migrates, the journal records a `cell_migration` event with source cell, destination cell, contract CID, and memory snapshot CID. The chain continues unbroken on Cell B.

```
Cell A Journal:                        Cell B Journal:
seq=100 type=decision                  seq=101 type=cell_migration
seq=101 type=cell_migration  ────────► seq=102 type=decision
                                       seq=103 type=decision
```

Any auditor can reconstruct the complete, unbroken journal across both cells.

---

## Distributed Consensus: The Knot System

When cells need to agree on shared state — which cell holds authoritative memory for a namespace, which agent version is active, who is the leader for a given partition — they use the `knot` consensus system.

`knot_consensus.rs` implements a Raft-based consensus protocol adapted for governance:

- **Governed proposals**: Every consensus proposal is itself a CCL-governed action, journaled and auditable
- **Policy-gated commits**: A consensus commit can be blocked by a policy rule (e.g., "no EU-resident data can be committed to a US-located primary")
- **Proof of agreement**: Every consensus decision produces a signed proof bundle that can be verified by a third party

This means that when cells disagree — a network partition, a failed leader — the resolution process is itself governed and auditable. There is no governance gap during failure recovery.

---

## Failure Detection and Recovery

`failure_detector.rs` monitors cell health using a Phi Accrual failure detector — a probabilistic model that produces a "suspicion level" rather than a binary alive/dead judgment. This prevents false positives from brief network hiccups while rapidly detecting true failures.

When a cell is suspected failed:

1. The scheduler (`scheduler.rs`) identifies agents on the failed cell
2. Agents with `recovery_policy: migrate` are scheduled to healthy cells
3. Memory is reconstructed from CID-addressed packets (available from any cell that has seen them)
4. The contract is loaded by CID from the registry
5. The journal continues with a `cell_recovery` event
6. The agent resumes. From the agent's perspective, the failure never happened.

Agents with `recovery_policy: halt` pause until their home cell recovers. This is appropriate for agents with strong data residency requirements.

---

## Service Registry: Capability-Based Routing

`service_registry.rs` is a distributed directory of what each cell can do:

```
Cell A:
  capabilities: [medical-nlp, hipaa-compliant, phi-storage]
  namespaces: [/p/hospital-a/, /m/medical-research/]
  agents: [patient-qa, clinical-summarizer, trial-matcher]
  governance_versions: [cls1-sha256-a3f7b2, cls1-sha256-d4e8f1]

Cell B:
  capabilities: [legal-analysis, gdpr-compliant, eu-data-residency]
  namespaces: [/m/legal/, /p/cases/]
  agents: [contract-reviewer, compliance-checker]
  governance_versions: [cls1-sha256-d4e8f1, cls1-sha256-c9b2a3]
```

When a request arrives for a "HIPAA-compliant medical summarization," the service registry finds all cells with `hipaa-compliant` capability, ranks them by health and latency, and the traffic manager routes to the best option.

---

## The Future: Planet-Scale Governed AI

The Global Agent Distribution Network enables a future where:

- A pharmaceutical company's research agents run in cells across 20 countries, each cell honoring the data sovereignty laws of its jurisdiction, all sharing a common governance contract and audit trail
- A hospital network's agents migrate automatically when a data center fails, with zero loss of audit trail and zero change in governance behavior
- An AI service provider runs thousands of Connector cells as a governed AI cloud — customers deploy contracts, the network places and runs agents, compliance is provable on demand

The network does not change the governance model. Every ring of the 9-ring architecture applies to every cell. Distribution does not weaken governance — it extends it.

The governance contract travels with the agent. The audit trail follows the agent. The proof is always available. Wherever an agent runs in the network, it is the same governed agent.

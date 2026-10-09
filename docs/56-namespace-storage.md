# 56 — Namespace and Storage Architecture

> The data topology of a Connector node. Every piece of data lives in a namespace. Namespaces are not folders — they are governed address spaces with security levels, integrity controls, access policies, and HMAC-chained isolation boundaries.

---

## The Namespace Model

In a conventional system, data is stored in files and folders. Access control is bolted on top — a permissions system applied after the data model was designed.

In Connector, the namespace *is* the access control. Data cannot exist outside a namespace. A namespace declaration determines who can read it, who can write it, whether it can reach the LLM, and what happens if an agent tries to cross the boundary.

Every namespace has:

```rust
pub struct NamespaceNode {
    pub id: String,               // The path: /p/hospital-a/patients/
    pub security_level: SecurityLevel,
    pub integrity_level: IntegrityLevel,
    pub isolation_status: IsolationStatus,
    pub resources: NamespaceResources,
    pub chain_hash: String,       // Current HMAC chain head
    pub access_policy: ContainmentPolicy,
}

pub enum SecurityLevel {
    Public,         // Any agent may read
    Internal,       // Agents with namespace access may read
    Restricted,     // Named agents only
    Classified,     // Requires explicit HITL approval per access
}

pub enum IntegrityLevel {
    Mutable,        // Standard read/write
    AppendOnly,     // New writes only, no modification
    Immutable,      // Sealed — no writes after sealing
    Ephemeral,      // Auto-deleted after session ends
}
```

---

## The Four Primary Namespaces

### `/p/` — Private

**What it holds:** PHI, PII, confidential records, secrets, patient data, financial records, legal documents.

**Core rule:** Data in `/p/` NEVER reaches the LLM. Not summarized, not paraphrased, not embedded in context. The firewall (Ring 3) enforces this at the packet level — any context construction attempt that includes `/p/` content is blocked before the LLM call is made.

**Security level:** `Restricted` or `Classified`  
**Integrity level:** `AppendOnly` (health records) or `Immutable` (sealed documents)

**Sub-namespace patterns:**
```
/p/hospital-a/patients/p_001/        ← Single patient record
/p/hospital-a/patients/p_001/notes/  ← Patient notes (extra restricted)
/p/tenant-b/customer-records/        ← Tenant isolation
/p/financial/transactions/2026/      ← Time-partitioned financial data
/p/legal/cases/active/               ← Active legal matters
```

**Access:** Agents must declare `/p/` namespace access in their CCL contract. The access is logged in the isolation chain for every operation.

---

### `/m/` — Agent Memory

**What it holds:** Working memory written during agent operation. Facts the agent observed, conclusions it reached, intermediate results, session context.

**Core rule:** `/m/` is the agent's scratchpad. It is readable by the owning agent and by agents with declared delegation access. It can be included in LLM context (after passing through the firewall) but the firewall checks it for PII before inclusion.

**Security level:** `Internal`  
**Integrity level:** `Mutable` (working memory) or `AppendOnly` (session logs)

**Sub-namespace patterns:**
```
/m/agent-01/session/abc123/          ← Session-scoped memory
/m/agent-01/long-term/               ← Persistent agent memory
/m/shared/coordinator-network/       ← Shared memory for agent coalition
/m/agent-01/working/                 ← Ephemeral working context
```

**Memory packet lifecycle:**
1. Agent writes fact → CID assigned → namespace chain extended → journal entry written
2. Agent recalls → semantic search in `/m/` → firewall checks result → LLM receives

---

### `/k/` — Knowledge

**What it holds:** Curated, expert-reviewed, compiled knowledge. Pre-trained seeds, domain expertise, verified facts, procedural knowledge, normative rules.

**Core rule:** `/k/` is read-heavy and write-restricted. Only authorized agents and the knowledge pipeline can write to `/k/`. It is designed for stability — knowledge does not change frequently, but when it does, the change is tracked and audited.

**Security level:** `Internal` or `Public` (some knowledge is shared across all agents)  
**Integrity level:** `AppendOnly` (knowledge grows, old facts are versioned not overwritten)

**Sub-namespace patterns:**
```
/k/medical/cardiology/guidelines/    ← Clinical guidelines (expert-curated)
/k/medical/pharmacology/drug-db/     ← Drug interaction database
/k/legal/regulations/hipaa/          ← Regulatory text and interpretations
/k/legal/case-law/precedents/        ← Curated case law
/k/finance/models/risk-factors/      ← Financial risk models
/k/company/policies/hr/              ← Internal company policies
/k/shared/world-facts/               ← General factual knowledge
```

**Knowledge vs. Memory:** `/k/` is what the agent *knows before it starts*. `/m/` is what the agent *learns during operation*. Knowledge seeds the reasoning. Memory extends it.

---

### `/s/` — System

**What it holds:** Node configuration, policy state, active contract registry state, internal coordination data, health metrics, scheduler state.

**Core rule:** `/s/` is for the Connector node, not for agents. Agents cannot read or write `/s/` directly. Access is through the system API, not through the memory kernel.

**Security level:** `Classified`  
**Integrity level:** `Mutable` (config changes) with `AppendOnly` log

**Sub-namespace patterns:**
```
/s/config/node/                      ← Node configuration
/s/policies/active/                  ← Currently active policies
/s/contracts/registry/               ← CLS contract registry state
/s/scheduler/state/                  ← Agent placement state
/s/health/metrics/                   ← Node health data
/s/audit/keys/                       ← HMAC signing keys (HSM-backed)
```

---

## The MemPacket Schema

Every data item stored in any namespace is a `MemPacket` — a standardized envelope that the entire system understands:

```
MemPacket {
    cid:          "mem1-sha256-a3f7b2c8d9e1f5a2..."   ← Content address
    namespace:    "/p/hospital-a/patients/p_001/"       ← Governed address
    packet_type:  "clinical_note" | "observation" | "fact" | ...
    content:      <structured or text content>
    agent_pid:    "ag_d4e8f1a3b2c9"                    ← Who wrote it
    timestamp:    "2026-04-14T00:15:32Z"
    hmac:         "<HMAC of content + prev_hmac>"       ← Chain link
    prev_cid:     "mem1-sha256-prev..."                 ← Previous packet
    embedding:    [0.12, -0.34, ...]                    ← Semantic vector
    confidence:   0.94                                  ← Source confidence
    ttl:          null | "2026-12-31"                   ← Expiry (GDPR)
    regulation_tags: ["hipaa", "minimum-necessary"]
}
```

**CID computation:** `SHA-256(canonical_cbor(content + namespace + packet_type + timestamp))` → encoded as `mem1-sha256-<hex>`

**Why CBOR not JSON:** Binary encoding is smaller (important for large memory stores) and canonical (same content always produces the same CID, regardless of key ordering).

---

## Storage Tiers

Data in Connector moves through three storage tiers based on access frequency:

```
HOT  (redb)    ← In-memory + disk, fastest access
  └── Active agent working memory (/m/ current sessions)
  └── Recently accessed knowledge (/k/ hot cache)
  └── Active policy state (/s/ config)

WARM (SQLite)  ← On-disk, fast access
  └── Recent memory (last 30 days)
  └── Full knowledge base (/k/)
  └── Recent audit entries

COLD (archive) ← Compressed, slow access
  └── Historical memory
  └── Old audit journal entries
  └── Archived proof nodes
```

Tier movement is automatic based on access patterns. An operator can force a tier with `StorageTier::Hot`, `StorageTier::Warm`, `StorageTier::Cold` declarations in the agent manifest.

---

## Data Standardization

All data written to Connector, regardless of source format (JSON, plain text, CSV, FHIR, PDF extract), is normalized into `MemPacket` before storage. The normalization pipeline:

```
Raw input
    │
    ▼
[Type detection]    What kind of data is this?
    │
    ▼
[Schema mapping]    Map to MemPacket fields
    │
    ▼
[Content encoding]  CBOR encoding of content
    │
    ▼
[CID computation]   SHA-256 of CBOR → mem1-sha256-*
    │
    ▼
[Embedding]         Generate semantic vector
    │
    ▼
[Namespace check]   Validate namespace access policy
    │
    ▼
[Chain extension]   Extend namespace HMAC chain
    │
    ▼
[Storage]           Write to appropriate tier
    │
    ▼
[Journal]           Write audit entry to books
```

This pipeline is the same for every piece of data. There is no "fast path" that skips normalization, CID computation, or chain extension. Every write is a governed write.

---

## Namespace Isolation Enforcement

`namespace_isolation.rs` enforces that data cannot cross namespace boundaries without explicit authorization.

The `ContainmentPolicy` for a namespace declares:
- Which agent PIDs may read
- Which agent PIDs may write  
- Whether content may be included in LLM context
- Whether content may be exported
- What happens on an unauthorized access attempt (`Block`, `BlockAndAlert`, `BlockAndHalt`)

Every unauthorized access attempt is recorded in the isolation chain and surfaced through `connectorctl`:

```bash
$ connectorctl inspect ag_a3f7b2
  namespace_violations:  2
  last_violation:        2026-04-14T00:03:21Z
  violation_type:        read_outside_scope /p/hospital-b/
  action_taken:          blocked_and_alerted
```

The isolation chain (`IsolationChain` with `trust_chain: Vec<ChainLink>`) records every access — authorized and unauthorized — to every namespace. It is the security perimeter audit for the entire node.

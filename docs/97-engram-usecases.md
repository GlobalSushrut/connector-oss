# Engram — What It Does, What You Get, Why It Wins

> One URL. Enterprise memory that actually works.

---

## What Engram Does (Plain English)

Engram is the memory layer for AI agents. Every agent you run — support bots, coding assistants, clinical AI, autonomous pipelines — needs to remember things across sessions, across calls, across time. Engram is where that memory lives, stays clean, stays honest, and stays provable.

It is not a vector database. It is not a chat history store. It is a **governed, queryable, self-healing memory system** that knows when its own memory is going bad and fixes it before your agent does.

---

## What Engram Can Do — Full Capability Map

### 1. Persistent Agent Memory (Write + Recall)

An agent writes a fact. That fact lives forever (or until the retention policy expires it). Any future session of any agent in the same namespace can recall it.

**What you get:**
- Every fact gets a content-addressed ID (`cid: mem1-sha256-3a4b5c...`) — tamper-evident, verifiable
- Hybrid retrieval: semantic similarity + BM25 keyword + entity linking scored in parallel, fused into one result
- Facts are typed: `working` / `evidence` / `episodic` / `semantic` — agents can ask for specific kinds
- Hot/warm/cold tiering handled automatically — recent facts stay fast, old facts stay cheap
- Every write is logged to the Connector audit chain — who wrote what, when, from which agent

**The output:**
```json
{
  "cid": "mem1-sha256-3a4b5c...",
  "namespace": "acme/support-agent",
  "entropy_score": 0.12,
  "entropy_health": "good",
  "ok": true
}
```

---

### 2. Entropy Scoring and Automatic Health Monitoring

As an agent writes memory over time, facts accumulate. Engram continuously scores the health of a namespace's memory on a 0–1 scale by measuring:

| Component | What it detects |
|---|---|
| **Contradiction score** | Two facts in the same namespace directly conflict ("User prefers Python" + "User hates Python") |
| **Redundancy score** | Same fact written 12 times across 12 sessions — near-duplicates polluting the pool |
| **Stale score** | Facts that haven't been recalled in N days — probably outdated |
| **Knot score** | Memory from different reasoning threads bleeding into each other |

**What you get:**
- A live `entropy_score` returned on every write — you always know your memory health
- `entropy_health` field: `"good"` / `"warning"` / `"halted"`
- Prometheus gauge `engram_entropy_score{namespace="..."}` — dashboards, alerts, SLOs
- Auto-consolidation: Engram merges near-duplicates and expires stale facts when the threshold is crossed
- `entropy_halt`: if memory becomes critically polluted, Engram blocks new writes and demands cleanup — agents cannot corrupt themselves further

**Nobody else does this.** Mem0, Zep, LangChain Memory, every vector DB — none of them tell you when their own memory is sick.

---

### 3. Dehallucination Chain — Provable Claims

Before an LLM response goes out, pass its claims through Engram. Engram checks each claim against the memory namespace and returns a grounding score.

```
POST /api/v1/memory/ground
{
  "claims": ["User's name is Sarah", "User prefers dark mode", "User is on the Pro plan"],
  "namespace": "acme/support-agent",
  "threshold": 0.75,
  "on_fail": "block"
}
```

**What you get:**
```json
{
  "results": [
    { "claim": "User's name is Sarah",       "grounding_score": 0.94, "grounded": true,  "outcome": "passed",  "source_cids": ["mem1-..."] },
    { "claim": "User prefers dark mode",      "grounding_score": 0.88, "grounded": true,  "outcome": "passed",  "source_cids": ["mem1-..."] },
    { "claim": "User is on the Pro plan",     "grounding_score": 0.21, "grounded": false, "outcome": "blocked", "source_cids": [] }
  ],
  "all_grounded": false,
  "proof_cid": "chain3-sha256-9f8e..."
}
```

- Claims that fail grounding are **blocked** (or flagged, or escalated to human review) before they reach the user
- Every grounding decision has a `proof_cid` — cryptographic receipt in WitnessCtl, auditable forever
- Three failure modes: `block` (stops the response), `flag` (marks it, lets it through), `hitl` (human-in-the-loop queue)

**The outcome:** Your agent never confidently lies. When it doesn't know, it says so — and you have proof it said so.

---

### 4. CoT Anchor — Long-Chain-of-Thought Stability

For agents running long reasoning chains (research agents, code planners, clinical decision systems), each step of the chain can drift. Engram's CoT Anchor validates every reasoning step against memory before the chain continues.

```
Start session → Submit Step 1 claim → Ground it → Submit Step 2 → Ground it → ... → Conclude
```

**What you get:**
- Session tracks every step: `step_number`, `grounding_score`, `source_cids`, `outcome`
- If a step fails: `retry` / `block` / `flag` based on policy
- On conclude: a cryptographic proof bundle CID covering every step in the chain — written to WitnessCtl
- The agent cannot proceed on a grounding failure in `block` mode — the chain is protected

**The outcome:** A 50-step reasoning chain has 50 verified checkpoints. The final answer is provably grounded in memory from step 1 to step 50. You can audit any step later.

**No other tool on the market does per-step CoT grounding with cryptographic proof bundles.**

---

### 5. Knot Entropy Resolver

Long-running agents working on multiple concurrent tasks develop "semantic knots" — memory from reasoning thread A bleeds into thread B because they share surface-level vocabulary ("deployment" means both software release and army deployment in the same agent's memory).

Engram detects these thread collisions and scores them.

**What you get:**
- `knot_score` per namespace: 0.0 (clean) → 1.0 (severely entangled)
- `threads_detected`: how many distinct reasoning threads Engram identified
- `recommended`: "separate_threads" / "monitor" / "none"
- Phase 2: automatic thread separation — conflicting threads get isolated into sub-namespaces

**The outcome:** Agents that work on multiple domains in parallel don't corrupt each other's reasoning. A clinical agent can discuss "discharge" (patient) and "discharge" (electrical) without confusing them.

---

### 6. Cross-Agent Knowledge Sharing with Permission Gates

One agent builds domain knowledge. Other agents should be able to read it — but with control.

```yaml
knowledge_sharing:
  - source_url: engram://key@host/acme/legal-agent
    target: acme/*
    path: /k/acme/legal-summaries/
    permission: read_only
```

**What you get:**
- Agent B can recall from Agent A's knowledge namespace — but only what A explicitly shared
- UCAN capability delegation: the permission is cryptographic, not a database flag — revocation is instant and provable
- Wildcard targets (`acme/*`) — share with all agents in an org in one line
- Every cross-agent read is logged in the audit chain with source and destination
- `read_only` vs `read_write` — write access is explicitly granted, never implied

**The outcome:** Your legal AI builds a corpus of case summaries. Your support AI, your compliance AI, and your onboarding AI all read from that corpus — but none can modify it, and you can revoke access in one command.

---

### 7. Engram Query Language (EQL) — The SQL of Agent Memory

Agents and operators can query memory with structured semantics, not just "what's similar to this text."

```sql
-- All contradictions in the last 7 days
SELECT * FROM memory
WHERE namespace = 'acme/support-agent'
  AND contradiction_score > 0.8
  AND created_at > NOW() - INTERVAL '7 days'
ORDER BY contradiction_score DESC

-- All evidence-type memories about billing
SELECT * FROM memory
WHERE namespace = 'acme/support-agent'
  AND memory_type = 'evidence'
  AND content MATCHES 'billing OR payment OR invoice'
LIMIT 10
```

**What you get:**
- Structured memory queries — filter by type, tag, contradiction score, date range, entropy threshold
- Composable: combine semantic search with structured filters in one query
- Returns verifiable CIDs for every result — the output of a query is itself auditable

**The outcome:** Operators can debug agent memory like a database. "Show me everything this agent believes about this customer" is a one-line query.

---

### 8. Namespace Isolation — Multi-Tenant Enterprise Memory

Every team, agent, or customer gets a fully isolated memory namespace. Isolation is not just a database row filter — it is enforced at the Connector kernel with MAC (Mandatory Access Control) and HMAC chains.

- Agent A **cannot** read namespace B unless explicitly granted via knowledge share
- HIPAA namespaces (`hipaa: true`) add PHI firewall — personal health information never reaches an LLM
- Per-namespace retention: `90d` for support agents, `7yr` for clinical records — enforced automatically
- Every namespace has its own entropy score, its own consolidation schedule

**The outcome:** A healthcare company can run their clinical AI and their billing AI in the same Engram instance with zero cross-contamination, full HIPAA compliance, and separate 7-year retention for clinical data.

---

### 9. CISO-Grade Audit Trail

Every memory operation — write, recall, ground, share, consolidate — produces an immutable audit record in WitnessCtl (Connector's tamper-evident receipt store).

**What you get:**
- CID-addressed audit entries: `audit_cid: "journal-sha256-..."`
- Every entry is causally linked to the previous (HMAC chain) — you cannot delete the middle of the chain
- CoT proof bundles: a complete proof of every grounding decision in a reasoning session, signed and stored
- Operator-facing: `GET /api/v1/cot/session/:id` returns the full step history with source CIDs
- SOC 2 / HIPAA ready out of the box

**The outcome:** When the compliance team asks "what did the AI know when it made this decision?" — you produce a cryptographic proof in seconds.

---

## Concrete Use Cases

### Support Agent (SaaS Company)
**Problem:** Support AI forgets that the user already explained their setup three tickets ago. Asks again. User is frustrated.

**With Engram:**
- Agent writes `episodic` memory after each ticket resolution
- Next ticket: Engram recalls "User is on Enterprise plan, uses SSO, has reported this issue twice before"
- Agent starts with full context — no re-explaining
- Entropy sweep catches "User on Free plan" (stale, from 2 years ago) and expires it before it misleads the agent

**Output:** Support deflection rate up, re-explanation rate → 0, per-user context lasts years

---

### Clinical AI (Healthcare)
**Problem:** Clinical AI hallucinates a drug dosage that was never in the patient record.

**With Engram:**
- Every clinical fact is tagged `evidence` type and stored with the source document CID
- Before any response involving medication: `POST /api/v1/memory/ground` checks every claim
- "Patient takes 10mg metformin" → grounding score 0.94 (found in admission note, CID: `mem1-...`) → passed
- "Patient has no known allergies" → grounding score 0.18 (not in record) → blocked, HITL queue
- PHI namespace firewall: raw clinical text never leaves the Connector `/p/` namespace into LLM context

**Output:** Zero hallucinated clinical facts in patient-facing responses. Every claim traceable to a source document. HIPAA audit trail for every session.

---

### Code Planning Agent (Developer Tools)
**Problem:** A 40-step code planning agent drifts by step 25. It "forgets" that the user said no microservices and recommends Kafka.

**With Engram:**
- CoT Anchor session started at step 0 with threshold 0.80
- Step 3: agent wrote `"User preference: monolith, no microservices"` to `working` memory
- Step 25: claim "recommend Kafka message broker" → grounding score 0.12 → fails → retried
- Agent rewrites step 25 with monolith-consistent approach → grounding score 0.91 → passed
- Full 40-step proof bundle written to WitnessCtl at conclude

**Output:** The plan is internally consistent. The user's constraints are enforced at every step, not just the first. The proof bundle is the audit trail if the agent is questioned.

---

### Multi-Agent Research Platform (Enterprise AI)
**Problem:** 8 specialist agents (legal, financial, technical, competitive) all write to the same memory store. After 3 months their memories are entangled — financial "interest rate" bleeding into technical "interest (curiosity)."

**With Engram:**
- Each specialist agent has its own namespace: `acme/legal-agent`, `acme/financial-agent`, etc.
- Knowledge sharing gates: `acme/legal-agent` shares `/k/acme/legal-summaries/` read-only with all others
- Knot resolver detects cross-namespace pollution weekly and flags semantic collisions
- EQL query: `SELECT * FROM memory WHERE knot_score > 0.7` — operators see exactly where entanglement is

**Output:** 8 agents sharing knowledge without polluting each other. Domain integrity maintained at scale. Operators have full visibility into which memories are entangled.

---

### Autonomous Task Agent (Operator / Platform Engineer)
**Problem:** An autonomous agent runs 24/7 and after 6 months has 50,000 memory facts. Nobody knows which are current, which are contradicted, which are stale. The agent starts giving inconsistent answers.

**With Engram:**
- Entropy sweep runs every 5 minutes, updating the score
- At score 0.72 (above `entropy_alert: 0.7`): Prometheus fires an alert, Slack message hits the on-call engineer
- `engram consolidate --namespace acme/task-agent` — Engram merges near-duplicates, expires stale facts, records the consolidation in the audit trail
- Before and after entropy scores recorded: `before: 0.72 → after: 0.31`
- If nobody acts and score hits 0.95: writes are halted automatically — the agent can still read, but can't pollute further until cleaned up

**Output:** Agent memory stays healthy indefinitely. Operators get early warning, not post-incident cleanup. Memory entropy is an SLO, not a mystery.

---

## Why Use Engram Instead of Competitors

### vs Mem0

| | Mem0 | Engram |
|---|---|---|
| Memory model | ADD-only — nothing overwritten, facts pile up | Governed lifecycle: write → score → consolidate → expire |
| Memory health | No concept of entropy or health | Entropy score on every write, auto-consolidation |
| Hallucination prevention | None — LLM can ignore context | Dehallucination chain blocks ungrounded claims |
| Long-chain stability | None | CoT Anchor: per-step grounding with rollback |
| Language support | Python only | Any language via HTTP — no SDK required |
| Multi-tenant isolation | None | Namespace MAC enforcement, HMAC chains |
| Audit trail | None | Cryptographic proof per operation, HIPAA-ready |
| Knot entropy | Not defined | Phase 2: thread collision detection + resolution |

**Mem0 is a good prototype tool. Engram is what you need in production.**

---

### vs Zep

Zep stores conversation history with entity extraction. It is good at "what did this user say in past sessions." It is not built for:

- Multi-agent isolation
- Claim grounding / dehallucination
- Entropy management across long agent lifetimes
- CoT stability for reasoning chains
- HIPAA compliance with PHI firewall
- Cryptographic audit trails

**Zep is a memory archive. Engram is a memory operating system.**

---

### vs Vector Databases (Pinecone, Weaviate, Chroma)

A vector database answers: *"What is most semantically similar to this vector?"*

Engram answers: *"What facts does this agent reliably know, are they still valid, are they grounded, and can I prove it?"*

These are completely different questions. A vector DB has no concept of contradiction, entropy, grounding, or audit. It stores embeddings. Engram manages knowledge.

Engram **uses** vector search as one component of hybrid recall — alongside BM25 and entity linking. A vector DB is a piece of Engram's infrastructure, not a replacement.

**You would not replace your application database with a B-tree. You would not replace Engram with a vector index.**

---

### vs LangChain Memory / LlamaIndex

LangChain's `ConversationBufferMemory` lives for one process lifetime.
`VectorStoreRetrieverMemory` requires the LangChain SDK and has no isolation, governance, or entropy management.

These are session-scoped utilities, not production memory infrastructure. They have no:
- Cross-session persistence with cryptographic identity
- Multi-tenant isolation
- Entropy health or contradiction detection
- Dehallucination chain
- SOC 2 audit trail

**LangChain memory is duct tape. Engram is infrastructure.**

---

### vs AIOS / MemOS

AIOS (research paper, experimental Rust rewrite) and MemOS (July 2025 paper) describe excellent visions for agent memory as an OS primitive.

Neither is runnable in production today. Neither has:
- A deployable binary
- A REST API
- Multi-tenant isolation at the kernel level
- An audit chain
- A migration-backed database schema

The Connector memory kernel — on which Engram is built — has been running in production Rust for over 2 years with HMAC chains, CID addressing, and contradiction detection already shipping.

**AIOS and MemOS defined the vision. Connector built it. Engram surfaces it.**

---

## The One-Line Summary for Every Buyer

| Buyer | What they tell their team |
|---|---|
| **Developer** | "Set `ENGRAM_URL`, call `.remember()` and `.recall()` — done. It handles everything else." |
| **ML Engineer** | "Our agents no longer hallucinate facts they never learned. Grounding score is in Prometheus." |
| **Platform Engineer** | "Memory entropy is an SLO now. We get alerted before the agent degrades, not after." |
| **CISO** | "Every memory operation has a cryptographic receipt. We passed the HIPAA audit in one afternoon." |
| **Healthcare CTO** | "PHI never leaves the `/p/` namespace. The clinical AI cannot hallucinate a drug it never saw in the record." |

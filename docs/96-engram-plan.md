# Engram — Plan, Strategy & Enterprise Design

> **Engram is the SQL of agent memory.**
> One URL. Paste it. Done. Enterprise-grade memory infrastructure — dehallucination chains, entropy control, long-chain-of-thought stability, cross-agent knowledge sharing — all powered by the Connector kernel. Zero infra. Zero configuration. Neon-level simplicity.

---

## 0. The Developer Experience Principle

**Engram is designed so that no developer, operator, or user ever has to think about infra.**

The entire DX is modeled after [Neon](https://neon.tech) — the serverless Postgres that reduced "set up a database" to copying one connection string. Neon's insight: the best infrastructure is invisible infrastructure. You get a URI, you paste it, everything works. That is exactly what Engram delivers for agent memory.

```
Neon model:          DATABASE_URL=postgres://user:pass@host/db
                     → instant Postgres, branching, scaling, audit

Engram model:        ENGRAM_URL=engram://cpk_live_xxx@engram.acme.com/acme/support-agent
                     → instant governed memory, entropy control,
                       dehallucination, CoT stability, audit
```

### What "Neon-level simplicity" means for Engram

| Neon | Engram |
|---|---|
| One `DATABASE_URL` | One `ENGRAM_URL` |
| Works from any language via standard driver | Works from any language via HTTP (no SDK required) |
| Branches from CLI: `neon branch create` | Namespaces from CLI: `engram ns create` |
| Connection pooling transparent | Retrieval pooling transparent |
| Scale to zero automatically | Hot/warm/cold tier managed automatically |
| Postgres-compatible: existing tools just work | OpenAI-compatible memory context: existing agents just work |
| Instant project from dashboard | Instant namespace from dashboard or `ENGRAM_URL` |

**The rule**: if a developer needs to read more than one paragraph to start using Engram, the DX has failed.

---

## 1. The Name

**Engram** — a neuroscience term for the physical/chemical trace that memory leaves in the brain. A memory trace. The substrate of what is remembered.

> "Every thought your agent makes, Engram remembers. Every claim it makes, Engram proves."

Portfolio slot:

```
Connector (kernel)
├── Identity:      AgentPassport
├── Code layer:    DevGuard
├── Runtime:       TraceTramp
├── Orchestration: Conductor
├── Lifecycle:     AgentLoop
├── Cost:          LedgerLens
├── Audit:         WitnessCtl
├── Runtime Proxy: Relay
└── Memory Store:  Engram          ← This
```

**Why "SQL of agent memory"?**

SQL became the universal interface for relational data. Every engineer knows `SELECT * FROM table WHERE condition`. Every system — regardless of language, framework, or database vendor — speaks SQL.

Engram is the universal interface for **agent memory**. Every agent — regardless of framework, language, or LLM provider — writes and reads through Engram. The memory layer becomes as standardized as `SELECT`.

---

## 2. The Problem — Why Memory Is Still Broken

### 2.1 What Exists Today (researched)

| Tool | What it is | Core failure mode |
|---|---|---|
| **Mem0** | Python agent memory. ADD-only extraction (April 2026 redesign). Multi-signal retrieval: semantic + BM25 + entity linking. 91.6 on LoCoMo, 93.4 on LongMemEval. | No governance. No multi-tenant RBAC. No dehallucination enforcement. Python only. No audit chain. Memories accumulate — no entropy control. "Nothing is overwritten" by design — creates memory pollution in long chains. |
| **LangChain Memory** | `ConversationBufferMemory`, `VectorStoreRetrieverMemory` etc. | Ephemeral. Session-scoped. Tied to LangChain SDK. No cross-agent sharing. No stability guarantees. |
| **OpenFang memory** | SQLite + pgvector per agent. Session and episodic layers. | Personal/prosumer only. No RBAC, no cross-org sharing, no compliance. |
| **AIOS memory manager** | Academic kernel module. Manages context window. | Not production. Research paper only. Not usable today. |
| **Zep** | Conversation memory with entity extraction. | Python SDK. No enterprise RBAC. No cryptographic audit. No dehallucination chain. No long-chain stability. |
| **MemOS** | Academic paper (July 2025) on memory operating system. Plaintext activation, parameter activation, external storage. | Research only. No implementation. |
| **Custom vector DB** | Pinecone, Weaviate, Qdrant, Chroma | Raw vector storage — no memory semantics, no contradiction detection, no chain stability, no agent namespace isolation. |

### 2.2 The Six Failures No One Has Solved

#### Failure 1: Memory Pollution (Entropy)

Mem0's "ADD-only" redesign is honest about the problem: memories accumulate. Over 100+ session turns, you get:
- Contradictory facts: "User prefers Python" and "User prefers TypeScript" both in store
- Stale facts: "User's budget is $5K/month" written 6 months ago, still surfacing
- Redundant facts: 15 slightly different versions of "User works at Acme Corp"

**No current tool actively manages memory entropy.** They just accumulate and hope retrieval scoring handles it.

#### Failure 2: No Dehallucination Chain

When an LLM makes a claim, current memory tools just supply the retrieved context and move on. **Nobody proves whether the LLM's claim was grounded in that context.** The LLM could ignore the memory, hallucinate anyway, and return an ungrounded claim as fact.

#### Failure 3: Long-Chain-of-Thought Instability

Multi-step reasoning chains — CoT, ReAct, Tree-of-Thought — are highly sensitive to early errors. A wrong fact at step 2 of a 15-step chain means every subsequent step is wrong. **Nobody currently stabilizes the chain by validating each intermediate claim against memory before the chain continues.**

#### Failure 4: Knot Entropy (Semantic Tangle)

In long-running agents with large memory stores, memory retrieval begins to return semantically "tangled" results — memories that are topically similar but causally unrelated. The agent conflates separate threads. This is **knot entropy**: the semantic space becomes a knot where distinct threads are no longer separable.

No tool today detects or resolves knot entropy. They rely on embedding distance alone.

#### Failure 5: No Enterprise Isolation

Every memory tool assumes a single agent or single user. In an enterprise with 200 agents across 15 teams:
- Agent A in team Finance should never read Agent B in team Healthcare's memory
- A memory write to `/p/patient-001/` should never surface in an unrelated query
- An auditor needs to prove that data isolation was maintained across all agents, all time

**No current tool provides cryptographic memory isolation with audit proof.**

#### Failure 6: No SQL-Like Interface

Memory is treated as black-box retrieval. You can't ask:
- "Give me all memories tagged `product-decision` written in the last 30 days by any agent in `team:engineering`"
- "Show me all facts that contradict each other in this agent's memory"
- "What is the grounding score distribution across all memories for agent X?"

**No current tool gives you a composable query language for agent memory.**

### 2.3 The ConnectorOS Advantage

Connector already solved most of this at the kernel level:

| Connector capability | What it solves |
|---|---|
| CID-addressed MemPackets (CBOR, SHA-256) | Content-addressed, dedup-native, DAG-structured |
| Namespace isolation with MAC enforcement | Cryptographic agent/org/team memory separation |
| HMAC-chained per-namespace memory chains | Tamper-evident write log per agent |
| Contradiction detection (`get_interference`) | Memory stability under contradictory writes |
| Dehallucination chain (Chain 3 in `chain_tree.rs`) | Claim grounding verification per LLM call |
| Hot/warm/cold storage tiers (redb → SQLite → archive) | Infinite retention with performance tiering |
| Semantic search + entity linking | Hybrid retrieval (vector + entity) |
| 4 memory types: working / evidence / episodic / semantic | Typed, structured memory |
| Causal chain references in audit entries | Provable chain-of-thought trace |
| RBAC + namespace UCAN capabilities | Per-team, per-agent memory access |
| HIPAA PHI controls (`/p/` namespace never reaches LLM) | Compliance-native memory |

**What Engram builds on top (~15% new):**
- The SQL-like query layer (`engram query` — structured memory search)
- Entropy scoring per namespace (measure and alert on memory health)
- Long-chain-of-thought validator (stabilize CoT chains using memory)
- Knot entropy resolver (semantic thread separator)
- Cross-agent knowledge sharing with permission gates
- One-command setup (`engram init`)
- Multi-language SDK wrappers with type safety

---

## 3. What Engram Is

### 3.1 The Core Idea

```
Every agent memory system today:
  Agent writes → vector DB (hope for the best)
  Agent reads  → vector search → unverified context → LLM → unverified claim

Engram:
  Agent writes → Engram
                 ├── CID-addressed (content hash = identity)
                 ├── Namespace-isolated (MAC enforced)
                 ├── Chain-extended (HMAC link appended)
                 ├── Entropy-scored (pollution level updated)
                 ├── Entity-linked (cross-memory entity graph updated)
                 └── Audit-logged (WitnessCtl entry created)

  Agent reads  → Engram
                 ├── Hybrid retrieval (vector + BM25 + entity)
                 ├── Entropy filter (stale/contradictory facts deprioritized)
                 ├── Grounding check (post-LLM claim verification)
                 ├── Stability score per fact
                 └── Auditable: every read logged with source CIDs

  LLM makes claim → Engram dehallucination chain
                    ├── Claim extracted
                    ├── Matched to memory CIDs
                    ├── Grounding score computed
                    ├── If below threshold: block / flag / HITL
                    └── Proof recorded (chain node CID in audit log)
```

### 3.2 The One-URI Model — Neon-Parity Onboarding

The entire Engram onboarding is a single environment variable. Everything else — namespacing, auth, tiering, entropy control, audit — is encoded in or inferred from that one value.

```
ENGRAM_URL=engram://cpk_live_acme1234@engram.acme.com/acme/support-agent
           └──────┘ └─────────────────┘ └─────────────────┘ └─────────────────┘
           scheme   api key             host                 namespace path
```

**That one line gives your agent:**
- Authenticated writes and reads
- Namespace isolation (MAC-enforced, HMAC-chained)
- Entropy scoring enabled automatically
- Audit log entries in WitnessCtl for every operation
- Hot/warm/cold tier managed transparently
- Dehallucination chain ready to activate

#### For the developer (zero SDK, zero config)

```bash
# Step 1: Get your URL from the ConnectorOS dashboard or CLI
export ENGRAM_URL=engram://cpk_live_acme1234@engram.acme.com/acme/support-agent

# Step 2: Write a memory — raw HTTP, any language, any framework
curl -X POST https://engram.acme.com/v1/memory \
  -H "Authorization: Bearer cpk_live_acme1234" \
  -H "X-Engram-Namespace: acme/support-agent" \
  -d '{"content": "User prefers concise Python. Dislikes boilerplate.", "type": "semantic"}'
# → {"cid": "mem1-sha256-3a4b5c...", "entropy_score": 0.12, "ok": true}

# Step 3: Recall — semantic search, hybrid retrieval, no config
curl -X POST https://engram.acme.com/v1/memory/recall \
  -H "Authorization: Bearer cpk_live_acme1234" \
  -H "X-Engram-Namespace: acme/support-agent" \
  -d '{"query": "coding language preferences", "top_k": 5}'
# → {"facts": [...], "entropy_health": "good", "sources": ["mem1-sha256-3a4b5c..."]}
```

No SDK. No config file. No Docker Compose. No vector database to provision. **Paste URL. Ship.**

#### For the developer who wants a typed SDK

```python
# Python — one import, one line
from engram import Engram
e = Engram(url=os.environ["ENGRAM_URL"])

e.remember("User prefers concise Python")          # write
facts = e.recall("coding language preferences")    # read
health = e.health()                                # entropy score
```

```typescript
// TypeScript — same pattern
import { Engram } from "@connector/engram";
const e = new Engram(process.env.ENGRAM_URL!);

await e.remember("User prefers concise Python");
const facts = await e.recall("coding language preferences");
```

```go
// Go — same pattern
e := engram.New(os.Getenv("ENGRAM_URL"))
e.Remember("User prefers concise Python")
facts, _ := e.Recall("coding language preferences", 5)
```

```rust
// Rust — same pattern
let e = engram::Client::from_env("ENGRAM_URL")?;
e.remember("User prefers concise Python").await?;
let facts = e.recall("coding language preferences", 5).await?;
```

The SDK is a thin HTTP wrapper. Every language calls the same REST API. There is no proprietary binary protocol, no gRPC ceremony, no config schema to learn.

#### For the operator (one YAML, one namespace, done)

The operator's only job is to create namespaces and hand out URLs. Everything else is automatic.

```yaml
# engram.yaml — the only config an operator ever writes
namespaces:
  - url: engram://cpk_live_acme1234@engram.acme.com/acme/support-agent
    team: support-eng
    retention: 90d
    hipaa: false

  - url: engram://cpk_live_hipaa999@engram.acme.com/acme/clinical-agent
    team: medical-ai
    retention: 7yr
    hipaa: true     # /p/ namespace — PHI never reaches LLM, enforced at kernel
```

```bash
# Apply — one command
engram apply -f engram.yaml

# That's it. Namespaces are live. Hand each team their URL.
# Nothing else to configure. No ports to open. No secrets to rotate manually.
```

#### For the user / end customer

Users interact with agents that use Engram. They never see Engram. The only visible difference:
- Agent remembers them across sessions (no re-explaining preferences)
- Agent never contradicts itself ("I told you last week I prefer Python — why are you suggesting Java now?")
- Agent says "I don't have evidence for that" instead of hallucinating

Engram is **invisible by design**. The user just notices that the agent actually works.

#### URL anatomy (full reference)

```
engram://cpk_live_acme1234@engram.acme.com/acme/support-agent?retention=90d&hipaa=false

└ scheme:    engram://        (HTTP/S under the hood, scheme is a signal to SDKs)
└ api_key:   cpk_live_acme1234
└ host:      engram.acme.com  (self-hosted or Connector Cloud)
└ namespace: acme/support-agent
└ params:    retention=90d    (optional overrides; defaults from dashboard/yaml)
             hipaa=false
```

Query parameters in the URL are optional overrides. Defaults come from `engram.yaml` or the dashboard. **The URL alone is always enough to get started.**

### 3.3 The Engram Query Language (EQL)

The SQL of agent memory:

```sql
-- Find all contradictions in an agent's memory
SELECT * FROM memory
WHERE namespace = 'acme/support-agent'
  AND contradiction_score > 0.8
ORDER BY timestamp DESC;

-- Find stale high-entropy memories
SELECT content, entropy_score, last_accessed, created_at
FROM memory
WHERE namespace = 'acme/*'
  AND entropy_score > 0.7
  AND last_accessed < NOW() - INTERVAL '30 days';

-- Find all ungrounded claims from last 7 days
SELECT claim_text, grounding_score, agent_id, timestamp
FROM dehallucination_chain
WHERE grounding_score < 0.5
  AND timestamp > NOW() - INTERVAL '7 days'
ORDER BY grounding_score ASC;

-- Cross-agent knowledge: what does team:engineering know about "deployment"?
SELECT content, source_agent, confidence, tags
FROM knowledge
WHERE team = 'engineering'
  AND semantic_match('deployment', threshold=0.85)
  AND memory_type = 'semantic'
LIMIT 20;

-- Audit: prove memory isolation was maintained
SELECT namespace, operation, agent_id, chain_hash, authorized
FROM memory_chain
WHERE namespace LIKE '/p/%'
  AND timestamp BETWEEN '2026-01-01' AND '2026-04-01'
  AND authorized = false;  -- should return 0 rows
```

EQL is a declarative query layer over the Connector memory kernel. Under the hood it compiles to Connector API calls + Postgres queries. Agents never need raw SQL — but platform engineers and compliance officers get the full power.

---

## 4. The Five Core Innovations

### 4.1 Entropy Chain — Memory Health as a First-Class Metric

Entropy score = a real-time measure of memory quality degradation per namespace.

```
Entropy contributors:
  + Contradictions between stored facts          (+0.3 per pair)
  + Semantic redundancy (near-duplicate facts)   (+0.1 per 5 similar)
  + Stale facts (not accessed in N days)         (+0.05 per stale fact)
  + Orphaned facts (no entity link, no tags)     (+0.02 per orphan)

Entropy reducers:
  - Consolidation (similar facts merged)         (-0.15 per merge)
  - Contradiction resolution (human confirms)    (-0.3 per resolved pair)
  - Evidence reinforcement (fact re-confirmed)   (-0.05 per reconfirmation)
```

When entropy exceeds the configured threshold:
- `entropy_alert`: notify platform team
- `entropy_consolidate`: auto-merge high-similarity facts (with audit)
- `entropy_halt`: block new writes until cleanup (for strict namespaces)
- `entropy_report`: generate a memory health report for the CISO

```yaml
# engram.yaml — full config (all optional; URL alone is sufficient to start)
namespaces:
  - url: engram://cpk_live_acme1234@engram.acme.com/acme/support-agent
    team: support-eng
    retention: 90d
    entropy:
      alert_threshold: 0.7    # notify platform team
      halt_threshold: 0.9     # block writes on critical namespaces
      auto_consolidate: true  # merge near-duplicates automatically
      stale_days: 30          # facts not accessed in 30d become stale
```

### 4.2 Dehallucination Chain — Provable Claims

Every LLM call that uses Engram context triggers automatic claim verification:

```
LLM response → Engram Claim Extractor
                ├── Extracts N discrete claims
                └── For each claim:
                    ├── Hybrid search in Engram (vector + BM25 + entity)
                    ├── Grounding score (0.0–1.0)
                    ├── Source CIDs (which memory packets support it)
                    └── Chain node written to audit log

If grounding_score < threshold:
  block:  Claim stripped, replaced with "No evidence found"
  flag:   Claim included with [UNVERIFIED] marker
  hitl:   Response held for human review
```

The dehallucination chain is the first cryptographic proof that your agent didn't make up its answer. Auditors can verify: "Every claim in every agent response since Jan 1 was grounded in documented evidence." That is a new category of proof.

### 4.3 Long-Chain-of-Thought Stability (CoT Anchor)

For multi-step reasoning (ReAct, Tree-of-Thought, Plan-and-Execute):

```
Standard CoT without Engram:
  Step 1: Reason → Claim A (unverified)
  Step 2: Reason using Claim A → Claim B (A was wrong, B is wrong)
  Step 3: Reason using Claims A+B → Claim C (doubly wrong)
  ...
  Step 15: Conclusion (propagated error from step 1)

Engram CoT Anchor:
  Step 1: Reason → Claim A
         ↓ Engram checks: grounding score 0.92 ✅ → proceed
  Step 2: Reason using verified Claim A → Claim B
         ↓ Engram checks: grounding score 0.34 ❌ → rollback
         ↓ Agent: "My assumption at step 2 was ungrounded. Retrying."
  Step 2b: Alternative reasoning → Claim B' → grounding score 0.88 ✅
  Step 3: Reason using verified Claims A + B' → Claim C
  ...
  Step 15: Conclusion anchored to verified facts at every step
```

CoT Anchor integration:

```python
from engram import Engram, CoTAnchor

e = Engram(namespace="acme/analysis-agent")
anchor = CoTAnchor(e, threshold=0.75, on_fail="retry")

with anchor.chain("market-analysis-2026") as cot:
    step1 = cot.step("The market grew 12% last year")     # verified or retried
    step2 = cot.step("Growth is driven by cloud adoption") # verified or retried
    step3 = cot.step(f"Given {step1} and {step2}, forecast 2027 growth") # stable
    result = cot.conclude()  # returns conclusion + full grounding proof
```

### 4.4 Knot Entropy Resolver — Untangling Semantic Threads

When a long-running agent accumulates memories across diverse topics, retrieval begins returning "tangled" results — topically similar but causally/contextually unrelated.

Example of knot: An agent working on both "deployment pipelines" and "marketing copy" has memories about "shipping" in both threads. A query about "shipping delays" returns memories about shipping software updates AND shipping marketing brochures. The agent conflates them.

Engram detects knots by:
1. **Thread tracing**: assigning a `thread_id` to each chain of reasoning (via CoT Anchor session IDs)
2. **Cross-thread pollution score**: measuring how often memories from thread A appear in thread B's retrieval
3. **Knot threshold alert**: when cross-thread pollution exceeds threshold
4. **Thread separators**: automatic re-tagging or isolation of ambiguous-namespace memories

```python
# Detect knot entropy
health = e.memory_health(namespace="acme/multi-domain-agent")
# {
#   "entropy_score": 0.65,
#   "knot_score": 0.81,         # high!
#   "threads_detected": 4,
#   "polluted_threads": 2,
#   "recommended_action": "separate_threads",
#   "specific_knots": [
#     {"thread_a": "deployment", "thread_b": "marketing", "shared_terms": ["shipping", "release"], "pollution": 0.82}
#   ]
# }
```

### 4.5 Cross-Agent Knowledge Sharing with Permission Gates

The `/k/` (knowledge) namespace is Connector's shared knowledge layer. Engram exposes it with enterprise-grade permission gates:

```yaml
# engram.yaml — knowledge sharing (append to same file, no separate config)
knowledge_sharing:
  - source_url: engram://cpk_live_legal@engram.acme.com/acme/legal-agent
    target: acme/*              # all agents in acme org
    path: /k/acme/legal-summaries/
    permission: read_only
    require_team_role: [engineer, senior, lead]

  - source_url: engram://cpk_live_research@engram.acme.com/acme/research-agent
    target: acme/analysis-agent
    path: /k/acme/market-research/
    permission: read_write
    audit: always
```

Permission gate enforcement:
- UCAN capability delegation (cryptographic, not just database flag)
- Every cross-agent read is logged to the audit chain with source and destination
- Revocation is instant: delete the capability, agent loses access immediately

---

## 5. Architecture

### 5.1 Component Map

```
┌──────────────────────────────────────────────────────────────────┐
│                        ENGRAM (plugin 9)                         │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │  Query Engine (EQL compiler)                             │    │
│  │  - parse EQL → Connector API calls + Postgres queries    │    │
│  │  - query planner, result assembler, pagination           │    │
│  └──────────────────────────────────────────────────────────┘    │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │  Memory Surface API                                      │    │
│  │  POST /v1/memory       — write with entropy update       │    │
│  │  GET  /v1/memory/recall — hybrid retrieval               │    │
│  │  POST /v1/memory/search — EQL query execution            │    │
│  │  GET  /v1/memory/health — entropy + knot scores          │    │
│  │  POST /v1/memory/ground — dehallucination check          │    │
│  └──────────────────────────────────────────────────────────┘    │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │  Entropy Engine                                          │    │
│  │  - contradiction scoring (get_interference wrapper)      │    │
│  │  - redundancy scorer (near-duplicate detection)          │    │
│  │  - stale scorer (access-time decay)                      │    │
│  │  - auto-consolidator (merge queue)                       │    │
│  │  - alert/halt/report dispatcher                          │    │
│  └──────────────────────────────────────────────────────────┘    │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │  CoT Anchor (Chain-of-Thought Stabilizer)                │    │
│  │  - step grounding validator                              │    │
│  │  - rollback/retry coordinator                            │    │
│  │  - proof bundle generator (full chain CIDs)              │    │
│  └──────────────────────────────────────────────────────────┘    │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │  Knot Resolver                                           │    │
│  │  - thread tracker (session → thread_id mapping)          │    │
│  │  - cross-thread pollution scorer                         │    │
│  │  - thread separator (re-tag + isolate)                   │    │
│  └──────────────────────────────────────────────────────────┘    │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │  Knowledge Gate                                          │    │
│  │  - cross-agent permission model                          │    │
│  │  - UCAN capability delegation                            │    │
│  │  - knowledge sharing audit                               │    │
│  └──────────────────────────────────────────────────────────┘    │
└────────────────────────────┬─────────────────────────────────────┘
                             │ HTTP only
┌────────────────────────────▼─────────────────────────────────────┐
│                      CONNECTOR (kernel)                          │
│  Memory kernel · Namespace isolation · HMAC chains               │
│  Dehallucination chain · CID store · RBAC · PHI controls         │
│  Audit log · UCAN · WitnessCtl · LedgerLens                      │
└──────────────────────────────────────────────────────────────────┘
```

### 5.2 Plugin Structure

```
plugins/engram/
├── Cargo.toml
├── migrations/
│   ├── 001_initial.sql          — engram_namespaces, engram_writes, engram_entropy
│   └── 002_cot_chains.sql       — engram_cot_sessions, engram_cot_steps
├── src/
│   ├── main.rs                  — startup, dual-port (9092 API + 9093 internal)
│   ├── types.rs                 — MemWrite, MemRecall, EQLQuery, EntropyScore, KnotReport
│   ├── error.rs                 — AppError, CISO-grade error codes
│   ├── routes.rs                — 16 API endpoints
│   ├── query.rs                 — EQL parser + compiler (to Connector API calls)
│   ├── entropy.rs               — Entropy scoring engine
│   ├── cot_anchor.rs            — CoT stabilizer (step validation + rollback)
│   ├── knot.rs                  — Knot entropy detector + resolver
│   ├── knowledge_gate.rs        — Cross-agent sharing + UCAN delegation
│   ├── dehallucination.rs       — Claim extractor + grounding checker
│   ├── url.rs                   — ENGRAM_URL parser (scheme, api_key, host, namespace, params)
│   ├── connector.rs             — ConnectorClient (memory kernel, namespace, audit)
│   └── metrics.rs               — Prometheus: entropy_score, grounding_rate, knot_score
└── .env.example
```

#### `.env.example` — what an operator actually sets

```bash
# ── The only required variable ────────────────────────────────────────────────
ENGRAM_URL=engram://cpk_live_acme1234@engram.acme.com/acme/support-agent

# ── Server (self-hosted operators only; Connector Cloud sets these) ────────────
DATABASE_URL=postgres://engram:pass@localhost:5432/engram
CONNECTOR_BASE_URL=http://connector:8080
PORT=9092

# ── Optional overrides (defaults come from dashboard / engram.yaml) ────────────
# ENGRAM_RETENTION_DAYS=90
# ENGRAM_ENTROPY_ALERT=0.7
# ENGRAM_ENTROPY_HALT=0.95
# ENGRAM_HIPAA=false
```

For **Connector Cloud** (hosted), the operator copies one URL from the dashboard. **Nothing else.**
For **self-hosted**, the operator adds `DATABASE_URL` and `CONNECTOR_BASE_URL`. **That's it.**

### 5.3 Database Schema

```sql
-- Engram-specific tables (Connector memory kernel handles the MemPackets)

engram_namespaces (
  id             UUID PRIMARY KEY,
  path           TEXT UNIQUE NOT NULL,       -- "acme/support-agent"
  team           TEXT,
  retention_days INT DEFAULT 90,
  entropy_alert  FLOAT DEFAULT 0.7,
  entropy_halt   FLOAT DEFAULT 0.95,
  hipaa          BOOLEAN DEFAULT false,
  created_at     TIMESTAMPTZ DEFAULT NOW()
)

engram_entropy_snapshots (
  id                  UUID PRIMARY KEY,
  namespace_id        UUID REFERENCES engram_namespaces,
  entropy_score       FLOAT NOT NULL,
  contradiction_count INT,
  redundancy_count    INT,
  stale_count         INT,
  knot_score          FLOAT,
  threads_detected    INT,
  snapped_at          TIMESTAMPTZ DEFAULT NOW()
)

engram_cot_sessions (
  id             UUID PRIMARY KEY,
  session_name   TEXT,
  namespace_id   UUID REFERENCES engram_namespaces,
  agent_id       TEXT,
  threshold      FLOAT DEFAULT 0.75,
  started_at     TIMESTAMPTZ DEFAULT NOW(),
  concluded_at   TIMESTAMPTZ,
  proof_cid      TEXT        -- bundle CID of full grounding proof
)

engram_cot_steps (
  id               UUID PRIMARY KEY,
  session_id       UUID REFERENCES engram_cot_sessions,
  step_number      INT,
  claim_text       TEXT NOT NULL,
  grounding_score  FLOAT,
  source_cids      JSONB,      -- array of MemPacket CIDs that grounded it
  outcome          TEXT,       -- "passed" | "failed" | "retried" | "blocked"
  retry_count      INT DEFAULT 0,
  created_at       TIMESTAMPTZ DEFAULT NOW()
)

engram_knowledge_shares (
  id             UUID PRIMARY KEY,
  source_ns      TEXT NOT NULL,
  target_pattern TEXT NOT NULL,    -- "acme/*" or specific namespace
  shared_path    TEXT NOT NULL,    -- "/k/acme/legal-summaries/"
  permission     TEXT NOT NULL,    -- "read_only" | "read_write"
  ucan_cid       TEXT,             -- UCAN capability CID
  active         BOOLEAN DEFAULT true,
  created_at     TIMESTAMPTZ DEFAULT NOW()
)
```

### 5.4 API Endpoints (16)

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/v1/namespaces` | Create namespace (engram.yaml or JSON) |
| `GET` | `/api/v1/namespaces` | List namespaces + health scores |
| `GET` | `/api/v1/namespaces/:path` | Namespace detail + live entropy |
| `PUT` | `/api/v1/namespaces/:path` | Update config (retention, thresholds) |
| `POST` | `/api/v1/memory` | Write a memory fact |
| `POST` | `/api/v1/memory/recall` | Hybrid recall (vector + BM25 + entity) |
| `POST` | `/api/v1/memory/search` | EQL query execution |
| `POST` | `/api/v1/memory/ground` | Dehallucination check for a claim set |
| `GET` | `/api/v1/memory/health/:path` | Entropy + knot score for namespace |
| `POST` | `/api/v1/memory/consolidate` | Trigger entropy consolidation |
| `POST` | `/api/v1/cot/session` | Start a CoT anchor session |
| `POST` | `/api/v1/cot/session/:id/step` | Submit a CoT step for grounding |
| `POST` | `/api/v1/cot/session/:id/conclude` | Conclude + get proof bundle |
| `GET` | `/api/v1/cot/session/:id` | Session status + step outcomes |
| `POST` | `/api/v1/knowledge/share` | Create a cross-agent knowledge share |
| `GET` | `/health` | DB + Connector kernel health |

---

## 6. What Connector Already Provides (~85% Built)

| Capability | Connector component | Engram uses it for |
|---|---|---|
| CID-addressed MemPackets | `memory_format.rs` | Every write gets a verifiable identity |
| Namespace MAC enforcement | `namespace_isolation.rs` | Cross-agent memory isolation |
| Per-namespace HMAC chains | `IsolationChain` in `chain_tree.rs` | Tamper-evident write log |
| Contradiction detection | `get_interference()` | Entropy scoring — contradiction component |
| Semantic search | Connector memory API | Hybrid recall, entity linking |
| Hot/warm/cold tiers | `redb_store.rs` | Infinite retention, performance-tiered |
| Dehallucination chain nodes | `DehallData` in `chain_tree.rs` | Claim grounding proof per CoT step |
| 4 memory types | `memory_type` field | Structured writes (working/evidence/episodic/semantic) |
| RBAC + API keys | Connector auth | Per-namespace, per-team access |
| UCAN capabilities | `/aapi/capabilities/*` | Knowledge sharing permission gates |
| PHI sanitization | `/p/` namespace firewall | HIPAA-safe memory for healthcare agents |
| Audit log (CausalRef) | `books.rs` JournalEntry | Every write/read provably logged |
| WitnessCtl | WitnessCtl plugin | Immutable receipts per memory operation |
| LedgerLens | LedgerLens plugin | Memory operation cost attribution |

**What Engram builds new (~15%):**
- `ENGRAM_URL` parser (`url.rs`) — one URI encodes auth + host + namespace + config
- EQL parser + compiler
- Entropy scoring engine (contradiction + redundancy + stale + knot)
- CoT Anchor (step-by-step grounding validator with rollback)
- Knot resolver (thread tracker + cross-thread pollution scorer)
- Knowledge Gate (cross-agent share config + UCAN delegation bridge)
- `engram.yaml` namespace config format (optional; URL alone is sufficient)
- CLI (`engram ns create`, `engram write`, `engram recall`, `engram health`, `engram query`, `engram audit`)
- SDKs: Python, TypeScript, Go, Rust — all thin HTTP wrappers, all one constructor call

---

## 7. The "How It Beats Them" Story

### vs Mem0

> **"Mem0 accumulates memories. Engram manages them."**

Mem0's April 2026 redesign is honest: ADD-only. Nothing is overwritten. Memories pile up.
- After 1000 turns: 1000 facts, unknown which are current, which contradict, which are stale
- No entropy score — you don't know if your memory is healthy or polluted
- No dehallucination chain — the LLM could ignore context and hallucinate, undetected
- Python-only — your Go service, Rust agent, TypeScript function can't use it
- No RBAC — if your enterprise has 50 agents, they're all in the same pool

Engram manages the full memory lifecycle: write → verify → score → consolidate → expire. And every step is cryptographically provable.

### vs Zep

> **"Zep stores conversations. Engram stores facts."**

Zep has entity extraction and temporal memory. Good for chatbot history.
- Not designed for multi-agent enterprise deployment
- No cross-agent knowledge sharing
- No entropy control, no CoT stability, no dehallucination chain
- No namespace isolation with cryptographic audit

### vs Vector Databases (Pinecone, Weaviate, Chroma)

> **"Vector DBs store embeddings. Engram stores grounded knowledge."**

A vector DB answers: "What is most similar to this query vector?"
Engram answers: "What facts are true, stable, grounded, and accessible to this agent right now?"

Completely different questions. Vector DB is a component inside Engram's retrieval — not a replacement.

### vs LangChain Memory

> **"LangChain memory lives for one session. Engram lives forever."**

LangChain's `ConversationBufferMemory` is cleared when the process stops.
Even `VectorStoreRetrieverMemory` requires the LangChain SDK.
No enterprise isolation, no RBAC, no entropy management, no audit.

### vs AIOS / MemOS

> **"AIOS and MemOS defined the vision. Connector already built it. Engram surfaces it."**

AIOS's memory manager module is a research proposal. MemOS is a paper (July 2025). Neither is runnable in production today.

Connector's memory kernel — HMAC chains, CID addressing, contradiction detection, dehallucination chain — has been running in production Rust for 2+ years. Engram is the enterprise-grade surface layer on top of that kernel.

---

## 8. Feature Comparison

| Feature | **Engram** | Mem0 | Zep | LangChain Mem | Vector DB |
|---|---|---|---|---|---|
| **Language-agnostic** | ✅ HTTP | Python only | Python/TS | Python only | varies |
| **Zero SDK required** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Multi-tenant RBAC** | ✅ | ❌ | ❌ | ❌ | partial |
| **Namespace isolation (crypto)** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **HMAC-chained write log** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Entropy scoring** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Contradiction detection** | ✅ | partial | partial | ❌ | ❌ |
| **Stale memory management** | ✅ | ❌ | partial | ❌ | ❌ |
| **Knot entropy resolver** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Dehallucination chain** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **CoT Anchor (step grounding)** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Long-chain stability** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **EQL query language** | ✅ | ❌ | partial | ❌ | partial |
| **Cross-agent knowledge sharing** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **UCAN capability delegation** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **HIPAA / PHI namespace** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **SOC 2 audit trail** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Cryptographic proof per claim** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Hot/warm/cold tiering** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Content-addressed (CID)** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Semantic + BM25 + entity recall** | ✅ | ✅ (Apr 2026) | partial | partial | partial |
| **Cost attribution per agent** | ✅ LedgerLens | ❌ | ❌ | ❌ | ❌ |

---

## 9. Build Order (3 Phases)

### Phase 1 — Memory Foundation (weeks 1–3)

**What ships**: Write, read, hybrid recall. Namespace init. Entropy scoring (basic).

- `ENGRAM_URL` parser (`url.rs`) — parse scheme, api_key, host, namespace, query params
- `engram.yaml` parser + namespace init (optional config; URL-first always works)
- `engram_namespaces` table + namespace CRUD endpoints
- `POST /v1/memory` — bridge to Connector memory kernel write
- `POST /v1/memory/recall` — hybrid retrieval (Connector semantic + BM25)
- Entropy scoring: contradiction + redundancy (using `get_interference`)
- `GET /v1/memory/health` — entropy score per namespace
- CLI: `engram ns create`, `engram write`, `engram recall`, `engram health`
- Python + TypeScript SDKs: `Engram(url=...).remember()`, `.recall()`

**Value**: Replace Mem0 immediately. Any agent in any language gets governed, auditable memory. One URL, done.

### Phase 2 — Stability Layer (weeks 4–6)

**What ships**: CoT Anchor. Dehallucination check. Knot resolver. Entropy consolidation.

- Dehallucination endpoint (`POST /v1/memory/ground`) — claim scoring via Connector Chain 3
- CoT Anchor sessions + step validation API
- Knot entropy scorer (thread tracker + cross-thread pollution)
- Entropy auto-consolidation (merge near-duplicates, flag stale, batch expire)
- Stale memory decay scoring + alert dispatcher
- `entropy_halt` enforcement (block writes on over-threshold namespaces)
- EQL Phase 1: SELECT + WHERE + ORDER BY (no joins yet)

**Value**: First memory system to deliver provable CoT stability and dehallucination chains.

### Phase 3 — Knowledge & Enterprise (weeks 7–9)

**What ships**: Cross-agent knowledge sharing. Full EQL. Multi-org. SDKs.

- Knowledge Gate: cross-agent permission model + UCAN delegation bridge
- `engram.yaml` knowledge sharing config
- Full EQL (joins, cross-namespace queries, aggregates)
- TypeScript SDK (`engram-ts`)
- Hot/warm/cold tier management API (force promote/demote)
- LedgerLens cost attribution per namespace/team
- Memory health dashboard (Prometheus metrics + Grafana panels)
- `engram audit` CLI — generate SOC 2 evidence from memory chain

**Value**: Enterprise-grade memory infrastructure that can be demonstrated to CISOs with cryptographic audit exports.

---

## 10. Competitive Position Summary

### What Engram replaces (per buyer)

| Buyer Pain | Tool today | Why it fails | Engram |
|---|---|---|---|
| "My agent hallucinates from its own memory" | Mem0 / LangChain | No grounding check | Dehallucination chain per call |
| "My long CoT chains drift and fail" | Nothing | No stability primitive | CoT Anchor: every step grounded |
| "My memory store is polluted after 6 months" | Mem0 | ADD-only accumulation | Entropy engine: score, alert, consolidate |
| "My agents are leaking context to each other" | Nothing | No isolation | Namespace MAC + HMAC chains |
| "I can't query our agent's knowledge" | Vector DB | No query language | EQL: SELECT from agent memory |
| "I can't prove what my agent knew when" | Nothing | No audit | WitnessCtl + HMAC chain per namespace |
| "HIPAA says I can't store PHI in agent memory" | Nothing | No controls | `/p/` namespace firewall (PHI never reaches LLM) |
| "I need cross-team knowledge sharing" | Manual copy | No permission model | Knowledge Gate + UCAN delegation |

### The moat

Engram's moat is not retrieval quality — Mem0's April 2026 multi-signal retrieval is excellent.

Engram's moat is **memory governance**. Entropy scoring, dehallucination chains, CoT stability, namespace isolation, cryptographic audit — none of these exist in any memory tool today. They exist in Connector's kernel, built over 2+ years. Reproducing them would require rebuilding the entire Connector kernel.

The secondary moat: **integration depth**. Engram's CoT Anchor feeds into WitnessCtl (audit). Its knowledge sharing uses UCAN (delegated capabilities from AgentPassport). Its cost attribution flows to LedgerLens. Relay-registered functions automatically get Engram memory injection. You cannot replicate this integration without rebuilding all of ConnectorOS.

---

## 11. Pricing

| Tier | Price | Includes |
|---|---|---|
| **Free** | $0 | 1 namespace, 10K writes/mo, 90d retention, basic entropy alerts |
| **Pro** | $49/mo | 10 namespaces, 500K writes/mo, CoT Anchor, dehallucination chain |
| **Team** | $249/mo | Unlimited namespaces, cross-agent knowledge sharing, EQL, HIPAA, entropy consolidation |
| **Enterprise** | Custom | On-prem, SOC 2 audit export, UCAN delegation, LedgerLens attribution, SLA |

**Expansion model**: land via Free (developer replaces Mem0 in 5 minutes) → Pro (team needs CoT stability) → Team (compliance needs HIPAA + audit) → Enterprise (CISO needs cryptographic proof per claim).

---

## 12. Go-To-Market

### Buyer personas

| Persona | Pain | What Engram says |
|---|---|---|
| **Developer** | Agent hallucinates from its own stale memory | "Engram knows what your agent knows. And proves it." |
| **ML Engineer** | Long CoT chains drift after step 5 | "Every step grounded. No drift. Rollback on failure." |
| **Platform Eng** | 50 agents, all sharing one messy memory pool | "Namespace isolation. One YAML. No leaks." |
| **CISO** | Can't prove what agent knew at time of decision | "Cryptographic proof per claim. Audit in 10 seconds." |
| **Healthcare CTO** | Agent memory might contain PHI exposed to wrong LLM | "/p/ namespace: PHI never reaches any LLM. Provable." |

### Wedge play

**Target**: ML engineer who built a RAG agent, shipped it to production, and now has users complaining that:
1. The agent "remembers" outdated facts (entropy problem)
2. The agent contradicts itself across sessions (no contradiction detection)
3. The agent sometimes ignores its memory and hallucinates anyway (no dehallucination chain)

Their current solution: add more context, tune embeddings, hope.

Engram's answer: `engram init --namespace my-agent`. Done.

---

## 13. Strategic Value in Connector Portfolio

Engram is the **memory substrate** for the entire portfolio:

- **Relay**: every Relay-registered function auto-gets Engram memory injection (via `engram_namespace` in `relay.yaml`)
- **Conductor**: multi-step pipelines read/write Engram; each pipeline step can validate CoT against Engram
- **AgentPassport**: each agent identity (DID) maps to its Engram namespace; identity and memory are unified
- **TraceTramp**: every Engram write generates an OTEL span; memory operations are observable
- **LedgerLens**: Engram tracks write/read counts per namespace/team → cost attribution
- **WitnessCtl**: Engram memory chains feed immutable receipts into WitnessCtl
- **DevGuard**: coding agents store code analysis results in Engram namespaces for cross-session continuity

The network effect: every new agent connected to Engram **grows the knowledge graph** for the org — because cross-agent knowledge sharing means agent A's verified research becomes available to agents B and C under UCAN-controlled gates.

---

## 14. One-Line Positioning

| Audience | One line |
|---|---|
| **Developer** | "One setup. Your agent's memory is governed, queryable, and never hallucinates from stale facts again." |
| **ML Engineer** | "CoT Anchor validates every reasoning step against memory. No more 15-step chains that drift from step 2." |
| **Platform Eng** | "SELECT from agent memory. Namespace-isolated. HMAC-chained. SQL-level query power for knowledge." |
| **CISO** | "Every memory fact has a CID. Every LLM claim has a grounding proof. Every read is in the audit log." |
| **Investor** | "The SQL of agent memory. Mem0 accumulates. Engram governs. The moat is 2+ years of Connector kernel work that cannot be replicated." |

---

> **Engram: Memory that never lies. Knowledge that never leaks. Proof that never fades.**

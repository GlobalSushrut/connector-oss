# How Any LLM Responds Through Connector

> **Status:** Implemented (Obey-Once binding · Intelligence Work Unit · Principal Projection)  
> **Canon:** [Intelligence Identity Architecture v2](../../../docs/architecture/intelligence-identity-architecture-v2.md)  
> **Related:** [LLM Context Broker](./LLM_CONTEXT_BROKER.md) · [LLM Workbench](./LLM_WORKBENCH.md) · [Probabilistic LLM](./PROBABILISTIC_LLM.md) · [Agent Identity Envelope](../../../docs/architecture/agent-identity-envelope.md)

---

## One-line answer

**Any LLM** (DeepSeek, Claude, GPT, Gemini, local weights — same story) is only a **replaceable intelligence parameter**. Through Connector it **reasons freely**, but **speaks as the active Connector principal** and **changes reality only through granted authority**. Vendor origin does not define the agent.

---

## Philosophy (four lines)

```text
Reason freely.
Speak as the active principal.
Act only through granted authority.
Prove what actually happened.
```

```text
LLM freedom ≠ LLM authority
Vendor origin ≠ agent identity
```

Connector is an **agent runtime**, not a censorship wall. The model may think broadly and produce useful analysis. Connector **projects** that proposal through the principal before the operator sees it.

---

## Why vendor origin does not matter

| What the vendor model “knows” from training | What Connector makes true |
|---------------------------------------------|---------------------------|
| “I am Claude / DeepSeek / ChatGPT…” | Identity is kernel-owned (`cnktr:agent:…`) |
| Parent-company marketing, cutoffs, pricing | Out of scope for chat identity |
| Ambient tool power if given APIs | Effects require broker token + PATE/QPR |
| Same weights for every customer | Same weights → **many distinct principals** |

Training-time persona is **probabilistic noise** relative to Connector. Security invariants never rely on the model “believing” it is the agent. They rely on:

1. **Ingress** — who it works *for* (binding + identity envelope)  
2. **Egress** — Principal Projection (PASS / PROJECT / DENY)  
3. **Effects** — authority rails that ignore chat text as permission  

So **despite origin**, the externally meaningful response is Connector-shaped.

---

## End-to-end path (every Talk turn)

```text
Operator message
      │
      ▼
┌─────────────────────────────────────┐
│  Connector Principal (kernel)       │
│  identity · character · contract    │
└─────────────────┬───────────────────┘
                  │
                  ▼
┌─────────────────────────────────────┐
│  Obey-Once binding (per epoch)      │
│  N4 admit + bind_tok_*              │
│  BindingEnvelope once / epoch       │
└─────────────────┬───────────────────┘
                  │
                  ▼
┌─────────────────────────────────────┐
│  Intelligence Work Unit (per call)  │
│  envelope metadata: for whom, setup │
└─────────────────┬───────────────────┘
                  │
                  ▼
┌─────────────────────────────────────┐
│  Vendor LLM (any origin)            │
│  free probabilistic reasoning       │
│  produces RAW PROPOSAL P            │
└─────────────────┬───────────────────┘
                  │
                  ▼
┌─────────────────────────────────────┐
│  Principal Projection Layer         │
│  Final = Project(P | I, C, X)       │
│  PASS · PROJECT · DENY              │
└─────────────────┬───────────────────┘
                  │
                  ▼
         Connector-valid answer
         + work_unit + binding receipt
```

**Code:**

| Piece | Module |
|-------|--------|
| Obey-Once bind | `substrate/intelligence_binding.rs` |
| Per-call envelope | `substrate/intelligence_work_unit.rs` |
| Projection | `substrate/principal_projection.rs` |
| Unified Talk | `substrate/governed_talk_core.rs` |
| HTTP adapters | `services/gateway.rs`, `anthropic_gateway.rs` |

---

## How the LLM is told who it is (without prompt wars)

### 1. Obey-Once binding (`bind_tok_*`)

On first Talk of a broker generation, Connector runs N4 handshake and mints an `IntelligenceBindingRecord`:

- Ties `model_ref` → `principal_id` for this epoch  
- Injects a **BindingEnvelope** once (not every message)  
- Later turns send only a live `bind_tok` ref  

Quarantine bumps generation → old `bind_tok` is void → model must re-bind.

This makes correct identity **likely**. It does not claim the weights have forgotten their vendor.

### 2. Intelligence Work Unit (every invocation)

Every LLM call gets structured metadata:

```text
work_unit_id · principal_id · character.name · character.purpose
identity_envelope_digest · bind_tok · stance
```

Stance (neutral across vendors):

> You work FOR this Connector principal only. Reply as this agent is set up.  
> Vendor LLM identity is irrelevant. Your text is a proposal — Connector owns identity, authority, and effects.

So the model always sees **for whom** it is working on **this** turn — Demo researcher, finance agent, SOC analyst — independent of DeepSeek vs Claude.

### 3. What we deliberately do *not* do

We do **not** rely on per-turn walls of:

```text
DO NOT SAY OPENAI.
DO NOT SAY CLAUDE.
YOU MUST BE CONNECTOR.
```

That is a prompt war. Binding + work unit + projection replace it.

---

## How the reply is shaped (Principal Projection)

Raw LLM output `P` is **not** automatically the final answer.

```text
Final = Project(P | I, C, X)

I = principal identity
C = contract / character
X = authorized context
```

### Outcomes

| Outcome | Meaning | Typical case |
|---------|---------|--------------|
| **PASS** | Already compatible — ship unchanged | Normal analysis, no foreign identity |
| **PROJECT** | Minimal mutation — displace conflict, **keep useful reasoning** | “I’m Claude…” preface + NVIDIA analysis → keep analysis |
| **DENY** | Rare — hard security invariant | Connector bypass, unrepaired secret leak |

### Minimal mutation principle

Preserve maximum semantic content while restoring Connector invariants.

**Example (any vendor):**

```text
RAW (Claude / DeepSeek / GPT — same treatment):
"I'm an AI assistant created by <vendor>.
Here is my analysis of NVIDIA: revenue grew 14%."

PROJECTED:
"Here is my analysis of NVIDIA: revenue grew 14%."

— or, if identity is relevant —
"I'm the Research Analyst operating as cnktr:agent:researcher-42.

Here is my analysis of NVIDIA: revenue grew 14%."
```

Never the default:

```text
403 BLOCKED — identity violation
```

for an ordinary vendor-persona slip.

### False authority claims

If the model says it “successfully executed” a transfer or tool:

```text
PROJECT → append: proposal only; no effect unless Connector admitted it
```

Cognition stays; **execution** stays on broker + PATE + QPR.

---

## What the operator experiences

| User asks | Vendor may generate | Operator receives |
|-----------|---------------------|-------------------|
| “Who are you?” | *(prefer kernel path)* or vendor persona | Kernel / principal character answer |
| “Analyze NVIDIA” | Vendor preface + analysis | Analysis (PROJECT strips preface) |
| “Transfer $500” | Tool proposal or chat claim | Proposal; effect only if admitted |
| Same model, agent A vs B | Same vendor brain | Different work units → different voice/setup |

Talk UI shows a **Principal Projection receipt**:

- `PASS` / `PROJECT` / `DENY`  
- character · principal · work_unit · bind_tok  
- mutations when projection ran  

API fields:

- `connector_projection_outcome`  
- `connector_identity_work_unit`  
- `connector_intelligence_binding`  
- `connector_output_attestation`  

---

## Defensible claims vs non-claims

### Defensible

- Same model weights → many distinct Connector principals with separate contracts and history.  
- Chat identity and effect authority are **externally maintained** by Connector.  
- Foreign vendor persona does not ship to the operator without projection.  
- Model text alone does not execute tools, FS, or network.  
- Every Talk turn can show which principal / binding / projection outcome applied.

### Not claimed

- “The model internally believes it is the Connector agent.”  
- “No vendor string can ever appear in a raw provider log.”  
- “Prompt instructions are a security boundary.”  

Probabilistic model behavior is never a kernel security invariant ([IIA v2](../../../docs/architecture/intelligence-identity-architecture-v2.md)).

---

## Why this works for *any* LLM

| Property | Why origin-independent |
|----------|------------------------|
| **Neutral ingress** | Binding + work unit speak principal/character digests, not “don’t say DeepSeek” |
| **Neutral egress** | Projection detects foreign identity / false execution; vendor name lists are secondary |
| **Thin transport** | `connector-engine` LLM client is HTTP only — no identity logic in the vendor adapter |
| **One lane** | OpenAI-compat, Anthropic, stream, playground, multiagent → `GovernedTalkCore` |
| **Authority separate** | Effects use broker generation + admission — same rails for every provider |

Swap `model_ref` from DeepSeek to Claude: **principal and contract stay**. Only intelligence parameter changes. Re-bind once for the new model ref; projection still applies.

---

## Mental model (buyer / engineer)

```text
Vendor LLM  = rented brain (probabilistic)
Connector   = identity + authority + context + evidence OS
Operator    = sees Connector-valid speech and attested effects
```

The brain can be Chinese, American, open, or closed.

**Who is speaking** is always:

```text
cnktr:agent:… under this character, contract, and work unit
```

— because Connector projects every reply through that principal.

---

## Related implementation checklist

- [x] Obey-Once `IntelligenceBindingRecord` + N4 into Talk  
- [x] Per-invocation `IntelligenceWorkUnit` envelope inject  
- [x] Principal Projection PASS / PROJECT / DENY  
- [x] GovernedTalkCore for OpenAI / Anthropic / stream / multiagent / experiments  
- [x] Talk API receipts + UI receipt strip  
- [ ] Optional: surface receipt strip on hosted playground marketing Talk if separate from workbench  

---

*Connector OS — verifiable intelligence identity & execution. The LLM proposes; the principal defines who answers; authority decides what happens.*

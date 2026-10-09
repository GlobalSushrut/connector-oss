# 22 — Cognitive Substrate: Theory and Implementation

> The research foundations of the Connector reasoning engine.

---

## Overview

The `cognitive/` module implements a structured reasoning substrate grounded in established cognitive science theories. This is not a simple LLM wrapper — it is a multi-layer pipeline that mirrors how rigorous human reasoning operates, with each layer enforcing a specific cognitive function.

---

## Theoretical Foundations

### Soar Cognitive Architecture

Soar (Laird, Rosenbloom, Newell) models cognition as:
- **Goals** — what the agent is trying to achieve
- **Operators** — actions that can move toward a goal
- **Impasses** — situations where no operator is clearly best → trigger deliberation

In Connector: goals come from the CCL contract intent block. Operators are the available step operations. Impasses trigger HITL escalation or deeper reasoning.

### BDI (Belief-Desire-Intention)

- **Beliefs** = memory namespace contents (what the agent knows)
- **Desires** = governance objectives from the CCL contract
- **Intentions** = committed execution plan

The BDI cycle: update beliefs (Ring 4 recall) → evaluate desires (Ring 5 policy) → form intentions (Layer 6 commitment) → execute (Ring 7).

### ACT-R

ACT-R (Anderson) separates:
- **Declarative memory** = `/m/` and `/k/` namespaces — facts and knowledge
- **Procedural memory** = CCL contracts and policy rules — how to act

Connector maps these directly: `recall_memory()` is declarative retrieval; CCL execution is procedural application.

### Global Workspace Theory (Baars)

A "global workspace" broadcasts high-priority signals to specialized modules. In Connector: `tension.rs` is the broadcast mechanism. High tension (competing goals, contradictions, confidence below threshold) broadcasts to all cognitive layers, which respond with their specialist reasoning.

### Active Inference (Friston)

Reasoning as minimizing prediction error / free energy. The agent models the expected state of the world and acts to reduce the gap between expected and observed. `reflection.rs` (Layer 9) compares expected vs actual outcomes and updates the model.

---

## The 11-Layer Cognitive Pipeline

```
┌─────────────────────────────────────────────────────────┐
│                  COGNITIVE PIPELINE                      │
│                                                         │
│  Layer 1   PERCEPTION      Parse incoming signal        │
│  Layer 2   MEANING         Extract semantic intent      │
│  Layer 3   TENSION         Identify competing pressures │  ← pressure.rs
│  Layer 4   POSSIBILITY     Enumerate response options   │
│  Layer 5   EVALUATION      Score against policy+memory  │
│  Layer 6   COMMITMENT      Select and commit to plan    │  ← commitment.rs
│  Layer 7   PLAN            Sequence steps               │
│  Layer 8   ACTION          Execute (→ Ring 7)           │
│  Layer 9   REFLECTION      Expected vs actual           │  ← reflection.rs
│  Layer 10  LEARNING        Update memory                │
│  Layer 11  EXPRESSION      Format for Ring 9 surface    │
└─────────────────────────────────────────────────────────┘
```

---

## Key Modules

### `tension.rs` — Pressure-Driven Cognition

Tension is the trigger for reasoning. **No tension = no deliberation.** Sources of tension:

- Competing goals in the CCL contract
- Contradiction in memory (from `get_interference`)
- Confidence below threshold
- Budget approaching limit
- Policy ambiguity (multiple matching rules)
- Pending HITL requests

```rust
pub struct TensionVector {
    pub goal_conflict:      f32,
    pub memory_contradiction: f32,
    pub confidence_deficit: f32,
    pub budget_pressure:    f32,
    pub policy_ambiguity:   f32,
}
```

When `tension.magnitude() > threshold`, the full 11-layer pipeline activates. Below threshold, the system uses a fast path.

### `commitment.rs` — Persistence Under Contradiction

Once the agent commits to a plan (Layer 6), it persists even under mild contradiction. This prevents thrashing (constant re-planning) for small perturbations.

A commitment is broken only when:
- A `require` predicate fails definitively
- Contradiction score exceeds the commitment threshold
- A HITL denial arrives
- Budget is exceeded

### `reflection.rs` — Learning from Outcomes

After execution (Layer 8), Layer 9 compares:
- **Expected outcome** (from the plan)
- **Actual outcome** (from Ring 8 journal)

Discrepancies are written to memory as learning observations:
```python
p.write_memory(pid, json.dumps({
    "kind": "reflection",
    "expected": expected_outcome,
    "actual":   actual_outcome,
    "delta":    "actual differed from expected — policy may need update"
}), memory_type="episodic")
```

---

## Hyperbolic Embeddings (`chain_tree.rs`)

Knowledge recall uses hyperbolic embeddings rather than Euclidean embeddings. Hyperbolic space models hierarchical relationships with lower distortion — important for medical knowledge (specialties → conditions → symptoms → treatments) and legal knowledge (statutes → regulations → clauses).

This means semantic search for hierarchically-related concepts returns better results than standard cosine-similarity in flat embedding space.

---

## Dehallucination via Grounding

Layer 9 (Reflection) implements dehallucination by cross-checking LLM output claims against the memory namespace:

```
LLM Output: "The patient's HbA1c is 7.2%"
    │
    ▼ Layer 9: Search /m/ for "HbA1c"
    │
    ▼ Found: mem1-sha256-abc... "lab_hba1c: 7.2%" ← grounded
    │
    ▼ DehallNode: {claim: "7.2%", source_cid: "mem1-sha256-abc...", grounded: true}
```

If no supporting memory exists → `grounded: false` → output withheld.

---

## Practical Implications

| Theory | Connector Behavior |
|---|---|
| Soar impasses | HITL escalation when no operator is clearly best |
| BDI intentions | Committed plan persists despite minor interruptions |
| ACT-R procedural | CCL contracts are the procedural memory |
| Global Workspace | Tension broadcasts force multi-module deliberation |
| Active Inference | Reflection updates beliefs based on prediction error |
| Free Energy | Agent minimizes surprise — defaults to safe/known actions |

---

## Next Steps

- **[23 — Formal Verification](23-theory-formal-verification.md)**
- **[17 — Ring 6: Reasoning](17-ring-6-reasoning-llm.md)**
- **[60 — Chains 1–3](60-chains-audit-memory-dehall.md)**

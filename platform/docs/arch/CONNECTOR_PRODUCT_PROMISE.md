# Connector Product Promise

**Audience:** Engineers building and operating dynamic agents  
**Status:** Product SoT — supersedes marketing language that claims absolute security  
**Parent standard:** [CONNECTOR_CAPABILITY_STANDARD.md](CONNECTOR_CAPABILITY_STANDARD.md)

---

## One-line thesis

> We give engineers the **tools, environment, isolation, monitoring, and proof** to host dynamic agents under the constraints **they** choose — we guarantee **honesty and reconstructibility of consequence**, not absolute security.

---

## What Connector is

Software for engineers. You compose how **dynamic** and how **constrained** each agent is. The same spine serves playground exploration and harden production — the difference is **posture**, not a different product.

| We provide | What you get |
|------------|----------------|
| **Tools** | Talk, MCP/tools, CONP/CNP, VAC memory, DIM, AAPI receipts, mission journal |
| **Env** | Namespaces, WorldGrant pores, budgets, tokenization/broker, DIM viability profiles |
| **Isolation** | Contract floor, DockLock/Landlock/microVM tiers, continuity cut — **as you configure** |
| **Monitoring** | Health, DIM Z_t/regime, KECS, operator pulse, decision traces, **Expometer**, **Action Trail** |
| **Proof** | Action digests, receipts, packet DNA, journals, forensic export — *what was admitted and what ran* |
| **Hard stop** | **SpendCease** — fence generation; admit is law (model desire irrelevant) |

Hosted reached surface (BankOps + Trail + Expometer): [CONNECTOR_PLAYGROUND_REACHED.md](../demo/CONNECTOR_PLAYGROUND_REACHED.md).


---

## What we do **not** guarantee

| Anti-claim | Why |
|------------|-----|
| “100% secure” | Covert channels, host compromise, partner HAL/SIL, novel LLM bypasses, and misconfigured soft-fail are outside absolute guarantees |
| “Every deploy is equally hard” | Playground / soft-fail is a first-class entropy leak — valid for labs, not production membrane |
| “Cognition is correct” | We gate and evidence consequence; we do not certify model truth |
| “Lab echo is SIL” | Physical safety stays partner/microVM attested — never claimed from stubs |
| “Confidence = permission” | DIM / Knot / KECS / usefulness never mint Allow |
| “We make an AI compliant” | Compliance is org/jurisdiction/process; Connector supplies controls + evidence (see parent §26–30) |

---

## What we **do** guarantee

1. **Posture honesty** — Intent vs `applied_truth`; LAB MODE when critical gates are off; soft-fail never marketed as harden.
2. **Effect exclusivity when gates are applied** — Mutating paths go through ActionBinding / PATE (ungated paths are bugs to close, not features).
3. **Engineer freedom** — Per-agent contract, grants, autonomy tier, cage tier, HITL, budgets, tokenization, DIM bands — composable without rewriting the spine.
4. **Reconstructible worldline** — Admitted effects leave digests / receipts / journal evidence you can export and verify.
5. **No cognitive self-authorization** — DIM / Knot / KECS / confidence cannot convert NF³ Fail → Pass or invent grants.
6. **Configurable continuum** — Playground → pilot → harden using the same primitives.
7. **Usable mediated access** — Inside the engineer envelope, the LLM reaches Connector (Talk/tools/memory/world). Budgets meter spend; they do not turn Connector into a permanent block wall. See [CONNECTOR_ARC.md](CONNECTOR_ARC.md) outcome triad.

These are the five core invariants of the [capability standard](CONNECTOR_CAPABILITY_STANDARD.md#31–33-security-model-and-invariants) stated as product guarantees.

---

## Engineer freedom (how you dial the agent)

```
more dynamic / exploratory          more constrained / verified
◄──────────────────────────────────────────────────────────────►
 higher Θ, wider recall              lower Θ, HITL on R2/R3
 softer budgets                      BCR spend + trajectory caps
 T0 app gates only                   Landlock → microVM
 playground soft-fail                fail-closed harden
```

You choose the point on that continuum. Connector makes the choice **real, observable, and provable**.

---

## Related docs

- [CONNECTOR_PLAYGROUND_REACHED.md](../demo/CONNECTOR_PLAYGROUND_REACHED.md) — hosted software reached (Workbench · Expometer · Action Trail · BankOps)
- [BANK_OPS_PLAYGROUND.md](../demo/BANK_OPS_PLAYGROUND.md) — BankOps click-path on try.cnktros.com
- [CONNECTOR_CAPABILITY_STANDARD.md](CONNECTOR_CAPABILITY_STANDARD.md) — parent capability / control / evidence / compliance model
- [CONNECTOR_FINAL_OUTCOMES.md](CONNECTOR_FINAL_OUTCOMES.md) — E / A / S acceptance outcomes
- [DYNAMIC_INTELLIGENCE_MANIFOLD.md](DYNAMIC_INTELLIGENCE_MANIFOLD.md) — cognitive condition (not authority)
- [CONNECTOR_SDB_RUNTIME.md](CONNECTOR_SDB_RUNTIME.md) — propose/verify/commit
- [CONSCIOUS_PHYSICS_BOUNDED_INTELLIGENCE.md](../../../CONSCIOUS_PHYSICS_BOUNDED_INTELLIGENCE.md) — CPM membrane laws

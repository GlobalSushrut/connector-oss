# Connector Augmented Environment — Operator Enablement

**Not lab.** For a real augmented environment node, set:

```bash
export CONNECTOR_AUGMENTED_ENV=1
# or equivalently under production preset:
# CONNECTOR_PRESET=production / CONNECTOR_ENV=production
```

This applies production membrane defaults and enables **harden refuse-start**:

- Agent `POST /agents/:pid/start` returns `START_REFUSED` when Requested gates are unmet (Ring-1, Landlock fail-closed, effect exclusivity, sandbox unbypassable, isolation grade, matrix cut when requested).
- Inspect triad: `GET /api/v1/substrate/status` → `harden_posture` / `product_promise.posture.harden_triad`
- Proof: `GET /api/v1/proof/export/:agent_pid` includes integrity sha256 + posture triad

**Usable when gates are met:** the LLM still gets **access through Connector** — Talk, declared tools, memory, WorldGrant pores — via admit → (optional) lease → effect. Augmented mode closes *bypass* and refuses *broken* posture; it is not a BCR brick wall that bans Connector use. Size contracts and budgets so in-envelope work succeeds. See [CONNECTOR_ARC.md](CONNECTOR_ARC.md) outcome triad.

**Smoke (augmented ready + usable):**

```bash
# gates met → start OK → Talk/tool in contract succeed
# gates unmet → START_REFUSED (honest)
# budget exhaust → spend refuse → top-up → tool works again
```

**Explicit flags (also used when AUGMENTED_ENV is unset):**

| Flag | Role |
|------|------|
| `CONNECTOR_HARDEN_REFUSE_START=1` | Start refuses when mandatory gates unmet |
| `CONNECTOR_EFFECT_EXCLUSIVITY=1` | Alternate effect paths closed |
| `CONNECTOR_SANDBOX_UNBYPASSABLE=1` | FS/net/VM/broker bar |
| `CONNECTOR_ISOLATION_RUNTIME=microvm` | Isolation grade for exclusivity |

Playground (`CONNECTOR_PLAYGROUND=1`) never engages augmented harden refuse-start.

See [CONNECTOR_REACH_CHECKLIST.md](CONNECTOR_REACH_CHECKLIST.md), [CONNECTOR_CAPABILITY_STANDARD.md](CONNECTOR_CAPABILITY_STANDARD.md), [CONNECTOR_ARC.md](CONNECTOR_ARC.md).

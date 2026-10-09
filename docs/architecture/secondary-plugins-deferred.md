# Secondary Plugins — Deferred by Constitution

Conductor, AgentLoop, Mesh Cage extras, LedgerLens, Relay, Engram, AgentPassport, and other secondary plugins are **not** co-equal kernels and are **not** current maturity gaps.

They remain next-phase reference institutions. They must:

1. Consume substrate primitives (`connector-trust` v2, admission, tenant binding, custody).
2. Pass the same lifecycle model as first-party workflows.
3. Never receive hidden first-party bypasses.

Until their enterprise acceptance suites exist, product claims must not treat them as shipping control planes.

## In-scope first-party institutions (today)

| Plugin | Role |
|--------|------|
| TraceTramp | Control / enforce plane for gateway traffic |
| WitnessCtl | Custody / audit receipts |
| DevGuard | Local agent governance / sessions |

Kernel `KNOWN_PLUGINS` / prod routes gate only these three (`platform/server/src/services/plugin_matrix.rs`). Secondary catalog entries may appear in developer Hub UI with a **deferred** badge — never equal control-plane chrome.

## Hub UI discipline

- Default Apps sidebar: TT / WC / DG only.
- Developer view may list marketed secondary plugins labeled **`· deferred`**.
- Do not wire prod management routes that imply Conductor/AgentLoop equal TT.

Related: [FINAL_REACH.md](../../FINAL_REACH.md) P5.4 · product catalog `platform/products/catalog.json`

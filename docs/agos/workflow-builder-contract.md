# Workflow builder contract (U6.4 / I-26 / P3.3)

How to author a CLS workflow that stays on the **Connector OS substrate** without compiling institution behavior into the kernel.

**Round-trip status:** `partial` when a session CLS fingerprint exists (non-empty `cls_source`); otherwise `planned`. Visual ↔ CLS source ↔ package is **not** closed. Honesty API: `GET /api/v1/workflows/:id/builder-round-trip` returns `round_trip: "planned" | "partial" | "ok"` plus `session_fingerprint` / `cls_source_fingerprint`. Fingerprint preserve only — not a full package round-trip (`ok` reserved for that).

## Laws

1. **SoT:** MemPackets, MomentManifest, UsageEvent, ArtifactLog, CFNI / causal envelopes.
2. **Projections:** TraceTramp, WitnessCtl, DevGuard, Hub apps — optional, never required for a valid WF.
3. **No private kernel types** in the package — only HTTP/API + CCL tools declared in the contract.
4. **Usage-first:** never invent `$`; `cost_usd: 0` in budget means “meter tokens/calls only.”
5. **Runtime:** Product ENABLE path is **CLS engine + CNP dispatch only** (`dual_runtime: false`); dry-run honesty is `correlated fabric replay: partial|audit_tail`.

See [doctrine-coders.md](../architecture/doctrine-coders.md) and [wf-projection-adapters.md](../architecture/wf-projection-adapters.md).

## Tool → substrate mapping (sample)

| CCL tool | Platform surface |
|----------|------------------|
| `memory_write` | `POST /api/v1/memory/write` (+ optional `parts[]` → Object Fabric) |
| `moment_commit` | Moment commit beside LLM/MemWrite (`MomentManifestV2`) |
| `usage_record` | `UsageEventV2` append |
| `artifact_append` | `ArtifactLogRecordV2` append |
| (optional) institution tools | TT/WC/DG via cage proxy — **projections only** |

## Shipped sample

**`substrate_memory_moment`** — bundled reference template:

- CCL: `platform/server/resources/workflow_templates/substrate_memory_moment.ccl`
- Operator surface: `substrate_memory_moment.operator.json` (`institutions: []`)
- Catalog: `GET /api/v1/workflows/reference-templates`

Install / enable:

```bash
# List
curl -sS "$BASE/api/v1/workflows/reference-templates" | jq '.templates[] | select(.id=="substrate_memory_moment")'

# Register from template (dashboard Setup or)
# POST /api/v1/workflows/reference-templates/substrate_memory_moment/install
# then ENABLE via workflow lifecycle API
```

## Package shape (future `.cpkg` WF)

A substrate-only workflow package SHOULD include:

- `plugin.toml` or workflow manifest with `institutions = []` (or omit)
- CLS source that only names substrate tools
- Operator surface JSON with honesty notes
- No dependency on TT/WC Postgres schemas

AGOS plugin bootstrap remains [PLUGIN_CONTRACT.md](../../PLUGIN_CONTRACT.md); workflows compose those plugins — they must not reimplement memory/custody kernels.

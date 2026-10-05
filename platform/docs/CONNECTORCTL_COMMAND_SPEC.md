# `connectorctl` — Enterprise Command Specification

> **Audience:** SREs, security engineers, compliance officers, AI platform operators.
> **Scope:** every public verb of `connectorctl`.
> **Authoring rule:** each entry lists **Purpose / Inputs / Data sources / Outcome format / Example**.
> **Output contract:** every verb emits either (a) a deterministic SOE surface + live-data overlay, or (b) a raw enterprise table. Never "stub" or "unknown" when the API has data.

---

## 0. Taxonomy

We ship **52** top-level verbs, grouped into **7 categories**. A pragmatic "core 35" is marked ⭐. Aliases: `e`→explain, `p`→prove, `t`→trace.

| Category | Verbs |
|---|---|
| **A. Lifecycle** (7) | ⭐`start` ⭐`stop` `restart` ⭐`boot` ⭐`activate` ⭐`clean` ⭐`deploy` |
| **B. Surface — the 9 operator verbs** (9) | ⭐`inspect` ⭐`show` ⭐`explain` ⭐`risk` ⭐`prove` ⭐`review` ⭐`verify` ⭐`cost` ⭐`trace` |
| **C. Fleet & Observability** (9) | ⭐`list` ⭐`agents` ⭐`top` ⭐`watch` ⭐`events` ⭐`stats` ⭐`metrics` ⭐`logs` ⭐`status` |
| **D. Intent-driven** (5) | ⭐`why` ⭐`issue` ⭐`fix` ⭐`check` `health` |
| **E. Chain / Security / Compliance** (6) | ⭐`chain` ⭐`security` ⭐`compliance` `surveillance` `threat` `pentest` |
| **F. Infra & Runtime** (8) | `infra` `network` `dns` `tls` `exec` `system` `registry` `storage` |
| **G. Admin / Meta** (8) | ⭐`policy` ⭐`mode` ⭐`admin` ⭐`config` `backup` `restore` `upgrade` `doctor` + `help` `version` `completion` `learn` `quickstart` `glue` |

35 ⭐ entries form the production-certified core. Everything else is supported but lower priority for pretty output.

---

## 1. Output format contract

Every verb has three output modes:

1. **Default human** — colored, boxed, executive-first (headline → signals → tree → actions).
2. **`--json`** — machine-readable structured output; stable schema per verb.
3. **`--raw`** — pass-through of the underlying kernel / API payload (for forensic work).

Every default-human output must start with the **Headline Contract Line**:
```
── {Subject} ── {EXEC} │ {TRUST} │ {HEALTH} │ {COMPLIANCE}  trust:{0-100}/{A-F}  cid:{surface-cid}
{one-line judgment using live numbers}
```

If any field cannot be computed from live data, the CLI prints a dim `(source: cache)` tag — **never** `UNKNOWN` when an API is actually reachable.

---

## B. The 9 Surface verbs (core operator language)

### B.1 `inspect <subject>` — full ACB drilldown
- **Purpose:** `cat /proc/<pid>/status` analogue — exhaustive structured view of an agent / workflow / policy.
- **Input:** subject id (kernel_pid / api_pid / logical name).
- **Data sources:**
  - `GET /api/v1/agents/{resolved_pid}` (status, namespace, model, role, tokens)
  - `GET /api/v1/agents/{resolved_pid}/audit/receipts` (receipt count, last_hash)
  - `GET /api/v1/agents/{resolved_pid}/activity?limit=5` (recent ops)
  - SOE surface document (for category/topology context)
- **Outcome format:**
  ```
  ── {name} ── ACTIVE │ VERIFIED │ HEALTHY │ COMPLIANT  trust:82/B  cid:...
  Agent running with 147 ops, 32 packets, $0.0421 cost, 28 receipts

    ✓ Evidence verified — 28 receipts on chain
    ✓ Health: HEALTHY
    ✓ Compliance: COMPLIANT

  ▼ Identity       id | name | role | namespace | created_at
  ▼ Resource Usage ops | mem | cost | receipts | last_hash
  ▼ Capabilities   from manifest
  ▼ Related        deep-links to prove / cost / trace

  Live Agent State
    Status: {Running|Idle|Suspended|...}
    Namespace: {ns}
    Audit Chain: {N} receipts
  ```

### B.2 `show <subject>` — quick status
- **Purpose:** `ls -l` analogue — compressed view, one screenful, for grep/pipe.
- **Input:** subject id (bare name auto-promotes to `agent <name>`).
- **Data:** same as inspect but only identity + ops + cost headline.
- **Outcome:** single card without expanded tree; suitable for `watch` integration.

### B.3 `explain <subject|decision-id>` — plain-English "why"
- **Purpose:** `dmesg | grep` analogue — narrative of *why* the subject is in its current state.
- **Two modes:**
  - **Agent mode** (`explain smoketest`) — rich agent explainer: status, LLM call pattern, recent denied ops, receipt-chain continuity.
  - **Decision mode** (`explain dec_abc123`) — per-decision forensics: integrity, tamper-proof flag, trust grade, kernel-state snapshot, upstream/downstream decisions.
- **Data sources:**
  - Agent: `/agents/{pid}`, `/agents/{pid}/cost`, `/agents/{pid}/audit/receipts`
  - Decision: `/disputes/{dec_id}/report`, `/disputes/decisions?limit=100`
- **Outcome:** four mandatory blocks — `✓/✖ STATUS`, `Problem / Why / Impact`, `→ ACTION` with follow-up commands, `✔ TRUST`, `📊 STATE`, optional `💸 RECENT LLM CALLS`.

### B.4 `risk <subject>` — risk posture
- **Purpose:** financial-audit-style risk rating with drivers.
- **Data:** KECS score + policy violations + cost trajectory + denied ops.
- **Outcome:**
  ```
  Risk: MEDIUM        (5 drivers)
  Risk Status: Degrading (was LOW 48h ago)
  What it did: 2 policy violations, 3 deny actions
  Why it did it: Model drift on pii_redact rule (v2 → v3)
  Guardrail: pii_redact@v3 — 98% block rate
  ```

### B.5 `prove <subject|decision-id>` — cryptographic proof
- **Purpose:** auditor-grade receipt chain verification.
- **Data:**
  - `/agents/{pid}/audit/receipts` (hash chain)
  - `/books` (global integrity: chain_verified, chain_length, trust_score)
- **Outcome:**
  ```
  Proof: Receipt chain intact
  Verification: VERIFIED
  Receipts: 28
  Chain: VERIFIED (2451 entries)
  Trust Score: 94/100
  Proving: sha256:{merkle-root}
  First receipt: 2026-04-15T04:35:12Z
  Last receipt:  2026-04-21T01:58:40Z
  ```

### B.6 `review <subject>` — operator decision-review view
- **Purpose:** daily-ops review format for an agent/workflow — health + top risks + recommended actions.
- **Data:** inspect + risk + recent events merged into a single triage card.
- **Outcome:** Headline + `⚠ TOP RISKS` (max 3) + `▸ RECOMMENDED ACTIONS` (numbered).

### B.7 `verify <subject>` — audit-chain verification
- **Purpose:** `journalctl --verify` analogue specifically for the signed audit chain.
- **Data:** `/agents/{pid}/audit/receipts` + `/books/integrity` + per-receipt signature verify.
- **Outcome:**
  ```
  Verify: agent smoketest
    Chain: ✓ intact (28 entries, head=sha256:...)
    Signatures: ✓ 28/28 valid
    Order: ✓ monotonic
    Root: sha256:{merkle-root}
  Conclusion: VERIFIED
  ```

### B.8 `cost <subject>` — financial breakdown
- **Purpose:** accountant-grade cost ledger for an agent (equivalent to our `books`).
- **Data:** `/agents/{pid}/cost` + `/agents/{pid}/budget`.
- **Outcome:**
  ```
  Agent: smoketest   Model: gpt-4o-mini | openai
  LLM Calls: 147
  Tokens: 221,348 (prompt: 198,211 | completion: 23,137)
  Total Cost: $0.0421  ($0.0002 / 1K tokens)
  Budget: 16,000 / 16,000  (0% used)
  First call: 2026-04-15T04:35:12Z
  Last call:  2026-04-21T01:58:40Z
  ```
- **`--statement`** variant: monthly rollup with avg/day, avg/1K tokens, variance.

### B.9 `trace <subject> [--memory|--audit]` — execution timeline
- **Purpose:** `strace -p` analogue. Default = syscall trace; `--memory` = packet stream; `--audit` = receipt stream.
- **Data:**
  - Default: `/agents/{pid}/activity?limit=100`
  - `--memory`: `/books/journal?agent_pid={pid}` filtered
  - `--audit`: `/agents/{pid}/audit/receipts?limit=100`
- **Outcome (default):**
  ```
  T+0.000s  OP_PLAN           plan_id=p_a12b  intent="generate invoice"
  T+0.142s  OP_LLM_CALL       model=gpt-4o  tok=1342  $0.0018
  T+0.298s  OP_MEMORY_WRITE   pkt=m/smoketest/p_0145  bytes=412
  T+0.301s  OP_AUDIT_RECEIPT  r_0028  hash=sha256:...
  ```
- **Outcome (`--memory`):** per-packet address + size + redaction status + vakya_id.

---

## C. Fleet & Observability (9)

### C.1 `list [noun]` — enumerate objects
- Nouns: `agents`, `policies`, `decisions`, `receipts`, `pilots`, `workflows`, `deployments`.
- Default = agents table.
- **Columns:** `PID │ NAME │ STATUS │ NS │ OPS │ MEM │ $  │ AGE │ LAST_HEARTBEAT`.

### C.2 `agents` — alias for `list agents` with filters.

### C.3 `top [--watch]` — live resource pressure
- Like `htop` for agents: rolling stats table, refresh every 2s.
- Columns: `PID │ %CPU │ RSS │ TOK/s │ OPS/s │ $/hr │ STATE`.

### C.4 `watch <subject>` — stream surface updates
- WebSocket to `/ui-rpc`; re-renders surface on every ACB mutation.

### C.5 `events [--follow] [--agent=pid]` — structured event stream
- Reads `/events?since={ts}` SSE.
- Columns: `TS │ LEVEL │ AGENT │ EVENT │ DETAILS`.

### C.6 `stats` — aggregate platform stats (tenant-scoped).

### C.7 `metrics [--prom]` — Prometheus scrape or summarized dump.

### C.8 `logs [component]` — tail server / agent / audit log.

### C.9 `status` — cluster/server health (one-line + JSON).

---

## D. Intent-driven (5)

Plain-English helpers that transpile to the right primitive verbs.

| Verb | Example | Transpiles to |
|---|---|---|
| `why` | `why did smoketest fail` | `explain smoketest` (agent mode) filtered on failures |
| `issue` | `issue list` / `issue resolve ISS-42` | `/api/v1/issues` CRUD |
| `fix` | `fix smoketest` | detects dominant failure class → runs remediation (e.g. reset trust, rebuild chain) |
| `check` | `check policy pii_redact` | `/policies/{id}/check` + report |
| `health` | `health` | `/health` → human table |

---

## E. Chain / Security / Compliance (6)

### E.1 `chain <analyze\|diff>`
- `analyze <cid> [--depth full]` — walk receipt tree, show branching, detect tamper.
- `diff <cid1> <cid2>` — receipt-level delta.

### E.2 `security <audit\|scan\|incident\|report>`
- `audit` → last 24h security-relevant ops.
- `scan [--deep]` → quick policy + receipt + signature scan.
- `incident {create\|list\|close}` → incident mgmt.
- `report` → PDF-ready rollup.

### E.3 `compliance <check\|evidence\|auto-remediate>`
- `check [--framework=eu_ai_act\|soc2\|hipaa]` → per-control pass/fail.
- `evidence [--since=24h]` → evidence package.
- `auto-remediate [--dry-run]` → propose/apply fixes.

### E.4 `surveillance <profile\|watch>` — behavior baselines & anomalies.

### E.5 `threat <intel\|hunt>` — feed lookup + YARA-style search.

### E.6 `pentest <scan\|exploit-check\|report>` — red-team suite.

---

## F. Infra & Runtime (8)

| Verb | Purpose |
|---|---|
| `infra <dns\|network\|config>` | aggregate infra surface |
| `network` | net interfaces + active sockets on platform |
| `dns` | DNS cache, resolver, overrides |
| `tls` | TLS cert status, expiry, rotate |
| `exec <pid> <cmd>` | run a signed command in an agent's sandbox |
| `system` | host system info (kernel, mem, disk, uptime) |
| `registry` | OCI/model registry ops |
| `storage` | redb/object-store usage |

---

## G. Admin / Meta / Lifecycle (glue)

### G.1 Lifecycle

| Verb | Purpose |
|---|---|
| `start [--foreground]` | boot platform (interactive mode picker) |
| `stop` | graceful shutdown |
| `restart` | stop + start |
| `boot` | synonym for start + status |
| `activate` | license activation / tier switch |
| `clean agents [--force]` | **admin**: terminate all agents, clear metadata |
| `deploy <file.yaml>` | apply declarative manifest |
| `upgrade` | in-place binary upgrade |
| `backup [--out dir]` | snapshot redb + config |
| `restore <path>` | restore snapshot |

### G.2 Admin

| Verb | Purpose |
|---|---|
| `policy <list\|show\|set>` | runtime policy CRUD |
| `mode <dev\|pilots\|prod\|airgap>` | switch runtime mode |
| `admin pilot <create\|list\|revoke\|extend\|scope>` | pilot mgmt |
| `config <show\|set\|path>` | config file inspector |

### G.3 Meta

| Verb | Purpose |
|---|---|
| `help [verb]` | help |
| `version` | version + build |
| `completion <bash\|zsh\|fish>` | shell completion |
| `learn` | 3-minute interactive tutorial |
| `quickstart` | 3-command bootstrap |
| `glue` | legacy `start/stop/status` wrapper |
| `doctor` | diagnose install + server state |

---

## 2. Gated time-slice views (future verbs)

The user's mention of "gate time" / "current LLM" → planned verbs **not yet implemented**:

- `gate llm --at "2026-04-21T01:45"` — what model+prompt+decision passed through the gateway at instant T.
- `gate time --window 5m` — every op across the cluster in a rolling 5-minute window.
- `gate agent <pid> --at T` — point-in-time snapshot of an agent's ACB.

These will all render as `trace` with a `--at`/`--window` modifier plus a new `/api/v1/gate/*` endpoint set. Captured in §9b of `AGENT_LIFECYCLE_FIX_PLAN.md` for follow-up.

---

## 3. Production-readiness checklist (per verb)

Every ⭐ verb must pass:

1. **Resolver** — accepts kernel_pid / api_pid / logical name / display form.
2. **Live data** — no `UNKNOWN`/`?` when the API has data.
3. **JSON mode** — `--json` produces stable schema; schema documented in this file.
4. **Non-zero-exit on error** — returns non-zero exit with a single actionable error line.
5. **No panics** — every `unwrap` replaced with `?` or a user-friendly error.
6. **Colorized vs piped** — auto-detect `isatty`, strip color on pipe.
7. **`--help`** — `connectorctl <verb> --help` shows usage + example + JSON schema link.
8. **Regression test** — smoke test registered against a known agent in CI.

## 4. Implementation order for polish pass

1. **B (surface 9)** — finish live-data parity on `verify`, `explain` (agent mode), `risk`, `review`.
2. **C.1 / C.3 / C.4** — `list`, `top`, `watch` tables must reflect kernel truth.
3. **D** — intent verbs need a small NL-intent router.
4. **E.1 / E.2 / E.3** — `chain`, `security`, `compliance` need schema docs + real data hookup.
5. **G.1** — harden `clean`, `deploy`, `backup/restore` with confirmation prompts.
6. Remaining F/G — lower priority; keep current behavior, add `--help`.

---

## 5. What the user sees vs what the system computes

For every verb, the transformation is:

```
raw domain events          →   kernel syscall facts   →   surface document     →   human output
(LLM calls, audit entries,     (ops_total, ops_denied,   (header + sections +    (boxed card + signals
 receipts, cost ledger,         memory.packets, status,   live overlay)           + live state footer)
 policy evaluations)           cost.total_usd)
```

The CLI's job is **never** to invent data. If a data source is missing, it must either fetch from the right endpoint or mark the field `(source: cache)`.

# Advanced lab — final plan (TraceTramp + WitnessCtl + DeepSeek + OpenFang)

**Purpose:** A **governance lab** built around **three things you can actually run**:

1. **Real action simulation** — operational workloads (multi-step agent flows, benign tool use, budgets, optional approval paths) that mirror production **behavior**, not canned scripts with fake backends.
2. **Real attack simulation** — adversarial traffic **on the wire** through TraceTramp (prompt injection, PII exfil patterns, tool abuse, rate/budget stress, control-plane misuse), aligned with OWASP LLM-style scenarios **inside your lab only**.
3. **Observable system response** — for every run you record **how the stack responded**: HTTP status and body shape, **`trace_events`**, **`action_trace_cumulative`**, WitnessCtl **captures / receipts / handoffs**, HITL or quarantine queues, blocks and redactions — so you can answer “what did governance **do** when we hit it?”

Traffic is **real**: **DeepSeek** (your key), **OpenFang** path (upstream Rust AIOS or this repo’s lab runner) → **TraceTramp** → DeepSeek. Evidence is **real** in WitnessCtl. Outcomes are visible in TUIs, exports, and SIEM-shaped JSON.

**Naming:** **OpenFang** = [RightNow-AI/openfang](https://github.com/RightNow-AI/openfang) — upstream is a **Rust** Agent OS (single binary, **Hands**, OpenAI-compatible `/v1` on the daemon). **Read upstream first:** [Getting started](https://openfang.sh/docs/getting-started) and the repo README. This repo’s Compose service **`openfang`** is a **Python lab runner** (not the upstream binary) until you wire the real `openfang` CLI against TraceTramp per §3. **Not** OpenFaaS. TraceTramp may still expose `/v1/functions/*` for other deployments; **this lab does not center OpenFaaS.**

**No mock LLM:** The lab **does not** ship a mock upstream. **`DEEPSEEK_API_KEY` is required** to bring the stack up (Compose fails fast if unset). There is **no** `MOCK_LLM` / lab-llm fallback in the standard lab path.

**Scope boundary:** Only **your** DeepSeek key, **your** stack, **isolated** lab networks. No authorization to attack third parties.

---

## 1. What “real” means in this lab

| Dimension | Requirement |
|-----------|-------------|
| **LLM provider** | **DeepSeek** cloud API: `DEEPSEEK_API_KEY` + `DEEPSEEK_BASE_URL` (default `https://api.deepseek.com/v1`). TraceTramp is configured to use that upstream for completions — the **DeepSeek API**, not “OpenAI” branding, even though TraceTramp’s internal env names (`TRACETRAMP_UPSTREAM_OPENAI_*`) follow a compatible chat schema. |
| **Real action simulation** | Scenarios that **do work**: e.g. sustained agent loop, multi-turn completion with tools (where enabled), normal business prompts, budget-adjacent load. Each scenario has a **declared intent** (baseline / stress / approval path) and **expected benign outcome** (200 + useful completion, or expected 429 when throttling). |
| **Real attack simulation** | Same HTTP surface as production clients; payloads are **deliberately hostile or exfil-shaped** but **only against lab endpoints**. No “attack succeeded” theater — you either see a **real block**, **redaction**, **HITL**, **upstream error**, or **allow with trace proof** (document which). |
| **System response evidence** | For **both** benign and attack runs, reports capture **at least**: `trace_id`, HTTP status, excerpt of error/body (no secrets), **`GET /decision/:trace_id`** highlights (`action_trace_cumulative`, `block_flags_cumulative` if present), and WitnessCtl correlation (`tracetramp_trace_id`, capture id, handoff row) where applicable. |
| **AIOS execution** | **[OpenFang](https://github.com/RightNow-AI/openfang)** path (§3): **real** loops against TraceTramp’s data plane (`TRACETRAMP_URL` / tenant key). |
| **TraceTramp action tree** | **`GET /decision/:trace_id`** → **`action_trace_cumulative`** proves TraceTramp **tracked** each step. |
| **Evidence** | WitnessCtl **ingests** proxied traffic where configured; TraceTramp **handoffs** land in `witness_tracetramp_handoffs` when secrets match. |
| **Runners** | Versioned **`runner/`** + future manifests call **only** TraceTramp / WitnessCtl / lab-runner surfaces — **no bypass** of TraceTramp for fake “success.” |

---

## 2. DeepSeek configuration contract

**Single source of truth:** `advanced-lab/.env` (from `.env.example`), interpolated by Compose into TraceTramp:

| Variable | Role |
|----------|------|
| `DEEPSEEK_API_KEY` | **Required** — DeepSeek platform key. Compose uses `${DEEPSEEK_API_KEY:?…}` so missing key **aborts** `docker compose up`. |
| `DEEPSEEK_BASE_URL` | DeepSeek API base (default `https://api.deepseek.com/v1`). |

Compose maps these to TraceTramp upstream (see `lab/advanced.yml`: `TRACETRAMP_UPSTREAM_OPENAI_BASE_URL` / `TRACETRAMP_UPSTREAM_OPENAI_API_KEY` — **implementation detail** of TraceTramp’s env names; **semantically** the lab uses **DeepSeek**).

**Preflight (recommended):**

1. Confirm `DEEPSEEK_API_KEY` is set and not a placeholder.
2. One minimal `POST /v1/chat/completions` via TraceTramp **9741** with tenant key; record latency and `trace_id`.
3. **`GET /decision/:trace_id`** — verify **`action_trace_cumulative`** is non-empty for multi-step or tool-heavy runs.

**Documentation rule:** Every lab report must state that the run used **DeepSeek** (key fingerprint / org policy as you allow — never paste secrets).

---

## 3. OpenFang upstream — how to use (read GitHub first)

Upstream **[OpenFang](https://github.com/RightNow-AI/openfang)** is an **open-source Agent Operating System** in **Rust** (one ~32 MB binary, dashboard on **http://localhost:4200**, **140+** REST/WS/SSE endpoints). It is **not** a thin Python shim: it ships **Hands** (autonomous capability bundles), **MCP**, tools, channels, and an **OpenAI-compatible** chat API on the daemon.

**Official flow** (from the README — follow this before changing lab wiring):

1. **Install** — Linux/macOS: `curl -fsSL https://openfang.sh/install | sh` · Windows: `irm https://openfang.sh/install.ps1 | iex`.
2. **`openfang init`** — walks through **provider** setup (DeepSeek is one of **27** routed providers).
3. **`openfang start`** — runs the daemon; dashboard at **http://localhost:4200**.
4. **Hands** — autonomous workloads, e.g. `openfang hand activate researcher`, `openfang hand status researcher`, `openfang hand list`, `openfang hand pause …`.
5. **Chat / agents** — e.g. `openfang chat researcher`, `openfang agent spawn coder`.

**Authoritative docs:** [openfang.sh — Getting started](https://openfang.sh/docs/getting-started) · [GitHub README](https://github.com/RightNow-AI/openfang). Upstream is **pre-1.0**; they recommend **pinning a specific commit** for production until v1.0.

### 3.1 TraceTramp in the middle (governance lab wiring)

OpenFang’s **OpenAI-compatible** driver should talk to **TraceTramp’s data plane** base URL (e.g. `http://<host>:<tracetramp-data>/v1`), **not** directly to `https://api.deepseek.com/v1`. **DeepSeek keys stay on TraceTramp** (§2); OpenFang uses a **tenant / lab API key** issued for TraceTramp. Then **Hands** and normal agent loops stay **real AIOS execution**, while **`GET /decision/:trace_id`** → **`action_trace_cumulative`** proves TraceTramp tracked each trace.

### 3.2 Compose service `openfang` in *this* repo

`lab/advanced.yml` builds **`advanced-lab/agents`** as **`openfang`** on host port **14200**. That service is a **lab HTTP runner** (health, loops, optional attacks) that sends traffic **only** to TraceTramp — useful for smoke and CI-shaped checks. Treat it as **stand-in automation** until the **upstream `openfang` binary** is installed and configured per §3.1.

---

## 4. Architecture (target)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  OpenFang (AIOS) — https://github.com/RightNow-AI/openfang                    │
│  Lab runner + agents → HTTP only to TraceTramp :9741 (+ admin :9742)           │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
        ┌─────────────────────────────┼─────────────────────────────┐
        ▼                             ▼                             ▼
┌───────────────┐           ┌─────────────────┐           ┌─────────────────┐
│ Chat / tools  │           │ Policies,       │           │ Operation       │
│ (via TT proxy)│           │ blocks, HITL    │           │ blocks, budgets │
└───────┬───────┘           └────────┬────────┘           └────────┬────────┘
        │                            │                              │
        └────────────────────────────┼──────────────────────────────┘
                                     ▼
                          ┌──────────────────────┐
                          │ TraceTramp Control    │
                          │ traces · action_trace │
                          │ cumulative per trace_id │
                          └──────────┬─────────────┘
                                     │
              ┌──────────────────────┼──────────────────────┐
              ▼                      ▼
     ┌────────────────┐    ┌────────────────┐
     │ DeepSeek API   │    │ Connector OS    │
     │ (your key)     │    │ kernel / policy │
     └────────────────┘    └────────────────┘
                                     │
                                     ▼
                          ┌──────────────────────┐
                          │ WitnessCtl proxy      │
                          │ capture · receipts ·   │
                          │ decision_digest        │
                          └──────────────────────┘
```

**Production / “cage” outcome (same stack, full contract):** for the authoritative definition of an **advanced caged environment** — any AI OS or orchestration under **control, management, proof**, and what **“impossible to bypass”** means in scope (ingress + egress + secrets) — see [`platform/docs/arch/AIOS_ADVANCED_CAGE_OUTCOME.md`](../../platform/docs/arch/AIOS_ADVANCED_CAGE_OUTCOME.md).

**Lab + upstream (minimum viable):**

1. Read **§3** and upstream docs; choose **upstream binary + TraceTramp base URL** (preferred) or the **Compose lab runner** (§3.2) for early integration.
2. Ensure **every** model call hits TraceTramp before DeepSeek (tenant key / `LAB_AGENT_KEY` as appropriate).
3. Enable **`ENABLE_ATTACKS=true`** only on the lab runner when you intend adversarial traffic; document blast radius.
4. Add **scenario manifests** (YAML/JSON) for OWASP-style probes, aligned with `trace_events` and **`action_trace_cumulative`**.

---

## 5. Scenarios: actions, attacks, and how to read the response

Design every lab session as **scenario cards**: *trigger* → *expected governance behavior* → *evidence to collect*. Below is the canonical split between **operational simulation** and **adversarial simulation**, and where the **system response** shows up.

### 5.1 Real action simulation (benign / operational)

Use these to prove **normal AIOS + gateway behavior** under load before you turn on attacks.

| Scenario | Trigger | Typical healthy response | Where to observe |
|----------|---------|--------------------------|------------------|
| **Baseline chat** | Single `POST /v1/chat/completions` via TraceTramp with tenant key | **200**, assistant content returned | Response body, `trace_id`, **`/decision/:trace_id`** |
| **Sustained agent loop** | Lab runner / OpenFang loop with `AGENT_LOOP_INTERVAL` | **200** series; occasional **429** if budget/rate limits | TraceTramp TUI / metrics, **`action_trace_cumulative`** |
| **Multi-turn / tool path** | Agent or client that uses tools if your policy allows | **200** or policy-driven **403**/block on disallowed tool | **`ToolBlocked`** or allow path in trace |
| **Witness path** | Same completion through WitnessCtl proxy session | **200** + `capture_id` | WitnessCtl API + **`by-trace/:trace_id`** |

### 5.2 Real attack simulation (adversarial — lab only)

**Runner behavior:** OpenFang lab runner (`ENABLE_ATTACKS=true`) or manifests send **the same HTTP** a malicious client would; payloads stay on **lab URLs and lab keys only**.

| Attack class | Example trigger | What “good defense” looks like | Where to observe |
|--------------|-----------------|--------------------------------|------------------|
| **LLM01** Prompt injection | Instruction override / jailbreak strings in user content | Block, redact, refuse, or **allow with** clear **`PolicyChecked`** / injection metadata in trace | **`trace_events`**, **`action_trace_cumulative`**, HTTP **4xx** if blocked |
| **LLM06** Sensitive disclosure | Synthetic SSN / card / email patterns in prompt or model output path | **PII** redaction or block; Witness flags when proxied | TraceTramp PII settings, WitnessCtl capture fields |
| **LLM07** Tool / agency abuse | Disallowed tool name or over-broad tool args | **`ToolBlocked`**, **403**, operation block | **`action_trace_cumulative`**, admin operation blocks |
| **Budget / rate** | Burst of completions or expensive prompts | **429**, `CostRecorded`, throttle markers | Traces, admin cost views |
| **Control misuse** | Invalid admin token or forbidden admin action | **401** / **403**, no silent success | Admin audit logs |

### 5.3 Control plane (attacks on governance itself)

- **Budget exhaustion** → **429** / `CostRecorded` in traces.
- **Operation blocks** (matched keys / policies) → **403** before upstream.
- **HITL / quarantine** → **202** / queue rows in DB + TUI; decision digest shows pending state.

### 5.4 OpenFang / AIOS lane (interleave benign + hostile)

- **Interleave** — alternate baseline traffic with attack payloads on **different** `trace_id`s; show TraceTramp **does not** confuse outcomes between traces.
- **Misconfiguration** — wrong `TRACETRAMP_URL` must **fail closed** (no silent direct DeepSeek from agents).

### 5.5 Lab report fields (minimum for “response to attacks”)

Each scenario export under `outputs/lab-runs/<ts>/` should include:

- `scenario_id`, `kind` (`action_sim` \| `attack_sim`), `started_at` / `finished_at`
- `trace_id`, `http_status`, `outcome` (`allow` \| `block` \| `redact` \| `hitl` \| `error`)
- Pointers (not full bodies): `decision_url` or path, `witness_correlation_ok`, optional `handoff_id`
- One **human sentence**: “System responded by … because … (cite trace node or event type).”

---

## 6. Phased delivery

### Phase A — Baseline (stack + keys)

- Compose: `lab/docker-compose.premium-lab.yml` + `lab/advanced.yml`.
- Set **`DEEPSEEK_API_KEY`** (required).
- Verify TraceTramp `/health`, WitnessCtl `/health`, **one** benign `POST /v1/chat/completions` via **9741**; **`GET /decision/:trace_id`** for **`action_trace_cumulative`**.

### Phase B — Real action simulations

- Run **§5.1** scenario set (baseline chat, sustained loop, optional Witness proxy path).
- Store **`outputs/lab-runs/<ts>/actions.json`** (or equivalent) with the §5.5 fields — proves **operational realism**.

### Phase C — Real attack simulations + response capture

- Enable attack traffic **only** when Phase B is stable (`ENABLE_ATTACKS` on lab runner, or dedicated manifest profile).
- Run **§5.2–5.3** scenarios; every attack card must have a filled **response** row (status + trace + Witness pointer).
- **`outputs/lab-runs/<ts>/attacks.json`** + optional **`summary-*.json`** from `runner` smoke — proves **defense under fire**, not theater.

### Phase D — Catalog + hardening

- Versioned **attack pack YAML** + **action sim YAML** (L4/L2); OpenFang upstream or lab runner personas; **replay-safe** defaults; `labdb` for run metadata if needed.

---

## 7. Acceptance criteria

1. **DeepSeek:** with a valid key, benign completions are **DeepSeek-backed** (non-trivial tokens/latency where applicable).
2. **Real action simulation:** ≥2 distinct **§5.1** scenarios executed and recorded under `outputs/lab-runs/` with §5.5 fields (at least one **sustained** loop through TraceTramp without bypass).
3. **Real attack simulation:** ≥3 distinct **§5.2** attack classes attempted **on lab endpoints only**; each documented with **actual** HTTP outcome (not assumed).
4. **System response:** for **each** attack in (3), evidence links **`trace_id`** → **`action_trace_cumulative`** (or explicit “allow with trace” justification) **and** WitnessCtl correlation where the scenario used the proxy path.
5. **At least one** attack outcome is a **hard defense** (block / redact / **403** / **429** / **HITL**) visible in trace or TUI — proving the stack **responded**, not only logged.
6. **Optional stretch:** benign + attack **interleaved** (§5.4) with distinct `trace_id`s showing correct per-trace outcomes.

---

## 8. Implementation backlog

| ID | Item |
|----|------|
| L1 | Preflight: assert `DEEPSEEK_API_KEY` + one probe completion + **`action_trace_cumulative`** sample in stdout or report. |
| L2 | **Two manifest families**: `actions/*.yaml` (§5.1) + `attacks/*.yaml` (§5.2); shared **report schema** (§5.5) under `outputs/lab-runs/`. |
| L3 | Docs: upstream **[openfang.sh](https://openfang.sh)** + **[Getting started](https://openfang.sh/docs/getting-started)** + GitHub; README + compose distinguish **Rust binary** vs **lab runner**. |
| L4 | Attack + action packs aligned with `trace_projection` / `block_flags_cumulative` / **`action_trace_cumulative`**; each row maps **trigger → expected defense → observability**. |
| L5 | Optional CI: **health / schema only** (no DeepSeek keys in CI; **no** mock LLM service in default lab compose). |

---

## 9. Why this is not a “normal demo”

- **Two simulation tracks:** you deliberately run **benign operational** scenarios *and* **adversarial** ones; both are **real HTTP** with **real** model and gateway behavior.
- **Response is the product:** the lab succeeds when you can **show what the system did** (status, trace tree, Witness), not when a slide says “secure.”
- **No bypass:** agents must not call DeepSeek **directly**; the story is **TraceTramp on the wire**.
- **No mock upstream:** failures surface as real errors — fix keys/network, do not hide behind a fake model.
- **Control + observe:** default TraceTramp **`X-TraceTramp-Lanes: control,observe`** on Control responses.
- **OpenFang AIOS, not OpenFaaS:** lab **automation and attacks** ride the **OpenFang** path; serverless OpenFaaS is out of scope for this plan.

---

## 10. Appendix — TraceTramp `/v1/functions` (optional, not this lab’s core)

TraceTramp implements **`POST /v1/functions/:name/call`** with pluggable backends (including **openfaas** in code). A **different** lab or customer might wire OpenFaaS there. **This advanced lab** standardizes on **DeepSeek + OpenFang + WitnessCtl** as described above.

---

## 11. Document control

| Version | Date | Summary |
|---------|------|---------|
| 1.0 | 2026-05-02 | Initial final plan. |
| 1.1 | 2026-05-02 | **OpenFang** (not OpenFaaS); **DeepSeek** as primary LLM; appendix for optional `/v1/functions`. |
| 1.2 | 2026-05-02 | **No mock LLM**; required **DeepSeek**; canonical **[OpenFang](https://github.com/RightNow-AI/openfang)**; **`action_trace_cumulative`** as proof of TraceTramp action-tree tracking. |
| 1.3 | 2026-05-02 | **§3** from upstream README: install / `init` / `start` / Hands; **TraceTramp-in-the-middle**; Compose **`openfang`** = lab Python runner vs Rust AIOS. |
| 1.4 | 2026-05-02 | **Three pillars**: real **action** sims, real **attack** sims, **system response** evidence; §5 tables + phased B/C split + stricter acceptance criteria. |

**Next action:** **L2** dual manifests + **L4** packs (action + attack), then **L1** preflight wired to §5.5 report fields.

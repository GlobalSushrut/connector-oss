# Court-defensible deployment — follow this checklist

**Date:** 2026-08-13  
**What this is:** The ordered path to make **one Connector node + one intelligence** court-defensible.  
**What this is not:** A claim that HMAC lab receipts, a PDF extract, or a green UI checkbox are court-grade. Counsel still decides admissibility in a jurisdiction.

**Architecture:** [DISTRIBUTED_INTELLIGENCE_PLAN.md](DISTRIBUTED_INTELLIGENCE_PLAN.md) §0  
**Why court was incomplete:** live WC + CFNI + node Ed25519 + no stubs + harden + human sign-off — not missing ACS/layers.  
**Machine check:** `connectorctl iia court --agent-pid <pid>` (exit 0 = CD-1…CD-7 green on that pid)

**Rule:** check a box only when the **Done when** test passes. Do not market “court-grade” until **CD-9** is signed.

```text
CD-0 engineering gates     already green in this repo (make iia-court-gate)
CD-1 harden the node       LAB MODE off
CD-2 CFNI secret           independent flow verify
CD-3 WitnessCtl live       independent institution session
CD-4 forensic=court        activate binds WC
CD-5 no stubs              live LLM, no glue stub
CD-6 court-tier package    node Ed25519 signs receipts + manifest
CD-7 offline verify        export + tamper fail
CD-8 custody (optional)    N-of-M WC quorum if you claim custody
CD-9 human + counsel       P10.9.4 + legal review
```

---

## Non-negotiables (never skip)

- [ ] **N1** No `verified: true` in UI without `connectorctl iia verify-export` passing on that file.  
- [ ] **N2** No marketed court on `signing_tier: hmac_lab`. Must be `ed25519_court`.  
- [ ] **N3** No ephemeral key minting court (node Ed25519 only).  
- [ ] **N4** No LLM stub / glue stub in the evidence window.  
- [ ] **N5** HMAC CFNI alone is not court. CFNI + WC session + court-tier package.  
- [ ] **N6** We provide **verify artifacts**. We do **not** certify “admissible in all courts.”

---

## CD-0 — Engineering gates (repo)

Already shipped. Re-run if you doubt the binary.

| Step | Command | Done when |
|------|---------|-----------|
| [ ] | `make iia-court-gate` | `platform/scripts/.iia-court-gate.ok` exists |
| [ ] | `make iia-flagship-demo` | `.iia-flagship-demo.ok` — 14/14 |
| [ ] | `make prod-dogfood-smoke` | harden path smoke green |

**Does not** make a customer node court-green. It proves the **code** can mint court-tier evidence in a gated lab.

---

## CD-1 — Harden the node (LAB off)

Court on a permissive lab node is theater.

```bash
connectorctl harden
# persist across restart:
export CONNECTOR_PRESET=production
```

| Check | Done when |
|-------|-----------|
| [ ] | `GET /api/v1/runtime/lab-mode` → `lab_mode: false` |
| [ ] | Ring-1, QPR, DockLock, HITL enforce, setup-gate **on** |
| [ ] | Sticky LAB banner gone in the dashboard |

**Fix if red:** `connectorctl harden` then restart with `CONNECTOR_PRESET=production`.

---

## CD-2 — CFNI (independent flow stamps)

```bash
# 32+ byte secret; do not use JWT/dev fallback
export CONNECTOR_CFNI_SECRET='<high-entropy-secret>'
# do NOT set CONNECTOR_CFNI_DISABLE=1
export CONNECTOR_CFNI_ENFORCE=1
```

| Check | Done when |
|-------|-----------|
| [ ] | `court-readiness.cfni.enabled` true |
| [ ] | `court-readiness.cfni.secret_configured` true |
| [ ] | `missing[]` does **not** contain `cfni_disabled` or `cfni_secret_unset` |

---

## CD-3 — WitnessCtl live (independent institution)

```bash
export CONNECTOR_WITNESSCTL_MANAGEMENT_URL='https://<wc-host>'   # no trailing slash
export CONNECTOR_WITNESSCTL_ADMIN_TOKEN='<admin>'
```

Start / enable WitnessCtl on the node (plugin catalog / `connectorctl`). Dashboard Evidence → WC sessions must list a real session after activate.

| Check | Done when |
|-------|-----------|
| [ ] | WC health via `GET /api/v1/plugins/witnessctl/health` ok |
| [ ] | Token accepted (not 401 on proxy) |
| [ ] | After CD-4 activate: `witnessctl.session_id` non-empty, status `opened` / `aligned` / `open` / `bound` |

**Fix if red:** URL + token on the **platform** process, then re-activate the agent.

---

## CD-4 — Intelligence forensic profile = court

The pid you will defend must be chartered for court, not `off` / `standard`.

```http
POST /api/v1/agents/:pid/setup
{ "forensic_profile": "court", "hitl_policy": "tool", "setup_complete": true }
```

Then Charter → Activate (opens WC session when CD-3 is set).

Or 5-min apply with `harden: true` and forensic ≥ court.

| Check | Done when |
|-------|-----------|
| [ ] | `court-readiness.forensic_profile` is `court` (or `hipaa` / `soc2` — WC-required) |
| [ ] | `witnessctl.required` true |
| [ ] | `missing[]` does **not** contain `forensic_profile_not_court_capable` or `wc_session_required` |

`off` / `standard` **cannot** go court-green. That is intentional.

---

## CD-5 — No stubs (live model)

```bash
# unset stub
unset CONNECTOR_LLM_STUB
connectorctl llm link --provider <openai|anthropic|openrouter|ollama> --key … --model … --ping
```

| Check | Done when |
|-------|-----------|
| [ ] | `GET /api/v1/settings/llms/status` → `stub_mode` false, `router_wired` true |
| [ ] | `missing[]` does **not** contain `llm_stub_on` or `stubs_in_window` |
| [ ] | Glue executor not used on this pid’s evidence window |

Talk / tool / CONP as that pid so receipts and DecisionTraces exist.

---

## CD-6 — Court-tier package (node Ed25519)

Receipts start `hmac_lab` until the **node** signing key signs them. Platform must have a persistent node key (`platform_signing.key` / verifying pub) — never an ephemeral key for court.

| Check | Done when |
|-------|-----------|
| [ ] | `package.signing_tier` is `ed25519_court` (or `Ed25519Court`) |
| [ ] | `package.package_court_ok` true |
| [ ] | `package.stubs_in_window` empty |
| [ ] | `package.receipt_count` ≥ 1 |

**Fix if `package_not_court_tier`:** node key missing or unsigned receipts. Restart platform with data-dir keys intact; generate work after the key exists; rebuild package.

---

## CD-7 — Offline verify + tamper

```bash
connectorctl iia court --agent-pid <pid> --save-package /tmp/court-export.json
connectorctl iia verify-export --file /tmp/court-export.json
# must print court-tier OK

# Tamper: flip one byte in a receipt hash, verify MUST fail
```

| Check | Done when |
|-------|-----------|
| [ ] | `connectorctl iia court --agent-pid <pid>` exit **0** |
| [ ] | `verify-export` PASS on the saved file |
| [ ] | Tampered copy FAIL |
| [ ] | Air-gap copy of `verify-export` + verifying pub still PASS (optional but gold) |

UI Evidence download is the same bytes. **Do not** treat the dashboard as the verifier.

---

## CD-8 — Custody (only if you claim “court-grade custody”)

Skip if you only claim **one-node intelligence evidence**.

| Check | Done when |
|-------|-----------|
| [ ] | WitnessCtl honesty strip `quorum_met` (not `local_only` / `partial`) |
| [ ] | N-of-M independent WC nodes |
| [ ] | Independent verify of custody export (recompute, not UI trust) |

See WitnessCtl custody docs. Local HMAC ≠ custody court.

---

## CD-9 — Human + counsel sign-off

Engineering green ≠ market court.

| Check | Done when |
|-------|-----------|
| [ ] | [IIA_CORE_UPGRADE_CHECKLIST.md](IIA_CORE_UPGRADE_CHECKLIST.md) **P10.9.4** signed (name, date, version) |
| [ ] | [PRODUCTION_READINESS_CHECKLIST.md](PRODUCTION_READINESS_CHECKLIST.md) Final GO sign-off if you ship this node |
| [ ] | Counsel reviewed the **export + verify-export procedure** for the jurisdiction |
| [ ] | Runbook: who holds `CONNECTOR_CFNI_SECRET`, WC admin token, node signing key |

**Sign-off (this deployment):**

| Field | Value |
|-------|-------|
| Node / version | |
| Agent pid(s) | |
| `iia court` exit 0 at (UTC) | |
| Package id / sha256 | |
| Signed by (eng) | |
| Counsel | |
| Date | |

---

## CD-10 — Still never claim

| Claim | Why forbidden |
|-------|----------------|
| “Admissible in all courts” | Jurisdiction is legal, not a flag |
| SIL / ROS / certified robot safety | CONP taxonomy ≠ certified e-stop |
| HMAC receipts are court-grade | Lab tier |
| PDF extract is court-green | Extract ≠ signed package |
| MicroVM / eBPF applied | Only if those backends are real |
| Lab node is production court | CD-1 failed |

---

## Operator loop (copy/paste)

```bash
# 1–3  node
connectorctl harden
export CONNECTOR_PRESET=production
export CONNECTOR_CFNI_SECRET='…'
export CONNECTOR_CFNI_ENFORCE=1
export CONNECTOR_WITNESSCTL_MANAGEMENT_URL='…'
export CONNECTOR_WITNESSCTL_ADMIN_TOKEN='…'
# restart connector-platform so env sticks

# 4    intelligence: forensic_profile=court → activate

# 5    live LLM, generate governed work (Talk / tool / CONP)

# 6–7  check + export
connectorctl iia court --agent-pid "$PID"
connectorctl iia court --agent-pid "$PID" --save-package /tmp/court-export.json
connectorctl iia verify-export --file /tmp/court-export.json
```

Exit 0 on `iia court` means CD-1…CD-7 are green **for that pid**. CD-8/9 are still human.

API: `GET /api/v1/forensics/court-readiness?agent_pid=` → `ready` + `missing[]` + `checklist`.

---

*Court-defensible = stranger can verify effects without trusting our UI. If a box cannot point at a command or `missing[]` code, it does not belong here.*

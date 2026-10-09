# AIOS +2 claim demo — T1–T12

Scripted **single-node L4 (+2)** claim tests from [FINAL_REACH.md](../FINAL_REACH.md) **P7**.  
Market **L4 / +2** only after P7 closeout is signed. This doc does **not** cover L5 mesh (see [AIOS_L5_MESH_CLAIM_DEMO.md](AIOS_L5_MESH_CLAIM_DEMO.md)).

## Conventions

| Symbol | Meaning |
|--------|---------|
| **PASS** | Observed outcome matches claim |
| **FAIL** | Outcome contradicts claim (block marketing) |
| **SKIP** | Cannot run without a live server / lab; do not treat as PASS |
| **EXPECT FAIL / OPEN** | Known gap per [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md); document honestly |

**Base URL:** `export BASE="${CONNECTOR_API_URL:-http://127.0.0.1:8080}"`  
**Auth:** `export AUTH="${CONNECTOR_SMOKE_TOKEN:-dev-token}"` (prod dogfood uses real JWT — see T7)

**Skip if no server** (default for curl probes):

```bash
if ! curl -sf --max-time 2 "${BASE}/health" >/dev/null; then
  echo "[skip] no server at ${BASE}/health"
  exit 0   # or mark SKIP in the scorecard below
fi
```

Laptop: do **not** run full `cargo test -p connector-platform` on ≤16 GiB ([LOW_MEMORY_DEV.md](LOW_MEMORY_DEV.md)). Prefer Make smokes and curl.

---

## Existing smokes (run first)

| Smoke | Make / script | Needs server? | Role |
|-------|---------------|---------------|------|
| Prod dogfood (JWT / no open auth) | `make prod-dogfood-smoke` → `platform/scripts/prod-dogfood-smoke.sh` | Starts its own | T1, T2, T7 posture |
| LLM fallback + cost-cap fields | `make llm-fallback-cap-smoke` → `platform/scripts/llm-fallback-cap-smoke.sh` | **Skip if no server** (exit 0) | T10 settings path |
| Custody quorum (unit + optional live) | `make custody-quorum-smoke` → `platform/scripts/custody-quorum-smoke.sh` | Live replicate only if `WITNESSCTL_CUSTODY_NODE_PORT` set | Prep for L5 T17; not a T1–T12 gate |
| Reference WF templates (light) | `bash platform/scripts/check-reference-templates-light.sh` | No | T3 / T9 substrate sample wiring |

```bash
# From repo root
make prod-dogfood-smoke          # builds + boots temp production preset
make llm-fallback-cap-smoke      # skip-friendly
make custody-quorum-smoke        # witnessctl unit/binary
bash platform/scripts/check-reference-templates-light.sh
```

---

## Claim scorecard

| ID | Test | Expected today | Gate |
|----|------|----------------|------|
| T1 | Admission on external effect | PASS (matrix + deny) or SKIP | L3 |
| T2 | Cage isolation = effective | OPEN / EXPECT FAIL until P4.1 | L3 |
| T3 | CLS→CNP + correlated dry-run | OPEN / EXPECT FAIL until P3.1–P3.2 | L3 |
| T4 | Capability via signed `.cpkg` Hub | PARTIAL (plugin path); WF Hub OPEN | L3 |
| T5 | TT/WC/DG shared principal/policy | OPEN until P5.1 | L3 |
| T6 | Backup / restore / node-upgrade | PASS scripts or SKIP | L3 |
| T7 | Stories A–D + clean VM signed tar | Human / CI gate (P7 closeout) | L3 |
| T8 | Unstamped egress fail-closed | OPEN / EXPECT FAIL until P6.8 | L4 |
| T9 | Moments + Object Fabric | PARTIAL (CAS put/get); multipart OPEN | L4 |
| T10 | UsageEvent SoT; unavailable ≠ $0 | PARTIAL (Books honesty); peer receipt OPEN | L4 |
| T11 | One evidence story; verified after recompute | OPEN until P6.4/P6.10 | L4 |
| T12 | SGKE/placement deny high I without H | OPEN until P6.6 | L4 |

---

## T1 — Agent cannot effect host/network without admission

**Pillar:** P2 · **Level:** L3

### Steps

```bash
# Skip if no server
curl -sf --max-time 2 "${BASE}/health" >/dev/null || { echo "[skip] no server"; exit 0; }

# 1) Admission matrix is published
curl -sf -H "Authorization: Bearer ${AUTH}" \
  "${BASE}/api/v1/substrate/admission/matrix" | tee /tmp/t1-matrix.json
# PASS: JSON lists effect → gate rows (gateway, tools/MCP, memory, object_fabric, debug restore)

# 2) Unauthenticated mutating path denied
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST \
  "${BASE}/api/v1/memory/write" -H 'Content-Type: application/json' -d '{}')
# PASS: 401 (or 403) — not 200

# 3) Optional: prod dogfood enforces JWT
make prod-dogfood-smoke
# PASS: unauthenticated GET /api/v1/agents → 401; prod_dogfood_http tests green
```

| Result | Meaning |
|--------|---------|
| PASS | Matrix present; unauth/mutating path denied; dogfood green |
| FAIL | Effect succeeds without admission / open auth in prod preset |
| SKIP | No server and dogfood not run |

**Evidence:** [admission-matrix.md](architecture/admission-matrix.md), `make prod-dogfood-smoke`

---

## T2 — Declared cage isolation = effective (no silent downgrade)

**Pillar:** P4 · **Level:** L3

### Steps

```bash
curl -sf --max-time 2 "${BASE}/health" >/dev/null || { echo "[skip] no server"; exit 0; }

# Effective isolation / backend honesty (Monitor / plugin console APIs)
curl -sf -H "Authorization: Bearer ${AUTH}" \
  "${BASE}/api/v1/substrate/status" | tee /tmp/t2-substrate.json
# Inspect isolation / cage fields if present

# Prod dogfood boots CONNECTOR_PRESET=production
make prod-dogfood-smoke
```

| Result | Meaning |
|--------|---------|
| PASS | Prod rejects silent subprocess/docker downgrade without break-glass audit |
| EXPECT FAIL / OPEN | P4.1 not closed — document; do not market |
| SKIP | No server |

---

## T3 — CLS→CNP programs; dry-run correlates fabric events

**Pillar:** P3 · **Level:** L3

### Steps

```bash
# Offline light check (no server)
bash platform/scripts/check-reference-templates-light.sh
# PASS: four templates wired; substrate_memory_moment has memory/moment/usage/artifact tools

curl -sf --max-time 2 "${BASE}/health" >/dev/null || { echo "[skip] live CLS/CNP"; exit 0; }

# Live: enable a reference WF and inspect dry-run payload for fabric event ids
# (exact route names follow Workflows UI / workflow_runtime — fail closed if blueprint-only)
curl -sf -H "Authorization: Bearer ${AUTH}" \
  "${BASE}/api/v1/workflows" | head -c 2000
```

| Result | Meaning |
|--------|---------|
| PASS | ENABLE emits CNP edges; dry-run shows would-fire/skip with event ids |
| EXPECT FAIL / OPEN | Dual-runtime / audit-tail dry-run still product path (KNOWN_LIMITATIONS) |
| SKIP | No server for live enable |

---

## T4 — New capability = signed `.cpkg` via Hub

**Pillar:** P4 · **Level:** L3

### Steps

```bash
# Offline / CLI
connectorctl plugin verify path/to/plugin.cpkg
# PASS: signature + manifest checks (2A.9 full SLO still OPEN — P4.3)

# Skip if no server
curl -sf --max-time 2 "${BASE}/health" >/dev/null || { echo "[skip] Hub HTTP"; exit 0; }

curl -sf -H "Authorization: Bearer ${AUTH}" "${BASE}/api/v1/hub/search?q=hello" | head -c 2000
# Install path: Hub UI or connectorctl plugin install — time <30s is P4.3 SLO (measure separately)
```

| Result | Meaning |
|--------|---------|
| PASS | Signed plugin `.cpkg` verifies and installs under admission |
| PARTIAL | Plugin Hub MVP works; workflow `.cpkg` Hub publish still OPEN (P4.2) |
| SKIP | No package / no server |

---

## T5 — TT/WC/DG share principals / policy — no parallel identity

**Pillar:** P5 · **Level:** L3

### Steps

```bash
curl -sf --max-time 2 "${BASE}/health" >/dev/null || { echo "[skip] no server"; exit 0; }

# Probe institution status surfaces for aligned policy / principal ids
for path in \
  /api/v1/plugins/tracetramp/status \
  /api/v1/plugins/witnessctl/status \
  /api/v1/plugins/devguard/status
do
  code=$(curl -s -o /tmp/t5.json -w '%{http_code}' -H "Authorization: Bearer ${AUTH}" "${BASE}${path}" || echo 000)
  echo "${path} → ${code}"
done
# PASS (when P5.1 closed): same policy_id / principal lineage visible gateway ↔ TT ↔ DG
```

| Result | Meaning |
|--------|---------|
| PASS | Shared `PrincipalContextV2` / policy ids across institutions |
| EXPECT FAIL / OPEN | Parallel mint / incomplete lineage (KNOWN_LIMITATIONS) |
| SKIP | Plugins or server down |

---

## T6 — Backup / restore / upgrade one trust domain

**Pillar:** P1 · **Level:** L3

### Steps

```bash
# Docs + CLI (server optional for backup of a live data_dir)
connectorctl backup -o /tmp/connector-td.tar.gz
test -f /tmp/connector-td.tar.gz.manifest.json   # or adjacent .manifest.json
# PASS: archive + manifest with node_version, env_key_refs_required

# Restore (STOP node first — destructive to data_dir)
# connectorctl stop
# connectorctl restore /tmp/connector-td.tar.gz --yes
# connectorctl start
# connectorctl doctor

connectorctl help node-upgrade   # or: connectorctl node-upgrade --help
# Settings honesty: GET backup block
curl -sf --max-time 2 "${BASE}/health" >/dev/null || { echo "[skip] backup API"; exit 0; }
curl -sf -H "Authorization: Bearer ${AUTH}" \
  "${BASE}/api/v1/settings/system/backup" | tee /tmp/t6-backup.json
# PASS: trust_domain / export_cmd present; no fake one-click if restore needs CLI
```

| Result | Meaning |
|--------|---------|
| PASS | Backup+manifest; restore boots; doctor green; node-upgrade distinct from billing |
| FAIL | Partial restore succeeds silently / second SoT invented |
| SKIP | No data_dir / no server for API |

**Evidence:** [TRUST_DOMAIN_BACKUP.md](TRUST_DOMAIN_BACKUP.md), [PRODUCTION_UPGRADE.md](PRODUCTION_UPGRADE.md)

---

## T7 — Stories A–D + constitutional success on clean VM signed tar

**Pillar:** P7 · **Level:** L3

### Steps

```bash
# Engineering gate (needs ≥32 GiB / CI — not a laptop default)
make prod-readiness-gate

# Signed release verify (offline hashes)
make verify-release-artifacts   # or bash scripts/verify-release-artifacts.sh

# Clean VM path — follow FINAL_GO_RUNBOOK (human)
# Docs: docs/FINAL_GO_RUNBOOK.md · docs/STORY_QA_RUNBOOK.md · docs/SIGNED_RELEASE.md
```

| Result | Meaning |
|--------|---------|
| PASS | Stories A–D + constitutional success signed on clean VM tarball |
| FAIL | Gate red or stories fail |
| SKIP | Human/CI not scheduled — **leave P7 human gates open** |

**Do not** mark T7 Done in FINAL_REACH until Final GO #6 / #7b.

---

## T8 — Unstamped egress fail-closed; forged stamp rejected

**Pillar:** P6 · **Level:** L4

### Steps

```bash
curl -sf --max-time 2 "${BASE}/health" >/dev/null || { echo "[skip] no server"; exit 0; }

curl -sf -H "Authorization: Bearer ${AUTH}" \
  "${BASE}/api/v1/substrate/status" | tee /tmp/t8-status.json
# Inspect flow_lease / enforce honesty fields

# Lab: attempt egress without FNI/ticket when prod enforce is on — must deny
# Forged stamp must not green-pass verify
```

| Result | Meaning |
|--------|---------|
| PASS | No lease/FNI → connect denied; forged stamp rejected |
| EXPECT FAIL / OPEN | Status honesty may exist; prod unstamped fail-closed incomplete (P6.8) |
| SKIP | No server |

---

## T9 — Moments + Object Fabric; RAG ≠ memory OS

**Pillar:** P6 · **Level:** L4

### Steps

```bash
# Offline wiring of substrate sample WF
bash platform/scripts/check-reference-templates-light.sh

curl -sf --max-time 2 "${BASE}/health" >/dev/null || { echo "[skip] Object Fabric HTTP"; exit 0; }

# Put bytes into Object Fabric CAS
HASH=$(curl -sf -X POST -H "Authorization: Bearer ${AUTH}" \
  -H 'Content-Type: application/octet-stream' \
  --data-binary 'aios-plus-two-t9' \
  "${BASE}/api/v1/memory/objects" | tee /tmp/t9-put.json | \
  python3 -c "import sys,json; print(json.load(sys.stdin).get('hash',''))" 2>/dev/null || true)

# Get by hash (hash verify on read)
if [[ -n "${HASH}" ]]; then
  curl -sf -H "Authorization: Bearer ${AUTH}" \
    "${BASE}/api/v1/memory/objects/${HASH}" -o /tmp/t9-blob
  # PASS: bytes round-trip; storage_backend honesty fs_cas (not payload_b64 SoT)
fi

curl -sf -H "Authorization: Bearer ${AUTH}" \
  "${BASE}/api/v1/substrate/status" | tee /tmp/t9-sub.json
# object_fabric.count present
```

| Result | Meaning |
|--------|---------|
| PASS | CAS put/get + hash verify; moments distinct from RAG index |
| PARTIAL | P6.1 CAS shipped; multipart/range (P6.2) still OPEN |
| SKIP | No server |

---

## T10 — UsageEvent SoT; unavailable ≠ $0; peer receipt / unmetered

**Pillar:** P6 · **Level:** L4

### Steps

```bash
# Settings contract (skip-friendly smoke)
make llm-fallback-cap-smoke
# PASS or SKIP(exit 0): fallback + cost_cap fields on /settings/llms/*

curl -sf --max-time 2 "${BASE}/health" >/dev/null || { echo "[skip] Books"; exit 0; }

curl -sf -H "Authorization: Bearer ${AUTH}" \
  "${BASE}/api/v1/books/usage" | tee /tmp/t10-usage.json
# PASS: unavailable / error surfaces must NOT coerce to $0

curl -sf -H "Authorization: Bearer ${AUTH}" \
  "${BASE}/api/v1/settings/llms/fallback-cap" | tee /tmp/t10-cap.json
```

| Result | Meaning |
|--------|---------|
| PASS | UsageEvent SoT; Books never fake $0; cap blocks overspend |
| PARTIAL | Settings + Books honesty; full primary-down→fallback E2E + peer UsageReceipt OPEN |
| SKIP | No server (`llm-fallback-cap-smoke` exits 0) |

---

## T11 — One evidence story; verified only after recompute

**Pillar:** P6 · **Level:** L4

### Steps

```bash
curl -sf --max-time 2 "${BASE}/health" >/dev/null || { echo "[skip] no server"; exit 0; }

# One request should correlate TT capture → WC custody → moment by FNI
# Then recompute integrity — verified:true only after recompute
curl -sf -H "Authorization: Bearer ${AUTH}" \
  "${BASE}/api/v1/books/journal?limit=5" | tee /tmp/t11-journal.json

# Reject decorative verified without recompute (UI + API honesty)
```

| Result | Meaning |
|--------|---------|
| PASS | Single story TT→WC→moment; badge verified only post-recompute |
| EXPECT FAIL / OPEN | Unified forensics + FNI export incomplete (P6.4 / P6.10) |
| SKIP | No server / institutions down |

---

## T12 — SGKE / placement can deny high I without H

**Pillar:** P6 · **Level:** L4

### Steps

```bash
curl -sf --max-time 2 "${BASE}/health" >/dev/null || { echo "[skip] no server"; exit 0; }

# Types exist in connector-trust (offline):
# cargo test -p connector-trust   # HardwarePlacementV2 / IntelligenceEdgeStateV2

# Live gate (when P6.6 wired): attempt tool egress with high I, missing H → deny + reason
curl -sf -H "Authorization: Bearer ${AUTH}" \
  "${BASE}/api/v1/substrate/status" | tee /tmp/t12-status.json
```

| Result | Meaning |
|--------|---------|
| PASS | High I missing H denied with SGKE reason code |
| EXPECT FAIL / OPEN | Placement types seeded (P6.7); SGKE gate not productized (P6.6) |
| SKIP | No server |

---

## P7 closeout checklist (human gates stay open)

Use this demo doc as **Core** evidence only. Still required before marketing **+2 / L4**:

- [ ] `make prod-readiness-gate` green on ≥32 GiB / CI
- [ ] Story QA paths (Jordan/Sam/Riley) green — [STORY_QA_RUNBOOK.md](STORY_QA_RUNBOOK.md)
- [ ] Clean VM §10 + signed tarball — [FINAL_GO_RUNBOOK.md](FINAL_GO_RUNBOOK.md)
- [ ] Sign Final GO #6 / #7b for **single-node L4**
- [ ] **Only then** publish **+2 / L4** (not L5)

---

## Quick operator loop

```bash
cd "$(git rev-parse --show-toplevel)"

bash platform/scripts/check-reference-templates-light.sh
make llm-fallback-cap-smoke          # skip if no server
make custody-quorum-smoke            # L5 prep; safe offline
# Optional heavy:
# make prod-dogfood-smoke
# make prod-readiness-gate           # CI / large machine only
```

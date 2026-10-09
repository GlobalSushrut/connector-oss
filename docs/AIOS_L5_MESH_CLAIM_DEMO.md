# AIOS L5 mesh claim demo — T13–T18

Scripted **global intelligence mesh (+3)** claim tests from [FINAL_REACH.md](../FINAL_REACH.md) **P9**.  
Do **not** market **L5 / court-grade / global mesh** until **P8 + P9** are signed.

Single-node L4 tests: [AIOS_PLUS_TWO_CLAIM_DEMO.md](AIOS_PLUS_TWO_CLAIM_DEMO.md).

## Honesty doctrine (read first)

Until P8 soak flips flags, every node must report:

| Field | Required value (pre-soak) |
|-------|---------------------------|
| `mesh_fabric` | `false` |
| `product_sot` | `single_node` |
| `automatic_failover` | `false` |
| `peer_tls` | `fail_closed` (unless lab escape) |

**Never** flip these in UI/API for demos. Court-grade requires N-of-M **independent** WitnessCtl verify — issuer-only HMAC is not court-grade.

Primary honesty surface:

```http
GET /api/v1/runtime/mesh
```

Also: `GET /api/v1/runtime/ha-federation`, `GET /api/v1/substrate/status` (`ha` / `peer_tls` blocks).

---

## Conventions

| Symbol | Meaning |
|--------|---------|
| **PASS** | Mesh claim proven under soak |
| **FAIL** | Overclaim or insecure peer path |
| **SKIP** | No multi-node lab / no server |
| **HONEST PRE-SOAK** | Flags correctly false on single node — good, not L5 PASS |

**Skip if no server:**

```bash
BASE="${CONNECTOR_API_URL:-http://127.0.0.1:8080}"
AUTH="${CONNECTOR_SMOKE_TOKEN:-dev-token}"
if ! curl -sf --max-time 2 "${BASE}/health" >/dev/null; then
  echo "[skip] no server at ${BASE}/health"
  exit 0
fi
```

Laptop: multi-node soaks belong on **lab VMs / CI**, not ≤16 GiB laptops ([LOW_MEMORY_DEV.md](LOW_MEMORY_DEV.md)).

---

## Existing smokes

| Smoke | Command | Role for L5 |
|-------|---------|-------------|
| Mesh honesty unit | `cargo test -p connector-platform mesh_status` (or focused test in `mesh_status.rs`) | T18 field shape |
| Custody quorum | `make custody-quorum-smoke` | T17 unit + optional live replicate |
| Prod dogfood | `make prod-dogfood-smoke` | Single-node prod posture (not mesh) |
| LLM fallback-cap | `make llm-fallback-cap-smoke` | Unrelated to mesh; skip-friendly |
| Reference templates light | `bash platform/scripts/check-reference-templates-light.sh` | Offline WF wiring only |

```bash
make custody-quorum-smoke
# Optional live custody replicate:
# WITNESSCTL_CUSTODY_NODE_PORT=19095 make custody-quorum-smoke
```

---

## Automated soak (preferred)

```bash
cd platform/server && CARGO_BUILD_JOBS=2 cargo build -p connector-platform --bin connector-platform
export CONNECTOR_BIN=$PWD/.cargo-target/debug/connector-platform
export CONNECTOR_MESH_CHANNEL_SECRET='mesh-soak-secret-32chars!!'
ARGS=--start-local make l5-mesh-soak
# On PASS → platform/scripts/.l5-mesh-soak.ok
# Then restart both nodes with CONNECTOR_MESH_FABRIC=1 to claim fabric.
make custody-multinode-soak
```

Cross-cell channel API: `POST /api/v1/runtime/mesh/channel/send` → peer `…/inbox` (HMAC `CONNECTOR_MESH_CHANNEL_SECRET`).

## Two-node lab outline

Minimal lab for T13–T18 (prefer **three** nodes for custody quorum).

### Topology

Prefer **three** nodes for custody quorum.

```
         ┌─────────────────┐         mTLS / QUIC          ┌─────────────────┐
         │  node-a         │◄────────────────────────────►│  node-b         │
         │  region: us-east│                              │  region: eu-west│
         │  :8080          │                              │  :8081          │
         └────────┬────────┘                              └────────┬────────┘
                  │                                                │
                  │         optional node-c (custody / zone)       │
                  └────────────────────┬───────────────────────────┘
                                       ▼
                              WitnessCtl custody N-of-M
```

### Env skeleton (each node)

```bash
# Shared
export CONNECTOR_PRESET=production
export CONNECTOR_DEFENSE_STRICT=1
export CONNECTOR_ENV=production
export CONNECTOR_JWT_SECRET='…≥32 bytes…'
# Peer TLS — fail-closed default (REQUIRED for marketed path)
export CONNECTOR_PEER_CA_CERT=/etc/connector/peer-ca.pem
# or: CONNECTOR_DISTRIBUTED_PEER_CA=…
# FORBIDDEN on claim path: CONNECTOR_DISTRIBUTED_ALLOW_INSECURE_TLS=1

# node-a
export CONNECTOR_HOST=0.0.0.0
export CONNECTOR_PORT=8080
export CONNECTOR_DATA_DIR=/var/lib/connector-a
export CONNECTOR_HA_ROLE=active
export CONNECTOR_HA_PEER_URLS=https://node-b:8081
# region / placement via CellAddress registry when P8.1 wired

# node-b
export CONNECTOR_PORT=8081
export CONNECTOR_DATA_DIR=/var/lib/connector-b
export CONNECTOR_HA_ROLE=passive
export CONNECTOR_HA_PEER_URLS=https://node-a:8080
```

Build with cluster feature when exercising vac-cluster path:

```bash
cd platform/server
cargo build --bin connector-platform --features cluster
```

Docs: [ha-federation.md](architecture/ha-federation.md). Starting points: `vac-cluster`, `distributed/transport.rs`, `services/mesh_status.rs`, `plugins/witnessctl` custody.

### Probe both nodes

```bash
for BASE in http://127.0.0.1:8080 http://127.0.0.1:8081; do
  echo "== ${BASE} =="
  curl -sf -H "Authorization: Bearer ${AUTH}" "${BASE}/api/v1/runtime/mesh" | tee "/tmp/mesh-$(basename ${BASE}).json"
done
```

---

## Claim scorecard

| ID | Test | Expected today | Gate |
|----|------|----------------|------|
| T13 | ≥2 nodes + real peer mTLS | OPEN / lab; honesty APIs ready | L5 |
| T14 | Geo-identity / placement filter | OPEN (types seeded P6.7) | L5 |
| T15 | Distributed CNP/vac channel effect | OPEN | L5 |
| T16 | Zone replication per policy | OPEN; Knot honesty if single-node | L5 |
| T17 | Court-grade N-of-M custody | Unit smoke PASS; multi-node OPEN | L5 |
| T18 | Honesty APIs match soak | **HONEST PRE-SOAK** PASS on single node | L5 |

---

## T13 — ≥2 (prefer 3) nodes form a cell mesh with real peer mTLS

**Pillar:** P8.2–P8.3 · **Level:** L5

### Steps

```bash
# 1) Peer TLS honesty on each node (skip if no server)
curl -sf --max-time 2 "${BASE}/health" >/dev/null || { echo "[skip] no server"; exit 0; }

curl -sf -H "Authorization: Bearer ${AUTH}" \
  "${BASE}/api/v1/runtime/mesh" | tee /tmp/t13-mesh.json
# Pre-soak PASS: peer_tls == "fail_closed", peer_tls_insecure == false
# FAIL: peer_tls insecure_lab on a marketed path

# 2) Two-node lab (outline above): good certs exchange; bad cert peer rejected
# Negative: unset peer CA → client must not SkipServerVerification
# Positive: CONNECTOR_PEER_CA_CERT set → QUIC/mTLS handshake succeeds

# 3) Confirm lab escape is off
# unset CONNECTOR_DISTRIBUTED_ALLOW_INSECURE_TLS
```

| Result | Meaning |
|--------|---------|
| PASS | ≥2 cells join with mutual auth; bad peer rejected |
| HONEST PRE-SOAK | Single node reports `fail_closed` / `mesh_fabric: false` |
| FAIL | Skip-verify on marketed path or fake mesh UI |
| SKIP | No multi-node lab |

**Evidence:** `distributed/transport.rs` (`build_quic_client_tls`), `GET /api/v1/runtime/mesh`

---

## T14 — Intelligence geo-identity / placement schedules or filters by region×hardware

**Pillar:** P8.1 · **Level:** L5

### Steps

```bash
# Offline types
# cargo test -p connector-trust   # HardwarePlacementV2, IntelligenceEdgeStateV2

curl -sf --max-time 2 "${BASE}/health" >/dev/null || { echo "[skip] no server"; exit 0; }

curl -sf -H "Authorization: Bearer ${AUTH}" \
  "${BASE}/api/v1/runtime/mesh" | tee /tmp/t14-mesh.json
# cells_by_region.capability noted; wired_to_fabric must stay false until soak

# When P8.1 Backend closed: list cells by region; place/filter identity by placement
# UI: Mesh / Topology = identities × geo × hardware (not fake k8s chrome)
```

| Result | Meaning |
|--------|---------|
| PASS | Two cells different regions; placement filters work |
| EXPECT FAIL / OPEN | Types seeded; registry not live fabric |
| SKIP | No lab |

---

## T15 — Distributed CNP/vac channel carries a governed effect across cells

**Pillar:** P8.4 · **Level:** L5

### Steps

```bash
curl -sf --max-time 2 "${BASE}/health" >/dev/null || { echo "[skip] no server"; exit 0; }

# After membership + CNP-over-QUIC wiring:
# 1) Join node-b to node-a (SWIM or vac-cluster CRDT — pick one, document)
# 2) Emit governed effect on cell A; observe on cell B via CNP/vac channel
# 3) Admission still applies on receive path

curl -sf -H "Authorization: Bearer ${AUTH}" \
  "${BASE}/api/v1/runtime/mesh" | jq '{mesh_fabric, product_sot, cluster_feature}'
```

| Result | Meaning |
|--------|---------|
| PASS | Cross-cell governed message with membership join/leave |
| EXPECT FAIL / OPEN | Membership half-wired; channel not product |
| SKIP | Single node only |

---

## T16 — Zone replication: packet/audit zone replicates per policy

**Pillar:** P8.2 · **Level:** L5

### Steps

```bash
# Two-node: write MemPacket / audit zone on A with ReplicationPolicy
# Observe CID on B per policy; Knot honesty if replication not multi-node

curl -sf --max-time 2 "${BASE}/health" >/dev/null || { echo "[skip] no server"; exit 0; }

curl -sf -H "Authorization: Bearer ${AUTH}" \
  "${BASE}/api/v1/substrate/status" | tee /tmp/t16-sub.json
# product_sot / ha honesty: single_node until vac-cluster soak
```

| Result | Meaning |
|--------|---------|
| PASS | Packet visible per replication policy on peer |
| HONEST PRE-SOAK | Knot / single-node honesty — no fake multi-node |
| SKIP | No peer |

**Starts from:** `storage_zone.rs`, `vac-replicate`, `vac-sync`.

---

## T17 — Court-grade path: N-of-M custody quorum; independent verify

**Pillar:** P8.6 · **Level:** L5

### Steps

```bash
# Always-safe offline / unit path
make custody-quorum-smoke
# PASS: custody_node quorum unit tests + witnessctl-node builds
# SKIP live: unless WITNESSCTL_CUSTODY_NODE_PORT set

# Multi-node (lab):
# 1) Start 3 witnessctl-node instances with DISTINCT keys
# 2) Collect N-of-M custody receipts
# 3) verify_quorum → quorum_met
# 4) Revoke one key → quorum fails
# 5) Export integrity_status from independent recompute (not issuer HMAC alone)
# 6) UI custody strip: local_only | partial | quorum_met | court_export_ready
#    — never label "court-grade" before quorum_met + independent verify
```

| Result | Meaning |
|--------|---------|
| PASS | 3-node quorum smoke; revoke breaks quorum; export from recompute |
| PARTIAL | `make custody-quorum-smoke` unit green; multi-node OPEN |
| FAIL | UI/API says court-grade from local HMAC |
| SKIP | No witnessctl build env |

**Evidence:** `plugins/witnessctl/src/custody_node.rs`, `make custody-quorum-smoke`

---

## T18 — Honesty APIs match soak (`mesh_fabric` / failover only if proven)

**Pillar:** P8.5 · **Level:** L5

### Steps

```bash
curl -sf --max-time 2 "${BASE}/health" >/dev/null || { echo "[skip] no server"; exit 0; }

curl -sf -H "Authorization: Bearer ${AUTH}" \
  "${BASE}/api/v1/runtime/mesh" | tee /tmp/t18-mesh.json

python3 - <<'PY'
import json,sys
v=json.load(open("/tmp/t18-mesh.json"))
assert v.get("mesh_fabric") is False, v
assert v.get("automatic_failover") is False, v
assert v.get("product_sot") == "single_node", v
assert v.get("peer_tls") in ("fail_closed","insecure_lab"), v
print("[ok] honesty fields present")
if v.get("peer_tls") == "insecure_lab":
    print("[warn] insecure_lab — not allowed on marketed L5 path")
    sys.exit(2)
print("[ok] pre-soak honesty PASS")
PY

# Cross-check HA + substrate
curl -sf -H "Authorization: Bearer ${AUTH}" \
  "${BASE}/api/v1/runtime/ha-federation" | tee /tmp/t18-ha.json
curl -sf -H "Authorization: Bearer ${AUTH}" \
  "${BASE}/api/v1/substrate/status" | tee /tmp/t18-sub.json
```

| Result | Meaning |
|--------|---------|
| PASS (pre-soak) | Flags false / `single_node` / `fail_closed` |
| PASS (post-soak) | Flags true **only** with attached soak report + tests that forbid lying |
| FAIL | Decorative `mesh_fabric: true` or `automatic_failover: true` without soak |
| SKIP | No server |

**After soak:** update [ha-federation.md](architecture/ha-federation.md) and adversarial tests **only when true**.

---

## P9 closeout checklist (human gates stay open)

- [ ] Two-/three-node soak in CI or lab runbook; update [MATURITY_21_SEGMENTS.md](../MATURITY_21_SEGMENTS.md) seg 9
- [ ] Mesh + custody + HA panels pass story QA
- [ ] Flip honesty flags **only** with evidence; keep tests that forbid lying
- [ ] **Only then** publish **L5 / +3 / global mesh / court-grade custody**

---

## Quick operator loop

```bash
cd "$(git rev-parse --show-toplevel)"

# Honesty (skip if no server)
BASE="${CONNECTOR_API_URL:-http://127.0.0.1:8080}"
AUTH="${CONNECTOR_SMOKE_TOKEN:-dev-token}"
if curl -sf --max-time 2 "${BASE}/health" >/dev/null; then
  curl -sf -H "Authorization: Bearer ${AUTH}" "${BASE}/api/v1/runtime/mesh"
else
  echo "[skip] mesh probe — no server"
fi

make custody-quorum-smoke
# Lab VMs: two-node outline above for T13–T16; three WitnessCtl nodes for T17
```

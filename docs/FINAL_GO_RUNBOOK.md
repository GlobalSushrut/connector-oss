# Final GO runbook — L4 market + L5 mesh

Engineering light gate ≠ market claim. Use this to **sign L4/+2** and then **L5/+3**.

## L4 — single-node +2 (market)

### 1. Engineering (automated)

```bash
make final-reach-light-gate   # laptop CORE
make l4-claim-gate            # light + section10 (+ L4_HEAVY=1 for tarball/story)
make prod-readiness-gate      # ≥32 GiB / CI — full release gate
```

### 2. Clean VM (T7)

On a host **without** prior `CONNECTOR_DATA_DIR` pollution:

1. `make package` → copy `dist/connector-os-*-linux.tar.gz` + `SHA256SUMS` (+ `.asc` if signed — [SIGNED_RELEASE.md](SIGNED_RELEASE.md)).
2. Verify: `make verify-release-artifacts` / `REQUIRE_SIGNATURE=1 make verify-release-artifacts`.
3. Extract; set production secrets (`CONNECTOR_PRESET=production`, JWT, audit HMAC ≥64 hex, CFNI, cage, bootstrap password).
4. `./connectorctl start` → `./connectorctl doctor`.
5. `make story-qa-smoke` against the node ([STORY_QA_RUNBOOK.md](STORY_QA_RUNBOOK.md)).

### 3. Sign L4

Mark [PRODUCTION_READINESS_CHECKLIST.md](../PRODUCTION_READINESS_CHECKLIST.md) Final GO #6/#7b and [FINAL_REACH.md](../FINAL_REACH.md) P7.  
Then market **L4 / +2** using [CONNECTOR_TRUTH_STORY.md](CONNECTOR_TRUTH_STORY.md) copy blocks.

---

## L5 — global intelligence mesh +3 (market)

### 1. Two-node soak (T13 + T15) — engineering PASS 2026-08-10

```bash
# Prefer a user-writable target (avoid stale root-owned .cargo-target):
cd platform/server && CARGO_BUILD_JOBS=2 CARGO_TARGET_DIR=.cargo-target-umesh \
  cargo build -p connector-platform --bin connector-platform

export CONNECTOR_BIN=$PWD/.cargo-target-umesh/debug/connector-platform
export CONNECTOR_MESH_CHANNEL_SECRET='mesh-soak-secret-32chars!!'
bash platform/scripts/l5-mesh-soak.sh --start-local --claim-fabric
# or: ARGS='--start-local --claim-fabric' make l5-mesh-soak
```

Evidence: `platform/scripts/.l5-mesh-soak.ok` (`t13=PASS`, `t15=PASS`).  
Peer probe uses `GET /runtime/mesh/ping` (not `/runtime/mesh`) to avoid A↔B recursion.

### 2. Claim fabric (honesty flip — only after soak)

Automated with `--claim-fabric`, or restart **both** nodes with:

```bash
export CONNECTOR_MESH_FABRIC=1
export CONNECTOR_HA_PEER_URLS=…   # peer URLs
export CONNECTOR_MESH_CHANNEL_SECRET=…
```

`GET /api/v1/runtime/mesh` → `mesh_fabric: true`, `product_sot: cell_mesh`, `peers_seen ≥ 2`.  
`automatic_failover` stays **false** until a separate HA soak (do not flip casually).  
**Note:** soak HMAC channel ≠ marketed QUIC peer mTLS (still fail_closed).

### 3. Custody court-path (T17)

```bash
make custody-multinode-soak
# Starts 3× witnessctl-node (distinct node_id) + independent verify → .custody-multinode-soak.ok
```

### 4. Sign L5

Mark FINAL_REACH P9 market sign-off; update MATURITY seg 9.  
Engineering soaks may be green — **market L5 / +3 only after human P9 sign-off**.

---

## Exit matrix

| Claim | Required green |
|-------|----------------|
| L4 / +2 | light-gate + prod-readiness-gate + T7 clean-VM signed + story QA + checklist sign-off |
| L5 / +3 | L4 + `l5-mesh-soak` + `CONNECTOR_MESH_FABRIC=1` with peers_seen≥2 + custody multinode path + P9 sign-off |

# Mesh membership — product choice (P8.4)

**Decision:** product L5 cell membership is **vac-cluster CRDT** (`Membership` / membership-view CRDT in `oss/vac/crates/vac-cluster`).  
**Do not** half-wire SWIM alongside CRDT as a second product SoT.

## Product membership: vac-cluster CRDT

| Item | Value |
|------|--------|
| Crate | `oss/vac/crates/vac-cluster` (`membership.rs`, ring / cell join) |
| Model | Lattice-based CRDT membership (conflict-free merge; join/leave/quorum helpers) |
| Product SoT flag | Stays `product_sot=single_node` / `mesh_fabric=false` until multi-node soak (P8.2 + P9) |
| Wire target | Platform boot with `cluster` feature → local `Cell` + membership view; registry heartbeats over verified peer transport |

Honesty APIs (`GET /runtime/mesh`, `/runtime/ha-federation`, `/substrate/status`) must not claim live multi-node membership until soak flips flags.

## Local heartbeat (wired)

| Item | Value |
|------|--------|
| Code | `platform/server/src/services/membership_heartbeat.rs` |
| Tick | Each `GET /runtime/mesh` advances a local CRDT membership heartbeat + probes `CONNECTOR_HA_PEER_URLS` |
| Peer probe | `GET /runtime/mesh/ping` only (never `/runtime/mesh` — avoids A↔B recursive probe deadlock) |
| API fields | `membership_algorithm: "vac_cluster_crdt"`, `peers_seen: 1+reachable`, `membership.*` |
| Soak | `make l5-mesh-soak` / `ARGS=--start-local` → `peers_seen≥2` |

## SWIM: library-only (do not productize in parallel)

| Item | Value |
|------|--------|
| Code | `platform/server/src/distributed/failure_detector.rs` (SWIM + Φ-accrual notes) |
| Status | **Library / experimental only** — not the product membership algorithm |
| Rule | Do **not** expose SWIM as live peer list UI or flip `mesh_fabric` from SWIM alone |
| Mesh field | `membership.swim: "library_only"` |

If SWIM is later chosen instead of CRDT, update this doc and retire the other path; until then **CRDT wins**.

## Channels

Distributed CNP / vac channels ride **verified** peer transport (QUIC mTLS — P8.3) to `CellAddress`. Local heartbeat is wired; cross-peer CNP channel soak remains open.

## Related

- [ha-federation.md](ha-federation.md) — cell mesh + VIP/geo-DNS honesty
- [FINAL_REACH.md](../../FINAL_REACH.md) P8.4
- Starting points: `vac-cluster`, `distributed/transport.rs`, `services/mesh_status.rs`

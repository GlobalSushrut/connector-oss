# Active/Passive HA and Federation

## Honesty

| Mode | Status |
|---|---|
| Single-node active | Default product |
| Active/passive | Operator-managed (VIP/DNS/shared storage); **no automatic failover kernel** |
| Federation | Optional peers + trust roots; SPIFFE-compatible as interface only |
| Mesh fabric | `mesh_fabric=false` until vac-cluster soak (P8.2) |

## Operator env

| Variable | Purpose |
|---|---|
| `CONNECTOR_HA_ROLE` | `standalone` / `active` / `passive` |
| `CONNECTOR_HA_PEER_URLS` | Comma-separated peer base URLs |
| `CONNECTOR_HA_SHARED_STORAGE` | `1` when data dir is shared |
| `CONNECTOR_FEDERATION_ENABLED` | Explicit federation on |
| `CONNECTOR_FEDERATION_PEERS` | Alias for peer URLs |
| `CONNECTOR_FEDERATION_TRUST_DOMAIN` | Trust domain label |
| `CONNECTOR_FEDERATION_MTLS_REQUIRED` | Require mTLS for cross-node |
| `CONNECTOR_AUDIT_HMAC_KEY` | 64+ hex chars — shared audit key for custody |
| `CONNECTOR_CELL_REGION` | Local cell geo/region label (default `local`) for placement |

## Join a peer (operator bootstrap)

Join-token HTTP API is **not shipping** yet (`join_token_api: false`). Use env bootstrap:

1. On the joining node set `CONNECTOR_HA_ROLE=passive` (or `secondary`) and `CONNECTOR_CELL_REGION=<region>`.
2. Set `CONNECTOR_HA_PEER_URLS` to the active node's base URL (comma-separated for multiple).
3. Share audit/trust roots (`CONNECTOR_AUDIT_HMAC_KEY` / `CONNECTOR_FEDERATION_TRUST_DOMAIN`) and require mTLS when ready (`CONNECTOR_FEDERATION_MTLS_REQUIRED=1`).
4. Point VIP / geo-DNS at the active endpoint for clients.
5. Settings → Network → Mesh shows peers + these instructions; the **Add peer** form is a stub (does not persist).

## API

| Route | Notes |
|---|---|
| `GET /api/v1/runtime/ha-federation` | Posture + `env.peer_urls` + `join` instructions; `automatic_failover` always `false` until soak |
| `GET /api/v1/runtime/mesh` | Local `HardwarePlacementV2`, `cells`, `intelligence_edge_example`, peers |
| `GET /api/v1/runtime/cells` | Local cell list by region (`HardwarePlacementV2` per cell) |

Never overclaim: `automatic_failover` and `mesh_fabric` stay false until a tested cluster kernel exists.

## Cell mesh (L5)

Intelligence clustering is **geo-identity × hardware placement**, not Kubernetes-as-product.

| Topic | Honesty |
|---|---|
| Local cell | `CONNECTOR_CELL_REGION` + `HardwarePlacementV2` on `/runtime/mesh` and `/runtime/cells` |
| Membership | **vac-cluster CRDT** is the product algorithm — see [mesh-membership.md](mesh-membership.md). SWIM remains library-only |
| Fabric flag | `mesh_fabric=false` / `product_sot=single_node` until vac-cluster + multi-node soak |
| Failover | Operator VIP / geo-DNS + shared storage; **two-node soak required** before any `automatic_failover: true` |
| Peers | `CONNECTOR_HA_PEER_URLS` / federation peers; mTLS required when `CONNECTOR_FEDERATION_MTLS_REQUIRED=1` |

Operator path: join peers (env bootstrap above) → place VIP/geo-DNS on active → verify HA panel matches reality (`automatic_failover` false until soak report attached).

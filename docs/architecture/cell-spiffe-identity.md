# Cell SPIFFE-ish identity (P8.3)

**URI shape (product constant):**

```text
spiffe://{trust_domain}/cell/{cell_id}
```

This is a **SPIFFE-compatible naming model** for cells — not a claim that Connector ships a full SPIFFE/SVID issuance + Workload API stack.

## Constants / code

| Item | Value |
|------|--------|
| Template | `CELL_SPIFFE_URI_TEMPLATE` in `platform/server/src/services/cell_spiffe.rs` |
| Trust domain | `CONNECTOR_FEDERATION_TRUST_DOMAIN` or `CONNECTOR_TRUST_DOMAIN`, default `connector.local` |
| Cell id | `CONNECTOR_CELL_ID`, default `cell_local` |
| Mesh exposure | `GET /api/v1/runtime/mesh` → `spiffe_id` (local cell) + `spiffe_uri_template` + `trust_domain` |

Example: `spiffe://connector.local/cell/cell_local`

## Peer trust roots

Peer mTLS still uses peer CA env (`CONNECTOR_PEER_CA_CERT` / `CONNECTOR_DISTRIBUTED_PEER_CA`) with fail-closed QUIC/TLS (see `distributed/transport.rs`). The SPIFFE-ish URI is the **identity label** operators and honesty APIs expose for the local cell; SAN embedding in peer certs remains a soak / lab follow-up.

## Honesty

- Do not market “SPIFFE verified” from URI formatting alone.
- `mesh_fabric` / `automatic_failover` stay false until P8/P9 soak.
- Related: [mesh-membership.md](mesh-membership.md), [ha-federation.md](ha-federation.md), FINAL_REACH P8.3.

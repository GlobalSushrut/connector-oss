# Cage URI stability (P4.4)

Rules for **stable plugin addresses** when the isolation backend swaps (microVM ↔ Docker lab ↔ subprocess break-glass). Clients and CLS/CNP must key off these URIs — never a raw `localhost:port` that changes with the backend.

## Stable surfaces

| Surface | Form | Source of truth |
|---------|------|-----------------|
| Public HTTP path | `/plugin/<slug>/*` | Kernel reverse proxy (`plugin_cage_proxy`) |
| Cage hostname | `<slug>.<cage_tld>` | In-process DNS (`internal_dns::plugin_cage_hostname`) |
| Default TLD | `cnktros` | `CONNECTOR_CAGE_TLD` (sanitized; default `cnktros`) |
| Routing key | same as cage hostname | `internal_dns::cage_routing_key` |

Examples: `tracetramp.cnktros`, `/plugin/tracetramp/admin/stats`.

## Stability rules

1. **Slug is the identity.** URI components use the plugin slug (ASCII lower). Backend (Firecracker vsock, Docker IP, Unix socket) is resolved behind the cage host / proxy — not in the client URL.
2. **Backend swap must not rename.** Changing `CONNECTOR_ISOLATION_RUNTIME` / `CONNECTOR_PLUGIN_RUN_BACKEND` updates the DNS table target only; `/plugin/<slug>` and `<slug>.cnktros` stay the same under policy.
3. **No silent public ICANN TLD.** Cage TLD is internal-only (see `cage_proof`); do not market cage hosts as public DNS.
4. **In-process DNS honesty.** Resolution is an in-process registry, not distributed DNS (`substrate/status` → `dns.honesty`).
5. **Inventory / Service Map.** Operator surfaces expose `cage_host` + `public_path` from the same helpers (`plugin_runtime_inventory`, `apps_catalog`, `plugins/service-map`).

## Code anchors

- `platform/server/src/internal_dns/mod.rs` — `plugin_cage_hostname`, `cage_tld`, register/resolve
- `platform/server/src/services/plugin_cage_proxy.rs` — `/plugin/<slug>/*` Host rewrite + forward
- `platform/server/src/services/plugin_runtime_inventory.rs` — inventory rows with stable URIs
- `platform/server/src/substrate/cage_security.rs` — principal binding uses slug + routing key, not backend id

## Verify (lab)

1. Boot with microVM (or available prodish backend); note `GET /api/v1/runtime/plugin-inventory` → `first_party_plugins[].cage_host` / `public_path`.
2. Swap backend under policy (lab only); confirm the same URIs still reach the plugin via `/plugin/<slug>`.
3. Clients that hard-coded a management `localhost:port` are out of contract — migrate to cage URI or public path.

Related: [FINAL_REACH.md](../../FINAL_REACH.md) P4.4 · [substrate-map.md](substrate-map.md)

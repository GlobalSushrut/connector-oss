# Production hardening guide

## Required settings

| Variable | Value |
|----------|--------|
| `CONNECTOR_PRESET` | `production` or `defense-strict` |
| `CONNECTOR_DEFENSE_STRICT` | `1` (set automatically by `defense-strict` / `edge-satellite`) |
| `CONNECTOR_JWT_SECRET` | Strong random secret (≥32 bytes) |
| `CONNECTOR_AUDIT_HMAC_KEY` | ≥64 hex chars (32-byte key). **Required** — boot fails if missing/default under production / defense-strict |
| `CONNECTOR_CFNI_SECRET` | Dedicated CFNI HMAC secret (do not reuse JWT in prod) |
| `CONNECTOR_CAGE_CAP_SECRET` | Dedicated cage capability HMAC secret |
| `CONNECTOR_BOOTSTRAP_SUPERADMIN_PASSWORD` | Set on first boot; rotate after login |
| `CONNECTOR_MEMWRITE_SYNC_FLUSH` | `1` (set by production presets when unset) |
| `CONNECTOR_CFNI_ENFORCE` | `1` (set by production presets when unset) |
| `CONNECTOR_PLUGIN_RUN_BACKEND` | `microvm` (or `docker` lab). Subprocess denied unless break-glass |

## Must be unset

- `CONNECTOR_DEV_MODE`
- `CONNECTOR_ULTIMATE_FREE` / `CONNECTOR_OPEN_AUTH` (unless you intentionally ship the community SKU)
- `CONNECTOR_CAPS_ALLOW_MOCK` (rejected at boot in production / defense-strict)
- `CONNECTOR_ALLOW_SUBPROCESS_ISOLATION` (break-glass only; audited)

## Preset effects

`CONNECTOR_PRESET=production` (and `defense-strict` / `airgap` / `edge-satellite` / `staging`) fill unset env vars for:

- `CONNECTOR_ENV=production`
- `CONNECTOR_PLUGIN_RUN_BACKEND=microvm`
- `CONNECTOR_MEMWRITE_SYNC_FLUSH=1`
- `CONNECTOR_CFNI_ENFORCE=1`

Boot then validates audit HMAC key + rejects mock caps + refuses JWT/dev fallbacks for CFNI/cage secrets.

## Doctrine (storage / forensics)

- **SoT:** MemPackets, ArtifactLog, UsageEvent (substrate).
- **Projections:** TraceTramp / WitnessCtl Postgres and admin UIs.
- **Knot:** rebuilds from packets at boot — not an independent durable DB.
- **HA:** automatic failover is **not** product SoT (single-node ship).

## TLS and firewall

- Terminate TLS at your reverse proxy or load balancer; set `connector.public_url` in `connector.yaml`.
- Allow inbound only to the dashboard/API port; plugin management ports should not be public.
- Custom domains and TLS: [`docs/TLS_CUSTOM_DOMAIN.md`](TLS_CUSTOM_DOMAIN.md) · smoke: `make custom-domain-smoke`.
- **World cage:** production preset sets `CONNECTOR_EFFECT_EXCLUSIVITY=1`, which turns on dest-pinned Landlock children (unless break-glass `CONNECTOR_ALLOW_IN_PROCESS_EFFECTS=1`). Point `/v1` clients at the gateway. Vendor IP DROP needs `CAP_NET_ADMIN`. Operator doc: [`docs/WORLD_CAGE_AND_BROWSER.md`](WORLD_CAGE_AND_BROWSER.md).

## Verification

```bash
make prod-dogfood-smoke   # 401 without auth, JWT login, microVM preset
make ci-beta-gate         # integration suite (includes durability-kill-soak)
make prod-readiness-gate  # engineering release gate
```

Signed tarball + clean VM Final GO: [`docs/SIGNED_RELEASE.md`](SIGNED_RELEASE.md).

## Community / Ultimate Free

`CONNECTOR_PRESET=ultimate-free` enables open auth for self-host demos. It is **not** the hardened production bar. See `docs/KNOWN_LIMITATIONS.md`.

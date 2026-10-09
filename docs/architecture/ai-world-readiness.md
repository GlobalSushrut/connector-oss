# AI-World Readiness — Operations Honesty

Constitutional target: one developer on modest hardware can install, inspect, repair, export, and understand a node; enterprise HA and federation are optional upgrades, not basic-install dependencies.

## Recovery

| Capability | Current posture | Gate |
|---|---|---|
| Engine store / VAC persistence | Local durable store under data dir | Backup data dir + keys |
| Bootstrap SuperAdmin | One-time `bootstrap-superadmin.secret` (0600), not logged | Rotate before external bind |
| Audit chain | Keyed HMAC with recompute verify (`CONNECTOR_AUDIT_HMAC_KEY`) | Persist key with node secrets |
| Proof artifacts | Persisted under `_trust_proofs`; `verified` only after recompute | Independent verifier uses `connector-trust::verify` |

## Active / passive HA

| Claim | Honesty |
|---|---|
| Single-node active | **Supported** — default product |
| Active/passive failover | Operator-managed (shared storage / DNS / VIP); not an automatic cluster kernel |
| Multi-cell federation | Optional; SPIFFE-compatible identity is an interface, not a local dependency |

Do not advertise automatic multi-master consistency until tested.

## Modest hardware

- Default profiles (`local`, `ultimate-free`, `playground`) must not require Docker, Firecracker, or a license cloud.
- Isolation may use subprocess with Linux hardening defaults in productionish env.
- MicroVM / Docker lab remain explicit isolation runtimes.

## Federation

- Workload identity and CNP naming bind to verified principal/tenant context.
- Cross-node trust requires explicit trust roots (cpkg signatures, mTLS, audit keys).

## Adversarial CI properties

Negative tests that must stay green:

1. Tenant mismatch (`X-Tenant-ID` ≠ JWT tenant) → 403
2. TraceTramp `/admin/*` without admin token → 401 (lab bypass requires dual env flags)
3. WitnessCtl session routes without owning token → 401
4. Proof generate does **not** return `verified: true`
5. Open auth refuses non-loopback bind unless `CONNECTOR_ALLOW_OPEN_AUTH_NONLOCAL=1`
6. Production/staging cpkg install requires signature unless `CONNECTOR_CPKG_ALLOW_UNSIGNED=1`
7. TraceTramp admission/policy fail-closed in production env

See also: [route-security-inventory.json](./route-security-inventory.json), [substrate-map.md](./substrate-map.md).

# Plugin verify — Hub 2A.9 certification checklist

Roadmap gate ([CONNECTOR_OS_ROADMAP.md](../CONNECTOR_OS_ROADMAP.md) §2A.9) before Hub publish.  
`connectorctl plugin verify` prints **all ten section headers** even when checks are still partial (`skip`).

Evidence: [FINAL_REACH.md](../FINAL_REACH.md) **P4.3**.

## Sections

| ID | Check | connectorctl today | Notes |
|----|-------|--------------------|-------|
| **2A.9.1** | Manifest schema valid; namespace + slug not reserved | **pass/fail** `manifest_parse_validate` | Reserved-namespace matrix still light |
| **2A.9.2** | ABI compatibility against kernel | **pass/fail** `agos_abi_matches_connectorctl` + optional `kernel_agos_contract` | `--require-kernel` fails closed if unreachable |
| **2A.9.3** | Resource budget honored (`memory_mb`, `vcpus`, `max_concurrency`) | **pass** echo `resource_budget_declared` | Runtime cgroup honor = 2A.10 (not verify) |
| **2A.9.4** | Idle behaviour within `idle_window` | **skip** (not automated) | Needs live idle probe |
| **2A.9.5** | Capability declarations match observed syscalls | **skip** (not automated) | Needs syscall / capability scan harness |
| **2A.9.6** | Ed25519 signature present and valid | **pass/fail/skip** `.cpkg` envelope + `--trust-keys` / `--require-signature` | Dir manifests skip envelope |
| **2A.9.7** | License & SPDX tag present | **pass/fail/warn** non-empty + SPDX hint | Hub may require stricter SPDX later |
| **2A.9.8** | Smoke: start, `/health` 200, `/admin/*` per manifest | **partial** `[health].path` shape + optional `--probe-health` for TT/WC/DG | Full start smoke open |
| **2A.9.9** | UI bundle (if any) loads without console errors | **skip** (not automated) | Dashboard bundle CI later |
| **2A.9.10** | No reserved kernel routes shadowed | **pass/fail** `routes_no_kernel_shadow` | `/api/v1` prefix forbidden |

## Operator commands

```bash
# Local / CI (offline-first)
connectorctl plugin verify path/to/plugin.toml
connectorctl plugin verify path/to/plugin.cpkg --json

# Fail if kernel contract mismatch / unreachable
connectorctl plugin verify . --require-kernel

# Signature gate for Hub publish path
connectorctl plugin verify dist/plugin.cpkg --require-signature --trust-keys hub-keys.json
```

Human-readable output groups checks under `══ 2A.9.N — … ══` headers. JSON includes `"certification": "2A.9"` and `sections_2a9`.

## Install SLO (still open)

First-party plugin install **&lt;30s** on reference hardware is **not** timed by `plugin verify` yet. Document measure when Hub install path ships (P4.2/P4.3 Backend).

## Related

- [docs/agos/plugin-authoring.md](agos/plugin-authoring.md)
- [PLUGIN_CONTRACT.md](../PLUGIN_CONTRACT.md)
- [docs/agos/abi-versioning.md](agos/abi-versioning.md)

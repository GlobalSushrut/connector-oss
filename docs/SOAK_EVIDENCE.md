# Soak / adversarial CI evidence pointers (P6.11)

Pointers to **existing** scripts, make targets, and adversarial tests. This is an evidence index — not a claim that L4/L5 soak is signed.

Related: [FINAL_REACH.md](../FINAL_REACH.md) P6.11 · [docs/SECTION10_AUTOMATED_GATES.md](SECTION10_AUTOMATED_GATES.md) · [docs/AIOS_PLUS_TWO_CLAIM_DEMO.md](AIOS_PLUS_TWO_CLAIM_DEMO.md)

## Make targets (CI / lab)

| Target | Script / notes |
|--------|----------------|
| `make section10-automated-smoke` | `platform/scripts/section10-automated-smoke.sh` |
| `make prod-readiness-gate` | `platform/scripts/prod-readiness-gate.sh` (≥32 GiB / CI preferred) |
| `make llm-fallback-cap-smoke` | `platform/scripts/llm-fallback-cap-smoke.sh` (P2.2 settings) |
| `make custody-quorum-smoke` | `platform/scripts/custody-quorum-smoke.sh` (P8.6 court strip) |
| `make custody-multinode-soak` | `platform/scripts/custody-multinode-soak.sh` → `.custody-multinode-soak.ok` (T17 live 3-node) |
| `make l5-mesh-soak` | `platform/scripts/l5-mesh-soak.sh` → `.l5-mesh-soak.ok` (T13/T15; optional `--claim-fabric`) |
| `make engineering-reach-gate` | `final-reach-light-gate` + both soak `.ok` files |
| `make story-qa-smoke` | `platform/scripts/story-qa-smoke.sh` |
| `make tt-wc-prod-smoke` / `make tt-wc-prod-gate` | TraceTramp / WitnessCtl prod posture |
| `make cage-smoke` / `make custom-domain-smoke` / `make smoke-all` | Cage + domain |
| `make one-green-start-smoke` | Boot path |
| `make ci-beta-gate` | `platform/scripts/ci_beta_gate.sh` |
| `make prod-dogfood-smoke` | Dogfood |
| `make upgrade-persist-smoke` | Upgrade persist |
| `make clean-vm-tarball-smoke` | Clean VM tarball |
| `make witness-bundle-smoke` | Witness bundle |
| `make verify-release-artifacts` | Signed release verify |
| `make k6-cage-load` / `make cage-tt-load-smoke` | Load (lab) |

Laptop rule: do **not** run `cargo test -p connector-platform --bin connector-platform` on ≤16 GiB ([LOW_MEMORY_DEV.md](LOW_MEMORY_DEV.md)). Prefer targeted crate tests + the smoke scripts above.

## Adversarial / soak test sources

| Path | Role |
|------|------|
| `platform/server/tests/trust_foundation_adversarial.rs` | Trust foundation adversarial |
| `platform/server/tests/trust_adversarial_http.rs` | HTTP adversarial trust |
| `platform/server/tests/enterprise_soak.rs` | Enterprise soak |
| `platform/server/scripts/durability-kill-soak.sh` | Durability kill soak |
| `platform/scripts/connector-kernel-bypass-lab.sh` | Bypass lab (admission) |
| `platform/scripts/connector-kernel-e2e-smoke.sh` | Kernel e2e |
| Substrate unit modules | `sgke_gate`, `admission_matrix`, `flow_lease`, `usage_receipt` (bin-local / crate tests) |

## Property / soak hooks script (P6.11 Backend)

| Script | Role |
|--------|------|
| `platform/scripts/property-soak-hooks.sh` | Runs `cargo test -p connector-trust` (from `oss/connector`), notes SGKE unit path (`platform/server/src/substrate/sgke_gate.rs` — bin-local; skipped on laptop unless `PROPERTY_SOAK_RUN_SGKE=1`), lists this file. Exit 0 on pass. |

```bash
bash platform/scripts/property-soak-hooks.sh
```

## L5 engineering soak evidence (laptop, 2026-08-10)

| File | Contents |
|------|----------|
| `platform/scripts/.l5-mesh-soak.ok` | `t13=PASS`, `t15=PASS`, optional `fabric_claim=PASS` |
| `platform/scripts/.custody-multinode-soak.ok` | `t17=PASS`, 3× distinct `witnessctl-node` + independent HMAC verify |

```bash
make platform-build
ARGS='--start-local --claim-fabric' make l5-mesh-soak
make custody-multinode-soak
make engineering-reach-gate
```

Build uses `CARGO_TARGET_DIR=.cargo-target-umesh` by default ([LOW_MEMORY_DEV.md](LOW_MEMORY_DEV.md)).

## Still open for P6.11 Backend

- Long multi-hour soak reports attached to P7/P9 claim sign-off (beyond unit/hooks above).
- Full `cargo test -p connector-platform --bin` SGKE link on laptop remains discouraged ([LOW_MEMORY_DEV.md](LOW_MEMORY_DEV.md)).

## How to cite

When flipping a FINAL_REACH checkbox, link a row from this file (make target or test path) plus date / CI run id when available.

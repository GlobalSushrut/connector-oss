# Low-memory development (14–16 GiB RAM)

This repo ships [`.cargo/config.toml`](../.cargo/config.toml) with **`jobs = 4`** so `rustc` does not spawn 16 link jobs on a ThinkPad-class machine.

## Root cause (measured on this ThinkPad)

Laptop freeze was **not** from the small unit tests themselves. Cause:

1. **`cargo test -p connector-platform --bin connector-platform`** builds the **entire monolith** as one debug+`cfg(test)` binary (not a slim test crate).
2. That binary is **~740–942 MiB** on disk under `platform/server/.cargo-target/debug/deps/connector_platform-*`.
3. Peak stress is the **final link** of that binary: the linker holds many large `.rcgu.o` / `.rlib` inputs (individual objects already **10–58 MiB**). On **14 GiB RAM + 4 GiB swap**, that peak plus Cursor/Chrome drives **swap thrash → UI freeze**, often before a clean OOM kill is logged.
4. Evidence of an interrupted link already on disk: a leftover **`connector_platform-*.tmp*` at 942 MiB** next to the finished binary (same size) — classic “link killed mid-write”.
5. Amplifiers (not the primary cause):
   - **`jobs = 4`** still allows several rustc/link workers; it does **not** cap final-link RSS for a ~1 GiB artifact.
   - Target dir **`~20 GiB`** (`~9 GiB` incremental alone) + **~4.6 GiB** of `connector_platform-*` dep binaries → disk pressure / page-cache starvation during link.
   - Agents often fire **several** such `cargo test --bin …` invocations back-to-back → repeated full or near-full relinks.

**Verdict:** freeze = **link RSS of the monolith debug test binary on ≤16 GiB**, not “Tokio tests” or “16 cores.” Mitigation is avoid that build on the laptop (light scripts / CI), or `CARGO_BUILD_JOBS=1` on a ≥32 GiB machine — not further lowering test-thread count.

## Do one heavy job at a time

| Job | Typical load |
|-----|----------------|
| `make platform-build` | High CPU + 4–8 GiB RAM peak |
| `make ci-beta-gate` | Server + many HTTP tests |
| `docker compose build` | High disk + RAM (use after `make clean-workspace`) |

## Safe sequence

```bash
make clean-workspace          # if disk creeps up
make doctor
make platform-test
make prod-dogfood-smoke
# last, alone:
make ci-beta-gate
```

Never run **`ci-beta-gate`** while Docker is rebuilding images or `cargo build` is linking `connector-platform`.

## Do **not** on a laptop with ≤16 GiB RAM

```bash
# BAD — rebuilds the giant connector-platform test binary (often freezes the machine)
cargo test -p connector-platform --bin connector-platform …
```

Use light checks instead:

```bash
bash platform/scripts/check-reference-templates-light.sh   # WF template wiring (U6.4)
make doctor                                                # when already built
make platform-build                                        # writes to .cargo-target-umesh by default
make engineering-reach-gate                              # light-gate + L5 soak evidence
```

**Mesh soak:** build with `CARGO_TARGET_DIR=.cargo-target-umesh` (Makefile default) — the legacy `platform/server/.cargo-target` binary may be root-owned/stale and lack `/runtime/mesh/ping`.

Full platform unit tests / `all_bundled_templates_compile` belong in **CI** or a machine with ≥32 GiB. If you must compile locally:

```bash
cd platform/server
CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=.cargo-target cargo test -p connector-platform \
  --bin connector-platform all_bundled_templates_compile -- --test-threads=1
```

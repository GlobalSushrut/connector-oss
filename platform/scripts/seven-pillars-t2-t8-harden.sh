#!/usr/bin/env bash
# T2 / T4 / T6–T8 hardening adversarial — light only (no full platform compile).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

echo "== T2 TLS egress proxy + kernel redirect =="
test -f platform/connector-egress-proxy/src/main.rs
grep -q 'tls_terminate\|CONNECTOR_EGRESS_TLS_TERMINATE' platform/connector-egress-proxy/src/main.rs
grep -q 'CONNECTOR_EGRESS_TLS_TERMINATE=1' platform/deploy/unbypassable.env
grep -q 'transparent_egress' platform/server/src/substrate/mod.rs
grep -q 'CONNECTOR_TRANSPARENT_EGRESS_KERNEL=1' platform/deploy/unbypassable.env
test -f platform/ebpf/connector_connect_redirect.bpf.c
grep -q 'EgressRedirectLoad\|nft-redirect' platform/connector-kerneld/src/main.rs

echo "== T6 SIL interlock =="
grep -q 'assert_sil_safe_for_dispatch' platform/server/src/kernel/sil_interlock.rs
grep -q 'sil_interlock::assert_sil_safe_for_dispatch' platform/server/src/services/conp_protocol.rs
grep -q 'CONNECTOR_CONP_SIL_REQUIRE=1' platform/deploy/unbypassable.env

echo "== T4 durable replay / mission journal =="
grep -q 'begin_step_detailed' platform/server/src/kernel/mission_journal.rs
grep -q 'BeginOutcome' platform/server/src/kernel/mission_journal.rs
grep -q 'mission_step_not_reentrant' platform/server/src/services/tools.rs
grep -q 'abandon_stale_pending\|CONNECTOR_MISSION_ABANDON_STALE_PENDING' \
  platform/server/src/kernel/mission_journal.rs
grep -q 'CONNECTOR_MISSION_ABANDON_STALE_PENDING=1' platform/deploy/unbypassable.env

echo "== T6 partner HAL (wire protocol adapters) =="
grep -q 'dispatch_conp_command' platform/server/src/kernel/partner_hal.rs
grep -q 'PartnerHalKind' platform/server/src/kernel/partner_hal.rs
grep -q 'partner_hal::dispatch_conp_command' platform/server/src/services/conp_protocol.rs
grep -q 'CONNECTOR_CONP_LAB_ECHO=0' platform/deploy/unbypassable.env
! grep -q 'default = "default_true"' platform/server/src/services/conp_protocol.rs

echo "== T7 MCP OOPC default =="
grep -q 'CONNECTOR_TOOLS_IN_MICROVM_STRICT=1' platform/deploy/unbypassable.env
grep -q 'CONNECTOR_ALLOW_HOST_MCP_BROKER=0' platform/deploy/unbypassable.env
grep -q 'in_process_hosted_mcp_allowed\|hosted_mcp_requires_oopc' \
  platform/server/src/services/mcp_hosting.rs
grep -q 'TOOLS_IN_MICROVM_STRICT' platform/server/src/connector_profile.rs

echo "== T8 unified catalog routes =="
grep -q 'apps_catalog::list_apps' platform/server/src/router.rs
grep -q 'catalog_parity_status' platform/server/src/router.rs
grep -q 'workflow_catalog_sync::get_workflow_catalog_status' platform/server/src/router.rs
grep -q 'catalog_parity.v1\|catalog_parity_status' platform/server/src/services/apps_catalog.rs

echo "== light proofs (T2 ticket + T4 soak) =="
cargo test --manifest-path platform/seven-pillars-proofs/Cargo.toml -- --nocapture
cargo run --manifest-path platform/seven-pillars-proofs/Cargo.toml -q

echo "seven-pillars-t2-t8-harden: OK"

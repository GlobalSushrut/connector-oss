# TraceTramp block / HITL — implementation checklist

Top-grade operator and buyer alignment: machine-readable holds, evidence refs, audit-friendly actor, TUI triage.

## Phase K — Kernel cage manifest + dual-ledger (code complete)

- [x] Connector **`GET /api/v1/kernel/cage-manifest`** — `KernelHostState::cage_manifest_json()` + route ([`platform/server/src/services/kernel_host.rs`](../../platform/server/src/services/kernel_host.rs), [`router.rs`](../../platform/server/src/router.rs))
- [x] TraceTramp connector **`get_kernel_cage_manifest()`** ([`connector.rs`](./src/connector.rs)) for operators / tooling
- [x] HITL **`hold_metadata.evidence.kernel_host_at_hold`** — policy_revision / profile / host_apply_state at enqueue ([`control.rs`](./src/control.rs) `hitl_hold_core`)
- [x] WitnessCtl **TraceTramp handoff** enriches payload with `witness_ledger_contract` + `ingress_ledger_contract` ([`witnessctl/src/routes.rs`](../witnessctl/src/routes.rs))
- [x] Strategy doc **K3 / T1 / W1** rows updated ([`CONNECTOR_KERNEL_CAGE_AND_LEDGER.md`](../../platform/docs/arch/CONNECTOR_KERNEL_CAGE_AND_LEDGER.md))

## Ledger — blockchain-inspired + git-like (complete)

- [x] DB trigger: `trace_events` **append-only** (no `DELETE`; only `metadata` may change on `UPDATE`) — `migrations/20260503160000_trace_events_ledger_guard.sql`
- [x] `decision_envelope`: `ledger_contract` = `tracetramp_append_only_ledger_v1` (documents model for exports)
- [x] `control.rs` module docs: ledger, explicit commands, git-like governance vs bypass
- [x] **Cage outcome (AI OS / orchestration):** [`platform/docs/arch/AIOS_ADVANCED_CAGE_OUTCOME.md`](../../platform/docs/arch/AIOS_ADVANCED_CAGE_OUTCOME.md) — full stack definition of controlled / managed / proved and deployment-bound “no bypass”
- [x] **Kernel-first cage + TT vs Wctl roles:** [`platform/docs/arch/CONNECTOR_KERNEL_CAGE_AND_LEDGER.md`](../../platform/docs/arch/CONNECTOR_KERNEL_CAGE_AND_LEDGER.md) — implement kernel shell first, then TraceTramp ingress ledger, then WitnessCtl witness path; custom plugins contract

## Phase 1 — Structured holds (complete)

- [x] DB: `approval_queue.hold_metadata` JSONB default `{}` (`migrations/20260503140000_approval_hold_metadata.sql`)
- [x] Control: `hitl_hold_core` + enriched `merge_hitl_envelope` (`hitl.block.class`, `hitl.evidence.refs`, optional `policy_block_reason` / `blocked_tool` / `risk_score`, `regulatory_hints`)
- [x] Control: `enqueue_default_hitl_hold` persists `hold_metadata` on every DB enqueue path
- [x] All hold lanes wired: `default_hitl`, `policy_soft_block`, `tool_soft_block`, `test_hitl`, `high_risk_hold`
- [x] Admin `list_approvals`: SELECT + `ApprovalRow.hold_metadata`
- [x] Connector `ApprovalItem.hold_metadata` for TUI / clients
- [x] Gateway trace bundle `reviewer_actions` includes `hold_metadata` when present

## Phase 2 — TUI + operator identity (complete)

- [x] `TRACETRAMP_TUI_OPERATOR` (default `tui-operator`) — all approve / reject / quarantine calls + confirm copy
- [x] Approvals table: **CLASS**, **trace**, **age**, lane, id, actor, reason
- [x] `Enter` in approvals panel: open trace inspector for selected row (fetch events + decision)
- [x] Help / footer text updated for new columns and inspector shortcut

## Phase 3 — Deferred

- [ ] Escalation / SLA fields on holds + TUI column
- [ ] Webhooks on enqueue / resolve
- [ ] Batch approve / dedupe queue
- [ ] Per-tenant approver pools (replace static `security-review`)

## Verification

- [x] `cargo check` — `plugins/tracetramp`, `plugins/witnessctl`, `platform/server` (connector-platform)
- [ ] Run `sqlx migrate run` on TraceTramp Postgres for `hold_metadata` + `trace_events_ledger_guard`; smoke: `curl -sS -H "Authorization: Bearer $KEY" "$CONNECTOR_URL/api/v1/kernel/cage-manifest" | jq .`
- [ ] Manual: soft hold → `P` in TUI shows CLASS + trace; `Enter` inspector; approve uses `TRACETRAMP_TUI_OPERATOR`; optional: confirm `kernel_host_at_hold` in `hold_metadata` when kernel attach is active

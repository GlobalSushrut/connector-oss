# WitnessCtl Production Checklist

This checklist is for promoting `plugins/witnessctl` to production.

## 1) Security and access control
- [ ] `WITNESSCTL_ADMIN_TOKEN` is set to a strong secret in runtime environment.
- [ ] Connector unlock path is validated in staging (`validate_access_key` success/failure paths).
- [ ] `WITNESSCTL_TRACETRAMP_HANDOFF_SECRET` is set and rotated on schedule.
- [ ] API bearer-token behavior is tested for admin and session tokens.
- [ ] Export and report endpoints enforce framework/format validation as expected.

## 2) Data integrity and compliance evidence
- [ ] Receipt chain verification passes for active and sealed sessions.
- [ ] `witness_compliance` rows are persisted and read back with stable DB IDs.
- [ ] Manual attestation route works: `POST /api/v1/compliance/:session_id/manual-attest`.
- [ ] Custody guard behavior validated for both `force=false` and `force=true`.
- [ ] Batch report manifest fields (`shared_artifact_*`, hash) are validated by client tooling.

## 3) Runtime reliability
- [ ] `cargo check` and test suite pass in CI for `plugins/witnessctl`.
- [ ] DB migrations are applied in order and verified on fresh database.
- [ ] `/health` and `/api/v1/popeye` endpoints return expected health/risk outputs.
- [ ] Rate limiting behavior is validated for `/api/v1/export/*` and `/witness/*`.
- [ ] Webhook queue enqueue path is validated under load.

## 4) TUI operational readiness
- [ ] TUI report flow (`r`) uses compliance picker path end-to-end.
- [ ] Compliance evaluate panel (`c`) handles non-2xx API errors with readable messages.
- [ ] Evidence export (`E`) and hash copy (`C`) work on target runtime images.
- [ ] HITL actions (`approve`, `reject`, `escalate`) are validated in staging.

## 5) Decision Pentest Report readiness
- [ ] Migration `20260428000014_decision_pentest_cache.sql` applied and verified.
- [ ] `GET /api/v1/pentest/:session_id/decisions` returns empty list (not 500) when no cache rows exist.
- [ ] `GET /api/v1/pentest/:session_id/decisions/:trace_id` falls back gracefully when Connector OS is unreachable (`connector_available: false`).
- [ ] Parallel Connector OS calls (pentest, tokenization, stability) timeout within configured deadline and return partial reports.
- [ ] Cache upsert (`ON CONFLICT`) works when re-fetching the same trace_id.
- [ ] `export_session` JSON output includes `decision_pentest_summaries` key.
- [ ] Markdown report includes "Decision Pentest Summaries" table when pentest rows exist.
- [ ] TUI `P` keybinding opens pentest panel, scroll works end-to-end against a live staging session.
- [ ] `payload_hash` in pentest cache row changes when Connector OS payload changes (regression guard).
- [ ] Pentest panel stability badge renders "INFECTED ✗" correctly for a mocked infected verdict.
- [ ] All three Connector OS endpoint paths (`/api/v1/pentest/decision/:trace_id`, `/api/v1/pentest/tokenization/:trace_id`, `/api/v1/pentest/stability/:trace_id`) are documented in the Connector OS API contract.

## 6) Release controls
- [ ] Build artifact versions and image tags are pinned for release.
- [ ] Rollback plan is documented and tested with one dry-run.
- [ ] Production env vars and secrets are recorded in ops runbook.
- [ ] Alert thresholds and dashboards are configured for key failure modes.


# Enterprise Acceptance Suites — First-Party Institutions

Reference institutions prove substrate primitives. They do not own parallel security kernels.

## TraceTramp

| Property | Acceptance |
|---|---|
| Management plane auth | `/admin/*` requires `require_admin` (JWT admin role or `TRACETRAMP_ADMIN_TOKEN`) |
| Insecure bypass | Only when **both** `TRACETRAMP_DEV_BYPASS=1` and `TRACETRAMP_ALLOW_INSECURE_ADMIN=1` |
| Tenant admin | `require_tenant_admin` binds JWT `tenant_id` to path tenant |
| Admission / policy outage | Fail-closed in production/staging/pilots (or `TRACETRAMP_FAIL_CLOSED=1`); lab may set `TRACETRAMP_ALLOW_FAIL_OPEN=1` |
| Tool policy missing `allowed` | Treated as deny |

## WitnessCtl

| Property | Acceptance |
|---|---|
| Session IDOR | `get/seal/ingest/compliance/proof/verify` call `enforce_session_access` |
| Tenant binding | `X-Tenant-ID` / `WITNESSCTL_TENANT_ID` honored when opening/listing; ownership still token+tenant |
| Receipt crypto | Existing HMAC receipt chain remains the custody evidence path |

## DevGuard

| Property | Acceptance |
|---|---|
| Boot wiring | `install_gateway_hooks` + `install_mcp_tools` run at platform boot |
| Session API | `/api/v1/devguard/sessions` (+ status/end/audit) mounted |
| Missing guards | Fail-closed under production/staging/pilots/defense-strict |

## Shared substrate contracts

All three institutions should eventually emit/consume `PrincipalContextV2`, `AdmissionTicketV2`, and `CustodyReceiptV2` from `connector-trust` without private bypasses.

## Memory Vector Box + DI audit middle

| Surface | Acceptance |
|---|---|
| Vector box | `GET /api/v1/memory/vector-box` + `/:cid` return `super_key`, `identity_key`, `cid`, `timestamp_ms`, `raw`, `log` |
| Data context | `GET /api/v1/memory/data-context/:agent_pid` returns boxes + graph + relational projections |
| WitnessCtl middle export | `GET /api/v1/export/:session_id?format=di_audit_middle` emits `connector.di_audit_middle.v1` with custody header; integrity status from recompute |

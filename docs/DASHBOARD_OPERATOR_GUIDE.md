# Dashboard operator guide (P0.2)

Configure the node from **`https://<host>:<port>`** after first `connectorctl start` — no `.env` archaeology for day-2 operations.

| Area | Dashboard path | API |
|------|----------------|-----|
| Secrets / vault | Settings → Secrets | `POST /api/v1/infra/vault/secrets` |
| LLM provider | Settings → LLM | env via UI store / `CONNECTOR_LLM_*` migration |
| Networking / custom domains | Settings → Networking | `GET/POST /api/v1/settings/networking/custom-domains` |
| Identity / users | Settings → Users | `POST /api/v1/auth/users` |
| API keys | Settings → API keys | `POST /api/v1/auth/api-keys` |
| Plugins | Apps / Plugins hub | `GET /api/v1/apps`, `GET /api/v1/plugins/status` |
| Workflows | Workflows | `GET /api/v1/workflows`, catalog sync dir |
| Bootstrap migration | CLI once | [`docs/BOOTSTRAP_RUNBOOK.md`](BOOTSTRAP_RUNBOOK.md) |

**LLM fallback:** set primary + fallback in Settings; kernel uses `LlmRouter` with `CONNECTOR_LLM_FALLBACK` (see `platform/server/src/main.rs`). UI E2E: disable primary key in vault → confirm fallback model in monitor/health.

**v1 manual QA:** Fresh VM sign-off still required for checklist P0.2 checkbox.

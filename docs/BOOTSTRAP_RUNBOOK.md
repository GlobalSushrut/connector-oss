# Bootstrap runbook — migrate legacy env secrets to the kernel vault

Use this once when upgrading from env-var–based installs to dashboard/vault storage.

## Prerequisites

- `connector-platform` is running and reachable (`GET /readyz` returns OK).
- `CONNECTOR_API_URL` points at your node (default `http://127.0.0.1:9091`).
- `CONNECTOR_API_KEY` or a SuperAdmin JWT is set if the node is not in dev/ultimate-free mode.

## Dry run

```bash
export CONNECTOR_LLM_API_KEY=sk-example
connectorctl bootstrap
```

Lists secrets that would be migrated (no writes).

## Apply

```bash
connectorctl bootstrap --apply
```

Each listed variable is POSTed to `/api/v1/infra/vault/secrets` as `bootstrap/env/<VAR_NAME>`.

## After apply

Unset the migrated variables in your shell and systemd unit files. Configure LLM and plugin tokens from **Settings** in the dashboard.

## Verified in CI

`platform/scripts/upgrade-persist-smoke.sh` and `make ci-beta-gate` exercise fresh `data_dir` bootstrap with `CONNECTOR_BOOTSTRAP_SUPERADMIN_PASSWORD`.

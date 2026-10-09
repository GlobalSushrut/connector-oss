# Changelog

All notable changes to Connector OS are documented here. Version numbers follow the `connector-platform` crate semver from `platform/server/Cargo.toml`.

## Unreleased

### Added

- `make story-qa-smoke` — Jordan/Sam/Riley HTTP acceptance
- Dry-run `cnp_replay` correlates workflow CNP registration + audit filter (3.6 partial)
- Production readiness gate: `make prod-readiness-gate`, `make prod-dogfood-smoke`, `make upgrade-persist-smoke`
- Ultimate Free open auth (`CONNECTOR_PRESET=ultimate-free`) with `open_auth_http` tests
- Workflow catalog auto-sync on boot (`data_dir/workflows/catalog`)
- REST RBAC on `/api/v1/*`, multi-tenant middleware, plugin cage `.fallback()` proxy
- Apps catalog `GET /api/v1/apps`, workflows HTTP API, CI beta gate smokes

### Fixed

- Lab Docker builds: `platform` additional context for `plugin-handshake` path dep
- Custom domain E2E smoke `ALIAS_HOST` export order

### Security

- `CONNECTOR_DEFENSE_STRICT=1` disables dev and ultimate-free bypass
- `SECURITY.md` and `scripts/audit-secrets-in-repo.sh`

## Versioning

Release artifacts: `connector-os-<semver>-<arch>-linux.tar.gz` from `make package`.

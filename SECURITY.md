# Security policy

## Reporting a vulnerability

Email security reports to your organization's security contact (replace before public launch). Do not open public GitHub issues for exploitable findings.

We aim to acknowledge reports within **3 business days** and provide a fix timeline within **14 days** for critical issues.

## Supported versions

| Version | Supported |
|---------|-----------|
| Latest release tarball | Yes |
| `main` branch | Best-effort |

## Secure defaults

- Production: `CONNECTOR_PRESET=production`, `CONNECTOR_DEFENSE_STRICT=1`, strong `CONNECTOR_JWT_SECRET`.
- Do not enable `CONNECTOR_DEV_MODE` or `CONNECTOR_ULTIMATE_FREE` on internet-facing nodes unless you accept open auth.

## CI hygiene

- `scripts/audit-secrets-in-repo.sh` — heuristic secret grep
- `scripts/audit-removed-paths.sh` — no stray compose/monitoring paths outside `lab/`

## Disclosure

We follow coordinated disclosure. Credit will be given with permission after a fix is released.

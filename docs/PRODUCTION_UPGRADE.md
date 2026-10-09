# Production upgrade (N → N+1)

Connector OS keeps state under `CONNECTOR_DATA_DIR` (default `./data`). Upgrading the binary does not wipe this directory.

**Billing vs node:** `connectorctl upgrade` = commercial **tier**. Binary/node upgrade = `connectorctl node-upgrade` (prints these steps) + tarball replace.

## Steps

1. Backup trust domain: `connectorctl backup -o /var/backups/pre-upgrade.tar.gz` ([TRUST_DOMAIN_BACKUP.md](TRUST_DOMAIN_BACKUP.md))
2. Stop the node: `connectorctl stop`
3. Verify release: `sha256sum -c SHA256SUMS` and optional `gpg --verify` ([SIGNED_RELEASE.md](SIGNED_RELEASE.md))
4. Replace binaries from the new release tarball (`connector-platform`, `connectorctl`, embedded dashboard `dist/`).
5. Start: `connectorctl start`
6. Verify: `connectorctl status`, `connectorctl doctor`, `GET /health`

## Migrate notes

| Area | Behavior |
|------|----------|
| `CONNECTOR_DATA_DIR` | Preserved across binary replace |
| VAC / redb / engine.db | Opened by new binary; if ABI breaks, release notes must say so — rollback binaries |
| Vault / JWT / audit HMAC | Env or vault — not in tarball; restore env if host changes |
| Plugin Postgres (TT/WC) | Separate; follow institution migrate docs |
| Bootstrap | `connectorctl bootstrap --apply` only if migrating secrets from env → vault |

## Automated check

```bash
make upgrade-persist-smoke
```

Writes a marker file in `data_dir`, stops, restarts, and confirms the marker survives.

## Rollback

Stop the node, restore the previous tarball binaries, start again. Do not delete `data_dir` unless you intend a clean install. Optional: `connectorctl restore` from pre-upgrade trust-domain backup.

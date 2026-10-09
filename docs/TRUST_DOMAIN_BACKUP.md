# Trust-domain backup bundle

One Connector OS **trust domain** = one node's durable state under `CONNECTOR_DATA_DIR` plus **out-of-band secrets** that must be restored from the operator vault / env (never invent a second SoT).

## Included in `connectorctl backup` tarball

| Path (under data_dir) | Role |
|----------------------|------|
| `engine.db` / engine store files | Engine projections |
| `kernel.redb` / VAC store | MemPackets / audit substrate |
| `connector.db` | Platform sqlite (if present) |
| `plugins/` | Plugin local state under data_dir |
| `*.pid` / runtime crumbs | Optional; restore may ignore |

Manifest file written beside the archive: `<backup>.manifest.json` with `node_version`, `data_dir`, file list + sha256, and `env_key_refs_required`.

## NOT in the tarball (must restore separately)

- `CONNECTOR_JWT_SECRET`
- `CONNECTOR_AUDIT_HMAC_KEY`
- `CONNECTOR_CFNI_SECRET` / `CONNECTOR_CAGE_CAP_SECRET`
- LLM / provider API keys (prefer vault after `connectorctl bootstrap --apply`)
- TraceTramp / WitnessCtl **external Postgres** (institution projections — back up per their docs)

## Commands

```bash
connectorctl backup -o /var/backups/connector-td.tar.gz
# Stop the node before restore:
connectorctl stop
connectorctl restore /var/backups/connector-td.tar.gz --yes
connectorctl start
connectorctl doctor
```

Partial tar failure **fails closed** (no `--ignore-failed-read`).

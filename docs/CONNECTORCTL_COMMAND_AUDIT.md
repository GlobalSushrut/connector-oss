# connectorctl command audit (vNext)

Ground truth: `platform/server/src/bin/connectorctl/`.

## Grammar

```
node | data | workload | govern | substrate | access | version | help | completion
```

Compat shims (one release): `status`, `health`, `doctor`, `logs`, `start`, `stop`, `restart`, `backup`, `restore`, `support-bundle`, `node-upgrade`/`upgrade`, `agents`.

## Evidence rule

Every success cites `node_api` (exact route) or `host` (systemd/journal/tar/fs). Removed soft-lie verbs (`pentest`, `threat`, `security`, `glue`, …) exit `3` with an explicit unavailable message.

## Packaging / UI

- Router serves filesystem UI when present; otherwise compile-time embed.
- `make package` includes `ui/` by default when Trunk dist exists (`CONNECTOR_PACKAGE_UI=0` to skip).

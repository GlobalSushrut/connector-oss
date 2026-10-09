# §10 Definition of Done — automated gates

Maps [`CONNECTOR_OS_ROADMAP.md`](../CONNECTOR_OS_ROADMAP.md) §10 items to commands we can run in CI or on a dev machine **without** a full clean VM or TLS terminator.

## One command

```bash
make section10-automated-smoke
```

Includes: `doctor`, `platform-test`, hygiene audits, TT/WC prod gate, prod dogfood, plugin tarballs, cage DNS check, story QA (if server up).

## Per-area mapping

| §10 area | Automated | Command |
|----------|-----------|---------|
| `make doctor` / CI green | Yes | `make prod-readiness-gate` or `make ci-beta-gate` |
| One tarball (kernel) | Yes | `make package` / `make clean-vm-tarball-smoke` |
| TraceTramp / WitnessCtl tarballs | Yes | `make package-plugins-smoke` |
| Cage `*.cnktros` not public | Yes | `dig tracetramp.cnktros @8.8.8.8` in gates |
| No hard-coded public URLs in plugins | Yes | `scripts/audit-plugin-cage-hosts.sh` |
| Service Map / TT / WC healthy | Partial | `make one-green-start-smoke` (Docker) |
| Jordan / Sam / Riley stories | Partial | `make story-qa-smoke` (server) |
| Dry-run CNP correlation | Yes | `story-qa-smoke` + platform tests |
| Reference workflow templates | Count | ≥3 `platform/server/resources/workflow_templates/*.ccl` |
| Trust-domain backup + node-upgrade docs | Yes | file-exists `docs/TRUST_DOMAIN_BACKUP.md` + `docs/PRODUCTION_UPGRADE.md` in `section10-automated-smoke` |
| Witness `.witness` offline | Yes | `make witness-bundle-smoke` |
| Helm install charts | Lint | `make helm-lint-smoke` |

## Still manual (v1)

- Dashboard-only secrets / LLM / networking after first boot
- LLM kill-primary → fallback from UI
- TLS on operator domain
- Lab demo video (zero terminal)
- Signed release (GPG/cosign keys on maintainer machine)
- 100-plugin scale / cold-start SLO on reference HW

See [`PRODUCTION_READINESS_CHECKLIST.md`](../PRODUCTION_READINESS_CHECKLIST.md) and [`KNOWN_LIMITATIONS.md`](KNOWN_LIMITATIONS.md).

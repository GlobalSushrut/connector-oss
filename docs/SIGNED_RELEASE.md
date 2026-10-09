# Signed release path (U8.1)

Engineering gate: `make prod-readiness-gate`.  
Final GO still requires a **clean VM** unpack + story QA (see `PRODUCTION_READINESS_CHECKLIST.md`).

## Signing (operator / release engineer)

1. Build tarball: `make package` → `dist/connector-os-<version>-<arch>-linux.tar.gz`
2. **GPG:**
   ```bash
   gpg --detach-sign --armor dist/connector-os-*.tar.gz
   ```
3. **cosign** (optional, keyless or key-pair):
   ```bash
   cosign sign-blob --yes --output-signature dist/connector-os.sig dist/connector-os-*.tar.gz
   ```
4. Publish tarball + `.asc` / `.sig` + checksums (`sha256sum`).

Automation of GPG/cosign in CI is a follow-up; do not claim signed releases until
artifacts are published with signatures for that version.

## Verify (operator)

```bash
make package
make sign-release-artifacts          # needs GPG_KEY_ID for .asc
make verify-release-artifacts        # sha256sum -c
REQUIRE_SIGNATURE=1 make verify-release-artifacts   # also gpg --verify *.asc
```

## Clean VM smoke

```bash
make clean-vm-tarball-smoke   # pack → extract → /health
```

Full Final GO (prod secrets + doctor + stories): [FINAL_GO_RUNBOOK.md](FINAL_GO_RUNBOOK.md).

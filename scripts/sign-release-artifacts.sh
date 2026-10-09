#!/usr/bin/env bash
# Optional GPG signing for dist/*.tar.gz (maintainer workstation).
# CI produces SHA256SUMS; run this locally when RELEASE_SIGNING_KEY is set.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST="${CONNECTOR_PACKAGE_DIR:-$ROOT/dist}"

if [[ -z "${GPG_KEY_ID:-}" ]]; then
  echo "[skip] GPG_KEY_ID not set — see docs/PRODUCTION_HARDENING.md for manual cosign/GPG"
  exit 0
fi

echo "== sign-release-artifacts =="
shopt -s nullglob
files=("$DIST"/*.tar.gz)
if [[ ${#files[@]} -eq 0 ]]; then
  echo "no tarballs in $DIST" >&2
  exit 1
fi

for f in "${files[@]}"; do
  echo "signing $(basename "$f") …"
  gpg --default-key "$GPG_KEY_ID" --detach-sign --armor "$f"
done
echo "[ok] detached signatures alongside tarballs"

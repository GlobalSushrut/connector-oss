#!/usr/bin/env bash
# Verify dist/ release tarball checksums (+ optional GPG when REQUIRE_SIGNATURE=1).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST="${DIST:-$ROOT/dist}"
cd "$DIST"

if [[ ! -f SHA256SUMS ]]; then
  echo "error: $DIST/SHA256SUMS missing — run make package first" >&2
  exit 1
fi

echo "==> sha256sum -c SHA256SUMS"
sha256sum -c SHA256SUMS

shopt -s nullglob
tarballs=(connector-os-*.tar.gz)
if [[ ${#tarballs[@]} -eq 0 ]]; then
  echo "error: no connector-os-*.tar.gz in $DIST" >&2
  exit 1
fi

if [[ "${REQUIRE_SIGNATURE:-0}" == "1" ]]; then
  for t in "${tarballs[@]}"; do
    if [[ -f "${t}.asc" ]]; then
      echo "==> gpg --verify ${t}.asc"
      gpg --verify "${t}.asc" "$t"
    elif [[ -f "${t%.tar.gz}.sig" ]] || [[ -f "${t}.sig" ]]; then
      echo "warn: found .sig but cosign verify not automated here — check docs/SIGNED_RELEASE.md" >&2
    else
      echo "error: REQUIRE_SIGNATURE=1 but no ${t}.asc" >&2
      exit 1
    fi
  done
else
  echo "note: REQUIRE_SIGNATURE unset — checksums only (see docs/SIGNED_RELEASE.md)"
fi

echo "OK: release artifacts verified"

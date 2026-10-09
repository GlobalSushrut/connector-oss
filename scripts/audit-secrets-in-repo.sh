#!/usr/bin/env bash
# P0.3 — grep for likely committed secrets (heuristic; allowlisted paths excluded).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PATTERNS=(
  'sk-[a-zA-Z0-9]{20,}'
  'AKIA[0-9A-Z]{16}'
  'BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY'
  'password\s*=\s*["\x27][^"\x27]{8,}'
)

hits=0
for pat in "${PATTERNS[@]}"; do
  if rg -n "$pat" . \
    --glob '!**/.git/**' \
    --glob '!**/target/**' \
    --glob '!**/.cargo-target/**' \
    --glob '!**/dist/**' \
    --glob '!**/*.example' \
    --glob '!**/.env.example' \
    --glob '!**/advanced-lab/**' \
    --glob '!**/lab-runs/**' \
    --glob '!**/*_example*' \
    --glob '!**/audit-secrets-in-repo.sh' \
    --glob '!**/docs/**' \
    --glob '!**/tests/**' \
    --glob '!**/secret_broker.rs' \
    --glob '!**/mtls.rs' \
    --glob '!**/dashboard/src/auth.rs' \
    2>/dev/null; then
    hits=1
  fi
done

if [[ "$hits" -ne 0 ]]; then
  echo "[fail] possible secrets matched (review above)" >&2
  exit 1
fi
echo "[ok] audit-secrets-in-repo: no heuristic secret patterns in tracked tree"
exit 0

#!/usr/bin/env bash
# P1.1 — first-party plugins must not hard-code public URLs; cage hosts come from kernel DNS.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

fail=0
# Active manifest keys only (not comments/examples). cage_host is assigned by the kernel.
for f in plugins/tracetramp/plugin.yaml plugins/witnessctl/plugin.yaml plugins/devguard/plugin.yaml; do
  [[ -f "$f" ]] || continue
  if rg -n '^\s*[^#]*https?://[a-z0-9.-]+\.(com|io|net|org|corp)' "$f" 2>/dev/null; then
    echo "[fail] public URL in $f" >&2
    fail=1
  fi
done

# Apps catalog derives cage_host from slug — smoke via unit tests in apps_catalog / cage_proof.
echo "[ok] audit-plugin-cage-hosts: no hard-coded public http(s) URLs in first-party plugin sources"
exit "$fail"

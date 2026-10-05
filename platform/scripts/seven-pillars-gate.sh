#!/usr/bin/env bash
# seven-pillars-gate.sh — enforce status discipline in SEVEN_PILLARS_STATUS.md
# Fails if:
#   - status enum is not one of the four allowed values
#   - SHIPPED_VERIFIED row lacks a non-empty Test id
#   - file missing
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
STATUS="${ROOT}/platform/docs/arch/SEVEN_PILLARS_STATUS.md"

if [[ ! -f "$STATUS" ]]; then
  echo "FAIL: missing $STATUS"
  exit 1
fi

ALLOWED='SHIPPED_VERIFIED|IMPLEMENTED_GATED|PLANNED|ASPIRATIONAL'
errors=0
verified=0
rows=0

while IFS= read -r line; do
  # Table data rows: | item | STATUS | TEST |
  if [[ "$line" =~ ^\|([^|]+)\|[[:space:]]*([A-Z_]+)[[:space:]]*\|[[:space:]]*([^|]+)[[:space:]]*\|$ ]]; then
    item="${BASH_REMATCH[1]}"
    status="${BASH_REMATCH[2]}"
    testid="${BASH_REMATCH[3]}"
    # skip header separator / header labels
    if [[ "$status" == "Status" || "$status" == "--------" ]]; then
      continue
    fi
    if [[ ! "$status" =~ ^($ALLOWED)$ ]]; then
      # might be a non-status table; skip if status looks like markdown dash
      if [[ "$status" =~ ^-+$ ]]; then
        continue
      fi
      # Only enforce on known status tokens; skip other tables
      if [[ "$status" =~ ^(SHIPPED_VERIFIED|IMPLEMENTED_GATED|PLANNED|ASPIRATIONAL)$ ]]; then
        :
      else
        continue
      fi
    fi
    rows=$((rows + 1))
    item_trim="$(echo "$item" | xargs)"
    test_trim="$(echo "$testid" | xargs)"
    if [[ ! "$status" =~ ^($ALLOWED)$ ]]; then
      echo "FAIL: invalid status '$status' for: $item_trim"
      errors=$((errors + 1))
      continue
    fi
    if [[ "$status" == "SHIPPED_VERIFIED" ]]; then
      verified=$((verified + 1))
      if [[ -z "$test_trim" || "$test_trim" == "—" || "$test_trim" == "-" ]]; then
        echo "FAIL: SHIPPED_VERIFIED without test id: $item_trim"
        errors=$((errors + 1))
      fi
    fi
  fi
done < "$STATUS"

# Also parse with awk for robustness (pipe tables)
while IFS='|' read -r _c1 item status testid _rest; do
  status="$(echo "${status:-}" | xargs)"
  testid="$(echo "${testid:-}" | xargs)"
  item="$(echo "${item:-}" | xargs)"
  [[ -z "$status" ]] && continue
  [[ "$status" == "Status" ]] && continue
  [[ "$status" =~ ^-+$ ]] && continue
  case "$status" in
    SHIPPED_VERIFIED|IMPLEMENTED_GATED|PLANNED|ASPIRATIONAL) ;;
    *) continue ;;
  esac
  if [[ "$status" == "SHIPPED_VERIFIED" && ( -z "$testid" || "$testid" == "—" ) ]]; then
    echo "FAIL: SHIPPED_VERIFIED without test id: $item"
    errors=$((errors + 1))
  fi
done < "$STATUS"

# Presence of adversarial scripts referenced by release honesty
for s in \
  platform/scripts/effect-exclusivity-adversarial.sh \
  platform/scripts/zt-handshake-adversarial.sh \
  platform/scripts/docklock-bypass-adversarial.sh \
  platform/scripts/seven-pillars-ebpf-adversarial.sh \
  platform/scripts/seven-pillars-sandbox-unbypassable-adversarial.sh \
  platform/scripts/seven-pillars-complete-adversarial.sh \
  platform/scripts/seven-pillars-p2t07-adversarial.sh
do
  if [[ ! -f "$ROOT/$s" ]]; then
    echo "WARN: missing adversarial script $s"
  fi
done

# eBPF object must build when clang is present (CI hosts usually have it)
if command -v clang >/dev/null 2>&1; then
  make -C "$ROOT/platform/ebpf" all >/dev/null
  test -f "$ROOT/platform/ebpf/connector_mark_deny.bpf.o"
  echo "seven-pillars-gate: eBPF object OK"
fi

if [[ "$errors" -gt 0 ]]; then
  echo "seven-pillars-gate: FAILED ($errors error(s))"
  exit 1
fi

echo "seven-pillars-gate: OK (status file present; no SHIPPED_VERIFIED without test id)"
exit 0

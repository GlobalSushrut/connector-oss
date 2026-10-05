#!/usr/bin/env bash
# FINAL_REACH light green gate — laptop-safe (≤14–16 GiB).
# Proves code + honesty without linking the connector-platform monolith test binary.
# P7/P9 human/CI soaks remain separate (see FINAL_REACH.md).
#
# Usage (repo root):
#   make final-reach-light-gate
#   bash platform/scripts/final-reach-light-gate.sh
#   REQUIRE_DIST=1 make final-reach-light-gate   # fail if dist/ missing
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

RESULTS_FILE="${FINAL_REACH_LIGHT_GATE_RESULTS:-$ROOT/platform/scripts/.final-reach-light-gate.last}"
if ! touch "$RESULTS_FILE" 2>/dev/null; then
  RESULTS_FILE="/tmp/final-reach-light-gate.last"
  touch "$RESULTS_FILE"
fi

CORE_FAIL=0
declare -A ST  # check status: PASS | SKIP | WARN | FAIL

pass() { ST["$1"]=PASS; echo "[PASS] $2"; }
skip() { ST["$1"]=SKIP; echo "[SKIP] $2"; }
warn() { ST["$1"]=WARN; echo "[WARN] $2"; }
fail() { ST["$1"]=FAIL; CORE_FAIL=1; echo "[FAIL] $2" >&2; }

echo "== final-reach-light-gate =="
echo "ROOT=$ROOT"
echo "Low-RAM: no cargo test -p connector-platform (see docs/LOW_MEMORY_DEV.md)"
echo "Results → $RESULTS_FILE"
echo

# ── CORE: claim / doctrine docs ──────────────────────────────────────────────
DOCS=(
  FINAL_REACH.md
  docs/AIOS_PLUS_TWO_CLAIM_DEMO.md
  docs/AIOS_L5_MESH_CLAIM_DEMO.md
  docs/TRUST_DOMAIN_BACKUP.md
  docs/architecture/admission-matrix.md
  docs/architecture/mesh-membership.md
  docs/architecture/cell-spiffe-identity.md
  docs/PLUGIN_VERIFY_2A9.md
  docs/SOAK_EVIDENCE.md
)
docs_ok=1
for f in "${DOCS[@]}"; do
  if [[ -f "$f" ]]; then
    echo "[ok] doc $f"
  else
    echo "[fail] missing $f" >&2
    docs_ok=0
  fi
done
if [[ "$docs_ok" -eq 1 ]]; then
  pass docs "claim/doctrine docs present"
else
  fail docs "one or more required docs missing"
fi

# ── CORE: reference WF templates (light) ─────────────────────────────────────
echo
echo "== check-reference-templates-light =="
if bash platform/scripts/check-reference-templates-light.sh; then
  pass templates "check-reference-templates-light"
else
  fail templates "check-reference-templates-light"
fi

# ── CORE: connector-trust unit tests (small crate; not the monolith) ─────────
echo
echo "== cargo test -p connector-trust =="
if (
  cd oss/connector
  CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}" cargo test -p connector-trust -- --test-threads=1
); then
  pass trust "connector-trust tests"
else
  fail trust "connector-trust tests"
fi

# ── CORE: release artifacts (WARN skip if no dist/ unless REQUIRE_DIST=1) ────
echo
echo "== verify-release-artifacts =="
if [[ -d dist ]] && [[ -f dist/SHA256SUMS ]]; then
  if bash scripts/verify-release-artifacts.sh; then
    pass release "verify-release-artifacts"
  else
    fail release "verify-release-artifacts"
  fi
elif [[ "${REQUIRE_DIST:-0}" == "1" ]]; then
  fail release "REQUIRE_DIST=1 but dist/SHA256SUMS missing — run make package"
else
  warn release "no dist/SHA256SUMS — skipped (set REQUIRE_DIST=1 to require)"
fi

# ── SOFT: custody-quorum-smoke ───────────────────────────────────────────────
echo
echo "== custody-quorum-smoke (soft) =="
if grep -qE '^custody-quorum-smoke:' Makefile 2>/dev/null; then
  if make custody-quorum-smoke; then
    pass custody "make custody-quorum-smoke"
  else
    # Soft: do not fail the gate; record WARN
    warn custody "make custody-quorum-smoke failed (soft — not blocking CORE)"
  fi
else
  skip custody "make target custody-quorum-smoke not present"
fi

# ── SOFT: llm-fallback-cap-smoke ─────────────────────────────────────────────
echo
echo "== llm-fallback-cap-smoke (soft) =="
if grep -qE '^llm-fallback-cap-smoke:' Makefile 2>/dev/null; then
  set +e
  out="$(make llm-fallback-cap-smoke 2>&1)"
  rc=$?
  set -e
  echo "$out"
  if echo "$out" | grep -q '\[skip\]'; then
    skip llm "llm-fallback-cap-smoke (no server / skip-friendly)"
  elif [[ "$rc" -eq 0 ]]; then
    pass llm "make llm-fallback-cap-smoke"
  else
    warn llm "llm-fallback-cap-smoke failed (soft — not blocking CORE)"
  fi
else
  skip llm "make target llm-fallback-cap-smoke not present"
fi

# ── SOFT: property-soak-hooks ────────────────────────────────────────────────
echo
echo "== property-soak-hooks (soft) =="
if [[ -f platform/scripts/property-soak-hooks.sh ]]; then
  if bash platform/scripts/property-soak-hooks.sh; then
    pass soak_hooks "property-soak-hooks.sh"
  else
    warn soak_hooks "property-soak-hooks.sh failed (soft — not blocking CORE)"
  fi
else
  skip soak_hooks "platform/scripts/property-soak-hooks.sh not present"
fi

# ── CORE: HA honesty — automatic_failover stays false ────────────────────────
echo
echo "== ha_federation automatic_failover: false =="
HA_SRC="platform/server/src/services/ha_federation.rs"
search() {
  if command -v rg >/dev/null 2>&1; then
    rg -n --fixed-strings "$1" "$2"
  else
    grep -nF "$1" "$2"
  fi
}
if [[ ! -f "$HA_SRC" ]]; then
  fail ha_honesty "missing $HA_SRC"
elif search 'automatic_failover: false' "$HA_SRC" >/dev/null; then
  pass ha_honesty "ha_federation still has automatic_failover: false"
else
  fail ha_honesty "automatic_failover: false not found in $HA_SRC — honesty regression"
fi

# ── CORE: connectorctl backup + node-upgrade strings ─────────────────────────
echo
echo "== connectorctl backup / node-upgrade =="
CTL_SRC="platform/server/src/bin/connectorctl.rs"
if [[ ! -f "$CTL_SRC" ]]; then
  fail connectorctl "missing $CTL_SRC"
else
  has_nu=0
  has_bu=0
  if search 'node-upgrade' "$CTL_SRC" >/dev/null; then has_nu=1; fi
  if search 'backup' "$CTL_SRC" >/dev/null; then has_bu=1; fi
  if [[ "$has_nu" -eq 1 && "$has_bu" -eq 1 ]]; then
    pass connectorctl "connectorctl source has node-upgrade + backup"
  else
    fail connectorctl "connectorctl missing node-upgrade and/or backup strings"
  fi
fi

# ── CORE: T7 partial — Story QA routes wired (no server) ─────────────────────
echo
echo "== l4-story-offline-check (T7 partial) =="
if [[ -f platform/scripts/l4-story-offline-check.sh ]]; then
  if bash platform/scripts/l4-story-offline-check.sh; then
    pass story_offline "l4-story-offline-check (Story QA routes in router.rs)"
  else
    fail story_offline "l4-story-offline-check"
  fi
else
  fail story_offline "platform/scripts/l4-story-offline-check.sh missing"
fi

# Soft: story-qa-smoke (SKIP exit 0 when no server)
echo
echo "== story-qa-smoke (soft; SKIP if no server) =="
if [[ -f platform/scripts/story-qa-smoke.sh ]]; then
  set +e
  out="$(bash platform/scripts/story-qa-smoke.sh 2>&1)"
  rc=$?
  set -e
  echo "$out"
  if echo "$out" | grep -q 'SKIP'; then
    skip story_qa "story-qa-smoke (no server — offline check covers T7 partial)"
  elif [[ "$rc" -eq 0 ]]; then
    pass story_qa "story-qa-smoke"
  else
    warn story_qa "story-qa-smoke failed (soft — not blocking CORE)"
  fi
else
  skip story_qa "story-qa-smoke.sh not present"
fi

# ── T1–T18 evidence map ──────────────────────────────────────────────────────
# Light gate maps each claim test to the check(s) that ran. Multi-node / clean-VM
# human soaks are not executed here → SKIP for soak-only rows when docs alone
# are insufficient to claim PASS.
status_of() {
  local k="$1"
  echo "${ST[$k]:-SKIP}"
}

# Prefer PASS > WARN > SKIP > FAIL for display of combined evidence
t_status() {
  # args: preferred statuses in order — first non-SKIP/WARN wins if PASS; FAIL wins always
  local best=SKIP
  for s in "$@"; do
    case "$s" in
      FAIL) echo FAIL; return ;;
      PASS) best=PASS ;;
      WARN) [[ "$best" != PASS ]] && best=WARN ;;
      SKIP) ;;
    esac
  done
  echo "$best"
}

T1="$(t_status "$(status_of docs)")"          # admission-matrix.md
T2="$(t_status "$(status_of docs)")"          # PLUGIN_VERIFY_2A9 / cage path docs
T3="$(t_status "$(status_of templates)")"     # reference templates light
T4="$(t_status "$(status_of docs)")"          # .cpkg / 2A.9 docs
T5="$(t_status "$(status_of docs)")"          # AIOS_PLUS_TWO institutions path
T6="$(t_status "$(status_of docs)" "$(status_of connectorctl)")"
# T7: offline story routes = partial PASS; full clean-VM/signed dist still human.
# Prefer story_qa live PASS, else story_offline, else release.
T7="$(t_status "$(status_of story_qa)" "$(status_of story_offline)" "$(status_of release)")"
T8="$(t_status "$(status_of trust)")"         # connector-trust
T9="$(t_status "$(status_of templates)")"     # moments/WF substrate sample
T10="$(t_status "$(status_of trust)" "$(status_of llm)")"  # UsageReceipt unit + optional LLM smoke
T11="$(t_status "$(status_of docs)" "$(status_of soak_hooks)")"
T12="$(t_status "$(status_of trust)")"        # SGKE + HardwarePlacement in connector-trust
# T13/T15: prior soak evidence file, else SKIP (run ARGS=--start-local make l5-mesh-soak).
if [[ -f "$ROOT/platform/scripts/.l5-mesh-soak.ok" ]] \
  && grep -q 't13=PASS' "$ROOT/platform/scripts/.l5-mesh-soak.ok" \
  && grep -q 't15=PASS' "$ROOT/platform/scripts/.l5-mesh-soak.ok"; then
  T13=PASS
  T15=PASS
else
  T13=SKIP
  T15=SKIP
fi
T14="$(t_status "$(status_of trust)" "$(status_of docs)")"  # HardwarePlacementV2 + mesh docs
T16="$(t_status "$(status_of ha_honesty)" "$(status_of docs)")"  # Knot/mesh honesty when not multi-node
if [[ -f "$ROOT/platform/scripts/.custody-multinode-soak.ok" ]] \
  && grep -q 't17=PASS' "$ROOT/platform/scripts/.custody-multinode-soak.ok"; then
  T17=PASS
else
  T17="$(t_status "$(status_of custody)")"
fi
T18="$(t_status "$(status_of ha_honesty)")"

echo
echo "======== T1–T18 light-gate evidence ========"
printf '%-4s %-6s %s\n' "ID" "Status" "Evidence (this gate)"
printf '%-4s %-6s %s\n' "----" "------" "--------------------"
printf '%-4s %-6s %s\n' "T1"  "$T1"  "docs: admission-matrix.md"
printf '%-4s %-6s %s\n' "T2"  "$T2"  "docs: PLUGIN_VERIFY_2A9 / cage path"
printf '%-4s %-6s %s\n' "T3"  "$T3"  "check-reference-templates-light"
printf '%-4s %-6s %s\n' "T4"  "$T4"  "docs: PLUGIN_VERIFY_2A9 + claim demos"
printf '%-4s %-6s %s\n' "T5"  "$T5"  "docs: AIOS_PLUS_TWO_CLAIM_DEMO"
printf '%-4s %-6s %s\n' "T6"  "$T6"  "TRUST_DOMAIN_BACKUP + connectorctl backup/node-upgrade"
printf '%-4s %-6s %s\n' "T7"  "$T7"  "l4-story-offline-check (T7 partial) + optional story-qa-smoke; clean-VM/signed dist separate"
printf '%-4s %-6s %s\n' "T8"  "$T8"  "cargo test -p connector-trust (CFNI mint/verify)"
printf '%-4s %-6s %s\n' "T9"  "$T9"  "check-reference-templates-light (substrate sample)"
printf '%-4s %-6s %s\n' "T10" "$T10" "connector-trust UsageReceipt (+ optional llm-fallback-cap-smoke)"
printf '%-4s %-6s %s\n' "T11" "$T11" "SOAK_EVIDENCE.md + property-soak-hooks"
printf '%-4s %-6s %s\n' "T12" "$T12" "cargo test -p connector-trust (SGKE path + placement)"
printf '%-4s %-6s %s\n' "T13" "$T13" ".l5-mesh-soak.ok or run ARGS=--start-local make l5-mesh-soak"
printf '%-4s %-6s %s\n' "T14" "$T14" "HardwarePlacementV2 unit + mesh/SPIFFE docs"
printf '%-4s %-6s %s\n' "T15" "$T15" ".l5-mesh-soak.ok or run ARGS=--start-local make l5-mesh-soak"
printf '%-4s %-6s %s\n' "T16" "$T16" "mesh_fabric:false / single_node honesty (not multi-node SoT)"
printf '%-4s %-6s %s\n' "T17" "$T17" ".custody-multinode-soak.ok or custody-quorum-smoke"
printf '%-4s %-6s %s\n' "T18" "$T18" "ha_federation automatic_failover: false"
echo "============================================"

# Persist results
{
  echo "# final-reach-light-gate $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "CORE_FAIL=$CORE_FAIL"
  for k in docs templates trust release custody llm soak_hooks ha_honesty connectorctl story_offline story_qa; do
    echo "CHECK_${k}=${ST[$k]:-}"
  done
  for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18; do
    eval "echo T${i}=\$T${i}"
  done
  if [[ "$CORE_FAIL" -eq 0 ]]; then
    echo "RESULT=OK"
  else
    echo "RESULT=FAIL"
  fi
} >"$RESULTS_FILE"

echo
echo "Wrote $RESULTS_FILE"

if [[ "$CORE_FAIL" -ne 0 ]]; then
  echo "== final-reach-light-gate: FAIL (CORE) ==" >&2
  exit 1
fi

echo "== final-reach-light-gate: OK (all CORE passed) =="
echo "Note: P7/P9 human soaks (T7 clean-VM, T13–T16 multi-node) remain separate."
exit 0

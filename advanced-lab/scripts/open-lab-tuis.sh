#!/usr/bin/env bash
# Lab runner helper (terminal UIs were removed from TraceTramp and WitnessCtl).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
# shellcheck source=/dev/null
source "$ROOT/advanced-lab/scripts/lab-tui-env.sh"

usage() {
  cat <<'EOF'
Usage: open-lab-tuis.sh <command>

  traffic     Run YAML lab scenarios (Docker lab-runner; needs DEEPSEEK_API_KEY in advanced-lab/.env).

  print-env   Print host URLs and tokens useful for curl / a future web UI (source this file instead).

EOF
}

cmd="${1:-}"
if [[ -z "$cmd" || "$cmd" == "-h" || "$cmd" == "--help" ]]; then
  usage
  exit 0
fi

case "$cmd" in
  print-env)
    cat "$ROOT/advanced-lab/scripts/lab-tui-env.sh"
    ;;
  traffic)
    cd "$ROOT"
    if [[ ! -f "$ROOT/advanced-lab/.env" ]]; then
      echo "Missing advanced-lab/.env (need DEEPSEEK_API_KEY for lab-runner)." >&2
      exit 1
    fi
    COMPOSE_PROFILES=lab docker compose --env-file "$ROOT/advanced-lab/.env" \
      -f "$ROOT/lab/docker-compose.premium-lab.yml" \
      -f "$ROOT/lab/advanced.yml" \
      run --rm lab-runner python -m lab_runner.lab_run --only all --output-dir /out
    echo "Reports under advanced-lab/outputs/lab-runs/<timestamp>/"
    ;;
  *)
    usage
    exit 1
    ;;
esac

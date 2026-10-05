#!/usr/bin/env bash
# Preflight checks before enabling Connector host kernel enforcement (nft + eBPF).
# Exit 0 = likely OK; non-zero = fix host or config before prod.
#
# Optional: --with-connector  After host checks, run connectorctl against CONNECTOR_API_URL
# (requires connectorctl on PATH and CONNECTOR_API_KEY unless dev bypass is active on that node).
set -euo pipefail

WITH_CONNECTOR=0
for arg in "$@"; do
  case "$arg" in
    --with-connector) WITH_CONNECTOR=1 ;;
    -h|--help)
      echo "Usage: $0 [--with-connector]"
      echo "  --with-connector  Run connectorctl status + doctor (JSON) when CONNECTOR_API_URL is set"
      echo "                    (requires jq or python3: fail if shell_production_env.warnings non-empty"
      echo "                    or phase_5_operator.production_dev_mode_hygiene != ok on status JSON;"
      echo "                    same checks on doctor JSON doctor_extensions when doctor exits 0;"
      echo "                    optional: process_env_operator_display_line must match between top-level and phase_5_operator (status) and root vs doctor_extensions vs phase_5_operator (doctor))"
      exit 0
      ;;
  esac
done

warn() { echo "[warn] $*" >&2; }
err() { echo "[err] $*" >&2; exit 1; }
ok() { echo "[ok] $*"; }

[[ "$(id -u)" -eq 0 ]] || warn "Not root — cgroup/nft/bpf checks may be incomplete"

# cgroup v2
if [[ -f /sys/fs/cgroup/cgroup.controllers ]]; then
  ok "cgroup v2 unified hierarchy present (/sys/fs/cgroup/cgroup.controllers)"
else
  err "cgroup v2 not detected — host kernel enforcement requires unified cgroup v2"
fi

# nftables
if command -v nft >/dev/null 2>&1; then
  ok "nft present: $(command -v nft)"
  nft --version 2>/dev/null | head -1 || true
else
  err "nft not installed"
fi

# optional bpftool (recommended for prod ops)
if command -v bpftool >/dev/null 2>&1; then
  ok "bpftool present: $(command -v bpftool)"
  bpftool version 2>/dev/null | head -3 || true
else
  warn "bpftool not installed — install for BPF map/link debugging"
fi

# kernel (rough floor for cgroup sock_addr / nft socket cgroupv2)
kver=$(uname -r | cut -d. -f1-2)
ok "kernel release: $(uname -r)"

# BPF filesystem
if [[ -d /sys/fs/bpf ]]; then
  ok "/sys/fs/bpf mounted"
else
  warn "/sys/fs/bpf not mounted — pin+link workflows need bpffs"
fi

# systemd (optional but typical for NFTSet= / scopes)
if command -v systemctl >/dev/null 2>&1; then
  ok "systemctl present"
else
  warn "systemctl not found — non-systemd hosts need custom cgroup watcher in connector-kerneld"
fi

echo ""
echo "Preflight finished. Review warnings before enabling CONNECTOR_KERNEL_ENFORCE (or equivalent)."

if [[ "$WITH_CONNECTOR" -eq 1 ]]; then
  echo ""
  echo "=== Optional: connector process checks (--with-connector) ==="
  if ! command -v connectorctl >/dev/null 2>&1; then
    err "connectorctl not on PATH — install platform binary or add to PATH"
  fi
  ok "connectorctl: $(command -v connectorctl)"
  if [[ -z "${CONNECTOR_API_URL:-}" ]]; then
    err "CONNECTOR_API_URL unset — export it (e.g. http://127.0.0.1:9091) for connector checks"
  fi
  ok "CONNECTOR_API_URL=$CONNECTOR_API_URL"
  ST="/tmp/connector-preflight-status.$$"
  ST_JSON="${ST}.json"
  if connectorctl status --json >"$ST_JSON" 2>"${ST}.err"; then
    ok "connectorctl status --json"
    shell_warns=0
    hygiene="ok"
    if command -v jq >/dev/null 2>&1; then
      shell_warns=$(jq '.shell_production_env.warnings // [] | length' "$ST_JSON" 2>/dev/null || echo 0)
      hygiene=$(jq -r '(.phase_5_operator // {}).production_dev_mode_hygiene // "ok"' "$ST_JSON" 2>/dev/null || echo ok)
    elif command -v python3 >/dev/null 2>&1; then
      shell_warns=$(python3 -c "import json,sys; d=json.load(open(sys.argv[1])); w=(d.get('shell_production_env') or {}); print(len(w.get('warnings') or []))" "$ST_JSON" 2>/dev/null || echo 0)
      hygiene=$(python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print((d.get('phase_5_operator') or {}).get('production_dev_mode_hygiene') or 'ok')" "$ST_JSON" 2>/dev/null || echo ok)
    else
      warn "install jq or python3 — skipping shell_production_env / production_dev_mode_hygiene checks on status JSON"
    fi
    shell_warns=$(echo "$shell_warns" | tr -d '[:space:]')
    if [[ "$shell_warns" =~ ^[0-9]+$ ]] && [[ "$shell_warns" -gt 0 ]]; then
      err "status --json: shell_production_env has ${shell_warns} warning(s) (production shell + CONNECTOR_DEV_MODE?) — fix shell env or systemd drop-ins; keep $ST_JSON"
    fi
    if [[ "$hygiene" != "ok" ]]; then
      err "status --json: phase_5_operator.production_dev_mode_hygiene=${hygiene} — align CONNECTOR_ENV / CONNECTOR_DEV_MODE / CONNECTOR_PRODUCTION_REJECT_DEV_MODE on the connector unit; keep $ST_JSON"
    fi
    if command -v jq >/dev/null 2>&1; then
      st_mismatch=$(jq -r '
        (.process_env_operator_display_line // "") as $a |
        (.phase_5_operator.process_env_operator_display_line // "") as $b |
        if ($a != "" and $b != "" and $a != $b) then "yes" else "no" end
      ' "$ST_JSON" 2>/dev/null || echo no)
      if [[ "$st_mismatch" == "yes" ]]; then
        err "status --json: process_env_operator_display_line top-level != phase_5_operator (connectorctl bug or tampered JSON); keep $ST_JSON"
      fi
    elif command -v python3 >/dev/null 2>&1; then
      if ! python3 -c "
import json,sys
d=json.load(open(sys.argv[1]))
a=d.get('process_env_operator_display_line')
b=(d.get('phase_5_operator') or {}).get('process_env_operator_display_line')
sa=a.strip() if isinstance(a,str) else ''
sb=b.strip() if isinstance(b,str) else ''
if sa and sb and sa!=sb:
    sys.exit(1)
" "$ST_JSON" 2>/dev/null; then
        err "status --json: process_env_operator_display_line top-level != phase_5_operator; keep $ST_JSON"
      fi
    fi
    rm -f "$ST_JSON" "${ST}.err"
  else
    err "connectorctl status failed — diagnostics in ${ST}.err"
  fi
  DOC="/tmp/connector-preflight-doctor.$$"
  DOC_JSON="${DOC}.json"
  if connectorctl doctor --json >"$DOC_JSON" 2>"${DOC}.err"; then
    ok "connectorctl doctor --json (exit 0 — node healthy)"
    d_shell=0
    d_hyg="ok"
    if command -v jq >/dev/null 2>&1; then
      d_shell=$(jq '.doctor_extensions.shell_production_env.warnings // [] | length' "$DOC_JSON" 2>/dev/null || echo 0)
      d_hyg=$(jq -r '(.doctor_extensions.phase_5_operator // {}).production_dev_mode_hygiene // "ok"' "$DOC_JSON" 2>/dev/null || echo ok)
    elif command -v python3 >/dev/null 2>&1; then
      d_shell=$(python3 -c "import json,sys; d=json.load(open(sys.argv[1])); de=d.get('doctor_extensions') or {}; w=(de.get('shell_production_env') or {}); print(len(w.get('warnings') or []))" "$DOC_JSON" 2>/dev/null || echo 0)
      d_hyg=$(python3 -c "import json,sys; d=json.load(open(sys.argv[1])); p=(d.get('doctor_extensions') or {}).get('phase_5_operator') or {}; print(p.get('production_dev_mode_hygiene') or 'ok')" "$DOC_JSON" 2>/dev/null || echo ok)
    else
      warn "install jq or python3 — skipping doctor_extensions hygiene checks on doctor JSON"
    fi
    d_shell=$(echo "$d_shell" | tr -d '[:space:]')
    if [[ "$d_shell" =~ ^[0-9]+$ ]] && [[ "$d_shell" -gt 0 ]]; then
      err "doctor --json: doctor_extensions.shell_production_env has ${d_shell} warning(s) — fix shell env; keep $DOC_JSON"
    fi
    if [[ "$d_hyg" != "ok" ]]; then
      err "doctor --json: doctor_extensions.phase_5_operator.production_dev_mode_hygiene=${d_hyg} — keep $DOC_JSON"
    fi
    if command -v jq >/dev/null 2>&1; then
      doc_mismatch=$(jq -r '
        (.process_env_operator_display_line // "") as $r |
        (.doctor_extensions.process_env_operator_display_line // "") as $e |
        (.doctor_extensions.phase_5_operator.process_env_operator_display_line // "") as $p |
        ([$r,$e,$p] | map(select(. != "")) | unique | length) as $n |
        if ([$r,$e,$p] | map(select(. != "")) | length) > 0 and $n > 1 then "yes" else "no" end
      ' "$DOC_JSON" 2>/dev/null || echo no)
      if [[ "$doc_mismatch" == "yes" ]]; then
        err "doctor --json: process_env_operator_display_line disagree across root / doctor_extensions / phase_5_operator; keep $DOC_JSON"
      fi
    elif command -v python3 >/dev/null 2>&1; then
      if ! python3 -c "
import json,sys
d=json.load(open(sys.argv[1]))
r=d.get('process_env_operator_display_line')
de=d.get('doctor_extensions') or {}
e=de.get('process_env_operator_display_line')
p=(de.get('phase_5_operator') or {}).get('process_env_operator_display_line')
vals=[]
for x in (r,e,p):
    if isinstance(x,str) and x.strip():
        vals.append(x.strip())
if len(set(vals)) > 1:
    sys.exit(1)
" "$DOC_JSON" 2>/dev/null; then
        err "doctor --json: process_env_operator_display_line disagree across root / doctor_extensions / phase_5_operator; keep $DOC_JSON"
      fi
    fi
    rm -f "$DOC_JSON" "${DOC}.err"
  else
    warn "connectorctl doctor --json exited non-zero (node unhealthy or misconfigured) — keep ${DOC}.err ${DOC}.json for inspection"
  fi
fi

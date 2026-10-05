#!/usr/bin/env bash
# Low-RAM check for bundled WF templates (no cargo / no platform rebuild).
# Full CCL parse: CI `all_bundled_templates_compile` only — never run on low-memory laptops.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TPL="$ROOT/platform/server/resources/workflow_templates"
RT="$ROOT/platform/server/src/services/workflow_runtime.rs"
SM="$ROOT/platform/server/src/operator/surface_merge.rs"

need() { test -f "$1" || { echo "[fail] missing $1" >&2; exit 1; }; }

for id in hitl_approve_audit pii_redaction_pipeline incident_slack_jira substrate_memory_moment; do
  need "$TPL/${id}.ccl"
  need "$TPL/${id}.operator.json"
  rg -q "\"id\": \"${id}\"" "$RT" || { echo "[fail] $id not in list_reference_templates" >&2; exit 1; }
  rg -q "\"${id}\"" "$SM" || { echo "[fail] $id not in bundled_reference_surface" >&2; exit 1; }
done

# Structural CCL checks for the substrate-only sample (U6.4)
CCL="$TPL/substrate_memory_moment.ccl"
for needle in \
  'contract substrate_memory_moment' \
  'tool memory_write' \
  'tool moment_commit' \
  'tool usage_record' \
  'tool artifact_append' \
  'cost_usd: 0.00'
do
  rg -q -F "$needle" "$CCL" || { echo "[fail] CCL missing: $needle" >&2; exit 1; }
done

# Must not declare institution tools or non-empty institutions list
if rg -n '^\s*tool (tracetramp|witnessctl|devguard)' "$CCL"; then
  echo "[fail] substrate_memory_moment must not declare TT/WC/DG tools" >&2
  exit 1
fi

ROOT="$ROOT" python3 - <<PY
import json, os, pathlib
root = os.environ["ROOT"]
p = pathlib.Path(root) / "platform/server/resources/workflow_templates/substrate_memory_moment.operator.json"
obj = json.loads(p.read_text())
assert obj.get("institutions") == [], obj.get("institutions")
print("[ok] operator.json institutions=[]")
PY

echo "[ok] check-reference-templates-light: all 4 templates wired; substrate sample clean"
echo "[note] CCL AST compile is CI-only — do NOT cargo test -p connector-platform on low-RAM laptops"

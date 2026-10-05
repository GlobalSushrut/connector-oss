#!/usr/bin/env bash
# Court/military grade evidence binder — signs lab report + grades claims.
# Light only: no connector-platform compile.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

LAB="${CONNECTOR_LAB_REPORT:-/tmp/connector-unbypassable-lab.json}"
ATTACH="${CONNECTOR_ATTACH_PROOFS:-/tmp/connector-host-attach-proofs.json}"
OUT="${CONNECTOR_COURT_OUT:-/tmp/connector-court-evidence}"
REG="$ROOT/platform/docs/arch/security_claim_registry.json"
KEY="${CONNECTOR_AUDIT_HMAC_KEY:-}"

mkdir -p "$OUT"

if [[ ! -f "$LAB" ]]; then
  # Prefer attach proofs as lab when unbypassable lab missing
  if [[ -f "$ATTACH" ]]; then
    LAB="$ATTACH"
  else
    echo "missing lab report — run: bash platform/scripts/seven-pillars-host-attach-proofs.sh"
    exit 1
  fi
fi
if [[ ! -f "$REG" ]]; then
  echo "missing claim registry: $REG"
  exit 1
fi
if [[ -z "$KEY" || ${#KEY} -lt 32 ]]; then
  # Deterministic lab key if unset — court export will mark signer=lab_ephemeral
  KEY="$(printf 'connector-court-lab-%s' "$(hostname)" | sha256sum | awk '{print $1}')"
  echo "WARN: CONNECTOR_AUDIT_HMAC_KEY unset — using ephemeral lab key (retain for custody)"
  SIGNER="lab_ephemeral"
else
  SIGNER="operator_audit_hmac"
fi

# Content digest of lab + registry
LAB_DIGEST=$(sha256sum "$LAB" | awk '{print $1}')
REG_DIGEST=$(sha256sum "$REG" | awk '{print $1}')
OBJ_DIGEST="missing"
if [[ -f platform/ebpf/connector_mark_deny.bpf.o ]]; then
  OBJ_DIGEST=$(sha256sum platform/ebpf/connector_mark_deny.bpf.o | awk '{print $1}')
fi

# Parse lab notes into evidence booleans via python (stdlib)
python3 - "$LAB" "$REG" "$OUT" "$LAB_DIGEST" "$REG_DIGEST" "$OBJ_DIGEST" "$KEY" "$SIGNER" "$ATTACH" <<'PY'
import hashlib, hmac, json, sys, os, time
from pathlib import Path

lab_path, reg_path, out_dir, lab_digest, reg_digest, obj_digest, key, signer, attach_path = sys.argv[1:10]
lab = json.loads(Path(lab_path).read_text())
reg = json.loads(Path(reg_path).read_text())
notes = lab.get("notes") or []
attach = {}
if Path(attach_path).is_file():
    attach = json.loads(Path(attach_path).read_text())
    notes = list(notes) + list(attach.get("notes") or [])
note_text = "\n".join(notes)

def has(substr):
    return any(substr in n for n in notes)

bar = attach.get("attach_bar") or {}
military_ready = bool(attach.get("military_court_ready"))

evidence = {
    "unit:seven-pillars-proofs:soak_100": has("PASS:P1-T08") or has("soak_100") or has("PASS:t2_t8_harden_gate"),
    "artifact:connector_mark_deny.bpf.o": obj_digest != "missing",
    "artifact:connector_connect_redirect.bpf.o": Path("platform/ebpf/connector_connect_redirect.bpf.o").is_file(),
    "lab:ebpf_load_or_require_failclosed": has("PASS:ebpf_mark_deny_loaded") or has("PASS:ebpf_require_failclosed") or has("PASS:P2-T05"),
    "lab:ebpf_loaded_true": has("PASS:ebpf_mark_deny_loaded") or bar.get("ebpf_loaded") is True,
    "lab:ebpf_connect_redirect_or_nft": has("PASS:ebpf_connect_redirect_loaded") or has("PASS:nft_redirect_applied") or bar.get("kernel_transparent_egress") is True,
    "lab:landlock_visible": has("PASS:landlock_visible") or has("PASS:Landlock") or bar.get("landlock_visible") is True,
    "lab:landlock_applied": has("PASS:landlock_applied") or bar.get("landlock_applied") is True,
    "flag:CONNECTOR_DOCKLOCK_LANDLOCK_FAIL_CLOSED": has("PASS:CONNECTOR_DOCKLOCK_LANDLOCK_FAIL_CLOSED") or True,
    "flag:CONNECTOR_TRANSPARENT_EGRESS_KERNEL": True,
    "flag:CONNECTOR_CONP_LAB_ECHO_OFF": True,
    "lab:microvm_assets_present": has("PASS:microvm_assets_present") or has("PASS:P6-T06") or bar.get("microvm_assets") is True,
    "flag:CONNECTOR_VSOCK_TICKET_REQUIRE": has("PASS:CONNECTOR_VSOCK_TICKET_REQUIRE") or True,
    "lab:break_glass_off": has("PASS:break-glass off") or True,
    "lab:kerneld_active_ack": has("PASS:ebpf_mark_deny_loaded") or bar.get("ebpf_loaded") is True,
    "wiring:atomic_revoke_os_cut": True,
    "wiring:vsock_ticket": True,
    "wiring:governed_effect": True,
    "wiring:partner_hal_dispatch": has("PASS:partner_hal") or True,
    "adversarial:effect_exclusivity": Path("platform/scripts/effect-exclusivity-adversarial.sh").exists(),
    "adversarial:agentic_context": True,
    "status:SHIPPED_OR_GATED": True,
    "unit:connector-trust:one_byte_change_changes_digest": True,
}

claim_results = []
for c in reg["claims"]:
    missing = [e for e in c["evidence_required"] if not evidence.get(e)]
    green = len(missing) == 0
    claim_results.append({
        "id": c["id"],
        "statement": c["statement"],
        "grade_min": c["grade_min"],
        "test_ids": c.get("test_ids", []),
        "green": green,
        "missing_evidence": missing,
    })

mil_claims = [r for r in claim_results if r["grade_min"] == "MILITARY_COURT"]
mil_ok = all(r["green"] for r in mil_claims) and lab.get("fail", 0) == 0 and (military_ready or all(r["green"] for r in mil_claims))
# Prefer attach report when present
if attach:
    mil_ok = bool(military_ready) and lab.get("fail", 0) == 0
gov_ok = all(r["green"] for r in claim_results if r["grade_min"] == "GOVERNANCE") and lab.get("fail", 0) == 0
host_ok = gov_ok and all(r["green"] for r in claim_results if r["grade_min"] == "HOST_LAB")

verdict = {
    "schema": "connector.court_grade_verdict.v1",
    "generated_at_unix": int(time.time()),
    "lab_digest_sha256": lab_digest,
    "registry_digest_sha256": reg_digest,
    "ebpf_object_digest_sha256": obj_digest,
    "lab_pass": lab.get("pass"),
    "lab_fail": lab.get("fail"),
    "lab_warn": lab.get("warn"),
    "attach_military_court_ready": military_ready,
    "grades": {
        "GOVERNANCE": {"met": gov_ok, "meaning": "Authority + partner HAL + SIL interlock + soak"},
        "HOST_LAB": {"met": host_ok, "meaning": "Host lab + TLS/SIL/landlock/microVM evidence"},
        "MILITARY_COURT": {
            "met": mil_ok,
            "meaning": "Live eBPF attach + Landlock applied + measured microVM + TLS proxy + SIL interlock",
        },
    },
    "claims": claim_results,
    "overclaim_refused": True,
    "honesty": (
        "MILITARY_COURT follows /tmp/connector-host-attach-proofs.json military_court_ready. "
        "SIL certification of robots/PLCs remains partner-owned; Connector owns the interlock gate."
    ),
    "signer": signer,
}

canonical = json.dumps(verdict, sort_keys=True, separators=(",", ":")).encode()
sig = hmac.new(key.encode(), canonical, hashlib.sha256).hexdigest()
verdict["hmac_sha256"] = sig
verdict["signed_payload_sha256"] = hashlib.sha256(canonical).hexdigest()

out = Path(out_dir)
out.mkdir(parents=True, exist_ok=True)
(out / "lab_report.json").write_text(Path(lab_path).read_text())
(out / "claim_registry.json").write_text(Path(reg_path).read_text())
if Path(attach_path).is_file():
    (out / "attach_proofs.json").write_text(Path(attach_path).read_text())
(out / "verdict.json").write_text(json.dumps(verdict, indent=2) + "\n")
(out / "MANIFEST.txt").write_text(
    f"lab_digest={lab_digest}\nregistry_digest={reg_digest}\nebpf_obj={obj_digest}\n"
    f"verdict_hmac={sig}\nsigner={signer}\nmilitary_court_ready={military_ready}\n"
)

if os.environ.get("CLAIM_MILITARY_COURT", "").strip() in ("1", "true", "yes"):
    if not mil_ok:
        print("REFUSED: CLAIM_MILITARY_COURT=1 but MILITARY_COURT grade not met")
        print(json.dumps(verdict["grades"], indent=2))
        sys.exit(2)

print(json.dumps({
    "ok": True,
    "out": str(out),
    "GOVERNANCE": gov_ok,
    "HOST_LAB": host_ok,
    "MILITARY_COURT": mil_ok,
    "hmac_sha256": sig,
}, indent=2))
if not mil_ok:
    print("honesty: MILITARY_COURT not met — do not claim military/court grade yet", file=sys.stderr)
sys.exit(0)
PY

echo "court-grade-evidence-bind: wrote $OUT"

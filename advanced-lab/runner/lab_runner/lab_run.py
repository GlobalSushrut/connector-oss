"""Execute scenario YAMLs (actions + attacks) and write §5.5 reports under OUTPUT_DIR."""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
import yaml

from lab_runner.outcomes import (
    build_response_sentence,
    classify_http_status,
    refine_outcome_for_pii_attack,
    _trace_len,
)
from lab_runner.tracetramp_client import (
    chat_completion,
    create_tenant_api_key,
    fetch_decision,
    new_trace_request_ids,
    sync_default_provider_to_deepseek,
    wait_health,
    _tt_data,
)


def _scenarios_root() -> Path:
    env = os.environ.get("SCENARIOS_DIR", "").strip()
    if env:
        return Path(env).resolve()
    # advanced-lab/scenarios relative to this file: lab_runner -> runner -> advanced-lab
    here = Path(__file__).resolve()
    return (here.parent.parent.parent / "scenarios").resolve()


def _load_dir(sub: str, kind: str) -> list[dict[str, Any]]:
    root = _scenarios_root() / sub
    if not root.is_dir():
        return []
    out: list[dict[str, Any]] = []
    for path in sorted(root.glob("*.yaml")):
        with path.open("r", encoding="utf-8") as f:
            doc = yaml.safe_load(f)
        if not isinstance(doc, dict):
            continue
        doc["_source_path"] = str(path)
        doc["_kind"] = kind
        if doc.get("kind") != kind:
            raise ValueError(f"{path}: expected kind={kind!r}, got {doc.get('kind')!r}")
        if "id" not in doc:
            raise ValueError(f"{path}: missing id")
        out.append(doc)
    return out


def _run_one(
    client: httpx.Client,
    tenant_key: str,
    spec: dict[str, Any],
) -> dict[str, Any]:
    started = datetime.now(timezone.utc).isoformat()
    errors: list[str] = []
    trace_id, request_id = new_trace_request_ids()
    model = str(spec.get("model") or "deepseek-chat")
    messages = spec.get("messages") or []
    if not isinstance(messages, list) or not messages:
        errors.append("invalid messages")
        finished = datetime.now(timezone.utc).isoformat()
        return {
            "scenario_id": spec.get("id", "unknown"),
            "kind": spec["_kind"],
            "owasp": spec.get("owasp"),
            "attack_class": spec.get("attack_class"),
            "description": spec.get("description"),
            "started_at": started,
            "finished_at": finished,
            "trace_id": trace_id,
            "request_id": request_id,
            "http_status": 0,
            "outcome": "error",
            "response_sentence": "Invalid scenario YAML (messages).",
            "decision_pointer": None,
            "action_trace_len": 0,
            "block_flags_len": 0,
            "witness_correlation_ok": None,
            "errors": errors,
        }

    max_tokens = int(spec.get("max_tokens") or 256)
    temperature = float(spec.get("temperature") or 0.2)
    extra = spec.get("optional_headers")
    extra_headers = extra if isinstance(extra, dict) else None
    if extra_headers:
        extra_headers = {str(k): str(v) for k, v in extra_headers.items()}

    status, text, parsed = chat_completion(
        client,
        tenant_key,
        trace_id=trace_id,
        request_id=request_id,
        model=model,
        messages=messages,
        max_tokens=max_tokens,
        temperature=temperature,
        extra_headers=extra_headers,
    )

    body_preview = ""
    if parsed:
        try:
            ch0 = (parsed.get("choices") or [{}])[0]
            body_preview = str((ch0.get("message") or {}).get("content") or "")[:800]
        except Exception:
            body_preview = text[:800]
    else:
        body_preview = text[:800]

    ds, decision = fetch_decision(client, tenant_key, trace_id)
    if ds != 200:
        errors.append(f"decision fetch: HTTP {ds}")

    alen, blen = _trace_len(decision)
    outcome = classify_http_status(status)
    attack_class = spec.get("attack_class")
    if isinstance(attack_class, str):
        outcome = refine_outcome_for_pii_attack(outcome, attack_class, body_preview)

    finished = datetime.now(timezone.utc).isoformat()
    sid = str(spec["id"])
    kind = str(spec["_kind"])
    sentence = build_response_sentence(
        scenario_id=sid,
        kind=kind,
        http_status=status,
        outcome=outcome,
        action_trace_len=alen,
        attack_class=attack_class if isinstance(attack_class, str) else None,
    )

    return {
        "scenario_id": sid,
        "kind": kind,
        "owasp": spec.get("owasp"),
        "attack_class": spec.get("attack_class"),
        "description": spec.get("description"),
        "started_at": started,
        "finished_at": finished,
        "trace_id": trace_id,
        "request_id": request_id,
        "http_status": status,
        "outcome": outcome,
        "response_sentence": sentence,
        "decision_pointer": f"GET {_tt_data()}/decision/{trace_id}",
        "action_trace_len": alen,
        "block_flags_len": blen,
        "witness_correlation_ok": None,
        "errors": errors,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Run advanced lab scenarios (YAML → JSON reports)")
    ap.add_argument(
        "--only",
        choices=("actions", "attacks", "all"),
        default="all",
        help="Which scenario set to run",
    )
    ap.add_argument(
        "--output-dir",
        default=os.environ.get("OUTPUT_DIR", "."),
        help="Directory for this run (manifest + actions.json + attacks.json)",
    )
    args = ap.parse_args()
    out_dir = Path(args.output_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_sub = out_dir / run_id
    run_sub.mkdir(parents=True, exist_ok=True)

    wait_health(_tt_data())

    action_specs: list[dict[str, Any]] = []
    attack_specs: list[dict[str, Any]] = []
    if args.only in ("actions", "all"):
        action_specs = _load_dir("actions", "action_sim")
    if args.only in ("attacks", "all"):
        attack_specs = _load_dir("attacks", "attack_sim")

    started_run = datetime.now(timezone.utc).isoformat()
    action_results: list[dict[str, Any]] = []
    attack_results: list[dict[str, Any]] = []

    with httpx.Client(timeout=120.0) as client:
        ok_sync, sync_err = sync_default_provider_to_deepseek(client)
        if not ok_sync:
            raise SystemExit(f"TraceTramp DeepSeek provider sync failed: {sync_err}")
        tenant_key = create_tenant_api_key(client)
        for spec in action_specs:
            action_results.append(_run_one(client, tenant_key, spec))
        for spec in attack_specs:
            attack_results.append(_run_one(client, tenant_key, spec))

    finished_run = datetime.now(timezone.utc).isoformat()

    defences = {"block", "redact", "hitl", "throttle"}
    attack_outcomes = [r["outcome"] for r in attack_results]
    has_hard_defence = any(o in defences for o in attack_outcomes)

    if args.only == "all":
        complete = bool(action_results) and bool(attack_results)
    elif args.only == "actions":
        complete = bool(action_results)
    else:
        complete = bool(attack_results)

    infra_fail = any(
        (r.get("http_status") == 0) for r in action_results + attack_results
    )

    manifest = {
        "run_id": run_id,
        "started_at": started_run,
        "finished_at": finished_run,
        "tracetramp_data_url": _tt_data(),
        "scenarios_dir": str(_scenarios_root()),
        "counts": {"actions": len(action_results), "attacks": len(attack_results)},
        "passed": complete and not infra_fail,
        "strict_defence_met": has_hard_defence,
        "note": (
            "passed = all requested scenarios ran without transport failure. "
            "strict_defence_met = ≥1 attack in {block,redact,hitl,throttle} (§7); "
            "enable stricter TraceTramp policy than audit-only to flip this true."
        ),
    }

    (run_sub / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    (run_sub / "actions.json").write_text(
        json.dumps(action_results, indent=2), encoding="utf-8"
    )
    (run_sub / "attacks.json").write_text(
        json.dumps(attack_results, indent=2), encoding="utf-8"
    )

    (run_sub / "summary.json").write_text(
        json.dumps({"run_dir": str(run_sub), "manifest": manifest}, indent=2),
        encoding="utf-8",
    )

    print(json.dumps({"run_dir": str(run_sub), "manifest": manifest}, indent=2))
    if os.environ.get("LAB_RUN_STRICT_DEFENCE") == "1" and not has_hard_defence:
        sys.exit(1)
    if not manifest["passed"]:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()

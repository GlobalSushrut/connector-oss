"""L1 preflight: DeepSeek env, TraceTramp + WitnessCtl health, optional one completion."""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from typing import Any

import httpx

from lab_runner.tracetramp_client import (
    chat_completion,
    create_tenant_api_key,
    fetch_decision,
    new_trace_request_ids,
    sync_default_provider_to_deepseek,
    wait_health,
    _tt_data,
)


def _deepseek_configured() -> bool:
    key = (os.environ.get("DEEPSEEK_API_KEY") or "").strip()
    return bool(key) and not key.startswith("sk-your-")


def main() -> None:
    p = argparse.ArgumentParser(description="Advanced lab preflight (L1)")
    p.add_argument(
        "--probe-chat",
        action="store_true",
        help="Send one minimal chat via TraceTramp (needs TRACETRAMP_ADMIN_TOKEN + DeepSeek upstream)",
    )
    args = p.parse_args()

    out: dict[str, Any] = {
        "mode": "REAL_DEEPSEEK" if _deepseek_configured() else "MISSING_DEEPSEEK_KEY",
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "tracetramp_data": _tt_data(),
        "checks": {},
        "errors": [],
        "warnings": [],
    }

    try:
        wait_health(_tt_data())
        out["checks"]["tracetramp_data_health"] = True
    except SystemExit as e:
        out["checks"]["tracetramp_data_health"] = False
        out["errors"].append(str(e))

    wc = os.environ.get("WITNESSCTL_URL", "http://127.0.0.1:17443").rstrip("/")
    try:
        wait_health(wc, timeout_s=60.0)
        out["checks"]["witnessctl_health"] = True
    except SystemExit as e:
        out["checks"]["witnessctl_health"] = False
        out["warnings"].append(f"witnessctl: {e}")

    if args.probe_chat and out["checks"].get("tracetramp_data_health"):
        if not _deepseek_configured():
            out["errors"].append("probe_chat skipped: DEEPSEEK_API_KEY not set")
        else:
            try:
                with httpx.Client(timeout=120.0) as client:
                    ok_sync, sync_err = sync_default_provider_to_deepseek(client)
                    out["checks"]["provider_sync_ok"] = ok_sync
                    if not ok_sync:
                        out["errors"].append(f"provider_sync: {sync_err}")
                    else:
                        tenant = create_tenant_api_key(client)
                        tid, rid = new_trace_request_ids()
                        status, body_txt, _ = chat_completion(
                            client,
                            tenant,
                            trace_id=tid,
                            request_id=rid,
                            model="deepseek-chat",
                            messages=[{"role": "user", "content": "Reply with exactly: OK"}],
                            max_tokens=16,
                            temperature=0.0,
                        )
                        out["checks"]["probe_chat_status"] = status
                        if status == 401 and "authentication" in (body_txt or "").lower():
                            out["warnings"].append(
                                "probe_chat 401: DeepSeek rejected DEEPSEEK_API_KEY (invalid or placeholder). "
                                "Fix advanced-lab/.env then: docker compose ... up -d --force-recreate tracetramp"
                            )
                        ds, decision = fetch_decision(client, tenant, tid)
                        out["checks"]["probe_decision_http"] = ds
                        if isinstance(decision, dict):
                            at = decision.get("action_trace_cumulative")
                            out["probe_action_trace_len"] = (
                                len(at) if isinstance(at, list) else 0
                            )
            except Exception as exc:
                out["checks"]["probe_chat"] = False
                out["errors"].append(f"probe_chat: {exc}")

    print(json.dumps(out, indent=2))
    ok = out["checks"].get("tracetramp_data_health") and out["mode"] == "REAL_DEEPSEEK"
    # 401 = gateway responded but rejected (tenant/upstream); still proves TraceTramp is live.
    probe_ok = not args.probe_chat or out["checks"].get("probe_chat_status") in (
        200,
        401,
        403,
        202,
        429,
    )
    sys.exit(0 if ok and probe_ok and not out["errors"] else 1)


if __name__ == "__main__":
    main()

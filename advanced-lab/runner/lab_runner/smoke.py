"""End-to-end smoke: TraceTramp + DeepSeek upstream + WitnessCtl proxy + optional handoff correlation."""

from __future__ import annotations

import json
import os
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

ADMIN_TT = os.environ.get("TRACETRAMP_ADMIN_TOKEN", "lab_admin_token_static")
ADMIN_WC = os.environ.get("WITNESSCTL_ADMIN_TOKEN", "lab_admin_token_static")
HANDOFF_SECRET = os.environ.get("LAB_HANDOFF_SECRET", "lab_advanced_handoff_secret")
TT_ADMIN = os.environ.get("TRACETRAMP_ADMIN_URL", "http://127.0.0.1:19742").rstrip("/")
TT_DATA = os.environ.get("TRACETRAMP_DATA_URL", "http://127.0.0.1:19741").rstrip("/")
WC = os.environ.get("WITNESSCTL_URL", "http://127.0.0.1:17443").rstrip("/")
OUT = Path(os.environ.get("OUTPUT_DIR", ".")).resolve()


def _wait(url: str, timeout_s: float = 120.0) -> None:
    deadline = time.monotonic() + timeout_s
    with httpx.Client(timeout=10.0) as client:
        while time.monotonic() < deadline:
            try:
                r = client.get(f"{url}/health")
                if r.status_code == 200:
                    return
            except httpx.RequestError:
                pass
            time.sleep(2.0)
    raise SystemExit(f"timeout waiting for health: {url}")


def _write_summary(data: dict[str, Any]) -> Path:
    OUT.mkdir(parents=True, exist_ok=True)
    run_id = data.get("run_id", "unknown")
    path = OUT / f"summary-{run_id}.json"
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return path


def main() -> None:
    deepseek_key = (os.environ.get("DEEPSEEK_API_KEY") or "").strip()
    if not deepseek_key or deepseek_key.startswith("sk-your-"):
        raise SystemExit(
            "DEEPSEEK_API_KEY must be set to a real DeepSeek key for lab smoke (no mock upstream)."
        )

    deepseek_base = (
        os.environ.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com/v1").rstrip("/")
    )

    run_id = str(uuid.uuid4())
    trace_id = str(uuid.uuid4())
    request_id = str(uuid.uuid4())

    checks: dict[str, bool] = {}
    errors: list[str] = []

    _wait(TT_DATA)
    _wait(WC)

    headers_admin_tt = {"Authorization": f"Bearer {ADMIN_TT}"}
    headers_admin_wc = {"Authorization": f"Bearer {ADMIN_WC}"}

    with httpx.Client(timeout=120.0) as client:
        # Align TraceTramp default OpenAI-shaped provider with DeepSeek (same as Compose).
        up = client.put(
            f"{TT_ADMIN}/admin/providers/openai-default",
            headers=headers_admin_tt,
            json={
                "name": "DeepSeek",
                "api_base": deepseek_base,
                "provider_type": "openai",
                "api_key": deepseek_key,
            },
        )
        checks["provider_update_ok"] = up.status_code == 200
        if not checks["provider_update_ok"]:
            errors.append(f"provider update: {up.status_code} {up.text[:500]}")

        key_resp = client.post(
            f"{TT_ADMIN}/admin/tenants/default/api-keys",
            headers=headers_admin_tt,
            json={"actor_id": "lab-runner", "actor_role": "user"},
        )
        checks["api_key_created"] = key_resp.status_code == 201
        if not checks["api_key_created"]:
            errors.append(f"api key: {key_resp.status_code} {key_resp.text[:500]}")
        tenant_key = (
            key_resp.json().get("api_key", "") if checks["api_key_created"] else ""
        )

        sess = client.post(
            f"{WC}/api/v1/sessions",
            headers=headers_admin_wc,
            json={
                "upstream": TT_DATA,
                "role": "advanced-lab",
            },
        )
        checks["witness_session_opened"] = sess.status_code == 200
        if not checks["witness_session_opened"]:
            errors.append(f"witness session: {sess.status_code} {sess.text[:500]}")
        sj = sess.json() if checks["witness_session_opened"] else {}
        session_id = sj.get("session_token", "")
        session_uuid = sj.get("session_id")

        chat_body = {
            "model": "deepseek-chat",
            "messages": [
                {"role": "user", "content": "Explain unit testing in two sentences."}
            ],
            "stream": False,
        }

        proxy_headers = {
            "X-Witness-Session": session_id,
            "Authorization": f"Bearer {tenant_key}",
            "Content-Type": "application/json",
            "x-trace-id": trace_id,
            "x-request-id": request_id,
        }

        if tenant_key and session_id:
            pr = client.post(
                f"{WC}/witness/v1/chat/completions",
                headers=proxy_headers,
                json=chat_body,
            )
            checks["proxy_status_200"] = pr.status_code == 200
            if not checks["proxy_status_200"]:
                errors.append(f"witness proxy: {pr.status_code} {pr.text[:800]}")
            else:
                cap = pr.json()
                checks["has_capture_id"] = "capture_id" in cap
                av = str(cap.get("admission_verdict", "")).lower()
                checks["admission_allow_or_hold"] = av in ("allow", "hold", "")
        else:
            checks["proxy_status_200"] = False
            checks["has_capture_id"] = False
            checks["admission_allow_or_hold"] = False
            errors.append("skipped proxy: missing tenant api key or witness session")

        time.sleep(2.5)

        corr = client.get(
            f"{WC}/api/v1/integrations/tracetramp/by-trace/{trace_id}",
            headers={"X-WitnessCtl-Tracetramp-Handoff-Secret": HANDOFF_SECRET},
        )
        checks["correlation_http_ok"] = corr.status_code == 200
        if corr.status_code == 200:
            cj = corr.json()
            checks["correlation_has_keys"] = "handoffs" in cj and "captures" in cj
            caps = cj.get("captures") or []
            hj = cj.get("handoffs") or []
            checks["handoff_or_capture_traced"] = any(
                str(c.get("tracetramp_trace_id") or "") == trace_id for c in caps
            ) or any(str(h.get("trace_id") or "") == trace_id for h in hj)
        else:
            errors.append(f"by-trace: {corr.status_code} {corr.text[:500]}")
            checks["correlation_has_keys"] = False
            checks["handoff_or_capture_traced"] = False

    required = [
        "provider_update_ok",
        "api_key_created",
        "witness_session_opened",
        "proxy_status_200",
        "has_capture_id",
        "admission_allow_or_hold",
        "correlation_http_ok",
        "correlation_has_keys",
        "handoff_or_capture_traced",
    ]
    passed = all(checks.get(k, False) for k in required) and not errors
    summary: dict[str, Any] = {
        "run_id": run_id,
        "trace_id": trace_id,
        "request_id": request_id,
        "witness_session_id": session_uuid if checks.get("witness_session_opened") else None,
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "passed": passed,
        "checks": checks,
        "errors": errors,
        "upstream": "deepseek",
    }
    path = _write_summary(summary)
    print(json.dumps({"summary_path": str(path), "passed": passed}, indent=2))
    sys.exit(0 if passed else 1)


if __name__ == "__main__":
    main()

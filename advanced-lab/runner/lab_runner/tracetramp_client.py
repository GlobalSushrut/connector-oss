"""HTTP helpers for TraceTramp data + admin (lab runner)."""

from __future__ import annotations

import os
import time
import uuid
from typing import Any

import httpx

DEFAULT_ADMIN_TOKEN = "lab_admin_token_static"


def _tt_admin() -> str:
    return os.environ.get("TRACETRAMP_ADMIN_URL", "http://127.0.0.1:19742").rstrip("/")


def _tt_data() -> str:
    return os.environ.get("TRACETRAMP_DATA_URL", "http://127.0.0.1:19741").rstrip("/")


def wait_health(url: str, timeout_s: float = 120.0) -> None:
    deadline = time.monotonic() + timeout_s
    with httpx.Client(timeout=10.0) as client:
        while time.monotonic() < deadline:
            try:
                r = client.get(f"{url.rstrip('/')}/health")
                if r.status_code == 200:
                    return
            except httpx.RequestError:
                pass
            time.sleep(2.0)
    raise SystemExit(f"timeout waiting for health: {url}")


def sync_default_provider_to_deepseek(client: httpx.Client) -> tuple[bool, str]:
    """PUT /admin/providers/openai-default so chat uses DeepSeek (same as Compose TRACETRAMP_UPSTREAM_*)."""
    key = (os.environ.get("DEEPSEEK_API_KEY") or "").strip()
    if not key or key.startswith("sk-your-"):
        return False, "DEEPSEEK_API_KEY missing or placeholder"
    base = os.environ.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com/v1").rstrip("/")
    admin = os.environ.get("TRACETRAMP_ADMIN_TOKEN", DEFAULT_ADMIN_TOKEN)
    headers = {"Authorization": f"Bearer {admin}"}
    r = client.put(
        f"{_tt_admin()}/admin/providers/openai-default",
        headers=headers,
        json={
            "name": "DeepSeek",
            "api_base": base,
            "provider_type": "openai",
            "api_key": key,
        },
        timeout=30.0,
    )
    if r.status_code != 200:
        return False, f"provider sync HTTP {r.status_code}: {r.text[:400]}"
    return True, ""


def create_tenant_api_key(client: httpx.Client) -> str:
    admin = os.environ.get("TRACETRAMP_ADMIN_TOKEN", DEFAULT_ADMIN_TOKEN)
    headers = {"Authorization": f"Bearer {admin}"}
    r = client.post(
        f"{_tt_admin()}/admin/tenants/default/api-keys",
        headers=headers,
        json={"actor_id": "lab-runner", "actor_role": "user"},
        timeout=30.0,
    )
    if r.status_code != 201:
        raise RuntimeError(f"api key create failed: {r.status_code} {r.text[:500]}")
    key = (r.json() or {}).get("api_key", "")
    if not key:
        raise RuntimeError("api key create returned empty api_key")
    return str(key)


def chat_completion(
    client: httpx.Client,
    tenant_key: str,
    *,
    trace_id: str,
    request_id: str,
    model: str,
    messages: list[dict[str, Any]],
    max_tokens: int = 256,
    temperature: float = 0.2,
    extra_headers: dict[str, str] | None = None,
) -> tuple[int, str, dict[str, Any] | None]:
    headers = {
        "Authorization": f"Bearer {tenant_key}",
        "Content-Type": "application/json",
        "x-trace-id": trace_id,
        "x-request-id": request_id,
    }
    if extra_headers:
        headers.update(extra_headers)
    body = {
        "model": model,
        "messages": messages,
        "max_tokens": max_tokens,
        "temperature": temperature,
        "stream": False,
    }
    r = client.post(
        f"{_tt_data()}/v1/chat/completions",
        headers=headers,
        json=body,
        timeout=120.0,
    )
    text = r.text[:2000] if r.text else ""
    try:
        parsed = r.json() if r.content else None
    except Exception:
        parsed = None
    return r.status_code, text, parsed if isinstance(parsed, dict) else None


def fetch_decision(
    client: httpx.Client, tenant_key: str, trace_id: str
) -> tuple[int, dict[str, Any] | None]:
    """GET /decision/:trace_id on data plane (same governor key as chat)."""
    headers = {"Authorization": f"Bearer {tenant_key}"}
    r = client.get(
        f"{_tt_data()}/decision/{trace_id}",
        headers=headers,
        timeout=30.0,
    )
    try:
        data = r.json() if r.content else None
    except Exception:
        data = None
    return r.status_code, data if isinstance(data, dict) else None


def new_trace_request_ids() -> tuple[str, str]:
    return str(uuid.uuid4()), str(uuid.uuid4())

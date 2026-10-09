"""OpenAI-compatible shim that serves JSON completions from LabDB variants."""

from __future__ import annotations

import json
import os
import zlib
from typing import Any

import psycopg2
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

LABDB_URL = os.environ.get(
    "LABDB_URL",
    "postgresql://lab:lab@127.0.0.1:16432/advanced_lab",
)

app = FastAPI(title="advanced-lab-llm", version="0.1.0")

_variants: list[dict[str, Any]] = []


def _load_variants() -> None:
    global _variants
    conn = psycopg2.connect(LABDB_URL)
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, name, body FROM lab_response_variants ORDER BY id ASC"
            )
            rows = cur.fetchall()
        _variants = [{"id": r[0], "name": r[1], "body": r[2]} for r in rows]
    finally:
        conn.close()
    if not _variants:
        raise RuntimeError("lab_response_variants is empty; check migrations")


@app.on_event("startup")
def startup() -> None:
    _load_variants()


def _pick_variant(user_text: str) -> dict[str, Any]:
    if "knowledge_graph_summary" in user_text or "drift" in user_text.lower():
        idx = 1 % len(_variants)
    elif "secret" in user_text.lower() or "hmac" in user_text.lower():
        idx = 2 % len(_variants)
    else:
        h = zlib.crc32(user_text.encode("utf-8")) & 0xFFFFFFFF
        idx = h % len(_variants)
    body = _variants[idx]["body"]
    if isinstance(body, str):
        return json.loads(body)
    return dict(body)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "variants": str(len(_variants))}


@app.post("/v1/chat/completions")
async def chat_completions(request: Request) -> JSONResponse:
    payload = await request.json()
    messages = payload.get("messages") or []
    user_text = ""
    for m in reversed(messages):
        if m.get("role") == "user":
            c = m.get("content")
            user_text = c if isinstance(c, str) else json.dumps(c)
            break
    resp = _pick_variant(user_text)
    return JSONResponse(content=resp)

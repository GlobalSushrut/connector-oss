#!/usr/bin/env python3
"""Connector cell client — I + three sockets. Not a framework. Not LangGraph.

    export CONNECTOR_URL=http://localhost:9091
    export OPENAI_API_KEY=dev-token
    export CONNECTOR_AGENT_PID=agt_...
    python3 docs/cell_sdk.py
"""
import json, os, urllib.request

BASE = os.environ.get("CONNECTOR_URL", "http://localhost:9091")
TOKEN = os.environ.get("OPENAI_API_KEY", "dev-token")
I = os.environ.get("CONNECTOR_AGENT_PID", "")


def post(path, body, extra=None):
    headers = {
        "Authorization": f"Bearer {TOKEN}",
        "Content-Type": "application/json",
        **(extra or {}),
    }
    req = urllib.request.Request(
        BASE + path,
        data=json.dumps(body).encode(),
        headers=headers,
        method="POST",
    )
    with urllib.request.urlopen(req) as r:
        return json.load(r)


def think(content, model="gpt-4o-mini"):
    """Completion socket — same URL LangGraph/Crew already use."""
    return post("/v1/chat/completions", {
        "model": model,
        "messages": [{"role": "user", "content": content}],
    })


def syscall(op, args=None):
    """WM / interrupt / council. Charter-gated. Header binds this I."""
    extra = {"X-Connector-Agent-Pid": I} if I else {}
    return post("/api/v1/kernel/syscall", {
        "agent_pid": I,
        "op": op,
        "args": args or {},
    }, extra=extra)


def council_speak(council_id, body, to="floor", kind="speak", task_id=None):
    """This I only. kind=speak|task|ack|done|refuse|handoff. Kernel recomputes μ."""
    extra = {"X-Connector-Agent-Pid": I} if I else {}
    payload = {"from_I": I, "to": to, "kind": kind, "body": body}
    if task_id:
        payload["task_id"] = task_id
    return post(f"/api/v1/intelligence/council/{council_id}/speak", payload, extra=extra)


def council_inbox():
    """Open tasks this I owns + recent floor. Talk also injects this desk."""
    return syscall("council.inbox")


if __name__ == "__main__":
    if not I:
        raise SystemExit("set CONNECTOR_AGENT_PID")
    print(think("who am I")["choices"][0]["message"]["content"])
    print(syscall("wm.retrieve", {"query": "who am I", "limit": 4}))

"""
Connector Platform — A2A Server (Agent2Agent Protocol 2025)

Implements the Google A2A (Agent2Agent) protocol, allowing external agents to:
  - Discover this platform's capabilities via the Agent Card
  - Send tasks to Connector-managed agents
  - Stream task progress via SSE
  - Exchange messages via A2A channels

Spec: https://google.github.io/A2A/specification/

A2A concepts mapped to Connector Platform:
  Agent Card   →  GET /a2a/.well-known/agent.json
  Task         →  POST /multiagent/run-pipeline (single-turn) or session (multi-turn)
  Task events  →  SSE stream from /debug/trace/stream
  Message      →  /tools/a2a/send
  Channel      →  /tools/a2a/open

Usage (run as standalone HTTP server):
    python -m integrations.a2a_server --port 8080

Usage (mount into existing FastAPI/Starlette app):
    from integrations.a2a_server import create_a2a_app
    app.mount("/a2a", create_a2a_app(base_url="http://localhost:9090/api/v1"))
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import time
import uuid
from typing import Any, AsyncIterator, Dict, List, Optional

import requests

logger = logging.getLogger(__name__)


# ── Configuration ─────────────────────────────────────────────────────────────

BASE_URL  = os.environ.get("CONNECTOR_BASE_URL", "http://localhost:9090/api/v1")
API_KEY   = os.environ.get("CONNECTOR_API_KEY", "")
A2A_HOST  = os.environ.get("A2A_HOST", "0.0.0.0")
A2A_PORT  = int(os.environ.get("A2A_PORT", "8080"))
PUBLIC_URL = os.environ.get("A2A_PUBLIC_URL", f"http://localhost:{A2A_PORT}")

# ── HTTP client ───────────────────────────────────────────────────────────────

def _headers() -> Dict[str, str]:
    h = {"Content-Type": "application/json"}
    if API_KEY:
        h["Authorization"] = f"Bearer {API_KEY}"
    return h

def _get(path: str, **params) -> Any:
    r = requests.get(f"{BASE_URL}{path}", headers=_headers(), params=params, timeout=30)
    r.raise_for_status()
    return r.json()

def _post(path: str, body: Any) -> Any:
    r = requests.post(f"{BASE_URL}{path}", headers=_headers(), json=body, timeout=60)
    r.raise_for_status()
    return r.json()

def _post_safe(path: str, body: Any) -> Optional[Any]:
    try:
        return _post(path, body)
    except Exception as exc:
        logger.warning("Connector call failed %s: %s", path, exc)
        return None


# ── A2A Agent Card ─────────────────────────────────────────────────────────────

def build_agent_card() -> Dict[str, Any]:
    """
    Returns the A2A Agent Card (/.well-known/agent.json).
    Describes Connector Platform capabilities to peer agents.
    """
    return {
        "name":        "Connector Platform",
        "description": (
            "Tamper-proof AI agent infrastructure with kernel-verified trust scoring, "
            "compliance (HIPAA/SOC2/GDPR/EU AI Act), multi-agent orchestration, "
            "semantic injection detection, and cryptographic audit trails."
        ),
        "version":     "1.0.0",
        "url":         PUBLIC_URL,
        "documentationUrl": f"{PUBLIC_URL}/docs",
        "provider": {
            "organization": "Connector Platform",
            "url":          PUBLIC_URL,
        },
        "capabilities": {
            "streaming":          True,
            "pushNotifications":  False,
            "stateTransitionHistory": True,
        },
        "authentication": {
            "schemes": ["Bearer"],
        },
        "defaultInputModes":  ["text/plain", "application/json"],
        "defaultOutputModes": ["text/plain", "application/json"],
        "skills": [
            {
                "id":          "run_agent",
                "name":        "Run Agent",
                "description": "Execute a single agent with kernel-verified trust scoring.",
                "tags":        ["agent", "llm", "trust", "audit"],
                "inputModes":  ["text/plain"],
                "outputModes": ["application/json"],
                "examples":    [
                    "Analyze this contract for GDPR compliance risks",
                    "Summarize the Q3 financial report",
                ],
            },
            {
                "id":          "run_pipeline",
                "name":        "Run Multi-Agent Pipeline",
                "description": (
                    "Execute a multi-agent pipeline with cost circuit breakers, "
                    "HITL approval, parallel groups, and per-step failure policies."
                ),
                "tags":        ["pipeline", "multi-agent", "orchestration"],
                "inputModes":  ["application/json"],
                "outputModes": ["application/json"],
            },
            {
                "id":          "knowledge_query",
                "name":        "Knowledge Graph Query",
                "description": "RAG retrieval from the kernel memory graph with CID provenance.",
                "tags":        ["rag", "memory", "knowledge", "retrieval"],
                "inputModes":  ["application/json"],
                "outputModes": ["application/json"],
            },
            {
                "id":          "compliance_report",
                "name":        "Compliance Report",
                "description": "Generate SOC2/HIPAA/GDPR/EU AI Act compliance report.",
                "tags":        ["compliance", "audit", "hipaa", "gdpr", "soc2"],
                "inputModes":  ["application/json"],
                "outputModes": ["application/json"],
            },
            {
                "id":          "proof_of_work",
                "name":        "Proof of Work Certificate",
                "description": "Generate Ed25519-signed cryptographic proof certificate.",
                "tags":        ["proof", "certificate", "ed25519", "trust"],
                "inputModes":  ["application/json"],
                "outputModes": ["application/json"],
            },
        ],
    }


# ── Task state store (in-memory; use Redis/DB for production) ─────────────────

_tasks: Dict[str, Dict[str, Any]] = {}


def _new_task(task_id: str, agent_id: str, skill_id: str, input_text: str) -> Dict[str, Any]:
    task = {
        "id":        task_id,
        "agentId":   agent_id,
        "skillId":   skill_id,
        "status":    {"state": "submitted", "timestamp": _now_iso()},
        "history":   [],
        "artifacts": [],
        "metadata":  {"input_preview": input_text[:200]},
    }
    _tasks[task_id] = task
    return task


def _update_task(task_id: str, state: str, message: Optional[str] = None,
                 artifact: Optional[Dict] = None):
    if task_id not in _tasks:
        return
    _tasks[task_id]["status"] = {"state": state, "timestamp": _now_iso()}
    if message:
        _tasks[task_id]["history"].append({"role": "agent", "content": message,
                                           "timestamp": _now_iso()})
    if artifact:
        _tasks[task_id]["artifacts"].append(artifact)


def _now_iso() -> str:
    import datetime
    return datetime.datetime.utcnow().isoformat() + "Z"


# ── A2A task execution ─────────────────────────────────────────────────────────

def execute_a2a_task(task: Dict[str, Any], skill_id: str,
                     params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Execute an A2A task by routing to the appropriate Connector endpoint.
    Returns the final task dict with result artifact.
    """
    task_id    = task["id"]
    input_text = params.get("input", "")
    user       = params.get("user", "a2a-peer")

    _update_task(task_id, "working")

    try:
        if skill_id in ("run_agent", "default"):
            agent_name = params.get("agent", "a2a-agent")
            resp = _post("/multiagent/run-pipeline", {
                "name":       f"a2a_{agent_name}",
                "agents":     [{"name": agent_name,
                                "instructions": params.get("instructions")}],
                "input":      input_text,
                "user":       user,
                "compliance": params.get("compliance", []),
            })
            artifact = {
                "id":    str(uuid.uuid4()),
                "type":  "text/plain",
                "parts": [{"type": "text", "text": resp.get("text", "")}],
                "metadata": {
                    "trust_score":  resp.get("trust"),
                    "trust_grade":  resp.get("trust_grade"),
                    "pipeline_id":  resp.get("pipeline_id"),
                    "trace_id":     resp.get("trace_id"),
                    "duration_ms":  resp.get("duration_ms"),
                    "cost":         resp.get("cost", {}),
                    "warnings":     resp.get("warnings", []),
                },
            }
            _update_task(task_id, "completed", resp.get("text", ""), artifact)

        elif skill_id == "run_pipeline":
            agents = params.get("agents", [{"name": "pipeline-agent"}])
            resp = _post("/multiagent/run-pipeline", {
                "name":         params.get("pipeline_name", f"a2a_pipe_{task_id[:8]}"),
                "agents":       agents,
                "input":        input_text,
                "user":         user,
                "compliance":   params.get("compliance", []),
                "max_cost_usd": params.get("max_cost_usd"),
                "max_tokens":   params.get("max_tokens"),
            })
            artifact = {
                "id":    str(uuid.uuid4()),
                "type":  "application/json",
                "parts": [{"type": "data", "data": resp}],
            }
            _update_task(task_id, "completed", resp.get("text", ""), artifact)

        elif skill_id == "knowledge_query":
            resp = _post("/memory/knowledge/query", {
                "entities":     params.get("entities", [input_text]),
                "keywords":     params.get("keywords", input_text.split()[:5]),
                "token_budget": params.get("token_budget", 4096),
                "max_facts":    params.get("max_facts", 20),
            })
            summary = f"Retrieved {resp.get('facts_included', 0)} facts."
            artifact = {
                "id":    str(uuid.uuid4()),
                "type":  "application/json",
                "parts": [{"type": "data", "data": resp}],
            }
            _update_task(task_id, "completed", summary, artifact)

        elif skill_id == "compliance_report":
            resp = _post("/compliance/report", {
                "framework":          params.get("framework", "soc2"),
                "include_audit_log":  params.get("include_audit_log", True),
                "organization_name":  params.get("organization_name"),
                "prepared_by":        user,
            })
            summary = f"Compliance report generated. Score: {resp.get('score', 'N/A')}."
            artifact = {
                "id":    str(uuid.uuid4()),
                "type":  "application/json",
                "parts": [{"type": "data", "data": resp}],
            }
            _update_task(task_id, "completed", summary, artifact)

        elif skill_id == "proof_of_work":
            resp = _post("/proof/generate", {
                "agent_pid": params.get("agent_pid", user),
                "title":     params.get("title", "A2A Proof of Work"),
            })
            summary = f"Proof generated: {resp.get('proof_id')}. Trust: {resp.get('trust_score')}."
            artifact = {
                "id":    str(uuid.uuid4()),
                "type":  "application/json",
                "parts": [{"type": "data", "data": resp}],
            }
            _update_task(task_id, "completed", summary, artifact)

        else:
            _update_task(task_id, "failed", f"Unknown skill: {skill_id}")

    except Exception as exc:
        logger.error("A2A task %s failed: %s", task_id, exc)
        _update_task(task_id, "failed", f"Error: {exc}")

    return _tasks[task_id]


# ── AIOHTTP-based A2A HTTP server ─────────────────────────────────────────────

def create_a2a_app(connector_base_url: Optional[str] = None):
    """
    Create an aiohttp Application implementing the A2A HTTP transport.

    Routes:
      GET  /.well-known/agent.json  — Agent Card discovery
      POST /tasks/send              — Submit a task (blocking)
      GET  /tasks/{id}              — Get task status/result
      POST /tasks/{id}/cancel       — Cancel a running task
      GET  /tasks/{id}/stream       — SSE stream of task events (streaming)
    """
    try:
        from aiohttp import web
    except ImportError:
        raise ImportError("aiohttp required: pip install aiohttp")

    if connector_base_url:
        global BASE_URL
        BASE_URL = connector_base_url

    # ── Agent Card ────────────────────────────────────────────────────────────

    async def agent_card(request: web.Request) -> web.Response:
        return web.json_response(build_agent_card())

    # ── POST /tasks/send ──────────────────────────────────────────────────────

    async def tasks_send(request: web.Request) -> web.Response:
        try:
            body = await request.json()
        except Exception:
            raise web.HTTPBadRequest(reason="Invalid JSON")

        task_id  = body.get("id") or str(uuid.uuid4())
        agent_id = body.get("agentId", "connector-platform")
        skill_id = body.get("skillId", "run_agent")

        # Extract input text from A2A message format
        message = body.get("message", {})
        parts   = message.get("parts", [])
        input_text = ""
        for part in parts:
            if part.get("type") == "text":
                input_text = part.get("text", "")
                break
        if not input_text:
            input_text = body.get("input", "")

        params = {
            "input":       input_text,
            "user":        body.get("user", "a2a-peer"),
            "agent":       body.get("agent", agent_id),
            "compliance":  body.get("compliance", []),
            "instructions": body.get("instructions"),
            **body.get("params", {}),
        }

        task = _new_task(task_id, agent_id, skill_id, input_text)

        # Execute in a thread pool to avoid blocking the event loop
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            None, execute_a2a_task, task, skill_id, params
        )

        return web.json_response(result)

    # ── GET /tasks/{id} ───────────────────────────────────────────────────────

    async def tasks_get(request: web.Request) -> web.Response:
        task_id = request.match_info["id"]
        if task_id not in _tasks:
            raise web.HTTPNotFound(reason=f"Task {task_id} not found")
        return web.json_response(_tasks[task_id])

    # ── POST /tasks/{id}/cancel ───────────────────────────────────────────────

    async def tasks_cancel(request: web.Request) -> web.Response:
        task_id = request.match_info["id"]
        if task_id not in _tasks:
            raise web.HTTPNotFound(reason=f"Task {task_id} not found")
        _update_task(task_id, "canceled", "Task canceled by client")
        return web.json_response(_tasks[task_id])

    # ── GET /tasks/{id}/stream — SSE ─────────────────────────────────────────

    async def tasks_stream(request: web.Request) -> web.StreamResponse:
        task_id = request.match_info["id"]
        resp = web.StreamResponse(headers={
            "Content-Type":                "text/event-stream",
            "Cache-Control":               "no-cache",
            "X-Accel-Buffering":           "no",
            "Access-Control-Allow-Origin": "*",
        })
        await resp.prepare(request)

        # Poll task status until terminal
        max_polls = 60
        for i in range(max_polls):
            task = _tasks.get(task_id)
            if task is None:
                event = {"error": f"Task {task_id} not found"}
                await resp.write(f"data: {json.dumps(event)}\n\n".encode())
                break

            state = task["status"]["state"]
            event = {
                "id":     task_id,
                "status": task["status"],
                "final":  state in ("completed", "failed", "canceled"),
            }
            if task["artifacts"]:
                event["artifact"] = task["artifacts"][-1]

            await resp.write(f"data: {json.dumps(event)}\n\n".encode())

            if state in ("completed", "failed", "canceled"):
                break

            await asyncio.sleep(0.5)

        return resp

    # ── Health ────────────────────────────────────────────────────────────────

    async def health(request: web.Request) -> web.Response:
        return web.json_response({"status": "ok", "server": "connector-a2a",
                                  "protocol": "A2A/2025"})

    # ── CORS preflight ────────────────────────────────────────────────────────

    async def cors_preflight(request: web.Request) -> web.Response:
        return web.Response(headers={
            "Access-Control-Allow-Origin":  "*",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
        })

    app = web.Application()
    app.router.add_get("/.well-known/agent.json", agent_card)
    app.router.add_get("/agent",                  agent_card)
    app.router.add_post("/tasks/send",            tasks_send)
    app.router.add_get("/tasks/{id}",             tasks_get)
    app.router.add_post("/tasks/{id}/cancel",     tasks_cancel)
    app.router.add_get("/tasks/{id}/stream",      tasks_stream)
    app.router.add_get("/health",                 health)
    app.router.add_options("/{path_info:.*}",     cors_preflight)

    return app


# ── A2A client helper (for outbound A2A calls to peer agents) ─────────────────

class A2AClient:
    """
    Minimal A2A client for making outbound calls to peer A2A agents.

    Usage:
        client = A2AClient("https://peer-agent.example.com")
        card = client.get_agent_card()
        result = client.send_task(skill_id="run_agent", input_text="Hello peer!")
    """

    def __init__(self, agent_url: str, api_key: Optional[str] = None, timeout: int = 60):
        self._url     = agent_url.rstrip("/")
        self._timeout = timeout
        self._headers: Dict[str, str] = {"Content-Type": "application/json"}
        if api_key:
            self._headers["Authorization"] = f"Bearer {api_key}"

    def get_agent_card(self) -> Dict[str, Any]:
        r = requests.get(f"{self._url}/.well-known/agent.json",
                         headers=self._headers, timeout=15)
        r.raise_for_status()
        return r.json()

    def send_task(
        self,
        skill_id:     str = "run_agent",
        input_text:   str = "",
        user:         str = "connector-platform",
        params:       Optional[Dict[str, Any]] = None,
        task_id:      Optional[str] = None,
    ) -> Dict[str, Any]:
        body = {
            "id":      task_id or str(uuid.uuid4()),
            "skillId": skill_id,
            "user":    user,
            "message": {
                "role":  "user",
                "parts": [{"type": "text", "text": input_text}],
            },
            "params": params or {},
        }
        r = requests.post(f"{self._url}/tasks/send", headers=self._headers,
                          json=body, timeout=self._timeout)
        r.raise_for_status()
        return r.json()

    def get_task(self, task_id: str) -> Dict[str, Any]:
        r = requests.get(f"{self._url}/tasks/{task_id}",
                         headers=self._headers, timeout=15)
        r.raise_for_status()
        return r.json()

    def open_channel(self, peer_agent_id: str, channel_type: str = "task") -> Dict[str, Any]:
        """Open an A2A channel via Connector Platform /tools/a2a/open."""
        return _post("/tools/a2a/open", {
            "peer_agent_id": peer_agent_id,
            "channel_type":  channel_type,
        })

    def send_channel_message(self, channel_id: str, message: str,
                              sender_pid: str = "a2a-client") -> Dict[str, Any]:
        """Send a message on an open A2A channel via /tools/a2a/send."""
        return _post("/tools/a2a/send", {
            "channel_id": channel_id,
            "sender_pid": sender_pid,
            "message":    message,
        })


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    logging.basicConfig(level=logging.INFO, stream=__import__("sys").stderr,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    parser = argparse.ArgumentParser(description="Connector Platform A2A Server")
    parser.add_argument("--host", default=A2A_HOST)
    parser.add_argument("--port", type=int, default=A2A_PORT)
    parser.add_argument("--base-url", default=BASE_URL,
                        help="Connector Platform base URL")
    args = parser.parse_args()

    try:
        from aiohttp import web
    except ImportError:
        logger.error("aiohttp required: pip install aiohttp")
        __import__("sys").exit(1)

    app = create_a2a_app(connector_base_url=args.base_url)
    logger.info("Connector A2A server on http://%s:%d", args.host, args.port)
    logger.info("Agent Card: http://%s:%d/.well-known/agent.json", args.host, args.port)
    web.run_app(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()

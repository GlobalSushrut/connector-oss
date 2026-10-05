"""
Connector Platform — MCP Server (Model Context Protocol 2025-03-26)

Exposes Connector Platform capabilities as an MCP server that any MCP client
(Claude Desktop, Cursor, VS Code Copilot, AutoGen, LangChain, etc.) can
connect to via stdio or SSE transport.

Spec: https://spec.modelcontextprotocol.io/specification/2025-03-26/

Exposed tools:
  connector_run_agent         — Run a single agent with trust scoring
  connector_run_pipeline      — Run a multi-agent pipeline
  connector_memory_write      — Write to kernel memory
  connector_memory_recall     — Recall from kernel memory
  connector_knowledge_query   — RAG knowledge retrieval
  connector_snapshot          — Take agent snapshot
  connector_restore           — Restore agent snapshot
  connector_list_agents       — List registered agents
  connector_action_log        — Query action log
  connector_proof_generate    — Generate proof of work
  connector_trust_score       — Get current trust score

Usage (stdio transport):
    python -m integrations.mcp_server

Usage (SSE transport):
    python -m integrations.mcp_server --transport sse --port 8765

Configure in claude_desktop_config.json:
    {
      "mcpServers": {
        "connector": {
          "command": "python",
          "args": ["-m", "integrations.mcp_server"],
          "env": {
            "CONNECTOR_BASE_URL": "http://localhost:9090/api/v1",
            "CONNECTOR_API_KEY": "your-key"
          }
        }
      }
    }
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
import uuid
from typing import Any, Dict, List, Optional

import requests

logger = logging.getLogger(__name__)


# ── Configuration ─────────────────────────────────────────────────────────────

BASE_URL  = os.environ.get("CONNECTOR_BASE_URL", "http://localhost:9090/api/v1")
API_KEY   = os.environ.get("CONNECTOR_API_KEY", "")
MCP_SERVER_NAME    = "connector-platform"
MCP_SERVER_VERSION = "1.0.0"
PROTOCOL_VERSION   = "2025-03-26"


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


# ── MCP Tool Definitions ──────────────────────────────────────────────────────

TOOLS: List[Dict[str, Any]] = [
    {
        "name": "connector_run_agent",
        "description": (
            "Run a single AI agent through the Connector Platform. "
            "Returns the agent response with a cryptographically verified trust score, "
            "kernel-backed audit trail, and compliance flags. "
            "Use this instead of calling LLMs directly to get tamper-proof provenance."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "agent":        {"type": "string", "description": "Agent name (e.g. 'assistant', 'analyst')"},
                "input":        {"type": "string", "description": "User input / prompt"},
                "user":         {"type": "string", "description": "User identifier for audit trail"},
                "instructions": {"type": "string", "description": "Optional system instructions"},
                "compliance":   {"type": "array", "items": {"type": "string"},
                                 "description": "Compliance frameworks: hipaa, soc2, gdpr, eu_ai_act"},
            },
            "required": ["agent", "input"],
        },
    },
    {
        "name": "connector_run_pipeline",
        "description": (
            "Run a multi-agent pipeline through the Connector Platform. "
            "Each agent in the pipeline processes output from the previous step. "
            "Supports parallel groups, human-in-the-loop approval, cost circuit breakers, "
            "and per-step failure policies (stop|skip|retry|fallback)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "name":         {"type": "string", "description": "Pipeline name"},
                "input":        {"type": "string", "description": "Initial input"},
                "user":         {"type": "string", "description": "User identifier"},
                "agents": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "name":         {"type": "string"},
                            "instructions": {"type": "string"},
                            "on_failure":   {"type": "string", "enum": ["stop", "skip", "retry", "fallback"]},
                        },
                        "required": ["name"],
                    },
                    "description": "Ordered list of agents",
                },
                "max_cost_usd": {"type": "number", "description": "Cost circuit breaker (USD)"},
                "max_tokens":   {"type": "integer", "description": "Token circuit breaker"},
                "compliance":   {"type": "array", "items": {"type": "string"}},
            },
            "required": ["name", "input", "agents"],
        },
    },
    {
        "name": "connector_memory_write",
        "description": (
            "Write a memory packet to the Connector kernel. "
            "All writes are CID-addressed, HMAC-chained, and immutable. "
            "Use to persist agent reasoning, decisions, or context for future recall."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "agent_pid":   {"type": "string", "description": "Agent PID to write into"},
                "content":     {"type": "string", "description": "Content to persist"},
                "user":        {"type": "string", "description": "User identifier"},
                "packet_type": {"type": "string",
                                "enum": ["input", "llm_raw", "decision", "action", "extraction", "feedback"],
                                "description": "Packet classification"},
            },
            "required": ["agent_pid", "content"],
        },
    },
    {
        "name": "connector_memory_recall",
        "description": (
            "Recall memory packets from the Connector kernel for a namespace. "
            "Returns CID-addressed packets with provenance metadata."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "namespace": {"type": "string", "description": "Namespace to recall from (e.g. 'ns:agent-name')"},
                "limit":     {"type": "integer", "description": "Max packets to return (default 50)"},
            },
            "required": ["namespace"],
        },
    },
    {
        "name": "connector_knowledge_query",
        "description": (
            "Query the Connector knowledge graph using RAG. "
            "Retrieves facts grounded in kernel memory with source CID provenance. "
            "Use before generation to provide verifiable context."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "entities":     {"type": "array", "items": {"type": "string"},
                                 "description": "Entity names to retrieve facts about"},
                "keywords":     {"type": "array", "items": {"type": "string"},
                                 "description": "Keywords to search for"},
                "token_budget": {"type": "integer", "description": "Max tokens for context (default 4096)"},
                "max_facts":    {"type": "integer", "description": "Max facts to return (default 20)"},
            },
        },
    },
    {
        "name": "connector_snapshot",
        "description": "Take a snapshot of an agent's current state for later restore.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "agent_pid": {"type": "string", "description": "Agent PID to snapshot"},
            },
            "required": ["agent_pid"],
        },
    },
    {
        "name": "connector_restore",
        "description": "Restore an agent from a previously taken snapshot.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "agent_pid":   {"type": "string", "description": "Agent PID to restore"},
                "snapshot_id": {"type": "string", "description": "Snapshot ID from connector_snapshot"},
            },
            "required": ["agent_pid", "snapshot_id"],
        },
    },
    {
        "name": "connector_list_agents",
        "description": "List all agents registered in the Connector Platform with their status and cost.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "description": "Max agents to return (default 50)"},
            },
        },
    },
    {
        "name": "connector_action_log",
        "description": "Query the immutable action log for audit and compliance evidence.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit":     {"type": "integer", "description": "Max entries (default 50)"},
                "agent_pid": {"type": "string", "description": "Filter by agent PID"},
            },
        },
    },
    {
        "name": "connector_proof_generate",
        "description": (
            "Generate a cryptographic proof-of-work certificate for an agent. "
            "Returns an Ed25519-signed certificate with trust score, CID chain, and audit trail. "
            "Use for compliance evidence, regulatory submissions, or audit packages."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "agent_pid":  {"type": "string", "description": "Agent to generate proof for"},
                "title":      {"type": "string", "description": "Certificate title"},
                "session_id": {"type": "string", "description": "Optional session scope"},
            },
            "required": ["agent_pid"],
        },
    },
    {
        "name": "connector_trust_score",
        "description": (
            "Get the current platform-wide trust score and per-dimension breakdown. "
            "Trust score is cryptographically derived from kernel state — "
            "memory integrity, audit completeness, authorization coverage, "
            "decision provenance, and operational health."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
]


# ── Tool executor ─────────────────────────────────────────────────────────────

def execute_tool(name: str, arguments: Dict[str, Any]) -> str:
    try:
        if name == "connector_run_agent":
            resp = _post("/multiagent/run-pipeline", {
                "name":   f"mcp_{arguments['agent']}",
                "agents": [{"name": arguments["agent"],
                             "instructions": arguments.get("instructions")}],
                "input":      arguments["input"],
                "user":       arguments.get("user", "mcp-client"),
                "compliance": arguments.get("compliance", []),
            })
            return json.dumps({
                "text":        resp.get("text"),
                "trust_score": resp.get("trust"),
                "trust_grade": resp.get("trust_grade"),
                "ok":          resp.get("ok"),
                "duration_ms": resp.get("duration_ms"),
                "trace_id":    resp.get("trace_id"),
                "pipeline_id": resp.get("pipeline_id"),
                "warnings":    resp.get("warnings", []),
                "cost":        resp.get("cost", {}),
            }, indent=2)

        elif name == "connector_run_pipeline":
            resp = _post("/multiagent/run-pipeline", {
                "name":         arguments["name"],
                "agents":       arguments["agents"],
                "input":        arguments["input"],
                "user":         arguments.get("user", "mcp-client"),
                "compliance":   arguments.get("compliance", []),
                "max_cost_usd": arguments.get("max_cost_usd"),
                "max_tokens":   arguments.get("max_tokens"),
            })
            return json.dumps(resp, indent=2)

        elif name == "connector_memory_write":
            resp = _post("/memory/write", {
                "agent_pid":   arguments["agent_pid"],
                "content":     arguments["content"],
                "user":        arguments.get("user", "mcp-client"),
                "pipeline":    "mcp",
                "packet_type": arguments.get("packet_type", "input"),
            })
            return json.dumps({"ok": resp.get("ok"), "cid": resp.get("cid")}, indent=2)

        elif name == "connector_memory_recall":
            resp = _get(f"/memory/recall/{arguments['namespace']}",
                        limit=arguments.get("limit", 50))
            return json.dumps({
                "count":   resp.get("count"),
                "packets": resp.get("packets", []),
            }, indent=2)

        elif name == "connector_knowledge_query":
            resp = _post("/memory/knowledge/query", {
                "entities":     arguments.get("entities", []),
                "keywords":     arguments.get("keywords", []),
                "token_budget": arguments.get("token_budget", 4096),
                "max_facts":    arguments.get("max_facts", 20),
            })
            return json.dumps({
                "facts":           resp.get("facts", []),
                "facts_included":  resp.get("facts_included"),
                "tokens_used":     resp.get("tokens_used"),
                "prompt_context":  resp.get("prompt_context", ""),
            }, indent=2)

        elif name == "connector_snapshot":
            resp = _post(f"/debug/agents/{arguments['agent_pid']}/snapshot", {})
            return json.dumps(resp, indent=2)

        elif name == "connector_restore":
            resp = _post(f"/debug/agents/{arguments['agent_pid']}/restore",
                         {"snapshot_id": arguments["snapshot_id"]})
            return json.dumps(resp, indent=2)

        elif name == "connector_list_agents":
            resp = _get("/agents", limit=arguments.get("limit", 50))
            return json.dumps({"count": resp.get("count"), "agents": resp.get("agents", [])}, indent=2)

        elif name == "connector_action_log":
            resp = _get("/actionlog/list",
                        limit=arguments.get("limit", 50),
                        agent_pid=arguments.get("agent_pid", ""))
            return json.dumps({"count": resp.get("count"), "actions": resp.get("actions", [])}, indent=2)

        elif name == "connector_proof_generate":
            resp = _post("/proof/generate", {
                "agent_pid":  arguments["agent_pid"],
                "title":      arguments.get("title"),
                "session_id": arguments.get("session_id"),
            })
            return json.dumps(resp, indent=2)

        elif name == "connector_trust_score":
            resp = _get("/monitor/health")
            return json.dumps({
                "trust_score":  resp.get("trust_score"),
                "trust_grade":  resp.get("trust_grade"),
                "status":       resp.get("status"),
                "dimensions":   resp.get("dimensions", {}),
                "governance":   resp.get("governance", {}),
            }, indent=2)

        else:
            return json.dumps({"error": f"Unknown tool: {name}"})

    except Exception as exc:
        return json.dumps({"error": str(exc), "tool": name})


# ── MCP JSON-RPC message handlers ────────────────────────────────────────────

def handle_message(msg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    method = msg.get("method", "")
    msg_id = msg.get("id")

    def ok(result: Any) -> Dict[str, Any]:
        return {"jsonrpc": "2.0", "id": msg_id, "result": result}

    def err(code: int, message: str) -> Dict[str, Any]:
        return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}

    if method == "initialize":
        return ok({
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {
                "tools":     {"listChanged": False},
                "resources": {},
                "prompts":   {},
                "logging":   {},
            },
            "serverInfo": {
                "name":    MCP_SERVER_NAME,
                "version": MCP_SERVER_VERSION,
            },
        })

    elif method == "notifications/initialized":
        return None  # notification, no response

    elif method == "tools/list":
        return ok({"tools": TOOLS})

    elif method == "tools/call":
        params     = msg.get("params", {})
        tool_name  = params.get("name", "")
        arguments  = params.get("arguments", {})

        result_text = execute_tool(tool_name, arguments)
        return ok({
            "content": [{"type": "text", "text": result_text}],
            "isError": False,
        })

    elif method == "resources/list":
        return ok({"resources": []})

    elif method == "prompts/list":
        return ok({"prompts": []})

    elif method == "ping":
        return ok({})

    else:
        if msg_id is not None:
            return err(-32601, f"Method not found: {method}")
        return None  # unknown notification


# ── Stdio transport ───────────────────────────────────────────────────────────

def run_stdio():
    logger.info("Connector MCP server starting (stdio transport)")
    for raw_line in sys.stdin:
        raw_line = raw_line.strip()
        if not raw_line:
            continue
        try:
            msg = json.loads(raw_line)
        except json.JSONDecodeError as exc:
            response = {"jsonrpc": "2.0", "id": None,
                        "error": {"code": -32700, "message": f"Parse error: {exc}"}}
            print(json.dumps(response), flush=True)
            continue

        response = handle_message(msg)
        if response is not None:
            print(json.dumps(response), flush=True)


# ── SSE transport ─────────────────────────────────────────────────────────────

def run_sse(host: str = "0.0.0.0", port: int = 8765):
    """
    SSE transport for browser-based MCP clients.
    Uses aiohttp for async SSE; falls back to a simple message loop.
    """
    try:
        from aiohttp import web

        async def _sse_handler(request: web.Request) -> web.StreamResponse:
            resp = web.StreamResponse(headers={
                "Content-Type":                "text/event-stream",
                "Cache-Control":               "no-cache",
                "Access-Control-Allow-Origin": "*",
            })
            await resp.prepare(request)

            async for chunk in request.content:
                try:
                    msg = json.loads(chunk.decode())
                    result = handle_message(msg)
                    if result:
                        await resp.write(f"data: {json.dumps(result)}\n\n".encode())
                except Exception as exc:
                    logger.warning("SSE handler error: %s", exc)

            return resp

        async def _post_handler(request: web.Request) -> web.Response:
            body = await request.json()
            result = handle_message(body)
            return web.json_response(result or {})

        app = web.Application()
        app.router.add_get("/mcp", _sse_handler)
        app.router.add_post("/mcp", _post_handler)

        logger.info("Connector MCP SSE server on http://%s:%d/mcp", host, port)
        web.run_app(app, host=host, port=port)

    except ImportError:
        logger.error("aiohttp not installed. Run: pip install aiohttp")
        sys.exit(1)


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    logging.basicConfig(level=logging.INFO, stream=sys.stderr,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    parser = argparse.ArgumentParser(description="Connector Platform MCP Server")
    parser.add_argument("--transport", choices=["stdio", "sse"], default="stdio")
    parser.add_argument("--host",      default="0.0.0.0")
    parser.add_argument("--port",      type=int, default=8765)
    args = parser.parse_args()

    if args.transport == "sse":
        run_sse(args.host, args.port)
    else:
        run_stdio()


if __name__ == "__main__":
    main()

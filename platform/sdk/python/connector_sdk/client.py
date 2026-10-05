"""
ConnectorAgent — DEPRECATED. Use GLUE instead.

GLUE is the new canonical interface that replaces this SDK.
See: platform/docs/GLUE_VS_SDK.md for migration guide.

DEPRECATED Usage (old way):
    from connector_sdk import ConnectorAgent
    agent = ConnectorAgent("my-agent")
    agent.remember("User prefers dark mode")

RECOMMENDED Usage (GLUE - 10x easier):
    from connector_sdk import glue
    
    # One line to run an agent
    result = glue.run("my-agent", {"input": "Hello"})
    
    # Simple memory operations
    glue.remember("preferences", "User prefers dark mode")
    memories = glue.recall("preferences").execute()
    
    # Automatic audit, compliance, and governance
    print(result.receipt.trace_id)  # Full audit trail included

Benefits of GLUE over this SDK:
- 10x fewer lines of code
- Automatic compliance and audit
- Structured errors with hints
- CLS contracts inline in Python
- No endpoint memorization needed
"""

from __future__ import annotations

import os
import json
import time
import uuid
from typing import Any, Dict, List, Optional, Union

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False

from .exceptions import ConnectorError, AgentNotFoundError, QuotaExceededError, AuthError


class ConnectorClient:
    """
    Low-level HTTP client for the Connector Platform API.
    Handles auth, error parsing, and retries.
    """

    def __init__(
        self,
        base_url: str = None,
        token: str = None,
        timeout: int = 30,
        retries: int = 3,
    ):
        if base_url is None:
            base_url = os.getenv("CONNECTOR_BASE_URL", "http://127.0.0.1:9091")
        if not HAS_REQUESTS:
            raise ImportError("connector-sdk requires 'requests'. Install with: pip install requests")

        if token is None:
            token = os.getenv("CONNECTOR_TOKEN") or os.getenv("CONNECTOR_API_TOKEN")
        profile = os.getenv("CONNECTOR_RUNTIME_PROFILE", "development").strip().lower()
        lab = profile in ("lab", "dev", "development", "test")
        if not token:
            if lab:
                token = ""
            else:
                raise ConnectorError(
                    "token_required: set CONNECTOR_TOKEN (no silent default outside lab)"
                )
        if token == "dev-token" and not lab:
            raise ConnectorError(
                "token_refused: default/dev-token is not allowed outside lab profile"
            )

        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout
        self.retries = retries
        self._session = requests.Session()
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "connector-sdk-python/0.1.0",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"
        self._session.headers.update(headers)

    def get(self, path: str, params: Dict = None) -> Dict:
        return self._request("GET", path, params=params)

    def post(self, path: str, body: Dict = None) -> Dict:
        return self._request("POST", path, json=body or {})

    def _request(self, method: str, path: str, **kwargs) -> Dict:
        url = f"{self.base_url}/api/v1{path}"
        last_error = None

        for attempt in range(self.retries):
            try:
                resp = self._session.request(method, url, timeout=self.timeout, **kwargs)
                return self._parse(resp)
            except requests.ConnectionError as e:
                last_error = ConnectorError(
                    f"Cannot connect to Connector at {self.base_url}. "
                    f"Is the server running? Start with: CONNECTOR_DEV_MODE=1 cargo run",
                    status_code=0,
                )
                if attempt < self.retries - 1:
                    time.sleep(0.5 * (attempt + 1))
            except requests.Timeout:
                last_error = ConnectorError(f"Request timed out after {self.timeout}s", status_code=408)
                if attempt < self.retries - 1:
                    time.sleep(0.5 * (attempt + 1))

        raise last_error

    def _parse(self, resp: "requests.Response") -> Dict:
        if resp.status_code == 401:
            raise AuthError(
                "Authentication failed. In dev mode, set CONNECTOR_DEV_MODE=1 on the server. "
                "Use token='dev-token' on the client.",
                status_code=401,
            )
        if resp.status_code == 422:
            try:
                detail = resp.json()
            except Exception:
                detail = {"error": resp.text}
            raise ConnectorError(
                f"Invalid request: {detail}. Check the field names and types.",
                status_code=422,
                response=detail,
            )
        if resp.status_code == 429:
            raise QuotaExceededError("Rate limit or quota exceeded", status_code=429)

        try:
            data = resp.json()
        except Exception:
            raise ConnectorError(f"Server returned non-JSON response (status {resp.status_code}): {resp.text[:200]}")

        if isinstance(data, dict) and data.get("ok") is False:
            error_msg = data.get("error", "Unknown error")
            if "not found" in str(error_msg).lower():
                raise AgentNotFoundError(error_msg, status_code=resp.status_code, response=data)
            raise ConnectorError(error_msg, status_code=resp.status_code, response=data)

        return data

    def capabilities(self) -> Dict:
        """Return the full platform capability manifest."""
        return self._request("GET", "")


class ConnectorAgent:
    """
    High-level agent interface. One object, all capabilities.

    Three lines to a working agent:
        agent = ConnectorAgent("my-agent")
        agent.remember("User prefers dark mode")
        memories = agent.recall()
    """

    def __init__(
        self,
        name: str,
        namespace: str = None,
        base_url: str = None,
        token: str = "dev-token",
        auto_register: bool = True,
        timeout: int = 30,
    ):
        if base_url is None:
            base_url = os.getenv("CONNECTOR_BASE_URL", "http://localhost:8080")
        self.name = name
        self.namespace = namespace or name
        self.client = ConnectorClient(base_url=base_url, token=token, timeout=timeout)
        self._pid: Optional[str] = None
        self._registered = False

        if auto_register:
            self._ensure_registered()

    # ── Registration ──────────────────────────────────────────────────────────

    def _ensure_registered(self) -> str:
        """Register the agent if not already registered. Idempotent."""
        if self._registered and self._pid:
            return self._pid
        try:
            result = self.client.post("/agents", {
                "name": self.name,
                "namespace": self.namespace,
            })
            self._pid = result.get("agent_pid") or result.get("pid") or self.name
            self._registered = True
            return self._pid
        except ConnectorError as e:
            # Only swallow 409 Conflict (agent already registered) — not auth/server errors
            if e.status_code == 409 or ("already" in str(e).lower() and e.status_code in (409, 422)):
                self._pid = self.name
                self._registered = True
                return self._pid
            if e.status_code in (401, 403):
                raise ConnectorError(
                    f"Authentication failed during agent registration. "
                    f"Check your token or set CONNECTOR_DEV_MODE=1 on the server. ({e})",
                    status_code=e.status_code,
                ) from e
            raise

    @property
    def pid(self) -> str:
        return self._pid or self.name

    # ── Memory ────────────────────────────────────────────────────────────────

    def remember(
        self,
        content: str,
        memory_type: str = "Feedback",
        tags: List[str] = None,
        session_id: str = None,
    ) -> Dict:
        """
        Write a memory packet.

        Args:
            content:     The text to remember.
            memory_type: One of Input, LlmRaw, Decision, Extraction, Action,
                         Feedback, Sync, Seed. Default: Feedback.
            tags:        Optional list of tags for retrieval.
            session_id:  Optional session ID for grouping.

        Returns:
            {"ok": True, "cid": "<content-id>"}

        Example:
            agent.remember("User is a senior engineer at a fintech startup")
            agent.remember("Contract approved", memory_type="Decision", tags=["legal"])
        """
        self._ensure_registered()
        body: Dict[str, Any] = {
            "content": content,
            "agent_pid": self.pid,
            "type": memory_type,
        }
        if tags:
            body["tags"] = tags
        if session_id:
            body["session_id"] = session_id
        return self.client.post("/memory/write", body)

    def recall(
        self,
        query: str = None,
        namespace: str = None,
        limit: int = 20,
    ) -> List[Dict]:
        """
        Recall memory packets from this agent's namespace.

        Args:
            query:     Optional search query (semantic search).
            namespace: Override namespace (default: agent's namespace).
            limit:     Max results to return.

        Returns:
            List of memory packets with cid, content, type, tags, timestamp.

        Example:
            memories = agent.recall()
            relevant = agent.recall("user preferences", limit=5)
        """
        self._ensure_registered()
        ns = namespace or self.namespace
        result = self.client.get(f"/memory/recall/{ns}", params={"q": query, "limit": limit} if query else {"limit": limit})
        return result.get("packets", result.get("memories", []))

    # ── Cognitive Cycle ───────────────────────────────────────────────────────

    def think(
        self,
        input_text: str,
        session_id: str = None,
        tools: List[str] = None,
    ) -> Dict:
        """
        Run a full cognitive cycle (ReAct-equivalent: observe → plan → act → reflect).

        Requires CONNECTOR_LLM_API_KEY to be set on the server for LLM calls.

        Args:
            input_text:  The user input or task description.
            session_id:  Optional session for continuity.
            tools:       Optional list of tool names to make available.

        Returns:
            {"output": "...", "steps": [...], "tokens_used": N}

        Example:
            result = agent.think("What are the user's preferences?")
            print(result["output"])
        """
        self._ensure_registered()
        body: Dict[str, Any] = {
            "agent_pid": self.pid,
            "input": input_text,
        }
        if session_id:
            body["session_id"] = session_id
        if tools:
            body["tools"] = tools
        return self.client.post("/cognitive/cycle", body)

    # ── Hallucination Safety ──────────────────────────────────────────────────

    def verify_claim(
        self,
        source_text: str,
        claims: List[Union[str, Dict]],
        source_cid: str = None,
    ) -> Dict:
        """
        Verify LLM-generated claims against source text.
        Detects hallucinations deterministically.

        Args:
            source_text: The original source document text.
            claims:      List of claim strings or dicts with item/quote/support.
            source_cid:  Optional CID of the source document.

        Returns:
            {
                "ok": True,
                "hallucination_safe": True/False,
                "confirmed": [...],
                "rejected": [...],
                "warnings": [...],
                "total_claims": N,
            }

        Example:
            result = agent.verify_claim(
                source_text="Drug reduced symptoms by 45%",
                claims=["45% reduction", "100% cure rate"]
            )
            if not result["hallucination_safe"]:
                print("WARNING:", result["warnings"])
        """
        normalized = []
        for c in claims:
            if isinstance(c, str):
                normalized.append({"item": c, "category": "general", "quote": c, "support": "explicit"})
            else:
                normalized.append(c)

        return self.client.post("/safety/claims/verify", {
            "source_cid": source_cid or f"sdk:{uuid.uuid4().hex[:8]}",
            "source_text": source_text,
            "claims": normalized,
        })

    def safety_check(self) -> Dict:
        """
        Run all 6 TLA+ formal invariants on the current kernel state.
        Use this to prove your AI system is operating correctly.

        Returns:
            {
                "ok": True,
                "all_invariants_passed": True/False,
                "invariants": [{"invariant": "...", "passed": True, "violations": []}, ...],
                "violation_count": 0,
            }

        Example:
            report = agent.safety_check()
            assert report["all_invariants_passed"], f"Safety violation: {report}"
        """
        return self.client.get("/safety/formal/verify")

    def ground(self, term: str, category: str = "medical") -> Optional[Dict]:
        """
        Look up a term in the deterministic grounding table.
        Returns None if not found (potential hallucination signal).

        Example:
            entry = agent.ground("type 2 diabetes", category="icd10")
            if entry is None:
                print("UNVERIFIED TERM — possible hallucination")
        """
        result = self.client.post("/safety/grounding/lookup", {
            "category": category,
            "term": term,
            "fuzzy": True,
        })
        if result.get("found"):
            return {"code": result.get("code"), "description": result.get("description"), "system": result.get("system")}
        return None

    # ── Protocol Bridges ──────────────────────────────────────────────────────

    def mcp_discover(self, server_url: str) -> Dict:
        """
        Discover tools available on a remote MCP server.

        Example:
            tools = agent.mcp_discover("http://tools.example.com")
            print(tools["tools"])
        """
        return self.client.post("/protocols/mcp/discover", {"server_url": server_url})

    def mcp_call(self, server_url: str, tool_name: str, arguments: Dict = None) -> Dict:
        """
        Call a tool on a remote MCP server.

        Example:
            result = agent.mcp_call(
                "http://tools.example.com",
                "search",
                {"query": "recent filings"}
            )
        """
        return self.client.post("/protocols/mcp/call", {
            "server_url": server_url,
            "tool_name": tool_name,
            "arguments": arguments or {},
        })

    def a2a_task(self, message: str, session_id: str = None) -> Dict:
        """
        Submit a task to this platform via the A2A protocol.
        Compatible with Google A2A clients.

        Example:
            task = agent.a2a_task("Summarize the Q3 financial report")
            print(task["task_id"], task["state"])
        """
        body: Dict[str, Any] = {"message": message}
        if session_id:
            body["session_id"] = session_id
        return self.client.post("/protocols/a2a/tasks", body)

    def send_message(self, to: str, content: str, content_type: str = "text/plain") -> Dict:
        """
        Send an async message to another agent via ACP.

        Example:
            agent.send_message("agent-reviewer", "Please review contract-001")
        """
        return self.client.post("/protocols/acp/messages", {
            "message_id": f"msg-{uuid.uuid4().hex[:8]}",
            "sender": self.pid,
            "recipient": to,
            "content": content,
            "content_type": content_type,
        })

    # ── Infrastructure ────────────────────────────────────────────────────────

    def store_secret(self, secret_id: str, value: str, ttl_hours: int = 24) -> str:
        """
        Store a secret in the kernel vault. Returns an opaque handle ID.
        The raw value is never returned after storage.

        Example:
            handle = agent.store_secret("stripe-key", "sk_live_xxx")
            # Use handle to reference the secret without exposing the value
        """
        result = self.client.post("/infra/vault/secrets", {
            "secret_id": secret_id,
            "value": value,
            "owner_pid": self.pid,
            "ttl_secs": ttl_hours * 3600,
        })
        return result["handle_id"]

    def propose_consensus(self, round_id: int, value: Any) -> Dict:
        """
        Propose a value for BFT consensus across all validator agents.

        Example:
            result = agent.propose_consensus(1, {"action": "approve_contract", "id": "c-001"})
        """
        return self.client.post("/infra/consensus/propose", {
            "round": round_id,
            "proposer": self.pid,
            "value": value,
        })

    def set_quota(self, namespace: str, limit: int) -> Dict:
        """
        Set a global token quota for a namespace.

        Example:
            agent.set_quota("production", 1_000_000)
        """
        return self.client.post("/infra/quota/set", {
            "namespace": namespace,
            "limit": limit,
        })

    def submit_pipeline(self, tasks: List[Dict]) -> Dict:
        """
        Submit a DAG of tasks for parallel execution via the orchestrator.

        Args:
            tasks: List of dicts with task_id, agent_pid, action, payload, dependencies.

        Example:
            result = agent.submit_pipeline([
                {"task_id": "fetch",    "agent_pid": "fetcher",    "action": "fetch_data",   "dependencies": []},
                {"task_id": "analyze",  "agent_pid": "analyzer",   "action": "analyze",      "dependencies": ["fetch"]},
                {"task_id": "report",   "agent_pid": "reporter",   "action": "write_report", "dependencies": ["analyze"]},
            ])
            print("Pipeline ID:", result["orchestrator_id"])
        """
        return self.client.post("/infra/orchestrator/submit", {"tasks": tasks})

    # ── Audit ─────────────────────────────────────────────────────────────────

    def audit_log(self, limit: int = 100) -> List[Dict]:
        """
        Return the full audit log for this platform (HIPAA/SOC2 ready).

        Example:
            log = agent.audit_log()
            for entry in log:
                print(entry["action"], entry["timestamp"])
        """
        result = self.client.get("/actionlog/actions", params={"limit": limit})
        return result.get("actions", result.get("entries", []))

    # ── Reputation ────────────────────────────────────────────────────────────

    def stake(self, amount: int = 1000) -> Dict:
        """Register this agent's stake in the EigenTrust reputation system."""
        return self.client.post("/infra/reputation/stake", {
            "agent_pid": self.pid,
            "stake": amount,
        })

    def rate_peer(self, peer_pid: str, score: float, context: str = "") -> Dict:
        """
        Submit a reputation feedback score for a peer agent.
        Score is 0.0 (terrible) to 1.0 (excellent).

        Example:
            agent.rate_peer("agent-reviewer", 0.9, context="great review on contract-001")
        """
        return self.client.post("/infra/reputation/feedback", {
            "from_pid": self.pid,
            "to_pid": peer_pid,
            "score": score,
            "weight": 0.5,
            "context": context,
        })

    # ── D13: Async Methods (asyncio + aiohttp) ────────────────────────────────

    async def _async_request(self, method: str, path: str, **kwargs) -> Dict:
        """Low-level async HTTP request using aiohttp."""
        if not HAS_AIOHTTP:
            raise ImportError(
                "Async methods require 'aiohttp'. Install with: pip install aiohttp"
            )
        url = f"{self.client.base_url}/api/v1{path}"
        headers = {
            "Authorization": f"Bearer {self.client.token}",
            "Content-Type": "application/json",
            "User-Agent": "connector-sdk-python/0.1.0",
        }
        timeout = aiohttp.ClientTimeout(total=self.client.timeout)
        async with aiohttp.ClientSession(headers=headers, timeout=timeout) as session:
            async with session.request(method, url, **kwargs) as resp:
                if resp.status == 429:
                    raise QuotaExceededError("Rate limit exceeded", status_code=429)
                if resp.status == 401:
                    raise AuthError("Authentication failed", status_code=401)
                data = await resp.json(content_type=None)
                if isinstance(data, dict) and data.get("ok") is False:
                    raise ConnectorError(
                        data.get("error", "Unknown error"),
                        status_code=resp.status,
                        response=data,
                    )
                return data

    async def aremember(
        self,
        content: str,
        memory_type: str = "Feedback",
        tags: List[str] = None,
        session_id: str = None,
    ) -> Dict:
        """
        Async variant of remember(). Write a memory packet using asyncio + aiohttp.

        Args:
            content:     The text to remember.
            memory_type: One of Input, LlmRaw, Decision, Extraction, Action,
                         Feedback, Sync, Seed. Default: Feedback.
            tags:        Optional list of tags for retrieval.
            session_id:  Optional session ID for grouping.

        Returns:
            {"ok": True, "cid": "<content-id>"}

        Example:
            await agent.aremember("User prefers async I/O")
            await agent.aremember("Contract approved", memory_type="Decision", tags=["legal"])
        """
        self._ensure_registered()
        body: Dict[str, Any] = {
            "content": content,
            "agent_pid": self.pid,
            "type": memory_type,
        }
        if tags:
            body["tags"] = tags
        if session_id:
            body["session_id"] = session_id
        return await self._async_request("POST", "/memory/write", json=body)

    async def arecall(
        self,
        query: str = None,
        namespace: str = None,
        limit: int = 20,
    ) -> List[Dict]:
        """
        Async variant of recall(). Recall memory packets using asyncio + aiohttp.

        Args:
            query:     Optional search query (semantic search).
            namespace: Override namespace (default: agent's namespace).
            limit:     Max results to return.

        Returns:
            List of memory packets with cid, content, type, tags, timestamp.

        Example:
            memories = await agent.arecall()
            relevant = await agent.arecall("user preferences", limit=5)
        """
        self._ensure_registered()
        ns = namespace or self.namespace
        params: Dict[str, Any] = {"limit": limit}
        if query:
            params["q"] = query
        result = await self._async_request("GET", f"/memory/recall/{ns}", params=params)
        return result.get("packets", result.get("memories", []))

    async def arun(
        self,
        input_text: str,
        session_id: str = None,
        tools: List[str] = None,
    ) -> Dict:
        """
        Async variant of think(). Run a full cognitive cycle using asyncio + aiohttp.

        Args:
            input_text:  The user input or task description.
            session_id:  Optional session for continuity.
            tools:       Optional list of tool names to make available.

        Returns:
            {"output": "...", "steps": [...], "tokens_used": N}

        Example:
            result = await agent.arun("Summarize the user's preferences")
            print(result["output"])
        """
        self._ensure_registered()
        body: Dict[str, Any] = {
            "agent_pid": self.pid,
            "input": input_text,
        }
        if session_id:
            body["session_id"] = session_id
        if tools:
            body["tools"] = tools
        return await self._async_request("POST", "/cognitive/cycle", json=body)

    async def stream(
        self,
        input_text: str,
        session_id: str = None,
    ):
        """
        Async generator that streams agent reasoning token-by-token via SSE.

        Yields dicts of one of three types:
          - ``{"type": "token_delta", "delta": "..."}``
          - ``{"type": "tool_call", "tool": "...", "args": {...}}``
          - ``{"type": "final_output", "output": "...", "tokens_used": N}``

        Requires ``aiohttp``. Install with: ``pip install aiohttp``

        Example::

            async for event in agent.stream("Summarize the user profile"):
                if event["type"] == "token_delta":
                    print(event["delta"], end="", flush=True)
                elif event["type"] == "final_output":
                    print()  # newline after streaming
        """
        if not HAS_AIOHTTP:
            raise ImportError("stream() requires 'aiohttp'. Install with: pip install aiohttp")
        self._ensure_registered()
        url = f"{self.client.base_url}/api/v1/v1/chat/completions"
        body: Dict[str, Any] = {
            "model": "connector-agent",
            "stream": True,
            "messages": [{"role": "user", "content": input_text}],
            "agent_pid": self.pid,
        }
        if session_id:
            body["session_id"] = session_id
        headers = {
            "Authorization": f"Bearer {self.client.token}",
            "Content-Type": "application/json",
            "Accept": "text/event-stream",
        }
        timeout = aiohttp.ClientTimeout(total=120)
        async with aiohttp.ClientSession(headers=headers, timeout=timeout) as session:
            async with session.post(url, json=body) as resp:
                if resp.status == 401:
                    raise AuthError("Authentication failed", status_code=401)
                if resp.status == 429:
                    raise QuotaExceededError("Rate limit exceeded", status_code=429)
                async for raw_line in resp.content:
                    line = raw_line.decode("utf-8", errors="replace").strip()
                    if not line or not line.startswith("data:"):
                        continue
                    data_str = line[5:].strip()
                    if data_str == "[DONE]":
                        return
                    try:
                        chunk = json.loads(data_str)
                    except json.JSONDecodeError:
                        continue
                    choices = chunk.get("choices", [])
                    if not choices:
                        continue
                    delta = choices[0].get("delta", {})
                    finish = choices[0].get("finish_reason")
                    if delta.get("content"):
                        yield {"type": "token_delta", "delta": delta["content"]}
                    if finish == "stop":
                        usage = chunk.get("usage", {})
                        yield {
                            "type": "final_output",
                            "output": "",
                            "tokens_used": usage.get("total_tokens", 0),
                        }

    def remember_kv(self, key: str, value: Any, ttl_seconds: int = None) -> Dict:
        """
        Simple key-value memory store on top of MemPackets.

        Stores ``value`` as a JSON-serialised ``Seed`` packet tagged with ``kv:{key}``.
        Use ``recall_kv(key)`` to retrieve it.

        Args:
            key:         Logical key name (e.g. ``"user_pref_theme"``).
            value:       Any JSON-serialisable value.
            ttl_seconds: Optional TTL hint stored in tags.

        Example::

            agent.remember_kv("user_tier", "pro")
            agent.remember_kv("last_order_id", 12345, ttl_seconds=3600)
        """
        self._ensure_registered()
        tags = [f"kv:{key}"]
        if ttl_seconds:
            tags.append(f"ttl:{ttl_seconds}")
        content = json.dumps({"__kv_key__": key, "__kv_value__": value})
        return self.client.post("/memory/write", {
            "content": content,
            "agent_pid": self.pid,
            "type": "Seed",
            "tags": tags,
        })

    def recall_kv(self, key: str) -> Any:
        """
        Retrieve a value stored via ``remember_kv(key, value)``.

        Returns the stored value, or ``None`` if not found.

        Example::

            theme = agent.recall_kv("user_pref_theme")  # → "pro"
        """
        self._ensure_registered()
        ns = self.namespace
        result = self.client.get(
            f"/memory/recall/{ns}",
            params={"q": f"kv:{key}", "limit": 1},
        )
        packets = result.get("packets", result.get("memories", []))
        for pkt in reversed(packets):
            content = pkt.get("content", "")
            try:
                data = json.loads(content) if isinstance(content, str) else content
                if isinstance(data, dict) and data.get("__kv_key__") == key:
                    return data.get("__kv_value__")
            except (json.JSONDecodeError, TypeError):
                continue
        return None

    def run_typed(self, input_text: str, output_model=None, session_id: str = None) -> Any:
        """
        Run a cognitive cycle and validate the output against ``output_model``.

        If ``output_model`` is a Pydantic model class, the response ``output``
        field is parsed and validated. Returns the model instance on success.
        Returns the raw output string if no model is provided.

        Args:
            input_text:   The user input or task description.
            output_model: Optional Pydantic ``BaseModel`` subclass for validation.
            session_id:   Optional session for continuity.

        Example::

            from pydantic import BaseModel

            class Summary(BaseModel):
                title: str
                bullets: list[str]

            result = agent.run_typed("Summarise Q4 results", Summary)
            print(result.title)
        """
        result = self.think(input_text, session_id=session_id)
        raw_output = result.get("output", "")
        if output_model is None:
            return raw_output
        try:
            data = json.loads(raw_output) if isinstance(raw_output, str) else raw_output
            return output_model(**data) if isinstance(data, dict) else output_model.model_validate(data)
        except Exception as exc:
            raise ConnectorError(
                f"Output validation failed for {output_model.__name__}: {exc}",
                status_code=422,
                response={"raw": raw_output},
            ) from exc

    # ── Utils ─────────────────────────────────────────────────────────────────

    def __repr__(self) -> str:
        return f"ConnectorAgent(name={self.name!r}, namespace={self.namespace!r}, pid={self._pid!r})"

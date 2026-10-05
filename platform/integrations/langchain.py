"""
Connector Platform — LangChain Integration
Traces LLM calls, tool invocations, and chain events via BaseCallbackHandler.

Usage:
    from integrations.langchain import ConnectorCallbackHandler
    handler = ConnectorCallbackHandler(
        base_url="http://localhost:8080/api/v1",
        api_key="cp-...",
        agent_pid="agent_abc123",
    )
    llm = ChatOpenAI(callbacks=[handler])
"""

from __future__ import annotations

import asyncio
import time
import uuid
from typing import Any, Dict, List, Optional, Union

try:
    from langchain_core.callbacks.base import BaseCallbackHandler, AsyncCallbackHandler
    from langchain_core.messages import BaseMessage
    from langchain_core.outputs import LLMResult
except ImportError:
    try:
        from langchain.callbacks.base import BaseCallbackHandler, AsyncCallbackHandler
        from langchain.schema import BaseMessage, LLMResult
    except ImportError:
        raise ImportError(
            "langchain or langchain-core is required. "
            "Install with: pip install langchain-core"
        )

try:
    import httpx
    _HTTPX_AVAILABLE = True
except ImportError:
    _HTTPX_AVAILABLE = False

import requests


def _get_or_create_event_loop() -> asyncio.AbstractEventLoop:
    try:
        return asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        return loop


class ConnectorCallbackHandler(BaseCallbackHandler):
    """LangChain callback handler that writes traces to the Connector Platform.

    Each LLM call, tool call, and chain event is written as a memory packet
    and recorded in the action log via the platform REST API.

    async_mode=True (default): uses httpx.AsyncClient — zero threads, no blocking.
    async_mode=False: uses requests.Session synchronously.
    """

    def __init__(
        self,
        base_url: str = "http://localhost:8080/api/v1",
        api_key: Optional[str] = None,
        agent_pid: Optional[str] = None,
        namespace: Optional[str] = None,
        timeout: int = 5,
        async_mode: bool = True,
    ) -> None:
        super().__init__()
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.agent_pid = agent_pid or f"lc_{uuid.uuid4().hex[:8]}"
        self.namespace = namespace or self.agent_pid
        self.timeout = timeout
        self.async_mode = async_mode and _HTTPX_AVAILABLE

        self._headers: Dict[str, str] = {"Content-Type": "application/json"}
        if api_key:
            self._headers["Authorization"] = f"Bearer {api_key}"

        # Sync fallback (async_mode=False or httpx not installed)
        self._session = requests.Session()
        self._session.headers.update(self._headers)

        # Async client — created lazily per event loop to avoid loop-binding issues
        self._async_client: Optional[Any] = None

        self._timers: Dict[str, float] = {}

    def _get_async_client(self) -> Any:
        if self._async_client is None or self._async_client.is_closed:
            self._async_client = httpx.AsyncClient(
                headers=self._headers,
                timeout=self.timeout,
            )
        return self._async_client

    def _post(self, path: str, payload: Dict[str, Any]) -> None:
        url = f"{self.base_url}{path}"
        if self.async_mode:
            # DX-P3-3: true async — schedule coroutine on the running loop.
            # If called from a sync context, fire-and-forget via ensure_future.
            async def _send() -> None:
                try:
                    client = self._get_async_client()
                    await client.post(url, json=payload)
                except Exception:
                    pass

            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    asyncio.ensure_future(_send())
                else:
                    loop.run_until_complete(_send())
            except Exception:
                pass
        else:
            try:
                self._session.post(url, json=payload, timeout=self.timeout)
            except Exception:
                pass

    def _write_packet(
        self,
        packet_type: str,
        content: str,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        self._post("/memory/write", {
            "agent_pid": self.agent_pid,
            "namespace": self.namespace,
            "packet_type": packet_type,
            "content": content,
            "tags": tags or [],
            "metadata": metadata or {},
        })

    def _log_action(
        self,
        intent: str,
        action: str,
        outcome: str,
        duration_ms: int = 0,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        self._post("/actionlog/record", {
            "agent_pid": self.agent_pid,
            "intent": intent,
            "action": action,
            "outcome": outcome,
            "duration_ms": duration_ms,
            "metadata": metadata or {},
        })

    def _elapsed(self, key: str) -> int:
        return int((time.monotonic() - self._timers.pop(key, time.monotonic())) * 1000)

    # LLM

    def on_llm_start(self, serialized: Dict[str, Any], prompts: List[str],
                     *, run_id: uuid.UUID, **kwargs: Any) -> None:
        self._timers[str(run_id)] = time.monotonic()
        model = serialized.get("kwargs", {}).get("model_name", "unknown")
        self._write_packet("Reasoning",
            f"LLM call started — model={model} prompts={len(prompts)}",
            tags=["llm", "start"], metadata={"model": model, "run_id": str(run_id)})

    def on_chat_model_start(self, serialized: Dict[str, Any],
                            messages: List[List[BaseMessage]],
                            *, run_id: uuid.UUID, **kwargs: Any) -> None:
        self._timers[str(run_id)] = time.monotonic()
        model = serialized.get("kwargs", {}).get("model_name", "unknown")
        self._write_packet("Reasoning",
            f"Chat model call — model={model} messages={sum(len(m) for m in messages)}",
            tags=["llm", "chat"], metadata={"model": model, "run_id": str(run_id)})

    def on_llm_end(self, response: LLMResult, *, run_id: uuid.UUID, **kwargs: Any) -> None:
        elapsed = self._elapsed(str(run_id))
        usage = response.llm_output.get("token_usage", {}) if response.llm_output else {}
        text = ""
        if response.generations and response.generations[0]:
            text = getattr(response.generations[0][0], "text", "")[:200]
        self._write_packet("Observation",
            f"LLM response ({elapsed}ms): {text}",
            tags=["llm", "response"], metadata={"duration_ms": elapsed, "token_usage": usage})
        self._log_action("llm_call", "complete", "Allowed", elapsed, {"token_usage": usage})

    def on_llm_error(self, error: Union[Exception, KeyboardInterrupt],
                     *, run_id: uuid.UUID, **kwargs: Any) -> None:
        elapsed = self._elapsed(str(run_id))
        self._write_packet("Observation",
            f"LLM error: {type(error).__name__}: {str(error)[:200]}",
            tags=["llm", "error"])
        self._log_action("llm_call", "error", "Failed", elapsed)

    # Tools

    def on_tool_start(self, serialized: Dict[str, Any], input_str: str,
                      *, run_id: uuid.UUID, **kwargs: Any) -> None:
        self._timers[str(run_id)] = time.monotonic()
        tool = serialized.get("name", "unknown")
        self._write_packet("ToolCall",
            f"Tool invoked: {tool} — {input_str[:300]}",
            tags=["tool", tool], metadata={"tool": tool, "run_id": str(run_id)})

    def on_tool_end(self, output: str, *, run_id: uuid.UUID, **kwargs: Any) -> None:
        elapsed = self._elapsed(str(run_id))
        self._write_packet("Observation",
            f"Tool result ({elapsed}ms): {str(output)[:300]}",
            tags=["tool", "result"], metadata={"duration_ms": elapsed})
        self._log_action("tool_call", "complete", "Allowed", elapsed)

    def on_tool_error(self, error: Union[Exception, KeyboardInterrupt],
                      *, run_id: uuid.UUID, **kwargs: Any) -> None:
        elapsed = self._elapsed(str(run_id))
        self._write_packet("Observation",
            f"Tool error: {str(error)[:200]}", tags=["tool", "error"])
        self._log_action("tool_call", "error", "Failed", elapsed)

    # Chains

    def on_chain_start(self, serialized: Dict[str, Any], inputs: Dict[str, Any],
                       *, run_id: uuid.UUID, **kwargs: Any) -> None:
        self._timers[f"chain_{run_id}"] = time.monotonic()
        chain_name = serialized.get("id", ["unknown"])[-1]
        self._write_packet("Reasoning", f"Chain started: {chain_name}",
            tags=["chain"], metadata={"chain": chain_name})

    def on_chain_end(self, outputs: Dict[str, Any], *, run_id: uuid.UUID, **kwargs: Any) -> None:
        elapsed = self._elapsed(f"chain_{run_id}")
        self._log_action("chain", "complete", "Allowed", elapsed)

    def on_chain_error(self, error: Union[Exception, KeyboardInterrupt],
                       *, run_id: uuid.UUID, **kwargs: Any) -> None:
        elapsed = self._elapsed(f"chain_{run_id}")
        self._write_packet("Observation", f"Chain error: {str(error)[:200]}", tags=["chain", "error"])
        self._log_action("chain", "error", "Failed", elapsed)

    # Agent

    def on_agent_action(self, action: Any, *, run_id: uuid.UUID, **kwargs: Any) -> None:
        self._write_packet("Reasoning",
            f"Agent action: {action.tool} — {str(action.tool_input)[:300]}",
            tags=["agent", "action", action.tool])

    def on_agent_finish(self, finish: Any, *, run_id: uuid.UUID, **kwargs: Any) -> None:
        self._write_packet("Observation",
            f"Agent finished: {str(finish.return_values)[:300]}",
            tags=["agent", "finish"])
        self._log_action("agent", "finish", "Allowed")


class AsyncConnectorCallbackHandler(AsyncCallbackHandler):
    """Native async LangChain callback handler using httpx.AsyncClient.

    Drop-in replacement for ConnectorCallbackHandler when running inside an
    async framework (FastAPI, LangServe, async Jupyter, etc.).

    Usage::
        handler = AsyncConnectorCallbackHandler(
            base_url="http://localhost:8080/api/v1",
            api_key="cp-...",
            agent_pid="my-agent",
        )
        llm = ChatOpenAI(callbacks=[handler])
        await llm.ainvoke("Hello")

    Requires: pip install httpx
    """

    def __init__(
        self,
        base_url: str = "http://localhost:8080/api/v1",
        api_key: Optional[str] = None,
        agent_pid: Optional[str] = None,
        namespace: Optional[str] = None,
        timeout: int = 5,
    ) -> None:
        super().__init__()
        if not _HTTPX_AVAILABLE:
            raise ImportError(
                "httpx is required for AsyncConnectorCallbackHandler. "
                "Install with: pip install httpx"
            )
        self.base_url = base_url.rstrip("/")
        self.agent_pid = agent_pid or f"lc_{uuid.uuid4().hex[:8]}"
        self.namespace = namespace or self.agent_pid
        self.timeout = timeout
        self._headers: Dict[str, str] = {"Content-Type": "application/json"}
        if api_key:
            self._headers["Authorization"] = f"Bearer {api_key}"
        self._client: Optional[httpx.AsyncClient] = None
        self._timers: Dict[str, float] = {}

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(headers=self._headers, timeout=self.timeout)
        return self._client

    async def _post(self, path: str, payload: Dict[str, Any]) -> None:
        try:
            client = await self._get_client()
            await client.post(f"{self.base_url}{path}", json=payload)
        except Exception:
            pass

    async def _write_packet(self, packet_type: str, content: str,
                             tags: Optional[List[str]] = None,
                             metadata: Optional[Dict[str, Any]] = None) -> None:
        await self._post("/memory/write", {
            "agent_pid": self.agent_pid, "namespace": self.namespace,
            "packet_type": packet_type, "content": content,
            "tags": tags or [], "metadata": metadata or {},
        })

    async def _log_action(self, intent: str, action: str, outcome: str,
                           duration_ms: int = 0,
                           metadata: Optional[Dict[str, Any]] = None) -> None:
        await self._post("/actionlog/record", {
            "agent_pid": self.agent_pid, "intent": intent,
            "action": action, "outcome": outcome,
            "duration_ms": duration_ms, "metadata": metadata or {},
        })

    def _elapsed(self, key: str) -> int:
        return int((time.monotonic() - self._timers.pop(key, time.monotonic())) * 1000)

    async def on_llm_start(self, serialized: Dict[str, Any], prompts: List[str],
                            *, run_id: uuid.UUID, **kwargs: Any) -> None:
        self._timers[str(run_id)] = time.monotonic()
        model = serialized.get("kwargs", {}).get("model_name", "unknown")
        await self._write_packet("Reasoning",
            f"LLM call started — model={model} prompts={len(prompts)}",
            tags=["llm", "start"], metadata={"model": model, "run_id": str(run_id)})

    async def on_chat_model_start(self, serialized: Dict[str, Any],
                                   messages: List[List[BaseMessage]],
                                   *, run_id: uuid.UUID, **kwargs: Any) -> None:
        self._timers[str(run_id)] = time.monotonic()
        model = serialized.get("kwargs", {}).get("model_name", "unknown")
        await self._write_packet("Reasoning",
            f"Chat model call — model={model} messages={sum(len(m) for m in messages)}",
            tags=["llm", "chat"], metadata={"model": model, "run_id": str(run_id)})

    async def on_llm_end(self, response: LLMResult, *, run_id: uuid.UUID, **kwargs: Any) -> None:
        elapsed = self._elapsed(str(run_id))
        usage = response.llm_output.get("token_usage", {}) if response.llm_output else {}
        text = ""
        if response.generations and response.generations[0]:
            text = getattr(response.generations[0][0], "text", "")[:200]
        await self._write_packet("Observation",
            f"LLM response ({elapsed}ms): {text}",
            tags=["llm", "response"], metadata={"duration_ms": elapsed, "token_usage": usage})
        await self._log_action("llm_call", "complete", "Allowed", elapsed, {"token_usage": usage})

    async def on_llm_error(self, error: Union[Exception, KeyboardInterrupt],
                            *, run_id: uuid.UUID, **kwargs: Any) -> None:
        elapsed = self._elapsed(str(run_id))
        await self._write_packet("Observation",
            f"LLM error: {type(error).__name__}: {str(error)[:200]}", tags=["llm", "error"])
        await self._log_action("llm_call", "error", "Failed", elapsed)

    async def on_tool_start(self, serialized: Dict[str, Any], input_str: str,
                             *, run_id: uuid.UUID, **kwargs: Any) -> None:
        self._timers[str(run_id)] = time.monotonic()
        tool = serialized.get("name", "unknown")
        await self._write_packet("ToolCall",
            f"Tool invoked: {tool} — {input_str[:300]}",
            tags=["tool", tool], metadata={"tool": tool, "run_id": str(run_id)})

    async def on_tool_end(self, output: str, *, run_id: uuid.UUID, **kwargs: Any) -> None:
        elapsed = self._elapsed(str(run_id))
        await self._write_packet("Observation",
            f"Tool result ({elapsed}ms): {str(output)[:300]}",
            tags=["tool", "result"], metadata={"duration_ms": elapsed})
        await self._log_action("tool_call", "complete", "Allowed", elapsed)

    async def on_tool_error(self, error: Union[Exception, KeyboardInterrupt],
                             *, run_id: uuid.UUID, **kwargs: Any) -> None:
        elapsed = self._elapsed(str(run_id))
        await self._write_packet("Observation",
            f"Tool error: {str(error)[:200]}", tags=["tool", "error"])
        await self._log_action("tool_call", "error", "Failed", elapsed)

    async def on_chain_start(self, serialized: Dict[str, Any], inputs: Dict[str, Any],
                              *, run_id: uuid.UUID, **kwargs: Any) -> None:
        self._timers[f"chain_{run_id}"] = time.monotonic()
        chain_name = serialized.get("id", ["unknown"])[-1]
        await self._write_packet("Reasoning", f"Chain started: {chain_name}",
            tags=["chain"], metadata={"chain": chain_name})

    async def on_chain_end(self, outputs: Dict[str, Any], *, run_id: uuid.UUID, **kwargs: Any) -> None:
        elapsed = self._elapsed(f"chain_{run_id}")
        await self._log_action("chain", "complete", "Allowed", elapsed)

    async def on_chain_error(self, error: Union[Exception, KeyboardInterrupt],
                              *, run_id: uuid.UUID, **kwargs: Any) -> None:
        elapsed = self._elapsed(f"chain_{run_id}")
        await self._write_packet("Observation", f"Chain error: {str(error)[:200]}", tags=["chain", "error"])
        await self._log_action("chain", "error", "Failed", elapsed)

    async def on_agent_action(self, action: Any, *, run_id: uuid.UUID, **kwargs: Any) -> None:
        await self._write_packet("Reasoning",
            f"Agent action: {action.tool} — {str(action.tool_input)[:300]}",
            tags=["agent", "action", action.tool])

    async def on_agent_finish(self, finish: Any, *, run_id: uuid.UUID, **kwargs: Any) -> None:
        await self._write_packet("Observation",
            f"Agent finished: {str(finish.return_values)[:300]}",
            tags=["agent", "finish"])
        await self._log_action("agent", "finish", "Allowed")

    async def aclose(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()


__all__ = ["ConnectorCallbackHandler", "AsyncConnectorCallbackHandler"]

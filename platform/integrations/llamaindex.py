"""
Connector Platform — LlamaIndex Integration
Implements a CallbackHandler for LlamaIndex query engines, agents, and pipelines.

Compatible with: llama-index-core >= 0.10, llama-index >= 0.9 (legacy)

Usage:
    from llama_index.core import Settings
    from llama_index.core.callbacks import CallbackManager
    from integrations.llamaindex import ConnectorCallbackHandler

    handler = ConnectorCallbackHandler(
        base_url="http://localhost:8080/api/v1",
        api_key="cp-...",
        agent_pid="llamaindex_pipeline_1",
    )
    Settings.callback_manager = CallbackManager([handler])

    # Now all query engine, agent, retriever, LLM calls are traced automatically.
    query_engine = index.as_query_engine()
    response = query_engine.query("What is the capital of France?")

    # For agents (FunctionCallingAgent, ReActAgent, etc.)
    from llama_index.core.agent import ReActAgent
    agent = ReActAgent.from_tools([...], callback_manager=CallbackManager([handler]))
"""

from __future__ import annotations

import time
import uuid
import threading
from typing import Any, Dict, List, Optional

import requests

try:
    from llama_index.core.callbacks.base_handler import BaseCallbackHandler as _Base
    from llama_index.core.callbacks.schema import CBEventType, EventPayload
    _CORE = True
except ImportError:
    try:
        from llama_index.callbacks.base_handler import BaseCallbackHandler as _Base
        from llama_index.callbacks.schema import CBEventType, EventPayload
        _CORE = False
    except ImportError:
        raise ImportError(
            "llama-index-core is required. Install with: pip install llama-index-core"
        )


class ConnectorCallbackHandler(_Base):
    """
    LlamaIndex CallbackHandler that traces all events to the Connector Platform.
    Handles LLM, embedding, query, retrieval, agent step, tool, and chunking events.
    """

    event_starts_to_ignore: List[Any] = []
    event_ends_to_ignore: List[Any] = []

    def __init__(
        self,
        base_url: str = "http://localhost:8080/api/v1",
        api_key: Optional[str] = None,
        agent_pid: Optional[str] = None,
        namespace: Optional[str] = None,
        timeout: int = 5,
        async_mode: bool = True,
    ) -> None:
        super().__init__(
            event_starts_to_ignore=[],
            event_ends_to_ignore=[],
        )
        self.base_url = base_url.rstrip("/")
        self.agent_pid = agent_pid or f"li_{uuid.uuid4().hex[:8]}"
        self.namespace = namespace or self.agent_pid
        self.timeout = timeout
        self.async_mode = async_mode
        self._session = requests.Session()
        if api_key:
            self._session.headers.update({"Authorization": f"Bearer {api_key}"})
        self._timers: Dict[str, float] = {}

    def _post(self, path: str, payload: Dict[str, Any]) -> None:
        url = f"{self.base_url}{path}"
        if self.async_mode:
            threading.Thread(
                target=lambda: self._session.post(url, json=payload, timeout=self.timeout),
                daemon=True,
            ).start()
        else:
            try:
                self._session.post(url, json=payload, timeout=self.timeout)
            except Exception:
                pass

    def _write(self, packet_type: str, content: str,
               tags: Optional[List[str]] = None, metadata: Optional[Dict[str, Any]] = None) -> None:
        self._post("/memory/write", {
            "agent_pid": self.agent_pid,
            "namespace": self.namespace,
            "packet_type": packet_type,
            "content": content[:2000],
            "tags": tags or [],
            "metadata": metadata or {},
        })

    def _log(self, intent: str, action: str, outcome: str = "Allowed",
             duration_ms: int = 0, metadata: Optional[Dict[str, Any]] = None) -> None:
        self._post("/actionlog/record", {
            "agent_pid": self.agent_pid,
            "intent": intent,
            "action": action,
            "outcome": outcome,
            "duration_ms": duration_ms,
            "metadata": metadata or {},
        })

    def on_event_start(self, event_type: Any, payload: Optional[Dict[str, Any]] = None,
                       event_id: str = "", **kwargs: Any) -> str:
        self._timers[event_id] = time.monotonic()
        ev = str(event_type.value if hasattr(event_type, "value") else event_type)

        if "LLM" in ev.upper():
            msgs = (payload or {}).get(EventPayload.MESSAGES, []) if _CORE else []
            self._write("Reasoning", f"LLM call started ({len(msgs)} messages)",
                        tags=["llamaindex", "llm", "start"])
        elif "QUERY" in ev.upper():
            q = str((payload or {}).get(EventPayload.QUERY_STR, ""))[:200] if _CORE else ""
            self._write("Reasoning", f"Query: {q}", tags=["llamaindex", "query"])
        elif "RETRIEVE" in ev.upper():
            self._write("Reasoning", "Retrieval started", tags=["llamaindex", "retrieve"])
        elif "FUNCTION_CALL" in ev.upper() or "TOOL" in ev.upper():
            fn = str((payload or {}).get("function_call", {}) if payload else "")[:100]
            self._write("ToolCall", f"Tool call: {fn}", tags=["llamaindex", "tool"])
        elif "AGENT_STEP" in ev.upper():
            self._write("Reasoning", "Agent step started", tags=["llamaindex", "agent"])

        return event_id

    def on_event_end(self, event_type: Any, payload: Optional[Dict[str, Any]] = None,
                     event_id: str = "", **kwargs: Any) -> None:
        elapsed = int((time.monotonic() - self._timers.pop(event_id, time.monotonic())) * 1000)
        ev = str(event_type.value if hasattr(event_type, "value") else event_type)

        if "LLM" in ev.upper():
            resp = (payload or {}).get(EventPayload.RESPONSE, None) if _CORE else None
            text = str(resp)[:300] if resp else ""
            self._write("Observation", f"LLM response ({elapsed}ms): {text}",
                        tags=["llamaindex", "llm", "end"])
            self._log("llm_call", "complete", "Allowed", elapsed)
        elif "QUERY" in ev.upper():
            resp = (payload or {}).get(EventPayload.RESPONSE, None) if _CORE else None
            self._write("Observation", f"Query result ({elapsed}ms): {str(resp)[:300]}",
                        tags=["llamaindex", "query", "end"])
            self._log("query", "complete", "Allowed", elapsed)
        elif "RETRIEVE" in ev.upper():
            nodes = (payload or {}).get(EventPayload.NODES, []) if _CORE else []
            self._write("Observation", f"Retrieved {len(nodes)} nodes in {elapsed}ms",
                        tags=["llamaindex", "retrieve", "end"])
            self._log("retrieve", "complete", "Allowed", elapsed)
        elif "FUNCTION_CALL" in ev.upper() or "TOOL" in ev.upper():
            out = str((payload or {}).get("function_call_response", ""))[:300]
            self._write("Observation", f"Tool result ({elapsed}ms): {out}",
                        tags=["llamaindex", "tool", "end"])
            self._log("tool_call", "complete", "Allowed", elapsed)
        elif "AGENT_STEP" in ev.upper():
            self._write("Observation", f"Agent step complete ({elapsed}ms)",
                        tags=["llamaindex", "agent", "end"])

    def start_trace(self, trace_id: Optional[str] = None) -> None:
        self._write("Reasoning", f"Trace started: {trace_id or 'default'}",
                    tags=["llamaindex", "trace", "start"])

    def end_trace(self, trace_id: Optional[str] = None,
                  trace_map: Optional[Dict[str, List[str]]] = None) -> None:
        self._write("Observation", f"Trace ended: {trace_id or 'default'}",
                    tags=["llamaindex", "trace", "end"])

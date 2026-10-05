"""
Connector Platform — Decorator Integration
Framework-agnostic instrumentation via Python decorators.

Usage:
    from integrations.decorator import connector_trace, ConnectorClient

    client = ConnectorClient(
        base_url="http://localhost:8080/api/v1",
        api_key="cp-...",
        agent_pid="agent_abc123",
    )

    @connector_trace(client=client, intent="summarize_document")
    def summarize(text: str) -> str:
        ...

    # Or as a context manager:
    with client.trace("search_web") as span:
        result = search(query)
        span.record(result)
"""

from __future__ import annotations

import time
import uuid
import functools
import threading
from contextlib import contextmanager
from typing import Any, Callable, Dict, Generator, List, Optional

import requests


class ConnectorClient:
    """Thin client for writing traces to the Connector Platform REST API."""

    def __init__(
        self,
        base_url: str = "http://localhost:8080/api/v1",
        api_key: Optional[str] = None,
        agent_pid: Optional[str] = None,
        namespace: Optional[str] = None,
        timeout: int = 5,
        async_mode: bool = True,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.agent_pid = agent_pid or f"cp_{uuid.uuid4().hex[:8]}"
        self.namespace = namespace or self.agent_pid
        self.timeout = timeout
        self.async_mode = async_mode
        self._session = requests.Session()
        if api_key:
            self._session.headers.update({"Authorization": f"Bearer {api_key}"})

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

    def write_packet(
        self,
        packet_type: str,
        content: str,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Write a typed memory packet to the kernel."""
        self._post("/memory/write", {
            "agent_pid": self.agent_pid,
            "namespace": self.namespace,
            "packet_type": packet_type,
            "content": content,
            "tags": tags or [],
            "metadata": metadata or {},
        })

    def log_action(
        self,
        intent: str,
        action: str,
        outcome: str = "Allowed",
        duration_ms: int = 0,
        target: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Record an action in the audit log."""
        self._post("/actionlog/record", {
            "agent_pid": self.agent_pid,
            "intent": intent,
            "action": action,
            "outcome": outcome,
            "duration_ms": duration_ms,
            "target": target or "",
            "metadata": metadata or {},
        })

    @contextmanager
    def trace(
        self,
        intent: str,
        packet_type: str = "Reasoning",
        tags: Optional[List[str]] = None,
    ) -> Generator["_Span", None, None]:
        """Context manager that creates a trace span for a block of code.

        Example:
            with client.trace("fetch_user_data", tags=["db"]) as span:
                data = db.query(...)
                span.record(str(data)[:500])
        """
        span = _Span(client=self, intent=intent, packet_type=packet_type, tags=tags or [])
        span._start = time.monotonic()
        self.write_packet(packet_type, f"[START] {intent}", tags=(tags or []) + ["start"])
        try:
            yield span
            elapsed = int((time.monotonic() - span._start) * 1000)
            self.log_action(intent, "complete", "Allowed", elapsed, metadata=span._metadata)
        except Exception as exc:
            elapsed = int((time.monotonic() - span._start) * 1000)
            self.write_packet("Observation",
                f"[ERROR] {intent}: {type(exc).__name__}: {str(exc)[:200]}",
                tags=(tags or []) + ["error"])
            self.log_action(intent, "error", "Failed", elapsed)
            raise


class _Span:
    """Span object yielded by ConnectorClient.trace()."""

    def __init__(
        self,
        client: ConnectorClient,
        intent: str,
        packet_type: str,
        tags: List[str],
    ) -> None:
        self._client = client
        self._intent = intent
        self._packet_type = packet_type
        self._tags = tags
        self._start: float = 0.0
        self._metadata: Dict[str, Any] = {}

    def record(self, content: str, tags: Optional[List[str]] = None) -> None:
        """Record an intermediate observation within the span."""
        self._client.write_packet(
            "Observation",
            content,
            tags=self._tags + (tags or []),
        )

    def set_metadata(self, key: str, value: Any) -> None:
        self._metadata[key] = value


def connector_trace(
    client: ConnectorClient,
    intent: Optional[str] = None,
    packet_type: str = "Reasoning",
    tags: Optional[List[str]] = None,
    record_args: bool = False,
    record_result: bool = True,
) -> Callable:
    """Decorator that traces a function call to the Connector Platform.

    Args:
        client:        ConnectorClient instance.
        intent:        Human-readable intent label (defaults to function name).
        packet_type:   Memory packet type (Reasoning, ToolCall, Observation).
        tags:          Extra tags to attach to packets.
        record_args:   Whether to write function arguments as a packet.
        record_result: Whether to write the return value as a packet.

    Example:
        @connector_trace(client=client, intent="classify_email", tags=["nlp"])
        def classify(text: str) -> str:
            ...
    """
    def decorator(fn: Callable) -> Callable:
        _intent = intent or fn.__name__
        _tags = tags or []

        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            start = time.monotonic()
            if record_args:
                arg_repr = f"args={args!r:.300} kwargs={kwargs!r:.300}"
                client.write_packet(packet_type,
                    f"[CALL] {_intent}: {arg_repr}",
                    tags=_tags + ["call"])
            else:
                client.write_packet(packet_type,
                    f"[CALL] {_intent}",
                    tags=_tags + ["call"])
            try:
                result = fn(*args, **kwargs)
                elapsed = int((time.monotonic() - start) * 1000)
                if record_result:
                    client.write_packet("Observation",
                        f"[RESULT] {_intent} ({elapsed}ms): {str(result)[:300]}",
                        tags=_tags + ["result"])
                client.log_action(_intent, "complete", "Allowed", elapsed)
                return result
            except Exception as exc:
                elapsed = int((time.monotonic() - start) * 1000)
                client.write_packet("Observation",
                    f"[ERROR] {_intent}: {type(exc).__name__}: {str(exc)[:200]}",
                    tags=_tags + ["error"])
                client.log_action(_intent, "error", "Failed", elapsed)
                raise

        return wrapper
    return decorator


def connector_tool(
    client: ConnectorClient,
    tool_name: Optional[str] = None,
    tags: Optional[List[str]] = None,
) -> Callable:
    """Convenience decorator for MCP-style tool functions.

    Writes a ToolCall packet on entry and Observation on exit/error.

    Example:
        @connector_tool(client=client, tool_name="web_search")
        def search(query: str) -> list[str]:
            ...
    """
    def decorator(fn: Callable) -> Callable:
        _tool = tool_name or fn.__name__
        _tags = ["tool", _tool] + (tags or [])
        return connector_trace(
            client=client,
            intent=f"tool:{_tool}",
            packet_type="ToolCall",
            tags=_tags,
            record_result=True,
        )(fn)
    return decorator

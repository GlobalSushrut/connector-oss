"""
Connector Platform — OpenAI Agents SDK Integration
Implements a TracingProcessor that writes all agent spans to the Connector Platform.

Compatible with: openai-agents >= 0.0.3 (the open-source Agents SDK, formerly Swarm)

Usage:
    from agents import Agent, Runner, trace
    from integrations.openai_agents import ConnectorTracingProcessor

    processor = ConnectorTracingProcessor(
        base_url="http://localhost:8080/api/v1",
        api_key="cp-...",
        agent_pid="openai_pipeline_1",
    )

    # Register globally — all agent runs in this process are traced
    from agents.tracing import add_trace_processor
    add_trace_processor(processor)

    agent = Agent(name="Triage", instructions="You are a helpful assistant.")
    result = await Runner.run(agent, input="Hello")

    # Or scope to a single run:
    with trace("my_workflow"):
        result = await Runner.run(agent, input="Hello")
"""

from __future__ import annotations

import time
import uuid
import threading
from typing import Any, Dict, List, Optional

import requests


class ConnectorTracingProcessor:
    """
    OpenAI Agents SDK TracingProcessor implementation.
    Registered via agents.tracing.add_trace_processor(processor).
    Receives on_trace_start, on_trace_end, on_span_start, on_span_end hooks.
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
        self.base_url = base_url.rstrip("/")
        self.agent_pid = agent_pid or f"oai_{uuid.uuid4().hex[:8]}"
        self.namespace = namespace or self.agent_pid
        self.timeout = timeout
        self.async_mode = async_mode
        self._session = requests.Session()
        if api_key:
            self._session.headers.update({"Authorization": f"Bearer {api_key}"})
        self._span_timers: Dict[str, float] = {}

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

    # ── TracingProcessor interface ─────────────────────────────────────────

    def on_trace_start(self, trace: Any) -> None:
        name = getattr(trace, "name", "trace")
        self._span_timers[f"trace_{id(trace)}"] = time.monotonic()
        self._write("Reasoning", f"Trace started: {name}",
                    tags=["openai_agents", "trace", "start"],
                    metadata={"trace_id": getattr(trace, "trace_id", None), "name": name})

    def on_trace_end(self, trace: Any) -> None:
        name = getattr(trace, "name", "trace")
        elapsed = int((time.monotonic() - self._span_timers.pop(f"trace_{id(trace)}", time.monotonic())) * 1000)
        self._write("Observation", f"Trace ended: {name} ({elapsed}ms)",
                    tags=["openai_agents", "trace", "end"])
        self._log(f"trace:{name}", "complete", "Allowed", elapsed)

    def on_span_start(self, span: Any) -> None:
        span_type = getattr(span, "span_data", None)
        type_name = type(span_type).__name__ if span_type else "span"
        self._span_timers[f"span_{id(span)}"] = time.monotonic()

        # Differentiate span types per OpenAI Agents SDK spec
        if "AgentSpanData" in type_name:
            agent_name = getattr(span_type, "name", "agent")
            self._write("Reasoning", f"Agent span: {agent_name}",
                        tags=["openai_agents", "agent"],
                        metadata={"agent": agent_name})

        elif "LlmSpanData" in type_name:
            model = getattr(span_type, "model", "unknown")
            self._write("Reasoning", f"LLM call: model={model}",
                        tags=["openai_agents", "llm"],
                        metadata={"model": model})

        elif "FunctionSpanData" in type_name:
            fn_name = getattr(span_type, "name", "function")
            inp = str(getattr(span_type, "input", ""))[:200]
            self._write("ToolCall", f"Function tool: {fn_name} input={inp}",
                        tags=["openai_agents", "tool", fn_name],
                        metadata={"function": fn_name})

        elif "HandoffSpanData" in type_name:
            to_agent = getattr(span_type, "to_agent", "?")
            from_agent = getattr(span_type, "from_agent", "?")
            self._write("Reasoning", f"Handoff: {from_agent} → {to_agent}",
                        tags=["openai_agents", "handoff"],
                        metadata={"from": from_agent, "to": to_agent})

        elif "GuardrailSpanData" in type_name:
            triggered = getattr(span_type, "triggered", False)
            self._write("Observation", f"Guardrail {'TRIGGERED' if triggered else 'passed'}",
                        tags=["openai_agents", "guardrail"],
                        metadata={"triggered": triggered})

    def on_span_end(self, span: Any) -> None:
        elapsed = int((time.monotonic() - self._span_timers.pop(f"span_{id(span)}", time.monotonic())) * 1000)
        span_type = getattr(span, "span_data", None)
        type_name = type(span_type).__name__ if span_type else "span"
        error = getattr(span, "error", None)

        if error:
            self._write("Observation", f"Span error ({type_name}): {error}",
                        tags=["openai_agents", "error"])
            self._log(f"span:{type_name}", "error", "Failed", elapsed)
        else:
            if "FunctionSpanData" in type_name:
                fn_name = getattr(span_type, "name", "fn")
                output = str(getattr(span_type, "output", ""))[:300]
                self._write("Observation", f"Function result ({fn_name}, {elapsed}ms): {output}",
                            tags=["openai_agents", "tool", "result"])
                self._log(f"tool:{fn_name}", "complete", "Allowed", elapsed)
            elif "LlmSpanData" in type_name:
                model = getattr(span_type, "model", "unknown")
                usage = getattr(span_type, "usage", {}) or {}
                self._log(f"llm:{model}", "complete", "Allowed", elapsed, metadata={"usage": usage})

    def force_flush(self) -> None:
        pass  # fire-and-forget threads; no buffering

    def shutdown(self) -> None:
        pass


def register_connector_tracing(
    base_url: str = "http://localhost:8080/api/v1",
    api_key: Optional[str] = None,
    agent_pid: Optional[str] = None,
) -> ConnectorTracingProcessor:
    """
    Convenience: create and register a ConnectorTracingProcessor globally.

    from integrations.openai_agents import register_connector_tracing
    register_connector_tracing(base_url="...", api_key="cp-...")
    """
    processor = ConnectorTracingProcessor(
        base_url=base_url, api_key=api_key, agent_pid=agent_pid
    )
    try:
        from agents.tracing import add_trace_processor
        add_trace_processor(processor)
    except ImportError:
        raise ImportError(
            "openai-agents is required. Install with: pip install openai-agents"
        )
    return processor

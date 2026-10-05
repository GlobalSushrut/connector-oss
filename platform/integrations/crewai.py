"""
Connector Platform — CrewAI Integration
Instruments CrewAI agents and tasks with memory packet tracing.

Usage:
    from integrations.crewai import ConnectorCrewObserver, instrument_crew

    observer = ConnectorCrewObserver(
        base_url="http://localhost:8080/api/v1",
        api_key="cp-...",
    )

    crew = Crew(agents=[...], tasks=[...])
    instrument_crew(crew, observer)
    result = crew.kickoff()
"""

from __future__ import annotations

import time
import uuid
import threading
from typing import Any, Dict, List, Optional

import requests


class ConnectorCrewObserver:
    """Observability layer for CrewAI — sends traces to the Connector Platform."""

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
        self.agent_pid = agent_pid or f"crew_{uuid.uuid4().hex[:8]}"
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

    def write_packet(
        self,
        packet_type: str,
        content: str,
        agent_name: Optional[str] = None,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        pid = f"crew_{agent_name}" if agent_name else self.agent_pid
        self._post("/memory/write", {
            "agent_pid": pid,
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
        agent_name: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        pid = f"crew_{agent_name}" if agent_name else self.agent_pid
        self._post("/actionlog/record", {
            "agent_pid": pid,
            "intent": intent,
            "action": action,
            "outcome": outcome,
            "duration_ms": duration_ms,
            "metadata": metadata or {},
        })

    # ------------------------------------------------------------------
    # Crew lifecycle hooks
    # ------------------------------------------------------------------

    def on_crew_start(self, crew: Any) -> None:
        agent_names = [getattr(a, "role", str(a)) for a in getattr(crew, "agents", [])]
        task_count = len(getattr(crew, "tasks", []))
        self.write_packet(
            "Reasoning",
            f"Crew kickoff — {len(agent_names)} agents, {task_count} tasks: {', '.join(agent_names)}",
            tags=["crew", "start"],
            metadata={"agents": agent_names, "task_count": task_count},
        )
        self._timers["crew"] = time.monotonic()

    def on_crew_end(self, crew: Any, result: Any) -> None:
        elapsed = int((time.monotonic() - self._timers.pop("crew", time.monotonic())) * 1000)
        self.write_packet(
            "Observation",
            f"Crew finished in {elapsed}ms: {str(result)[:400]}",
            tags=["crew", "end"],
            metadata={"duration_ms": elapsed},
        )
        self.log_action("crew", "complete", "Allowed", elapsed)

    def on_agent_start(self, agent: Any, task: Any) -> None:
        role = getattr(agent, "role", "unknown")
        task_desc = getattr(task, "description", str(task))[:200]
        key = f"agent_{role}"
        self._timers[key] = time.monotonic()
        self.write_packet(
            "Reasoning",
            f"Agent '{role}' starting task: {task_desc}",
            agent_name=role,
            tags=["agent", "task_start", role],
            metadata={"role": role, "task": task_desc},
        )

    def on_agent_end(self, agent: Any, task: Any, output: Any) -> None:
        role = getattr(agent, "role", "unknown")
        key = f"agent_{role}"
        elapsed = int((time.monotonic() - self._timers.pop(key, time.monotonic())) * 1000)
        self.write_packet(
            "Observation",
            f"Agent '{role}' completed task in {elapsed}ms: {str(output)[:400]}",
            agent_name=role,
            tags=["agent", "task_end", role],
            metadata={"role": role, "duration_ms": elapsed},
        )
        self.log_action(f"task:{getattr(task, 'description', '')[:60]}", "complete",
                        "Allowed", elapsed, agent_name=role)

    def on_tool_use(self, agent: Any, tool_name: str, tool_input: Any, tool_output: Any) -> None:
        role = getattr(agent, "role", "unknown")
        self.write_packet(
            "ToolCall",
            f"Tool '{tool_name}' called by '{role}': input={str(tool_input)[:200]} → {str(tool_output)[:200]}",
            agent_name=role,
            tags=["tool", tool_name, role],
            metadata={"tool": tool_name, "agent": role},
        )
        self.log_action(f"tool:{tool_name}", "invoke", "Allowed", agent_name=role)

    def on_task_start(self, task: Any) -> None:
        desc = getattr(task, "description", str(task))[:200]
        key = f"task_{id(task)}"
        self._timers[key] = time.monotonic()
        self.write_packet(
            "Reasoning",
            f"Task started: {desc}",
            tags=["task", "start"],
            metadata={"task": desc},
        )

    def on_task_end(self, task: Any, output: Any) -> None:
        desc = getattr(task, "description", str(task))[:60]
        key = f"task_{id(task)}"
        elapsed = int((time.monotonic() - self._timers.pop(key, time.monotonic())) * 1000)
        self.write_packet(
            "Observation",
            f"Task '{desc}' done in {elapsed}ms: {str(output)[:300]}",
            tags=["task", "end"],
            metadata={"duration_ms": elapsed},
        )


def instrument_crew(crew: Any, observer: ConnectorCrewObserver) -> Any:
    """Monkey-patch a CrewAI Crew instance to fire observer hooks.

    Works by wrapping the crew's kickoff() method and each agent's
    execute_task() method if available.

    Returns the crew for chaining.
    """
    original_kickoff = crew.kickoff

    def patched_kickoff(*args: Any, **kwargs: Any) -> Any:
        observer.on_crew_start(crew)
        try:
            result = original_kickoff(*args, **kwargs)
            observer.on_crew_end(crew, result)
            return result
        except Exception as exc:
            elapsed = int((time.monotonic() - observer._timers.pop("crew", time.monotonic())) * 1000)
            observer.write_packet("Observation",
                f"Crew error: {type(exc).__name__}: {str(exc)[:200]}",
                tags=["crew", "error"])
            observer.log_action("crew", "error", "Failed", elapsed)
            raise

    crew.kickoff = patched_kickoff

    # Wrap individual agent execute_task if available
    for agent in getattr(crew, "agents", []):
        _wrap_agent(agent, observer)

    return crew


def _wrap_agent(agent: Any, observer: ConnectorCrewObserver) -> None:
    execute_fn = getattr(agent, "execute_task", None)
    if execute_fn is None:
        return

    def patched_execute(task: Any, *args: Any, **kwargs: Any) -> Any:
        observer.on_agent_start(agent, task)
        try:
            output = execute_fn(task, *args, **kwargs)
            observer.on_agent_end(agent, task, output)
            return output
        except Exception as exc:
            role = getattr(agent, "role", "unknown")
            observer.write_packet("Observation",
                f"Agent '{role}' error: {str(exc)[:200]}",
                agent_name=role, tags=["agent", "error"])
            observer.log_action("task", "error", "Failed", agent_name=role)
            raise

    agent.execute_task = patched_execute

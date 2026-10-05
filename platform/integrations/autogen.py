"""
Connector Platform — AutoGen 0.4 (AgentChat) Integration
Implements a ClosureAgent-compatible middleware + ChatAgent wrapper.

Compatible with: microsoft-autogen >= 0.4, autogen-agentchat >= 0.4
Also supports legacy AutoGen 0.2 via monkey-patch fallback.

Usage (AutoGen 0.4 AgentChat):
    from integrations.autogen import ConnectorMiddleware, instrument_autogen_agent

    middleware = ConnectorMiddleware(
        base_url="http://localhost:8080/api/v1",
        api_key="cp-...",
        agent_pid="autogen_pipeline_1",
    )

    # Wrap any AssistantAgent / UserProxyAgent
    agent = instrument_autogen_agent(my_agent, middleware)

Usage (AutoGen 0.4 runtime middleware):
    from autogen_agentchat.teams import RoundRobinGroupChat
    team = RoundRobinGroupChat(agents=[...], termination_condition=...)
    middleware.attach_team(team)
    await team.run(task="...")

Usage (legacy AutoGen 0.2):
    middleware.patch_initiate_chat(initiator_agent)
"""

from __future__ import annotations

import time
import uuid
import threading
from typing import Any, Dict, List, Optional

import requests


class ConnectorMiddleware:
    """Universal AutoGen middleware — works with 0.2 monkey-patch and 0.4 message hooks."""

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
        self.agent_pid = agent_pid or f"ag_{uuid.uuid4().hex[:8]}"
        self.namespace = namespace or self.agent_pid
        self.timeout = timeout
        self.async_mode = async_mode
        self._session = requests.Session()
        if api_key:
            self._session.headers.update({"Authorization": f"Bearer {api_key}"})
        self._timers: Dict[str, float] = {}

    # ── Transport ──────────────────────────────────────────────────────────

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

    def write_packet(self, packet_type: str, content: str,
                     agent_name: Optional[str] = None,
                     tags: Optional[List[str]] = None,
                     metadata: Optional[Dict[str, Any]] = None) -> None:
        pid = f"ag_{agent_name}" if agent_name else self.agent_pid
        self._post("/memory/write", {
            "agent_pid": pid,
            "namespace": self.namespace,
            "packet_type": packet_type,
            "content": content[:2000],
            "tags": tags or [],
            "metadata": metadata or {},
        })

    def log_action(self, intent: str, action: str, outcome: str = "Allowed",
                   duration_ms: int = 0, agent_name: Optional[str] = None,
                   metadata: Optional[Dict[str, Any]] = None) -> None:
        pid = f"ag_{agent_name}" if agent_name else self.agent_pid
        self._post("/actionlog/record", {
            "agent_pid": pid,
            "intent": intent,
            "action": action,
            "outcome": outcome,
            "duration_ms": duration_ms,
            "metadata": metadata or {},
        })

    # ── AutoGen 0.4 AgentChat hooks ────────────────────────────────────────

    def on_message_send(self, source: str, content: str, recipient: str) -> None:
        """Call before sending a message between agents."""
        self.write_packet(
            "Reasoning",
            f"[{source}→{recipient}] {content[:500]}",
            agent_name=source,
            tags=["autogen", "message", "send"],
            metadata={"source": source, "recipient": recipient},
        )

    def on_message_receive(self, source: str, content: str, recipient: str) -> None:
        """Call after an agent receives a message."""
        self.write_packet(
            "Observation",
            f"[{recipient} received from {source}] {content[:500]}",
            agent_name=recipient,
            tags=["autogen", "message", "receive"],
            metadata={"source": source, "recipient": recipient},
        )

    def on_tool_call(self, agent_name: str, tool_name: str,
                     tool_input: Any, tool_output: Any, duration_ms: int = 0) -> None:
        self.write_packet(
            "ToolCall",
            f"[{agent_name}] tool={tool_name} input={str(tool_input)[:200]} → {str(tool_output)[:200]}",
            agent_name=agent_name,
            tags=["autogen", "tool", tool_name],
            metadata={"tool": tool_name, "duration_ms": duration_ms},
        )
        self.log_action(f"tool:{tool_name}", "invoke", "Allowed", duration_ms, agent_name)

    def on_termination(self, team_name: str, reason: str, duration_ms: int = 0) -> None:
        self.write_packet(
            "Observation",
            f"Team '{team_name}' terminated: {reason}",
            tags=["autogen", "termination"],
            metadata={"team": team_name, "reason": reason, "duration_ms": duration_ms},
        )
        self.log_action("team_run", "complete", "Allowed", duration_ms)

    # ── AutoGen 0.4 team wrapper ───────────────────────────────────────────

    def attach_team(self, team: Any) -> Any:
        """
        Wrap an AutoGen 0.4 RoundRobinGroupChat / SelectorGroupChat team.
        Intercepts run() to emit start/end traces.
        Returns team for chaining.
        """
        original_run = getattr(team, "run", None)
        original_run_stream = getattr(team, "run_stream", None)
        middleware = self

        if original_run is not None:
            import asyncio

            async def patched_run(task=None, **kwargs):
                t0 = time.monotonic()
                team_name = type(team).__name__
                middleware.write_packet("Reasoning", f"Team '{team_name}' started — task={str(task)[:200]}",
                                        tags=["autogen", "team", "start"])
                try:
                    result = await original_run(task=task, **kwargs)
                    elapsed = int((time.monotonic() - t0) * 1000)
                    middleware.on_termination(team_name, "completed", elapsed)
                    return result
                except Exception as exc:
                    elapsed = int((time.monotonic() - t0) * 1000)
                    middleware.write_packet("Observation", f"Team error: {exc}",
                                           tags=["autogen", "error"])
                    middleware.log_action("team_run", "error", "Failed", elapsed)
                    raise

            team.run = patched_run

        return team

    # ── Legacy AutoGen 0.2 monkey-patch ───────────────────────────────────

    def patch_initiate_chat(self, initiator: Any) -> Any:
        """
        Patch AutoGen 0.2 ConversableAgent.initiate_chat() to emit traces.
        Works with UserProxyAgent, AssistantAgent, etc.
        """
        original = getattr(initiator, "initiate_chat", None)
        if original is None:
            return initiator
        middleware = self

        def patched_initiate_chat(recipient, message=None, **kwargs):
            t0 = time.monotonic()
            name = getattr(initiator, "name", "initiator")
            rec_name = getattr(recipient, "name", "recipient")
            middleware.write_packet("Reasoning",
                f"Chat started: {name} → {rec_name}: {str(message)[:300]}",
                agent_name=name,
                tags=["autogen02", "chat", "start"])
            try:
                result = original(recipient, message=message, **kwargs)
                elapsed = int((time.monotonic() - t0) * 1000)
                middleware.write_packet("Observation",
                    f"Chat completed in {elapsed}ms",
                    tags=["autogen02", "chat", "end"])
                middleware.log_action("chat", "complete", "Allowed", elapsed, name)
                return result
            except Exception as exc:
                elapsed = int((time.monotonic() - t0) * 1000)
                middleware.write_packet("Observation", f"Chat error: {exc}",
                                       tags=["autogen02", "error"])
                middleware.log_action("chat", "error", "Failed", elapsed, name)
                raise

        initiator.initiate_chat = patched_initiate_chat
        return initiator


def instrument_autogen_agent(agent: Any, middleware: ConnectorMiddleware) -> Any:
    """
    Instruments a single AutoGen 0.4 agent by wrapping its on_messages / generate_reply.
    Returns the agent for chaining.
    """
    # AutoGen 0.4 BaseChatAgent.on_messages
    original_on_messages = getattr(agent, "on_messages", None)
    if original_on_messages is not None:
        import asyncio

        async def patched_on_messages(messages, cancellation_token=None, **kwargs):
            name = getattr(agent, "name", "agent")
            for m in (messages or []):
                content = getattr(m, "content", str(m))
                source = getattr(m, "source", "user")
                middleware.on_message_receive(source, str(content), name)
            t0 = time.monotonic()
            try:
                response = await original_on_messages(messages, cancellation_token=cancellation_token, **kwargs)
                elapsed = int((time.monotonic() - t0) * 1000)
                out_content = getattr(response, "chat_message", None)
                if out_content:
                    middleware.on_message_send(name, str(getattr(out_content, "content", ""))[:400], "team")
                middleware.log_action("on_messages", "complete", "Allowed", elapsed, name)
                return response
            except Exception as exc:
                elapsed = int((time.monotonic() - t0) * 1000)
                middleware.write_packet("Observation", f"Agent '{name}' error: {exc}",
                                       tags=["autogen", "error"])
                middleware.log_action("on_messages", "error", "Failed", elapsed, name)
                raise

        agent.on_messages = patched_on_messages

    # AutoGen 0.2 fallback
    original_reply = getattr(agent, "generate_reply", None)
    if original_reply is not None:
        def patched_generate_reply(messages=None, sender=None, **kwargs):
            name = getattr(agent, "name", "agent")
            middleware.write_packet("Reasoning",
                f"generate_reply from {getattr(sender, 'name', 'sender')}",
                agent_name=name, tags=["autogen02", "reply"])
            return original_reply(messages=messages, sender=sender, **kwargs)
        agent.generate_reply = patched_generate_reply

    return agent

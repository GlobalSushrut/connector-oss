"""Connector Platform — Framework integrations (commercial).

Quick-start (D4):
    import connector
    connector.auto_instrument(llm, base_url="http://localhost:8080", agent_pid="my-agent")

That one line gives any LangChain / AutoGen / CrewAI / LlamaIndex / OpenAI Agents object:
  - Full audit trail (every LLM call recorded)
  - Injection detection (score ≥ 0.75 → blocked)
  - Token budget enforcement
  - Memory persistence
  - Prometheus metrics
  - SOC2 / HIPAA compliance logging
"""

from __future__ import annotations

import os
from typing import Any, Optional


def auto_instrument(
    obj: Any,
    base_url: str = "http://localhost:8080",
    agent_pid: Optional[str] = None,
    api_key: Optional[str] = None,
    namespace: Optional[str] = None,
) -> Any:
    """Patch *obj* so all LLM calls route through the Connector AI Gateway.

    Supports: LangChain (LLM / ChatModel / Chain), AutoGen (AssistantAgent /
    ConversableAgent), CrewAI (Crew / Agent), LlamaIndex (LLM), OpenAI Agents
    SDK (Agent), raw ``openai.OpenAI`` client, and ``openai.AsyncOpenAI``.

    Parameters
    ----------
    obj:
        The framework object to instrument.
    base_url:
        URL of your Connector server (default: ``http://localhost:8080``).
    agent_pid:
        Agent PID for audit attribution. Auto-generated if omitted.
    api_key:
        Connector API key (``cpk_live_*``). Falls back to
        ``CONNECTOR_API_KEY`` env var.
    namespace:
        Memory namespace for this agent. Defaults to ``gateway/{agent_pid}``.

    Returns
    -------
    The same *obj*, patched in-place (also returned for chaining).
    """
    resolved_key = api_key or os.environ.get("CONNECTOR_API_KEY", "dev-token")
    resolved_pid = agent_pid or os.environ.get("CONNECTOR_AGENT_PID", "auto-instrumented")
    gateway_url = base_url.rstrip("/") + "/v1"

    cls_name = type(obj).__name__
    module = type(obj).__module__ or ""

    # ── LangChain ────────────────────────────────────────────────────────────
    if "langchain" in module:
        from .langchain import instrument_langchain
        return instrument_langchain(obj, gateway_url, resolved_pid, resolved_key)

    # ── AutoGen ──────────────────────────────────────────────────────────────
    if "autogen" in module:
        from .autogen import instrument_autogen
        return instrument_autogen(obj, gateway_url, resolved_pid, resolved_key)

    # ── CrewAI ───────────────────────────────────────────────────────────────
    if "crewai" in module:
        from .crewai import instrument_crewai
        return instrument_crewai(obj, gateway_url, resolved_pid, resolved_key)

    # ── LlamaIndex ───────────────────────────────────────────────────────────
    if "llama" in module:
        from .llamaindex import instrument_llamaindex
        return instrument_llamaindex(obj, gateway_url, resolved_pid, resolved_key)

    # ── OpenAI raw client ────────────────────────────────────────────────────
    if cls_name in ("OpenAI", "AsyncOpenAI") or "openai" in module:
        obj.base_url = gateway_url
        if resolved_key:
            obj.api_key = resolved_key
        return obj

    # ── Fallback: try to set base_url / api_key attributes directly ──────────
    _try_set(obj, "base_url", gateway_url)
    _try_set(obj, "openai_api_base", gateway_url)
    _try_set(obj, "api_key", resolved_key)
    return obj


def _try_set(obj: Any, attr: str, value: Any) -> None:
    try:
        setattr(obj, attr, value)
    except (AttributeError, TypeError):
        pass

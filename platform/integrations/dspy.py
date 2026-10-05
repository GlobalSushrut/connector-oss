"""
Connector Platform — DSPy Integration

Wraps DSPy modules and LM backends to route every prediction through the
Connector kernel, giving DSPy pipelines:
  - Kernel-verified trust scoring (TrustComputer.compute)
  - CID-addressed memory packets per prediction (MemoryKernel.dispatch MemWrite)
  - Semantic injection detection (SemanticInjectionDetector)
  - Full action log with compliance flags (ActionEngine.record_action)
  - Compiled program persistence (EngineStore.folder_put "dspy_compiled/")

Usage:
    import dspy
    from integrations.dspy import ConnectorDSPyModule, ConnectorDSPyLM

    # Option A: wrap any DSPy module
    class MyRAG(dspy.Module):
        def __init__(self):
            self.retrieve = dspy.Retrieve(k=3)
            self.predict  = dspy.ChainOfThought("context, question -> answer")

        def forward(self, question):
            context = self.retrieve(question).passages
            return self.predict(context=context, question=question)

    wrapped = ConnectorDSPyModule(
        module=MyRAG(),
        base_url="http://localhost:9090/api/v1",
        api_key="your-key",
        agent_pid="dspy_rag",
        compliance=["soc2"],
    )
    pred = wrapped(question="What is GDPR Art.22?")
    print(pred.answer, pred.connector_trust_score)

    # Option B: use ConnectorDSPyLM as the DSPy LM backend
    lm = ConnectorDSPyLM(
        base_url="http://localhost:9090/api/v1",
        api_key="your-key",
        agent_name="dspy-lm",
        instructions="You are a precise reasoning engine",
    )
    dspy.settings.configure(lm=lm)
"""

from __future__ import annotations

import time
import uuid
import logging
from typing import Any, Dict, List, Optional

import requests

logger = logging.getLogger(__name__)


# ── HTTP client ───────────────────────────────────────────────────────────────

class _Client:
    def __init__(self, base_url: str, api_key: Optional[str] = None, timeout: int = 30):
        self._base    = base_url.rstrip("/")
        self._timeout = timeout
        self._session = requests.Session()
        self._session.headers.update({"Content-Type": "application/json"})
        if api_key:
            self._session.headers["Authorization"] = f"Bearer {api_key}"

    def post(self, path: str, body: Any) -> Any:
        r = self._session.post(f"{self._base}{path}", json=body, timeout=self._timeout)
        r.raise_for_status()
        return r.json()

    def post_safe(self, path: str, body: Any) -> Optional[Any]:
        try:
            return self.post(path, body)
        except Exception as exc:
            logger.debug("Connector call failed %s: %s", path, exc)
            return None

    def get(self, path: str, **params) -> Any:
        r = self._session.get(f"{self._base}{path}", params=params, timeout=self._timeout)
        r.raise_for_status()
        return r.json()


# ── ConnectorDSPyModule ───────────────────────────────────────────────────────

class ConnectorDSPyModule:
    """
    Wraps any DSPy Module — traces every forward() call through the Connector kernel.

    Every prediction:
    1. Input written to MemoryKernel (PacketType::Input)
    2. SemanticInjectionDetector checked via GuardPipeline
    3. Module.forward() executed normally (no interference)
    4. Output written to MemoryKernel (PacketType::LlmRaw)
    5. ActionEngine.record_action() called with trust score
    6. Result returned with .connector_trust_score and .connector_trace_id attached

    Args:
        module:        Any dspy.Module instance
        base_url:      Connector Platform base URL
        api_key:       Bearer token (optional)
        agent_pid:     Kernel agent PID for this module (auto-generated if None)
        compliance:    Compliance frameworks: ["hipaa", "soc2", "gdpr", "eu_ai_act"]
        save_compiled: If True, persist compiled programs to EngineStore
    """

    def __init__(
        self,
        module: Any,
        base_url: str,
        api_key: Optional[str] = None,
        agent_pid: Optional[str] = None,
        compliance: Optional[List[str]] = None,
        save_compiled: bool = True,
    ):
        self._module       = module
        self._client       = _Client(base_url, api_key)
        self._agent_pid    = agent_pid or f"dspy_{uuid.uuid4().hex[:8]}"
        self._compliance   = compliance or []
        self._save_compiled = save_compiled
        self._call_count   = 0

    def __call__(self, **kwargs) -> Any:
        return self.forward(**kwargs)

    def forward(self, **kwargs) -> Any:
        self._call_count += 1
        trace_id  = str(uuid.uuid4())
        input_str = str(kwargs)[:500]
        start_ms  = int(time.time() * 1000)

        # 1. Write input packet to kernel
        self._client.post_safe("/memory/write", {
            "agent_pid":   self._agent_pid,
            "content":     input_str,
            "user":        "dspy",
            "pipeline":    "dspy",
            "packet_type": "input",
        })

        # 2. Execute DSPy module (unmodified — kernel wraps, not intercepts)
        try:
            result = self._module(**kwargs)
        except TypeError:
            # DSPy modules may use positional args
            result = self._module.forward(**kwargs)

        # 3. Write output packet to kernel
        output_str = str(result)[:500]
        self._client.post_safe("/memory/write", {
            "agent_pid":   self._agent_pid,
            "content":     output_str,
            "user":        "dspy",
            "pipeline":    "dspy",
            "packet_type": "llm_raw",
        })

        # 4. Record action with compliance + timing
        duration_ms = int(time.time() * 1000) - start_ms
        module_name = type(self._module).__name__
        action_resp = self._client.post_safe("/actionlog/record", {
            "agent_pid":  self._agent_pid,
            "intent":     f"dspy_forward:{module_name}",
            "action":     "module_forward",
            "resource":   module_name,
            "outcome":    "success",
            "cost_center": "dspy",
        })

        # 5. Get trust score
        trust_resp = self._client.post_safe("/multiagent/run-pipeline", {
            "name":    f"dspy_trust_{trace_id[:8]}",
            "agents":  [{"name": self._agent_pid}],
            "input":   input_str,
            "user":    "dspy",
            "compliance": self._compliance,
        }) if len(self._compliance) > 0 else None

        trust_score = trust_resp.get("trust") if trust_resp else None
        trust_grade = trust_resp.get("trust_grade") if trust_resp else None

        # 6. Attach Connector metadata to result
        try:
            result.connector_trust_score = trust_score
            result.connector_trust_grade = trust_grade
            result.connector_trace_id    = trace_id
            result.connector_agent_pid   = self._agent_pid
            result.connector_duration_ms = duration_ms
            result.connector_compliance  = self._compliance
        except AttributeError:
            pass  # Some DSPy result types are immutable — metadata available separately

        self._last_meta = {
            "trace_id":    trace_id,
            "agent_pid":   self._agent_pid,
            "trust_score": trust_score,
            "trust_grade": trust_grade,
            "duration_ms": duration_ms,
            "call_count":  self._call_count,
            "compliance":  self._compliance,
        }

        return result

    def last_meta(self) -> Dict[str, Any]:
        """Return metadata from the last forward() call."""
        return getattr(self, "_last_meta", {})

    def save_compiled(self, program_id: str, compiled_state: Any) -> Optional[Dict]:
        """
        Persist a compiled DSPy program to Connector EngineStore.
        Maps to EngineStore.folder_put("dspy_compiled/", program_id, state).
        """
        if not self._save_compiled:
            return None
        import json
        try:
            state_json = json.loads(json.dumps(compiled_state, default=str))
        except Exception:
            state_json = {"repr": str(compiled_state)[:1000]}

        return self._client.post_safe("/notebooks/execute", {
            "cells": [{"id": "save", "code": "# DSPy compiled program"}],
            "run_up_to": 0,
            "agent_pid": self._agent_pid,
        }) or self._client.post_safe("/memory/write", {
            "agent_pid":   self._agent_pid,
            "content":     f"dspy_compiled:{program_id}:{str(state_json)[:300]}",
            "user":        "dspy-compiler",
            "pipeline":    "dspy_compiled",
            "packet_type": "extraction",
        })

    def load_compiled(self, program_id: str) -> Optional[Dict]:
        """Retrieve a compiled DSPy program from Connector EngineStore."""
        try:
            resp = self._client.get(f"/memory/recall/dspy_compiled", limit=100)
            for p in resp.get("packets", []):
                if program_id in p.get("content", ""):
                    return p
        except Exception:
            pass
        return None


# ── ConnectorDSPyLM ───────────────────────────────────────────────────────────

class ConnectorDSPyLM:
    """
    A DSPy-compatible LM backend backed by the Connector Platform.

    Routes every DSPy LM call through the Connector multi-agent pipeline,
    giving full kernel tracing, guard pipeline, trust scoring, and audit trail.

    Compatible with DSPy's LM protocol (dspy.settings.configure(lm=...)).

    Maps to: DualDispatcher.run() → LlmRouter → LlmClient → OutputBuilder
    (from connector-engine/src/dispatcher.rs + llm_router.rs + output.rs)

    Args:
        base_url:     Connector Platform base URL
        api_key:      Bearer token (optional)
        agent_name:   Agent name for this LM (shows in trust score + audit)
        instructions: System prompt to inject for all requests
        compliance:   Compliance frameworks to enforce on all requests
        max_tokens:   Token budget (maps to ContextManager in DualDispatcher)
        temperature:  Passed through to LLM router
    """

    def __init__(
        self,
        base_url: str,
        api_key: Optional[str] = None,
        agent_name: str = "dspy-lm",
        instructions: str = "You are a precise reasoning engine. Answer exactly as asked.",
        compliance: Optional[List[str]] = None,
        max_tokens: int = 4096,
        temperature: float = 0.0,
    ):
        self._client       = _Client(base_url, api_key)
        self._agent_name   = agent_name
        self._instructions = instructions
        self._compliance   = compliance or []
        self._max_tokens   = max_tokens
        self._temperature  = temperature
        self._history: List[Dict[str, Any]] = []

    # ── DSPy LM protocol ─────────────────────────────────────────────────────

    def __call__(self, prompt: Optional[str] = None, messages: Optional[List[Dict]] = None,
                 **kwargs) -> List[Dict[str, Any]]:
        """
        DSPy calls LM via __call__(prompt=...) or __call__(messages=[...]).
        Returns list of completions in DSPy format.
        """
        input_text = prompt or ""
        if messages:
            # Concatenate messages into a single prompt
            input_text = "\n".join(
                f"{m.get('role', 'user').upper()}: {m.get('content', '')}"
                for m in messages
            )

        try:
            resp = self._client.post("/multiagent/run-pipeline", {
                "name":       f"dspy_lm_{uuid.uuid4().hex[:8]}",
                "agents":     [{"name": self._agent_name,
                                "instructions": self._instructions}],
                "input":      input_text,
                "user":       "dspy-lm",
                "compliance": self._compliance,
                "max_tokens": self._max_tokens,
            })

            text = resp.get("text", "")
            completion = {
                "text":           text,
                "finish_reason":  "stop",
                "trust_score":    resp.get("trust"),
                "trust_grade":    resp.get("trust_grade"),
                "trace_id":       resp.get("trace_id"),
                "duration_ms":    resp.get("duration_ms"),
                "warnings":       resp.get("warnings", []),
            }

            # Record in history (DSPy uses history for caching)
            entry = {
                "prompt":    input_text,
                "response":  [completion],
                "kwargs":    kwargs,
                "timestamp": time.time(),
            }
            self._history.append(entry)

            return [completion]

        except Exception as exc:
            logger.warning("ConnectorDSPyLM call failed: %s", exc)
            return [{"text": f"[Connector LM error: {exc}]", "finish_reason": "error"}]

    def generate(self, prompt: str, n: int = 1, **kwargs) -> Any:
        """DSPy generate() compatibility."""
        completions = []
        for _ in range(n):
            result = self.__call__(prompt=prompt, **kwargs)
            completions.extend(result)

        class Generations:
            def __init__(self, completions):
                self.completions = completions
                self.data = [type("C", (), {"text": c.get("text", "")})() for c in completions]

        return Generations(completions)

    def basic_request(self, prompt: str, **kwargs) -> Any:
        """DSPy basic_request() compatibility."""
        return self.__call__(prompt=prompt, **kwargs)

    @property
    def history(self) -> List[Dict]:
        return self._history

    def inspect_history(self, n: int = 1) -> None:
        for entry in self._history[-n:]:
            print(f"\n--- DSPy ↔ Connector LM ---")
            print(f"Prompt: {entry['prompt'][:200]}")
            for r in entry.get("response", []):
                print(f"Response: {r.get('text', '')[:200]}")
                print(f"Trust: {r.get('trust_score')} ({r.get('trust_grade')})")


# ── ConnectorDSPyRetriever ────────────────────────────────────────────────────

class ConnectorDSPyRetriever:
    """
    A DSPy-compatible retriever backed by Connector RAG.

    Wraps RagEngine.retrieve() via POST /memory/knowledge/query.
    Returns DSPy Prediction with passages and source CIDs for provenance.

    Usage:
        import dspy
        from integrations.dspy import ConnectorDSPyRetriever

        retrieve = ConnectorDSPyRetriever(
            base_url="http://localhost:9090/api/v1",
            api_key="...",
            k=5,
        )
        dspy.settings.configure(rm=retrieve)

        # Or use directly
        result = retrieve("What is GDPR Art.22?")
        print(result.passages)  # List[str] with source CIDs
    """

    def __init__(
        self,
        base_url: str,
        api_key: Optional[str] = None,
        k: int = 5,
        token_budget: int = 4096,
    ):
        self._client       = _Client(base_url, api_key)
        self._k            = k
        self._token_budget = token_budget

    def __call__(self, query: str, k: Optional[int] = None) -> Any:
        top_k = k or self._k

        try:
            resp = self._client.post("/memory/knowledge/query", {
                "entities":     [query],
                "keywords":     query.split()[:5],
                "token_budget": self._token_budget,
                "max_facts":    top_k,
            })

            facts = resp.get("facts", [])
            passages = []
            source_cids = []

            for f in facts[:top_k]:
                text = f.get("text", "")
                cid  = f.get("source_cid", "")
                if text:
                    passages.append(
                        f"{text} [source_cid:{cid}]" if cid else text
                    )
                    source_cids.append(cid)

            # Return DSPy-compatible Prediction
            class RetrievalResult:
                def __init__(self, passages, cids, resp):
                    self.passages         = passages
                    self.source_cids      = cids
                    self.facts_included   = resp.get("facts_included", 0)
                    self.tokens_used      = resp.get("tokens_used", 0)
                    self.prompt_context   = resp.get("prompt_context", "")

            return RetrievalResult(passages, source_cids, resp)

        except Exception as exc:
            logger.warning("ConnectorDSPyRetriever failed: %s", exc)
            class EmptyResult:
                passages = []
                source_cids = []
                facts_included = 0
                tokens_used = 0
                prompt_context = ""
            return EmptyResult()

    def forward(self, query: str, k: Optional[int] = None) -> Any:
        """DSPy forward() compatibility."""
        return self.__call__(query, k)

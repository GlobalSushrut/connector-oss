"""
Connector Platform — Haystack 2.x Integration

Provides:
  ConnectorTracer      — Haystack component tracing via pipeline events
  ConnectorDocument    — Haystack Document enriched with Connector provenance
  ConnectorRetriever   — Haystack-compatible retriever backed by /memory/recall
  ConnectorGenerator   — Haystack-compatible generator backed by /multiagent/run-pipeline

Usage:
    from haystack import Pipeline
    from integrations.haystack import ConnectorTracer, ConnectorRetriever, ConnectorGenerator

    tracer   = ConnectorTracer(base_url="http://localhost:9090/api/v1", api_key="...")
    retriever = ConnectorRetriever(base_url="...", api_key="...", namespace="docs")
    generator = ConnectorGenerator(base_url="...", api_key="...", agent_name="rag-bot")

    pipe = Pipeline()
    pipe.add_component("retriever", retriever)
    pipe.add_component("generator", generator)
    pipe.connect("retriever.documents", "generator.documents")

    result = pipe.run({"retriever": {"query": "What is GDPR Art.22?"}})
"""

from __future__ import annotations

import time
import uuid
import logging
from dataclasses import dataclass, field
from typing import Any, ClassVar, Dict, List, Optional

import requests

logger = logging.getLogger(__name__)


# ── Shared HTTP client ────────────────────────────────────────────────────────

class _Client:
    def __init__(self, base_url: str, api_key: Optional[str] = None, timeout: int = 30):
        self._base = base_url.rstrip("/")
        self._timeout = timeout
        self._headers: Dict[str, str] = {"Content-Type": "application/json"}
        if api_key:
            self._headers["Authorization"] = f"Bearer {api_key}"

    def get(self, path: str, **params) -> Any:
        r = requests.get(f"{self._base}{path}", headers=self._headers,
                         params=params, timeout=self._timeout)
        r.raise_for_status()
        return r.json()

    def post(self, path: str, body: Any) -> Any:
        r = requests.post(f"{self._base}{path}", headers=self._headers,
                          json=body, timeout=self._timeout)
        r.raise_for_status()
        return r.json()

    def post_safe(self, path: str, body: Any) -> Optional[Any]:
        try:
            return self.post(path, body)
        except Exception as exc:
            logger.debug("Connector telemetry failed (%s %s): %s", path, body, exc)
            return None


# ── ConnectorTracer ───────────────────────────────────────────────────────────

class ConnectorTracer:
    """
    Haystack 2.x pipeline-level tracer.

    Attach to a Pipeline via:
        pipe.add_component("tracer", ConnectorTracer(...))
    Or wrap individual component calls manually.

    Every pipeline run creates an action log entry and, on completion,
    sends a full telemetry record to the Connector Platform.
    """

    def __init__(
        self,
        base_url: str,
        api_key: Optional[str] = None,
        agent_pid: str = "haystack-pipeline",
        cost_center: Optional[str] = None,
        team: Optional[str] = None,
    ):
        self._client = _Client(base_url, api_key)
        self._agent_pid = agent_pid
        self._cost_center = cost_center
        self._team = team
        self._spans: List[Dict[str, Any]] = []

    # ── Span API (call from component wrappers) ───────────────────────────────

    def start_span(self, name: str, span_type: str = "component", **meta) -> str:
        span_id = str(uuid.uuid4())
        self._spans.append({
            "span_id": span_id,
            "name": name,
            "type": span_type,
            "started_at": time.time(),
            "finished_at": None,
            "status": "running",
            **meta,
        })
        return span_id

    def end_span(self, span_id: str, status: str = "ok", output: Any = None):
        for span in self._spans:
            if span["span_id"] == span_id:
                span["finished_at"] = time.time()
                span["duration_ms"] = int((span["finished_at"] - span["started_at"]) * 1000)
                span["status"] = status
                if output is not None:
                    span["output_preview"] = str(output)[:200]
                break

    # ── Pipeline lifecycle hooks ──────────────────────────────────────────────

    def on_pipeline_start(self, pipeline_name: str, inputs: Any) -> str:
        run_id = str(uuid.uuid4())
        self._client.post_safe("/actionlog/record", {
            "agent_pid": self._agent_pid,
            "intent":    f"haystack_pipeline_start:{pipeline_name}",
            "action":    "pipeline_run",
            "resource":  pipeline_name,
            "outcome":   "started",
            "cost_center": self._cost_center,
            "team":      self._team,
        })
        self._current_run_id = run_id
        self._pipeline_name = pipeline_name
        self._start_time = time.time()
        return run_id

    def on_pipeline_end(
        self,
        pipeline_name: str,
        outputs: Any,
        tokens_used: int = 0,
        cost_usd: float = 0.0,
    ):
        duration_ms = int((time.time() - getattr(self, "_start_time", time.time())) * 1000)
        self._client.post_safe("/actionlog/record", {
            "agent_pid":    self._agent_pid,
            "intent":       f"haystack_pipeline_end:{pipeline_name}",
            "action":       "pipeline_complete",
            "resource":     pipeline_name,
            "outcome":      "success",
            "cost_usd":     cost_usd,
            "tokens_used":  tokens_used,
            "cost_center":  self._cost_center,
            "team":         self._team,
        })
        # Write result packet to kernel memory for provenance
        self._client.post_safe("/memory/write", {
            "agent_pid":    self._agent_pid,
            "content":      str(outputs)[:500],
            "user":         "haystack",
            "pipeline":     pipeline_name,
            "packet_type":  "llm_raw",
        })

    def on_component_error(self, component_name: str, error: Exception):
        self._client.post_safe("/actionlog/record", {
            "agent_pid": self._agent_pid,
            "intent":    f"haystack_component_error:{component_name}",
            "action":    "component_run",
            "resource":  component_name,
            "outcome":   f"error:{type(error).__name__}",
        })

    # ── Span summary ─────────────────────────────────────────────────────────

    def flush(self) -> List[Dict[str, Any]]:
        spans = list(self._spans)
        self._spans.clear()
        return spans


# ── ConnectorDocument ─────────────────────────────────────────────────────────

@dataclass
class ConnectorDocument:
    """
    A Haystack-compatible Document enriched with Connector provenance fields.

    Compatible with haystack.dataclasses.Document — can be passed directly
    to any Haystack component that accepts documents.
    """

    content: str
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    meta: Dict[str, Any] = field(default_factory=dict)

    # Connector provenance
    cid: Optional[str] = None
    agent_pid: Optional[str] = None
    trust_score: Optional[int] = None
    namespace: Optional[str] = None

    # Haystack compatibility
    score: Optional[float] = None
    embedding: Optional[List[float]] = None

    def to_haystack(self) -> Dict[str, Any]:
        return {
            "id":      self.id,
            "content": self.content,
            "meta":    {
                **self.meta,
                "connector_cid":         self.cid,
                "connector_agent_pid":   self.agent_pid,
                "connector_trust_score": self.trust_score,
                "connector_namespace":   self.namespace,
            },
            "score": self.score,
        }

    @classmethod
    def from_packet(cls, packet: Dict[str, Any]) -> "ConnectorDocument":
        text = packet.get("text", "") or packet.get("content", "")
        return cls(
            content=text,
            id=packet.get("cid", str(uuid.uuid4())),
            cid=packet.get("cid"),
            agent_pid=packet.get("agent_pid"),
            namespace=packet.get("namespace"),
            meta={"packet_type": packet.get("type", "input")},
        )


# ── ConnectorRetriever ────────────────────────────────────────────────────────

class ConnectorRetriever:
    """
    Haystack 2.x-compatible retriever backed by Connector Platform memory.

    Retrieves documents from /memory/recall/{namespace} and optionally
    enriches with RAG retrieval via /memory/knowledge/query.

    Input:  query (str)
    Output: documents (List[ConnectorDocument])
    """

    # Haystack component metadata
    output_types: ClassVar[Dict[str, type]] = {"documents": list}

    def __init__(
        self,
        base_url: str,
        api_key: Optional[str] = None,
        namespace: str = "default",
        top_k: int = 10,
        use_rag: bool = False,
        tracer: Optional[ConnectorTracer] = None,
    ):
        self._client = _Client(base_url, api_key)
        self._namespace = namespace
        self._top_k = top_k
        self._use_rag = use_rag
        self._tracer = tracer

    def run(self, query: str) -> Dict[str, List[ConnectorDocument]]:
        span_id = self._tracer.start_span("ConnectorRetriever", span_type="retrieval",
                                           query=query[:100]) if self._tracer else None
        try:
            if self._use_rag:
                resp = self._client.post("/memory/knowledge/query", {
                    "entities":     [query],
                    "keywords":     query.split()[:5],
                    "token_budget": 4096,
                    "max_facts":    self._top_k,
                })
                docs = [
                    ConnectorDocument(
                        content=f["text"],
                        cid=f.get("source_cid"),
                        score=f.get("relevance_score"),
                        meta={"entity_id": f.get("entity_id"), "tier": f.get("tier")},
                    )
                    for f in resp.get("facts", [])
                ]
            else:
                resp = self._client.get(f"/memory/recall/{self._namespace}", limit=self._top_k)
                docs = [
                    ConnectorDocument.from_packet(p)
                    for p in resp.get("packets", [])
                ]

            if span_id and self._tracer:
                self._tracer.end_span(span_id, "ok", f"{len(docs)} docs")
            return {"documents": docs}

        except Exception as exc:
            if span_id and self._tracer:
                self._tracer.end_span(span_id, "error", str(exc))
            if self._tracer:
                self._tracer.on_component_error("ConnectorRetriever", exc)
            return {"documents": []}


# ── ConnectorGenerator ────────────────────────────────────────────────────────

class ConnectorGenerator:
    """
    Haystack 2.x-compatible generator backed by Connector Platform multi-agent pipeline.

    Input:  prompt (str), documents (Optional[List[ConnectorDocument]])
    Output: replies (List[str]), metadata (Dict)
    """

    output_types: ClassVar[Dict[str, type]] = {"replies": list, "metadata": dict}

    def __init__(
        self,
        base_url: str,
        api_key: Optional[str] = None,
        agent_name: str = "haystack-generator",
        user: str = "haystack",
        compliance: Optional[List[str]] = None,
        tracer: Optional[ConnectorTracer] = None,
    ):
        self._client = _Client(base_url, api_key)
        self._agent_name = agent_name
        self._user = user
        self._compliance = compliance or []
        self._tracer = tracer

    def run(
        self,
        prompt: str,
        documents: Optional[List[ConnectorDocument]] = None,
    ) -> Dict[str, Any]:
        span_id = self._tracer.start_span("ConnectorGenerator", span_type="generation",
                                           prompt=prompt[:100]) if self._tracer else None

        # Prepend retrieved context to prompt
        context_text = ""
        if documents:
            context_parts = [f"[Doc {i+1}]: {d.content[:300]}"
                              for i, d in enumerate(documents[:5])]
            context_text = "\n".join(context_parts) + "\n\n"

        full_input = context_text + prompt

        try:
            resp = self._client.post("/multiagent/run-pipeline", {
                "name":       f"haystack_{self._agent_name}",
                "agents":     [{"name": self._agent_name, "instructions": (
                    "You are a helpful assistant. Use the provided context to answer accurately."
                )}],
                "input":      full_input,
                "user":       self._user,
                "compliance": self._compliance,
            })

            text = resp.get("text", "")
            metadata = {
                "trust_score":  resp.get("trust"),
                "trust_grade":  resp.get("trust_grade"),
                "duration_ms":  resp.get("duration_ms"),
                "pipeline_id":  resp.get("pipeline_id"),
                "warnings":     resp.get("warnings", []),
                "cost":         resp.get("cost", {}),
            }

            if span_id and self._tracer:
                self._tracer.end_span(span_id, "ok", text[:100])
            return {"replies": [text], "metadata": metadata}

        except Exception as exc:
            if span_id and self._tracer:
                self._tracer.end_span(span_id, "error", str(exc))
            if self._tracer:
                self._tracer.on_component_error("ConnectorGenerator", exc)
            return {"replies": [f"[Connector error: {exc}]"], "metadata": {}}


# ── ConnectorDocumentStore ────────────────────────────────────────────────────

class ConnectorDocumentStore:
    """
    Haystack 2.x-compatible DocumentStore backed by Connector Platform memory.

    Wraps /memory/write (write_document) and /memory/recall (get_all_documents).
    """

    def __init__(
        self,
        base_url: str,
        api_key: Optional[str] = None,
        namespace: str = "haystack-docs",
        agent_pid: str = "haystack-docstore",
    ):
        self._client = _Client(base_url, api_key)
        self._namespace = namespace
        self._agent_pid = agent_pid

    def write_documents(self, documents: List[ConnectorDocument], policy: str = "overwrite") -> int:
        written = 0
        for doc in documents:
            result = self._client.post_safe("/memory/write", {
                "agent_pid":   self._agent_pid,
                "content":     doc.content,
                "user":        "haystack-docstore",
                "pipeline":    self._namespace,
                "packet_type": "input",
            })
            if result and result.get("ok"):
                written += 1
        return written

    def get_all_documents(self, limit: int = 100) -> List[ConnectorDocument]:
        resp = self._client.get(f"/memory/recall/{self._namespace}", limit=limit)
        return [ConnectorDocument.from_packet(p) for p in resp.get("packets", [])]

    def count_documents(self) -> int:
        resp = self._client.get(f"/memory/recall/{self._namespace}", limit=1)
        return resp.get("total", 0)

    def delete_documents(self, document_ids: List[str]) -> None:
        logger.warning("ConnectorDocumentStore.delete_documents: use kernel eviction via /memory endpoint")

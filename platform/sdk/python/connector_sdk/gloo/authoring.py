"""Typed Agent / Tool / Graph authoring (Python Gloo primary).

Builders emit connector-native-contract-shaped specs (ToolSpec / AgentSpec /
GraphSpec). Production run always requires a built `.cpkg` pin outside lab.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional


TOOL_SPEC_SCHEMA = "connector.tool_spec.v1"
AGENT_SPEC_SCHEMA = "connector.agent_spec.v1"
GRAPH_SPEC_SCHEMA = "connector.graph_spec.v1"


def _digest(obj: dict) -> str:
    canonical = json.dumps(obj, sort_keys=True, separators=(",", ":"))
    return f"spec-sha256-{hashlib.sha256(canonical.encode()).hexdigest()}"


@dataclass
class EffectRow:
    effect_class: str
    mutates: bool = True
    disclosure_class: Optional[str] = None

    def to_dict(self) -> dict:
        out = {"effect_class": self.effect_class, "mutates": self.mutates}
        if self.disclosure_class:
            out["disclosure_class"] = self.disclosure_class
        return out


@dataclass
class Tool:
    tool_id: str
    name: str
    effect: EffectRow
    input_schema: Dict[str, Any] = field(default_factory=dict)
    output_schema: Dict[str, Any] = field(default_factory=dict)
    timeout_ms: int = 30_000
    handler: Optional[Callable[..., Any]] = field(default=None, repr=False)

    def to_spec(self) -> dict:
        body = {
            "schema": TOOL_SPEC_SCHEMA,
            "tool_id": self.tool_id,
            "name": self.name,
            "effect": self.effect.to_dict(),
            "input_schema": self.input_schema,
            "output_schema": self.output_schema,
            "timeout_ms": self.timeout_ms,
        }
        body["digest"] = _digest(body)
        return body


@dataclass
class Agent:
    name: str
    model: str = "provider-neutral/default"
    tools: List[Tool] = field(default_factory=list)
    output_schema: Dict[str, Any] = field(default_factory=dict)
    purpose: str = ""
    deps_schema: Dict[str, Any] = field(default_factory=dict)

    def to_spec(self) -> dict:
        body = {
            "schema": AGENT_SPEC_SCHEMA,
            "name": self.name,
            "model_requirements": {"route": self.model},
            "tools": [t.tool_id for t in self.tools],
            "tool_specs": [t.to_spec() for t in self.tools],
            "output_schema": self.output_schema,
            "purpose": self.purpose,
            "deps_schema": self.deps_schema,
        }
        body["digest"] = _digest({k: v for k, v in body.items() if k != "tool_specs"})
        return body

    def emit_cnktr(self, app_id: Optional[str] = None) -> str:
        aid = app_id or self.name.replace(" ", "-").lower()
        return (
            f"app:\n  id: {aid}\n  mode: managed\n"
            f"intelligence:\n  contract: contracts/{aid}.cls\n"
            "authority:\n  default: deny\n"
            "adapters: []\n"
        )


@dataclass
class GraphNode:
    node_id: str
    kind: str  # agent | tool | branch | checkpoint | subgraph
    ref: str = ""
    params: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphEdge:
    from_id: str
    to_id: str
    when: Optional[str] = None


@dataclass
class Graph:
    name: str
    state_schema: Dict[str, Any] = field(default_factory=dict)
    nodes: List[GraphNode] = field(default_factory=list)
    edges: List[GraphEdge] = field(default_factory=list)
    interrupt_before: List[str] = field(default_factory=list)

    def node(self, node_id: str, kind: str, ref: str = "", **params: Any) -> "Graph":
        self.nodes.append(GraphNode(node_id=node_id, kind=kind, ref=ref, params=params))
        return self

    def edge(self, from_id: str, to_id: str, when: Optional[str] = None) -> "Graph":
        self.edges.append(GraphEdge(from_id=from_id, to_id=to_id, when=when))
        return self

    def interrupt(self, node_id: str) -> "Graph":
        self.interrupt_before.append(node_id)
        return self

    def to_spec(self) -> dict:
        body = {
            "schema": GRAPH_SPEC_SCHEMA,
            "name": self.name,
            "state_schema": self.state_schema,
            "nodes": [asdict(n) for n in self.nodes],
            "edges": [asdict(e) for e in self.edges],
            "interrupt_before": list(self.interrupt_before),
        }
        body["digest"] = _digest(body)
        return body


@dataclass
class Project:
    """Authoring project that always packages before production run."""

    root: Path
    app_id: str

    @classmethod
    def current(cls, root: str | Path = ".", app_id: str = "gloo-app") -> "Project":
        return cls(root=Path(root), app_id=app_id)

    def write_specs(self, *specs: dict) -> Path:
        out = self.root / "dist" / "specs"
        out.mkdir(parents=True, exist_ok=True)
        for spec in specs:
            name = spec.get("name") or spec.get("tool_id") or "spec"
            safe = str(name).replace("/", "-")
            (out / f"{safe}.json").write_text(json.dumps(spec, indent=2) + "\n")
        return out

    def ensure_cnktr(self, agent: Optional[Agent] = None) -> Path:
        path = self.root / "cnktr.yaml"
        if not path.exists():
            text = (
                agent.emit_cnktr(self.app_id)
                if agent
                else (
                    f"app:\n  id: {self.app_id}\n  mode: managed\n"
                    "intelligence:\n  contract: contracts/main.cls\n"
                    "authority:\n  default: deny\n"
                    "adapters: []\n"
                )
            )
            path.write_text(text)
        return path

    def build(self, agent: Optional[Agent] = None, graph: Optional[Graph] = None) -> Path:
        """Emit specs + require `.cpkg` via GlooProject.build_cpkg."""
        from .project import GlooProject

        self.ensure_cnktr(agent)
        specs: List[dict] = []
        if agent:
            specs.append(agent.to_spec())
        if graph:
            specs.append(graph.to_spec())
        if specs:
            self.write_specs(*specs)
        return GlooProject.build_cpkg(self.root)

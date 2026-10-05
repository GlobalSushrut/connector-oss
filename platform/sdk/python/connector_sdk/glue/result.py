"""
GlueResult - Canonical success envelope
"""

from typing import Any, Dict, Optional
from dataclasses import dataclass, field


@dataclass
class GlueReceipt:
    """Audit receipt for every operation"""
    id: str
    trace_id: str
    timestamp_ms: int
    cid: Optional[str] = None
    policy: Optional[str] = None
    verified: Optional[bool] = None


@dataclass
class ResourceInfo:
    """Information about the affected resource"""
    id: str
    uid: str
    kind: str
    state: Optional[str] = None


@dataclass
class ResultIntent:
    """The intent that produced this result"""
    verb: str
    noun: str
    target: str


@dataclass
class ResultSummary:
    title: str
    message: str
    status: str
    why: Optional[str] = None
    next: list[str] = field(default_factory=list)


@dataclass
class TrustInfo:
    verified: bool
    score: Optional[int] = None
    grade: Optional[str] = None


@dataclass
class EvidenceRef:
    kind: str
    id: str
    verified: bool
    label: Optional[str] = None


@dataclass
class RenderHints:
    role: str
    redacted: bool
    redacted_fields: list[str] = field(default_factory=list)


@dataclass
class ResultPresentation:
    mode: str
    table_safe: bool
    row_count: Optional[int] = None
    columns: list[str] = field(default_factory=list)


@dataclass
class ResultMeta:
    schema: str = "glue.v1"
    view: str = "json"
    source: str = "glue"


@dataclass
class GlueResult:
    """
    Canonical success result from any GLUE operation.
    
    Every GLUE operation returns this standardized envelope.
    """
    ok: bool
    intent: ResultIntent
    resource: Optional[ResourceInfo] = None
    receipt: Optional[GlueReceipt] = None
    summary: Optional[ResultSummary] = None
    trust: Optional[TrustInfo] = None
    evidence: list[EvidenceRef] = field(default_factory=list)
    links: Dict[str, str] = field(default_factory=dict)
    render: Optional[RenderHints] = None
    presentation: Optional[ResultPresentation] = None
    meta: ResultMeta = field(default_factory=ResultMeta)
    data: Dict[str, Any] = field(default_factory=dict)
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get a data field"""
        return self.data.get(key, default)
    
    def __getitem__(self, key: str) -> Any:
        """Allow dict-like access to data"""
        return self.data[key]
    
    def __contains__(self, key: str) -> bool:
        """Check if key exists in data"""
        return key in self.data
    
    @classmethod
    def success(cls, verb: str, noun: str, target: str) -> "GlueResult":
        """Create a success result"""
        return cls(
            ok=True,
            intent=ResultIntent(verb=verb, noun=noun, target=target),
            summary=ResultSummary(
                title=f"{verb} {noun}",
                message=f"{verb} {noun} completed",
                status="completed",
            ),
            render=RenderHints(role="developer", redacted=False),
            presentation=ResultPresentation(mode="receipt", table_safe=False),
        )
    
    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "GlueResult":
        """Create from API response dict"""
        intent = ResultIntent(
            verb=d.get("intent", {}).get("verb", ""),
            noun=d.get("intent", {}).get("noun", ""),
            target=d.get("intent", {}).get("target", "")
        )
        
        resource = None
        if "resource" in d and d["resource"]:
            resource = ResourceInfo(
                id=d["resource"].get("id", ""),
                uid=d["resource"].get("uid", ""),
                kind=d["resource"].get("kind", ""),
                state=d["resource"].get("state")
            )
        
        receipt = None
        if "receipt" in d and d["receipt"]:
            receipt = GlueReceipt(
                id=d["receipt"].get("id", ""),
                trace_id=d["receipt"].get("trace_id", ""),
                timestamp_ms=d["receipt"].get("timestamp_ms", 0),
                cid=d["receipt"].get("cid"),
                policy=d["receipt"].get("policy"),
                verified=d["receipt"].get("verified"),
            )

        summary = None
        if "summary" in d and d["summary"]:
            summary = ResultSummary(
                title=d["summary"].get("title", ""),
                message=d["summary"].get("message", ""),
                status=d["summary"].get("status", ""),
                why=d["summary"].get("why"),
                next=d["summary"].get("next", []),
            )

        trust = None
        if "trust" in d and d["trust"]:
            trust = TrustInfo(
                verified=bool(d["trust"].get("verified", False)),
                score=d["trust"].get("score"),
                grade=d["trust"].get("grade"),
            )

        evidence = [
            EvidenceRef(
                kind=item.get("kind", ""),
                id=item.get("id", ""),
                verified=bool(item.get("verified", False)),
                label=item.get("label"),
            )
            for item in d.get("evidence", [])
        ]

        render = None
        if "render" in d and d["render"]:
            render = RenderHints(
                role=d["render"].get("role", "developer"),
                redacted=bool(d["render"].get("redacted", False)),
                redacted_fields=d["render"].get("redacted_fields", []),
            )

        presentation = None
        if "presentation" in d and d["presentation"]:
            presentation = ResultPresentation(
                mode=d["presentation"].get("mode", "detail"),
                table_safe=bool(d["presentation"].get("table_safe", False)),
                row_count=d["presentation"].get("row_count"),
                columns=d["presentation"].get("columns", []),
            )

        meta = ResultMeta(
            schema=d.get("meta", {}).get("schema", "glue.v1"),
            view=d.get("meta", {}).get("view", "json"),
            source=d.get("meta", {}).get("source", "glue"),
        )
        
        return cls(
            ok=d.get("ok", True),
            intent=intent,
            resource=resource,
            receipt=receipt,
            summary=summary,
            trust=trust,
            evidence=evidence,
            links=d.get("links", {}),
            render=render,
            presentation=presentation,
            meta=meta,
            data=d.get("data", {})
        )

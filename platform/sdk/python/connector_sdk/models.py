"""
connector_sdk.models — Typed response models for the Connector Platform SDK.

Install with: pip install connector-sdk[typed]

All models use pydantic v2 when available, falling back to plain dataclasses
so the SDK works without pydantic installed.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

try:
    from pydantic import BaseModel, Field

    _PYDANTIC = True
except ImportError:
    from dataclasses import dataclass, field as _field
    BaseModel = object  # type: ignore
    _PYDANTIC = False


def _model(cls):
    """Decorator: wraps class as pydantic BaseModel or plain dataclass."""
    if _PYDANTIC:
        return cls
    return dataclass(cls)  # type: ignore


# ── Agent ─────────────────────────────────────────────────────────────────────

if _PYDANTIC:
    class AgentInfo(BaseModel):
        agent_pid: str
        name: str
        namespace: str
        status: str
        phase: str = ""
        role: str = ""
        clearance: str = ""
        health_score: float = 1.0
        total_tokens_consumed: int = 0
        registered_at: Optional[int] = None
        last_active: Optional[int] = None
        tool_bindings: List[str] = Field(default_factory=list)

        @classmethod
        def from_dict(cls, d: Dict[str, Any]) -> "AgentInfo":
            return cls(**{k: v for k, v in d.items() if k in cls.model_fields})

    class AgentList(BaseModel):
        agents: List[AgentInfo] = Field(default_factory=list)
        count: int = 0

        @classmethod
        def from_dict(cls, d: Dict[str, Any]) -> "AgentList":
            agents = [AgentInfo.from_dict(a) for a in d.get("agents", [])]
            return cls(agents=agents, count=d.get("count", len(agents)))

else:
    @dataclass
    class AgentInfo:  # type: ignore
        agent_pid: str = ""
        name: str = ""
        namespace: str = ""
        status: str = ""
        phase: str = ""
        role: str = ""
        clearance: str = ""
        health_score: float = 1.0
        total_tokens_consumed: int = 0
        registered_at: Optional[int] = None
        last_active: Optional[int] = None
        tool_bindings: List[str] = _field(default_factory=list)

        @classmethod
        def from_dict(cls, d: Dict[str, Any]) -> "AgentInfo":
            return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})

    @dataclass
    class AgentList:  # type: ignore
        agents: List[Any] = _field(default_factory=list)
        count: int = 0

        @classmethod
        def from_dict(cls, d: Dict[str, Any]) -> "AgentList":
            agents = [AgentInfo.from_dict(a) for a in d.get("agents", [])]
            return cls(agents=agents, count=d.get("count", len(agents)))


# ── Memory ────────────────────────────────────────────────────────────────────

if _PYDANTIC:
    class MemoryPacket(BaseModel):
        cid: str
        content: str
        namespace: str = ""
        agent_pid: str = ""
        session_id: Optional[str] = None
        packet_type: str = "Observation"
        timestamp_ms: int = 0
        sealed: bool = False
        pinned: bool = False
        tags: List[str] = Field(default_factory=list)

        @classmethod
        def from_dict(cls, d: Dict[str, Any]) -> "MemoryPacket":
            return cls(**{k: v for k, v in d.items() if k in cls.model_fields})

    class MemoryRecallResult(BaseModel):
        packets: List[MemoryPacket] = Field(default_factory=list)
        namespace: str = ""
        count: int = 0

        @classmethod
        def from_dict(cls, d: Dict[str, Any]) -> "MemoryRecallResult":
            pkts = [MemoryPacket.from_dict(p) for p in d.get("packets", [])]
            return cls(packets=pkts, namespace=d.get("namespace", ""), count=d.get("count", len(pkts)))

else:
    @dataclass
    class MemoryPacket:  # type: ignore
        cid: str = ""
        content: str = ""
        namespace: str = ""
        agent_pid: str = ""
        session_id: Optional[str] = None
        packet_type: str = "Observation"
        timestamp_ms: int = 0
        sealed: bool = False
        pinned: bool = False
        tags: List[str] = _field(default_factory=list)

        @classmethod
        def from_dict(cls, d: Dict[str, Any]) -> "MemoryPacket":
            return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})

    @dataclass
    class MemoryRecallResult:  # type: ignore
        packets: List[Any] = _field(default_factory=list)
        namespace: str = ""
        count: int = 0

        @classmethod
        def from_dict(cls, d: Dict[str, Any]) -> "MemoryRecallResult":
            pkts = [MemoryPacket.from_dict(p) for p in d.get("packets", [])]
            return cls(packets=pkts, namespace=d.get("namespace", ""), count=d.get("count", len(pkts)))


# ── Safety / Claims ───────────────────────────────────────────────────────────

if _PYDANTIC:
    class ClaimVerifyResult(BaseModel):
        claim: str = ""
        verdict: str = ""
        hallucination_safe: bool = False
        confidence: float = 0.0
        supporting_evidence: List[str] = Field(default_factory=list)
        contradicting_evidence: List[str] = Field(default_factory=list)

        @classmethod
        def from_dict(cls, d: Dict[str, Any]) -> "ClaimVerifyResult":
            return cls(**{k: v for k, v in d.items() if k in cls.model_fields})

else:
    @dataclass
    class ClaimVerifyResult:  # type: ignore
        claim: str = ""
        verdict: str = ""
        hallucination_safe: bool = False
        confidence: float = 0.0
        supporting_evidence: List[str] = _field(default_factory=list)
        contradicting_evidence: List[str] = _field(default_factory=list)

        @classmethod
        def from_dict(cls, d: Dict[str, Any]) -> "ClaimVerifyResult":
            return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


# ── Trust ─────────────────────────────────────────────────────────────────────

if _PYDANTIC:
    class TrustScore(BaseModel):
        score: float = 1.0
        grade: str = "A"
        integrity: float = 1.0
        consistency: float = 1.0
        safety: float = 1.0
        compliance: float = 1.0

        @classmethod
        def from_dict(cls, d: Dict[str, Any]) -> "TrustScore":
            return cls(**{k: v for k, v in d.items() if k in cls.model_fields})

else:
    @dataclass
    class TrustScore:  # type: ignore
        score: float = 1.0
        grade: str = "A"
        integrity: float = 1.0
        consistency: float = 1.0
        safety: float = 1.0
        compliance: float = 1.0

        @classmethod
        def from_dict(cls, d: Dict[str, Any]) -> "TrustScore":
            return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


# ── Audit ─────────────────────────────────────────────────────────────────────

if _PYDANTIC:
    class AuditEntry(BaseModel):
        cid: str = ""
        agent_pid: str = ""
        action: str = ""
        outcome: str = ""
        reason: str = ""
        timestamp_ms: int = 0
        namespace: str = ""
        scitt_receipt_cid: Optional[str] = None

        @classmethod
        def from_dict(cls, d: Dict[str, Any]) -> "AuditEntry":
            return cls(**{k: v for k, v in d.items() if k in cls.model_fields})

else:
    @dataclass
    class AuditEntry:  # type: ignore
        cid: str = ""
        agent_pid: str = ""
        action: str = ""
        outcome: str = ""
        reason: str = ""
        timestamp_ms: int = 0
        namespace: str = ""
        scitt_receipt_cid: Optional[str] = None

        @classmethod
        def from_dict(cls, d: Dict[str, Any]) -> "AuditEntry":
            return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


# ── Billing ───────────────────────────────────────────────────────────────────

if _PYDANTIC:
    class BillingUsage(BaseModel):
        agent_pid: str = ""
        namespace: str = ""
        tokens_used: int = 0
        llm_calls: int = 0
        memory_packets: int = 0
        cost_usd: float = 0.0
        period_start: Optional[int] = None
        period_end: Optional[int] = None

        @classmethod
        def from_dict(cls, d: Dict[str, Any]) -> "BillingUsage":
            return cls(**{k: v for k, v in d.items() if k in cls.model_fields})

else:
    @dataclass
    class BillingUsage:  # type: ignore
        agent_pid: str = ""
        namespace: str = ""
        tokens_used: int = 0
        llm_calls: int = 0
        memory_packets: int = 0
        cost_usd: float = 0.0
        period_start: Optional[int] = None
        period_end: Optional[int] = None

        @classmethod
        def from_dict(cls, d: Dict[str, Any]) -> "BillingUsage":
            return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


# ── Error envelope ────────────────────────────────────────────────────────────

if _PYDANTIC:
    class ConnectorApiError(BaseModel):
        code: str = ""
        message: str = ""
        hint: Optional[str] = None
        docs: str = ""
        status: int = 0
        resource: Optional[str] = None

        @classmethod
        def from_dict(cls, d: Dict[str, Any]) -> "ConnectorApiError":
            err = d.get("error", d)
            return cls(**{k: v for k, v in err.items() if k in cls.model_fields})

        def __str__(self) -> str:
            parts = [f"[{self.code}] {self.message}"]
            if self.hint:
                parts.append(f"  → {self.hint}")
            if self.docs:
                parts.append(f"  docs: {self.docs}")
            return "\n".join(parts)

else:
    @dataclass
    class ConnectorApiError:  # type: ignore
        code: str = ""
        message: str = ""
        hint: Optional[str] = None
        docs: str = ""
        status: int = 0
        resource: Optional[str] = None

        @classmethod
        def from_dict(cls, d: Dict[str, Any]) -> "ConnectorApiError":
            err = d.get("error", d)
            return cls(**{k: v for k, v in err.items() if k in cls.__dataclass_fields__})

        def __str__(self) -> str:
            parts = [f"[{self.code}] {self.message}"]
            if self.hint:
                parts.append(f"  → {self.hint}")
            if self.docs:
                parts.append(f"  docs: {self.docs}")
            return "\n".join(parts)


__all__ = [
    "AgentInfo", "AgentList",
    "MemoryPacket", "MemoryRecallResult",
    "ClaimVerifyResult",
    "TrustScore",
    "AuditEntry",
    "BillingUsage",
    "ConnectorApiError",
]

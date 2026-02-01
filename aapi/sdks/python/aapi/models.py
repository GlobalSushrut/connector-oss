from __future__ import annotations
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from datetime import datetime, timezone
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator


class SemanticVersion(BaseModel):
    major: int
    minor: int
    patch: int
    pre: Optional[str] = None
    build: Optional[str] = None

    @classmethod
    def v0_1_0(cls) -> "SemanticVersion":
        return cls(major=0, minor=1, patch=0)

    def __str__(self) -> str:
        base = f"{self.major}.{self.minor}.{self.patch}"
        if self.pre:
            base += f"-{self.pre}"
        if self.build:
            base += f"+{self.build}"
        return base


class ActorType(str, Enum):
    HUMAN = "human"
    AGENT = "agent"
    SERVICE = "service"
    WORKFLOW = "workflow"


class CapabilityAttenuation(BaseModel):
    removed_scopes: List[str] = Field(default_factory=list)
    reduced_budgets: List[Any] = Field(default_factory=list)
    reduced_ttl_ms: Optional[int] = None


class DelegationHop(BaseModel):
    delegator: str
    delegated_at: str  # ISO8601
    reason: Optional[str] = None
    attenuation: Optional[CapabilityAttenuation] = None


class Karta(BaseModel):
    """V1: Kartā - The actor performing the action"""
    pid: str
    role: Optional[str] = None
    realm: Optional[str] = None
    key_id: Optional[str] = None
    actor_type: ActorType = ActorType.HUMAN
    delegation_chain: List[DelegationHop] = Field(default_factory=list)


class Namespace(BaseModel):
    parts: List[str]

    @classmethod
    def from_str(cls, s: str) -> "Namespace":
        return cls(parts=s.split("."))

    def __str__(self) -> str:
        return ".".join(self.parts)


class Karma(BaseModel):
    """V2: Karma - The object/resource being acted upon"""
    rid: str
    kind: Optional[str] = None
    ns: Optional[Union[str, Namespace]] = None  # Allow str for convenience
    version: Optional[str] = None
    labels: Dict[str, str] = Field(default_factory=dict)

    @field_validator("ns")
    def validate_ns(cls, v):
        if isinstance(v, str):
            return Namespace.from_str(v)
        return v


class EffectBucket(str, Enum):
    NONE = "NONE"
    CREATE = "CREATE"
    READ = "READ"
    UPDATE = "UPDATE"
    DELETE = "DELETE"
    EXTERNAL = "EXTERNAL"


class Kriya(BaseModel):
    """V3: Kriyā - The action/verb being performed"""
    action: str  # domain.verb
    domain: Optional[str] = None
    verb: Optional[str] = None
    expected_effect: EffectBucket = EffectBucket.NONE
    idempotent: bool = False

    @staticmethod
    def new(domain: str, verb: str) -> "Kriya":
        return Kriya(
            action=f"{domain}.{verb}",
            domain=domain,
            verb=verb
        )


class Karana(BaseModel):
    """V4: Karaṇa - The means/instrument"""
    via: Optional[str] = None
    adapter: Optional[str] = None
    tool: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class DeliveryPreference(BaseModel):
    channel: str
    address: str
    options: Dict[str, Any] = Field(default_factory=dict)


class Sampradana(BaseModel):
    """V5: Sampradāna - The recipient/beneficiary"""
    recipient: str
    recipient_type: Optional[str] = None
    delivery: Optional[DeliveryPreference] = None


class Apadana(BaseModel):
    """V6: Apādāna - The source/origin"""
    source: str
    source_type: Optional[str] = None
    location: Optional[str] = None


class Caveat(BaseModel):
    caveat_type: str
    value: Any


class CapabilityToken(BaseModel):
    token_id: str
    issuer: str
    subject: str
    actions: List[str]
    resources: List[str]
    expires_at: str
    signature: Optional[str] = None
    caveats: List[Caveat] = Field(default_factory=list)


class TtlConstraint(BaseModel):
    expires_at: str
    max_duration_ms: Optional[int] = None


class Budget(BaseModel):
    resource: str
    limit: float
    used: float
    reset_at: Optional[str] = None


class ApprovalLane(str, Enum):
    NONE = "none"
    STANDARD = "standard"
    CRITICAL = "critical"
    MULTI_PARTY = "multi_party"


class Adhikarana(BaseModel):
    """V7: Adhikaraṇa - The authority/context"""
    cap: Union[Dict[str, str], CapabilityToken]  # cap_ref or inline
    policy_ref: Optional[str] = None
    ttl: Optional[TtlConstraint] = None
    budgets: List[Budget] = Field(default_factory=list)
    approval_lane: ApprovalLane = ApprovalLane.NONE
    scopes: List[str] = Field(default_factory=list)
    context: Optional[Dict[str, Any]] = None

    @staticmethod
    def default_cap(ref: str = "cap:default") -> Dict[str, str]:
        return {"cap_ref": ref}


class BodyType(BaseModel):
    name: str = "generic"
    version: SemanticVersion = Field(default_factory=SemanticVersion.v0_1_0)
    content_type: str = "application/json"


class ReasoningStep(BaseModel):
    step: str
    evidence: Optional[str] = None


class Hetu(BaseModel):
    """Reasoning/justification for the action"""
    reason: str
    chain: List[ReasoningStep] = Field(default_factory=list)
    confidence: Optional[float] = None


class TraceContext(BaseModel):
    trace_id: str
    span_id: str
    parent_span_id: Optional[str] = None
    sampled: bool = True


class VakyaMeta(BaseModel):
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    trace: Optional[TraceContext] = None
    hetu: Optional[Hetu] = None
    client: Optional[Dict[str, Any]] = None
    extensions: Dict[str, Any] = Field(default_factory=dict)


class Vakya(BaseModel):
    """
    VĀKYA - The Agentic Action Request Envelope
    """
    vakya_version: SemanticVersion = Field(default_factory=SemanticVersion.v0_1_0)
    vakya_id: str = Field(default_factory=lambda: str(uuid4()))
    
    v1_karta: Karta
    v2_karma: Karma
    v3_kriya: Kriya
    v4_karana: Optional[Karana] = None
    v5_sampradana: Optional[Sampradana] = None
    v6_apadana: Optional[Apadana] = None
    v7_adhikarana: Adhikarana
    
    body_type: BodyType = Field(default_factory=BodyType)
    body: Dict[str, Any] = Field(default_factory=dict)
    meta: VakyaMeta = Field(default_factory=VakyaMeta)

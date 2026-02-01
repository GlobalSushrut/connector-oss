from typing import Optional, Any, Dict
from datetime import datetime, timedelta, timezone
import uuid

from .models import (
    Vakya,
    Karta,
    Karma,
    Kriya,
    Adhikarana,
    ActorType,
    Namespace,
    TraceContext,
    Hetu,
    TtlConstraint,
    VakyaMeta,
)

class VakyaBuilder:
    """Fluent builder for constructing VĀKYA requests"""
    
    def __init__(self):
        self._actor_pid: Optional[str] = None
        self._actor_role: Optional[str] = None
        self._actor_type: ActorType = ActorType.HUMAN
        self._resource_id: Optional[str] = None
        self._resource_kind: Optional[str] = None
        self._resource_ns: Optional[str] = None
        self._action: Optional[str] = None
        self._capability_ref: Optional[str] = None
        self._ttl_secs: Optional[int] = 3600
        self._body: Dict[str, Any] = {}
        self._trace_id: Optional[str] = None
        self._reason: Optional[str] = None

    def actor(self, pid: str) -> "VakyaBuilder":
        self._actor_pid = pid
        return self

    def actor_with_role(self, pid: str, role: str) -> "VakyaBuilder":
        self._actor_pid = pid
        self._actor_role = role
        return self

    def as_agent(self) -> "VakyaBuilder":
        self._actor_type = ActorType.AGENT
        return self

    def resource(self, rid: str) -> "VakyaBuilder":
        self._resource_id = rid
        return self

    def resource_with_kind(self, rid: str, kind: str) -> "VakyaBuilder":
        if rid:
            self._resource_id = rid
        self._resource_kind = kind
        return self

    def action(self, action: str) -> "VakyaBuilder":
        self._action = action
        return self

    def capability(self, cap_ref: str) -> "VakyaBuilder":
        self._capability_ref = cap_ref
        return self

    def ttl_secs(self, secs: int) -> "VakyaBuilder":
        self._ttl_secs = secs
        return self

    def body(self, body: Dict[str, Any]) -> "VakyaBuilder":
        self._body = body
        return self

    def reason(self, reason: str) -> "VakyaBuilder":
        self._reason = reason
        return self

    def trace(self, trace_id: str) -> "VakyaBuilder":
        self._trace_id = trace_id
        return self

    def build(self) -> Vakya:
        if not self._actor_pid:
            raise ValueError("Actor PID is required")
        if not self._resource_id:
            raise ValueError("Resource ID is required")
        if not self._action:
            raise ValueError("Action is required")

        # Parse action into domain.verb
        parts = self._action.split(".", 1)
        domain = parts[0]
        verb = parts[1] if len(parts) > 1 else self._action

        # TTL
        ttl = None
        if self._ttl_secs is not None:
            expires_at = (datetime.now(timezone.utc) + timedelta(seconds=self._ttl_secs)).isoformat()
            ttl = TtlConstraint(
                expires_at=expires_at,
                max_duration_ms=self._ttl_secs * 1000
            )

        # Capability
        cap_ref = self._capability_ref or "cap:default"
        
        # Meta
        meta = VakyaMeta()
        if self._trace_id:
            meta.trace = TraceContext(
                trace_id=self._trace_id,
                span_id=str(uuid.uuid4())
            )
        if self._reason:
            meta.hetu = Hetu(reason=self._reason)

        return Vakya(
            v1_karta=Karta(
                pid=self._actor_pid,
                role=self._actor_role,
                actor_type=self._actor_type
            ),
            v2_karma=Karma(
                rid=self._resource_id,
                kind=self._resource_kind,
                ns=Namespace.from_str(self._resource_ns) if self._resource_ns else None
            ),
            v3_kriya=Kriya(
                action=self._action,
                domain=domain,
                verb=verb
            ),
            v7_adhikarana=Adhikarana(
                cap={"cap_ref": cap_ref},
                ttl=ttl
            ),
            body=self._body,
            meta=meta
        )

class FileActionBuilder:
    """Helper for file actions"""
    
    @staticmethod
    def read(actor: str, path: str) -> VakyaBuilder:
        return VakyaBuilder()\
            .actor(actor)\
            .resource(f"file:{path}")\
            .resource_with_kind("", "file")\
            .action("file.read")

    @staticmethod
    def write(actor: str, path: str, content: str) -> VakyaBuilder:
        return VakyaBuilder()\
            .actor(actor)\
            .resource(f"file:{path}")\
            .resource_with_kind("", "file")\
            .action("file.write")\
            .body({"content": content})

class HttpActionBuilder:
    """Helper for HTTP actions"""

    @staticmethod
    def get(actor: str, url: str) -> VakyaBuilder:
        return VakyaBuilder()\
            .actor(actor)\
            .resource(url)\
            .resource_with_kind("", "http")\
            .action("http.get")

    @staticmethod
    def post(actor: str, url: str, body: Dict[str, Any]) -> VakyaBuilder:
        return VakyaBuilder()\
            .actor(actor)\
            .resource(url)\
            .resource_with_kind("", "http")\
            .action("http.post")\
            .body({"body": body})

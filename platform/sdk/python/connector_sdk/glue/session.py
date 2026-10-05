"""
GlueSession - Scoped execution context
"""

from typing import Any, Dict, Optional, TYPE_CHECKING
import uuid
import time

if TYPE_CHECKING:
    from .core import Glue
    from .result import GlueResult


class GlueSession:
    """
    A scoped session with inherited policy and namespace.
    
    Usage:
        with glue.session(policy="hipaa_strict") as session:
            result = session.run("claims.review", inputs)
    """
    
    def __init__(self, glue: "Glue", policy: Optional[str] = None,
                 namespace: Optional[str] = None):
        self._glue = glue
        self._policy = policy
        self._namespace = namespace
        self._session_id = f"sess_{uuid.uuid4().hex[:12]}"
        self._start_time = None
    
    @property
    def id(self) -> str:
        return self._session_id
    
    @property
    def policy(self) -> Optional[str]:
        return self._policy
    
    @property
    def namespace(self) -> Optional[str]:
        return self._namespace
    
    def __enter__(self) -> "GlueSession":
        self._start_time = time.time()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        # Session cleanup if needed
        pass
    
    def run(self, target: str, inputs: Optional[Dict[str, Any]] = None) -> "GlueResult":
        """Run a contract within this session"""
        return self._glue.run(target, inputs, policy=self._policy)
    
    def remember(self, key: str, content: str) -> "GlueResult":
        """Remember within this session's namespace"""
        ns = self._namespace or self._glue.config.default_namespace
        return self._glue.remember(key, content, namespace=ns)
    
    def recall(self, query: str, limit: int = 10) -> "GlueResult":
        """Recall within this session's namespace"""
        ns = self._namespace or self._glue.config.default_namespace
        return self._glue.recall(query, namespace=ns, limit=limit)

"""
GLUE Core - Main interface for Connector operations
"""

from typing import Any, Dict, Optional, List
from dataclasses import dataclass, field
import os

from .result import GlueResult
from .error import GlueError, ErrorCode
from .session import GlueSession
from .contract import CompiledContract


@dataclass
class GlueConfig:
    """Configuration for GLUE instance"""
    default_namespace: str = "default"
    default_policy: Optional[str] = None
    audit_enabled: bool = True
    base_url: str = field(default_factory=lambda: os.environ.get("CONNECTOR_URL", "http://localhost:9091"))
    api_key: Optional[str] = field(default_factory=lambda: os.environ.get("CONNECTOR_API_KEY"))
    strict_mode: bool = True  # Fail closed, require server receipts


class Glue:
    """
    The main GLUE interface - entry point for all Connector operations.
    
    Usage:
        glue = Glue()
        result = glue.run("my-agent", {"input": "Hello"})
        
        # Or use the global instance
        from connector.glue import glue
        result = glue.run("my-agent", {"input": "Hello"})
    """
    
    def __init__(self, config: Optional[GlueConfig] = None):
        self.config = config or GlueConfig()
        self._client = None  # Lazy HTTP client
    
    # =========================================================================
    # Core Verbs
    # =========================================================================
    
    def run(self, target: str, inputs: Optional[Dict[str, Any]] = None, 
            policy: Optional[str] = None) -> GlueResult:
        """
        Run a contract or agent.
        
        Args:
            target: Contract name, agent name, or CompiledContract
            inputs: Input parameters
            policy: Optional policy to apply
            
        Returns:
            GlueResult with execution output
        """
        from .runtime import execute_run
        return execute_run(self, target, inputs or {}, policy)
    
    def remember(self, key: str, content: str, 
                 namespace: Optional[str] = None) -> GlueResult:
        """
        Store data to memory.
        
        Args:
            key: Memory key/identifier
            content: Content to store
            namespace: Optional namespace (defaults to config)
        """
        from .runtime import execute_remember
        return execute_remember(self, key, content, namespace)
    
    def recall(self, query: str, namespace: Optional[str] = None,
               limit: int = 10) -> GlueResult:
        """
        Recall data from memory.
        
        Args:
            query: Search query
            namespace: Optional namespace
            limit: Maximum results
        """
        from .runtime import execute_recall
        return execute_recall(self, query, namespace, limit)
    
    def search(self, query: str, namespace: Optional[str] = None,
               limit: int = 20) -> GlueResult:
        """
        Search across memory/knowledge.
        
        Args:
            query: Search query
            namespace: Optional namespace
            limit: Maximum results
        """
        from .runtime import execute_search
        return execute_search(self, query, namespace, limit)
    
    def show(self, noun: str, target: str) -> GlueResult:
        """
        Show/inspect a resource.
        
        Args:
            noun: Resource type (agent, memory, tool, etc.)
            target: Resource identifier
        """
        from .runtime import execute_show
        return execute_show(self, noun, target)
    
    def list(self, noun: str, namespace: Optional[str] = None,
             limit: int = 50) -> GlueResult:
        """
        List resources.
        
        Args:
            noun: Resource type (agents, memories, tools, etc.)
            namespace: Optional namespace filter
            limit: Maximum results
        """
        from .runtime import execute_list
        return execute_list(self, noun, namespace, limit)
    
    def audit(self, target: str) -> GlueResult:
        """
        Get audit trail for an execution.
        
        Args:
            target: Execution ID (e.g., "claims-review#002")
        """
        from .runtime import execute_audit
        return execute_audit(self, target)
    
    def verify(self, what: str, for_agent: Optional[str] = None) -> GlueResult:
        """
        Verify compliance/policy.
        
        Args:
            what: What to verify (e.g., "hipaa", "compliance")
            for_agent: Optional agent to verify for
        """
        from .runtime import execute_verify
        return execute_verify(self, what, for_agent)
    
    # =========================================================================
    # Infra Operations
    # =========================================================================
    
    def explain(self, target: str, last: Optional[str] = None) -> GlueResult:
        """
        Get decision explanation for an agent or execution.
        
        Args:
            target: Agent ID or execution ID
            last: Optional time window (e.g., "5m", "1h")
        """
        from .runtime import execute_explain
        return execute_explain(self, target, last)
    
    def prove(self, target: str, forensic: bool = False) -> GlueResult:
        """
        Get cryptographic proof for an agent or execution.
        
        Args:
            target: Agent ID or execution ID
            forensic: Include full forensic evidence chain
        """
        from .runtime import execute_prove
        return execute_prove(self, target, forensic)
    
    def trace(self, target: str, last: Optional[str] = None, limit: int = 50) -> GlueResult:
        """
        Get execution trace for an agent.
        
        Args:
            target: Agent ID
            last: Optional time window (e.g., "5m", "1h")
            limit: Maximum trace entries
        """
        from .runtime import execute_trace
        return execute_trace(self, target, last, limit)
    
    def review(self, target: str) -> GlueResult:
        """
        Get risk and guarded action posture for an agent.
        
        Args:
            target: Agent ID
        """
        from .runtime import execute_review
        return execute_review(self, target)
    
    def cost(self, target: Optional[str] = None, breakdown: bool = False) -> GlueResult:
        """
        Get cost statement.
        
        Args:
            target: Optional agent ID (defaults to global)
            breakdown: Include detailed breakdown
        """
        from .runtime import execute_cost
        return execute_cost(self, target, breakdown)
    
    def health(self) -> GlueResult:
        """
        Quick health check of the node.
        """
        from .runtime import execute_health
        return execute_health(self)
    
    def doctor(self, verbose: bool = False) -> GlueResult:
        """
        Full diagnostic report of the node.
        
        Args:
            verbose: Include additional environment details
        """
        from .runtime import execute_doctor
        return execute_doctor(self, verbose)
    
    def logs(self, target: Optional[str] = None, follow: bool = False, 
             tail: int = 100) -> GlueResult:
        """
        View node or agent logs.
        
        Args:
            target: Optional agent ID (defaults to node logs)
            follow: Stream logs (not yet implemented in SDK)
            tail: Number of recent lines
        """
        from .runtime import execute_logs
        return execute_logs(self, target, tail)
    
    # =========================================================================
    # Resource Handles
    # =========================================================================
    
    def agent(self, name: str) -> "AgentHandle":
        """Get a handle for agent operations."""
        return AgentHandle(self, name)
    
    def memory(self, namespace: str) -> "MemoryHandle":
        """Get a handle for memory operations."""
        return MemoryHandle(self, namespace)
    
    def tool(self, name: str) -> "ToolHandle":
        """Get a handle for tool operations."""
        return ToolHandle(self, name)
    
    def policy(self, name: str) -> "PolicyHandle":
        """Get a handle for policy operations."""
        return PolicyHandle(self, name)
    
    # =========================================================================
    # Session Management
    # =========================================================================
    
    def session(self, policy: Optional[str] = None, 
                namespace: Optional[str] = None) -> GlueSession:
        """
        Create a scoped session with inherited policy.
        
        Args:
            policy: Policy to apply to all operations
            namespace: Default namespace for operations
            
        Returns:
            GlueSession context manager
        """
        return GlueSession(self, policy, namespace)


class AgentHandle:
    """Handle for agent operations"""
    
    def __init__(self, glue: Glue, name: str):
        self._glue = glue
        self._name = name
    
    def start(self) -> GlueResult:
        """Start the agent"""
        from .runtime import agent_start
        return agent_start(self._glue, self._name)
    
    def stop(self) -> GlueResult:
        """Stop the agent"""
        from .runtime import agent_stop
        return agent_stop(self._glue, self._name)
    
    def status(self) -> GlueResult:
        """Get agent status"""
        from .runtime import agent_status
        return agent_status(self._glue, self._name)
    
    def pause(self) -> GlueResult:
        """Pause the agent"""
        from .runtime import agent_pause
        return agent_pause(self._glue, self._name)
    
    def resume(self) -> GlueResult:
        """Resume the agent"""
        from .runtime import agent_resume
        return agent_resume(self._glue, self._name)


class MemoryHandle:
    """Handle for memory operations"""
    
    def __init__(self, glue: Glue, namespace: str):
        self._glue = glue
        self._namespace = namespace
    
    def write(self, content: str) -> GlueResult:
        """Write to memory"""
        from .runtime import memory_write
        return memory_write(self._glue, self._namespace, content)
    
    def read(self) -> GlueResult:
        """Read from memory"""
        from .runtime import memory_read
        return memory_read(self._glue, self._namespace)
    
    def range(self, start: int, end: int) -> GlueResult:
        """Get a range of memory entries"""
        from .runtime import memory_range
        return memory_range(self._glue, self._namespace, start, end)
    
    def search(self, query: str, limit: int = 10) -> GlueResult:
        """Search within this namespace"""
        return self._glue.search(query, namespace=self._namespace, limit=limit)


class ToolHandle:
    """Handle for tool operations"""
    
    def __init__(self, glue: Glue, name: str):
        self._glue = glue
        self._name = name
    
    def call(self, params: Dict[str, Any]) -> GlueResult:
        """Call the tool"""
        from .runtime import tool_call
        return tool_call(self._glue, self._name, params)
    
    def info(self) -> GlueResult:
        """Get tool info"""
        from .runtime import tool_info
        return tool_info(self._glue, self._name)


class PolicyHandle:
    """Handle for policy operations"""
    
    def __init__(self, glue: Glue, name: str):
        self._glue = glue
        self._name = name
    
    def bind_to(self, agent: str) -> GlueResult:
        """Bind policy to an agent"""
        from .runtime import policy_bind
        return policy_bind(self._glue, self._name, agent)
    
    def check(self, agent: str) -> GlueResult:
        """Check policy compliance for an agent"""
        from .runtime import policy_check
        return policy_check(self._glue, self._name, agent)


# Global GLUE instance
glue = Glue()

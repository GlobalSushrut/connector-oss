"""Connector — Trusted Memory for AI Agents.

# Quick Start (3 lines)

```python
from connector import Agent

agent = Agent("my-bot", "You are helpful")
print(agent.run("Hello!"))
```

# With Memory (5 lines)

```python
from connector import Agent

agent = Agent("my-bot", "You are helpful")
agent.remember("User prefers dark mode")
print(agent.run("What do you know about me?"))
```

# With Tools (10 lines)

```python
from connector import Agent, Tool

@Tool
def search(query: str) -> str:
    return f"Results for: {query}"

agent = Agent("research", "You help with research", tools=[search])
print(agent.run("Find papers on AI safety"))
```

# With Compliance (15 lines)

```python
from connector import Agent

agent = Agent("medical", "You are a triage nurse")
agent.comply("hipaa", "phi", "audit")
result = agent.run("Patient reports chest pain")
print(result.text)
print(result.trust)        # 95/100
print(result.compliance)   # ComplianceReport
```
"""

from __future__ import annotations

import os
import functools
from typing import Any, Callable, Dict, List, Optional, Union

# ═══════════════════════════════════════════════════════════════════════════════
# SIMPLIFIED AGENT API — The primary interface
# ═══════════════════════════════════════════════════════════════════════════════


class AgentResult:
    """
    Rich result object from agent.run().
    
    Provides easy access to response text and advanced capabilities
    like trust scoring, books ledger, and compliance reports.
    
    Example:
        result = agent.run("Hello!")
        print(result.text)       # "Hello! How can I help?"
        print(result.tokens)     # 150
        print(result.trust)      # 0.95
        print(result.cost_usd)   # 0.002
        print(result)            # Pretty dashboard view
    """
    
    def __init__(self, data: Dict[str, Any]):
        self._data = data
    
    # ── Basic Fields ──────────────────────────────────────────────────────────
    
    @property
    def text(self) -> str:
        """The agent's response text."""
        return self._data.get("text", self._data.get("output", ""))
    
    @property
    def tokens(self) -> int:
        """Total tokens used (input + output)."""
        return self._data.get("tokens", self._data.get("tokens_used", 0))
    
    @property
    def latency_ms(self) -> int:
        """Response latency in milliseconds."""
        return self._data.get("latency_ms", self._data.get("duration_ms", 0))
    
    @property
    def cost_usd(self) -> float:
        """Estimated cost in USD."""
        return self._data.get("cost_usd", self._data.get("cost", 0.0))
    
    @property
    def ok(self) -> bool:
        """Whether the request succeeded."""
        return self._data.get("ok", True)
    
    # ── Advanced Fields (always present) ──────────────────────────────────────
    
    @property
    def trust(self) -> float:
        """
        Trust score (0.0 - 1.0).
        
        Computed from 8 dimensions:
        1. Memory integrity
        2. Audit completeness
        3. Authorization coverage
        4. Decision provenance
        5. Operational health
        6. KECS confidence
        7. Claim validity
        8. Identity coherence
        
        Learn more: docs.connector.dev/capabilities/trust
        """
        raw = self._data.get("trust", self._data.get("trust_score", 100))
        return raw / 100.0 if raw > 1 else raw
    
    @property
    def trust_grade(self) -> str:
        """Trust grade (A+, A, B, C, D, F)."""
        return self._data.get("trust_grade", self._grade_from_score(self.trust))
    
    @property
    def trace_id(self) -> Optional[str]:
        """Trace ID for debugging. Use: connector trace show <id>"""
        return self._data.get("trace_id")
    
    @property
    def tool_calls(self) -> List[Dict]:
        """List of tool calls made during this run."""
        return self._data.get("tool_calls", self._data.get("steps", []))
    
    # ── Enterprise Fields (if enabled) ───────────────────────────────────────
    
    @property
    def compliance(self) -> Optional[Dict]:
        """Compliance report (if comply() was called)."""
        return self._data.get("compliance", self._data.get("compliance_check"))
    
    @property
    def books_entry(self) -> Optional[Dict]:
        """Books ledger entry for this operation."""
        return self._data.get("books_entry", self._data.get("journal_entry"))
    
    @property
    def contract_receipt(self) -> Optional[Dict]:
        """Execution receipt (if using contracts)."""
        return self._data.get("contract_receipt", self._data.get("receipt"))
    
    # ── Helpers ───────────────────────────────────────────────────────────────
    
    def _grade_from_score(self, score: float) -> str:
        if score >= 0.95: return "A+"
        if score >= 0.90: return "A"
        if score >= 0.80: return "B"
        if score >= 0.70: return "C"
        if score >= 0.60: return "D"
        return "F"
    
    def is_success(self) -> bool:
        """Check if the run succeeded."""
        return self.ok
    
    def is_failure(self) -> bool:
        """Check if the run failed."""
        return not self.ok
    
    def learn_more(self, topic: str = "result") -> str:
        """Get documentation URL for a topic."""
        base = "https://docs.connector.dev/capabilities"
        return f"{base}/{topic}"
    
    def __str__(self) -> str:
        """Pretty dashboard view."""
        lines = [
            "┌" + "─" * 58 + "┐",
            "│ Agent Response" + " " * 43 + "│",
            "├" + "─" * 58 + "┤",
            f"│ Text:    {self.text[:45]}{'...' if len(self.text) > 45 else ''}" + " " * max(0, 45 - len(self.text[:45])) + "│",
            f"│ Tokens:  {self.tokens}" + " " * (48 - len(str(self.tokens))) + "│",
            f"│ Cost:    ${self.cost_usd:.4f}" + " " * (47 - len(f"${self.cost_usd:.4f}")) + "│",
            f"│ Trust:   {int(self.trust * 100)}/100 (Grade: {self.trust_grade})" + " " * (35 - len(self.trust_grade)) + "│",
        ]
        if self.trace_id:
            lines.append(f"│ Trace:   {self.trace_id}" + " " * (48 - len(self.trace_id)) + "│")
        lines.append("└" + "─" * 58 + "┘")
        return "\n".join(lines)
    
    def __repr__(self) -> str:
        return f"AgentResult(text={self.text[:30]!r}..., trust={self.trust}, tokens={self.tokens})"
    
    def to_dict(self) -> Dict[str, Any]:
        """Return the raw response data."""
        return self._data


class Agent:
    """
    Simplified agent interface — the primary way to use Connector.
    
    Three lines to a working agent:
    
        from connector import Agent
        agent = Agent("my-bot", "You are helpful")
        print(agent.run("Hello!"))
    
    Progressive complexity:
    
        # Level 0: Hello World (3 lines)
        agent = Agent("bot")
        
        # Level 1: With instructions
        agent = Agent("bot", "You are helpful")
        
        # Level 2: With memory
        agent.remember("User prefers dark mode")
        
        # Level 3: With tools
        agent = Agent("bot", tools=[search, send_email])
        
        # Level 4: With compliance
        agent.comply("hipaa", "phi", "audit")
        
        # Level 5: From config
        agent = Agent.from_config("connector.yaml")
    """
    
    def __init__(
        self,
        name: str,
        instructions: str = "You are a helpful assistant.",
        *,
        tools: List[Callable] = None,
        model: str = None,
        base_url: str = None,
        api_key: str = None,
    ):
        """
        Create a new agent.
        
        Args:
            name: Agent identifier (e.g., "support-bot")
            instructions: System prompt for the agent
            tools: List of @Tool decorated functions
            model: LLM model (default: gpt-4o or from env)
            base_url: Connector server URL (default: localhost:8080)
            api_key: API key (default: from OPENAI_API_KEY env)
        """
        self.name = name
        self.instructions = instructions
        self._tools = tools or []
        self._compliance: List[str] = []
        self._model = model or os.getenv("CONNECTOR_MODEL", "gpt-4o")
        self._base_url = base_url or os.getenv("CONNECTOR_BASE_URL", "http://localhost:8080")
        self._api_key = api_key or os.getenv("OPENAI_API_KEY", "")
        self._memories: List[str] = []
        self._native = None
        
        # Try to use native Rust kernel
        self._init_native()
    
    def _init_native(self):
        """Initialize native Rust kernel if available."""
        try:
            from vac_ffi import Connector as NativeConnector
            if self._api_key:
                self._native = NativeConnector("openai", self._model, self._api_key)
        except ImportError:
            pass  # Fall back to HTTP
    
    # ── Factory Methods ───────────────────────────────────────────────────────
    
    @classmethod
    def from_config(cls, path: str = "connector.yaml") -> "Agent":
        """
        Load agent from a config file.
        
        Example:
            agent = Agent.from_config("connector.yaml")
        """
        from connector.config import load_file
        cfg = load_file(path)
        
        # Extract agent config
        agent_cfg = cfg.get("agent", cfg.get("connector", {}))
        name = agent_cfg.get("name", "agent")
        instructions = agent_cfg.get("instructions", "You are a helpful assistant.")
        model = agent_cfg.get("model")
        
        agent = cls(name, instructions, model=model)
        
        # Apply compliance
        comply = agent_cfg.get("comply", [])
        if comply:
            agent.comply(*comply)
        
        return agent
    
    @classmethod
    def from_contract(cls, path: str) -> "Agent":
        """
        Load agent from a contract.yaml file.
        
        For complex workflows with state machines and governance.
        
        Example:
            agent = Agent.from_contract("contract.yaml")
        """
        from connector.config import load_file
        cfg = load_file(path)
        
        name = cfg.get("name", "agent")
        description = cfg.get("description", "")
        
        agent = cls(name, description)
        agent._contract = cfg
        
        return agent
    
    # ── Core Methods ──────────────────────────────────────────────────────────
    
    def run(self, input_text: str, *, user: str = None) -> AgentResult:
        """
        Run the agent with the given input.
        
        Args:
            input_text: The user's message or task
            user: Optional user identifier for audit
        
        Returns:
            AgentResult with text, trust, tokens, and more
        
        Example:
            result = agent.run("Hello!")
            print(result.text)   # "Hello! How can I help?"
            print(result.trust)  # 0.95
        """
        if self._native:
            return self._run_native(input_text, user)
        return self._run_http(input_text, user)
    
    def _run_native(self, input_text: str, user: str = None) -> AgentResult:
        """Run using native Rust kernel."""
        try:
            native_agent = self._native.agent(self.name, self.instructions)
            result = native_agent.run(input_text, user or "user:default")
            return AgentResult({
                "text": result.text,
                "trust": result.trust,
                "trust_grade": result.trust_grade,
                "tokens": getattr(result, "tokens", 0),
                "ok": result.ok,
                "trace_id": getattr(result, "trace_id", None),
            })
        except Exception as e:
            return AgentResult({"text": str(e), "ok": False, "trust": 0})
    
    def _run_http(self, input_text: str, user: str = None) -> AgentResult:
        """Run using HTTP API."""
        try:
            import requests
        except ImportError:
            raise ImportError("HTTP mode requires 'requests'. Install with: pip install requests")
        
        resp = requests.post(
            f"{self._base_url}/run",
            json={
                "agent": self.name,
                "input": input_text,
                "instructions": self.instructions,
                "user": user or "user:default",
                "compliance": self._compliance,
                "tools": [t.__name__ for t in self._tools],
            },
            headers={"Content-Type": "application/json"},
            timeout=60,
        )
        
        if resp.ok:
            return AgentResult(resp.json())
        return AgentResult({"text": f"Error: {resp.text}", "ok": False, "trust": 0})
    
    # ── Memory Methods ────────────────────────────────────────────────────────
    
    def remember(self, content: str, *, tags: List[str] = None) -> "Agent":
        """
        Store a memory for this agent.
        
        Args:
            content: The text to remember
            tags: Optional tags for retrieval
        
        Returns:
            self (for chaining)
        
        Example:
            agent.remember("User prefers dark mode")
            agent.remember("User is a senior engineer", tags=["profile"])
        """
        self._memories.append(content)
        
        # Also persist to kernel if available
        if self._native:
            try:
                self._native.remember(self.name, content, "user:sdk")
            except Exception:
                pass  # Memory stored locally
        
        return self
    
    def recall(self, query: str = None, *, limit: int = 20) -> List[str]:
        """
        Recall memories for this agent.
        
        Args:
            query: Optional search query (semantic search)
            limit: Max results to return
        
        Returns:
            List of memory strings
        
        Example:
            memories = agent.recall()
            relevant = agent.recall("preferences", limit=5)
        """
        if self._native:
            try:
                result = self._native.memories(self.name, limit)
                return [m.get("content", "") for m in result.get("packets", [])]
            except Exception:
                pass
        
        # Return local memories
        if query:
            return [m for m in self._memories if query.lower() in m.lower()][:limit]
        return self._memories[:limit]
    
    def knowledge_graph(self) -> Dict[str, Any]:
        """
        Get the knowledge graph extracted from memories.
        
        Returns:
            Dict with 'entities' and 'relations' lists
        
        Example:
            kg = agent.knowledge_graph()
            print(kg['entities'])   # [Entity("User", type="person"), ...]
            print(kg['relations'])  # [Relation("User", "prefers", "dark mode")]
        """
        # Placeholder — would call kernel knowledge graph API
        return {
            "entities": [],
            "relations": [],
            "_note": "Knowledge graph auto-extracted from memories",
        }
    
    # ── Compliance Methods ────────────────────────────────────────────────────
    
    def comply(self, *frameworks: str) -> "Agent":
        """
        Enable compliance frameworks.
        
        Supported frameworks:
        - "audit" — Log all operations
        - "hipaa" — HIPAA compliance
        - "phi" — PHI detection and protection
        - "gdpr" — GDPR compliance
        - "soc2" — SOC2 controls
        - "iso42001" — ISO 42001 AI management
        
        Args:
            *frameworks: One or more framework names
        
        Returns:
            self (for chaining)
        
        Example:
            agent.comply("hipaa", "phi", "audit")
        """
        self._compliance.extend(frameworks)
        return self
    
    # ── Tool Methods ──────────────────────────────────────────────────────────
    
    @property
    def tools(self) -> List[Callable]:
        """Get registered tools."""
        return self._tools
    
    @tools.setter
    def tools(self, value: List[Callable]):
        """Set registered tools."""
        self._tools = value
    
    # ── Utility Methods ───────────────────────────────────────────────────────
    
    def __repr__(self) -> str:
        return f"Agent(name={self.name!r}, tools={len(self._tools)}, comply={self._compliance})"


# ═══════════════════════════════════════════════════════════════════════════════
# TOOL DECORATOR — Simple way to define tools
# ═══════════════════════════════════════════════════════════════════════════════


def Tool(func: Callable = None, *, timeout: int = 30, clearance: int = 1) -> Callable:
    """
    Decorator to mark a function as an agent tool.
    
    Example:
        @Tool
        def search(query: str) -> str:
            '''Search the web for information'''
            return f"Results for: {query}"
        
        @Tool(timeout=60, clearance=2)
        def send_email(to: str, subject: str, body: str) -> str:
            '''Send an email to a recipient'''
            return f"Email sent to {to}"
        
        agent = Agent("bot", tools=[search, send_email])
    """
    def decorator(f: Callable) -> Callable:
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            return f(*args, **kwargs)
        
        # Attach metadata
        wrapper._is_tool = True
        wrapper._timeout = timeout
        wrapper._clearance = clearance
        wrapper._description = f.__doc__ or f"Tool: {f.__name__}"
        
        return wrapper
    
    if func is not None:
        return decorator(func)
    return decorator


# ═══════════════════════════════════════════════════════════════════════════════
# LEGACY IMPORTS — For backward compatibility
# ═══════════════════════════════════════════════════════════════════════════════

try:
    from vac_ffi import Connector, Pipeline, PipelineResult
    _HAS_NATIVE = True
except ImportError:
    _HAS_NATIVE = False
    Connector = None
    Pipeline = None
    PipelineResult = None

from connector.config import load_file as load_config

__all__ = [
    # New simplified API
    "Agent",
    "AgentResult",
    "Tool",
    # Legacy API (still works)
    "Connector",
    "Pipeline",
    "PipelineResult",
    "load_config",
]
__version__ = "0.2.0"

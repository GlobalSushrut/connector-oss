"""
Strict typed Glue grammar - verbs, nouns, and validation
"""

from enum import Enum
from typing import Literal


class GlueVerb(str, Enum):
    """Canonical Glue verbs"""
    # Core operations
    RUN = "run"
    REMEMBER = "remember"
    RECALL = "recall"
    SEARCH = "search"
    SHOW = "show"
    LIST = "list"
    AUDIT = "audit"
    VERIFY = "verify"
    
    # Agent operations
    START = "start"
    STOP = "stop"
    STATUS = "status"
    PAUSE = "pause"
    RESUME = "resume"
    DEPLOY = "deploy"
    
    # Memory operations
    WRITE = "write"
    READ = "read"
    RANGE = "range"
    
    # Tool operations
    CALL = "call"
    INFO = "info"
    
    # Policy operations
    BIND = "bind"
    CHECK = "check"
    
    # Infra operations
    EXPLAIN = "explain"
    PROVE = "prove"
    TRACE = "trace"
    REVIEW = "review"
    COST = "cost"
    HEALTH = "health"
    DOCTOR = "doctor"
    LOGS = "logs"
    BACKUP = "backup"
    RESTORE = "restore"
    UPGRADE = "upgrade"


class GlueNoun(str, Enum):
    """Canonical Glue nouns"""
    # Execution
    CONTRACT = "contract"
    AGENT = "agent"
    EXECUTION = "execution"
    
    # Memory
    MEMORY = "memory"
    KNOWLEDGE = "knowledge"
    SESSION = "session"
    
    # Tools & Policy
    TOOL = "tool"
    POLICY = "policy"
    
    # Compliance & Proof
    COMPLIANCE = "compliance"
    PROOF = "proof"
    RECEIPT = "receipt"
    
    # Infrastructure
    NODE = "node"
    PROTOCOL = "protocol"
    MONITOR = "monitor"
    INFRA = "infra"


# Type aliases for strict grammar
GlueVerbLiteral = Literal[
    "run", "remember", "recall", "search", "show", "list", "audit", "verify",
    "start", "stop", "status", "pause", "resume", "deploy",
    "write", "read", "range",
    "call", "info",
    "bind", "check",
    "explain", "prove", "trace", "review", "cost",
    "health", "doctor", "logs", "backup", "restore", "upgrade"
]

GlueNounLiteral = Literal[
    "contract", "agent", "execution",
    "memory", "knowledge", "session",
    "tool", "policy",
    "compliance", "proof", "receipt",
    "node", "protocol", "monitor", "infra"
]

"""
GlueError - Canonical error envelope
"""

from typing import List, Optional
from enum import Enum


class ErrorCode(Enum):
    """Standard error codes"""
    # Auth/Access
    AUTH_REQUIRED = "auth_required"
    ACCESS_DENIED = "access_denied"
    QUOTA_REACHED = "quota_reached"
    POLICY_VIOLATION = "policy_violation"
    # Resource
    NOT_FOUND = "not_found"
    ALREADY_EXISTS = "already_exists"
    INVALID_STATE = "invalid_state"
    # Contract
    COMPILE_ERROR = "compile_error"
    VALIDATION_ERROR = "validation_error"
    EXECUTION_ERROR = "execution_error"
    # Input
    INVALID_INPUT = "invalid_input"
    MISSING_REQUIRED = "missing_required"
    TYPE_MISMATCH = "type_mismatch"
    # System
    INTERNAL_ERROR = "internal_error"
    TIMEOUT = "timeout"
    UNAVAILABLE = "unavailable"


class GlueError(Exception):
    """
    Canonical error from any GLUE operation.
    
    Provides structured error information with hints and documentation links.
    """
    
    def __init__(self, code: ErrorCode, message: str,
                 detail: Optional[str] = None,
                 hints: Optional[List[str]] = None,
                 docs: Optional[str] = None,
                 status: Optional[int] = None,
                 retryable: bool = False):
        super().__init__(message)
        self.code = code
        self.message = message
        self.detail = detail
        self.hints = hints or []
        self.docs = docs
        self.status = status
        self.retryable = retryable
    
    def __str__(self) -> str:
        parts = [f"[{self.code.value}] {self.message}"]
        if self.detail:
            parts.append(f"  Detail: {self.detail}")
        for hint in self.hints:
            parts.append(f"  Hint: {hint}")
        if self.docs:
            parts.append(f"  Docs: {self.docs}")
        return "\n".join(parts)
    
    @classmethod
    def not_found(cls, what: str) -> "GlueError":
        return cls(ErrorCode.NOT_FOUND, f"{what} not found")
    
    @classmethod
    def compile_error(cls, msg: str, detail: Optional[str] = None) -> "GlueError":
        return cls(ErrorCode.COMPILE_ERROR, msg, detail=detail)
    
    @classmethod
    def invalid_input(cls, msg: str) -> "GlueError":
        return cls(ErrorCode.INVALID_INPUT, msg)
    
    @classmethod
    def policy_violation(cls, policy: str, reason: str) -> "GlueError":
        return cls(
            ErrorCode.POLICY_VIOLATION,
            f"Policy '{policy}' violated: {reason}"
        )
    
    @classmethod
    def from_dict(cls, d: dict) -> "GlueError":
        """Create from API error response"""
        error = d.get("error", d)
        code_str = error.get("code", "internal_error")
        try:
            code = ErrorCode(code_str)
        except ValueError:
            code = ErrorCode.INTERNAL_ERROR
        
        return cls(
            code=code,
            message=error.get("message", "Unknown error"),
            detail=error.get("detail"),
            hints=error.get("hints", error.get("hint", [])),
            docs=error.get("docs"),
            status=error.get("status"),
            retryable=bool(error.get("retryable", False)),
        )

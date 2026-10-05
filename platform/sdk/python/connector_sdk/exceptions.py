class ConnectorError(Exception):
    """Base exception for all Connector SDK errors."""
    def __init__(self, message: str, status_code: int = None, response: dict = None):
        super().__init__(message)
        self.status_code = status_code
        self.response = response or {}


class AgentNotFoundError(ConnectorError):
    """Raised when the agent PID is not found in the kernel."""
    pass


class QuotaExceededError(ConnectorError):
    """Raised when the agent or namespace has exceeded its token/packet quota."""
    pass


class AuthError(ConnectorError):
    """Raised when the token is invalid or missing."""
    pass


class HallucinationRisk(ConnectorError):
    """Raised when claims verification fails or hallucination risk is high."""
    pass

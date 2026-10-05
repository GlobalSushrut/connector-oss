"""
Connector SDK — DSPy Integration

Usage:
    from connector_sdk.integrations.dspy import ConnectorDSPyLogger
    logger = ConnectorDSPyLogger(base_url="http://localhost:8080/api/v1", api_key="cp-...")

Install:
    pip install connector-sdk[dspy]
"""
import os, sys
_here = os.path.dirname(__file__)
_root = os.path.normpath(os.path.join(_here, "..", "..", "..", "..", "integrations"))
if os.path.isdir(_root) and os.path.dirname(_root) not in sys.path:
    sys.path.insert(0, os.path.dirname(_root))
try:
    from integrations.dspy import ConnectorDSPyLogger  # type: ignore
except ImportError:
    raise ImportError("DSPy integration requires the Connector platform source.\n  pip install connector-sdk[dspy]")

__all__ = ["ConnectorDSPyLogger"]

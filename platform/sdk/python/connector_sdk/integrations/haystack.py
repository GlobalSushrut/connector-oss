"""
Connector SDK — Haystack Integration

Usage:
    from connector_sdk.integrations.haystack import ConnectorHaystackTracer
    tracer = ConnectorHaystackTracer(base_url="http://localhost:8080/api/v1", api_key="cp-...")

Install:
    pip install connector-sdk[haystack]
"""
import os, sys
_here = os.path.dirname(__file__)
_root = os.path.normpath(os.path.join(_here, "..", "..", "..", "..", "integrations"))
if os.path.isdir(_root) and os.path.dirname(_root) not in sys.path:
    sys.path.insert(0, os.path.dirname(_root))
try:
    from integrations.haystack import ConnectorHaystackTracer  # type: ignore
except ImportError:
    raise ImportError("Haystack integration requires the Connector platform source.\n  pip install connector-sdk[haystack]")

__all__ = ["ConnectorHaystackTracer"]

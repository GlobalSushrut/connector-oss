"""
Connector SDK — AutoGen Integration

Usage:
    from connector_sdk.integrations.autogen import ConnectorMiddleware, instrument_autogen_agent
    middleware = ConnectorMiddleware(base_url="http://localhost:8080/api/v1", api_key="cp-...")
    agent = instrument_autogen_agent(my_agent, middleware)

Install:
    pip install connector-sdk[autogen]
"""
import os, sys
_here = os.path.dirname(__file__)
_platform_integrations = os.path.normpath(os.path.join(_here, "..", "..", "..", "..", "integrations"))
if os.path.isdir(_platform_integrations) and os.path.dirname(_platform_integrations) not in sys.path:
    sys.path.insert(0, os.path.dirname(_platform_integrations))
try:
    from integrations.autogen import ConnectorMiddleware, instrument_autogen_agent  # type: ignore
except ImportError:
    raise ImportError("AutoGen integration requires the Connector platform source.\n  pip install connector-sdk[autogen]")

__all__ = ["ConnectorMiddleware", "instrument_autogen_agent"]

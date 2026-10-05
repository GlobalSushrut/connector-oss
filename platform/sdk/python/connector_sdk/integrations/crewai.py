"""
Connector SDK — CrewAI Integration

Usage:
    from connector_sdk.integrations.crewai import ConnectorCrewAIObserver
    observer = ConnectorCrewAIObserver(base_url="http://localhost:8080/api/v1", api_key="cp-...")

Install:
    pip install connector-sdk[crewai]
"""
import os, sys
_here = os.path.dirname(__file__)
_root = os.path.normpath(os.path.join(_here, "..", "..", "..", "..", "integrations"))
if os.path.isdir(_root) and os.path.dirname(_root) not in sys.path:
    sys.path.insert(0, os.path.dirname(_root))
try:
    from integrations.crewai import ConnectorCrewAIObserver  # type: ignore
except ImportError:
    raise ImportError("CrewAI integration requires the Connector platform source.\n  pip install connector-sdk[crewai]")

__all__ = ["ConnectorCrewAIObserver"]

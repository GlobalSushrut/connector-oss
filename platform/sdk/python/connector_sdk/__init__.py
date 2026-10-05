"""
Connector SDK for Python
The production AI agent runtime — memory, safety, protocols, and compliance in one binary.

GLUE Quickstart (recommended):
    from connector_sdk import glue
    from connector_sdk.glue import cls
    
    contract = cls.compile('''
        contract hello {
            interface {
                input name: string required
                output greeting: string
            }
        }
    ''')
    result = glue.run(contract, {"name": "World"})

Legacy Quickstart:
    from connector_sdk import ConnectorAgent
    agent = ConnectorAgent("my-agent", base_url="http://localhost:9090")
    agent.remember("User prefers dark mode")
"""

from .client import ConnectorAgent, ConnectorClient
from .exceptions import ConnectorError, AgentNotFoundError, QuotaExceededError
from .native import NativeClient, NativeClientError, PackagePin, admit_package_for_effect

# GLUE - The canonical developer interface (replaces SDK pattern)
from .glue import glue, cls, Glue, GlueResult, GlueError, GlueSession, CompiledContract
from .gloo import GlooApp, GlooAppManifest, GlooWorkflowSpec, GlooAgentSpec, GlooNode, GlooProject

__version__ = "0.1.0"
__all__ = [
    # GLUE (recommended)
    "glue", "cls", "Glue", "GlueResult", "GlueError", "GlueSession", "CompiledContract",
    # GLOO (developer platform layer)
    "GlooApp", "GlooAppManifest", "GlooWorkflowSpec", "GlooAgentSpec", "GlooNode", "GlooProject",
    # Native control plane
    "NativeClient", "NativeClientError", "PackagePin", "admit_package_for_effect",
    # Legacy
    "ConnectorAgent", "ConnectorClient", "ConnectorError", "AgentNotFoundError", "QuotaExceededError"
]

"""
Connector SDK — LangChain Integration

Usage:
    from connector_sdk.integrations.langchain import ConnectorCallbackHandler
    handler = ConnectorCallbackHandler(
        base_url="http://localhost:8080/api/v1",
        api_key="cp-...",
        agent_pid="agent_abc123",
    )
    llm = ChatOpenAI(callbacks=[handler])

Install:
    pip install connector-sdk[langchain]
"""

# Re-export from the canonical platform integration module.
# This gives users a stable `connector_sdk.integrations.langchain` import path
# regardless of where the platform source tree is installed.
try:
    from platform.integrations.langchain import ConnectorCallbackHandler  # type: ignore
except ImportError:
    # Fallback: inline minimal shim so the import never hard-fails at import time.
    # Full functionality requires the platform integrations directory on sys.path.
    import os
    import sys
    _here = os.path.dirname(__file__)
    _platform_integrations = os.path.normpath(
        os.path.join(_here, "..", "..", "..", "..", "integrations")
    )
    if os.path.isdir(_platform_integrations) and _platform_integrations not in sys.path:
        sys.path.insert(0, os.path.dirname(_platform_integrations))
    try:
        from integrations.langchain import ConnectorCallbackHandler  # type: ignore
    except ImportError:
        raise ImportError(
            "LangChain integration requires the Connector platform source.\n"
            "  Install: pip install connector-sdk[langchain]\n"
            "  Or ensure platform/integrations/ is on your PYTHONPATH."
        )

__all__ = ["ConnectorCallbackHandler"]

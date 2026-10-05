"""
Connector SDK — Framework Integrations

Usage:
    from connector_sdk.integrations.langchain import ConnectorCallbackHandler
    from connector_sdk.integrations.autogen import ConnectorMiddleware, instrument_autogen_agent
    from connector_sdk.integrations.crewai import ConnectorCrewAIObserver
    from connector_sdk.integrations.llamaindex import ConnectorLlamaIndexCallback
    from connector_sdk.integrations.dspy import ConnectorDSPyLogger
    from connector_sdk.integrations.haystack import ConnectorHaystackTracer

Install extras:
    pip install connector-sdk[langchain]
    pip install connector-sdk[autogen]
    pip install connector-sdk[crewai]
    pip install connector-sdk[llamaindex]
    pip install connector-sdk[all]
"""

__all__ = [
    "ConnectorCallbackHandler",
    "ConnectorMiddleware",
    "instrument_autogen_agent",
    "ConnectorCrewAIObserver",
    "ConnectorLlamaIndexCallback",
    "ConnectorDSPyLogger",
    "ConnectorHaystackTracer",
]


def ConnectorCallbackHandler(*args, **kwargs):
    from connector_sdk.integrations.langchain import ConnectorCallbackHandler as _H
    return _H(*args, **kwargs)


def ConnectorMiddleware(*args, **kwargs):
    from connector_sdk.integrations.autogen import ConnectorMiddleware as _M
    return _M(*args, **kwargs)


def instrument_autogen_agent(agent, middleware):
    from connector_sdk.integrations.autogen import instrument_autogen_agent as _f
    return _f(agent, middleware)


def ConnectorCrewAIObserver(*args, **kwargs):
    from connector_sdk.integrations.crewai import ConnectorCrewAIObserver as _O
    return _O(*args, **kwargs)


def ConnectorLlamaIndexCallback(*args, **kwargs):
    from connector_sdk.integrations.llamaindex import ConnectorLlamaIndexCallback as _C
    return _C(*args, **kwargs)


def ConnectorDSPyLogger(*args, **kwargs):
    from connector_sdk.integrations.dspy import ConnectorDSPyLogger as _L
    return _L(*args, **kwargs)


def ConnectorHaystackTracer(*args, **kwargs):
    from connector_sdk.integrations.haystack import ConnectorHaystackTracer as _T
    return _T(*args, **kwargs)

"""
Gloo developer surface for Connector.

This package adds a Python-first app/project layer on top of the existing
Connector SDK and GLUE primitives.
"""

from .app import GlooApp, GlooAppManifest, GlooWorkflowSpec, GlooAgentSpec
from .authoring import Agent, EffectRow, Graph, Project, Tool
from .node import GlooNode
from .project import GlooProject

__all__ = [
    "GlooApp",
    "GlooAppManifest",
    "GlooWorkflowSpec",
    "GlooAgentSpec",
    "GlooNode",
    "GlooProject",
    "Agent",
    "Tool",
    "Graph",
    "Project",
    "EffectRow",
]

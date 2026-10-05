"""
GLUE - Governed Logic Unification Engine

The canonical Python interface for Connector. GLUE replaces traditional SDKs
with a governed, auditable execution surface.

Usage:
    from connector import glue
    from connector.glue import cls

    # Compile and run a CLS contract
    contract = cls.compile('''
        contract hello {
            interface {
                input name: string required
                output greeting: string
            }
        }
    ''')

    result = glue.run(contract, {"name": "World"})
    print(result.data["greeting"])
"""

from .core import Glue, glue
from .cls import cls, compile as compile_cls
from .result import GlueResult, GlueReceipt
from .error import GlueError, ErrorCode
from .session import GlueSession
from .contract import CompiledContract
from .types import GlueVerb, GlueNoun

__all__ = [
    "Glue",
    "glue",
    "cls",
    "compile_cls",
    "GlueResult",
    "GlueReceipt",
    "GlueError",
    "ErrorCode",
    "GlueSession",
    "CompiledContract",
    "GlueVerb",
    "GlueNoun",
]

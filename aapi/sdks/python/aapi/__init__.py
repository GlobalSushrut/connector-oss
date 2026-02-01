"""
AAPI Python SDK
~~~~~~~~~~~~~~~

A Python client library for the Agentic Action Protocol Interface (AAPI).
"""

from .models import Vakya, Karta, Karma, Kriya, Adhikarana
from .client import AapiClient
from .builder import VakyaBuilder, FileActionBuilder, HttpActionBuilder
from .merkle import MerkleTreeVerifier

try:
    from .crypto import VakyaSigner, KeyPair
except Exception:  # pragma: no cover
    VakyaSigner = None  # type: ignore
    KeyPair = None  # type: ignore

try:
    from .langchain import AapiTool
except Exception:  # pragma: no cover
    AapiTool = None  # type: ignore

__version__ = "0.1.0"

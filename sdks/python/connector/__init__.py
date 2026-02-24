"""Connector — Trusted Memory for AI Agents.

```python
from connector import Connector

c = Connector("openai", "gpt-4o", "sk-...")
agent = c.agent("bot", "You are helpful")
result = agent.run("Hello!", "user:alice")
print(result.text)
print(result.trust)
print(result)  # beautiful dashboard
```
"""

try:
    from vac_ffi import Connector, Agent, Pipeline, PipelineResult
except ImportError:
    raise ImportError(
        "connector-agent requires the native Rust kernel.\n"
        "Install it with:\n"
        "  pip install vac-ffi\n"
        "Or build from source:\n"
        "  cd vac/crates/vac-ffi && maturin develop --release"
    )

from connector.config import load_file as load_config

__all__ = ["Connector", "Agent", "Pipeline", "PipelineResult", "load_config"]
__version__ = "0.1.0"

# Connector Python SDK

Trusted Memory for AI Agents — Python SDK backed by the real Rust kernel.

## Install

```bash
pip install connector-agent
```

## Quick Start

```python
from connector import Connector

# 3 lines: agent with memory
c = Connector("openai", "gpt-4o", "sk-...")
agent = c.agent("assistant", "You help users")
result = agent.run("What is Rust?", user="user:alice")

print(result.text)        # response
print(result.trust)       # 92 (kernel-verified)
print(result.trust_grade) # "A"
print(result)             # beautiful dashboard
```

## Multi-Agent Pipeline

```python
pipe = c.pipeline("support")
pipe.agent("triage", "Classify tickets")
pipe.agent("resolver", "Find answers")
pipe.route("triage -> resolver")
pipe.hipaa()

result = pipe.run("My account is locked", user="user:bob")
print(result.to_json())   # machine-parseable with provenance tags
```

## Observability

```python
result.to_json()       # every field tagged with source (kernel/llm/derived/user)
result.to_otel()       # OTLP-compatible trace export
result.to_llm()        # LLM-friendly summary
result.provenance()    # {"kernel_verified": 5, "trust_percentage": 100.0}
result.is_verified()   # True = zero-fake guarantee
```

## License

Apache-2.0

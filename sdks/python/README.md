# connector-oss — Python SDK

> Tamper-proof memory, chain-of-custody, and OS-grade runtime for AI agents.
> Native Rust kernel via PyO3 — ~140 methods, zero Python overhead.

## Install

```bash
pip install connector-oss
```

Prebuilt wheels available for:
- Linux x86_64 / aarch64
- macOS x86_64 / Apple Silicon (aarch64)
- Windows x86_64

## Quick Start

```python
import os
from connector_oss import Connector

# 3 lines: agent with trusted memory
c = Connector("deepseek", "deepseek-chat", os.environ["DEEPSEEK_API_KEY"])
result = c.agent("bot", "You are helpful").run("Hello!", "user:alice")

print(result.text)         # LLM response
print(result.trust)        # 0-100 kernel-verified trust score
print(result.trust_grade)  # "A+" | "A" | "B" | "C" | "D" | "F"
```

### From YAML Config

```python
c = Connector.from_config("connector.yaml")
```

## Memory & Knowledge

```python
# Write tamper-proof memory (CID-addressed)
c.memory_write("pid:bot", "text", "Patient has fever", "user:nurse", "ns:er")

# Search memory
packets = c.search_namespace("ns:er", limit=10)

# Knowledge graph + RAG
c.knowledge_ingest("ns:er")
ctx = c.rag_retrieve("pid:bot", "ns:er", entities=["fever"], max_facts=10)

# Cognitive cycle
report = c.cognitive_cycle("pid:bot", "ns:er", "Diagnose patient")
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

## Custom Folders (OS mkdir model)

```python
c.create_agent_folder("nurse", "notes", "Patient notes")
c.folder_put("agent:nurse/notes", "p123", '{"bp": "140/90"}')
val = c.folder_get("agent:nurse/notes", "p123")
```

## Observability

```python
result.to_json()       # every field tagged with source (kernel/llm/derived/user)
result.to_otel()       # OTLP-compatible trace export
result.to_llm()        # LLM-friendly summary
result.provenance()    # {"kernel_verified": 5, "trust_percentage": 100.0}
result.is_verified()   # True = zero-fake guarantee
```

## What Makes This Different

| | LangChain | CrewAI | **connector-oss** |
|-|-----------|--------|-------------------|
| Tamper-proof memory | ❌ | ❌ | ✅ CID-addressed, kernel-verified |
| Audit trail | ❌ | ❌ | ✅ Ed25519-signed, append-only |
| HIPAA/SOC2/GDPR | ❌ | ❌ | ✅ Built-in compliance |
| Trust scoring | ❌ | ❌ | ✅ Per-response, 0-100 |
| Policy enforcement | ❌ | ❌ | ✅ Non-bypassable 5-layer guard |

## Links

- [QUICKSTART.md](https://github.com/GlobalSushrut/connector-oss/blob/main/QUICKSTART.md)
- [ARCHITECTURE.md](https://github.com/GlobalSushrut/connector-oss/blob/main/ARCHITECTURE.md)
- [GitHub](https://github.com/GlobalSushrut/connector-oss)

## License

Apache-2.0

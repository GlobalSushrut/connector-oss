# TraceTramp Python Client

`tracetramp-client` is a drop-in Python wrapper for TraceTramp's cage URL.

## Install

```bash
pip install -e plugins/tracetramp-client-py
```

## Quick start

```python
from tracetramp_client import TraceTrampClient

client = TraceTrampClient(
    cage_base_url="http://localhost:9741",
    api_key="cpk_lab_your_key",
)

resp = client.chat_completions(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "hello from python"}],
)

print(resp["choices"][0]["message"]["content"])
print("trace_id", client.last_headers.get("X-Trace-Id"))
print("cost_usd", client.last_headers.get("X-Cost-USD"))
```

## Environment-based setup

```python
from tracetramp_client import from_env

client = from_env()
```

Expected env vars:

- `OPENAI_BASE_URL` (default: `http://localhost:9741`)
- `OPENAI_API_KEY` (required)

## Notes

- This uses OpenAI-compatible path `/v1/chat/completions`.
- Cage routing is done by TraceTramp using your key and policy context.

# 42 — Builder: Tool Bridge and MCP Integration

> Expose any tool, API, or function as a governed tool callable by agents.

---

## The Tool Bridge Architecture

```
Agent (Ring 5)
    │ request: invoke tool X with args Y
    │
    ▼ Ring 7: Tool Execution
       ├── Allowlist check
       ├── Schema validation
       ├── Namespace policy check
       ├── Budget check
       ▼
    Tool Bridge
       ├── governence receipt generated
       ├── MCP call dispatched
       ▼
    Your Tool / MCP Server / API
       │
       ▼ result
    Tool Bridge
       ├── Receipt chained
       ├── Evidence stored
       ▼
    Agent (result returned)
```

---

## Option 1: Register a Python Function as a Tool

```python
# Define your tool
def get_weather(city: str) -> dict:
    """Fetch current weather for a city."""
    import requests
    resp = requests.get(f"https://wttr.in/{city}?format=j1")
    return {"city": city, "temp_c": resp.json()["current_condition"][0]["temp_C"]}

# Register with Connector
p.mcp_register_bridge(
    bridge_id="weather-bridge",
    url="http://localhost:8081/mcp",     # your local MCP server
    tools=["get_weather"]
)

# Invoke through Connector (governed)
result = p.mcp_invoke_tool(
    "weather-bridge",
    "get_weather",
    pid,
    tool_input={"city": "London"}
)
print(result)
```

---

## Option 2: Launch an MCP Server

A minimal MCP server in Python:

```python
# tools/weather_server.py
from fastapi import FastAPI
from pydantic import BaseModel
import requests, uvicorn

app = FastAPI()

class InvokeRequest(BaseModel):
    tool: str
    input: dict
    agent_pid: str

@app.post("/mcp/invoke")
async def invoke(req: InvokeRequest):
    if req.tool == "get_weather":
        city = req.input.get("city", "London")
        resp = requests.get(f"https://wttr.in/{city}?format=j1")
        data = resp.json()
        return {
            "result": {
                "city":   city,
                "temp_c": data["current_condition"][0]["temp_C"],
                "desc":   data["current_condition"][0]["weatherDesc"][0]["value"]
            },
            "ok": True
        }
    return {"error": f"Unknown tool: {req.tool}"}

@app.get("/mcp/tools")
async def list_tools():
    return {"tools": ["get_weather"]}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8081)
```

Start it:
```bash
python tools/weather_server.py &
```

---

## Option 3: `tools.yaml` Configuration

```yaml
# tools.yaml
tools:
  - name: get_weather
    description: "Get current weather for a city"
    bridge: weather-bridge
    parameters:
      city:
        type: string
        description: "City name"
        min_length: 2
        max_length: 100
    required: [city]
    returns:
      type: object
      properties:
        temp_c: {type: number}
        desc:   {type: string}
    allowed_namespaces: [/m/]
    required_clearance: 1
    audit: true
    rate_limit: 60_per_minute

  - name: read_file
    description: "Read a file from the allowed path"
    bridge: filesystem-bridge
    parameters:
      path:
        type: string
        pattern: "^/data/shared/.*"    # path restriction
    required: [path]
    allowed_namespaces: [/m/, /k/]
    required_clearance: 2
    audit: true

  - name: run_sql
    description: "Execute a read-only SQL query"
    bridge: database-bridge
    parameters:
      query:
        type: string
        max_length: 2000
      table:
        type: string
        enum: [public_data, summaries, reports]   # table allowlist
    required: [query, table]
    required_clearance: 3
    audit: true
    dry_run_available: true
```

---

## Governed Tool Invocation

```python
# The agent invokes — Connector governs
result = p.mcp_invoke_tool(
    bridge_id="weather-bridge",
    tool="get_weather",
    agent_pid=pid,
    tool_input={"city": "Paris"}
)

# Result includes governance fields
print(result["result"])          # the tool's return value
print(result.get("receipt_id"))  # unique receipt for this call
print(result.get("audit_cid"))   # journal entry CID
```

---

## Adding Schema Validation

```python
import jsonschema

WEATHER_SCHEMA = {
    "type": "object",
    "properties": {
        "city": {"type": "string", "minLength": 2, "maxLength": 100}
    },
    "required": ["city"],
    "additionalProperties": False
}

def validated_invoke(pid, tool, input_data, schema):
    """Validate schema before governed tool call."""
    try:
        jsonschema.validate(input_data, schema)
    except jsonschema.ValidationError as e:
        p.record_decision(pid, f"tool.schema_violation.{tool}",
                          tool, "denied", rationale=str(e))
        raise

    return p.mcp_invoke_tool("weather-bridge", tool, pid, tool_input=input_data)
```

---

## Tool Call Receipts

Every tool call generates a receipt:

```json
{
  "receipt_id":   "rec_abc123",
  "tool":         "get_weather",
  "bridge_id":    "weather-bridge",
  "agent_pid":    "agent_xxx",
  "input_hash":   "sha256:...",
  "output_hash":  "sha256:...",
  "prev_receipt": "rec_abc122",
  "timestamp":    "2026-04-16T09:00:00Z",
  "signature":    "ed25519:...",
  "audit_cid":    "mem1-sha256-..."
}
```

Receipts are chained — the `prev_receipt` field creates a linked list of all tool calls for the session.

---

## Dry-Run Mode

For destructive tools, add dry-run support:

```python
# In your MCP server:
@app.post("/mcp/invoke")
async def invoke(req: InvokeRequest):
    if req.input.get("dry_run"):
        # Return the plan without executing
        return {
            "plan":    ["Step 1: validate", "Step 2: execute"],
            "dry_run": True,
            "ok":      True
        }
    # ... actual execution

# Call with dry-run
plan = p.mcp_invoke_tool("ops-bridge", "deploy", pid,
                         tool_input={"service": "api", "dry_run": True})
print(f"Plan: {plan.get('plan')}")

# If plan looks good, execute
result = p.mcp_invoke_tool("ops-bridge", "deploy", pid,
                           tool_input={"service": "api"})
```

---

## Tool Allowlist Enforcement

An agent with a restricted tool allowlist cannot call other tools:

```python
# Test allowlist enforcement
result = p.mcp_invoke_tool("ops-bridge", "restart_node", pid, {})
# Returns error if "restart_node" is not in agent's allowlist:
# {"error": "Tool 'restart_node' not in agent allowlist"}
```

---

## Next Steps

- **[18 — Ring 7: Tool Execution](18-ring-7-tool-execution.md)**
- **[43 — Builder: Memory Extensions](43-builder-memory-extensions.md)**
- **[47 — Builder: Real Execution Control](47-builder-real-execution-control.md)**

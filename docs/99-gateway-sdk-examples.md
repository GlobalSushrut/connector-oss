# 99 — Gateway SDK Examples

Use Connector as an OpenAI-compatible gateway:

```text
http://localhost:9091/v1
```

Set once:

```bash
export OPENAI_BASE_URL=http://localhost:9091/v1
export OPENAI_API_KEY=dev-token
```

## OpenAI SDK

```python
from openai import OpenAI

client = OpenAI(base_url="http://localhost:9091/v1", api_key="dev-token")
resp = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "hello from connector"}],
)
print(resp.choices[0].message.content)
```

## LangChain

```python
from langchain_openai import ChatOpenAI

llm = ChatOpenAI(
    model="gpt-4o-mini",
    base_url="http://localhost:9091/v1",
    api_key="dev-token",
)
print(llm.invoke("Summarize Connector in one line").content)
```

## LangGraph

```python
from langchain_openai import ChatOpenAI
from langgraph.graph import StateGraph, START, END
from typing import TypedDict

class State(TypedDict):
    prompt: str
    answer: str

llm = ChatOpenAI(model="gpt-4o-mini", base_url="http://localhost:9091/v1", api_key="dev-token")

def run_node(state: State):
    out = llm.invoke(state["prompt"])
    return {"answer": out.content}

g = StateGraph(State)
g.add_node("run", run_node)
g.add_edge(START, "run")
g.add_edge("run", END)
app = g.compile()
print(app.invoke({"prompt": "Give one compliance benefit of Connector"})["answer"])
```

## CrewAI

```python
from crewai import Agent, Task, Crew, Process
from langchain_openai import ChatOpenAI

llm = ChatOpenAI(model="gpt-4o-mini", base_url="http://localhost:9091/v1", api_key="dev-token")
agent = Agent(role="Analyst", goal="Produce one-line answer", backstory="Fast and concise", llm=llm)
task = Task(description="Explain Connector gateway in one line.", expected_output="Single sentence.", agent=agent)
crew = Crew(agents=[agent], tasks=[task], process=Process.sequential)
print(crew.kickoff())
```

## Cell SDK (no framework)

A matrix cell is `I` + three sockets. Do not `pip install` a Connector graph library.
Runnable copy: [`docs/cell_sdk.py`](cell_sdk.py) (`python3 docs/cell_sdk.py`).

```python
import json, os, urllib.request

BASE = os.environ.get("CONNECTOR_URL", "http://localhost:9091")
TOKEN = os.environ.get("OPENAI_API_KEY", "dev-token")
I = os.environ["CONNECTOR_AGENT_PID"]  # chartered intelligence, not a Linux PID

def post(path, body, extra=None):
    req = urllib.request.Request(
        BASE + path,
        data=json.dumps(body).encode(),
        headers={"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json", **(extra or {})},
        method="POST",
    )
    with urllib.request.urlopen(req) as r:
        return json.load(r)

# 1. Thinker socket (LangGraph/Crew/scripts use this same URL)
os.environ.setdefault("OPENAI_BASE_URL", BASE + "/v1")
think = post("/v1/chat/completions", {
    "model": "gpt-4o-mini",
    "messages": [{"role": "user", "content": "who am I"}],
})
print(think["choices"][0]["message"]["content"])

# 2. Syscall socket (WM — charter-gated)
wm = post("/api/v1/kernel/syscall", {
    "agent_pid": I,
    "op": "wm.retrieve",
    "args": {"query": "who am I", "limit": 4},
}, extra={"X-Connector-Agent-Pid": I})
print(wm.get("hits") or wm)

# 3. Council (root mints; this I speaks as itself — μ on the floor)
# post(f"/api/v1/intelligence/council/{COUNCIL}/speak",
#      {"from_I": I, "to": "floor", "body": "hello shop"},
#      extra={"X-Connector-Agent-Pid": I})

# 4. Stop this I (VJ)
# post(f"/api/v1/agents/{I}/kill-switch", {})
```

Compensate (operator, not the cell): `POST /api/v1/kernel/aios/operate` `op=compensate` with `grant_address` / `portal_id` / `deny_tool` + root passcode.

## Validation checklist

- Run `make run-local`
- Run `connectorctl quickstart`
- Execute one snippet above
- Confirm activity: `connectorctl trace agent <agent-id>`

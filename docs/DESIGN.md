# 🔌 Connector Platform — Integration Design & Output Standards

**Date:** March 2026
**Research basis:** AWS Bedrock AgentCore, Azure AI Content Safety, Google Vertex AI, OpenTelemetry GenAI Semantic Conventions, CloudEvents v1.0, OCSF, LangSmith, Langfuse, Arize Phoenix, Datadog LLM Observability, Helicone, Splunk SIEM

---

## 📐 Core Design Principle

> **"Meet developers where they are. Emit what enterprises already consume."**

Customers use their own:
- **Frameworks** (LangChain, CrewAI, AutoGen, OpenAI Agents SDK, Haystack, LlamaIndex)
- **LLM providers** (OpenAI, Anthropic, DeepSeek, local models via Ollama/vLLM)
- **Observability stacks** (Datadog, Grafana, Splunk, Elastic, New Relic)
- **Cloud platforms** (AWS, Azure, GCP, bare metal)
- **Security tools** (Splunk SIEM, AWS Security Lake, Sentinel)

We don't replace any of these. We **plug into all of them**.

---

## 🌍 Integration Architecture Overview

```
┌──────────────────────────────────────────────────────────────────────────┐
│                     CUSTOMER'S EXISTING STACK                            │
│                                                                          │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │
│  │ LangChain   │  │ CrewAI       │  │ AutoGen      │  │ OpenAI SDK   │ │
│  │ LangGraph   │  │              │  │              │  │ Agents SDK   │ │
│  └──────┬──────┘  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘ │
│         │                │                  │                 │          │
│         ▼                ▼                  ▼                 ▼          │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │              CONNECTOR INTEGRATION LAYER                         │   │
│  │                                                                  │   │
│  │  ┌────────────────────────────────────────────────────────────┐  │   │
│  │  │  Framework Connectors (SDK-side, runs in customer's code)  │  │   │
│  │  │                                                            │  │   │
│  │  │  • LangChainHandler     — CallbackHandler                  │  │   │
│  │  │  • CrewAIObserver       — OpenTelemetry bridge              │  │   │
│  │  │  • AutoGenTracer        — Event handler                    │  │   │
│  │  │  • OpenAIAgentsHook     — Trace interceptor                │  │   │
│  │  │  • GenericDecorator     — @connector.observe()             │  │   │
│  │  │  • OTelExporter         — OTLP span exporter               │  │   │
│  │  └────────────────────────────────────────────────────────────┘  │   │
│  │                           │                                      │   │
│  │                           ▼                                      │   │
│  │  ┌────────────────────────────────────────────────────────────┐  │   │
│  │  │  Connector Platform (self-hosted binary)                   │  │   │
│  │  │                                                            │  │   │
│  │  │  Ingest: REST API / OTLP / gRPC / WebSocket               │  │   │
│  │  │  Process: Kernel + Trust + Audit + Knowledge               │  │   │
│  │  │  Store: SQLite / Postgres (customer's disk)                │  │   │
│  │  └────────────────────────────────────────────────────────────┘  │   │
│  │                           │                                      │   │
│  │                           ▼                                      │   │
│  │  ┌────────────────────────────────────────────────────────────┐  │   │
│  │  │  Output Adapters (emit to customer's existing tools)       │  │   │
│  │  │                                                            │  │   │
│  │  │  • OpenTelemetry OTLP  → Datadog, Grafana, Jaeger, Zipkin │  │   │
│  │  │  • Prometheus /metrics → Grafana, AlertManager             │  │   │
│  │  │  • CloudEvents         → AWS EventBridge, Azure Event Grid │  │   │
│  │  │  • OCSF events         → Splunk, AWS Security Lake         │  │   │
│  │  │  • Webhook POST        → Slack, PagerDuty, Teams, custom   │  │   │
│  │  │  • Syslog (RFC 5424)   → Any SIEM                         │  │   │
│  │  │  • S3/GCS/Blob export  → Data lake                        │  │   │
│  │  │  • PDF/HTML reports    → Management, legal, compliance     │  │   │
│  │  │  • CSV/Parquet         → BI tools, data teams              │  │   │
│  │  └────────────────────────────────────────────────────────────┘  │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │
│  │ Datadog      │  │ Grafana      │  │ Splunk       │  │ Slack        │ │
│  │ New Relic    │  │ Prometheus   │  │ Elastic      │  │ PagerDuty    │ │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘ │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## 🔗 Part 1: Framework Connectors — How Users Plug In

### The 3 Integration Methods (matching industry standard)

Based on research of Langfuse, LangSmith, Arize Phoenix, Helicone, and Datadog:

| Method | Setup Time | Depth | Best For |
|--------|-----------|-------|----------|
| **Decorator** `@connector.observe()` | 5 min | Medium | Any Python code |
| **Framework callback** | 15 min | Deep | LangChain, CrewAI, AutoGen |
| **OpenTelemetry exporter** | 30 min | Maximum | Any language, any framework |

---

### Method 1: Python Decorator (simplest)

Works with ANY Python code. No framework dependency.

```python
from connector import Connector, observe

c = Connector.from_config("connector.yaml")

@observe(connector=c, agent="research-bot")
def analyze(query: str) -> str:
    # Your existing code — LangChain, CrewAI, raw OpenAI, anything
    response = openai.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": query}]
    )
    return response.choices[0].message.content

# Every call is now:
# ✅ Memory-recorded (CID-addressed)
# ✅ Audit-logged (Ed25519 + HMAC chain)
# ✅ Trust-scored (5-dimension kernel verification)
# ✅ Cost-tracked (tokens, latency, model)
result = analyze("What causes inflation?")
```

**Implementation:** Python decorator wraps any function, intercepts input/output, writes to kernel via existing `memory_write()` + `record_action()` + `log_interaction()` APIs.

```python
# connector/integrations/decorator.py (~150 LOC)

import functools, time
from connector import Connector

def observe(connector: Connector, agent: str, pipeline: str = "default"):
    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            pid = connector.register_agent(agent)
            session = connector.create_session(pid, label=fn.__name__)

            # Record input
            input_str = str(args) + str(kwargs)
            input_cid = connector.memory_write(
                pid, input_str, "system", pipeline, "input", session
            )

            # Execute original function
            start = time.time()
            try:
                result = fn(*args, **kwargs)
                duration_ms = int((time.time() - start) * 1000)

                # Record output
                output_cid = connector.memory_write(
                    pid, str(result), "system", pipeline, "llm_raw", session
                )

                # Log interaction
                connector.log_interaction(
                    pid, "llm", fn.__name__, "invoke",
                    "success", duration_ms
                )

                return result

            except Exception as e:
                connector.log_interaction(
                    pid, "llm", fn.__name__, "invoke",
                    "error", int((time.time() - start) * 1000)
                )
                raise
        return wrapper
    return decorator
```

---

### Method 2: Framework Callbacks

#### LangChain / LangGraph

```python
from connector.integrations.langchain import ConnectorCallbackHandler

handler = ConnectorCallbackHandler(
    connector=c,
    agent="langchain-agent",
    track_tokens=True,
    track_cost=True,
)

# Drop into any LangChain call
chain = prompt | llm | parser
result = chain.invoke({"input": "..."}, config={"callbacks": [handler]})

# Or with LangGraph
app = graph.compile()
result = app.invoke({"messages": [...]}, config={"callbacks": [handler]})
```

**Implementation:** Implements LangChain's `BaseCallbackHandler`:

```python
# connector/integrations/langchain.py (~250 LOC)

from langchain_core.callbacks import BaseCallbackHandler

class ConnectorCallbackHandler(BaseCallbackHandler):
    """Pipes LangChain events into Connector kernel."""

    def on_llm_start(self, serialized, prompts, **kwargs):
        # memory_write(input) + log_interaction(start)

    def on_llm_end(self, response, **kwargs):
        # memory_write(llm_raw) + log_interaction(complete)
        # Extract tokens, cost from response.llm_output

    def on_tool_start(self, serialized, input_str, **kwargs):
        # record_action(intent=tool_name) + authorize_tool()

    def on_tool_end(self, output, **kwargs):
        # memory_write(tool_result) + log_interaction()

    def on_chain_start(self, serialized, inputs, **kwargs):
        # create_session() for this chain

    def on_chain_end(self, outputs, **kwargs):
        # close_session() + trust_breakdown()

    def on_chain_error(self, error, **kwargs):
        # record_action(outcome="error") + log_interaction(status="error")
```

#### CrewAI

```python
from connector.integrations.crewai import ConnectorCrewObserver

observer = ConnectorCrewObserver(connector=c)

crew = Crew(
    agents=[researcher, writer],
    tasks=[research_task, write_task],
    verbose=True,
)

# CrewAI uses OpenTelemetry — we bridge it
with observer.trace(crew):
    result = crew.kickoff()

# Every agent step → kernel memory
# Every tool call → audit trail
# Task completion → trust score
```

#### AutoGen

```python
from connector.integrations.autogen import ConnectorAutoGenHandler

handler = ConnectorAutoGenHandler(connector=c)

assistant = autogen.AssistantAgent("assistant", llm_config={...})
user_proxy = autogen.UserProxyAgent("user")

# Register handler on agents
handler.register(assistant)
handler.register(user_proxy)

result = user_proxy.initiate_chat(assistant, message="...")
```

#### OpenAI Agents SDK

```python
from connector.integrations.openai_agents import ConnectorAgentsTracer

tracer = ConnectorAgentsTracer(connector=c)

from openai import Agent, Runner

agent = Agent(name="assistant", instructions="...")
with tracer.trace():
    result = Runner.run_sync(agent, "Hello")
```

---

### Method 3: OpenTelemetry (any language, any framework)

For teams already using OTel, or non-Python stacks.

```python
# Python example
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from connector.integrations.otel import ConnectorSpanExporter

exporter = ConnectorSpanExporter(endpoint="http://localhost:9090")
processor = BatchSpanProcessor(exporter)
provider.add_span_processor(processor)

# Now ANY OTel-instrumented code flows into Connector
```

```typescript
// TypeScript/Node.js example
import { ConnectorSpanExporter } from '@connector-oss/otel';

const exporter = new ConnectorSpanExporter({
  endpoint: 'http://localhost:9090',
});
```

```go
// Go example
import "github.com/connector-oss/otel-go"

exporter := connector.NewSpanExporter("http://localhost:9090")
```

**Why this matters:** OpenTelemetry GenAI Semantic Conventions are THE emerging standard. Every major framework (LangChain, CrewAI, Haystack) is adopting OTel. By accepting OTLP, we work with everything, forever, in any language.

---

### Integration Summary Table

| Framework | Method | Setup | What Gets Captured |
|-----------|--------|-------|-------------------|
| **LangChain/LangGraph** | CallbackHandler | 15 min | LLM calls, tool calls, chains, tokens, cost |
| **CrewAI** | OTel bridge | 15 min | Agent steps, tasks, tool calls, delegation |
| **AutoGen** | Event handler | 15 min | Agent messages, tool calls, group chat |
| **OpenAI Agents SDK** | Trace hook | 15 min | Agent runs, tool calls, handoffs |
| **Haystack** | Pipeline hook | 15 min | Pipeline components, retrieval, generation |
| **LlamaIndex** | Callback manager | 15 min | Query engine, retrieval, synthesis |
| **Raw Python** | `@observe()` | 5 min | Any function input/output |
| **Any language** | OTLP exporter | 30 min | Any OTel-instrumented code |
| **REST API** | HTTP POST | 5 min | Manual event recording |

---

## 📤 Part 2: Output Standards — Matching AWS/Azure/GCP

### The Problem

When a CTO evaluates us, they compare our output to:
- AWS Bedrock AgentCore's governance traces
- Azure AI Content Safety's monitoring dashboard
- Google Vertex AI's audit logs
- Datadog LLM Observability's traces
- Splunk's SIEM events

If our output doesn't fit their existing tools, they won't buy. Period.

### Our Output Format Strategy

```
Connector Kernel
      │
      ▼
  ┌─────────────────────┐
  │  Canonical Internal  │   ← Our format (CID + MemPacket + AuditEntry)
  │  Format (rich)       │
  └──────────┬──────────┘
             │
    ┌────────┼────────┬──────────┬──────────┬──────────┐
    ▼        ▼        ▼          ▼          ▼          ▼
  OTel    Cloud    OCSF      Prometheus  Webhook    Report
  OTLP    Events   Events    Metrics     Events     PDF/HTML
```

We store rich. We emit standard.

---

### Output Format 1: OpenTelemetry (OTel GenAI Semantic Conventions)

**Who consumes it:** Datadog, Grafana Tempo, Jaeger, Zipkin, Honeycomb, New Relic, Arize

**Standard:** [OpenTelemetry GenAI Semantic Conventions](https://opentelemetry.io/docs/specs/semconv/gen-ai/) (CNCF)

```json
{
  "resourceSpans": [{
    "resource": {
      "attributes": [
        {"key": "service.name", "value": {"stringValue": "connector-platform"}},
        {"key": "service.version", "value": {"stringValue": "1.0.0"}}
      ]
    },
    "scopeSpans": [{
      "spans": [{
        "traceId": "abc123...",
        "spanId": "def456...",
        "name": "chat deepseek-chat",
        "kind": "SPAN_KIND_CLIENT",
        "startTimeUnixNano": "1709312580000000000",
        "endTimeUnixNano": "1709312581200000000",
        "attributes": [
          {"key": "gen_ai.operation.name", "value": {"stringValue": "chat"}},
          {"key": "gen_ai.provider.name", "value": {"stringValue": "deepseek"}},
          {"key": "gen_ai.request.model", "value": {"stringValue": "deepseek-chat"}},
          {"key": "gen_ai.request.temperature", "value": {"doubleValue": 0.7}},
          {"key": "gen_ai.request.max_tokens", "value": {"intValue": 4096}},
          {"key": "gen_ai.response.finish_reasons", "value": {"arrayValue": {"values": [{"stringValue": "stop"}]}}},
          {"key": "gen_ai.usage.input_tokens", "value": {"intValue": 248}},
          {"key": "gen_ai.usage.output_tokens", "value": {"intValue": 412}},

          {"key": "connector.trust.score", "value": {"intValue": 80}},
          {"key": "connector.trust.grade", "value": {"stringValue": "B+"}},
          {"key": "connector.audit.count", "value": {"intValue": 12}},
          {"key": "connector.cid.input", "value": {"stringValue": "bafy...a8f3"}},
          {"key": "connector.cid.output", "value": {"stringValue": "bafy...k7q2"}},
          {"key": "connector.integrity.verified", "value": {"boolValue": true}}
        ],
        "events": [
          {
            "name": "gen_ai.content.prompt",
            "attributes": [
              {"key": "gen_ai.prompt", "value": {"stringValue": "Diagnose patient..."}}
            ]
          },
          {
            "name": "gen_ai.content.completion",
            "attributes": [
              {"key": "gen_ai.completion", "value": {"stringValue": "Based on symptoms..."}}
            ]
          },
          {
            "name": "connector.trust.computed",
            "attributes": [
              {"key": "connector.trust.memory_integrity", "value": {"intValue": 20}},
              {"key": "connector.trust.audit_completeness", "value": {"intValue": 20}},
              {"key": "connector.trust.authorization_coverage", "value": {"intValue": 0}},
              {"key": "connector.trust.decision_provenance", "value": {"intValue": 20}},
              {"key": "connector.trust.operational_health", "value": {"intValue": 20}}
            ]
          }
        ]
      }]
    }]
  }]
}
```

**Server-side implementation:**

```
GET  /api/v1/export/otlp/traces    → OTLP JSON traces (batch export)
POST /v1/traces                    → OTLP receiver (ingest from customer's OTel pipeline)
```

**Comparison with competitors:**

| Feature | AWS Bedrock | Datadog LLM | Langfuse | **Connector** |
|---------|------------|-------------|----------|--------------|
| OTel GenAI spans | ❌ (CloudWatch) | ✅ | ✅ | ✅ |
| Trust score per span | ❌ | ❌ | ❌ | ✅ **unique** |
| CID per span | ❌ | ❌ | ❌ | ✅ **unique** |
| Integrity verification | ❌ | ❌ | ❌ | ✅ **unique** |
| Tool call tracing | ✅ | ✅ | ✅ | ✅ |
| Token/cost tracking | ✅ | ✅ | ✅ | ✅ |

---

### Output Format 2: CloudEvents v1.0

**Who consumes it:** AWS EventBridge, Azure Event Grid, Google Eventarc, any event-driven architecture

**Standard:** [CloudEvents v1.0](https://cloudevents.io/) (CNCF Graduated)

```json
{
  "specversion": "1.0",
  "id": "evt_8a3f2c4d",
  "source": "connector-platform/agent/doctor",
  "type": "ai.connector.decision.made",
  "time": "2026-03-01T14:22:00Z",
  "datacontenttype": "application/json",
  "subject": "patient:42",
  "data": {
    "agent_pid": "pid:000002",
    "action": "prescribe",
    "target": "patient:42",
    "outcome": "success",
    "confidence": 0.92,
    "trust_score": 80,
    "trust_grade": "B+",
    "input_cid": "bafy...a8f3",
    "output_cid": "bafy...k7q2",
    "audit_chain_verified": true,
    "evidence": ["bafy...c2d1", "bafy...e4f5"],
    "regulations": ["hipaa"],
    "duration_ms": 1200,
    "tokens": {"input": 248, "output": 412},
    "cost_usd": 0.004
  }
}
```

**Event types we emit:**

| CloudEvent Type | When | Data |
|----------------|------|------|
| `ai.connector.agent.registered` | Agent created | pid, name, model |
| `ai.connector.agent.terminated` | Agent stopped | pid, reason |
| `ai.connector.decision.made` | Action recorded | action, outcome, evidence, trust |
| `ai.connector.memory.written` | Memory created | cid, type, namespace |
| `ai.connector.trust.changed` | Trust score shift | old_score, new_score, reason |
| `ai.connector.policy.violated` | Policy denied | action, rule, agent |
| `ai.connector.integrity.failed` | Integrity check fail | error_count, details |
| `ai.connector.budget.exceeded` | Budget limit hit | agent, resource, limit |
| `ai.connector.capability.issued` | Capability token created | issuer, subject, actions |
| `ai.connector.session.closed` | Session ended | session_id, packets, duration |

**Server-side implementation:**

```
GET  /api/v1/export/cloudevents     → Batch export as CloudEvents array
POST /api/v1/webhooks               → Configure where to push CloudEvents
```

---

### Output Format 3: OCSF (Open Cybersecurity Schema Framework)

**Who consumes it:** Splunk, AWS Security Lake, Datadog Cloud SIEM, Microsoft Sentinel

**Standard:** [OCSF 1.1](https://ocsf.io/) — the format AWS Security Lake uses natively

```json
{
  "class_uid": 3001,
  "class_name": "API Activity",
  "category_uid": 3,
  "category_name": "Audit Activity",
  "severity_id": 1,
  "severity": "Informational",
  "activity_id": 1,
  "activity_name": "Create",
  "time": 1709312580000,
  "message": "Agent 'doctor' made decision: prescribe aspirin for patient:42",
  "actor": {
    "user": {"name": "agent:doctor", "uid": "pid:000002", "type": "Service"},
    "session": {"uid": "sess_a8f3c2"}
  },
  "api": {
    "operation": "record_action",
    "service": {"name": "connector-platform"},
    "request": {
      "uid": "bafy...a8f3"
    },
    "response": {
      "code": 200
    }
  },
  "resources": [
    {"uid": "patient:42", "type": "Patient Record"}
  ],
  "metadata": {
    "version": "1.1.0",
    "product": {"name": "Connector Platform", "vendor_name": "Connector OSS"},
    "log_name": "ai_decision_audit"
  },
  "unmapped": {
    "connector.trust_score": 80,
    "connector.cid": "bafy...k7q2",
    "connector.integrity_verified": true,
    "connector.regulations": ["hipaa"]
  }
}
```

**Why this matters:** Any company already using Splunk or AWS Security Lake can ingest our audit trail without ANY custom parsing. Their existing SIEM dashboards, alerts, and compliance reports just work.

---

### Output Format 4: Prometheus Metrics

**Who consumes it:** Grafana, AlertManager, Prometheus, Thanos

**Endpoint:** `GET /metrics` (Prometheus exposition format)

```prometheus
# HELP connector_trust_score Current kernel trust score
# TYPE connector_trust_score gauge
connector_trust_score{grade="B+"} 80

# HELP connector_trust_dimension Trust score breakdown by dimension
# TYPE connector_trust_dimension gauge
connector_trust_dimension{dimension="memory_integrity"} 20
connector_trust_dimension{dimension="audit_completeness"} 20
connector_trust_dimension{dimension="authorization_coverage"} 0
connector_trust_dimension{dimension="decision_provenance"} 20
connector_trust_dimension{dimension="operational_health"} 20

# HELP connector_packets_total Total memory packets
# TYPE connector_packets_total counter
connector_packets_total 1247

# HELP connector_audit_entries_total Total audit entries
# TYPE connector_audit_entries_total counter
connector_audit_entries_total 3891

# HELP connector_agents_active Currently active agents
# TYPE connector_agents_active gauge
connector_agents_active 4

# HELP connector_denied_total Total denied operations
# TYPE connector_denied_total counter
connector_denied_total 3

# HELP connector_llm_duration_seconds LLM call duration
# TYPE connector_llm_duration_seconds histogram
connector_llm_duration_seconds_bucket{model="deepseek-chat",le="0.5"} 42
connector_llm_duration_seconds_bucket{model="deepseek-chat",le="1.0"} 89
connector_llm_duration_seconds_bucket{model="deepseek-chat",le="2.0"} 97

# HELP connector_llm_tokens_total Total LLM tokens consumed
# TYPE connector_llm_tokens_total counter
connector_llm_tokens_total{model="deepseek-chat",direction="input"} 28491
connector_llm_tokens_total{model="deepseek-chat",direction="output"} 41203

# HELP connector_llm_cost_usd_total Total LLM cost in USD
# TYPE connector_llm_cost_usd_total counter
connector_llm_cost_usd_total{model="deepseek-chat"} 0.42

# HELP connector_memory_pressure Current memory pressure (0-1)
# TYPE connector_memory_pressure gauge
connector_memory_pressure 0.23

# HELP connector_integrity_check_passed Last integrity check result
# TYPE connector_integrity_check_passed gauge
connector_integrity_check_passed 1
```

**Grafana dashboard import:** We ship a pre-built Grafana dashboard JSON that customers import in 1 click.

---

### Output Format 5: Webhook Events (Slack, PagerDuty, Teams, Custom)

```json
// POST to customer's webhook URL

// Slack format
{
  "text": "🔴 *Connector Alert: Trust Drop*\nTrust score fell from 80 → 45\nAgent: rogue-bot (pid:000005)\nReason: 3 denied operations in 5 minutes\nAction: Agent auto-suspended",
  "blocks": [
    {
      "type": "section",
      "text": {
        "type": "mrkdwn",
        "text": "🔴 *Trust Score Alert*\n`80 → 45` in 5 minutes"
      }
    }
  ]
}

// PagerDuty format
{
  "routing_key": "xxx",
  "event_action": "trigger",
  "payload": {
    "summary": "Connector: Trust score dropped to 45 — agent rogue-bot suspended",
    "severity": "warning",
    "source": "connector-platform",
    "component": "trust-monitor",
    "custom_details": {
      "trust_score": 45,
      "previous_score": 80,
      "agent": "rogue-bot",
      "denied_count": 3
    }
  }
}

// Generic webhook (works with anything)
{
  "event": "trust.threshold_breached",
  "timestamp": "2026-03-01T14:22:00Z",
  "severity": "warning",
  "data": {
    "trust_score": 45,
    "agent_pid": "pid:000005",
    "reason": "3 denied operations"
  }
}
```

**Configurable alert rules:**

```yaml
# connector.yaml
alerts:
  - name: trust-drop
    condition: trust_score < 60
    channels: [slack, pagerduty]
    cooldown: 5m

  - name: denied-spike
    condition: denied_count > 5 per 1h
    channels: [slack]
    cooldown: 15m

  - name: integrity-failure
    condition: integrity_check == false
    channels: [pagerduty, email]
    cooldown: 0  # immediate, no cooldown

  - name: budget-exceeded
    condition: budget_remaining < 0
    channels: [slack]
    cooldown: 1h
```

---

### Output Format 6: Compliance Reports (PDF/HTML)

**Who consumes it:** Auditors, legal teams, management, customers in disputes

```html
<!-- Connector AI Decision Report -->
<!-- Generated: 2026-03-01T14:30:00Z -->

┌────────────────────────────────────────────────┐
│  CONNECTOR AI DECISION AUDIT REPORT            │
│  Report ID: rpt_8a3f2c4d                       │
│  Generated: 2026-03-01T14:30:00Z               │
│  Period: 2026-03-01 08:00 – 14:30 UTC          │
├────────────────────────────────────────────────┤
│                                                │
│  EXECUTIVE SUMMARY                             │
│  Total decisions: 142                          │
│  Trust score: 80/100 (Grade B+)                │
│  Integrity: ✅ All chains verified              │
│  Denied operations: 3 (2.1%)                   │
│  Compliance frameworks: HIPAA, SOC 2           │
│                                                │
│  TRUST BREAKDOWN                               │
│  Memory Integrity      20/20  ██████████       │
│  Audit Completeness    20/20  ██████████       │
│  Authorization Cov.     0/20  ░░░░░░░░░░       │
│  Decision Provenance   20/20  ██████████       │
│  Operational Health    20/20  ██████████       │
│                                                │
│  DECISION LOG (last 20)                        │
│  #  Time   Agent    Action    Outcome  CID     │
│  1  08:01  doctor   diagnose  ✅       bafy..  │
│  2  08:03  nurse    vitals    ✅       bafy..  │
│  3  08:05  rogue    read      ❌ DENY  bafy..  │
│  ...                                           │
│                                                │
│  EVIDENCE CHAIN                                │
│  All 142 decisions have:                       │
│  ✅ CID content hash (CIDv1, SHA2-256)         │
│  ✅ HMAC chain verification                    │
│  ✅ Ed25519 signatures                         │
│  ✅ Timestamp provenance                       │
│                                                │
│  CRYPTOGRAPHIC VERIFICATION                    │
│  To independently verify any decision:         │
│  $ connector verify bafy...k7q2                │
│  → CID matches content: ✅                      │
│  → HMAC chain valid: ✅                         │
│  → Audit entry exists: ✅                       │
│                                                │
└────────────────────────────────────────────────┘
```

---

### Output Comparison: Us vs Big 3

| Output Capability | AWS Bedrock | Azure AI | GCP Vertex | **Connector** |
|------------------|------------|----------|------------|--------------|
| **OpenTelemetry traces** | ❌ CloudWatch | ❌ Azure Monitor | ❌ Cloud Logging | ✅ Native OTLP |
| **CloudEvents** | ✅ EventBridge | ✅ Event Grid | ✅ Eventarc | ✅ Native |
| **OCSF for SIEM** | ✅ Security Lake | ❌ | ❌ | ✅ Native |
| **Prometheus metrics** | ❌ | ❌ | ❌ | ✅ /metrics |
| **Webhook alerts** | ✅ SNS | ✅ Logic Apps | ✅ Pub/Sub | ✅ Native |
| **PDF compliance reports** | ❌ | ❌ | ❌ | ✅ **unique** |
| **CID per event** | ❌ | ❌ | ❌ | ✅ **unique** |
| **Trust score per event** | ❌ | ❌ | ❌ | ✅ **unique** |
| **Tamper-proof audit chain** | ❌ | ❌ | ❌ | ✅ **unique** |
| **Self-hosted** | ❌ (cloud only) | ❌ (cloud only) | ❌ (cloud only) | ✅ **unique** |
| **Works offline** | ❌ | ❌ | ❌ | ✅ **unique** |
| **Vendor lock-in** | AWS only | Azure only | GCP only | ✅ **None** |

**Our positioning:** "Everything the big 3 output, plus cryptographic proof, self-hosted, no vendor lock-in."

---

## 🏗️ Part 3: New Crates for Integration & Export

### Crate 1: `connector-integrations` (~1,200 LOC)

Framework connectors that run in customer's Python code.

```
connector/integrations/
├── __init__.py
├── decorator.py          # @observe() — 150 LOC
├── langchain.py          # ConnectorCallbackHandler — 250 LOC
├── crewai.py             # ConnectorCrewObserver — 200 LOC
├── autogen.py            # ConnectorAutoGenHandler — 200 LOC
├── openai_agents.py      # ConnectorAgentsTracer — 150 LOC
├── haystack.py           # ConnectorHaystackHook — 100 LOC
└── llamaindex.py         # ConnectorLlamaIndexCallback — 150 LOC
```

Published as: `pip install connector-agent-oss[langchain]`, `pip install connector-agent-oss[crewai]`, etc.

### Crate 2: `connector-export` (Rust, ~1,500 LOC)

Server-side export adapters.

```
connector/crates/connector-export/
├── Cargo.toml
└── src/
    ├── lib.rs
    ├── otel.rs            # OTel OTLP trace builder — 300 LOC
    ├── cloudevents.rs     # CloudEvents v1.0 builder — 200 LOC
    ├── ocsf.rs            # OCSF event builder — 250 LOC
    ├── prometheus.rs      # Prometheus metrics exposition — 200 LOC
    ├── webhook.rs         # Webhook sender (Slack, PagerDuty, generic) — 200 LOC
    ├── syslog.rs          # RFC 5424 syslog forwarder — 100 LOC
    └── report.rs          # HTML/PDF report generator — 250 LOC
```

### Crate 3: `connector-ingest` (Rust, ~800 LOC)

Server-side ingest from external sources.

```
connector/crates/connector-ingest/
├── Cargo.toml
└── src/
    ├── lib.rs
    ├── otlp_receiver.rs   # Accept OTLP traces and map to kernel — 300 LOC
    ├── rest_ingest.rs     # REST API event ingestion — 200 LOC
    └── cloudevents_in.rs  # Accept CloudEvents and map to kernel — 300 LOC
```

### Total new code for integration layer:

| Component | LOC | Language |
|-----------|-----|---------|
| connector-integrations (Python) | ~1,200 | Python |
| connector-export (Rust) | ~1,500 | Rust |
| connector-ingest (Rust) | ~800 | Rust |
| **Total** | **~3,500** | Mixed |

---

## 🔄 Part 4: How Customer's Full Stack Connects

### Scenario A: LangChain + Datadog team

```
Customer's code (Python)
    │
    │ from connector.integrations.langchain import ConnectorCallbackHandler
    │ handler = ConnectorCallbackHandler(connector=c)
    │ chain.invoke(..., config={"callbacks": [handler]})
    │
    ▼
Connector Platform (:9090)
    │
    ├── Kernel: memory, audit, trust, knowledge
    ├── UI: http://localhost:9090 (debug, monitor, history)
    │
    ├── GET /metrics → Datadog agent scrapes Prometheus metrics
    ├── GET /api/v1/export/otlp/traces → Datadog APM ingests OTel traces
    └── POST webhook → Slack #ai-alerts channel
```

### Scenario B: CrewAI + Grafana team

```
Customer's code (Python)
    │
    │ from connector.integrations.crewai import ConnectorCrewObserver
    │ observer = ConnectorCrewObserver(connector=c)
    │
    ▼
Connector Platform (:9090)
    │
    ├── Kernel: memory, audit, trust, knowledge
    ├── UI: http://localhost:9090
    │
    ├── GET /metrics → Prometheus → Grafana dashboards
    ├── OTLP export → Grafana Tempo (traces)
    └── Grafana Alerting → PagerDuty on trust < 60
```

### Scenario C: AutoGen + Splunk enterprise

```
Customer's code (Python)
    │
    │ from connector.integrations.autogen import ConnectorAutoGenHandler
    │ handler.register(assistant_agent)
    │
    ▼
Connector Platform (:9090)
    │
    ├── Kernel: memory, audit, trust, knowledge
    ├── UI: http://localhost:9090
    │
    ├── OCSF events → Splunk Universal Forwarder → Splunk SIEM
    ├── Syslog (RFC 5424) → Splunk TCP input
    └── PDF reports → compliance team email
```

### Scenario D: Custom Python + bare metal (no observability stack)

```
Customer's code (Python)
    │
    │ from connector import Connector, observe
    │ @observe(connector=c, agent="my-bot")
    │ def my_function(input): ...
    │
    ▼
Connector Platform (:9090)
    │
    ├── Kernel: memory, audit, trust, knowledge
    ├── UI: http://localhost:9090 ← THIS IS THEIR OBSERVABILITY
    └── Webhook → Slack on errors
```

**Key insight:** For teams WITHOUT Datadog/Grafana/Splunk, our built-in UI IS their observability platform. For teams WITH those tools, we emit into their existing stack.

---

## ⚡ Part 5: Ingest API — How External Events Get In

Not all AI work runs through our SDK. Customers need to push events from systems we don't have a connector for.

### REST Ingest API

```
POST /api/v1/ingest/event
Content-Type: application/json

{
  "agent": "my-custom-agent",
  "type": "decision",
  "input": "User asked for refund",
  "output": "Approved refund of $42.00",
  "user": "user:alice",
  "metadata": {
    "model": "gpt-4o",
    "tokens_input": 248,
    "tokens_output": 105,
    "cost_usd": 0.003,
    "duration_ms": 850
  },
  "tags": ["support", "refund"],
  "entities": ["user:alice", "order:8842"],
  "regulations": ["gdpr"]
}

→ Response:
{
  "cid": "bafy...k7q2",
  "trust_score": 80,
  "audit_id": "aud_4f2a",
  "session_id": "sess_a8f3"
}
```

### OTLP Receiver

```
POST /v1/traces
Content-Type: application/x-protobuf

(accepts standard OTLP protobuf or JSON)
→ Maps gen_ai.* attributes to kernel memory packets
→ Returns trust score per trace
```

### CloudEvents Receiver

```
POST /api/v1/ingest/cloudevents
Content-Type: application/cloudevents+json

(accepts CloudEvents v1.0)
→ Maps to kernel memory + audit
```

---

## 🎨 Part 6: UI Integration Points

The UI doesn't just display data — it helps users CONNECT their stack:

### Setup Wizard (first-time experience)

```
┌─────────────────────────────────────────────────────────────┐
│  🚀 Welcome to Connector Platform                          │
│                                                             │
│  Step 1: Your AI Framework                                  │
│  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐   │
│  │LangCh. │ │ CrewAI │ │AutoGen │ │ OpenAI │ │ Custom │   │
│  │  ✅    │ │        │ │        │ │        │ │        │   │
│  └────────┘ └────────┘ └────────┘ └────────┘ └────────┘   │
│                                                             │
│  Step 2: Copy this into your code                           │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ pip install connector-agent-oss[langchain]           │   │
│  │                                                      │   │
│  │ from connector.integrations.langchain import \       │   │
│  │     ConnectorCallbackHandler                         │   │
│  │ handler = ConnectorCallbackHandler(                  │   │
│  │     endpoint="http://localhost:9090"                  │   │
│  │ )                                                    │   │
│  │ chain.invoke(..., config={"callbacks": [handler]})   │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                             │
│  Step 3: Your Observability Stack (optional)                │
│  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐   │
│  │Datadog │ │Grafana │ │Splunk  │ │ None   │ │ Other  │   │
│  │        │ │        │ │        │ │  ✅    │ │        │   │
│  └────────┘ └────────┘ └────────┘ └────────┘ └────────┘   │
│                                                             │
│  Step 4: Alert Channels (optional)                          │
│  ☐ Slack webhook: https://hooks.slack.com/...               │
│  ☐ PagerDuty key: _______________                           │
│  ☐ Email: team@company.com                                  │
│                                                             │
│  [Start Monitoring →]                                       │
└─────────────────────────────────────────────────────────────┘
```

### Integration Status Dashboard

```
┌─────────────────────────────────────────────────────────────┐
│  🔌 Integrations                                            │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  INGEST (data coming in)                                    │
│  ✅ LangChain callback   — 142 events today                │
│  ✅ REST API ingest      — 38 events today                 │
│  ⚪ OTLP receiver        — not configured                  │
│                                                             │
│  EXPORT (data going out)                                    │
│  ✅ Prometheus /metrics  — Grafana scraping every 15s       │
│  ✅ Slack webhook        — 3 alerts sent today              │
│  ⚪ OCSF → Splunk        — not configured                  │
│  ⚪ OTLP → Datadog       — not configured                  │
│                                                             │
│  [+ Add Integration]                                        │
└─────────────────────────────────────────────────────────────┘
```

---

## 📊 Implementation Estimate

| Component | LOC | Days | Priority |
|-----------|-----|------|----------|
| `@observe()` decorator | 150 | 0.5 | P0 — ship first |
| LangChain CallbackHandler | 250 | 1 | P0 |
| CrewAI Observer | 200 | 1 | P1 |
| AutoGen Handler | 200 | 1 | P1 |
| OpenAI Agents Tracer | 150 | 0.5 | P1 |
| OTel OTLP exporter | 300 | 1.5 | P0 |
| CloudEvents builder | 200 | 1 | P1 |
| OCSF event builder | 250 | 1 | P2 |
| Prometheus /metrics | 200 | 1 | P0 |
| Webhook sender | 200 | 1 | P0 |
| HTML/PDF reports | 250 | 1.5 | P1 |
| OTLP receiver | 300 | 1.5 | P1 |
| REST ingest API | 200 | 1 | P0 |
| Setup wizard UI | 300 | 1.5 | P0 |
| Integration status UI | 200 | 1 | P1 |
| Grafana dashboard JSON | 100 | 0.5 | P1 |
| **Total** | **~3,650** | **~16 days** | |

### Ship order:
1. **Week 1 (P0):** decorator, LangChain, REST ingest, Prometheus, webhooks, setup wizard
2. **Week 2 (P1):** CrewAI, AutoGen, OpenAI, OTel, CloudEvents, reports, Grafana dashboard
3. **Week 3 (P2):** OCSF, syslog, Haystack, LlamaIndex, advanced integrations

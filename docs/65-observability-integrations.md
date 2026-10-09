# 65 — Observability and Monitoring Integrations

## Observability Architecture

Connector's `observability.rs` provides unified monitoring through three engines:

| Engine | Purpose | Data |
|--------|---------|------|
| SystemWatchdog | Self-healing | Resource limits, anomalies |
| ReputationEngine | Trust scoring | Agent behavior, verification |
| BehaviorAnalyzer | Anomaly detection | Pattern analysis |

## Supported Observability Tools

| Tool | Integration | Events |
|------|-------------|--------|
| **Splunk** | HEC webhook | All audit events |
| **Datadog** | API intake | Metrics, logs, traces |
| **Prometheus** | /metrics endpoint | Metrics (pull) |
| **Grafana** | Prometheus | Dashboards |
| **New Relic** | OTLP | Traces, metrics |
| **Elastic** | Filebeat | Logs |
| **CloudWatch** | SDK | AWS deployments |
| **Stackdriver** | API | GCP deployments |
| **PagerDuty** | Events API | Critical alerts |
| **Slack** | Webhook | Team notifications |

## Webhook Configuration

```yaml
observability:
  webhooks:
    # Splunk HEC (HTTP Event Collector)
    - name: splunk-audit
      url: "https://splunk.company.com:8088/services/collector/event"
      headers:
        Authorization: "Splunk ${SPLUNK_HEC_TOKEN}"
      events: []  # empty = all events
      format: json
      retry:
        max_retries: 3
        
    # Datadog Log Intake
    - name: datadog-logs
      url: "https://http-intake.logs.datadoghq.com/v1/input"
      headers:
        DD-API-KEY: "${DATADOG_API_KEY}"
        DD-APP-KEY: "${DATADOG_APP_KEY}"
      events: []
      tags:
        - env:production
        - service:connector
        
    # PagerDuty for critical alerts
    - name: pagerduty-critical
      url: "https://events.pagerduty.com/v2/enqueue"
      headers:
        Authorization: "Token token=${PAGERDUTY_TOKEN}"
      events:
        - audit.tamper
        - chain.broken
        - agent.failed
        - budget.exceeded
      severity: critical
      dedup_key: "{{event_type}}-{{node_id}}"
      
    # Slack for team notifications
    - name: slack-alerts
      url: "${SLACK_WEBHOOK_URL}"
      events:
        - injection.blocked
        - trust.degraded
        - hitl.escalated
      secret: "${SLACK_WEBHOOK_SECRET}"
      payload_template: |
        {
          "text": "Connector Alert: {{event_type}}",
          "blocks": [
            {
              "type": "section",
              "text": {
                "type": "mrkdwn",
                "text": "*{{event_type}}* on {{node_id}}\n{{message}}"
              }
            }
          ]
        }
```

## Event Types

| Event | Description | Severity |
|-------|-------------|----------|
| `budget.exceeded` | Token budget depleted | Warning |
| `budget.warning` | 70/80/90% budget used | Info |
| `injection.blocked` | Semantic injection detected | Warning |
| `trust.degraded` | Agent trust score dropped | Warning |
| `agent.failed` | Agent error rate > 20% | Critical |
| `pipeline.completed` | Multi-agent pipeline finished | Info |
| `pipeline.failed` | Pipeline step errored | Error |
| `anomaly.detected` | Behavioral anomaly | Warning |
| `audit.tamper` | HMAC chain integrity failure | Critical |
| `chain.broken` | Any chain broken | Critical |
| `hitl.escalated` | Human review required | Info |
| `hitl.resolved` | Human review completed | Info |

## Prometheus Metrics

```yaml
observability:
  metrics:
    enabled: true
    format: prometheus
    port: 9090
    path: /metrics
    prefix: connector_
```

Available metrics:

```prometheus
# Node health
connector_health_status{node_id="node-01"}

# Chain integrity (0 = broken, 1 = intact)
connector_chain_integrity{chain_type="audit"}
connector_chain_integrity{chain_type="memory",namespace="/p/hospital-a/"}

# Agent metrics
connector_agent_count{status="running"}
connector_agent_trust_score{agent_pid="ag_a3f7b2"}
connector_agent_budget_remaining{agent_pid="ag_a3f7b2"}

# Firewall
connector_firewall_blocks_total{reason="injection"}
connector_firewall_blocks_total{reason="pii_exposure"}
connector_firewall_injection_score{quantile="0.99"}

# LLM
connector_llm_requests_total{provider="openai",model="gpt-4o"}
connector_llm_cost_total{provider="openai"}
connector_llm_latency_seconds{quantile="0.99"}
connector_llm_circuit_breaker_state{provider="openai"}

# Compliance
connector_compliance_decisions_total{regulation="hipaa"}
connector_hitl_queue_depth

# Memory
connector_memory_writes_total{namespace="/p/"}
connector_memory_reads_total{namespace="/k/"}

# Tools
connector_tool_calls_total{tool="search",bridge="github"}
connector_tool_latency_seconds{tool="query",quantile="0.95"}
```

## Grafana Dashboard

```json
{
  "dashboard": {
    "title": "Connector Overview",
    "panels": [
      {
        "title": "Chain Integrity",
        "targets": [
          {
            "expr": "connector_chain_integrity",
            "legendFormat": "{{chain_type}}"
          }
        ]
      },
      {
        "title": "Agent Trust Scores",
        "targets": [
          {
            "expr": "avg(connector_agent_trust_score)",
            "legendFormat": "Average"
          }
        ]
      },
      {
        "title": "Firewall Blocks",
        "targets": [
          {
            "expr": "rate(connector_firewall_blocks_total[5m])",
            "legendFormat": "{{reason}}"
          }
        ]
      },
      {
        "title": "LLM Cost (USD)",
        "targets": [
          {
            "expr": "increase(connector_llm_cost_total[1h])",
            "legendFormat": "{{provider}}"
          }
        ]
      }
    ]
  }
}
```

## OpenTelemetry Traces

```yaml
observability:
  traces:
    enabled: true
    exporter: otlp
    endpoint: "${OTEL_COLLECTOR_ENDPOINT}"  # e.g., otel-collector:4317
    
    # Sampling
    sampling:
      ratio: 0.1  # 10% of traces
      
    # Attributes
    resource:
      service.name: connector
      service.version: "1.0.0"
      deployment.environment: production
```

## Splunk HEC Setup

```bash
# 1. Create HEC token in Splunk
# Settings → Data Inputs → HTTP Event Collector → New Token

# 2. Configure Connector webhook (see yaml above)

# 3. Search in Splunk
index=connector sourcetype=_json
| eval event_type=json_extract(_raw, "event_type")
| stats count by event_type

# Alert for critical events
index=connector event_type="audit.tamper" OR event_type="chain.broken"
| eval severity="critical"
```

## Datadog Integration

```yaml
# Connector sends logs directly to Datadog
observability:
  webhooks:
    - name: datadog
      url: "https://http-intake.logs.datadoghq.com/v1/input"
      headers:
        DD-API-KEY: "${DD_API_KEY}"
      events: []
```

```python
# Datadog metrics integration via API
from datadog import initialize, api

initialize(api_key=os.environ['DD_API_KEY'])

# Query Connector metrics from Datadog
api.Metric.query(
    start=time.time() - 3600,
    end=time.time(),
    query='avg:connector.agent.trust_score{*}'
)
```

## CloudWatch (AWS)

```yaml
observability:
  cloudwatch:
    enabled: true
    region: "${AWS_REGION}"
    namespace: "Connector"
    
    # Automatic from EC2 metadata
    auto_detect_instance: true
```

## Alerting Rules

```yaml
observability:
  alerts:
    - name: chain_broken
      condition: chain_integrity == 0
      severity: critical
      channels: [pagerduty, email]
      
    - name: low_trust
      condition: agent_trust_score < 0.5
      severity: warning
      channels: [slack]
      
    - name: budget_exceeded
      condition: budget_remaining < 0
      severity: warning
      channels: [slack, email]
      
    - name: injection_spike
      condition: rate(injection_blocks[5m]) > 10
      severity: warning
      channels: [slack]
      
    - name: node_unhealthy
      condition: health_status == 0
      severity: critical
      channels: [pagerduty]
```

## Webhook Security

All webhook payloads are HMAC-signed:

```
X-Connector-Signature: sha256=<hmac>
X-Connector-Timestamp: <unix_timestamp>
X-Connector-Event-ID: <uuid>
```

```python
# Verify webhook signature
import hmac
import hashlib

def verify_webhook(payload, signature, secret):
    expected = hmac.new(
        secret.encode(),
        payload.encode(),
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(f"sha256={expected}", signature)
```

## Observability Checklist

- [ ] Prometheus scraping enabled
- [ ] Grafana dashboards imported
- [ ] Webhooks configured (Slack/PagerDuty)
- [ ] Log aggregation configured (Splunk/Datadog)
- [ ] Tracing enabled (OTel)
- [ ] Alert rules active
- [ ] On-call rotation configured
- [ ] Chain integrity alerting
- [ ] Budget alerting
- [ ] Health checks verified

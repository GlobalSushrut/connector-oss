# 66 — Orchestration and Workflow Integrations

> Connector's native DAG orchestrator integrates with external workflow platforms. This chapter covers OpenClaw, Dify, n8n, Temporal, Airflow, and other orchestration tools that can drive governed AI agents through Connector's control plane.

---

## Native Orchestrator

Connector includes a built-in DAG orchestrator (`orchestrator.rs`) for agent pipeline execution:

```rust
pub struct OrchestratorTask {
    pub task_id: String,
    pub agent_pid: String,
    pub capability_key: String,
    pub depends_on: Vec<String>,
    pub state: TaskState,
    pub max_retries: u32,
    pub retry_count: u32,
    pub backoff_base_ms: u64,
}

pub enum TaskState {
    Pending, Ready, Running, Completed, Failed, Retrying, Skipped,
}
```

**API Endpoints:**
- `POST /infra/orchestrator/submit` — Submit DAG
- `GET /infra/orchestrator/{id}` — DAG status
- `GET /infra/orchestrator/sagas` — List saga pipelines
- `POST /infra/orchestrator/sagas/{id}/rollback` — Manual rollback

---

## OpenClaw Integration

[OpenClaw](https://github.com/swarmclawai/swarmclaw) is an open-source autonomous AI agent runtime with messaging-based interfaces.

### Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  OpenClaw   │────▶│  Connector  │────▶│   LLM/API   │
│   Gateway   │     │ Control Plane│     │   Providers │
└─────────────┘     └─────────────┘     └─────────────┘
       │                    │
       │                    │
       ▼                    ▼
┌─────────────┐     ┌─────────────┐
│  Telegram   │     │  Audit Chain│
│   Slack     │     │  Compliance │
│   Discord   │     │  9 Chains   │
└─────────────┘     └─────────────┘
```

### Connector as OpenClaw Backend

```python
# openclaw_connector_adapter.py
from connector import Agent, Platform

class ConnectorOpenClawBackend:
    """Use Connector as the governance layer for OpenClaw agents."""
    
    def __init__(self, node_url: str, api_key: str):
        self.platform = Platform(node_url, api_key)
        
    async def execute_task(self, task: dict) -> dict:
        """Execute an OpenClaw task through Connector's 9-ring enforcement."""
        
        # 1. Create governed agent for this task
        agent = self.platform.create_agent(
            name=f"openclaw-{task['id']}",
            contract_cid="cls1-sha256-openclaw-standard",
            namespace="/m/openclaw/tasks/"
        )
        
        # 2. Execute with full governance
        result = agent.run(
            intent=task['description'],
            tools=task.get('tools', []),
            budget=task.get('budget', {'tokens': 10000})
        )
        
        # 3. Return with audit trail
        return {
            'output': result.content,
            'audit_cid': result.audit_cid,
            'decision_id': result.decision_id,
            'grounded': result.grounded,
            'proof': result.generate_proof()
        }
```

### OpenClaw Mission Control Integration

[OpenClaw Mission Control](https://github.com/abhi1693/openclaw-mission-control) provides centralized operations for agent teams:

```yaml
# connector_openclaw_bridge.yaml
openclaw:
  mission_control_url: https://mission-control.openclaw.io
  gateway_endpoints:
    - https://gateway-1.openclaw.io
    - https://gateway-2.openclaw.io
    
  connector_backends:
    - node_id: connector-prod-01
      url: https://connector.internal:8443
      priority: primary
      regulations: [hipaa, soc2]
    - node_id: connector-prod-02
      url: https://connector-dr.internal:8443
      priority: failover
      
  routing:
    medical_tasks: connector-prod-01  # HIPAA-bound
    general_tasks: connector-prod-02  # General workloads
```

---

## Dify Integration

[Dify](https://dify.ai) is an LLM application development platform with visual workflow builders.

### Dify → Connector Workflow

```python
# dify_connector_node.py
from connector import Agent

class DifyConnectorNode:
    """Custom Dify node that routes through Connector."""
    
    def execute(self, inputs: dict) -> dict:
        """Called by Dify workflow engine."""
        
        agent = Agent.from_pid(inputs['agent_pid'])
        
        # Pass through Connector's governance
        result = agent.run(
            intent=inputs['query'],
            context=inputs.get('context', {}),
            regulation_tags=inputs.get('regulations', [])
        )
        
        return {
            'response': result.content,
            'audit_cid': result.audit_cid,
            'grounded': result.grounded
        }
```

### Visual Workflow with Governance

```yaml
# dify_workflow_with_connector.yaml
workflow:
  name: "Customer Support with Compliance"
  
  nodes:
    - id: start
      type: start
      
    - id: classify_intent
      type: llm
      model: gpt-4
      prompt: "Classify: {{input.query}}"
      
    - id: connector_governance
      type: custom
      implementation: DifyConnectorNode
      config:
        agent_pid: "ag_customer_support_01"
        regulations: ["gdpr", "customer-data-policy"]
      
    - id: retrieve_knowledge
      type: connector_memory
      namespace: "/k/support/faqs/"
      
    - id: generate_response
      type: connector_chat
      governed: true
      hitl_threshold: 0.8
      
    - id: end
      type: end
```

---

## n8n Integration

[n8n](https://n8n.io) is a workflow automation tool with 400+ integrations.

### n8n Connector Node

```javascript
// n8n-nodes-connector/Connector.node.js
const { IExecuteFunctions } = require('n8n-core');

class ConnectorNode {
    async execute(this) {
        const node_url = this.getNodeParameter('node_url');
        const api_key = this.getCredentials('connectorApiKey');
        const agent_pid = this.getNodeParameter('agent_pid');
        const intent = this.getNodeParameter('intent');
        
        // Call Connector API
        const response = await fetch(`${node_url}/api/v1/agents/${agent_pid}/chat`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${api_key}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                message: intent,
                governed: true,
                regulation_tags: this.getNodeParameter('regulations', [])
            })
        });
        
        const result = await response.json();
        
        return [{
            json: {
                response: result.content,
                audit_cid: result.audit_cid,
                decision_id: result.decision_id,
                grounded: result.grounded
            }
        }];
    }
}
```

### Workflow Example

```json
{
  "nodes": [
    {
      "type": "n8n-nodes-base.trigger",
      "name": "Webhook Trigger"
    },
    {
      "type": "n8n-nodes-connector.connector",
      "name": "Governed AI",
      "parameters": {
        "node_url": "https://connector.internal:8443",
        "agent_pid": "ag_sales_01",
        "intent": "={{ $json.customer_query }}",
        "regulations": ["gdpr"]
      }
    },
    {
      "type": "n8n-nodes-base.slack",
      "name": "Send Response"
    }
  ]
}
```

---

## Temporal Integration

[Temporal](https://temporal.io) is a durable workflow execution platform.

### Temporal Workflow with Connector

```python
# temporal_connector_workflow.py
from temporalio import workflow
from connector import Platform

@workflow.defn
class GovernedAIWorkflow:
    @workflow.run
    async def run(self, input: dict) -> dict:
        platform = Platform("https://connector.internal:8443")
        
        # Step 1: Create agent (durable, survives retries)
        agent = await workflow.execute_activity(
            create_governed_agent,
            args=[platform, input['agent_config']],
            start_to_close_timeout=timedelta(seconds=30)
        )
        
        # Step 2: Execute with governance
        result = await workflow.execute_activity(
            execute_governed_task,
            args=[agent.pid, input['task']],
            start_to_close_timeout=timedelta(minutes=5),
            retry_policy=RetryPolicy(
                maximum_attempts=3,
                non_retryable_error_types=["PolicyViolation"]
            )
        )
        
        # Step 3: Generate compliance proof
        proof = await workflow.execute_activity(
            generate_proof_bundle,
            args=[agent.pid],
            start_to_close_timeout=timedelta(seconds=10)
        )
        
        return {
            'result': result,
            'audit_cid': result.audit_cid,
            'proof': proof
        }

async def create_governed_agent(platform: Platform, config: dict) -> Agent:
    return platform.create_agent(
        name=config['name'],
        contract_cid=config['contract'],
        namespace=config['namespace']
    )

async def execute_governed_task(agent_pid: str, task: dict) -> dict:
    agent = Agent.from_pid(agent_pid)
    return agent.run(
        intent=task['description'],
        tools=task.get('tools', [])
    )
```

---

## Apache Airflow Integration

[Airflow](https://airflow.apache.org) is a workflow scheduler for data pipelines.

### Airflow Connector Operator

```python
# airflow_connector_plugin/operators/connector_operator.py
from airflow.models import BaseOperator
from connector import Platform

class GovernedAIOperator(BaseOperator):
    """Execute AI tasks through Connector with full governance."""
    
    def __init__(
        self,
        node_url: str,
        agent_pid: str,
        intent: str,
        regulations: list = None,
        **kwargs
    ):
        super().__init__(**kwargs)
        self.node_url = node_url
        self.agent_pid = agent_pid
        self.intent = intent
        self.regulations = regulations or []
        
    def execute(self, context):
        platform = Platform(self.node_url)
        agent = platform.get_agent(self.agent_pid)
        
        result = agent.run(
            intent=self.intent,
            regulation_tags=self.regulations
        )
        
        # Push audit trail to XCom
        context['ti'].xcom_push(key='audit_cid', value=result.audit_cid)
        context['ti'].xcom_push(key='decision_id', value=result.decision_id)
        
        return result.content
```

### DAG Example

```python
# dags/governed_etl.py
from airflow import DAG
from airflow_connector_plugin import GovernedAIOperator

with DAG('governed_customer_analysis', schedule='@daily'):
    
    extract = GovernedAIOperator(
        task_id='extract_data',
        node_url='https://connector.internal:8443',
        agent_pid='ag_etl_01',
        intent='Extract customer data from CRM',
        regulations=['gdpr', 'data-minimization']
    )
    
    analyze = GovernedAIOperator(
        task_id='analyze_sentiment',
        node_url='https://connector.internal:8443',
        agent_pid='ag_analytics_01',
        intent='Analyze customer sentiment',
        regulations=['gdpr']
    )
    
    report = GovernedAIOperator(
        task_id='generate_report',
        node_url='https://connector.internal:8443',
        agent_pid='ag_reporting_01',
        intent='Generate compliance report'
    )
    
    extract >> analyze >> report
```

---

## Integration Comparison

| Platform | Type | Best For | Governance Level |
|----------|------|----------|------------------|
| **OpenClaw** | Autonomous agents | Messaging-based AI agents | Full (via Connector backend) |
| **Dify** | App builder | Visual LLM apps | Workflow-level governance |
| **n8n** | Automation | Business process automation | Node-level governance |
| **Temporal** | Durable execution | Long-running workflows | Activity-level governance |
| **Airflow** | Data pipelines | ETL, analytics | Task-level governance |
| **Native** | DAG orchestrator | Connector-native pipelines | Built-in 9 rings |

---

## Hybrid Orchestration Pattern

```
┌─────────────────────────────────────────────────────────┐
│                  Workflow Trigger                       │
│         (Schedule / Webhook / Message)                │
└─────────────────────────┬───────────────────────────────┘
                          │
              ┌───────────▼───────────┐
              │   n8n / Airflow / etc   │
              │    (Business Logic)     │
              └───────────┬───────────────┘
                          │
              ┌───────────▼───────────┐
              │    Connector API        │
              │   (Governance Layer)    │
              │  9 Rings + 9 Chains     │
              └───────────┬───────────────┘
                          │
              ┌───────────▼───────────┐
              │   LLM / Tool Provider │
              │  (OpenAI, MCP, etc)   │
              └─────────────────────────┘
```

The external orchestrator handles business logic; Connector handles governance, audit, and compliance.

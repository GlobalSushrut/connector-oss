# 70 — Real Execution Control: Beyond Guidance to Action

> Moving from AI that advises to AI that acts. This chapter covers how Connector enables real-world execution control for infrastructure, systems, and operations — not just generating recommendations but taking governed actions.

---

## The Gap Between Advice and Action

Most AI systems stop at guidance:
- "You should restart the server"
- "The database needs more memory"
- "Delete the temporary files"

Connector bridges this gap with **governed execution** — the AI proposes, the policy approves, the system acts, and everything is audited.

---

## Execution Control Architecture

```
┌─────────────────────────────────────────────────────────┐
│              AI Agent Decision                          │
│  "Restart service X because memory is at 95%"           │
└─────────────────────────┬───────────────────────────────┘
                          │
              ┌───────────▼───────────┐
              │   Connector Control     │
              │      Plane              │
              │                         │
              │  ┌───────────────────┐  │
              │  │ Policy Check      │  │
              │  │ Is this allowed?  │  │
              │  └───────────────────┘  │
              │            ↓            │
              │  ┌───────────────────┐  │
              │  │ HITL Gate         │  │
              │  │ Human approval?   │  │
              │  └───────────────────┘  │
              │            ↓            │
              │  ┌───────────────────┐  │
              │  │ Budget Check      │  │
              │  │ Can we afford?    │  │
              │  └───────────────────┘  │
              └───────────┬───────────────┘
                          │
              ┌───────────▼───────────┐
              │    Execution Bridge    │
              │   (SSH/API/Agent)      │
              └───────────┬───────────────┘
                          │
              ┌───────────▼───────────┐
              │    Target System       │
              │   (Server/DB/Device)   │
              └─────────────────────────┘
```

---

## Execution Modes

### 1. Advisory Mode (Default)

AI generates recommendations, human executes.

```yaml
execution_mode: advisory

response_format: |
  ## Recommendation
  {{action_description}}
  
  ## Command
  ```bash
  {{suggested_command}}
  ```
  
  ## Safety Check
  {{risk_assessment}}
  
  ## To Execute
  Run: connectorctl exec --session {{session_id}} --approve
```

### 2. Semi-Autonomous Mode

Low-risk actions auto-execute, high-risk require approval.

```yaml
execution_mode: semi_autonomous

auto_execute:
  risk_level: [low, medium]
  command_patterns:
    - "status"
    - "list"
    - "get"
    - "describe"
    - "ls"
    - "cat"
    - "grep"
    - "find"
    
require_approval:
  risk_level: [high, critical]
  command_patterns:
    - "rm"
    - "kill"
    - "restart"
    - "stop"
    - "drop"
    - "delete"
    - "write"
    - "modify"
```

### 3. Autonomous Mode (Restricted)

Pre-approved actions execute without human intervention.

```yaml
execution_mode: autonomous

allowed_actions:
  - name: restart_web_server
    command: "systemctl restart nginx"
    conditions:
      - metric: "nginx.error_rate"
        threshold: "> 0.1"
      - metric: "nginx.connections"
        threshold: "> 10000"
    max_frequency: "1 per hour"
    
  - name: scale_up_database
    command: "aws rds modify-db-instance --db-instance-identifier prod-db --allocated-storage {{new_size}}"
    conditions:
      - metric: "db.free_storage_percent"
        threshold: "< 20"
    require_approval_if:
      cost_impact: "> $100"
```

---

## Execution Bridges

Connector connects to target systems through execution bridges:

### SSH Bridge

```yaml
bridges:
  - id: production_servers
    type: ssh
    config:
      host: prod-server-01.company.com
      user: connector-agent
      key_path: /secure/ssh/prod-key
      timeout_seconds: 30
      allowed_commands:
        - "systemctl *"
        - "docker *"
        - "kubectl *"
        - "df -h"
        - "free -m"
      denied_commands:
        - "rm -rf *"
        - "mkfs.*"
        - "> /dev/sd*"
```

```python
# Execute via SSH bridge
result = agent.execute(
    bridge="production_servers",
    command="systemctl restart nginx",
    justification="Memory pressure causing 502 errors"
)
```

### API Bridge

```yaml
bridges:
  - id: aws_api
    type: http
    config:
      base_url: https://ec2.amazonaws.com
      auth:
        type: aws_signature_v4
        region: us-east-1
        service: ec2
      allowed_endpoints:
        - "GET /instances"
        - "POST /instances/*/reboot"
        - "PUT /instances/*/resize"
      denied_endpoints:
        - "DELETE /instances/*"
        - "POST /instances/*/terminate"
```

### K8s Bridge

```yaml
bridges:
  - id: production_k8s
    type: kubernetes
    config:
      kubeconfig_path: /secure/kubeconfig/prod
      context: production
      allowed_resources:
        - "deployments"
        - "pods"
        - "services"
        - "configmaps"
      allowed_verbs:
        - "get"
        - "list"
        - "describe"
        - "restart"
        - "scale"
      denied_verbs:
        - "delete"
        - "exec"
        - "attach"
      allowed_namespaces:
        - "app-*"
        - "monitoring"
```

### Database Bridge

```yaml
bridges:
  - id: production_db
    type: database
    config:
      driver: postgresql
      connection_string: "${DB_CONNECTION}"
      read_only: false
      allowed_operations:
        - "SELECT"
        - "EXPLAIN"
        - "VACUUM ANALYZE"
        - "REINDEX"
      denied_operations:
        - "DROP"
        - "TRUNCATE"
        - "DELETE"  # Without WHERE
      query_timeout_seconds: 300
      max_rows_returned: 10000
```

---

## Real Execution Examples

### Server Maintenance

```python
from connector import Agent, Bridge

agent = Agent.from_yaml("infrastructure-agent.yaml")

# Connect to server bridge
server = Bridge("production_servers")

# Check system status
status = server.execute("systemctl status nginx")
memory = server.execute("free -m")
disk = server.execute("df -h /")

# AI analyzes and decides
if memory.available_mb < 500:
    # Propose action
    proposal = agent.propose(
        action="restart_nginx",
        reason="Memory exhaustion causing instability",
        command="systemctl restart nginx",
        impact="2-second service interruption"
    )
    
    # Policy gate checks if auto-approval
    if proposal.risk_level == "low":
        result = server.execute(proposal.command)
        agent.record(result, audit_trail=True)
```

### Database Operations

```python
# Connect to database
db = Bridge("production_db")

# Analyze slow queries
slow_queries = db.execute("""
    SELECT query, mean_exec_time, calls
    FROM pg_stat_statements
    ORDER BY mean_exec_time DESC
    LIMIT 10
""")

# AI proposes optimization
optimization = agent.propose(
    action="add_index",
    target="orders.created_at",
    command="CREATE INDEX CONCURRENTLY idx_orders_created_at ON orders(created_at)",
    estimated_improvement="10x faster date range queries"
)

# Execute with governance
if optimization.approved:
    db.execute(optimization.command)
```

### Kubernetes Operations

```python
k8s = Bridge("production_k8s")

# Check pod status
pods = k8s.execute("kubectl get pods -n app-production")

# Scale if needed
if pods.cpu_utilization > 80:
    agent.propose_and_execute(
        action="scale_deployment",
        command="kubectl scale deployment app --replicas=5 -n app-production",
        justification="High CPU load, adding capacity"
    )
```

---

## Safety Mechanisms

### 1. Dry Run Mode

```python
# Test without executing
result = agent.execute(
    command="DROP TABLE old_data",
    dry_run=True
)
# Returns what WOULD happen without doing it
```

### 2. Two-Phase Commit

```python
# Phase 1: Prepare
proposal = agent.prepare(
    commands=[
        "ALTER TABLE users ADD COLUMN new_field VARCHAR(255)",
        "UPDATE users SET new_field = 'default'",
    ]
)

# Human review
print(f"Will modify {proposal.affected_rows} rows")
approval = input("Proceed? (yes/no): ")

# Phase 2: Commit
if approval == "yes":
    agent.commit(proposal)
```

### 3. Automatic Rollback

```yaml
execution:
  rollback_on_failure: true
  
  health_checks:
    post_execution:
      - "systemctl is-active nginx"
      - "curl -f http://localhost/health"
      
  rollback_commands:
    - "systemctl restart nginx-previous"
    - "rollback deployment"
```

### 4. Circuit Breaker

```python
# Stop executing if failure rate is high
if recent_failure_rate > 0.5:
    circuit_breaker.trip()
    agent.notify("Circuit breaker open - manual intervention required")
```

---

## Execution Audit Trail

Every executed command generates:

```json
{
  "execution_id": "exec_a3f7b2c8",
  "timestamp": "2026-04-14T02:00:00Z",
  "agent_pid": "ag_infra_01",
  "bridge": "production_servers",
  "command": "systemctl restart nginx",
  "justification": "Memory pressure",
  "approval": {
    "type": "auto",
    "policy_rule": "maintenance_restart_low_risk",
    "risk_level": "low"
  },
  "result": {
    "exit_code": 0,
    "stdout": "...",
    "stderr": "",
    "duration_ms": 2150
  },
  "pre_state": {
    "nginx.status": "degraded",
    "memory.available_mb": 120
  },
  "post_state": {
    "nginx.status": "healthy",
    "memory.available_mb": 2048
  },
  "audit_cid": "mem1-sha256-d4e8f1...",
  "chain_verified": true
}
```

---

## Human-in-the-Loop for Critical Actions

```python
# High-stakes execution requires human approval
result = agent.execute(
    command="terraform apply -destroy",
    require_approval=True,
    approvers=["infra-lead", "cto"],
    approval_timeout_hours: 24,
    justification="""
    Destroying staging environment as part of 
    cost optimization initiative. All data backed up.
    Estimated savings: $500/month.
    """
)

# Notification sent via Slack/PagerDuty
# Approval granted through web UI or CLI
# Only then does execution proceed
```

---

## Execution Control Checklist

When building real execution workflows:

- [ ] Define clear execution boundaries
- [ ] Implement dry-run for testing
- [ ] Add comprehensive rollback procedures
- [ ] Require HITL for high-risk actions
- [ ] Set rate limits on automated actions
- [ ] Monitor execution success/failure rates
- [ ] Alert on unexpected failures
- [ ] Maintain complete audit trail
- [ ] Test rollback procedures regularly
- [ ] Document all allowed/denied actions

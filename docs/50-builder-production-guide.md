# 50 — Builder: Production Readiness Guide

> Everything you need to move from development to a production Connector deployment.

---

## Production Readiness Checklist

### Security

- [ ] Ed25519 keypair in KMS — not a plaintext file
- [ ] `CONNECTOR_DEV_MODE` is **not set** in production
- [ ] TLS enabled with valid certificate (not self-signed)
- [ ] mTLS configured for node-to-node communication
- [ ] `CONNECTOR_API_KEY` stored in secrets manager (not env var in K8s spec)
- [ ] Node binary attestation enabled (`binary_attestation: true`)
- [ ] All agent clearance levels reviewed and minimized
- [ ] Tool allowlists reviewed and minimized

### Data

- [ ] Journal retention policy: ≥ 365 days (SOC2), ≥ 2190 days (HIPAA)
- [ ] Backup tested with documented recovery time
- [ ] Cold-tier archive configured (S3 / GCS)
- [ ] Encryption at rest enabled
- [ ] `/p/` namespace policy verified (no LLM access)

### Operations

- [ ] Health endpoints configured in load balancer
- [ ] Chain break alert configured
- [ ] Budget threshold alerts configured (warn at 80%, block at 95%)
- [ ] HITL queue monitor with notification (email/Slack)
- [ ] Log shipping to SIEM configured
- [ ] Proof bundle export tested
- [ ] Formal verification report reviewed (grade ≥ B)

### Compliance

- [ ] Regulation frameworks activated in `connector.yaml`
- [ ] Policy files reviewed by compliance team
- [ ] First compliance report generated and reviewed
- [ ] HITL escalation path tested end-to-end
- [ ] Offline proof verification tested

---

## Production `connector.yaml`

```yaml
node:
  id: "${NODE_ID}"
  env: production
  log_level: warn
  keypair_path: "${KMS_KEYPAIR_PATH}"
  binary_attestation: true

api:
  host: 0.0.0.0
  port: 9091
  tls:
    enabled: true
    cert: "${TLS_CERT_PATH}"
    key:  "${TLS_KEY_PATH}"
  auth:
    api_key: "${CONNECTOR_API_KEY}"
    allow_agent_pid_auth: true
  rate_limit:
    requests_per_minute: 5000

storage:
  path: "${STORAGE_PATH}"
  journal_retention_days: 365
  encryption_at_rest: true
  kms_key_id: "${KMS_KEY_ID}"
  backup:
    enabled: true
    interval_hours: 6

llm:
  default_provider: openai
  timeout_seconds: 30
  providers:
    openai:
      api_key: "${OPENAI_API_KEY}"
      model: gpt-4o

firewall:
  enabled: true
  fail_closed: true

compliance:
  frameworks: [hipaa, soc2_type2, gdpr]

# No CONNECTOR_DEV_MODE in production
```

---

## Monitoring Setup

### Metrics to Track

| Metric | Alert Threshold | Action |
|---|---|---|
| `chain_verified` | `false` | Immediate alert — potential tamper |
| Block rate | > 5% | Investigation |
| HITL queue depth | > 10 | Notify reviewers |
| Budget utilization | > 80% | Warning; > 95% = alert |
| Journal write latency | > 100ms | Investigate storage |
| Proof generation time | > 2s | Investigate chain length |
| Agent quarantine count | > 0 | Immediate review |

### Prometheus Metrics (if configured)

```yaml
# connector.yaml
observability:
  prometheus:
    enabled: true
    port: 9092
    path: /metrics
```

Exposes:
- `connector_journal_entries_total`
- `connector_chain_verified`
- `connector_firewall_blocks_total`
- `connector_agent_count`
- `connector_budget_utilization`

---

## Log Shipping to SIEM

```yaml
# connector.yaml
observability:
  logging:
    format: json
    output: stdout
    level: warn
    structured_fields:
      - agent_pid
      - action
      - outcome
      - audit_cid
      - regulation
```

Pipe to your SIEM:
```bash
connector-server 2>&1 | your-siem-agent --input stdin --index connector-audit
```

---

## Proof Export Schedule

```bash
#!/bin/bash
# cron: 0 1 * * 0   (weekly, Sunday 1am)
# Weekly proof export for compliance archive

TODAY=$(date +%Y%m%d)
AGENTS=$(connectorctl agents --output json | jq -r '.agents[].pid')

for PID in $AGENTS; do
    connectorctl prove agent "$PID" \
        --title "weekly_${TODAY}" \
        --format json \
        --export "/archive/proofs/${TODAY}/"
done

# Verify all exported bundles
for BUNDLE in /archive/proofs/${TODAY}/*.json; do
    connectorctl verify-bundle "$BUNDLE"
done

echo "Weekly proof export complete: ${TODAY}"
```

---

## Blue-Green Deployment

```bash
# 1. Start new (green) node
docker run -d --name connector-green \
  -p 9092:9091 \
  -e CONNECTOR_API_KEY="${CONNECTOR_API_KEY}" \
  -v connector_data_green:/var/lib/connector \
  connectorai/connector:latest

# 2. Verify green is healthy
curl http://localhost:9092/health/maturity

# 3. Switch load balancer
# (update nginx/ALB to route to green:9092)

# 4. Drain blue
# (wait for in-flight requests to complete)

# 5. Seal blue session
connectorctl prove agent --all --title "pre_migration_backup"

# 6. Stop blue
docker stop connector-blue
```

---

## Scaling Guidelines

| Agents | Requests/min | Recommended Setup |
|---|---|---|
| 1–10 | < 100 | Single node, 4 CPU, 8 GB RAM |
| 10–50 | < 1,000 | Single node, 8 CPU, 16 GB RAM |
| 50–200 | < 5,000 | 2-node cluster, 16 CPU, 32 GB RAM |
| 200+ | 5,000+ | Multi-node cluster + shared storage |

---

## Disaster Recovery

```bash
# Restore from backup
connector-server restore \
  --backup-path /var/backups/connector/latest \
  --verify-chain

# Verify chain after restore
connectorctl health --detail
# chains.verified: true = successful restore

# Generate proof immediately after restore
connectorctl prove agent --all --title "post_restore_verification"
```

---

## First Production Audit

Run this sequence after first week in production:

```python
# 1. Health check
health = p.get_health()
assert health["status"] == "ready"
assert health["chain_verified"]

# 2. Formal verification
verify = p.get_verify_report()
grade  = verify.get("executive_summary", {}).get("grade")
assert grade in ("A", "B"), f"Grade too low: {grade}"

# 3. Generate proofs for all agents
for agent in p.list_agents().get("agents", []):
    proof = p.generate_proof(agent["pid"], title="first_production_week")
    print(f"{agent['name']}: {proof['proof_id']}")

# 4. Compliance reports
for framework in ["soc2", "hipaa", "gdpr"]:
    report = p.get_regulation_report(framework)
    print(f"{framework}: ok={report.get('ok')}")

# 5. Verify no violations
violations = p.get_policy_violations()
print(f"Policy violations: {violations.get('count', 0)}")
```

---

## Next Steps

- **[25 — External Deployment](25-infra-external.md)**
- **[63 — Hosting and Deployment](63-hosting-deployment.md)**
- **[58 — Compliance Framework](58-compliance-framework.md)**

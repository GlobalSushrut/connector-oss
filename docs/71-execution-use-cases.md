# 71 — Execution Use Cases

## Self-Healing Infrastructure

```yaml
workflow: self-healing
triggers:
  - metric: service.error_rate > 0.05 for 5m
  - metric: memory_usage > 90% for 3m

steps:
  - diagnose: systemctl status, journalctl, free, df
  - classify: llm analyzes issue type
  - remediate:
      - if memory: restart service
      - if disk: clean logs
      - else: escalate
  - verify: health checks
```

## Incident Response

```yaml
workflow: incident-response
triggers:
  - security_alert severity [high, critical]
  - failed_logins > 100 in 5m

steps:
  - gather: netstat, logs, cloudtrail
  - analyze: llm classifies threat
  - contain:
      - scale deployment to 0
      - block IPs
      - revoke credentials
  - preserve: copy logs to evidence
  - notify: pagerduty, slack
```

## Cost Optimization

```yaml
workflow: cost-optimization
triggers:
  - schedule: weekly
  - monthly_spend > $10k

actions:
  - identify: unused instances, unattached volumes
  - hitl_approval: if savings > $100
  - remediate: terminate, detach
  - report: savings to finance
```

## Database Maintenance

```yaml
workflow: db-maintenance
schedule: weekly sunday 3am
pre_conditions:
  - connections < 50
  - error_rate < 0.01

steps:
  - maintenance_mode: enable
  - vacuum_analyze: all tables
  - check_bloat: identify bloated indexes
  - reindex: if needed (with hitl)
  - exit_maintenance
  - verify: health checks
```

## Certificate Management

```yaml
workflow: cert-renewal
schedule: daily
triggers:
  - cert_expiring within 30 days

steps:
  - scan: all certificates
  - renew: cert-manager
  - verify: new cert deployed
  - restart: affected services
  - notify: team
```

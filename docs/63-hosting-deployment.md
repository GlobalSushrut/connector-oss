# 63 — Hosting and Deployment

## Deployment Patterns

| Pattern | Nodes | Use Case |
|---------|-------|----------|
| Single | 1 | Development, small teams |
| HA | 2-3 | Production uptime |
| Multi-Region | 3+ | Global distribution |
| Edge Mesh | 10+ | IoT, CDN-style |

## Docker

```bash
docker run -d \
  --name connector \
  -p 8080:8080 \
  -v $(pwd)/connector.yaml:/etc/connector/connector.yaml \
  -v connector-data:/data \
  connectorplatform/connector-node:latest
```

## Kubernetes

```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: connector
spec:
  replicas: 3
  template:
    spec:
      containers:
        - name: connector
          image: connectorplatform/connector-node:latest
          ports:
            - containerPort: 8080
            - containerPort: 8443
          volumeMounts:
            - name: data
              mountPath: /data
```

## systemd

```ini
[Unit]
Description=Connector Node
After=network.target

[Service]
Type=notify
ExecStart=/usr/local/bin/connector-node --config /etc/connector/connector.yaml
Restart=on-failure
MemoryMax=8G

[Install]
WantedBy=multi-user.target
```

## Production connector.yaml

```yaml
node:
  id: "${NODE_ID}"
  data_dir: /data
  log_level: info

cluster:
  mode: ha
  seed_nodes: ["node-0", "node-1", "node-2"]

security:
  tls:
    cert_path: /etc/certs/server.crt
    key_path: /etc/certs/server.key
  hsm:
    enabled: true
    provider: pkcs11

observability:
  metrics:
    enabled: true
    format: prometheus
    port: 9090
  webhooks:
    - name: slack
      url: "${SLACK_WEBHOOK}"
      events: ["budget.exceeded", "injection.blocked"]
    - name: pagerduty
      url: "${PAGERDUTY_URL}"
      events: ["agent.failed", "audit.tamper"]

backup:
  enabled: true
  schedule: "0 2 * * *"
  destination: s3
  s3:
    bucket: "${BACKUP_BUCKET}"
    region: "${AWS_REGION}"
```

## Security Checklist

- [ ] mTLS enabled
- [ ] API keys rotated (90 days)
- [ ] Encryption at rest (AES-256)
- [ ] HSM for signing keys
- [ ] Secrets in Vault
- [ ] RBAC configured
- [ ] Network policies active

## Troubleshooting

```bash
# Check health
connectorctl health

# Verify chains
connectorctl chain analyze <pid>

# View logs
journalctl -u connector-node -f
```

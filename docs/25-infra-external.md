# 25 — External Deployment Topology

> Deploying Connector in production — bare metal, Kubernetes, cloud, multi-node.

---

## Deployment Shapes

| Shape | When to Use | HA | Scale |
|---|---|---|---|
| Single node | Development, small teams | No | Low |
| Single node + HA storage | Production (single site) | Partial | Medium |
| Multi-node cluster | Production (enterprise) | Yes | High |
| Multi-region | Global, regulated data residency | Yes | Very High |
| Edge mesh | Low-latency, distributed users | Yes | Very High |

---

## Single-Node (Bare Metal / VM)

```bash
# Install
curl -fsSL https://install.connector.ai | bash

# Configure
cp /etc/connector/connector.example.yaml /etc/connector/connector.yaml
# Edit: api_key, llm.providers, storage.path

# Start
systemctl enable connector
systemctl start connector

# Verify
connectorctl health
```

---

## Docker Compose (Development)

```yaml
# docker-compose.yml
version: "3.9"
services:
  connector:
    image: connectorai/connector:latest
    ports:
      - "9091:9091"
    environment:
      CONNECTOR_API_KEY: "${CONNECTOR_API_KEY}"
      OPENAI_API_KEY:    "${OPENAI_API_KEY}"
      CONNECTOR_DEV_MODE: "0"
    volumes:
      - ./connector.yaml:/etc/connector/connector.yaml
      - connector_data:/var/lib/connector
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:9091/health"]
      interval: 30s
      timeout: 10s
      retries: 3

volumes:
  connector_data:
```

---

## Kubernetes StatefulSet

```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: connector
  namespace: connector-system
spec:
  serviceName: connector
  replicas: 3
  selector:
    matchLabels:
      app: connector
  template:
    metadata:
      labels:
        app: connector
    spec:
      containers:
        - name: connector
          image: connectorai/connector:latest
          ports:
            - containerPort: 9091
          env:
            - name: CONNECTOR_API_KEY
              valueFrom:
                secretKeyRef:
                  name: connector-secrets
                  key: api-key
            - name: CONNECTOR_CLUSTER_MODE
              value: "true"
          volumeMounts:
            - name: data
              mountPath: /var/lib/connector
            - name: config
              mountPath: /etc/connector
          livenessProbe:
            httpGet:
              path: /health
              port: 9091
            initialDelaySeconds: 10
            periodSeconds: 30
          readinessProbe:
            httpGet:
              path: /health/maturity
              port: 9091
            initialDelaySeconds: 15
            periodSeconds: 10
  volumeClaimTemplates:
    - metadata:
        name: data
      spec:
        accessModes: ["ReadWriteOnce"]
        resources:
          requests:
            storage: 50Gi
---
apiVersion: v1
kind: Service
metadata:
  name: connector
  namespace: connector-system
spec:
  selector:
    app: connector
  ports:
    - port: 9091
      targetPort: 9091
  type: ClusterIP
```

---

## AWS Reference Architecture

```
                        Route 53
                            │
                    Application Load Balancer
                    (TLS termination, WAF)
                            │
               ┌────────────┴────────────┐
               │                         │
        connector-01                connector-02
        (us-east-1a)                (us-east-1b)
               │                         │
               └────────────┬────────────┘
                            │
                    EFS (shared journal)
                    or: each node has own EBS
                    + S3 (cold archive)
                            │
                    AWS Secrets Manager
                    (API keys, node keypairs)
                            │
                    AWS KMS
                    (encryption key for storage)
```

---

## Network Policy

**Inbound:**
| Port | Protocol | Source | Purpose |
|---|---|---|---|
| 9091 | HTTPS | Application | API + LLM gateway |
| 9091 | WSS | Application | WebSocket streams |

**Outbound:**
| Destination | Port | Purpose |
|---|---|---|
| LLM providers | 443 | OpenAI, Anthropic, etc. |
| AWS KMS | 443 | Key operations |
| Secrets Manager | 443 | Secret retrieval |
| Peer nodes | 9091 | Cluster gossip |

**No other outbound connections.** Connector does not phone home, send telemetry, or make undeclared external calls.

---

## TLS Options

```yaml
api:
  tls:
    # Option 1: Self-managed certificate
    cert: /etc/connector/tls/cert.pem
    key:  /etc/connector/tls/key.pem

    # Option 2: Let's Encrypt auto-renew
    acme:
      domain: connector.yourdomain.com
      email: ops@yourdomain.com

    # Option 3: Bring-your-own CA (enterprise PKI)
    cert: /etc/connector/tls/server.crt
    key:  /etc/connector/tls/server.key
    client_ca: /etc/connector/tls/ca.crt    # mTLS
```

---

## License Server Architecture

Connector uses a two-system topology for licensing:

```
Customer infrastructure          Connector owner infrastructure
──────────────────────           ───────────────────────────────
connector-platform               connector-license-server
(customer-hosted)      ◄────────► (owner-hosted, cloud)
  - All data stays                  - Validates entitlement
    on customer infra               - No access to customer data
  - Periodic license                - Issues time-limited tokens
    check (no data                  - Tier enforcement
    transmitted)
```

The license check transmits only: node_id (public key hash), tier, timestamp. No customer data, no agent content, no journal entries.

---

## Production Checklist

- [ ] Ed25519 keypair generated and stored in KMS (not plaintext file)
- [ ] TLS enabled with valid certificate
- [ ] `CONNECTOR_API_KEY` in secrets manager (not environment variable in K8s spec)
- [ ] `CONNECTOR_DEV_MODE` = 0 or unset
- [ ] Journal retention policy set (≥ 365 days for SOC2, ≥ 2190 days for HIPAA)
- [ ] Backup tested and recovery time measured
- [ ] HITL queue monitored (alerts if pending > threshold)
- [ ] Chain break alerts configured
- [ ] Budget alerts configured
- [ ] Log shipping to SIEM configured

---

## Next Steps

- **[63 — Hosting and Deployment](63-hosting-deployment.md)** — full deployment runbook
- **[50 — Builder: Production Guide](50-builder-production-guide.md)**
- **[53 — Global Agent Distribution](53-global-agent-distribution.md)**

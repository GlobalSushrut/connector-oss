# Deployment

> Build, Docker, connector-server, Prometheus metrics, scaling
> Source: `connector/crates/connector-server/src/`, `Dockerfile`, `docker-compose.yml`

---

## Prerequisites

| Dependency | Version | Purpose |
|-----------|---------|---------|
| Rust | 1.75+ | Build all crates |
| Python | 3.10+ | Python SDK + demos |
| maturin | latest | Build vac-ffi PyO3 wheel |
| Docker | 20+ | Container deployment |
| Node.js | 18+ | TypeScript SDK |

---

## Build

### 1. Build vac-ffi (Python bindings)

```bash
cd vac/crates/vac-ffi
maturin develop --release
cd ../../..
```

### 2. Build connector-server (Rust HTTP server)

```bash
cd connector
cargo build --release -p connector-server
# Binary: connector/target/release/connector-server
```

### 3. Build all Rust crates

```bash
# VAC workspace
cd vac && cargo build --release && cd ..

# AAPI workspace
cd aapi && cargo build --release && cd ..

# Connector workspace
cd connector && cargo build --release && cd ..
```

### 4. Install Python SDK

```bash
cd sdks/python
pip install -e .
cd ../..
```

### 5. Build TypeScript SDK

```bash
cd sdks/typescript
npm install
npm run build
cd ../..
```

---

## connector-server

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CONNECTOR_ADDR` | `0.0.0.0:8080` | Listen address |
| `DEEPSEEK_API_KEY` | — | DeepSeek API key |
| `OPENAI_API_KEY` | — | OpenAI API key (fallback) |
| `ANTHROPIC_API_KEY` | — | Anthropic API key (fallback) |
| `CONNECTOR_CONFIG` | `connector.yaml` | Config file path |
| `RUST_LOG` | `info` | Log level: trace/debug/info/warn/error |

### Running

```bash
# Development
CONNECTOR_ADDR=0.0.0.0:8080 \
DEEPSEEK_API_KEY=sk-... \
RUST_LOG=info \
./connector/target/release/connector-server

# With config file
CONNECTOR_CONFIG=./connector.yaml \
DEEPSEEK_API_KEY=sk-... \
./connector/target/release/connector-server
```

---

## Docker

### Dockerfile (multi-stage)

```dockerfile
# Stage 1: Build (rust:1.75-alpine)
FROM rust:1.75-alpine AS builder
WORKDIR /app
COPY . .
RUN cargo build --release -p connector-server

# Stage 2: Runtime (FROM scratch — ~5MB, 0 CVEs)
FROM scratch
COPY --from=builder /app/connector/target/release/connector-server /connector-server
ENTRYPOINT ["/connector-server"]
```

### Build and run

```bash
docker build -t connector-server:latest .

docker run -p 8080:8080 \
  -e DEEPSEEK_API_KEY=sk-... \
  -e CONNECTOR_ADDR=0.0.0.0:8080 \
  connector-server:latest
```

---

## docker-compose.yml

```yaml
version: '3.8'
services:
  connector:
    image: connector-server:latest
    ports:
      - "8080:8080"
    environment:
      - DEEPSEEK_API_KEY=${DEEPSEEK_API_KEY}
      - CONNECTOR_ADDR=0.0.0.0:8080
      - RUST_LOG=info
    volumes:
      - ./data:/data
      - ./connector.yaml:/connector.yaml
    restart: unless-stopped

  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
    restart: unless-stopped

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
    restart: unless-stopped
```

### prometheus.yml

```yaml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: connector
    static_configs:
      - targets: ['connector:8080']
    metrics_path: /metrics
```

```bash
docker-compose up -d
# connector-server: http://localhost:8080
# Prometheus:       http://localhost:9090
# Grafana:          http://localhost:3000
```

---

## Prometheus Metrics

9 metrics exposed at `GET /metrics`:

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `connector_requests_total` | Counter | method, path, status | Total HTTP requests |
| `connector_request_duration_seconds` | Histogram | method, path | Request latency (buckets: 0.01–10s) |
| `connector_trust_score` | Gauge | agent | Last trust score (0–100) |
| `connector_events_total` | Counter | event_type | Total ObservationEvents |
| `connector_actions_total` | Counter | outcome | Total AAPI actions (authorized/denied) |
| `connector_memory_packets_total` | Counter | packet_type | Total packets written |
| `connector_warnings_total` | Counter | — | Total warnings |
| `connector_errors_total` | Counter | — | Total errors |
| `connector_active_agents` | Gauge | — | Currently active agents |

---

## Makefile

```makefile
all:    rust python server

rust:
	cd vac && cargo build --release
	cd aapi && cargo build --release
	cd connector && cargo build --release

python:
	cd vac/crates/vac-ffi && maturin develop --release

server:
	cd connector && cargo build --release -p connector-server

docker:
	docker build -t connector-server:latest .

clean:
	cd vac && cargo clean
	cd aapi && cargo clean
	cd connector && cargo clean

fmt:
	cd vac && cargo fmt --all
	cd aapi && cargo fmt --all
	cd connector && cargo fmt --all

clippy:
	cd vac && cargo clippy --all -- -D warnings
	cd aapi && cargo clippy --all -- -D warnings
	cd connector && cargo clippy --all -- -D warnings

test:
	cd vac && cargo test --workspace
	cd aapi && cargo test --workspace
	cd connector && cargo test --workspace
```

---

## Scaling

### Single Node (default)

```
connector-server (1 instance)
  └── MemoryKernel (in-process)
        └── RedbKernelStore (local file)
```

### Multi-Node Cluster

```yaml
# connector.yaml
cluster:
  nodes: [node1:4222, node2:4222, node3:4222]
  cell_id: cell-001
  replication_factor: 2
```

```
node1: connector-server + Cell (primary)
node2: connector-server + Cell (replica)
node3: connector-server + Cell (replica)
  │
  └── vac-bus (NATS JetStream)
        └── ClusterKernelStore (replication via ReplicationOp events)
```

**Write path**: local (sync, fast) + replicate (async, background via NATS)
**Read path**: local only (fast), Merkle root verification for freshness
**Conflict resolution**: CID-addressed data is conflict-free by construction

### Scaling Tiers

| Tier | Agents | Bus | Consensus |
|------|--------|-----|-----------|
| Nano | 1–10 | InProcessBus | None |
| Micro | 10–100 | InProcessBus | None |
| Small | 100–1K | NatsBus | Raft (openraft) |
| Medium | 1K–100K | NATS JetStream | Raft |
| Large | 100K–1M | Kafka | Raft + PBFT |
| Planetary | 1M–1B | Kafka + Federation | PBFT |

---

## Test Suite

```bash
# Run all Rust tests
cd vac && cargo test --workspace      # ~353 tests
cd aapi && cargo test --workspace     # ~150 tests
cd connector && cargo test --workspace # ~187 tests

# Run Python demos
DEEPSEEK_API_KEY=sk-... python demos/python/01_hello_world.py
DEEPSEEK_API_KEY=sk-... python demos/python/02_hospital_er.py

# Run TypeScript demos
cd demos/typescript
npx ts-node 01_hello_world.ts
```

---

## Production Checklist

- [ ] Set `DEEPSEEK_API_KEY` (or other LLM provider key)
- [ ] Set `storage: redb:./data/connector.redb` (not `memory://`)
- [ ] Set `security.signing: true`
- [ ] Set `security.data_classification` appropriate for your data
- [ ] Set `security.retention_days` per your compliance requirements
- [ ] Set `firewall.preset: strict` or `hipaa` for regulated data
- [ ] Configure `comply:` list for your frameworks
- [ ] Set `CONNECTOR_ADDR` to bind only on required interfaces
- [ ] Mount `/data` volume for persistence in Docker
- [ ] Configure Prometheus scraping for `GET /metrics`
- [ ] Set `RUST_LOG=warn` in production (not `debug`)
- [ ] Enable `cluster:` config for high availability

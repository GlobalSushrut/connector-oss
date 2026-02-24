# TypeScript SDK

> connector-server REST API, TypeScript SDK, fromConfig
> Source: `connector/crates/connector-server/src/`, `sdks/typescript/src/`

---

## Architecture

```
TypeScript code
    ↓
sdks/typescript/src/   (REST client — fetch())
    ↓
connector-server       (axum HTTP server, port 8080)
    ↓
connector-api (Rust)   (Ring 4 — developer API)
    ↓
connector-engine (Rust) (Ring 3 — orchestration)
    ↓
vac-core MemoryKernel (Rust) (Ring 1 — memory kernel)
```

The TypeScript SDK communicates with the Rust `connector-server` via REST. No WASM required — the server handles all kernel operations.

---

## connector-server

```rust
// connector/crates/connector-server/src/main.rs
// Listens on CONNECTOR_ADDR env var, default: 0.0.0.0:8080
```

### Routes

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/run` | Run a single agent |
| `POST` | `/pipeline` | Run a multi-agent pipeline |
| `POST` | `/config/parse` | Parse and validate a YAML config |
| `GET` | `/health` | Health check |
| `GET` | `/metrics` | Prometheus metrics |

---

### POST /run

**Request**:
```json
{
  "agent": "triage",
  "message": "Patient: 45M, chest pain 2h, BP 158/95",
  "user_id": "patient:P-001",
  "instructions": "Classify patients by urgency 1-5.",
  "config": {
    "provider": "deepseek",
    "model": "deepseek-chat",
    "api_key": "sk-..."
  }
}
```

**Response**:
```json
{
  "text": "Urgency 1. Differentials: ACS (I21.3)...",
  "trust": 87,
  "trust_grade": "A",
  "cid": "bafyreigima...",
  "trace_id": "pipe:triage:a3f8c1",
  "ok": true,
  "verified": true,
  "warnings": [],
  "errors": [],
  "duration_ms": 1243,
  "provenance": {
    "kernel_verified": 4,
    "llm_unverified": 1,
    "total": 5,
    "trust_percentage": 80.0
  }
}
```

---

### POST /pipeline

**Request**:
```json
{
  "pipeline": "er_pipeline",
  "message": "New patient arrival",
  "user_id": "patient:P-001",
  "config": { ... },
  "actors": [
    { "name": "triage", "role": "writer", "instructions": "..." },
    { "name": "doctor", "role": "tool_agent", "memory_from": ["triage"] }
  ],
  "flow": "triage -> doctor",
  "compliance": ["hipaa"]
}
```

---

### POST /config/parse

**Request**: raw YAML string in body

**Response**:
```json
{
  "valid": true,
  "config": { ... },
  "errors": [],
  "warnings": ["No storage configured, using memory://"]
}
```

---

### GET /health

```json
{
  "status": "ok",
  "version": "0.1.0",
  "kernel_packets": 42,
  "kernel_agents": 3,
  "uptime_secs": 3600
}
```

---

### GET /metrics (Prometheus)

9 metrics exposed:

| Metric | Type | Description |
|--------|------|-------------|
| `connector_requests_total` | Counter | Total HTTP requests |
| `connector_request_duration_seconds` | Histogram | Request latency |
| `connector_trust_score` | Gauge | Last trust score |
| `connector_events_total` | Counter | Total ObservationEvents |
| `connector_actions_total` | Counter | Total AAPI actions |
| `connector_memory_packets_total` | Counter | Total packets written |
| `connector_warnings_total` | Counter | Total warnings |
| `connector_errors_total` | Counter | Total errors |
| `connector_active_agents` | Gauge | Currently active agents |

---

## TypeScript SDK

### Installation

```bash
cd sdks/typescript
npm install
npm run build
```

### Connector Class

```typescript
// sdks/typescript/src/connector.ts
import { Connector } from '@connector-oss/connector';

// From explicit config
const c = new Connector({
  provider: 'deepseek',
  model: 'deepseek-chat',
  apiKey: process.env.DEEPSEEK_API_KEY!,
  baseUrl: 'http://localhost:8080',  // connector-server URL
});

// From YAML file
const c = await Connector.fromConfig('./connector.yaml');
// → reads file → POST /config/parse → returns Connector

// From YAML string
const c = await Connector.fromConfigStr(yamlString);
```

### Agent

```typescript
// sdks/typescript/src/agent.ts
const agent = c.agent('triage', 'Classify patients by urgency 1-5.');

const result = await agent.run(
  'Patient: 45M, chest pain 2h, BP 158/95',
  'patient:P-001'
);

console.log(result.text);          // LLM response
console.log(result.trust);         // 87
console.log(result.trustGrade);    // "A"
console.log(result.cid);           // "bafyreigima..."
console.log(result.ok);            // true
console.log(result.verified);      // true
console.log(result.warnings);      // string[]
console.log(result.durationMs);    // 1243
```

### Pipeline

```typescript
// sdks/typescript/src/pipeline.ts
const pipeline = c.pipeline('er_pipeline')
  .compliance(['hipaa'])
  .actor('triage', a => a
    .instructions('Classify patients')
    .role('writer')
  )
  .actor('doctor', a => a
    .role('tool_agent')
    .memoryFrom(['triage'])
  )
  .flow('triage -> doctor');

const result = await pipeline.run(
  'New patient: chest pain',
  'patient:P-001'
);
```

---

## TypeScript Types

```typescript
// sdks/typescript/src/types.ts

interface PipelineOutput {
  text:        string;
  trust:       number;
  trustGrade:  string;
  cid:         string;
  traceId:     string;
  ok:          boolean;
  verified:    boolean;
  warnings:    string[];
  errors:      string[];
  durationMs:  number;
  provenance:  ProvenanceSummary;
  aapi:        AapiSummary;
  memory:      MemorySummary;
}

interface ProvenanceSummary {
  kernelVerified:  number;
  llmUnverified:   number;
  total:           number;
  trustPercentage: number;
}

interface AapiSummary {
  actionsAuthorized:  number;
  actionsDenied:      number;
  capabilitiesIssued: number;
  budgetTokensUsed:   number;
  budgetCostUsd:      number;
}

interface MemorySummary {
  packetsWritten:  number;
  packetsRead:     number;
  namespacesUsed:  string[];
  totalTokens:     number;
}
```

---

## tsconfig.json

```json
{
  "compilerOptions": {
    "target": "ES2020",
    "module": "commonjs",
    "lib": ["ES2020"],
    "strict": true,
    "esModuleInterop": true,
    "outDir": "./dist",
    "rootDir": "./src",
    "typeRoots": ["../../sdks/typescript/node_modules/@types"]
  }
}
```

`@types/node` must be installed in `sdks/typescript/node_modules/@types` for Node.js type resolution.

---

## Running connector-server

```bash
# Build
cd connector && cargo build --release -p connector-server

# Run
CONNECTOR_ADDR=0.0.0.0:8080 \
DEEPSEEK_API_KEY=sk-... \
./target/release/connector-server

# Docker
docker run -p 8080:8080 \
  -e DEEPSEEK_API_KEY=sk-... \
  connector-server:latest
```

---

## Demo Files

| File | Description |
|------|-------------|
| `demos/typescript/01_hello_world.ts` | Basic agent + kernel memory + CID provenance |
| `demos/typescript/02_pipeline.ts` | Multi-agent pipeline demo |

# Code Dictionary — TypeScript

> Every TypeScript pattern explained: what to write, what it does, what you get back.
> Covers simple chatbot → enterprise pipeline → military-grade secure agent.

---

## How to Read This Dictionary

Each entry shows:
1. **The code** — exact, copy-pasteable
2. **What it does** — plain English
3. **What you get back** — exact fields and types
4. **When to use it** — the right scenario

---

## Setup

```bash
# 1. Start the Rust connector-server
cd connector && cargo build --release -p connector-server
DEEPSEEK_API_KEY=sk-... ./target/release/connector-server
# Server listens on http://localhost:8080

# 2. Install TypeScript SDK
cd sdks/typescript && npm install && npm run build
```

```typescript
import { Connector } from '@connector-oss/connector';
```

---

## Pattern 1 — Hello World (3 lines)

```typescript
const c = new Connector({ provider: 'deepseek', model: 'deepseek-chat', apiKey: process.env.DEEPSEEK_API_KEY! });
const agent = c.agent('bot', 'You are a helpful assistant.');
const result = await agent.run('What is 2+2?', 'user:alice');
console.log(result.text);
```

**What you get back:**
```typescript
result.text          // string — LLM response
result.trust         // number — 0-100
result.trustGrade    // string — "A+" | "A" | "B" | "C" | "D" | "F"
result.ok            // boolean
result.verified      // boolean
result.cid           // string — CID of response packet
result.traceId       // string
result.durationMs    // number
result.warnings      // string[]
result.errors        // string[]
```

**When to use:** Any simple chatbot, FAQ bot, internal tool.

---

## Pattern 2 — Load from YAML

```typescript
// connector.yaml has all config — no secrets in code
const c = await Connector.fromConfig('./connector.yaml');
// → reads file → POST /config/parse → validates → returns Connector
// Throws ConfigError if required field missing or env var not set

const agent = c.agent('bot', 'You are helpful.');
const result = await agent.run('Hello!', 'user:alice');
console.log(result.text);
```

**When to use:** All production code. Never hardcode API keys.

---

## Pattern 3 — Load from YAML String

```typescript
const yaml = `
connector:
  provider: deepseek
  model: deepseek-chat
  api_key: \${DEEPSEEK_API_KEY}
  storage: redb:./data/agent.redb
  comply: [hipaa]
`;

const c = await Connector.fromConfigStr(yaml);
const result = await c.agent('bot', 'You are helpful.').run('Hello!', 'user:alice');
```

**When to use:** Dynamic config generation, testing, config from database.

---

## Pattern 4 — Multi-Agent Pipeline

```typescript
const c = new Connector({
  provider: 'deepseek',
  model: 'deepseek-chat',
  apiKey: process.env.DEEPSEEK_API_KEY!,
  baseUrl: 'http://localhost:8080',  // connector-server URL
});

// Build pipeline
const pipeline = c.pipeline('er_pipeline')
  .compliance(['hipaa'])
  .actor('triage', a => a
    .instructions('Classify patients by urgency 1-5.')
    .role('writer')
  )
  .actor('doctor', a => a
    .instructions('Diagnose based on triage data.')
    .role('tool_agent')
    .memoryFrom(['triage'])   // doctor reads triage namespace
  )
  .actor('pharmacist', a => a
    .instructions('Verify and dispense medication.')
    .requireApproval(['dispense_medication'])
    .memoryFrom(['triage', 'doctor'])
  )
  .flow('triage -> doctor -> pharmacist');

const result = await pipeline.run(
  'Patient: 45M, chest pain 2h, BP 158/95',
  'patient:P-001'
);

console.log(`Response: ${result.text}`);
console.log(`Trust:    ${result.trust}/100 (${result.trustGrade})`);
console.log(`Verified: ${result.verified}`);
```

**What `.memoryFrom()` does:** The `doctor` agent gets read access to `ns:triage` — it sees all packets the triage agent wrote. Without this, cross-namespace reads are denied.

---

## Pattern 5 — Check Trust and Provenance

```typescript
const result = await agent.run('Summarize patient history', 'patient:P-001');

console.log(`Trust: ${result.trust}/100 (${result.trustGrade})`);
console.log(`Verified: ${result.verified}`);

// Provenance breakdown
const prov = result.provenance;
console.log(`Kernel-verified: ${prov.kernelVerified}/${prov.total}`);
console.log(`Trust %: ${prov.trustPercentage.toFixed(1)}%`);

// AAPI summary
const aapi = result.aapi;
console.log(`Actions authorized: ${aapi.actionsAuthorized}`);
console.log(`Actions denied:     ${aapi.actionsDenied}`);
console.log(`Cost: $${aapi.budgetCostUsd.toFixed(4)}`);

// Memory summary
const mem = result.memory;
console.log(`Packets written: ${mem.packetsWritten}`);
console.log(`Namespaces used: ${mem.namespacesUsed.join(', ')}`);
```

---

## Pattern 6 — Error Handling

```typescript
import { Connector, ConnectorError } from '@connector-oss/connector';

try {
  const result = await agent.run('Diagnose patient', 'patient:P-001');

  if (!result.ok) {
    console.error('Agent failed:', result.errors);
    return;
  }

  if (result.warnings.length > 0) {
    console.warn('Warnings:', result.warnings);
  }

  // Hard gate for regulated use cases
  if (!result.verified) {
    throw new Error('Output not kernel-verified — cannot use in regulated context');
  }

  if (result.trust < 70) {
    throw new Error(`Trust score ${result.trust} below minimum threshold`);
  }

  console.log(result.text);

} catch (e) {
  if (e instanceof ConnectorError) {
    switch (e.code) {
      case 'FIREWALL_BLOCKED':
        console.error('Firewall blocked:', e.message);
        break;
      case 'BUDGET_EXCEEDED':
        console.error('Budget exceeded:', e.message);
        break;
      case 'POLICY_DENIED':
        console.error('Policy denied:', e.message);
        break;
      default:
        console.error('Connector error:', e.message);
    }
  } else {
    throw e;
  }
}
```

---

## Pattern 7 — REST API Direct (No SDK)

The TypeScript SDK is a thin wrapper over the REST API. You can call it directly from any language or tool:

```typescript
// POST /run — single agent
const response = await fetch('http://localhost:8080/run', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    agent: 'triage',
    message: 'Patient: 45M, chest pain 2h, BP 158/95',
    user_id: 'patient:P-001',
    instructions: 'Classify patients by urgency 1-5.',
    config: {
      provider: 'deepseek',
      model: 'deepseek-chat',
      api_key: process.env.DEEPSEEK_API_KEY,
    }
  })
});

const result = await response.json();
console.log(result.text);
console.log(`Trust: ${result.trust}/100 (${result.trust_grade})`);
console.log(`CID: ${result.cid}`);
```

**What the server returns:**
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

## Pattern 8 — POST /pipeline (Multi-Agent via REST)

```typescript
const response = await fetch('http://localhost:8080/pipeline', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    pipeline: 'er_pipeline',
    message: 'New patient: chest pain',
    user_id: 'patient:P-001',
    config: {
      provider: 'deepseek',
      model: 'deepseek-chat',
      api_key: process.env.DEEPSEEK_API_KEY,
    },
    actors: [
      { name: 'triage', role: 'writer', instructions: 'Classify urgency 1-5.' },
      { name: 'doctor', role: 'tool_agent', memory_from: ['triage'],
        instructions: 'Diagnose based on triage data.' }
    ],
    flow: 'triage -> doctor',
    compliance: ['hipaa']
  })
});

const result = await response.json();
```

---

## Pattern 9 — Config Validation

```typescript
// Validate a YAML config before deploying
const yamlContent = fs.readFileSync('./connector.yaml', 'utf-8');

const response = await fetch('http://localhost:8080/config/parse', {
  method: 'POST',
  headers: { 'Content-Type': 'text/plain' },
  body: yamlContent
});

const validation = await response.json();
// {
//   "valid": true,
//   "config": { ... },
//   "errors": [],
//   "warnings": ["No storage configured, using memory://"]
// }

if (!validation.valid) {
  console.error('Config errors:', validation.errors);
  process.exit(1);
}
console.log('Config valid ✅');
```

---

## Pattern 10 — Health Check and Metrics

```typescript
// Health check
const health = await fetch('http://localhost:8080/health').then(r => r.json());
// {
//   "status": "ok",
//   "version": "0.1.0",
//   "kernel_packets": 42,
//   "kernel_agents": 3,
//   "uptime_secs": 3600
// }
console.log(`Server: ${health.status}, packets: ${health.kernel_packets}`);

// Prometheus metrics (plain text)
const metrics = await fetch('http://localhost:8080/metrics').then(r => r.text());
console.log(metrics);
// connector_requests_total{method="POST",path="/run",status="200"} 47
// connector_trust_score{agent="triage"} 87
// connector_memory_packets_total{packet_type="extraction"} 12
// ...
```

---

## Pattern 11 — Healthcare HIPAA Pipeline

```typescript
import { Connector } from '@connector-oss/connector';

async function runERPipeline(patientInput: string, patientId: string) {
  // Load HIPAA config
  const c = await Connector.fromConfig('./hospital.yaml');
  // hospital.yaml: comply=[hipaa], signing=true, data_classification=PHI

  // Build ER pipeline
  const pipeline = c.pipeline('er')
    .compliance(['hipaa'])
    .actor('triage', a => a
      .instructions('Classify patients by urgency 1-5. Cite vitals.')
      .role('writer')
    )
    .actor('doctor', a => a
      .instructions('Diagnose. Provide ICD-10 codes. Cite triage data.')
      .role('tool_agent')
      .memoryFrom(['triage'])
    )
    .flow('triage -> doctor');

  const result = await pipeline.run(patientInput, patientId);

  // Compliance gate
  if (!result.verified) {
    throw new Error('Pipeline output not verified — cannot use in clinical context');
  }

  return {
    diagnosis: result.text,
    trust: result.trust,
    grade: result.trustGrade,
    cid: result.cid,           // immutable proof of this diagnosis
    auditTrail: result.provenance,
  };
}

// Usage
const diagnosis = await runERPipeline(
  '45M, chest pain 2h, radiating to left arm, diaphoresis, BP 158/95, HR 102',
  'patient:P-44291'
);
console.log(`Diagnosis: ${diagnosis.diagnosis}`);
console.log(`Trust: ${diagnosis.trust}/100 (${diagnosis.grade})`);
console.log(`CID (immutable proof): ${diagnosis.cid}`);
```

---

## Pattern 12 — Finance Compliance Pipeline

```typescript
async function analyzeFraud(transaction: string, userId: string) {
  const c = await Connector.fromConfig('./finance.yaml');
  // finance.yaml: comply=[soc2, gdpr], signing=true, pii_types=[credit_card, ssn]

  const result = await c.agent('fraud_analyzer',
    'Analyze transactions for fraud. Output: risk_score (0-100), indicators, recommendation.'
  ).run(transaction, userId);

  // Reject if trust too low
  if (result.trust < 80) {
    return { decision: 'MANUAL_REVIEW', reason: `Trust score ${result.trust} below threshold` };
  }

  // Parse structured output
  const analysis = JSON.parse(result.text);  // assumes LLM returns JSON

  return {
    decision: analysis.recommendation,   // "approve" | "review" | "block"
    riskScore: analysis.risk_score,
    indicators: analysis.indicators,
    evidence: result.cid,                 // CID = immutable audit evidence
    trustScore: result.trust,
  };
}
```

---

## Pattern 13 — Military-Grade Secure Agent

```typescript
async function analyzeIntelligence(report: string, operatorId: string) {
  // Air-gapped: local Ollama, no external calls
  const c = new Connector({
    provider: 'ollama',
    model: 'llama3.2',
    apiKey: 'local',
    baseUrl: 'http://localhost:8080',  // connector-server (local)
    // For full DoD config: use fromConfig('./dod.yaml')
  });

  const result = await c.agent('intel_analyst',
    'Analyze intelligence reports. Cite all sources. Never speculate without evidence.'
  ).run(report, operatorId);

  // Hard security gates
  if (!result.ok) {
    throw new Error(`Analysis failed: ${result.errors.join(', ')}`);
  }
  if (!result.verified) {
    throw new Error('SECURITY: Output not kernel-verified — cannot use');
  }
  if (result.trust < 90) {
    throw new Error(`SECURITY: Trust score ${result.trust} below DoD threshold (90)`);
  }
  if (result.warnings.length > 0) {
    console.warn('SECURITY WARNINGS:', result.warnings);
  }

  return {
    analysis: result.text,
    trustScore: result.trust,
    grade: result.trustGrade,
    cid: result.cid,           // chain-of-custody proof
    durationMs: result.durationMs,
  };
}
```

---

## Pattern 14 — Streaming Output (Server-Sent Events)

```typescript
// When streaming: true in connector.yaml
const response = await fetch('http://localhost:8080/run', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    agent: 'bot',
    message: 'Write a detailed analysis...',
    user_id: 'user:alice',
    stream: true,
    config: { provider: 'deepseek', model: 'deepseek-chat', api_key: process.env.DEEPSEEK_API_KEY }
  })
});

const reader = response.body!.getReader();
const decoder = new TextDecoder();

while (true) {
  const { done, value } = await reader.read();
  if (done) break;

  const chunk = decoder.decode(value);
  const lines = chunk.split('\n').filter(l => l.startsWith('data: '));

  for (const line of lines) {
    const data = JSON.parse(line.slice(6));
    if (data.type === 'token') {
      process.stdout.write(data.text);
    } else if (data.type === 'done') {
      console.log(`\nTrust: ${data.trust}/100 (${data.trust_grade})`);
      console.log(`CID: ${data.cid}`);
    }
  }
}
```

---

## Complete Type Reference

```typescript
// Connector
new Connector(config: ConnectorConfig)
Connector.fromConfig(path: string): Promise<Connector>
Connector.fromConfigStr(yaml: string): Promise<Connector>
c.agent(name: string, instructions: string): AgentBuilder
c.pipeline(name: string): PipelineBuilder

// ConnectorConfig
interface ConnectorConfig {
  provider:  string;
  model:     string;
  apiKey:    string;
  baseUrl?:  string;   // default: "http://localhost:8080"
  endpoint?: string;   // LLM API base URL override
}

// AgentBuilder
agent.run(message: string, userId: string): Promise<PipelineOutput>
agent.remember(text: string, userId: string): Promise<string>  // returns CID
agent.recall(query: string, userId: string): Promise<MemPacket[]>

// PipelineBuilder
pipeline.compliance(frameworks: string[]): PipelineBuilder
pipeline.actor(name: string, builder: (a: ActorBuilder) => ActorBuilder): PipelineBuilder
pipeline.flow(route: string): PipelineBuilder
pipeline.run(message: string, userId: string): Promise<PipelineOutput>

// ActorBuilder
a.instructions(text: string): ActorBuilder
a.role(role: string): ActorBuilder
a.memoryFrom(namespaces: string[]): ActorBuilder
a.requireApproval(tools: string[]): ActorBuilder

// PipelineOutput
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

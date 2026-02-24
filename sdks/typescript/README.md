# Connector TypeScript SDK

Trusted Memory for AI Agents — TypeScript SDK.

Uses napi-rs v3 native bindings (Node.js) with WASM fallback (browser).
Until napi-rs bindings are built, uses the REST API as transport.

## Install

```bash
npm install @connector-oss/connector
```

## Quick Start

```typescript
import { Connector } from '@connector-oss/connector'

const c = new Connector({ llm: 'openai:gpt-4o', apiKey: 'sk-...' })
const agent = c.agent('assistant', 'You help users')
const result = await agent.run('What is Rust?', { user: 'alice' })

console.log(result.text)
console.log(result.trust)      // 92
console.log(result.trustGrade) // "A"
```

## Pipeline

```typescript
const pipe = c.pipeline('support')
  .agent('triage', 'Classify tickets')
  .agent('resolver', 'Find answers')
  .route('triage -> resolver')
  .hipaa()

const result = await pipe.run('My account is locked', { user: 'bob' })
```

## License

Apache-2.0

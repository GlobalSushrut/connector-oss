# @connector-oss/connector — TypeScript SDK

> Tamper-proof memory, chain-of-custody, and OS-grade runtime for AI agents.
> Native Rust via NAPI-RS — ~35 async methods. Falls back to HTTP if native addon is unavailable.

## Install

```bash
npm install @connector-oss/connector
```

Prebuilt native binaries for:
- Linux x86_64 (glibc + musl) / aarch64 (glibc + musl)
- macOS x86_64 / Apple Silicon (aarch64)
- Windows x86_64

If no prebuilt binary is available, the SDK falls back to HTTP REST calls automatically.

## Quick Start

```typescript
import { Connector, isNativeAvailable } from '@connector-oss/connector'

console.log('Native Rust:', isNativeAvailable()) // true if .node addon loaded

const c = new Connector({
  llm: 'deepseek:deepseek-chat',
  apiKey: process.env.DEEPSEEK_API_KEY
})

console.log(c.isNative) // true = calls Rust directly, no server needed
```

### From YAML Config

```typescript
const c = Connector.fromConfig('connector.yaml')
```

## Memory & Knowledge

```typescript
// Write tamper-proof memory (CID-addressed)
await c.remember('pid:bot', 'Patient has fever', 'nurse')

// Search memory
const mems = await c.memories('ns:er')

// Knowledge graph
await c.knowledgeIngest('ns:er')
```

## Sessions & Search

```typescript
const sess = await c.sessionCreate('pid:bot', 'ns:er', 'ER Visit')
await c.sessionClose('pid:bot', sess.session_id)

const results = await c.search({ namespace: 'ns:er', limit: 10 })
```

## Custom Folders (OS mkdir model)

```typescript
await c.folderCreate('agent:nurse/notes', 'agent', 'nurse', 'Patient notes')
await c.folderPut('agent:nurse/notes', 'p123', { bp: '140/90' })
const val = await c.folderGet('agent:nurse/notes', 'p123')
```

## Connector Protocol (CP/1.0)

```typescript
const info = await c.protocolInfo()           // 7-layer summary
const caps = await c.protocolCapabilities()   // 120 capabilities × 12 categories
await c.protocolIdentityRegister('robot-1', 'machine')
await c.protocolEstop('operator', 'safety violation', 'global')
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

## What Makes This Different

| | LangChain.js | Vercel AI | **@connector-oss/connector** |
|-|-------------|-----------|------------------------------|
| Tamper-proof memory | ❌ | ❌ | ✅ CID-addressed, kernel-verified |
| Audit trail | ❌ | ❌ | ✅ Ed25519-signed, append-only |
| HIPAA/SOC2/GDPR | ❌ | ❌ | ✅ Built-in compliance |
| Trust scoring | ❌ | ❌ | ✅ Per-response, 0-100 |
| Native Rust performance | ❌ | ❌ | ✅ NAPI-RS, zero JS overhead |
| Protocol (A2A/MCP/ACP) | Partial | ❌ | ✅ All three + CP/1.0 |

## Links

- [QUICKSTART.md](https://github.com/GlobalSushrut/connector-oss/blob/main/QUICKSTART.md)
- [ARCHITECTURE.md](https://github.com/GlobalSushrut/connector-oss/blob/main/ARCHITECTURE.md)
- [GitHub](https://github.com/GlobalSushrut/connector-oss)

## License

Apache-2.0

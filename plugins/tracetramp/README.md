# TraceTramp

**Runtime proxy and execution control plane for AI agents**

A Connector plugin providing enterprise-grade observability and governance for AI workloads.

## Architecture

Think of TraceTramp as a **segment in the water line**: everything flows through one ingress where you **meter** usage, **filter** policy/PII risk, and can **quarantine** (operation blocks, session quarantine) with **git-like** governance (policies and blocks are versioned artifacts; **revoke** / release is an explicit forward action — operators can drive it from the TUI/API when needed, but day-to-day traffic does not require toggling modes).

TraceTramp operates two planes:

- **Data Plane** (`:9741`): API proxy — **Control** pipeline is the default (enforcement **and** full observability: `trace_events`, decision trees, exports).
- **Management Plane** (`:9742`): Admin API for tenants, policies, budgets, operation blocks / approvals

### Control vs optional View

| Path | What it does | When |
|------|----------------|------|
| **Control** (default) | **Enforcement + observation in parallel** on the same request (meter, filter, quarantine hooks, `trace_events`, decision trees, exports). Responses include `X-TraceTramp-Lanes: control,observe`. | All production traffic; this is the main product path |
| **View** (optional) | Passthrough diagnostics without Control enforcement | **Off by default.** Set `TRACETRAMP_ALLOW_VIEW_PIPELINE=1` and send header `X-TraceTramp-Pipeline: view` only in lab/debug |

You do **not** pick “observability OR enforcement”: Control carries observability. View is an explicit escape hatch for engineers, not a second production lane.

### Three Planes

- **Data Plane**: HTTP ingress, request normalization, **Control** pipeline (default)
- **Management Plane**: Tenants, providers, RBAC, budgets, policies, block space
- **Evidence Plane**: Trace, explain, prove, cost attribution (fed by Control)

## Quick Start

```bash
# Copy environment config
cp .env.example .env
# Edit .env with your settings

# Run migrations
cargo sqlx migrate run

# Start TraceTramp
cargo run
```

## API Endpoints

### Data Plane (Port 9741)

**OpenAI-compatible**
- `POST /v1/chat/completions` - Chat completions with tracing
- `POST /v1/embeddings` - Text embeddings
- `GET /v1/models` - List available models
- `POST /v1/messages` - Anthropic-style messages
- `POST /v1/responses` - OpenAI responses API

**Universal Provider Endpoint**
- `POST /v1/unified/completions` - Provider-agnostic completions (auto-routes to best provider)

**Tool Execution**
- `POST /v1/tools/invoke` - Execute any tool (OpenAI functions, MCP, custom)
- `POST /v1/tools/invoke/:tool_name` - Execute specific tool
- `POST /v1/tools/batch` - Batch tool execution

**Function Execution (OpenFaaS, Lambda, Docker)**
- `POST /v1/functions/:name/call` - Call serverless function
- `POST /v1/functions/:name/async` - Async function invocation

**Evidence**
- `GET /trace/:trace_id` - Full execution trace
- `GET /explain/:request_id` - Decision explanations
- `GET /prove/:request_id` - Integrity proof
- `GET /cost/:request_id` - Cost attribution

**Compliance export (data plane)**

- `GET /v1/compliance/export` — tenant-scoped interaction export for GRC / SIEM.
- **Query:** `tenant_id` (string), `start_date` / `end_date` (ISO 8601 UTC), `format` = `csv` | `json` | `html` | `pdf`, optional `include_raw=true` (full target/status text instead of truncated previews).
- **`html`:** full print-styled HTML (`connector-report-pdf`); operators can **Print → Save as PDF** in a browser with no server-side renderer.
- **`pdf`:** same HTML rendered to bytes via headless Chromium or `wkhtmltopdf` when installed on the host; use `html` in locked-down images without those binaries.

**Workflows / Pipelines (Agentic Execution)**
- `POST /v1/workflows` - Create workflow definition
- `GET /v1/workflows` - List workflows
- `POST /v1/workflows/:id/run` - Execute workflow
- `POST /v1/workflows/:id/trigger` - Trigger workflow via event
- `GET /v1/runs/:run_id` - Get workflow run status
- `POST /v1/runs/:run_id/cancel` - Cancel workflow
- `POST /v1/runs/:run_id/resume` - Resume paused workflow

**Pipeline Orchestration**
- `POST /v1/pipelines/submit` - Submit complex pipeline
- `GET /v1/pipelines/:id/status` - Pipeline status

**Streaming**
- `GET /v1/stream/:stream_id` - SSE streaming for long-running tasks

### Management Plane (Port 9742)

**Tenants**
- `GET /admin/tenants` - List tenants
- `POST /admin/tenants` - Create tenant
- `GET /admin/tenants/:id` - Get tenant
- `POST /admin/tenants/:id/api-keys` - Create tenant API key (returns value once, PBKDF2 hash stored)
- `POST /admin/tenants/:tenant_id/api-keys/:key_id/rotate` - Rotate API key and revoke previous key

**Providers**
- `GET /admin/providers` - List providers
- `POST /admin/providers` - Add provider (OpenAI, Anthropic, Azure, Ollama)

**Policies**
- `GET /admin/policies` - List policies
- `POST /admin/policies` - Create policy bundle

**Budgets**
- `GET /admin/budgets` - List budgets
- `POST /admin/budgets` - Set budget limits

**Operation-scoped blocks** (data plane enforces before LLM/tools; “git-like” revoke = release)

- `GET /admin/operation-blocks?tenant_id=` — list active blocks (admin JWT).
- `POST /admin/operation-blocks` — create/update block (`tenant_id`, `actor_id`, `operation_key`, e.g. `llm.chat`, `tool:bash`).
- `POST /admin/operation-blocks/release` — deactivate block (`tenant_id`, `actor_id`, `operation_key`). When WitnessCtl handoff is configured on TraceTramp, a **`operation_block_released`** payload may be sent for audit.

**Decision envelope schema** (for `trace_events.metadata.decision`): `plugins/tracetramp/schemas/metadata.decision.schema.json`.

## Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `TRACETRAMP_DATA_PLANE_PORT` | Data plane HTTP port | 9741 |
| `TRACETRAMP_MANAGEMENT_PLANE_PORT` | Management plane HTTP port | 9742 |
| `TRACETRAMP_CONNECTOR_BASE_URL` | Connector kernel URL | http://localhost:9735 |
| `TRACETRAMP_DATABASE_URL` | PostgreSQL connection | postgres://localhost/tracetramp |
| `TRACETRAMP_REDIS_URL` | Redis connection | redis://localhost:6379 |
| `TRACETRAMP_CONTROL_MODE_ENABLED` | Enable policy enforcement | true |
| `TRACETRAMP_ALLOW_VIEW_PIPELINE` | Allow optional View via `X-TraceTramp-Pipeline: view` | false |

## Production Auth Requirement

In production, identity and auth must be issued/validated by Connector OS identity services.
TraceTramp JWT auth is for local/dev operations and management bootstrap only; do not treat it as the primary production identity source.

## Universal Provider Support

TraceTramp supports all major LLM providers with intelligent routing:

| Provider | Models | Tools | Streaming | Cost Optimization |
|----------|--------|-------|-----------|-------------------|
| OpenAI | GPT-4o, GPT-4o-mini, o1 | ✅ | ✅ | ✅ |
| Anthropic | Claude 3.5 Sonnet, Claude 3 Opus | ✅ | ✅ | ✅ |
| Azure OpenAI | All GPT models | ✅ | ✅ | ✅ |
| Ollama | Llama, Mistral, Qwen, etc. | ✅ | ✅ | ✅ (free) |
| Mistral | Mistral Large, Medium, Small | ✅ | ✅ | ✅ |
| Cohere | Command, Embed | ✅ | ✅ | ✅ |

**Smart Routing**: Automatically routes requests based on:
- Model capabilities required
- Cost constraints
- Latency requirements
- Token budget
- Fallback chain configuration

## Function Execution Backends

- **OpenFaaS**: Serverless functions on Kubernetes
- **AWS Lambda**: Cloud functions
- **Docker**: Containerized execution
- **WASM**: WebAssembly modules
- **Local**: Direct process execution

## Tool Ecosystem

TraceTramp supports multiple tool formats:
- **OpenAI Functions**: Native function calling
- **MCP (Model Context Protocol)**: Anthropic's tool standard
- **Anthropic Tools**: Native tool use
- **Custom REST APIs**: Any HTTP endpoint
- **GraphQL**: Schema-based queries
- **SQL**: Database queries
- **Python/JavaScript**: Inline code execution

## Project Structure

```
plugins/tracetramp/
├── src/
│   ├── main.rs              # Entry point, dual-plane server
│   ├── config.rs            # Environment configuration
│   ├── types.rs             # Core types and schemas
│   ├── error.rs             # Error handling
│   ├── connector.rs         # Connector kernel client
│   ├── storage.rs           # Postgres + Redis storage
│   ├── gateway.rs           # Data Plane HTTP router (extended API)
│   ├── resolver.rs          # Identity/tenant resolution
│   ├── view.rs              # View Pipeline (observability)
│   ├── control.rs           # Control Pipeline (enforcement)
│   ├── admin.rs             # Management Plane API
│   ├── auth.rs              # Authentication middleware
│   ├── providers/           # LLM provider implementations
│   │   ├── mod.rs
│   │   ├── unified.rs       # Smart routing
│   │   ├── openai.rs
│   │   ├── anthropic.rs
│   │   ├── azure.rs
│   │   └── ollama.rs
│   ├── workflows/           # Workflow engine
│   │   ├── mod.rs
│   │   ├── engine.rs
│   │   ├── state.rs
│   │   └── triggers.rs
│   ├── functions/           # Function execution
│   │   ├── mod.rs
│   │   ├── openfaas.rs
│   │   ├── lambda.rs
│   │   └── docker.rs
│   └── tools/               # Tool registry
├── migrations/              # Database schema
├── Cargo.toml
├── .env.example
└── README.md
```

## License

MIT

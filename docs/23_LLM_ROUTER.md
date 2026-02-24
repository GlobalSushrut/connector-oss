# LLM Router

> LlmRouter, retry, fallback, circuit breaker, cost tracking
> Source: `connector/crates/connector-engine/src/llm_router.rs`, `llm.rs`

---

## Purpose

`LlmRouter` wraps `LlmClient` with production-grade resilience. Developers configure it via YAML; the router handles all failure modes automatically.

---

## LlmClient

```rust
// connector-engine/src/llm.rs
pub struct LlmClient {
    config: LlmConfig,
}

pub struct LlmConfig {
    pub provider:  String,   // "deepseek" | "openai" | "anthropic" | "ollama" | ...
    pub model:     String,   // "deepseek-chat" | "gpt-4o" | "claude-3.5-sonnet" | ...
    pub api_key:   String,
    pub endpoint:  Option<String>,  // custom base URL (OpenAI-compatible)
    pub max_tokens: Option<u32>,
    pub temperature: Option<f32>,
}

pub struct ChatMessage {
    pub role:    String,   // "system" | "user" | "assistant"
    pub content: String,
}

pub struct LlmResponse {
    pub text:         String,
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub model:        String,
    pub finish_reason: String,
}
```

---

## LlmRouter

```rust
pub struct LlmRouter {
    primary:   LlmClient,
    fallbacks: Vec<LlmClient>,
    retry:     RetryConfig,
    breakers:  HashMap<String, CircuitBreaker>,  // provider → breaker
    costs:     HashMap<String, ProviderCost>,    // provider → cost tracker
}
```

---

## RetryConfig

```rust
pub struct RetryConfig {
    pub max_retries:        u32,     // default: 3
    pub base_delay_ms:      u64,     // default: 500ms
    pub max_delay_ms:       u64,     // default: 10_000ms (10s)
    pub retryable_statuses: Vec<u16>, // default: [429, 500, 502, 503, 504]
}
```

**Backoff formula**: `delay = min(base_delay * 2^attempt + jitter, max_delay)`

---

## Circuit Breaker

```rust
pub enum CircuitState {
    Closed,    // normal operation
    Open,      // tripped — all calls fail fast
    HalfOpen,  // cooldown expired — one probe call allowed
}

pub struct CircuitBreakerConfig {
    pub failure_threshold: u32,      // default: 5 consecutive failures to trip
    pub cooldown:          Duration, // default: 30s before HalfOpen
}
```

**State transitions**:
```
Closed → Open:     failure_threshold consecutive failures
Open → HalfOpen:   cooldown elapsed
HalfOpen → Closed: probe call succeeds
HalfOpen → Open:   probe call fails
```

---

## Fallback Chain

```
Primary provider fails (after retries + circuit open):
  → Try fallback[0]
  → If fallback[0] fails: try fallback[1]
  → ...
  → If all fail: return LlmError::AllProvidersFailed
```

**YAML configuration**:
```yaml
connector:
  provider: deepseek
  model: deepseek-chat
  api_key: ${DEEPSEEK_API_KEY}

  fallbacks:
    - provider: openai
      model: gpt-4o-mini
      api_key: ${OPENAI_API_KEY}
    - provider: ollama
      model: llama3.2
      endpoint: http://localhost:11434

  router:
    retry:
      max_retries: 3
      base_delay_ms: 500
      max_delay_ms: 10000
    circuit_breaker:
      failure_threshold: 5
      cooldown_secs: 30
```

---

## Cost Tracking

```rust
pub struct ProviderCost {
    pub provider:       String,
    pub input_tokens:   u64,
    pub output_tokens:  u64,
    pub total_cost_usd: f64,
}

// Per-million token pricing (approximate, as of 2025):
pub fn cost_per_million(provider: &str, model: &str) -> (f64, f64) {
    // Returns (input_usd_per_million, output_usd_per_million)
    match (provider, model) {
        ("deepseek", "deepseek-chat")         => (0.27, 1.10),
        ("openai",   "gpt-4o")                => (2.50, 10.00),
        ("openai",   "gpt-4o-mini")           => (0.15, 0.60),
        ("anthropic","claude-3.5-sonnet")     => (3.00, 15.00),
        ("groq",     _)                       => (0.05, 0.08),
        _                                     => (1.00, 3.00),  // default estimate
    }
}
```

**API**:
```rust
router.cost_summary()     // HashMap<String, ProviderCost>
router.total_cost_usd()   // f64 — sum across all providers
router.circuit_states()   // HashMap<String, CircuitState>
router.reset_circuits()   // reset all circuit breakers
```

---

## LlmRouter API

```rust
impl LlmRouter {
    pub fn new(primary: LlmConfig) -> Self
    pub fn with_fallback(mut self, fallback: LlmConfig) -> Self
    pub fn with_retry(mut self, config: RetryConfig) -> Self
    pub fn with_circuit_breaker(mut self, config: CircuitBreakerConfig) -> Self

    // Async chat completion
    pub async fn chat(
        &mut self,
        messages: Vec<ChatMessage>,
    ) -> Result<LlmResponse, LlmError>

    // Sync wrapper (used in connector-engine)
    pub fn complete_sync(
        &mut self,
        messages: Vec<ChatMessage>,
    ) -> Result<LlmResponse, LlmError>
}
```

---

## Supported Providers

| Provider | Models | Notes |
|----------|--------|-------|
| `deepseek` | `deepseek-chat`, `deepseek-reasoner` | OpenAI-compatible API |
| `openai` | `gpt-4o`, `gpt-4o-mini`, `o1`, `o3-mini` | |
| `anthropic` | `claude-3.5-sonnet`, `claude-3-haiku` | |
| `ollama` | any local model | set `endpoint: http://localhost:11434` |
| `groq` | `llama-3.3-70b`, `mixtral-8x7b` | |
| any | any | OpenAI-compatible endpoint via `endpoint:` field |

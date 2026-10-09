# TraceTramp Node Client

`tracetramp-client-node` is a drop-in Node wrapper for TraceTramp's cage URL.

## Quick start

```js
import { TraceTrampClient } from "./src/client.js";

const client = new TraceTrampClient({
  cageBaseUrl: "http://localhost:9741",
  apiKey: "cpk_lab_your_key"
});

const data = await client.chatCompletions({
  model: "gpt-4o-mini",
  messages: [{ role: "user", content: "hello from node" }]
});

console.log(data.choices?.[0]?.message?.content);
console.log(client.lastHeaders["x-trace-id"]);
console.log(client.lastHeaders["x-cost-usd"]);
```

## Environment setup

```js
import { fromEnv } from "./src/client.js";

const client = fromEnv();
```

Expected env vars:

- `OPENAI_BASE_URL` (default `http://localhost:9741`)
- `OPENAI_API_KEY` (required)

## Notes

- Uses OpenAI-compatible endpoint `/v1/chat/completions`.
- Returns parsed JSON and keeps last response headers for audit visibility.

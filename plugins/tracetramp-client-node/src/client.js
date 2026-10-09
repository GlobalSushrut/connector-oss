export class TraceTrampClient {
  constructor({ cageBaseUrl, apiKey, timeoutMs = 120000, fetchImpl = globalThis.fetch } = {}) {
    if (!apiKey || !String(apiKey).trim()) {
      throw new Error("apiKey is required");
    }
    if (!cageBaseUrl || !String(cageBaseUrl).trim()) {
      throw new Error("cageBaseUrl is required");
    }
    if (typeof fetchImpl !== "function") {
      throw new Error("fetch implementation is required");
    }
    this.cageBaseUrl = String(cageBaseUrl).replace(/\/+$/, "");
    this.apiKey = String(apiKey);
    this.timeoutMs = Number(timeoutMs);
    this.fetchImpl = fetchImpl;
    this.lastHeaders = {};
  }

  async chatCompletions({ model, messages, temperature, max_tokens, extra } = {}) {
    if (!model) {
      throw new Error("model is required");
    }
    if (!Array.isArray(messages) || messages.length === 0) {
      throw new Error("messages must be a non-empty array");
    }
    const payload = { model, messages };
    if (temperature !== undefined) payload.temperature = temperature;
    if (max_tokens !== undefined) payload.max_tokens = max_tokens;
    if (extra && typeof extra === "object") {
      Object.assign(payload, extra);
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const res = await this.fetchImpl(`${this.cageBaseUrl}/v1/chat/completions`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${this.apiKey}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify(payload),
        signal: controller.signal
      });
      this.lastHeaders = Object.fromEntries(res.headers.entries());
      if (!res.ok) {
        const txt = await res.text();
        throw new Error(`TraceTramp request failed (${res.status}): ${txt}`);
      }
      return await res.json();
    } finally {
      clearTimeout(timer);
    }
  }
}

export function fromEnv(env = process.env) {
  return new TraceTrampClient({
    cageBaseUrl: env.OPENAI_BASE_URL || "http://localhost:9741",
    apiKey: env.OPENAI_API_KEY || ""
  });
}

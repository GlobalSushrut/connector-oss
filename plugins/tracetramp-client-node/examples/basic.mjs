import { fromEnv } from "../src/client.js";

async function main() {
  const client = fromEnv();
  const result = await client.chatCompletions({
    model: "gpt-4o-mini",
    messages: [{ role: "user", content: "Say hello from TraceTramp cage." }]
  });
  console.log(result?.choices?.[0]?.message?.content ?? "<no content>");
  console.log("trace_id:", client.lastHeaders["x-trace-id"] ?? "-");
  console.log("cost_usd:", client.lastHeaders["x-cost-usd"] ?? "-");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

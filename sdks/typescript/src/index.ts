/**
 * connector_oss — Tamper-proof memory and chain-of-custody for AI agents.
 *
 * Install:
 *   npm install connector_oss
 *
 * Usage:
 * ```typescript
 * import { Connector } from 'connector_oss'
 *
 * const c = new Connector({
 *   provider: 'deepseek',
 *   model: 'deepseek-chat',
 *   apiKey: process.env.DEEPSEEK_API_KEY!,
 * })
 * const result = await c.agent('bot', 'You are helpful.').run('Hello!', 'user:alice')
 * console.log(result.text)        // LLM response
 * console.log(result.trust)       // 0-100 kernel-verified trust score
 * console.log(result.trustGrade)  // "A+" | "A" | "B" | "C" | "D" | "F"
 * console.log(result.cid)         // tamper-proof CID of this response
 * console.log(result.verified)    // true if all events are kernel-verified
 * ```
 *
 * The TypeScript SDK calls connector-server (Rust axum HTTP server) via REST.
 * Start the server before using:
 *   DEEPSEEK_API_KEY=sk-... connector-server
 * Or with Docker:
 *   docker run -p 8080:8080 -e DEEPSEEK_API_KEY=sk-... connector-server:latest
 */

export { Connector } from './connector'
export { Agent } from './agent'
export { Pipeline } from './pipeline'
export type { ConnectorConfig, RunOptions, PipelineResult, AgentDef } from './types'

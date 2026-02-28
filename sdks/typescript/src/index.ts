/**
 * connector_oss — Tamper-proof memory and chain-of-custody for AI agents.
 *
 * Native Rust bindings via NAPI-RS. Falls back to HTTP if native addon
 * is not built. Build native addon with: `npm run build:native`
 *
 * Usage:
 * ```typescript
 * import { Connector, isNativeAvailable } from 'connector_oss'
 *
 * console.log('native:', isNativeAvailable()) // true if .node addon is built
 *
 * // Native mode — calls Rust engine directly (no HTTP server needed)
 * const c = new Connector({
 *   llm: 'deepseek:deepseek-chat',
 *   apiKey: process.env.DEEPSEEK_API_KEY!,
 * })
 *
 * // Or from YAML config
 * const c2 = Connector.fromConfig('connector.yaml')
 *
 * const result = await c.agent('bot', 'You are helpful.').run('Hello!', { user: 'alice' })
 * console.log(result.text)        // LLM response
 * console.log(result.trust)       // 0-100 kernel-verified trust score
 * console.log(result.verified)    // true if all events are kernel-verified
 * console.log(c.isNative)         // true if using native Rust engine
 * ```
 */

export { Connector, isNativeAvailable } from './connector'
export { Agent } from './agent'
export { Pipeline } from './pipeline'
export type {
  ConnectorConfig, RunOptions, PipelineResult, AgentDef,
  MemoryPacket, MemoriesResponse, KnowledgeFact, KnowledgeQueryResponse,
  AgentInfo, AuditEntry, FolderInfo, DbStats,
} from './types'

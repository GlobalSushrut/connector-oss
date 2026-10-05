export interface ConnectorConfig {
  llm: string
  apiKey?: string
  endpoint?: string
  /** Base URL of the connector-server REST API (default: http://localhost:8080) */
  serverUrl?: string
}

export interface RunOptions {
  /** User identifier for audit (default: user:default) */
  user?: string
  /** Session ID for continuity */
  sessionId?: string
}

export interface AgentDef {
  name: string
  instructions?: string
}

export interface PipelineResult {
  text: string
  trust: number
  trustGrade: string
  ok: boolean
  durationMs: number
  actors: number
  steps: number
  eventCount: number
  spanCount: number
  traceId: string
  verified: boolean
  warnings: string[]
  errors: string[]
  provenance: Record<string, unknown>
  json: Record<string, unknown>
}

// ── Memory & Knowledge ──────────────────────────────────────────

export interface MemoryPacket {
  cid: string
  type: string
  text: string
  user: string
}

export interface MemoriesResponse {
  namespace: string
  count: number
  packets: MemoryPacket[]
}

export interface KnowledgeFact {
  text: string
  source_cid: string
  entity_id: string
  relevance_score: number
  tier: string
}

export interface KnowledgeQueryResponse {
  facts: KnowledgeFact[]
  facts_included: number
  tokens_used: number
  prompt_context: string
  entities: string[]
  source_cids: string[]
}

// ── Agents & Audit ──────────────────────────────────────────────

export interface AgentInfo {
  pid: string
  name: string
  namespace: string
  status: string
  registered_at: number
}

export interface AuditEntry {
  timestamp: number
  operation: string
  agent_pid: string
  outcome: string
  reason: string | null
  error: string | null
}

// ── Custom Folders ──────────────────────────────────────────────

export interface FolderInfo {
  namespace: string
  owner: string
  description: string
  entry_count: number
  created_at: number
}

// ── DB Stats ────────────────────────────────────────────────────

export interface DbStats {
  kernel_packets: number
  kernel_agents: number
  kernel_audit_entries: number
  engine_folders: number
  engine_tools: number
  engine_policies: number
  storage_tree: string
}

// ── Tools ────────────────────────────────────────────────────────

/**
 * Tool definition for use with agents.
 * 
 * @example
 * ```typescript
 * const search: ToolDefinition = {
 *   name: 'search',
 *   handler: async (query: string) => `Results for: ${query}`,
 *   timeout: 30,
 *   clearance: 1,
 *   description: 'Search the web',
 * }
 * ```
 */
export interface ToolDefinition {
  /** Tool name (must be unique per agent) */
  name: string
  /** Async function that implements the tool */
  handler: (...args: any[]) => Promise<any>
  /** Timeout in seconds (default: 30) */
  timeout?: number
  /** Clearance level required (default: 1) */
  clearance?: number
  /** Human-readable description */
  description?: string
}

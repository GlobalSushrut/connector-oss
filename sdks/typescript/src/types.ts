export interface ConnectorConfig {
  llm: string
  apiKey?: string
  endpoint?: string
  /** Base URL of the connector-server REST API (default: http://localhost:8080) */
  serverUrl?: string
}

export interface RunOptions {
  user: string
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

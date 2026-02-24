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

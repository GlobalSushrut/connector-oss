/**
 * Connector TypeScript SDK — native Rust bindings via NAPI-RS.
 *
 * All calls go directly into the Rust engine (no HTTP server required).
 * The native addon is built from `native/` via `npm run build:native`.
 */

import {
  ConnectorConfig, MemoriesResponse, KnowledgeQueryResponse,
  AgentInfo, AuditEntry, FolderInfo, DbStats,
} from './types'
import { Agent } from './agent'
import { Pipeline } from './pipeline'

// ── Native binding loader ──────────────────────────────────────
// NAPI-RS produces a .node file that we load at runtime.
// Falls back to HTTP mode if native addon is not available.
let native: any = null
try {
  native = require('../connector-napi.linux-x64-gnu.node')
} catch {
  try {
    native = require('../connector-napi.darwin-arm64.node')
  } catch {
    try {
      native = require('../connector-napi.darwin-x64.node')
    } catch {
      // native addon not built — will use HTTP fallback
    }
  }
}

/** True if the native Rust addon is available. */
export function isNativeAvailable(): boolean {
  return native !== null && native.NativeConnector !== undefined
}

export class Connector {
  private _native: any | null = null
  private config: ConnectorConfig
  private baseUrl: string

  constructor(config: ConnectorConfig) {
    this.config = config
    this.baseUrl = config.serverUrl || 'http://localhost:8080'

    // Try to create native connector if addon is available
    if (native?.NativeConnector && config.llm && config.apiKey) {
      const [provider, model] = config.llm.split(':')
      try {
        this._native = new native.NativeConnector(provider, model, config.apiKey)
      } catch {
        // fallback to HTTP
      }
    }
  }

  /** True if this instance is using the native Rust engine directly. */
  get isNative(): boolean {
    return this._native !== null
  }

  /**
   * Load from a connector.yaml file.
   * Uses native Rust config parser if addon is available.
   */
  static fromConfig(path: string, serverUrl = 'http://localhost:8080'): Connector {
    if (native?.NativeConnector) {
      const c = new Connector({ llm: '', serverUrl })
      c._native = native.NativeConnector.fromConfig(path)
      return c
    }
    // HTTP fallback
    const fs = require('fs')
    if (!fs.existsSync(path)) {
      throw new Error(`Config file not found: ${path}`)
    }
    return new Connector({ llm: '', serverUrl })
  }

  /**
   * Load from a YAML string.
   * Uses native Rust config parser if addon is available.
   */
  static fromConfigStr(yaml: string, serverUrl = 'http://localhost:8080'): Connector {
    if (native?.NativeConnector) {
      const c = new Connector({ llm: '', serverUrl })
      c._native = native.NativeConnector.fromConfigStr(yaml)
      return c
    }
    return new Connector({ llm: '', serverUrl })
  }

  agent(name: string, instructions: string): Agent {
    return new Agent(this, name, instructions)
  }

  pipeline(name: string): Pipeline {
    return new Pipeline(this, name)
  }

  // ═══════════════════════════════════════════════════════════════
  // All methods below: native Rust call first, HTTP fetch fallback
  // ═══════════════════════════════════════════════════════════════

  // ── Memory & Knowledge ──────────────────────────────────────

  /** Write a memory packet to the kernel. */
  async remember(agentPid: string, content: string, user: string): Promise<{ ok: boolean; cid?: string }> {
    if (this._native) {
      const cid = this._native.remember(agentPid, content, user)
      return { ok: true, cid }
    }
    const res = await fetch(`${this.baseUrl}/remember`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ agent_pid: agentPid, content, user }),
    })
    return res.json() as Promise<{ ok: boolean }>
  }

  /** List packets in a namespace. */
  async memories(namespace: string, limit = 50): Promise<MemoriesResponse> {
    if (this._native) return JSON.parse(this._native.memories(namespace, limit))
    const res = await fetch(`${this.baseUrl}/memories/${encodeURIComponent(namespace)}?limit=${limit}`)
    return res.json() as Promise<MemoriesResponse>
  }

  /** Ingest a namespace into the knowledge graph. */
  async knowledgeIngest(namespace: string): Promise<{ ok: boolean; packets_ingested: number }> {
    if (this._native) return JSON.parse(this._native.knowledgeIngest(namespace))
    const res = await fetch(`${this.baseUrl}/knowledge/ingest`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ namespace }),
    })
    return res.json() as Promise<{ ok: boolean; packets_ingested: number }>
  }

  /** RAG retrieval with entities/keywords. */
  async knowledgeQuery(opts: { entities?: string[]; keywords?: string[]; tokenBudget?: number; maxFacts?: number } = {}): Promise<KnowledgeQueryResponse> {
    if (this._native) return JSON.parse(this._native.knowledgeQuery(
      opts.entities ?? [], opts.keywords ?? [],
      opts.tokenBudget ?? 4096, opts.maxFacts ?? 20,
    ))
    const res = await fetch(`${this.baseUrl}/knowledge/query`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        entities: opts.entities ?? [], keywords: opts.keywords ?? [],
        token_budget: opts.tokenBudget ?? 4096, max_facts: opts.maxFacts ?? 20,
      }),
    })
    return res.json() as Promise<KnowledgeQueryResponse>
  }

  // ── Agents & Audit ────────────────────────────────────────────

  /** List all registered agents. */
  async agents(): Promise<{ count: number; agents: AgentInfo[] }> {
    if (this._native) return JSON.parse(this._native.agents())
    const res = await fetch(`${this.baseUrl}/agents`)
    return res.json() as Promise<{ count: number; agents: AgentInfo[] }>
  }

  /** Tail the audit log. */
  async audit(limit = 50): Promise<{ count: number; entries: AuditEntry[] }> {
    if (this._native) return JSON.parse(this._native.audit(limit))
    const res = await fetch(`${this.baseUrl}/audit?limit=${limit}`)
    return res.json() as Promise<{ count: number; entries: AuditEntry[] }>
  }

  /** Kernel trust breakdown. */
  async trust(): Promise<Record<string, unknown>> {
    if (this._native) return JSON.parse(this._native.trust())
    const res = await fetch(`${this.baseUrl}/trust`)
    return res.json() as Promise<Record<string, unknown>>
  }

  /** Packet count. */
  async packetCount(): Promise<number> {
    if (this._native) return this._native.packetCount()
    const stats = await this.dbStats()
    return stats.kernel_packets
  }

  /** Audit entry count. */
  async auditCount(): Promise<number> {
    if (this._native) return this._native.auditCount()
    const stats = await this.dbStats()
    return stats.kernel_audit_entries
  }

  /** Agent count. */
  async agentCount(): Promise<number> {
    if (this._native) return this._native.agentCount()
    const stats = await this.dbStats()
    return stats.kernel_agents
  }

  // ── Sessions ──────────────────────────────────────────────────

  /** Create a session for an agent. */
  async sessionCreate(agentPid: string, namespace: string, label?: string): Promise<{ ok: boolean; session_id: string }> {
    if (this._native) return JSON.parse(this._native.sessionCreate(agentPid, namespace, label ?? null))
    const res = await fetch(`${this.baseUrl}/sessions/create`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ agent_pid: agentPid, namespace, label }),
    })
    return res.json() as Promise<{ ok: boolean; session_id: string }>
  }

  /** Close a session. */
  async sessionClose(agentPid: string, sessionId: string): Promise<{ ok: boolean }> {
    if (this._native) return JSON.parse(this._native.sessionClose(agentPid, sessionId))
    const res = await fetch(`${this.baseUrl}/sessions/close`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ agent_pid: agentPid, session_id: sessionId }),
    })
    return res.json() as Promise<{ ok: boolean }>
  }

  // ── Search ────────────────────────────────────────────────────

  /** Search packets by namespace or session. */
  async search(opts: { namespace?: string; sessionId?: string; limit?: number } = {}): Promise<{ count: number; packets: unknown[] }> {
    if (this._native) return JSON.parse(this._native.search(
      opts.namespace ?? null, opts.sessionId ?? null, opts.limit ?? 50,
    ))
    const res = await fetch(`${this.baseUrl}/search`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        namespace: opts.namespace, session_id: opts.sessionId,
        limit: opts.limit ?? 50,
      }),
    })
    return res.json() as Promise<{ count: number; packets: unknown[] }>
  }

  // ── Custom Folders ────────────────────────────────────────────

  /** Create a namespaced storage folder. */
  async folderCreate(namespace: string, ownerType = 'system', ownerId = '', description = ''): Promise<{ ok: boolean }> {
    if (this._native) return JSON.parse(this._native.folderCreate(namespace, ownerType, ownerId, description))
    const res = await fetch(`${this.baseUrl}/folders/create`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ namespace, owner_type: ownerType, owner_id: ownerId, description }),
    })
    return res.json() as Promise<{ ok: boolean }>
  }

  /** Write a key-value pair to a folder. */
  async folderPut(namespace: string, key: string, value: unknown): Promise<{ ok: boolean }> {
    if (this._native) return JSON.parse(this._native.folderPut(namespace, key, JSON.stringify(value)))
    const res = await fetch(`${this.baseUrl}/folders/put`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ namespace, key, value }),
    })
    return res.json() as Promise<{ ok: boolean }>
  }

  /** Read a value from a folder. */
  async folderGet(namespace: string, key: string): Promise<{ ok: boolean; value: unknown }> {
    if (this._native) return JSON.parse(this._native.folderGet(namespace, key))
    const res = await fetch(`${this.baseUrl}/folders/get`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ namespace, key }),
    })
    return res.json() as Promise<{ ok: boolean; value: unknown }>
  }

  /** List all folders. */
  async folderList(): Promise<{ count: number; folders: FolderInfo[] }> {
    if (this._native) return JSON.parse(this._native.folderList())
    const res = await fetch(`${this.baseUrl}/folders/list`)
    return res.json() as Promise<{ count: number; folders: FolderInfo[] }>
  }

  // ── DB Stats ──────────────────────────────────────────────────

  /** Get engine store and kernel statistics. */
  async dbStats(): Promise<DbStats> {
    if (this._native) return JSON.parse(this._native.dbStats())
    const res = await fetch(`${this.baseUrl}/db/stats`)
    return res.json() as Promise<DbStats>
  }

  // ── Connector Protocol (CP/1.0) ──────────────────────────────

  /** Full protocol layer summary. */
  async protocolInfo(): Promise<Record<string, unknown>> {
    if (this._native) return JSON.parse(this._native.protocolInfo())
    const res = await fetch(`${this.baseUrl}/protocol/info`)
    return res.json() as Promise<Record<string, unknown>>
  }

  /** Register an entity identity. */
  async protocolIdentityRegister(entityId: string, entityClass: string): Promise<Record<string, unknown>> {
    if (this._native) return JSON.parse(this._native.protocolIdentityRegister(entityId, entityClass))
    const res = await fetch(`${this.baseUrl}/protocol/identity/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ entity_id: entityId, entity_class: entityClass }),
    })
    return res.json() as Promise<Record<string, unknown>>
  }

  /** List all 120 protocol capabilities by category. */
  async protocolCapabilities(): Promise<Record<string, unknown>> {
    if (this._native) return JSON.parse(this._native.protocolCapabilities())
    const res = await fetch(`${this.baseUrl}/protocol/capabilities`)
    return res.json() as Promise<Record<string, unknown>>
  }

  /** Check if entity class can use a capability. */
  async protocolCapabilityCheck(capabilityId: string, entityClass: string): Promise<Record<string, unknown>> {
    if (this._native) return JSON.parse(this._native.protocolCapabilityCheck(capabilityId, entityClass))
    const res = await fetch(`${this.baseUrl}/protocol/capability/check`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ capability_id: capabilityId, entity_class: entityClass }),
    })
    return res.json() as Promise<Record<string, unknown>>
  }

  /** Emergency stop (ambient capability — cannot be denied). */
  async protocolEstop(issuer: string, reason: string, scope?: string): Promise<Record<string, unknown>> {
    if (this._native) return JSON.parse(this._native.protocolEstop(issuer, reason, scope ?? null))
    const res = await fetch(`${this.baseUrl}/protocol/safety/estop`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ issuer, reason, scope }),
    })
    return res.json() as Promise<Record<string, unknown>>
  }

  /** Submit AI agent intent for goal decomposition. */
  async protocolIntent(agentId: string, goal: string, opts: {
    coordination?: string;
  } = {}): Promise<Record<string, unknown>> {
    if (this._native) return JSON.parse(this._native.protocolIntent(agentId, goal, opts.coordination ?? null))
    const res = await fetch(`${this.baseUrl}/protocol/intent`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ agent_id: agentId, goal, ...opts }),
    })
    return res.json() as Promise<Record<string, unknown>>
  }

  /** @internal — access for Agent/Pipeline subclasses */
  getNative(): any | null { return this._native }
  getConfig(): ConnectorConfig { return this.config }
  getBaseUrl(): string { return this.baseUrl }
}

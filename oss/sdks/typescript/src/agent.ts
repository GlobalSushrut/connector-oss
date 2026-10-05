/**
 * Connector TypeScript SDK — Agent Module
 * 
 * Quick Start (3 lines):
 * 
 * ```typescript
 * import { Agent } from 'connector'
 * 
 * const agent = new Agent('my-bot', 'You are helpful')
 * console.log(await agent.run('Hello!'))
 * ```
 * 
 * With Memory:
 * 
 * ```typescript
 * agent.remember('User prefers dark mode')
 * const result = await agent.run('What do you know about me?')
 * ```
 * 
 * With Tools:
 * 
 * ```typescript
 * const search = tool('search', async (query: string) => {
 *   return `Results for: ${query}`
 * })
 * const agent = new Agent('research', { tools: [search] })
 * ```
 */

import { Connector } from './connector'
import { RunOptions, ToolDefinition } from './types'

// ═══════════════════════════════════════════════════════════════════════════════
// AGENT RESULT — Rich result object with progressive disclosure
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Rich result object from agent.run().
 * 
 * Provides easy access to response text and advanced capabilities
 * like trust scoring, books ledger, and compliance reports.
 * 
 * @example
 * ```typescript
 * const result = await agent.run('Hello!')
 * console.log(result.text)       // "Hello! How can I help?"
 * console.log(result.tokens)     // 150
 * console.log(result.trust)      // 0.95
 * console.log(result.costUsd)    // 0.002
 * console.log(result.toString()) // Pretty dashboard view
 * ```
 */
export class AgentResult {
  private _data: Record<string, any>

  constructor(data: Record<string, any>) {
    this._data = data
  }

  // ── Basic Fields ──────────────────────────────────────────────────────────

  /** The agent's response text. */
  get text(): string {
    return this._data.text ?? this._data.output ?? ''
  }

  /** Total tokens used (input + output). */
  get tokens(): number {
    return this._data.tokens ?? this._data.tokens_used ?? 0
  }

  /** Response latency in milliseconds. */
  get latencyMs(): number {
    return this._data.latency_ms ?? this._data.duration_ms ?? 0
  }

  /** Estimated cost in USD. */
  get costUsd(): number {
    return this._data.cost_usd ?? this._data.cost ?? 0.0
  }

  /** Whether the request succeeded. */
  get ok(): boolean {
    return this._data.ok ?? true
  }

  // ── Advanced Fields (always present) ──────────────────────────────────────

  /**
   * Trust score (0.0 - 1.0).
   * 
   * Computed from 8 dimensions:
   * 1. Memory integrity
   * 2. Audit completeness
   * 3. Authorization coverage
   * 4. Decision provenance
   * 5. Operational health
   * 6. KECS confidence
   * 7. Claim validity
   * 8. Identity coherence
   * 
   * Learn more: docs.connector.dev/capabilities/trust
   */
  get trust(): number {
    const raw = this._data.trust ?? this._data.trust_score ?? 100
    return raw > 1 ? raw / 100.0 : raw
  }

  /** Trust grade (A+, A, B, C, D, F). */
  get trustGrade(): string {
    return this._data.trust_grade ?? this._gradeFromScore(this.trust)
  }

  /** Trace ID for debugging. Use: connector trace show <id> */
  get traceId(): string | undefined {
    return this._data.trace_id
  }

  /** List of tool calls made during this run. */
  get toolCalls(): Array<Record<string, any>> {
    return this._data.tool_calls ?? this._data.steps ?? []
  }

  // ── Enterprise Fields (if enabled) ───────────────────────────────────────

  /** Compliance report (if comply() was called). */
  get compliance(): Record<string, any> | undefined {
    return this._data.compliance ?? this._data.compliance_check
  }

  /** Books ledger entry for this operation. */
  get booksEntry(): Record<string, any> | undefined {
    return this._data.books_entry ?? this._data.journal_entry
  }

  /** Execution receipt (if using contracts). */
  get contractReceipt(): Record<string, any> | undefined {
    return this._data.contract_receipt ?? this._data.receipt
  }

  // ── Helpers ───────────────────────────────────────────────────────────────

  private _gradeFromScore(score: number): string {
    if (score >= 0.95) return 'A+'
    if (score >= 0.90) return 'A'
    if (score >= 0.80) return 'B'
    if (score >= 0.70) return 'C'
    if (score >= 0.60) return 'D'
    return 'F'
  }

  /** Check if the run succeeded. */
  isSuccess(): boolean {
    return this.ok
  }

  /** Check if the run failed. */
  isFailure(): boolean {
    return !this.ok
  }

  /** Get documentation URL for a topic. */
  learnMore(topic: string = 'result'): string {
    return `https://docs.connector.dev/capabilities/${topic}`
  }

  /** Pretty dashboard view. */
  toString(): string {
    const lines = [
      '┌' + '─'.repeat(58) + '┐',
      '│ Agent Response' + ' '.repeat(43) + '│',
      '├' + '─'.repeat(58) + '┤',
      `│ Text:    ${this.text.slice(0, 45)}${this.text.length > 45 ? '...' : ''}`.padEnd(59) + '│',
      `│ Tokens:  ${this.tokens}`.padEnd(59) + '│',
      `│ Cost:    $${this.costUsd.toFixed(4)}`.padEnd(59) + '│',
      `│ Trust:   ${Math.round(this.trust * 100)}/100 (Grade: ${this.trustGrade})`.padEnd(59) + '│',
    ]
    if (this.traceId) {
      lines.push(`│ Trace:   ${this.traceId}`.padEnd(59) + '│')
    }
    lines.push('└' + '─'.repeat(58) + '┘')
    return lines.join('\n')
  }

  /** Return the raw response data. */
  toJSON(): Record<string, any> {
    return this._data
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// AGENT CLASS — Simplified interface for building agents
// ═══════════════════════════════════════════════════════════════════════════════

export interface AgentOptions {
  /** System prompt for the agent */
  instructions?: string
  /** List of tool definitions */
  tools?: ToolDefinition[]
  /** LLM model (default: gpt-4o) */
  model?: string
  /** Connector server URL (default: localhost:8080) */
  baseUrl?: string
  /** API key (default: from OPENAI_API_KEY env) */
  apiKey?: string
}

/**
 * Simplified agent interface — the primary way to use Connector.
 * 
 * Three lines to a working agent:
 * 
 * ```typescript
 * import { Agent } from 'connector'
 * const agent = new Agent('my-bot', 'You are helpful')
 * console.log(await agent.run('Hello!'))
 * ```
 * 
 * Progressive complexity:
 * 
 * ```typescript
 * // Level 0: Hello World (3 lines)
 * const agent = new Agent('bot')
 * 
 * // Level 1: With instructions
 * const agent = new Agent('bot', 'You are helpful')
 * 
 * // Level 2: With memory
 * agent.remember('User prefers dark mode')
 * 
 * // Level 3: With tools
 * const agent = new Agent('bot', { tools: [search, sendEmail] })
 * 
 * // Level 4: With compliance
 * agent.comply('hipaa', 'phi', 'audit')
 * 
 * // Level 5: From config
 * const agent = Agent.fromConfig('connector.yaml')
 * ```
 */
export class Agent {
  private connector: Connector | null = null
  private _name: string
  private _instructions: string
  private _tools: ToolDefinition[] = []
  private _compliance: string[] = []
  private _memories: string[] = []
  private _baseUrl: string
  private _model: string

  /**
   * Create a new agent.
   * 
   * @param name - Agent identifier (e.g., "support-bot")
   * @param instructionsOrOptions - System prompt string OR options object
   */
  constructor(
    name: string,
    instructionsOrOptions?: string | AgentOptions
  ) {
    this._name = name
    
    if (typeof instructionsOrOptions === 'string') {
      this._instructions = instructionsOrOptions
      this._baseUrl = process.env.CONNECTOR_BASE_URL ?? 'http://localhost:8080'
      this._model = process.env.CONNECTOR_MODEL ?? 'gpt-4o'
    } else {
      const opts = instructionsOrOptions ?? {}
      this._instructions = opts.instructions ?? 'You are a helpful assistant.'
      this._tools = opts.tools ?? []
      this._baseUrl = opts.baseUrl ?? process.env.CONNECTOR_BASE_URL ?? 'http://localhost:8080'
      this._model = opts.model ?? process.env.CONNECTOR_MODEL ?? 'gpt-4o'
    }
  }

  /** Agent name */
  get name(): string { return this._name }

  /** Agent instructions */
  get instructions(): string { return this._instructions }

  // ── Factory Methods ───────────────────────────────────────────────────────

  /**
   * Load agent from a config file.
   * 
   * @example
   * ```typescript
   * const agent = Agent.fromConfig('connector.yaml')
   * ```
   */
  static fromConfig(path: string): Agent {
    const connector = Connector.fromConfig(path)
    const agent = new Agent('agent')
    agent.connector = connector
    return agent
  }

  /**
   * Load agent from a contract.yaml file.
   * 
   * For complex workflows with state machines and governance.
   * 
   * @example
   * ```typescript
   * const agent = Agent.fromContract('contract.yaml')
   * ```
   */
  static fromContract(path: string): Agent {
    // Load contract and create agent
    const fs = require('fs')
    const yaml = require('js-yaml')
    const content = fs.readFileSync(path, 'utf8')
    const cfg = yaml.load(content)
    
    const agent = new Agent(cfg.name ?? 'agent', cfg.description ?? '')
    ;(agent as any)._contract = cfg
    return agent
  }

  // ── Core Methods ──────────────────────────────────────────────────────────

  /**
   * Run the agent with the given input.
   * 
   * @param input - The user's message or task
   * @param options - Optional run options (user, etc.)
   * @returns AgentResult with text, trust, tokens, and more
   * 
   * @example
   * ```typescript
   * const result = await agent.run('Hello!')
   * console.log(result.text)   // "Hello! How can I help?"
   * console.log(result.trust)  // 0.95
   * ```
   */
  async run(input: string, options: RunOptions = {}): Promise<AgentResult> {
    const res = await fetch(`${this._baseUrl}/run`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        agent: this._name,
        input,
        user: options.user ?? 'user:default',
        instructions: this._instructions,
        compliance: this._compliance,
        tools: this._tools.map(t => t.name),
      }),
    })

    if (!res.ok) {
      return new AgentResult({
        text: `Error: ${res.statusText}`,
        ok: false,
        trust: 0,
      })
    }

    const data = await res.json()
    return new AgentResult(data)
  }

  // ── Memory Methods ────────────────────────────────────────────────────────

  /**
   * Store a memory for this agent.
   * 
   * @param content - The text to remember
   * @returns this (for chaining)
   * 
   * @example
   * ```typescript
   * agent.remember('User prefers dark mode')
   * agent.remember('User is a senior engineer')
   * ```
   */
  remember(content: string): Agent {
    this._memories.push(content)
    
    // Also persist to server
    fetch(`${this._baseUrl}/remember`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        agent_pid: this._name,
        content,
        user: 'user:sdk',
      }),
    }).catch(() => {}) // Fire and forget
    
    return this
  }

  /**
   * Recall memories for this agent.
   * 
   * @param query - Optional search query (semantic search)
   * @param limit - Max results to return
   * @returns List of memory strings
   * 
   * @example
   * ```typescript
   * const memories = await agent.recall()
   * const relevant = await agent.recall('preferences', 5)
   * ```
   */
  async recall(query?: string, limit: number = 20): Promise<string[]> {
    try {
      const url = new URL(`${this._baseUrl}/memories/${this._name}`)
      url.searchParams.set('limit', String(limit))
      if (query) url.searchParams.set('q', query)
      
      const res = await fetch(url.toString())
      if (!res.ok) return this._memories.slice(0, limit)
      
      const data = await res.json()
      return (data.packets ?? []).map((p: any) => p.content ?? '')
    } catch {
      // Return local memories on error
      if (query) {
        return this._memories
          .filter(m => m.toLowerCase().includes(query.toLowerCase()))
          .slice(0, limit)
      }
      return this._memories.slice(0, limit)
    }
  }

  /**
   * Get the knowledge graph extracted from memories.
   * 
   * @returns Object with 'entities' and 'relations' arrays
   * 
   * @example
   * ```typescript
   * const kg = await agent.knowledgeGraph()
   * console.log(kg.entities)   // [{ name: 'User', type: 'person' }, ...]
   * console.log(kg.relations)  // [{ from: 'User', relation: 'prefers', to: 'dark mode' }]
   * ```
   */
  async knowledgeGraph(): Promise<{ entities: any[]; relations: any[] }> {
    // Placeholder — would call kernel knowledge graph API
    return {
      entities: [],
      relations: [],
    }
  }

  // ── Compliance Methods ────────────────────────────────────────────────────

  /**
   * Enable compliance frameworks.
   * 
   * Supported frameworks:
   * - "audit" — Log all operations
   * - "hipaa" — HIPAA compliance
   * - "phi" — PHI detection and protection
   * - "gdpr" — GDPR compliance
   * - "soc2" — SOC2 controls
   * - "iso42001" — ISO 42001 AI management
   * 
   * @param frameworks - One or more framework names
   * @returns this (for chaining)
   * 
   * @example
   * ```typescript
   * agent.comply('hipaa', 'phi', 'audit')
   * ```
   */
  comply(...frameworks: string[]): Agent {
    this._compliance.push(...frameworks)
    return this
  }

  // ── Tool Methods ──────────────────────────────────────────────────────────

  /** Get registered tools. */
  get tools(): ToolDefinition[] {
    return this._tools
  }

  /** Set registered tools. */
  set tools(value: ToolDefinition[]) {
    this._tools = value
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// TOOL HELPER — Simple way to define tools
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Create a tool definition for use with agents.
 * 
 * @param name - Tool name
 * @param handler - Async function that implements the tool
 * @param options - Optional tool configuration
 * @returns ToolDefinition
 * 
 * @example
 * ```typescript
 * const search = tool('search', async (query: string) => {
 *   return `Results for: ${query}`
 * })
 * 
 * const sendEmail = tool('send_email', async (to: string, subject: string, body: string) => {
 *   return `Email sent to ${to}`
 * }, { timeout: 60, clearance: 2 })
 * 
 * const agent = new Agent('bot', { tools: [search, sendEmail] })
 * ```
 */
export function tool<T extends (...args: any[]) => Promise<any>>(
  name: string,
  handler: T,
  options: { timeout?: number; clearance?: number; description?: string } = {}
): ToolDefinition {
  return {
    name,
    handler,
    timeout: options.timeout ?? 30,
    clearance: options.clearance ?? 1,
    description: options.description ?? `Tool: ${name}`,
  }
}

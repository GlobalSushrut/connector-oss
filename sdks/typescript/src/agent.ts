import { Connector } from './connector'
import { RunOptions, PipelineResult } from './types'

export class Agent {
  private connector: Connector
  private name: string
  private instructions: string
  private compliance: string[] = []

  constructor(connector: Connector, name: string, instructions: string) {
    this.connector = connector
    this.name = name
    this.instructions = instructions
  }

  comply(frameworks: string[]): Agent {
    this.compliance = frameworks
    return this
  }

  async run(input: string, options: RunOptions): Promise<PipelineResult> {
    const res = await fetch(`${this.connector.getBaseUrl()}/run`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        agent: this.name,
        input,
        user: options.user,
        instructions: this.instructions,
        compliance: this.compliance,
      }),
    })
    if (!res.ok) throw new Error(`Agent run failed: ${res.statusText}`)
    const data = await res.json()
    return {
      text: data.text,
      trust: data.trust,
      trustGrade: data.trust_grade,
      ok: data.ok,
      durationMs: data.duration_ms,
      actors: data.actors,
      steps: data.steps,
      eventCount: data.event_count,
      spanCount: data.span_count,
      traceId: data.trace_id,
      verified: data.verified,
      warnings: data.warnings,
      errors: data.errors,
      provenance: data.provenance,
      json: data.json,
    }
  }
}

import { Connector } from './connector'
import { AgentDef, RunOptions, PipelineResult } from './types'

export class Pipeline {
  private connector: Connector
  private name: string
  private agents: AgentDef[] = []
  private routeStr?: string
  private compliance: string[] = []

  constructor(connector: Connector, name: string) {
    this.connector = connector
    this.name = name
  }

  agent(name: string, instructions: string): Pipeline {
    this.agents.push({ name, instructions })
    return this
  }

  route(route: string): Pipeline {
    this.routeStr = route
    return this
  }

  hipaa(): Pipeline {
    if (!this.compliance.includes('hipaa')) this.compliance.push('hipaa')
    return this
  }

  soc2(): Pipeline {
    if (!this.compliance.includes('soc2')) this.compliance.push('soc2')
    return this
  }

  gdpr(): Pipeline {
    if (!this.compliance.includes('gdpr')) this.compliance.push('gdpr')
    return this
  }

  async run(input: string, options: RunOptions): Promise<PipelineResult> {
    const res = await fetch(`${this.connector.getBaseUrl()}/pipeline`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: this.name,
        agents: this.agents,
        input,
        user: options.user,
        compliance: this.compliance,
      }),
    })
    if (!res.ok) throw new Error(`Pipeline run failed: ${res.statusText}`)
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

import { ConnectorConfig } from './types'
import { Agent } from './agent'
import { Pipeline } from './pipeline'
import * as fs from 'fs'

export class Connector {
  private config: ConnectorConfig
  private baseUrl: string

  constructor(config: ConnectorConfig) {
    this.config = config
    this.baseUrl = config.serverUrl || 'http://localhost:8080'
  }

  /**
   * Load a Connector from a connector.yaml file.
   * The file is read locally, then sent to the connector-server which
   * parses it via the Rust config loader (full env-var interpolation,
   * all 3-tier config sections).
   *
   * ```typescript
   * const c = await Connector.fromConfig('connector.yaml')
   * const result = await c.agent('bot', 'You are helpful').run('Hello', { user: 'alice' })
   * ```
   */
  static async fromConfig(
    path: string,
    serverUrl = 'http://localhost:8080',
  ): Promise<Connector> {
    if (!fs.existsSync(path)) {
      throw new Error(
        `Config file not found: ${path}\n` +
        `  Create one or check the path.`,
      )
    }
    const yaml = fs.readFileSync(path, 'utf-8')
    return Connector.fromConfigStr(yaml, serverUrl)
  }

  /**
   * Load a Connector from a YAML string.
   * Useful for testing or embedding config inline.
   *
   * ```typescript
   * const c = await Connector.fromConfigStr(`
   * connector:
   *   provider: openai
   *   model: gpt-4o
   *   api_key: sk-test
   * `)
   * ```
   */
  static async fromConfigStr(
    yaml: string,
    serverUrl = 'http://localhost:8080',
  ): Promise<Connector> {
    const res = await fetch(`${serverUrl}/config/parse`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/yaml' },
      body: yaml,
    })
    if (!res.ok) {
      const detail = await res.text()
      throw new Error(`Config parse failed (${res.status}): ${detail}`)
    }
    const parsed = await res.json() as { provider?: string; model?: string; endpoint?: string }
    return new Connector({
      llm: `${parsed.provider ?? 'openai'}:${parsed.model ?? 'gpt-4o'}`,
      apiKey: undefined,
      endpoint: parsed.endpoint,
      serverUrl,
    })
  }

  agent(name: string, instructions: string): Agent {
    return new Agent(this, name, instructions)
  }

  pipeline(name: string): Pipeline {
    return new Pipeline(this, name)
  }

  /** @internal */
  getConfig(): ConnectorConfig {
    return this.config
  }

  /** @internal */
  getBaseUrl(): string {
    return this.baseUrl
  }
}

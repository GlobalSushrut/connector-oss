/**
 * GlueSession - Scoped execution context
 */

import { Glue } from './core';
import { GlueResult } from './result';
function randomId(bytes = 16): string {
  const buf = new Uint8Array(bytes);
  globalThis.crypto.getRandomValues(buf);
  return Array.from(buf, (b) => b.toString(16).padStart(2, '0')).join('');
}

export class GlueSession {
  private readonly _glue: Glue;
  private readonly _policy?: string;
  private readonly _namespace?: string;
  private readonly _sessionId: string;

  constructor(glue: Glue, policy?: string, namespace?: string) {
    this._glue = glue;
    this._policy = policy;
    this._namespace = namespace;
    this._sessionId = `sess_${randomId(8).slice(0, 12)}`;
  }

  get id(): string {
    return this._sessionId;
  }

  get policy(): string | undefined {
    return this._policy;
  }

  get namespace(): string | undefined {
    return this._namespace;
  }

  async run(
    target: string,
    inputs: Record<string, unknown> = {}
  ): Promise<GlueResult> {
    return this._glue.run(target, inputs, this._policy);
  }

  async remember(key: string, content: string): Promise<GlueResult> {
    const ns = this._namespace || this._glue.config.defaultNamespace;
    return this._glue.remember(key, content, ns);
  }

  async recall(query: string, limit: number = 10): Promise<GlueResult> {
    const ns = this._namespace || this._glue.config.defaultNamespace;
    return this._glue.recall(query, ns, limit);
  }
}

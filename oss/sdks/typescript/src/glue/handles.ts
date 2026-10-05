/**
 * Resource Handles for GLUE operations
 */

import { Glue } from './core';
import { GlueResult } from './result';
import * as runtime from './runtime';

export class AgentHandle {
  constructor(private readonly glue: Glue, private readonly name: string) {}

  async start(): Promise<GlueResult> {
    return runtime.agentStart(this.glue, this.name);
  }

  async stop(): Promise<GlueResult> {
    return runtime.agentStop(this.glue, this.name);
  }

  async status(): Promise<GlueResult> {
    return runtime.agentStatus(this.glue, this.name);
  }

  async pause(): Promise<GlueResult> {
    return runtime.agentPause(this.glue, this.name);
  }

  async resume(): Promise<GlueResult> {
    return runtime.agentResume(this.glue, this.name);
  }
}

export class MemoryHandle {
  constructor(private readonly glue: Glue, private readonly namespace: string) {}

  async write(content: string): Promise<GlueResult> {
    return runtime.memoryWrite(this.glue, this.namespace, content);
  }

  async read(): Promise<GlueResult> {
    return runtime.memoryRead(this.glue, this.namespace);
  }

  async range(start: number, end: number): Promise<GlueResult> {
    return runtime.memoryRange(this.glue, this.namespace, start, end);
  }

  async search(query: string, limit: number = 10): Promise<GlueResult> {
    return this.glue.search(query, this.namespace, limit);
  }
}

export class ToolHandle {
  constructor(private readonly glue: Glue, private readonly name: string) {}

  async call(params: Record<string, unknown>): Promise<GlueResult> {
    return runtime.toolCall(this.glue, this.name, params);
  }

  async info(): Promise<GlueResult> {
    return runtime.toolInfo(this.glue, this.name);
  }
}

export class PolicyHandle {
  constructor(private readonly glue: Glue, private readonly name: string) {}

  async bindTo(agent: string): Promise<GlueResult> {
    return runtime.policyBind(this.glue, this.name, agent);
  }

  async check(agent: string): Promise<GlueResult> {
    return runtime.policyCheck(this.glue, this.name, agent);
  }
}

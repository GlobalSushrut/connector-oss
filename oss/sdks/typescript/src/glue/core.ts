/**
 * GLUE Core - Main interface for Connector operations
 */

import { GlueResult } from './result';
import { GlueError } from './error';
import { GlueSession } from './session';
import { CompiledContract } from './contract';
import { AgentHandle, MemoryHandle, ToolHandle, PolicyHandle } from './handles';
import * as runtime from './runtime';

export interface GlueConfig {
  defaultNamespace: string;
  defaultPolicy?: string;
  auditEnabled: boolean;
  baseUrl: string;
  apiKey?: string;
  strictMode: boolean; // Fail closed, require server receipts
}

const defaultConfig: GlueConfig = {
  defaultNamespace: 'default',
  auditEnabled: true,
  strictMode: true,
  baseUrl: process.env.CONNECTOR_URL || 'http://localhost:9091',
  apiKey: process.env.CONNECTOR_API_KEY,
};

/**
 * The main GLUE interface - entry point for all Connector operations.
 */
export class Glue {
  readonly config: GlueConfig;

  constructor(config: Partial<GlueConfig> = {}) {
    this.config = { ...defaultConfig, ...config };
  }

  // =========================================================================
  // Core Verbs
  // =========================================================================

  /**
   * Run a contract or agent.
   */
  async run(
    target: string | CompiledContract,
    inputs: Record<string, unknown> = {},
    policy?: string
  ): Promise<GlueResult> {
    const targetName = typeof target === 'string' ? target : target.name;
    return runtime.executeRun(this, targetName, inputs, policy);
  }

  /**
   * Store data to memory.
   */
  async remember(
    key: string,
    content: string,
    namespace?: string
  ): Promise<GlueResult> {
    return runtime.executeRemember(this, key, content, namespace);
  }

  /**
   * Recall data from memory.
   */
  async recall(
    query: string,
    namespace?: string,
    limit: number = 10
  ): Promise<GlueResult> {
    return runtime.executeRecall(this, query, namespace, limit);
  }

  /**
   * Search across memory/knowledge.
   */
  async search(
    query: string,
    namespace?: string,
    limit: number = 20
  ): Promise<GlueResult> {
    return runtime.executeSearch(this, query, namespace, limit);
  }

  /**
   * Show/inspect a resource.
   */
  async show(noun: string, target: string): Promise<GlueResult> {
    return runtime.executeShow(this, noun, target);
  }

  /**
   * List resources.
   */
  async list(
    noun: string,
    namespace?: string,
    limit: number = 50
  ): Promise<GlueResult> {
    return runtime.executeList(this, noun, namespace, limit);
  }

  /**
   * Get audit trail for an execution.
   */
  async audit(target: string): Promise<GlueResult> {
    return runtime.executeAudit(this, target);
  }

  /**
   * Verify compliance/policy.
   */
  async verify(what: string, forAgent?: string): Promise<GlueResult> {
    return runtime.executeVerify(this, what, forAgent);
  }

  // =========================================================================
  // Infra Operations
  // =========================================================================

  /**
   * Get decision explanation for an agent or execution.
   */
  async explain(target: string, last?: string): Promise<GlueResult> {
    return runtime.executeExplain(this, target, last);
  }

  /**
   * Get cryptographic proof for an agent or execution.
   */
  async prove(target: string, forensic: boolean = false): Promise<GlueResult> {
    return runtime.executeProve(this, target, forensic);
  }

  /**
   * Get execution trace for an agent.
   */
  async trace(target: string, last?: string, limit: number = 50): Promise<GlueResult> {
    return runtime.executeTrace(this, target, last, limit);
  }

  /**
   * Get risk and guarded action posture for an agent.
   */
  async review(target: string): Promise<GlueResult> {
    return runtime.executeReview(this, target);
  }

  /**
   * Get cost statement.
   */
  async cost(target?: string, breakdown: boolean = false): Promise<GlueResult> {
    return runtime.executeCost(this, target, breakdown);
  }

  /**
   * Quick health check of the node.
   */
  async health(): Promise<GlueResult> {
    return runtime.executeHealth(this);
  }

  /**
   * Full diagnostic report of the node.
   */
  async doctor(verbose: boolean = false): Promise<GlueResult> {
    return runtime.executeDoctor(this, verbose);
  }

  /**
   * View node or agent logs.
   */
  async logs(target?: string, tail: number = 100): Promise<GlueResult> {
    return runtime.executeLogs(this, target, tail);
  }

  // =========================================================================
  // Resource Handles
  // =========================================================================

  /**
   * Get a handle for agent operations.
   */
  agent(name: string): AgentHandle {
    return new AgentHandle(this, name);
  }

  /**
   * Get a handle for memory operations.
   */
  memory(namespace: string): MemoryHandle {
    return new MemoryHandle(this, namespace);
  }

  /**
   * Get a handle for tool operations.
   */
  tool(name: string): ToolHandle {
    return new ToolHandle(this, name);
  }

  /**
   * Get a handle for policy operations.
   */
  policy(name: string): PolicyHandle {
    return new PolicyHandle(this, name);
  }

  // =========================================================================
  // Session Management
  // =========================================================================

  /**
   * Create a scoped session with inherited policy.
   */
  session(policy?: string, namespace?: string): GlueSession {
    return new GlueSession(this, policy, namespace);
  }
}

// Global GLUE instance
export const glue = new Glue();

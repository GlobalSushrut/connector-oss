/**
 * LangChain integration for VAC SDK
 *
 * Provides memory adapters for LangChain/LangGraph agents.
 */

import type { Event, ClaimBundle } from './types';
import { Vault } from './vault';
import { encodeFeatures, computeEntropy } from './red';

/**
 * Message type for LangChain compatibility
 */
export interface Message {
  role: 'user' | 'assistant' | 'system' | 'tool';
  content: string;
  name?: string;
  tool_call_id?: string;
}

/**
 * Memory entry returned by VAC
 */
export interface MemoryEntry {
  cid: string;
  content: string;
  timestamp: number;
  relevance: number;
  source: string;
}

/**
 * VAC Memory adapter for LangChain
 *
 * Usage with LangGraph:
 * ```typescript
 * const memory = new VacMemory({ vaultId: 'agent-memory', ownerId: 'did:key:...' });
 *
 * // In your agent graph
 * const state = await memory.loadMemoryVariables({ query: 'user preferences' });
 * // ... agent processing ...
 * await memory.saveContext(input, output);
 * ```
 */
export class VacMemory {
  private vault: Vault;
  private sessionMessages: Message[] = [];

  constructor(config: { vaultId: string; ownerId: string }) {
    this.vault = new Vault(config);
  }

  /**
   * Load relevant memories for a query
   */
  async loadMemoryVariables(inputs: {
    query?: string;
    k?: number;
  }): Promise<{ history: MemoryEntry[] }> {
    // For v0.1, return session messages as memory
    // Full retrieval will be implemented with Prolly tree queries
    const history: MemoryEntry[] = this.sessionMessages.map((msg, i) => ({
      cid: `session-${i}`,
      content: msg.content,
      timestamp: Date.now() - (this.sessionMessages.length - i) * 1000,
      relevance: 1.0,
      source: msg.role,
    }));

    return { history };
  }

  /**
   * Save interaction context to memory
   */
  async saveContext(
    input: { input: string },
    output: { output: string }
  ): Promise<void> {
    // Add to session
    this.sessionMessages.push({ role: 'user', content: input.input });
    this.sessionMessages.push({ role: 'assistant', content: output.output });

    // Create events in vault
    this.vault.createEvent(input.input, {
      tags: ['user_input'],
      actors: ['user'],
    });

    this.vault.createEvent(output.output, {
      tags: ['assistant_output'],
      actors: ['assistant'],
    });
  }

  /**
   * Extract and store claims from conversation
   */
  async extractClaims(
    text: string,
    subjectId: string
  ): Promise<ClaimBundle[]> {
    // Simple claim extraction (in production, use NLP)
    const claims: ClaimBundle[] = [];

    // Pattern: "X prefers Y" or "X likes Y"
    const preferencePattern = /(\w+)\s+(prefers?|likes?)\s+(.+)/gi;
    let match;

    while ((match = preferencePattern.exec(text)) !== null) {
      const claim = this.vault.createClaim(
        subjectId,
        'preference:general',
        match[3].trim(),
        { confidence: 0.7 }
      );
      claims.push(claim);
    }

    return claims;
  }

  /**
   * Commit all pending changes
   */
  async commit(): Promise<void> {
    await this.vault.commit();
  }

  /**
   * Provide feedback on retrieval usefulness
   */
  feedback(query: string, wasUseful: boolean): void {
    this.vault.feedback([], query, wasUseful);
  }

  /**
   * Clear session memory (not persistent memory)
   */
  clearSession(): void {
    this.sessionMessages = [];
  }

  /**
   * Get memory statistics
   */
  getStats(): {
    sessionMessages: number;
    blockNo: number;
    redStats: { observations: number; retrievals: number };
  } {
    return {
      sessionMessages: this.sessionMessages.length,
      blockNo: this.vault.getBlockNo(),
      redStats: this.vault.getRedStats(),
    };
  }
}

/**
 * Create a VAC memory instance for LangChain
 */
export function createVacMemory(config: {
  vaultId: string;
  ownerId: string;
}): VacMemory {
  return new VacMemory(config);
}

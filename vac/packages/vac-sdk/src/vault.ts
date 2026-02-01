/**
 * Vault - High-level API for VAC operations
 */

import type {
  Event,
  ClaimBundle,
  BlockHeader,
  ManifestRoot,
  VaultPatch,
  Source,
  ScoreComponents,
} from './types';
import { computeCidString } from './cid';
import { VacStore, MemoryStore } from './store';
import { RedEngine, SparseVector, encodeFeatures, computeEntropy } from './red';

/**
 * Vault configuration
 */
export interface VaultConfig {
  vaultId: string;
  ownerId: string;
}

/**
 * Vault - Main entry point for VAC operations
 */
export class Vault {
  private store: VacStore;
  private red: RedEngine;
  private headBlockHash: Uint8Array | null = null;
  private blockNo = 0;
  private pendingEvents: Event[] = [];
  private pendingClaims: ClaimBundle[] = [];

  constructor(
    public readonly config: VaultConfig,
    store?: VacStore
  ) {
    this.store = store ?? new VacStore(new MemoryStore());
    this.red = new RedEngine();
  }

  /**
   * Create a new event
   */
  createEvent(
    payload: unknown,
    options: {
      chapterHint?: string;
      actors?: string[];
      tags?: string[];
      entities?: string[];
      source?: Source;
    } = {}
  ): Event {
    const payloadBytes = new TextEncoder().encode(JSON.stringify(payload));
    const payloadCid = computeCidString(payloadBytes);

    const source = options.source ?? {
      kind: 'self' as const,
      principal_id: this.config.ownerId,
    };

    // Encode features for RED
    const vector = encodeFeatures(
      options.entities ?? [],
      [],
      typeof payload === 'string' ? payload : JSON.stringify(payload)
    );

    // Compute entropy
    const entropy = computeEntropy(this.red, vector, 0, 0);

    const event: Event = {
      type: 'event',
      version: 1,
      ts: Date.now(),
      chapter_hint: options.chapterHint,
      actors: options.actors ?? [],
      tags: options.tags ?? [],
      entities: options.entities ?? [],
      payload_ref: payloadCid,
      feature_sketch: new Uint8Array(64),
      entropy,
      importance: 0.5,
      score_components: {
        salience: 0.5,
        recency: 1.0,
        connectivity: 0,
      },
      source,
      trust_tier: source.kind === 'self' ? 3 : 1,
      links: {},
      metadata: {},
    };

    // Update RED engine
    this.red.observe(vector);

    this.pendingEvents.push(event);
    return event;
  }

  /**
   * Create a new claim
   */
  createClaim(
    subjectId: string,
    predicateKey: string,
    value: unknown,
    options: {
      units?: string;
      confidence?: number;
      evidenceRefs?: string[];
      source?: Source;
    } = {}
  ): ClaimBundle {
    const source = options.source ?? {
      kind: 'self' as const,
      principal_id: this.config.ownerId,
    };

    const valueType =
      typeof value === 'string'
        ? 'string'
        : typeof value === 'number'
          ? 'number'
          : typeof value === 'boolean'
            ? 'bool'
            : 'json';

    const claim: ClaimBundle = {
      type: 'claim_bundle',
      version: 1,
      subject_id: subjectId,
      predicate_key: predicateKey,
      value,
      value_type: valueType as 'string' | 'number' | 'bool' | 'json',
      units: options.units,
      epistemic: 'observed',
      asserted_ts: Date.now(),
      confidence: options.confidence,
      evidence_refs: options.evidenceRefs ?? [],
      source,
      trust_tier: source.kind === 'self' ? 3 : 1,
      links: {},
      metadata: {},
    };

    this.pendingClaims.push(claim);
    return claim;
  }

  /**
   * Commit pending changes to a new block
   */
  async commit(signingKey?: string): Promise<BlockHeader> {
    const addedCids: string[] = [];

    // Store pending events
    for (const event of this.pendingEvents) {
      const cid = await this.store.putObject(event);
      addedCids.push(cid);
    }

    // Store pending claims
    for (const claim of this.pendingClaims) {
      const cid = await this.store.putObject(claim);
      addedCids.push(cid);
    }

    // Create patch
    const patch: VaultPatch = {
      type: 'vault_patch',
      version: 1,
      parent_block_hash: this.headBlockHash ?? new Uint8Array(32),
      added_cids: addedCids,
      removed_refs: [],
      updated_roots: {},
      links: { added: addedCids },
      metadata: {},
    };

    const patchCid = await this.store.putObject(patch);

    // Create manifest
    const manifest: ManifestRoot = {
      type: 'manifest_root',
      version: 1,
      block_no: this.blockNo,
      chapter_index_root: new Uint8Array(32),
      snaptree_roots: {},
      pcnn_basis_root: new Uint8Array(32),
      pcnn_mpn_root: new Uint8Array(32),
      pcnn_ie_root: new Uint8Array(32),
      body_cas_root: new Uint8Array(32),
      policy_root: new Uint8Array(32),
      revocation_root: new Uint8Array(32),
      manifest_hash: new Uint8Array(32),
      metadata: {},
    };

    const manifestCid = await this.store.putObject(manifest);

    // Create block header
    const block: BlockHeader = {
      type: 'block_header',
      version: 1,
      block_no: this.blockNo,
      prev_block_hash: this.headBlockHash ?? new Uint8Array(32),
      ts: Date.now(),
      links: {
        patch: patchCid,
        manifest: manifestCid,
      },
      signatures: [],
      block_hash: new Uint8Array(32), // Will be computed
      metadata: {},
    };

    // Compute block hash (simplified)
    const blockData = JSON.stringify({
      block_no: block.block_no,
      prev_block_hash: Array.from(block.prev_block_hash),
      ts: block.ts,
      patch: patchCid,
      manifest: manifestCid,
    });
    const blockHashBytes = new TextEncoder().encode(blockData);
    // In production, use proper SHA256
    block.block_hash = new Uint8Array(32);
    for (let i = 0; i < Math.min(blockHashBytes.length, 32); i++) {
      block.block_hash[i] = blockHashBytes[i];
    }

    await this.store.putObject(block);

    // Update state
    this.headBlockHash = block.block_hash;
    this.blockNo++;
    this.pendingEvents = [];
    this.pendingClaims = [];

    return block;
  }

  /**
   * Provide retrieval feedback to RED engine
   */
  feedback(entities: string[], text: string, wasUseful: boolean): void {
    const vector = encodeFeatures(entities, [], text);
    this.red.retrievalFeedback(vector, wasUseful);
  }

  /**
   * Trigger network reframing (consolidation)
   */
  reframe(): void {
    this.red.reframeNetwork();
  }

  /**
   * Get current block number
   */
  getBlockNo(): number {
    return this.blockNo;
  }

  /**
   * Get RED engine stats
   */
  getRedStats(): { observations: number; retrievals: number } {
    return {
      observations: this.red.totalObservations,
      retrievals: this.red.totalRetrievals,
    };
  }
}

/**
 * Create a new vault
 */
export function createVault(config: VaultConfig): Vault {
  return new Vault(config);
}

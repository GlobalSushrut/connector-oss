import { CID } from 'multiformats/cid';

/**
 * Core types for VAC SDK
 */
/** Source kind */
type SourceKind = 'self' | 'user' | 'tool' | 'web' | 'untrusted';
/** Source of an event or claim */
interface Source {
    kind: SourceKind;
    principal_id: string;
}
/** Verification status */
type VerificationStatus = 'pending' | 'verified' | 'failed';
/** Verification info */
interface Verification {
    status: VerificationStatus;
    receipt_cid?: string;
}
/** Score components for deterministic heap derivation */
interface ScoreComponents {
    salience: number;
    recency: number;
    connectivity: number;
}
/** Event - raw input atom */
interface Event {
    type: 'event';
    version: number;
    ts: number;
    chapter_hint?: string;
    actors: string[];
    tags: string[];
    entities: string[];
    payload_ref: string;
    feature_sketch: Uint8Array;
    entropy: number;
    importance: number;
    score_components: ScoreComponents;
    source: Source;
    trust_tier: number;
    verification?: Verification;
    links: Record<string, string>;
    metadata: Record<string, unknown>;
}
/** Epistemic status */
type Epistemic = 'observed' | 'inferred' | 'verified' | 'retracted';
/** Validity time range */
interface ValidityRange {
    from: number;
    to: number | null;
}
/** ClaimBundle - structured assertion */
interface ClaimBundle {
    type: 'claim_bundle';
    version: number;
    subject_id: string;
    predicate_key: string;
    value: unknown;
    value_type: 'string' | 'number' | 'bool' | 'json';
    units?: string;
    epistemic: Epistemic;
    asserted_ts: number;
    valid_ts_range?: ValidityRange;
    confidence?: number;
    evidence_refs: string[];
    supersedes?: string;
    source: Source;
    trust_tier: number;
    links: Record<string, string[]>;
    metadata: Record<string, unknown>;
}
/** Entropy band */
type EntropyBand = 'low' | 'mid' | 'high';
/** Bracket - time-entropy window */
interface Bracket {
    type: 'bracket';
    version: number;
    t_min: number;
    t_max: number;
    entropy_band: EntropyBand;
    detail_level: number;
    links: Record<string, string>;
    merkle_root: Uint8Array;
    metadata: Record<string, unknown>;
}
/** Node kind */
type NodeKind = 'LEAF' | 'SUMMARY';
/** Time range */
interface TimeRange {
    min: number;
    max: number;
}
/** Node - compression tree node */
interface Node {
    type: 'node';
    version: number;
    kind: NodeKind;
    ts_range: TimeRange;
    entropy: number;
    importance: number;
    score_components: ScoreComponents;
    event_refs?: string[];
    summary_ref?: string;
    children?: string[];
    links: Record<string, string[]>;
    merkle_hash: Uint8Array;
    metadata: Record<string, unknown>;
}
/** Frame links */
interface FrameLinks {
    bracket: string;
    frame_summary?: string;
    parents: string[];
    children: string[];
}
/** Frame - snapshot page */
interface Frame {
    type: 'frame';
    version: number;
    chapter_id: string;
    frame_ts: number;
    links: FrameLinks;
    merkle_root: Uint8Array;
    metadata: Record<string, unknown>;
}
/** Signature */
interface Signature {
    public_key: string;
    signature: Uint8Array;
}
/** Block links */
interface BlockLinks {
    patch: string;
    manifest: string;
}
/** BlockHeader - attestation block */
interface BlockHeader {
    type: 'block_header';
    version: number;
    block_no: number;
    prev_block_hash: Uint8Array;
    ts: number;
    links: BlockLinks;
    signatures: Signature[];
    block_hash: Uint8Array;
    metadata: Record<string, unknown>;
}
/** ManifestRoot - per-block root summary */
interface ManifestRoot {
    type: 'manifest_root';
    version: number;
    block_no: number;
    chapter_index_root: Uint8Array;
    snaptree_roots: Record<string, Uint8Array>;
    pcnn_basis_root: Uint8Array;
    pcnn_mpn_root: Uint8Array;
    pcnn_ie_root: Uint8Array;
    body_cas_root: Uint8Array;
    policy_root: Uint8Array;
    revocation_root: Uint8Array;
    manifest_hash: Uint8Array;
    metadata: Record<string, unknown>;
}
/** VaultPatch - change manifest */
interface VaultPatch {
    type: 'vault_patch';
    version: number;
    parent_block_hash: Uint8Array;
    added_cids: string[];
    removed_refs: string[];
    updated_roots: Record<string, Uint8Array>;
    links: Record<string, string[]>;
    metadata: Record<string, unknown>;
}
/** IE kind */
type IeKind = 'reinforce' | 'contradict' | 'refine' | 'alias';
/** IE links */
interface IeLinks {
    from: string;
    to: string;
}
/** InterferenceEdge */
interface InterferenceEdge {
    type: 'ie';
    version: number;
    kind: IeKind;
    strength: number;
    created_ts: number;
    links: IeLinks;
    metadata: Record<string, unknown>;
}
/** ProllyNode - narrow tree node */
interface ProllyNode {
    type: 'prolly_node';
    version: number;
    level: number;
    keys: Uint8Array[];
    values: string[];
    node_hash: Uint8Array;
    metadata: Record<string, unknown>;
}
/** Any VAC object */
type VacObject = Event | ClaimBundle | Bracket | Node | Frame | BlockHeader | ManifestRoot | VaultPatch | InterferenceEdge | ProllyNode;

/**
 * CID computation for VAC objects
 */

/**
 * Compute CIDv1 for any object using DAG-CBOR + SHA2-256
 */
declare function computeCid(obj: unknown): CID;
/**
 * Compute CID and return as string
 */
declare function computeCidString(obj: unknown): string;
/**
 * Compute SHA256 hash
 */
declare function computeSha256(data: Uint8Array): Uint8Array;
/**
 * Compute Prolly node hash
 */
declare function computeProllyNodeHash(level: number, keys: Uint8Array[], values: string[]): Uint8Array;

/**
 * Codec utilities for VAC objects
 */

/**
 * Encode object to DAG-CBOR bytes
 */
declare function encode(obj: VacObject): Uint8Array;
/**
 * Decode DAG-CBOR bytes to object
 */
declare function decode<T extends VacObject>(bytes: Uint8Array): T;
/**
 * Encode to JSON (for debugging/display)
 */
declare function toJson(obj: VacObject): string;

/**
 * Content-addressable storage for VAC SDK
 */

/**
 * Content store interface
 */
interface ContentStore {
    get(cid: string): Promise<Uint8Array | null>;
    put(bytes: Uint8Array): Promise<string>;
    has(cid: string): Promise<boolean>;
    delete(cid: string): Promise<void>;
}
/**
 * In-memory content store for testing
 */
declare class MemoryStore implements ContentStore {
    private data;
    get(cid: string): Promise<Uint8Array | null>;
    put(bytes: Uint8Array): Promise<string>;
    has(cid: string): Promise<boolean>;
    delete(cid: string): Promise<void>;
    get size(): number;
    clear(): void;
}
/**
 * Typed store wrapper for VAC objects
 */
declare class VacStore {
    private store;
    constructor(store: ContentStore);
    getObject<T extends VacObject>(cid: string): Promise<T | null>;
    putObject(obj: VacObject): Promise<string>;
    hasObject(cid: string): Promise<boolean>;
    deleteObject(cid: string): Promise<void>;
}

/**
 * Regressive Entropic Displacement (RED) engine for TypeScript
 *
 * Non-ML learning system based on:
 * - Maximum Entropy Principle (Jaynes)
 * - KL Divergence as information gain
 * - Multiplicative Weights Update (Hedge algorithm)
 */
/** Default dimensions for feature vectors */
declare const DEFAULT_DIMS = 65536;
/** Default learning rate */
declare const DEFAULT_ETA = 0.1;
/**
 * Sparse vector for feature representation
 */
declare class SparseVector {
    readonly dims: number;
    private entries;
    constructor(dims?: number);
    add(dim: number, value: number): void;
    set(dim: number, value: number): void;
    get(dim: number): number;
    nonzero(): Generator<[number, number]>;
    nnz(): number;
    norm(): number;
    normalize(): void;
    dot(other: SparseVector): number;
    cosineSimilarity(other: SparseVector): number;
    toDistribution(): number[];
}
/**
 * Hash a string to a dimension
 */
declare function hashToDim(s: string, dims?: number): number;
/**
 * Extract n-grams from text
 */
declare function extractNgrams(text: string, n: number): string[];
/**
 * Encode features into a sparse vector
 */
declare function encodeFeatures(entities: string[], predicates: string[], text: string, dims?: number): SparseVector;
/**
 * Regressive Entropic Displacement engine
 */
declare class RedEngine {
    readonly dims: number;
    readonly eta: number;
    private prior;
    private posterior;
    private cumulativeLoss;
    totalObservations: number;
    totalRetrievals: number;
    constructor(dims?: number, eta?: number);
    /**
     * Update belief distribution when new event is observed
     */
    observe(vector: SparseVector): void;
    /**
     * Update weights based on retrieval outcome (Hedge algorithm)
     */
    retrievalFeedback(vector: SparseVector, wasUseful: boolean): void;
    /**
     * Compute entropy (novelty) via KL divergence
     */
    computeEntropy(vector: SparseVector): number;
    /**
     * Compute entropic displacement (learning signal)
     */
    computeDisplacement(oldPosterior: number[]): number;
    /**
     * Periodic reframing (consolidation)
     */
    reframeNetwork(): void;
    /**
     * Get current posterior
     */
    getPosterior(): number[];
    private normalizePosterior;
}
/**
 * Compute combined entropy score
 */
declare function computeEntropy(red: RedEngine, vector: SparseVector, conflictCount: number, timeSinceSimilarSecs: number): number;

/**
 * Vault - High-level API for VAC operations
 */

/**
 * Vault configuration
 */
interface VaultConfig {
    vaultId: string;
    ownerId: string;
}
/**
 * Vault - Main entry point for VAC operations
 */
declare class Vault {
    readonly config: VaultConfig;
    private store;
    private red;
    private headBlockHash;
    private blockNo;
    private pendingEvents;
    private pendingClaims;
    constructor(config: VaultConfig, store?: VacStore);
    /**
     * Create a new event
     */
    createEvent(payload: unknown, options?: {
        chapterHint?: string;
        actors?: string[];
        tags?: string[];
        entities?: string[];
        source?: Source;
    }): Event;
    /**
     * Create a new claim
     */
    createClaim(subjectId: string, predicateKey: string, value: unknown, options?: {
        units?: string;
        confidence?: number;
        evidenceRefs?: string[];
        source?: Source;
    }): ClaimBundle;
    /**
     * Commit pending changes to a new block
     */
    commit(signingKey?: string): Promise<BlockHeader>;
    /**
     * Provide retrieval feedback to RED engine
     */
    feedback(entities: string[], text: string, wasUseful: boolean): void;
    /**
     * Trigger network reframing (consolidation)
     */
    reframe(): void;
    /**
     * Get current block number
     */
    getBlockNo(): number;
    /**
     * Get RED engine stats
     */
    getRedStats(): {
        observations: number;
        retrievals: number;
    };
}
/**
 * Create a new vault
 */
declare function createVault(config: VaultConfig): Vault;

/**
 * LangChain integration for VAC SDK
 *
 * Provides memory adapters for LangChain/LangGraph agents.
 */

/**
 * Message type for LangChain compatibility
 */
interface Message {
    role: 'user' | 'assistant' | 'system' | 'tool';
    content: string;
    name?: string;
    tool_call_id?: string;
}
/**
 * Memory entry returned by VAC
 */
interface MemoryEntry {
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
declare class VacMemory {
    private vault;
    private sessionMessages;
    constructor(config: {
        vaultId: string;
        ownerId: string;
    });
    /**
     * Load relevant memories for a query
     */
    loadMemoryVariables(inputs: {
        query?: string;
        k?: number;
    }): Promise<{
        history: MemoryEntry[];
    }>;
    /**
     * Save interaction context to memory
     */
    saveContext(input: {
        input: string;
    }, output: {
        output: string;
    }): Promise<void>;
    /**
     * Extract and store claims from conversation
     */
    extractClaims(text: string, subjectId: string): Promise<ClaimBundle[]>;
    /**
     * Commit all pending changes
     */
    commit(): Promise<void>;
    /**
     * Provide feedback on retrieval usefulness
     */
    feedback(query: string, wasUseful: boolean): void;
    /**
     * Clear session memory (not persistent memory)
     */
    clearSession(): void;
    /**
     * Get memory statistics
     */
    getStats(): {
        sessionMessages: number;
        blockNo: number;
        redStats: {
            observations: number;
            retrievals: number;
        };
    };
}
/**
 * Create a VAC memory instance for LangChain
 */
declare function createVacMemory(config: {
    vaultId: string;
    ownerId: string;
}): VacMemory;

export { type BlockHeader, type BlockLinks, type Bracket, type ClaimBundle, type ContentStore, DEFAULT_DIMS, DEFAULT_ETA, type EntropyBand, type Epistemic, type Event, type Frame, type FrameLinks, type IeKind, type IeLinks, type InterferenceEdge, type ManifestRoot, type MemoryEntry, MemoryStore, type Message, type Node, type NodeKind, type ProllyNode, RedEngine, type ScoreComponents, type Signature, type Source, type SourceKind, SparseVector, type TimeRange, VacMemory, type VacObject, VacStore, type ValidityRange, Vault, type VaultConfig, type VaultPatch, type Verification, type VerificationStatus, computeCid, computeCidString, computeEntropy, computeProllyNodeHash, computeSha256, createVacMemory, createVault, decode, encode, encodeFeatures, extractNgrams, hashToDim, toJson };

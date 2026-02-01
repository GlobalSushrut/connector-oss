/**
 * Core types for VAC SDK
 */

/** Source kind */
export type SourceKind = 'self' | 'user' | 'tool' | 'web' | 'untrusted';

/** Source of an event or claim */
export interface Source {
  kind: SourceKind;
  principal_id: string;
}

/** Verification status */
export type VerificationStatus = 'pending' | 'verified' | 'failed';

/** Verification info */
export interface Verification {
  status: VerificationStatus;
  receipt_cid?: string;
}

/** Score components for deterministic heap derivation */
export interface ScoreComponents {
  salience: number;
  recency: number;
  connectivity: number;
}

/** Event - raw input atom */
export interface Event {
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
export type Epistemic = 'observed' | 'inferred' | 'verified' | 'retracted';

/** Validity time range */
export interface ValidityRange {
  from: number;
  to: number | null;
}

/** ClaimBundle - structured assertion */
export interface ClaimBundle {
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
export type EntropyBand = 'low' | 'mid' | 'high';

/** Bracket - time-entropy window */
export interface Bracket {
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
export type NodeKind = 'LEAF' | 'SUMMARY';

/** Time range */
export interface TimeRange {
  min: number;
  max: number;
}

/** Node - compression tree node */
export interface Node {
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
export interface FrameLinks {
  bracket: string;
  frame_summary?: string;
  parents: string[];
  children: string[];
}

/** Frame - snapshot page */
export interface Frame {
  type: 'frame';
  version: number;
  chapter_id: string;
  frame_ts: number;
  links: FrameLinks;
  merkle_root: Uint8Array;
  metadata: Record<string, unknown>;
}

/** Signature */
export interface Signature {
  public_key: string;
  signature: Uint8Array;
}

/** Block links */
export interface BlockLinks {
  patch: string;
  manifest: string;
}

/** BlockHeader - attestation block */
export interface BlockHeader {
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
export interface ManifestRoot {
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
export interface VaultPatch {
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
export type IeKind = 'reinforce' | 'contradict' | 'refine' | 'alias';

/** IE links */
export interface IeLinks {
  from: string;
  to: string;
}

/** InterferenceEdge */
export interface InterferenceEdge {
  type: 'ie';
  version: number;
  kind: IeKind;
  strength: number;
  created_ts: number;
  links: IeLinks;
  metadata: Record<string, unknown>;
}

/** ProllyNode - narrow tree node */
export interface ProllyNode {
  type: 'prolly_node';
  version: number;
  level: number;
  keys: Uint8Array[];
  values: string[];
  node_hash: Uint8Array;
  metadata: Record<string, unknown>;
}

/** Any VAC object */
export type VacObject =
  | Event
  | ClaimBundle
  | Bracket
  | Node
  | Frame
  | BlockHeader
  | ManifestRoot
  | VaultPatch
  | InterferenceEdge
  | ProllyNode;

/**
 * CID computation for VAC objects
 */

import { sha256 } from '@noble/hashes/sha256';
import * as dagCbor from '@ipld/dag-cbor';
import { CID } from 'multiformats/cid';
import { create } from 'multiformats/hashes/digest';

/** DAG-CBOR codec code */
const DAG_CBOR_CODE = 0x71;

/** SHA2-256 multihash code */
const SHA256_CODE = 0x12;

/**
 * Compute CIDv1 for any object using DAG-CBOR + SHA2-256
 */
export function computeCid(obj: unknown): CID {
  const bytes = dagCbor.encode(obj);
  const hash = sha256(bytes);
  const digest = create(SHA256_CODE, hash);
  return CID.createV1(DAG_CBOR_CODE, digest);
}

/**
 * Compute CID and return as string
 */
export function computeCidString(obj: unknown): string {
  return computeCid(obj).toString();
}

/**
 * Compute SHA256 hash
 */
export function computeSha256(data: Uint8Array): Uint8Array {
  return sha256(data);
}

/**
 * Compute Prolly node hash
 */
export function computeProllyNodeHash(
  level: number,
  keys: Uint8Array[],
  values: string[]
): Uint8Array {
  const parts: number[] = [];
  
  // Level
  parts.push(level);
  
  // Number of keys (2 bytes, big endian)
  const numKeys = keys.length;
  parts.push((numKeys >> 8) & 0xff);
  parts.push(numKeys & 0xff);
  
  // Keys (length-prefixed)
  for (const key of keys) {
    const keyLen = key.length;
    parts.push((keyLen >> 8) & 0xff);
    parts.push(keyLen & 0xff);
    parts.push(...key);
  }
  
  // Values (CID strings as bytes)
  for (const value of values) {
    const valueBytes = new TextEncoder().encode(value);
    parts.push(...valueBytes);
  }
  
  return sha256(new Uint8Array(parts));
}

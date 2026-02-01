/**
 * Codec utilities for VAC objects
 */

import * as dagCbor from '@ipld/dag-cbor';
import type { VacObject } from './types';

/**
 * Encode object to DAG-CBOR bytes
 */
export function encode(obj: VacObject): Uint8Array {
  return dagCbor.encode(obj);
}

/**
 * Decode DAG-CBOR bytes to object
 */
export function decode<T extends VacObject>(bytes: Uint8Array): T {
  return dagCbor.decode(bytes) as T;
}

/**
 * Encode to JSON (for debugging/display)
 */
export function toJson(obj: VacObject): string {
  return JSON.stringify(obj, (_, value) => {
    if (value instanceof Uint8Array) {
      return Array.from(value);
    }
    return value;
  }, 2);
}

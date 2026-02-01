/**
 * Content-addressable storage for VAC SDK
 */

import { computeCid } from './cid';
import type { VacObject } from './types';
import { encode, decode } from './codec';

/**
 * Content store interface
 */
export interface ContentStore {
  get(cid: string): Promise<Uint8Array | null>;
  put(bytes: Uint8Array): Promise<string>;
  has(cid: string): Promise<boolean>;
  delete(cid: string): Promise<void>;
}

/**
 * In-memory content store for testing
 */
export class MemoryStore implements ContentStore {
  private data = new Map<string, Uint8Array>();

  async get(cid: string): Promise<Uint8Array | null> {
    return this.data.get(cid) ?? null;
  }

  async put(bytes: Uint8Array): Promise<string> {
    const cid = computeCid(bytes).toString();
    this.data.set(cid, bytes);
    return cid;
  }

  async has(cid: string): Promise<boolean> {
    return this.data.has(cid);
  }

  async delete(cid: string): Promise<void> {
    this.data.delete(cid);
  }

  get size(): number {
    return this.data.size;
  }

  clear(): void {
    this.data.clear();
  }
}

/**
 * Typed store wrapper for VAC objects
 */
export class VacStore {
  constructor(private store: ContentStore) {}

  async getObject<T extends VacObject>(cid: string): Promise<T | null> {
    const bytes = await this.store.get(cid);
    if (!bytes) return null;
    return decode<T>(bytes);
  }

  async putObject(obj: VacObject): Promise<string> {
    const bytes = encode(obj);
    return this.store.put(bytes);
  }

  async hasObject(cid: string): Promise<boolean> {
    return this.store.has(cid);
  }

  async deleteObject(cid: string): Promise<void> {
    return this.store.delete(cid);
  }
}

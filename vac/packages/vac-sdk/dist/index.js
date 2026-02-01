"use strict";
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var index_exports = {};
__export(index_exports, {
  DEFAULT_DIMS: () => DEFAULT_DIMS,
  DEFAULT_ETA: () => DEFAULT_ETA,
  MemoryStore: () => MemoryStore,
  RedEngine: () => RedEngine,
  SparseVector: () => SparseVector,
  VacMemory: () => VacMemory,
  VacStore: () => VacStore,
  Vault: () => Vault,
  computeCid: () => computeCid,
  computeCidString: () => computeCidString,
  computeEntropy: () => computeEntropy,
  computeProllyNodeHash: () => computeProllyNodeHash,
  computeSha256: () => computeSha256,
  createVacMemory: () => createVacMemory,
  createVault: () => createVault,
  decode: () => decode2,
  encode: () => encode3,
  encodeFeatures: () => encodeFeatures,
  extractNgrams: () => extractNgrams,
  hashToDim: () => hashToDim,
  toJson: () => toJson
});
module.exports = __toCommonJS(index_exports);

// src/cid.ts
var import_sha256 = require("@noble/hashes/sha256");
var dagCbor = __toESM(require("@ipld/dag-cbor"));
var import_cid = require("multiformats/cid");
var import_digest = require("multiformats/hashes/digest");
var DAG_CBOR_CODE = 113;
var SHA256_CODE = 18;
function computeCid(obj) {
  const bytes = dagCbor.encode(obj);
  const hash = (0, import_sha256.sha256)(bytes);
  const digest = (0, import_digest.create)(SHA256_CODE, hash);
  return import_cid.CID.createV1(DAG_CBOR_CODE, digest);
}
function computeCidString(obj) {
  return computeCid(obj).toString();
}
function computeSha256(data) {
  return (0, import_sha256.sha256)(data);
}
function computeProllyNodeHash(level, keys, values) {
  const parts = [];
  parts.push(level);
  const numKeys = keys.length;
  parts.push(numKeys >> 8 & 255);
  parts.push(numKeys & 255);
  for (const key of keys) {
    const keyLen = key.length;
    parts.push(keyLen >> 8 & 255);
    parts.push(keyLen & 255);
    parts.push(...key);
  }
  for (const value of values) {
    const valueBytes = new TextEncoder().encode(value);
    parts.push(...valueBytes);
  }
  return (0, import_sha256.sha256)(new Uint8Array(parts));
}

// src/codec.ts
var dagCbor2 = __toESM(require("@ipld/dag-cbor"));
function encode3(obj) {
  return dagCbor2.encode(obj);
}
function decode2(bytes) {
  return dagCbor2.decode(bytes);
}
function toJson(obj) {
  return JSON.stringify(obj, (_, value) => {
    if (value instanceof Uint8Array) {
      return Array.from(value);
    }
    return value;
  }, 2);
}

// src/store.ts
var MemoryStore = class {
  constructor() {
    this.data = /* @__PURE__ */ new Map();
  }
  async get(cid) {
    return this.data.get(cid) ?? null;
  }
  async put(bytes) {
    const cid = computeCid(bytes).toString();
    this.data.set(cid, bytes);
    return cid;
  }
  async has(cid) {
    return this.data.has(cid);
  }
  async delete(cid) {
    this.data.delete(cid);
  }
  get size() {
    return this.data.size;
  }
  clear() {
    this.data.clear();
  }
};
var VacStore = class {
  constructor(store) {
    this.store = store;
  }
  async getObject(cid) {
    const bytes = await this.store.get(cid);
    if (!bytes) return null;
    return decode2(bytes);
  }
  async putObject(obj) {
    const bytes = encode3(obj);
    return this.store.put(bytes);
  }
  async hasObject(cid) {
    return this.store.has(cid);
  }
  async deleteObject(cid) {
    return this.store.delete(cid);
  }
};

// src/red.ts
var DEFAULT_DIMS = 65536;
var DEFAULT_ETA = 0.1;
var SparseVector = class {
  constructor(dims = DEFAULT_DIMS) {
    this.dims = dims;
    this.entries = /* @__PURE__ */ new Map();
  }
  add(dim, value) {
    const current = this.entries.get(dim) ?? 0;
    this.entries.set(dim, current + value);
  }
  set(dim, value) {
    if (Math.abs(value) < 1e-10) {
      this.entries.delete(dim);
    } else {
      this.entries.set(dim, value);
    }
  }
  get(dim) {
    return this.entries.get(dim) ?? 0;
  }
  *nonzero() {
    for (const [dim, val] of this.entries) {
      yield [dim, val];
    }
  }
  nnz() {
    return this.entries.size;
  }
  norm() {
    let sum = 0;
    for (const val of this.entries.values()) {
      sum += val * val;
    }
    return Math.sqrt(sum);
  }
  normalize() {
    const n = this.norm();
    if (n > 1e-10) {
      for (const [dim, val] of this.entries) {
        this.entries.set(dim, val / n);
      }
    }
  }
  dot(other) {
    let result = 0;
    const [smaller, larger] = this.nnz() < other.nnz() ? [this.entries, other.entries] : [other.entries, this.entries];
    for (const [dim, val] of smaller) {
      const otherVal = larger.get(dim);
      if (otherVal !== void 0) {
        result += val * otherVal;
      }
    }
    return result;
  }
  cosineSimilarity(other) {
    const dot = this.dot(other);
    const normProduct = this.norm() * other.norm();
    return normProduct > 1e-10 ? dot / normProduct : 0;
  }
  toDistribution() {
    const dist = new Array(this.dims).fill(0);
    let sum = 0;
    for (const val of this.entries.values()) {
      sum += val;
    }
    if (sum > 1e-10) {
      for (const [dim, val] of this.entries) {
        dist[dim] = val / sum;
      }
    }
    return dist;
  }
};
function hashToDim(s, dims = DEFAULT_DIMS) {
  let hash = 0;
  for (let i = 0; i < s.length; i++) {
    const char = s.charCodeAt(i);
    hash = (hash << 5) - hash + char | 0;
  }
  return Math.abs(hash) % dims;
}
function extractNgrams(text, n) {
  if (text.length < n) return [text];
  const ngrams = [];
  for (let i = 0; i <= text.length - n; i++) {
    ngrams.push(text.slice(i, i + n));
  }
  return ngrams;
}
function encodeFeatures(entities, predicates, text, dims = DEFAULT_DIMS) {
  const vector = new SparseVector(dims);
  for (const entity of entities) {
    const dim = hashToDim(entity, dims);
    vector.add(dim, 2);
  }
  for (const predicate of predicates) {
    const dim = hashToDim(predicate, dims);
    vector.add(dim, 1.5);
  }
  for (const ngram of extractNgrams(text, 3)) {
    const dim = hashToDim(ngram, dims);
    vector.add(dim, 0.5);
  }
  vector.normalize();
  return vector;
}
function sigmoid(x) {
  return 1 / (1 + Math.exp(-x));
}
function softmax(x) {
  const maxX = Math.max(...x);
  const expX = x.map((xi) => Math.exp(xi - maxX));
  const sum = expX.reduce((a, b) => a + b, 0);
  return expX.map((e) => e / sum);
}
var RedEngine = class {
  constructor(dims = DEFAULT_DIMS, eta = DEFAULT_ETA) {
    this.dims = dims;
    this.eta = eta;
    this.totalObservations = 0;
    this.totalRetrievals = 0;
    const uniform = 1 / dims;
    this.prior = new Array(dims).fill(uniform);
    this.posterior = new Array(dims).fill(uniform);
    this.cumulativeLoss = new Array(dims).fill(0);
  }
  /**
   * Update belief distribution when new event is observed
   */
  observe(vector) {
    this.totalObservations++;
    for (const [dim, weight] of vector.nonzero()) {
      this.posterior[dim] *= 1 + this.eta * weight;
    }
    this.normalizePosterior();
  }
  /**
   * Update weights based on retrieval outcome (Hedge algorithm)
   */
  retrievalFeedback(vector, wasUseful) {
    this.totalRetrievals++;
    const loss = wasUseful ? 0 : 1;
    for (const [dim, weight] of vector.nonzero()) {
      this.cumulativeLoss[dim] += loss * weight;
      this.posterior[dim] *= Math.exp(-this.eta * loss * weight);
    }
    this.normalizePosterior();
  }
  /**
   * Compute entropy (novelty) via KL divergence
   */
  computeEntropy(vector) {
    const p = vector.toDistribution();
    const epsilon = 1e-10;
    let klDiv = 0;
    for (let dim = 0; dim < this.dims; dim++) {
      if (p[dim] > epsilon) {
        const qDim = Math.max(this.posterior[dim], epsilon);
        klDiv += p[dim] * Math.log(p[dim] / qDim);
      }
    }
    return sigmoid(klDiv - 1);
  }
  /**
   * Compute entropic displacement (learning signal)
   */
  computeDisplacement(oldPosterior) {
    const epsilon = 1e-10;
    let klDiv = 0;
    for (let dim = 0; dim < this.dims; dim++) {
      const pDim = Math.max(this.posterior[dim], epsilon);
      const qDim = Math.max(oldPosterior[dim], epsilon);
      klDiv += pDim * Math.log(pDim / qDim);
    }
    return klDiv;
  }
  /**
   * Periodic reframing (consolidation)
   */
  reframeNetwork() {
    if (this.totalRetrievals === 0) return;
    const avgLoss = this.cumulativeLoss.map(
      (loss) => loss / this.totalRetrievals
    );
    const invLoss = avgLoss.map((l) => 1 / (1 + l));
    this.prior = softmax(invLoss);
    this.cumulativeLoss.fill(0);
    const alpha = 0.1;
    for (let dim = 0; dim < this.dims; dim++) {
      this.posterior[dim] = (1 - alpha) * this.posterior[dim] + alpha * this.prior[dim];
    }
    this.normalizePosterior();
  }
  /**
   * Get current posterior
   */
  getPosterior() {
    return [...this.posterior];
  }
  normalizePosterior() {
    const sum = this.posterior.reduce((a, b) => a + b, 0);
    if (sum > 1e-10) {
      for (let i = 0; i < this.dims; i++) {
        this.posterior[i] /= sum;
      }
    }
  }
};
function computeEntropy(red, vector, conflictCount, timeSinceSimilarSecs) {
  const novelty = red.computeEntropy(vector);
  const conflictScore = Math.min(conflictCount / 3, 1);
  const temporalNovelty = 1 - Math.exp(-timeSinceSimilarSecs / (24 * 3600));
  return 0.4 * novelty + 0.3 * conflictScore + 0.3 * temporalNovelty;
}

// src/vault.ts
var Vault = class {
  constructor(config, store) {
    this.config = config;
    this.headBlockHash = null;
    this.blockNo = 0;
    this.pendingEvents = [];
    this.pendingClaims = [];
    this.store = store ?? new VacStore(new MemoryStore());
    this.red = new RedEngine();
  }
  /**
   * Create a new event
   */
  createEvent(payload, options = {}) {
    const payloadBytes = new TextEncoder().encode(JSON.stringify(payload));
    const payloadCid = computeCidString(payloadBytes);
    const source = options.source ?? {
      kind: "self",
      principal_id: this.config.ownerId
    };
    const vector = encodeFeatures(
      options.entities ?? [],
      [],
      typeof payload === "string" ? payload : JSON.stringify(payload)
    );
    const entropy = computeEntropy(this.red, vector, 0, 0);
    const event = {
      type: "event",
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
        recency: 1,
        connectivity: 0
      },
      source,
      trust_tier: source.kind === "self" ? 3 : 1,
      links: {},
      metadata: {}
    };
    this.red.observe(vector);
    this.pendingEvents.push(event);
    return event;
  }
  /**
   * Create a new claim
   */
  createClaim(subjectId, predicateKey, value, options = {}) {
    const source = options.source ?? {
      kind: "self",
      principal_id: this.config.ownerId
    };
    const valueType = typeof value === "string" ? "string" : typeof value === "number" ? "number" : typeof value === "boolean" ? "bool" : "json";
    const claim = {
      type: "claim_bundle",
      version: 1,
      subject_id: subjectId,
      predicate_key: predicateKey,
      value,
      value_type: valueType,
      units: options.units,
      epistemic: "observed",
      asserted_ts: Date.now(),
      confidence: options.confidence,
      evidence_refs: options.evidenceRefs ?? [],
      source,
      trust_tier: source.kind === "self" ? 3 : 1,
      links: {},
      metadata: {}
    };
    this.pendingClaims.push(claim);
    return claim;
  }
  /**
   * Commit pending changes to a new block
   */
  async commit(signingKey) {
    const addedCids = [];
    for (const event of this.pendingEvents) {
      const cid = await this.store.putObject(event);
      addedCids.push(cid);
    }
    for (const claim of this.pendingClaims) {
      const cid = await this.store.putObject(claim);
      addedCids.push(cid);
    }
    const patch = {
      type: "vault_patch",
      version: 1,
      parent_block_hash: this.headBlockHash ?? new Uint8Array(32),
      added_cids: addedCids,
      removed_refs: [],
      updated_roots: {},
      links: { added: addedCids },
      metadata: {}
    };
    const patchCid = await this.store.putObject(patch);
    const manifest = {
      type: "manifest_root",
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
      metadata: {}
    };
    const manifestCid = await this.store.putObject(manifest);
    const block = {
      type: "block_header",
      version: 1,
      block_no: this.blockNo,
      prev_block_hash: this.headBlockHash ?? new Uint8Array(32),
      ts: Date.now(),
      links: {
        patch: patchCid,
        manifest: manifestCid
      },
      signatures: [],
      block_hash: new Uint8Array(32),
      // Will be computed
      metadata: {}
    };
    const blockData = JSON.stringify({
      block_no: block.block_no,
      prev_block_hash: Array.from(block.prev_block_hash),
      ts: block.ts,
      patch: patchCid,
      manifest: manifestCid
    });
    const blockHashBytes = new TextEncoder().encode(blockData);
    block.block_hash = new Uint8Array(32);
    for (let i = 0; i < Math.min(blockHashBytes.length, 32); i++) {
      block.block_hash[i] = blockHashBytes[i];
    }
    await this.store.putObject(block);
    this.headBlockHash = block.block_hash;
    this.blockNo++;
    this.pendingEvents = [];
    this.pendingClaims = [];
    return block;
  }
  /**
   * Provide retrieval feedback to RED engine
   */
  feedback(entities, text, wasUseful) {
    const vector = encodeFeatures(entities, [], text);
    this.red.retrievalFeedback(vector, wasUseful);
  }
  /**
   * Trigger network reframing (consolidation)
   */
  reframe() {
    this.red.reframeNetwork();
  }
  /**
   * Get current block number
   */
  getBlockNo() {
    return this.blockNo;
  }
  /**
   * Get RED engine stats
   */
  getRedStats() {
    return {
      observations: this.red.totalObservations,
      retrievals: this.red.totalRetrievals
    };
  }
};
function createVault(config) {
  return new Vault(config);
}

// src/langchain.ts
var VacMemory = class {
  constructor(config) {
    this.sessionMessages = [];
    this.vault = new Vault(config);
  }
  /**
   * Load relevant memories for a query
   */
  async loadMemoryVariables(inputs) {
    const history = this.sessionMessages.map((msg, i) => ({
      cid: `session-${i}`,
      content: msg.content,
      timestamp: Date.now() - (this.sessionMessages.length - i) * 1e3,
      relevance: 1,
      source: msg.role
    }));
    return { history };
  }
  /**
   * Save interaction context to memory
   */
  async saveContext(input, output) {
    this.sessionMessages.push({ role: "user", content: input.input });
    this.sessionMessages.push({ role: "assistant", content: output.output });
    this.vault.createEvent(input.input, {
      tags: ["user_input"],
      actors: ["user"]
    });
    this.vault.createEvent(output.output, {
      tags: ["assistant_output"],
      actors: ["assistant"]
    });
  }
  /**
   * Extract and store claims from conversation
   */
  async extractClaims(text, subjectId) {
    const claims = [];
    const preferencePattern = /(\w+)\s+(prefers?|likes?)\s+(.+)/gi;
    let match;
    while ((match = preferencePattern.exec(text)) !== null) {
      const claim = this.vault.createClaim(
        subjectId,
        "preference:general",
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
  async commit() {
    await this.vault.commit();
  }
  /**
   * Provide feedback on retrieval usefulness
   */
  feedback(query, wasUseful) {
    this.vault.feedback([], query, wasUseful);
  }
  /**
   * Clear session memory (not persistent memory)
   */
  clearSession() {
    this.sessionMessages = [];
  }
  /**
   * Get memory statistics
   */
  getStats() {
    return {
      sessionMessages: this.sessionMessages.length,
      blockNo: this.vault.getBlockNo(),
      redStats: this.vault.getRedStats()
    };
  }
};
function createVacMemory(config) {
  return new VacMemory(config);
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  DEFAULT_DIMS,
  DEFAULT_ETA,
  MemoryStore,
  RedEngine,
  SparseVector,
  VacMemory,
  VacStore,
  Vault,
  computeCid,
  computeCidString,
  computeEntropy,
  computeProllyNodeHash,
  computeSha256,
  createVacMemory,
  createVault,
  decode,
  encode,
  encodeFeatures,
  extractNgrams,
  hashToDim,
  toJson
});

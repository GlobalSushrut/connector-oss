/**
 * Regressive Entropic Displacement (RED) engine for TypeScript
 *
 * Non-ML learning system based on:
 * - Maximum Entropy Principle (Jaynes)
 * - KL Divergence as information gain
 * - Multiplicative Weights Update (Hedge algorithm)
 */

/** Default dimensions for feature vectors */
export const DEFAULT_DIMS = 65536;

/** Default learning rate */
export const DEFAULT_ETA = 0.1;

/**
 * Sparse vector for feature representation
 */
export class SparseVector {
  private entries = new Map<number, number>();

  constructor(public readonly dims: number = DEFAULT_DIMS) {}

  add(dim: number, value: number): void {
    const current = this.entries.get(dim) ?? 0;
    this.entries.set(dim, current + value);
  }

  set(dim: number, value: number): void {
    if (Math.abs(value) < 1e-10) {
      this.entries.delete(dim);
    } else {
      this.entries.set(dim, value);
    }
  }

  get(dim: number): number {
    return this.entries.get(dim) ?? 0;
  }

  *nonzero(): Generator<[number, number]> {
    for (const [dim, val] of this.entries) {
      yield [dim, val];
    }
  }

  nnz(): number {
    return this.entries.size;
  }

  norm(): number {
    let sum = 0;
    for (const val of this.entries.values()) {
      sum += val * val;
    }
    return Math.sqrt(sum);
  }

  normalize(): void {
    const n = this.norm();
    if (n > 1e-10) {
      for (const [dim, val] of this.entries) {
        this.entries.set(dim, val / n);
      }
    }
  }

  dot(other: SparseVector): number {
    let result = 0;
    const [smaller, larger] =
      this.nnz() < other.nnz()
        ? [this.entries, other.entries]
        : [other.entries, this.entries];

    for (const [dim, val] of smaller) {
      const otherVal = larger.get(dim);
      if (otherVal !== undefined) {
        result += val * otherVal;
      }
    }
    return result;
  }

  cosineSimilarity(other: SparseVector): number {
    const dot = this.dot(other);
    const normProduct = this.norm() * other.norm();
    return normProduct > 1e-10 ? dot / normProduct : 0;
  }

  toDistribution(): number[] {
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
}

/**
 * Hash a string to a dimension
 */
export function hashToDim(s: string, dims: number = DEFAULT_DIMS): number {
  let hash = 0;
  for (let i = 0; i < s.length; i++) {
    const char = s.charCodeAt(i);
    hash = ((hash << 5) - hash + char) | 0;
  }
  return Math.abs(hash) % dims;
}

/**
 * Extract n-grams from text
 */
export function extractNgrams(text: string, n: number): string[] {
  if (text.length < n) return [text];
  const ngrams: string[] = [];
  for (let i = 0; i <= text.length - n; i++) {
    ngrams.push(text.slice(i, i + n));
  }
  return ngrams;
}

/**
 * Encode features into a sparse vector
 */
export function encodeFeatures(
  entities: string[],
  predicates: string[],
  text: string,
  dims: number = DEFAULT_DIMS
): SparseVector {
  const vector = new SparseVector(dims);

  // Entity features (highest weight)
  for (const entity of entities) {
    const dim = hashToDim(entity, dims);
    vector.add(dim, 2.0);
  }

  // Predicate features
  for (const predicate of predicates) {
    const dim = hashToDim(predicate, dims);
    vector.add(dim, 1.5);
  }

  // N-gram features
  for (const ngram of extractNgrams(text, 3)) {
    const dim = hashToDim(ngram, dims);
    vector.add(dim, 0.5);
  }

  vector.normalize();
  return vector;
}

/**
 * Sigmoid function
 */
function sigmoid(x: number): number {
  return 1 / (1 + Math.exp(-x));
}

/**
 * Softmax function
 */
function softmax(x: number[]): number[] {
  const maxX = Math.max(...x);
  const expX = x.map((xi) => Math.exp(xi - maxX));
  const sum = expX.reduce((a, b) => a + b, 0);
  return expX.map((e) => e / sum);
}

/**
 * Regressive Entropic Displacement engine
 */
export class RedEngine {
  private prior: number[];
  private posterior: number[];
  private cumulativeLoss: number[];
  public totalObservations = 0;
  public totalRetrievals = 0;

  constructor(
    public readonly dims: number = DEFAULT_DIMS,
    public readonly eta: number = DEFAULT_ETA
  ) {
    const uniform = 1 / dims;
    this.prior = new Array(dims).fill(uniform);
    this.posterior = new Array(dims).fill(uniform);
    this.cumulativeLoss = new Array(dims).fill(0);
  }

  /**
   * Update belief distribution when new event is observed
   */
  observe(vector: SparseVector): void {
    this.totalObservations++;

    for (const [dim, weight] of vector.nonzero()) {
      this.posterior[dim] *= 1 + this.eta * weight;
    }

    this.normalizePosterior();
  }

  /**
   * Update weights based on retrieval outcome (Hedge algorithm)
   */
  retrievalFeedback(vector: SparseVector, wasUseful: boolean): void {
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
  computeEntropy(vector: SparseVector): number {
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
  computeDisplacement(oldPosterior: number[]): number {
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
  reframeNetwork(): void {
    if (this.totalRetrievals === 0) return;

    // Compute average loss per dimension
    const avgLoss = this.cumulativeLoss.map(
      (loss) => loss / this.totalRetrievals
    );

    // Update prior using softmax
    const invLoss = avgLoss.map((l) => 1 / (1 + l));
    this.prior = softmax(invLoss);

    // Reset cumulative loss
    this.cumulativeLoss.fill(0);

    // Blend posterior toward new prior
    const alpha = 0.1;
    for (let dim = 0; dim < this.dims; dim++) {
      this.posterior[dim] =
        (1 - alpha) * this.posterior[dim] + alpha * this.prior[dim];
    }

    this.normalizePosterior();
  }

  /**
   * Get current posterior
   */
  getPosterior(): number[] {
    return [...this.posterior];
  }

  private normalizePosterior(): void {
    const sum = this.posterior.reduce((a, b) => a + b, 0);
    if (sum > 1e-10) {
      for (let i = 0; i < this.dims; i++) {
        this.posterior[i] /= sum;
      }
    }
  }
}

/**
 * Compute combined entropy score
 */
export function computeEntropy(
  red: RedEngine,
  vector: SparseVector,
  conflictCount: number,
  timeSinceSimilarSecs: number
): number {
  // 1. Entropic novelty via KL divergence
  const novelty = red.computeEntropy(vector);

  // 2. Contradiction score
  const conflictScore = Math.min(conflictCount / 3, 1);

  // 3. Temporal novelty (24h decay)
  const temporalNovelty = 1 - Math.exp(-timeSinceSimilarSecs / (24 * 3600));

  // 4. Weighted combination
  return 0.4 * novelty + 0.3 * conflictScore + 0.3 * temporalNovelty;
}

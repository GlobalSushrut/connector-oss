/**
 * GlueResult - Canonical success envelope
 */

export interface GlueReceipt {
  id: string;
  trace_id: string;
  timestamp_ms: number;
  cid?: string;
  policy?: string;
  verified?: boolean;
}

export interface ResourceInfo {
  id: string;
  uid?: string;
  kind: string;
  state?: string;
}

export interface ResultIntent {
  verb: string;
  noun: string;
  target: string;
}

export interface ResultSummary {
  title: string;
  message: string;
  status: string;
  why?: string;
  next?: string[];
}

export interface TrustInfo {
  score?: number;
  grade?: string;
  verified: boolean;
}

export interface EvidenceRef {
  kind: string;
  id: string;
  label?: string;
  verified: boolean;
}

export interface RenderHints {
  role: string;
  redacted: boolean;
  redacted_fields?: string[];
}

export interface ResultPresentation {
  mode: string;
  table_safe: boolean;
  row_count?: number;
  columns?: string[];
}

export interface ResultMeta {
  schema: string;
  view: string;
  source: string;
}

export interface GlueResult {
  ok: boolean;
  intent: ResultIntent;
  resource?: ResourceInfo;
  receipt?: GlueReceipt;
  summary?: ResultSummary;
  trust?: TrustInfo;
  evidence?: EvidenceRef[];
  links?: Record<string, string>;
  render?: RenderHints;
  presentation?: ResultPresentation;
  meta?: ResultMeta;
  data: Record<string, unknown>;
}

export function createSuccessResult(
  verb: string,
  noun: string,
  target: string
): GlueResult {
  return {
    ok: true,
    intent: { verb, noun, target },
    summary: {
      title: `${verb} ${noun}`,
      message: `${verb} ${noun} completed`,
      status: 'completed',
      next: [],
    },
    evidence: [],
    links: {},
    render: {
      role: 'developer',
      redacted: false,
      redacted_fields: [],
    },
    presentation: {
      mode: 'receipt',
      table_safe: false,
      columns: [],
    },
    meta: {
      schema: 'glue.v1',
      view: 'json',
      source: 'glue',
    },
    data: {},
  };
}

export function createReceipt(traceId: string): GlueReceipt {
  return {
    id: `rcpt_${traceId.slice(0, 8)}`,
    trace_id: traceId,
    timestamp_ms: Date.now(),
  };
}

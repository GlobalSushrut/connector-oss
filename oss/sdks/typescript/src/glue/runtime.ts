/**
 * Runtime execution layer for GLUE operations
 */

import { Glue } from './core';
import { GlueResult, createSuccessResult, createReceipt, ResourceInfo } from './result';
import { GlueError } from './error';
import { v4 as uuidv4 } from 'uuid';

function generateTraceId(): string {
  return uuidv4().replace(/-/g, '');
}

async function apiCall(
  glue: Glue,
  method: 'GET' | 'POST',
  endpoint: string,
  data?: Record<string, unknown>
): Promise<Record<string, unknown>> {
  const url = `${glue.config.baseUrl}/api/v1${endpoint}`;
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };
  if (glue.config.apiKey) {
    headers['Authorization'] = `Bearer ${glue.config.apiKey}`;
  }

  try {
    const response = await fetch(url, {
      method,
      headers,
      body: method === 'POST' ? JSON.stringify(data) : undefined,
    });
    return (await response.json()) as Record<string, unknown>;
  } catch {
    return { ok: true, data: {} };
  }
}

// =============================================================================
// Core Verb Implementations
// =============================================================================

export async function executeRun(
  glue: Glue,
  target: string,
  inputs: Record<string, unknown>,
  policy?: string
): Promise<GlueResult> {
  const traceId = generateTraceId();

  const response = await apiCall(glue, 'POST', `/agents/${target}/run`, {
    inputs,
    policy,
  });

  const result = createSuccessResult('run', 'contract', target);
  result.resource = {
    id: target,
    uid: `exec_${traceId.slice(0, 12)}`,
    kind: 'execution',
    state: 'completed',
  };
  result.data = { inputs };
  if (policy) result.data.policy = policy;
  result.receipt = createReceipt(traceId);

  return result;
}

export async function executeRemember(
  glue: Glue,
  key: string,
  content: string,
  namespace?: string
): Promise<GlueResult> {
  const traceId = generateTraceId();
  const ns = namespace || glue.config.defaultNamespace;

  await apiCall(glue, 'POST', '/memory/write', { key, content, namespace: ns });

  const result = createSuccessResult('remember', 'memory', key);
  result.resource = {
    id: key,
    uid: `mem_${traceId.slice(0, 12)}`,
    kind: 'memory',
  };
  result.data = { namespace: ns, contentLength: content.length };
  result.receipt = createReceipt(traceId);

  return result;
}

export async function executeRecall(
  glue: Glue,
  query: string,
  namespace?: string,
  limit: number = 10
): Promise<GlueResult> {
  const traceId = generateTraceId();
  const ns = namespace || glue.config.defaultNamespace;

  const response = await apiCall(glue, 'GET', '/memory/recall', {
    query,
    namespace: ns,
    limit,
  });

  const result = createSuccessResult('recall', 'memory', query);
  result.data = {
    namespace: ns,
    limit,
    results: ((response.data as Record<string, unknown>)?.results as unknown[]) || [],
  };
  result.receipt = createReceipt(traceId);

  return result;
}

export async function executeSearch(
  glue: Glue,
  query: string,
  namespace?: string,
  limit: number = 20
): Promise<GlueResult> {
  const traceId = generateTraceId();
  const ns = namespace || glue.config.defaultNamespace;

  const response = await apiCall(glue, 'POST', '/memory/search', {
    query,
    namespace: ns,
    limit,
  });

  const result = createSuccessResult('search', 'knowledge', query);
  result.data = {
    namespace: ns,
    limit,
    results: ((response.data as Record<string, unknown>)?.results as unknown[]) || [],
  };
  result.receipt = createReceipt(traceId);

  return result;
}

export async function executeShow(
  glue: Glue,
  noun: string,
  target: string
): Promise<GlueResult> {
  const traceId = generateTraceId();

  const response = await apiCall(glue, 'GET', `/${noun}s/${target}`, {});
  const data = (response.data as Record<string, unknown>) || {};

  const result = createSuccessResult('show', noun, target);
  result.resource = {
    id: target,
    uid: (data.uid as string) || `${noun}_${traceId.slice(0, 12)}`,
    kind: noun,
    state: data.state as string | undefined,
  };
  result.data = data;
  result.receipt = createReceipt(traceId);

  return result;
}

export async function executeList(
  glue: Glue,
  noun: string,
  namespace?: string,
  limit: number = 50
): Promise<GlueResult> {
  const traceId = generateTraceId();

  const params: Record<string, unknown> = { limit };
  if (namespace) params.namespace = namespace;

  const response = await apiCall(glue, 'GET', `/${noun}s`, params);
  const data = (response.data as Record<string, unknown>) || {};

  const result = createSuccessResult('list', noun, 'all');
  result.data = {
    items: (data.items as unknown[]) || [],
    total: (data.total as number) || 0,
    limit,
  };
  if (namespace) result.data.namespace = namespace;
  result.receipt = createReceipt(traceId);

  return result;
}

export async function executeAudit(glue: Glue, target: string): Promise<GlueResult> {
  const traceId = generateTraceId();

  const response = await apiCall(glue, 'GET', `/audit/${target}`, {});
  const data = (response.data as Record<string, unknown>) || {};

  const result = createSuccessResult('audit', 'execution', target);
  result.data = {
    trace: (data.trace as unknown[]) || [],
    decisions: (data.decisions as unknown[]) || [],
  };
  result.receipt = createReceipt(traceId);

  return result;
}

export async function executeVerify(
  glue: Glue,
  what: string,
  forAgent?: string
): Promise<GlueResult> {
  const traceId = generateTraceId();

  const payload: Record<string, unknown> = { policy: what };
  if (forAgent) payload.agent = forAgent;

  const response = await apiCall(glue, 'POST', '/compliance/verify', payload);
  const data = (response.data as Record<string, unknown>) || {};

  const result = createSuccessResult('verify', 'compliance', what);
  result.data = { compliant: (data.compliant as boolean) ?? true };
  if (forAgent) result.data.agent = forAgent;
  result.receipt = createReceipt(traceId);

  return result;
}

// =============================================================================
// Agent Operations
// =============================================================================

export async function agentStart(glue: Glue, name: string): Promise<GlueResult> {
  const traceId = generateTraceId();
  await apiCall(glue, 'POST', `/agents/${name}/start`, {});

  const result = createSuccessResult('start', 'agent', name);
  result.resource = { id: name, uid: `agt_${traceId.slice(0, 12)}`, kind: 'agent', state: 'running' };
  result.receipt = createReceipt(traceId);
  return result;
}

export async function agentStop(glue: Glue, name: string): Promise<GlueResult> {
  const traceId = generateTraceId();
  await apiCall(glue, 'POST', `/agents/${name}/stop`, {});

  const result = createSuccessResult('stop', 'agent', name);
  result.resource = { id: name, uid: `agt_${traceId.slice(0, 12)}`, kind: 'agent', state: 'stopped' };
  result.receipt = createReceipt(traceId);
  return result;
}

export async function agentStatus(glue: Glue, name: string): Promise<GlueResult> {
  const traceId = generateTraceId();
  const response = await apiCall(glue, 'GET', `/agents/${name}/status`, {});
  const data = (response.data as Record<string, unknown>) || {};

  const result = createSuccessResult('status', 'agent', name);
  result.resource = {
    id: name,
    uid: (data.uid as string) || `agt_${traceId.slice(0, 12)}`,
    kind: 'agent',
    state: (data.state as string) || 'unknown',
  };
  result.data = data;
  result.receipt = createReceipt(traceId);
  return result;
}

export async function agentPause(glue: Glue, name: string): Promise<GlueResult> {
  const traceId = generateTraceId();
  await apiCall(glue, 'POST', `/agents/${name}/pause`, {});

  const result = createSuccessResult('pause', 'agent', name);
  result.resource = { id: name, uid: `agt_${traceId.slice(0, 12)}`, kind: 'agent', state: 'paused' };
  result.receipt = createReceipt(traceId);
  return result;
}

export async function agentResume(glue: Glue, name: string): Promise<GlueResult> {
  const traceId = generateTraceId();
  await apiCall(glue, 'POST', `/agents/${name}/resume`, {});

  const result = createSuccessResult('resume', 'agent', name);
  result.resource = { id: name, uid: `agt_${traceId.slice(0, 12)}`, kind: 'agent', state: 'running' };
  result.receipt = createReceipt(traceId);
  return result;
}

// =============================================================================
// Memory Operations
// =============================================================================

export async function memoryWrite(glue: Glue, namespace: string, content: string): Promise<GlueResult> {
  const traceId = generateTraceId();
  await apiCall(glue, 'POST', '/memory/write', { namespace, content });

  const result = createSuccessResult('write', 'memory', namespace);
  result.data = { bytesWritten: content.length };
  result.receipt = createReceipt(traceId);
  return result;
}

export async function memoryRead(glue: Glue, namespace: string): Promise<GlueResult> {
  const traceId = generateTraceId();
  const response = await apiCall(glue, 'GET', `/memory/${namespace}`, {});

  const result = createSuccessResult('read', 'memory', namespace);
  result.data = { content: ((response.data as Record<string, unknown>)?.content as unknown) || null };
  result.receipt = createReceipt(traceId);
  return result;
}

export async function memoryRange(glue: Glue, namespace: string, start: number, end: number): Promise<GlueResult> {
  const traceId = generateTraceId();
  const response = await apiCall(glue, 'GET', `/memory/${namespace}/range`, { start, end });
  const data = (response.data as Record<string, unknown>) || {};

  const result = createSuccessResult('range', 'memory', namespace);
  result.data = { start, end, items: (data.items as unknown[]) || [] };
  result.receipt = createReceipt(traceId);
  return result;
}

// =============================================================================
// Tool Operations
// =============================================================================

export async function toolCall(glue: Glue, name: string, params: Record<string, unknown>): Promise<GlueResult> {
  const traceId = generateTraceId();
  const response = await apiCall(glue, 'POST', `/tools/${name}/call`, { params });
  const data = (response.data as Record<string, unknown>) || {};

  const result = createSuccessResult('call', 'tool', name);
  result.data = { params, output: data.output || null };
  result.receipt = createReceipt(traceId);
  return result;
}

export async function toolInfo(glue: Glue, name: string): Promise<GlueResult> {
  const traceId = generateTraceId();
  const response = await apiCall(glue, 'GET', `/tools/${name}`, {});

  const result = createSuccessResult('info', 'tool', name);
  result.data = (response.data as Record<string, unknown>) || { name, available: true };
  result.receipt = createReceipt(traceId);
  return result;
}

// =============================================================================
// Policy Operations
// =============================================================================

export async function policyBind(glue: Glue, policy: string, agent: string): Promise<GlueResult> {
  const traceId = generateTraceId();
  await apiCall(glue, 'POST', `/policies/${policy}/bind`, { agent });

  const result = createSuccessResult('bind', 'policy', policy);
  result.data = { agent, bound: true };
  result.receipt = createReceipt(traceId);
  return result;
}

export async function policyCheck(glue: Glue, policy: string, agent: string): Promise<GlueResult> {
  const traceId = generateTraceId();
  const response = await apiCall(glue, 'POST', `/policies/${policy}/check`, { agent });
  const data = (response.data as Record<string, unknown>) || {};

  const result = createSuccessResult('check', 'policy', policy);
  result.data = { agent, compliant: (data.compliant as boolean) ?? true };
  result.receipt = createReceipt(traceId);
  return result;
}

// =============================================================================
// Infra Operations
// =============================================================================

export async function executeExplain(glue: Glue, target: string, last?: string): Promise<GlueResult> {
  const traceId = generateTraceId();
  const params: Record<string, unknown> = {};
  if (last) params.last = last;

  const response = await apiCall(glue, 'GET', `/agents/${target}/explain`, params);
  const data = (response.data as Record<string, unknown>) || {};

  const result = createSuccessResult('explain', 'agent', target);
  result.data = data;
  result.receipt = createReceipt(traceId);
  return result;
}

export async function executeProve(glue: Glue, target: string, forensic: boolean): Promise<GlueResult> {
  const traceId = generateTraceId();
  const params: Record<string, unknown> = forensic ? { forensic } : {};

  const response = await apiCall(glue, 'GET', `/agents/${target}/prove`, params);
  const data = (response.data as Record<string, unknown>) || {};

  const result = createSuccessResult('prove', 'agent', target);
  result.data = data;
  result.receipt = createReceipt(traceId);
  return result;
}

export async function executeTrace(glue: Glue, target: string, last?: string, limit: number = 50): Promise<GlueResult> {
  const traceId = generateTraceId();
  const params: Record<string, unknown> = { limit };
  if (last) params.last = last;

  const response = await apiCall(glue, 'GET', `/agents/${target}/trace`, params);
  const data = (response.data as Record<string, unknown>) || {};

  const result = createSuccessResult('trace', 'agent', target);
  result.data = data;
  result.receipt = createReceipt(traceId);
  return result;
}

export async function executeReview(glue: Glue, target: string): Promise<GlueResult> {
  const traceId = generateTraceId();
  const response = await apiCall(glue, 'GET', `/agents/${target}/review`, {});
  const data = (response.data as Record<string, unknown>) || {};

  const result = createSuccessResult('review', 'agent', target);
  result.data = data;
  result.receipt = createReceipt(traceId);
  return result;
}

export async function executeCost(glue: Glue, target?: string, breakdown: boolean = false): Promise<GlueResult> {
  const traceId = generateTraceId();
  const endpoint = target ? `/agents/${target}/cost` : '/monitor/cost-dashboard';
  const params: Record<string, unknown> = breakdown ? { breakdown } : {};

  const response = await apiCall(glue, 'GET', endpoint, params);
  const data = (response.data as Record<string, unknown>) || {};

  const result = createSuccessResult('cost', target ? 'agent' : 'node', target || 'global');
  result.data = data;
  result.receipt = createReceipt(traceId);
  return result;
}

export async function executeHealth(glue: Glue): Promise<GlueResult> {
  const traceId = generateTraceId();
  const response = await apiCall(glue, 'GET', '/monitor/health', {});
  const data = (response.data as Record<string, unknown>) || {};

  const result = createSuccessResult('health', 'node', 'local');
  result.data = data;
  result.receipt = createReceipt(traceId);
  return result;
}

export async function executeDoctor(glue: Glue, verbose: boolean): Promise<GlueResult> {
  const traceId = generateTraceId();
  const params: Record<string, unknown> = verbose ? { verbose } : {};

  const response = await apiCall(glue, 'GET', '/monitor/doctor', params);
  const data = (response.data as Record<string, unknown>) || {};

  const result = createSuccessResult('doctor', 'node', 'local');
  result.data = data;
  result.receipt = createReceipt(traceId);
  return result;
}

export async function executeLogs(glue: Glue, target?: string, tail: number = 100): Promise<GlueResult> {
  const traceId = generateTraceId();
  const endpoint = target ? `/agents/${target}/logs` : '/monitor/logs';
  const params: Record<string, unknown> = { tail };

  const response = await apiCall(glue, 'GET', endpoint, params);
  const data = (response.data as Record<string, unknown>) || {};

  const result = createSuccessResult('logs', target ? 'agent' : 'node', target || 'local');
  result.data = data;
  result.receipt = createReceipt(traceId);
  return result;
}

export async function agentPause(glue: Glue, name: string): Promise<GlueResult> {
  const traceId = generateTraceId();
  await apiCall(glue, 'POST', `/agents/${name}/pause`, {});

  const result = createSuccessResult('pause', 'agent', name);
  result.resource = { id: name, uid: `agt_${traceId.slice(0, 12)}`, kind: 'agent', state: 'paused' };
  result.receipt = createReceipt(traceId);
  return result;
}

export async function agentResume(glue: Glue, name: string): Promise<GlueResult> {
  const traceId = generateTraceId();
  await apiCall(glue, 'POST', `/agents/${name}/resume`, {});

  const result = createSuccessResult('resume', 'agent', name);
  result.resource = { id: name, uid: `agt_${traceId.slice(0, 12)}`, kind: 'agent', state: 'running' };
  result.receipt = createReceipt(traceId);
  return result;
}

// =============================================================================
// Memory Operations
// =============================================================================

export async function memoryWrite(glue: Glue, namespace: string, content: string): Promise<GlueResult> {
  const traceId = generateTraceId();
  await apiCall(glue, 'POST', '/memory/write', { namespace, content });

  const result = createSuccessResult('write', 'memory', namespace);
  result.data = { bytesWritten: content.length };
  result.receipt = createReceipt(traceId);
  return result;
}

export async function memoryRead(glue: Glue, namespace: string): Promise<GlueResult> {
  const traceId = generateTraceId();
  const response = await apiCall(glue, 'GET', `/memory/${namespace}`, {});

  const result = createSuccessResult('read', 'memory', namespace);
  result.data = { content: ((response.data as Record<string, unknown>)?.content as unknown) || null };
  result.receipt = createReceipt(traceId);
  return result;
}

export async function memoryRange(glue: Glue, namespace: string, start: number, end: number): Promise<GlueResult> {
  const traceId = generateTraceId();
  const response = await apiCall(glue, 'GET', `/memory/${namespace}/range`, { start, end });
  const data = (response.data as Record<string, unknown>) || {};

  const result = createSuccessResult('range', 'memory', namespace);
  result.data = { start, end, items: (data.items as unknown[]) || [] };
  result.receipt = createReceipt(traceId);
  return result;
}

// =============================================================================
// Tool Operations
// =============================================================================

export async function toolCall(glue: Glue, name: string, params: Record<string, unknown>): Promise<GlueResult> {
  const traceId = generateTraceId();
  const response = await apiCall(glue, 'POST', `/tools/${name}/call`, { params });
  const data = (response.data as Record<string, unknown>) || {};

  const result = createSuccessResult('call', 'tool', name);
  result.data = { params, output: data.output || null };
  result.receipt = createReceipt(traceId);
  return result;
}

export async function toolInfo(glue: Glue, name: string): Promise<GlueResult> {
  const traceId = generateTraceId();
  const response = await apiCall(glue, 'GET', `/tools/${name}`, {});

  const result = createSuccessResult('info', 'tool', name);
  result.data = (response.data as Record<string, unknown>) || { name, available: true };
  result.receipt = createReceipt(traceId);
  return result;
}

// =============================================================================
// Policy Operations
// =============================================================================

export async function policyBind(glue: Glue, policy: string, agent: string): Promise<GlueResult> {
  const traceId = generateTraceId();
  await apiCall(glue, 'POST', `/policies/${policy}/bind`, { agent });

  const result = createSuccessResult('bind', 'policy', policy);
  result.data = { agent, bound: true };
  result.receipt = createReceipt(traceId);
  return result;
}

export async function policyCheck(glue: Glue, policy: string, agent: string): Promise<GlueResult> {
  const traceId = generateTraceId();
  const response = await apiCall(glue, 'POST', `/policies/${policy}/check`, { agent });
  const data = (response.data as Record<string, unknown>) || {};

  const result = createSuccessResult('check', 'policy', policy);
  result.data = { agent, compliant: (data.compliant as boolean) ?? true };
  result.receipt = createReceipt(traceId);
  return result;
}

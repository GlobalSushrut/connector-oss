/**
 * Minimal TypeScript Gloo authoring mirror — same JSON digest algorithm as Python.
 * Not a full runtime; produces Tool/Agent/Graph specs with identical digests.
 */

import { createHash } from "node:crypto";

export const TOOL_SPEC_SCHEMA = "connector.tool_spec.v1";
export const AGENT_SPEC_SCHEMA = "connector.agent_spec.v1";
export const GRAPH_SPEC_SCHEMA = "connector.graph_spec.v1";

function digest(obj: unknown): string {
  const sorted = JSON.stringify(sortKeys(obj));
  const hex = createHash("sha256").update(sorted).digest("hex");
  return `spec-sha256-${hex}`;
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(value as object).sort()) {
      out[k] = sortKeys((value as Record<string, unknown>)[k]);
    }
    return out;
  }
  return value;
}

export type EffectRow = {
  effect_class: string;
  mutates: boolean;
  disclosure_class?: string;
};

export type ToolSpec = {
  schema: string;
  tool_id: string;
  name: string;
  effect: EffectRow;
  input_schema: Record<string, unknown>;
  output_schema: Record<string, unknown>;
  timeout_ms: number;
  digest: string;
};

export function toolSpec(input: {
  tool_id: string;
  name: string;
  effect: EffectRow;
  input_schema?: Record<string, unknown>;
  output_schema?: Record<string, unknown>;
  timeout_ms?: number;
}): ToolSpec {
  const body = {
    schema: TOOL_SPEC_SCHEMA,
    tool_id: input.tool_id,
    name: input.name,
    effect: input.effect,
    input_schema: input.input_schema ?? {},
    output_schema: input.output_schema ?? {},
    timeout_ms: input.timeout_ms ?? 30_000,
  };
  return { ...body, digest: digest(body) };
}

export function agentSpec(input: {
  name: string;
  model?: string;
  tools?: string[];
  purpose?: string;
}): Record<string, unknown> {
  const body = {
    schema: AGENT_SPEC_SCHEMA,
    name: input.name,
    model_requirements: { route: input.model ?? "provider-neutral/default" },
    tools: input.tools ?? [],
    output_schema: {},
    purpose: input.purpose ?? "",
    deps_schema: {},
  };
  return { ...body, digest: digest(body) };
}

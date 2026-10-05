/**
 * CompiledContract - CLS contract representation
 */

export interface ParamDef {
  name: string;
  typeName: string;
  required: boolean;
  description?: string;
}

export interface CompiledContract {
  cid: string;
  name: string;
  version?: string;
  source?: string;
  inputs: ParamDef[];
  outputs: ParamDef[];
  tools: string[];
  capabilities: string[];
  policies: string[];
  metadata: Record<string, unknown>;
}

export function createContract(cid: string, name: string): CompiledContract {
  return {
    cid,
    name,
    inputs: [],
    outputs: [],
    tools: [],
    capabilities: [],
    policies: [],
    metadata: {},
  };
}

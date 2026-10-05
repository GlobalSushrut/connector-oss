/**
 * CLS - Connector Logic System embedding for TypeScript
 * 
 * Allows CLS contracts to be written directly in TypeScript using tagged templates.
 */

import { CompiledContract, createContract } from './contract';
import { GlueError, ErrorCode } from './error';
import * as crypto from 'crypto';

const contractCache = new Map<string, CompiledContract>();

/**
 * Tagged template literal for CLS contracts.
 * 
 * @example
 * ```typescript
 * const contract = cls`
 *   contract hello {
 *     interface {
 *       input name: string required
 *       output greeting: string
 *     }
 *   }
 * `;
 * ```
 */
export function cls(
  strings: TemplateStringsArray,
  ...values: unknown[]
): CompiledContract {
  // Reconstruct the source with interpolated values
  let source = strings[0];
  for (let i = 0; i < values.length; i++) {
    source += String(values[i]) + strings[i + 1];
  }
  
  return compile(source);
}

/**
 * Compile CLS source code into a CompiledContract.
 */
export function compile(source: string): CompiledContract {
  // Generate hash for caching
  const hash = crypto.createHash('sha256').update(source).digest('hex').slice(0, 32);
  
  // Check cache
  const cached = contractCache.get(hash);
  if (cached) return cached;
  
  // Parse and compile
  const contract = parseContract(source, hash);
  contractCache.set(hash, contract);
  
  return contract;
}

function parseContract(source: string, hash: string): CompiledContract {
  const cid = `cls1-sha256-${hash}`;
  
  // Extract contract name
  const nameMatch = source.match(/contract\s+(\w+)/);
  if (!nameMatch) {
    throw new GlueError(
      ErrorCode.COMPILE_ERROR,
      'Invalid contract: missing contract name',
      'Expected: contract <name> { ... }'
    );
  }
  
  const name = nameMatch[1];
  const contract = createContract(cid, name);
  contract.source = source;
  
  // Extract version if present
  const versionMatch = source.match(/version\s*:\s*"([^"]+)"/);
  if (versionMatch) {
    contract.version = versionMatch[1];
  }
  
  // Extract inputs
  const inputRegex = /input\s+(\w+)\s*:\s*(\w+)(\s+required)?/g;
  let match;
  while ((match = inputRegex.exec(source)) !== null) {
    contract.inputs.push({
      name: match[1],
      typeName: match[2],
      required: !!match[3],
    });
  }
  
  // Extract outputs
  const outputRegex = /output\s+(\w+)\s*:\s*(\w+)/g;
  while ((match = outputRegex.exec(source)) !== null) {
    contract.outputs.push({
      name: match[1],
      typeName: match[2],
      required: true,
    });
  }
  
  // Extract tools
  const toolRegex = /tool\s+(\w+)/g;
  while ((match = toolRegex.exec(source)) !== null) {
    contract.tools.push(match[1]);
  }
  
  return contract;
}

/**
 * Contract builder for programmatic contract creation.
 */
export class ContractBuilder {
  private _name: string;
  private _version?: string;
  private _domain?: string;
  private _inputs: Array<{ name: string; type: string; required: boolean }> = [];
  private _outputs: Array<{ name: string; type: string }> = [];
  private _tools: Array<{ name: string; binding: string }> = [];
  private _policies: Array<{ kind: string; subject: string }> = [];

  constructor(name: string) {
    this._name = name;
  }

  version(v: string): this {
    this._version = v;
    return this;
  }

  domain(d: string): this {
    this._domain = d;
    return this;
  }

  input(name: string, type: string, options: { required?: boolean } = {}): this {
    this._inputs.push({ name, type, required: options.required ?? false });
    return this;
  }

  output(name: string, type: string): this {
    this._outputs.push({ name, type });
    return this;
  }

  tool(name: string, binding: string = 'advisory'): this {
    this._tools.push({ name, binding });
    return this;
  }

  policy(kind: 'require' | 'deny', subject: string): this {
    this._policies.push({ kind, subject });
    return this;
  }

  build(): CompiledContract {
    const source = this.generateSource();
    return compile(source);
  }

  private generateSource(): string {
    const lines: string[] = [`contract ${this._name} {`];

    // Solution block
    if (this._version || this._domain) {
      lines.push(`    solution ${this._name} {`);
      if (this._version) lines.push(`        version: "${this._version}"`);
      if (this._domain) lines.push(`        domain: "${this._domain}"`);
      lines.push('    }');
    }

    // Interface block
    if (this._inputs.length > 0 || this._outputs.length > 0) {
      lines.push('    interface {');
      for (const inp of this._inputs) {
        const req = inp.required ? ' required' : '';
        lines.push(`        input ${inp.name}: ${inp.type}${req}`);
      }
      for (const out of this._outputs) {
        lines.push(`        output ${out.name}: ${out.type}`);
      }
      lines.push('    }');
    }

    // Capabilities block
    if (this._tools.length > 0) {
      lines.push('    capabilities {');
      for (const tool of this._tools) {
        lines.push(`        tool ${tool.name} ${tool.binding}`);
      }
      lines.push('    }');
    }

    // Policy block
    if (this._policies.length > 0) {
      lines.push('    policy {');
      for (const pol of this._policies) {
        lines.push(`        ${pol.kind} ${pol.subject}`);
      }
      lines.push('    }');
    }

    lines.push('}');
    return lines.join('\n');
  }
}

/**
 * Create a contract using the builder pattern.
 */
export function contract(name: string): ContractBuilder {
  return new ContractBuilder(name);
}

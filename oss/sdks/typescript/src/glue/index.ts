/**
 * GLUE - Governed Logic Unification Engine
 * 
 * The canonical TypeScript interface for Connector. GLUE replaces traditional SDKs
 * with a governed, auditable execution surface.
 * 
 * @example
 * ```typescript
 * import { glue, cls } from '@connector/glue';
 * 
 * // Compile and run a CLS contract
 * const contract = cls`
 *   contract hello {
 *     interface {
 *       input name: string required
 *       output greeting: string
 *     }
 *   }
 * `;
 * 
 * const result = await glue.run(contract, { name: "World" });
 * console.log(result.data.greeting);
 * ```
 */

export { Glue, GlueConfig } from './core';
export { cls, compile } from './cls';
export { GlueResult, GlueReceipt, ResourceInfo, ResultIntent } from './result';
export { GlueError, ErrorCode } from './error';
export { GlueSession } from './session';
export { CompiledContract, ParamDef } from './contract';
export { AgentHandle, MemoryHandle, ToolHandle, PolicyHandle } from './handles';
export { GlueVerb, GlueNoun, GlueVerbType, GlueNounType } from './types';

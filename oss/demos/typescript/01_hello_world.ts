/**
 * Demo 1 — Hello World (TypeScript, 5 capabilities, YAML config)
 *
 * Run:
 *   export OPENAI_API_KEY=sk-...
 *   # start server: cd connector && cargo run -p connector-server
 *   npx ts-node demos/typescript/01_hello_world.ts
 */
import { Connector } from '../../sdks/typescript/src/connector'

async function main() {
  // load from YAML — Rust kernel handles env-var interpolation
  // run from repo root: npx ts-node demos/typescript/01_hello_world.ts
  const c = await Connector.fromConfig('demos/python/hello.yaml', 'http://localhost:9090')

  const agent = c.agent('bot', 'You are a concise assistant.')

  // 1. Agent execution
  const r1 = await agent.run('What is 2+2? One sentence.', { user: 'alice' })
  console.log(`[1] text=${JSON.stringify(r1.text)}  trust=${r1.trust}/100  grade=${r1.trustGrade}  ok=${r1.ok}`)

  // 2. Kernel memory — event_count grows with each run
  const r2 = await agent.run('Capital of France?',  { user: 'alice' })
  const r3 = await agent.run('Name three planets.', { user: 'alice' })
  console.log(`[2] event_counts: ${r1.eventCount} → ${r2.eventCount} → ${r3.eventCount}`)

  // 3. CID / trace provenance — every run gets a unique trace_id
  console.log(`[3] trace_ids unique: ${new Set([r1.traceId, r2.traceId, r3.traceId]).size === 3}`)
  console.log(`    r1.traceId=${r1.traceId}`)

  // 4. Namespace isolation — two agents, separate trace contexts
  const ra = await c.agent('alice', 'Help Alice.').run('Alice secret=42', { user: 'alice' })
  const rb = await c.agent('bob',   'Help Bob.').run('Bob secret=99',   { user: 'bob' })
  console.log(`[4] alice ok=${ra.ok} trust=${ra.trust}  bob ok=${rb.ok} trust=${rb.trust}`)
  console.log(`    traces isolated: ${ra.traceId !== rb.traceId}`)

  // 5. Audit trail — provenance summary on every result
  const prov = typeof r1.provenance === 'string' ? JSON.parse(r1.provenance) : r1.provenance
  console.log(`[5] verified=${r1.verified}  warnings=${r1.warnings.length}  errors=${r1.errors.length}`)
  console.log(`    provenance:`, prov)

  console.log('\nDone.')
}

main().catch(e => { console.error(e.message); throw e })

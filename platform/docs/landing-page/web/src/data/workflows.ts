/** Ten marketed workflows. Three are tryable today. Seven are on the map. */

export type WorkflowStatus = 'ready' | 'planned'

export interface Workflow {
  slug: string
  name: string
  color: string
  /** One-line sell. Keep it a buyer sentence, not a kernel lecture. */
  tagline: string
  outcome: string
  problem: string
  tags: string[]
  status: WorkflowStatus
  /** Product page, or null for workflows that are not a plugin yet. */
  href: string | null
}

export const WORKFLOWS: Workflow[] = [
  {
    slug: 'devguard',
    name: 'DevGuard',
    color: '#f87171',
    tagline: 'Coding-agent guardrails — files, commands, secrets, git',
    outcome: 'Your coding agent cannot touch what it should not.',
    problem:
      'Cursor, Claude Code, and similar tools read .env files, edit production configs, and run shell with no lane.',
    tags: ['Coding agents', 'Security'],
    status: 'ready',
    href: '/products/devguard',
  },
  {
    slug: 'tracetramp',
    name: 'TraceTramp',
    color: '#5ba8ff',
    tagline: 'Who did what — execution graph, no extra instrumentation',
    outcome: 'See the path: tools, order, identity. Reconstruct a governed run.',
    problem:
      'When an agent misbehaves you have logs from the model, not a graph of what it actually did.',
    tags: ['Observability', 'Incident'],
    status: 'ready',
    href: '/products/tracetramp',
  },
  {
    slug: 'witnessctl',
    name: 'WitnessCtl',
    color: '#3ecf8e',
    tagline: 'Tamper-evident receipts for every admitted action',
    outcome: 'Hand a reviewer a chain they can inspect — not a CSV dump.',
    problem:
      'Reviewers ask what the agent decided. You hand them mutable logs. That is not evidence.',
    tags: ['Evidence', 'Review'],
    status: 'ready',
    href: '/products/witnessctl',
  },
  {
    slug: 'conductor',
    name: 'Conductor',
    color: '#a78bfa',
    tagline: 'Multi-agent orchestration with runtime enforcement',
    outcome: 'Named handoffs. Failures stop the pipeline instead of going silent.',
    problem:
      'Multi-agent pipelines are hand-wired. One silent failure takes the whole job down.',
    tags: ['Multi-agent', 'Orchestration'],
    status: 'planned',
    href: '/products/conductor',
  },
  {
    slug: 'agentloop',
    name: 'AgentLoop',
    color: '#34d399',
    tagline: 'Fleet lifecycle — spawn, watch, suspend, recover',
    outcome: 'One plane for agents that hang, drift, or need a kill switch.',
    problem:
      'Agents start, hang, or go rogue with no single control plane.',
    tags: ['Fleet', 'SRE'],
    status: 'planned',
    href: '/products/agentloop',
  },
  {
    slug: 'ledgerlens',
    name: 'LedgerLens',
    color: '#fbbf24',
    tagline: 'Hard cost caps per agent, team, and model',
    outcome: 'The loop stops at the budget. Gateway cost-cap posture exists; the LedgerLens SKU is planned.',
    problem:
      'LLM bills arrive with no breakdown by team, agent, or model. A hard-stop SKU is not packaged yet.',
    tags: ['FinOps', 'Cost'],
    status: 'planned',
    href: '/products/ledgerlens',
  },
  {
    slug: 'agentpassport',
    name: 'AgentPassport',
    color: '#fb923c',
    tagline: 'Portable identity for every intelligence',
    outcome: 'Who-am-I that another process cannot spoof.',
    problem:
      'Agents have a name in a prompt. Impersonation is undetectable.',
    tags: ['Identity', 'Zero-trust'],
    status: 'planned',
    href: '/products/agentpassport',
  },
  {
    slug: 'relay',
    name: 'Relay',
    color: '#38bdf8',
    tagline: 'Sit beneath any HTTP agent, SDK, or graph',
    outcome: 'Keep your stack. Governance on the path in.',
    problem:
      'Adding governance means rewriting the agent. Teams skip it.',
    tags: ['Integration', 'Platform'],
    status: 'planned',
    href: '/products/relay',
  },
  {
    slug: 'engram',
    name: 'Engram',
    color: '#c084fc',
    tagline: 'Memory that outlives one graph run',
    outcome: 'Scoped recall with provenance — not a shared bag of embeddings.',
    problem:
      'Agents write anything to memory and read it back as fact.',
    tags: ['Memory', 'Provenance'],
    status: 'planned',
    href: '/products/engram',
  },
  {
    slug: 'support-cx',
    name: 'Support / CX',
    color: '#94a3b8',
    tagline: 'Refunds, tickets, and customer actions with a stop button',
    outcome: 'A support agent can act — and you can stop and prove. Stop is not undo.',
    problem:
      'Customer-facing agents issue refunds and change accounts with no named owner and no kill switch.',
    tags: ['Support', 'CX'],
    status: 'planned',
    href: null,
  },
]

export const READY_WORKFLOWS = WORKFLOWS.filter(w => w.status === 'ready')
export const PLANNED_WORKFLOWS = WORKFLOWS.filter(w => w.status === 'planned')

export function workflowBySlug(slug: string): Workflow | undefined {
  return WORKFLOWS.find(w => w.slug === slug)
}

export function isWorkflowReady(slug: string): boolean {
  return workflowBySlug(slug)?.status === 'ready'
}

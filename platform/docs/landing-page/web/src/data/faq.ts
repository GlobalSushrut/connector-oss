export interface FaqItem {
  q: string
  a: string
  category: string
}

export const FAQ: FaqItem[] = [
  {
    category: 'General',
    q: 'What is Connector?',
    a: 'A self-hosted operating substrate for intelligence: identity, admission, isolation, memory, and audit on one node. Agents, models, tools, and workflows run on it. TraceTramp, WitnessCtl, and DevGuard are institutions on that OS — not a second kernel, and not a coding-agent product.',
  },
  {
    category: 'General',
    q: 'What can I try today?',
    a: 'Three institutions: DevGuard, TraceTramp, and WitnessCtl. Open try.cnktros.com/trial, enter your email, start 90 minutes. You get a private node. Other emails cannot see yours. Up to 10 people can try at once. Seven more workflows are planned.',
  },
  {
    category: 'General',
    q: 'Is Connector an agent framework?',
    a: 'No. You keep your agents, SDKs, graphs, or IDEs. Point them at this node. Connector admits or refuses effects, then records who did what. It is the OS underneath — not another framework and not a coding assistant.',
  },
  {
    category: 'General',
    q: 'Do I need to rewrite my agents?',
    a: 'The ready path is a self-hosted node (or the playground) in front of OpenAI- or Anthropic-compatible /v1 calls you already make. A dedicated Relay plugin for arbitrary HTTP without any client change is planned, not ready.',
  },
  {
    category: 'Ready',
    q: 'What does DevGuard do?',
    a: 'It is the institution for workstation coding agents: files, commands, secrets, git. One client of the OS. Ready to try in the playground.',
  },
  {
    category: 'Ready',
    q: 'What does TraceTramp do?',
    a: 'It records the execution path on governed traffic — tools, order, identity — so you can see who did what when something breaks. Ready to try.',
  },
  {
    category: 'Ready',
    q: 'What does WitnessCtl do?',
    a: 'It writes an HMAC-chained journal of admitted actions. A reviewer can inspect the chain. That is evidence, not a SOC 2 or HIPAA certificate, and not court-grade multi-party custody.',
  },
  {
    category: 'Kernel',
    q: 'How does isolation actually work?',
    a: 'World addresses need an owner grant. Network dials from the node go through dest-pinned Landlock children (pore table, default DROP). LLM vendor HTTPS can be DROPped on the host except the cage mark when a session is connected (needs CAP_NET_ADMIN for nft). Browser exploration is a granted document GET, not Chromium computer-use. Firecracker MicroCell is a separate isolation plane — not the default claim of this page.',
  },
  {
    category: 'Planned',
    q: 'What about Conductor, cost caps, identity, Relay, and memory?',
    a: 'The node already has a memory kernel, /v1 gateway, identity at boot, and a cost-cap hard-stop posture. Conductor, AgentLoop, LedgerLens, AgentPassport, Relay, Engram, and Support/CX are product packaging still on the map. If one of those products is why you would buy, that is a design partnership — not a download of that SKU.',
  },
  {
    category: 'Evidence',
    q: 'Are you SOC 2, HIPAA, or FedRAMP certified?',
    a: 'No. We do not sell those as a checkbox. Receipts are something a reviewer can inspect. Framework mapping is a design-partner path.',
  },
  {
    category: 'Evidence',
    q: 'Can I generate a proof bundle?',
    a: 'Yes for a session trail: connectorctl prove agent <id> assembles HMAC-chained receipts. It does not map to SOC 2 CC controls out of the box, and it is not a certification artifact.',
  },
  {
    category: 'Access',
    q: 'How do I try it?',
    a: 'Go to try.cnktros.com/trial. Enter your email. That address owns a private 90-minute node with one Demo agent and three institutions. Same email can start again and gets a new Demo session. A paid pilot is a real node on your infrastructure.',
  },
  {
    category: 'Access',
    q: 'Is the playground a real node?',
    a: 'Yes. Hosted on Fly.io (not Vercel). Your email gets an isolated tenant, one Demo agent, three institutions on the node, and a 90-minute idle clock. It is not your production deployment. Five emails means five separate playgrounds.',
  },
]

export const FAQ_CATEGORIES = [...new Set(FAQ.map(f => f.category))]

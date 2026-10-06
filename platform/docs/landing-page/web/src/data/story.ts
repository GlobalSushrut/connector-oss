/** Claimable today. Matches the public README. Do not add a product name here. */
export const OUTCOMES = [
  {
    title: 'One decision per action',
    body: 'Before an agent sends a request, changes data, calls a tool, spends money, or contacts another agent, Connector admits or refuses that action. The answers are Proceed, Ask, Defer, Quarantine, or Block.',
  },
  {
    title: 'Stop does not ask the model',
    body: 'An operator can pause, stop, or Cease. Cease fences the current generation and stops the next admission. It does not wait for the model to agree.',
  },
  {
    title: 'A receipt you can inspect',
    body: 'Admission and what was observed share a trail. A reviewer can read it. That trail is not a SOC 2, HIPAA, or FedRAMP certificate.',
  },
  {
    title: 'Identity, knowledge, and authority stay apart',
    body: 'Who the agent is, what it knows, what it is told, what it remembers, and what it may do are separate. Memory is a MemPacket, not a line in the trace.',
  },
  {
    title: 'A pasted address is not a grant',
    body: 'Authority is scoped to the agent and the action. Pointing at a URL does not authorize it. A tool credential does not authorize the whole process.',
  },
  {
    title: 'You run it yourself',
    body: 'Clone connector-oss and run ./up.sh. Open http://127.0.0.1:9091/ and choose Open on this machine. The local development token stays on your computer.',
  },
] as const

/** Not shipping. Named so a reader can see the gap. */
export const FUTURE = [
  {
    title: 'Traffic that is actually forwarded',
    body: 'agentgateway is the intended path for LLM, MCP, A2A, and HTTP. The image can start. A real forwarded request has not been proven, so forwarding stays off.',
  },
  {
    title: 'A microVM, not only a binary',
    body: 'Firecracker boot downloads the official binary and jailer. It does not create a microVM kernel or root filesystem. World dials today use dest-pinned Landlock.',
  },
  {
    title: 'Backends the action actually uses',
    body: './up.sh starts identity, enforcement, and evidence components. Starting them does not yet prove every admitted effect passed through the component that owns that job.',
  },
  {
    title: 'A production claim',
    body: 'Not made. Production readiness, security, correctness, safety, and compliance stay off this site until the limits above are closed.',
  },
] as const

export const MAINTAINER = {
  name: 'Umesh Adhikari',
  email: 'Umeshlamton@gmail.com',
  linkedin: 'https://www.linkedin.com/in/umesh-adhikari-231586229',
  linkedinLabel: 'linkedin.com/in/umesh-adhikari-231586229',
} as const

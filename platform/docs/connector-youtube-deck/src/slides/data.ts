export const slideCount = 20;

export interface SlideMeta {
  id: number;
  title: string;
  subtitle: string;
}

export const slides: SlideMeta[] = [
  { id: 1, title: 'Stack placement', subtitle: 'Agents, control plane, systems of record' },
  { id: 2, title: 'Layered platform', subtitle: 'From APIs to cryptographic base' },
  { id: 3, title: 'Request journey', subtitle: 'One path from intent to proof' },
  { id: 4, title: 'Two kernels', subtitle: 'Durable memory vs. governed actions' },
  { id: 5, title: 'Governance loop', subtitle: 'Policy, audit, replay, attest' },
  { id: 6, title: 'What is Connector?', subtitle: 'Opening frame for your channel' },
  { id: 7, title: 'Plain-English definition', subtitle: 'One paragraph anyone can repeat' },
  { id: 8, title: 'The hard problem', subtitle: 'Why “just shipping an agent” fails at scale' },
  { id: 9, title: 'Three pillars', subtitle: 'Control, memory, and proof' },
  { id: 10, title: 'Who it is for', subtitle: 'Roles and teams that get value first' },
  { id: 11, title: 'Use case · regulated AI', subtitle: 'Healthcare, finance, public sector' },
  { id: 12, title: 'Use case · agent platforms', subtitle: 'Internal copilots and tool-using agents' },
  { id: 13, title: 'Use case · workflow + receipts', subtitle: 'Automation that can be defended' },
  { id: 14, title: 'Workflow · human gates', subtitle: 'Approvals and escalations' },
  { id: 15, title: 'Workflow · pipelines', subtitle: 'Multi-step sagas and handoffs' },
  { id: 16, title: 'Workflow · APIs & events', subtitle: 'Systems calling systems' },
  { id: 17, title: 'Enterprise signals', subtitle: 'What procurement and security look for' },
  { id: 18, title: 'Why the upside compounds', subtitle: 'Velocity, trust, and reuse' },
  { id: 19, title: 'Adoption path', subtitle: 'Start narrow, widen with confidence' },
  { id: 20, title: 'Recap & next step', subtitle: 'Bookmark-friendly close' },
];

export interface PluginData {
  slug: string
  name: string
  color: string
  tagline: string
  problem: string
  what: string
  capabilities: { title: string; desc: string }[]
  outcomes: string[]
  comparison: { feature: string; us: string; them: string }[]
  howToUse: { step: string; detail: string }[]
  poweredBy: string
}

export const PLUGINS: PluginData[] = [
  {
    slug: 'devguard',
    name: 'DevGuard',
    color: '#f87171',
    tagline: 'Coding agent guardrails — files, commands, secrets, git',
    problem:
      'Your coding agents — Cursor, Claude Code, Windsurf, Kiro — run with no guardrails. They can read your .env, modify production configs, run arbitrary shell commands, and push to any branch. When something breaks, you have no record of what the agent did.',
    what:
      'DevGuard is a policy enforcement plugin that sits between your coding agent and your filesystem, shell, git, and secret store. It evaluates every action against a role-based policy (devguard.yaml), assigns a risk score (0–100), and issues a verdict: ALLOW, DENY, HOLD, or NEEDS_APPROVAL.',
    capabilities: [
      { title: 'Role-based file policy', desc: 'Define which files, directories, and extensions each agent role can read or write. Production configs, .env files, and Terraform are locked by default.' },
      { title: 'Command execution gating', desc: 'Every shell command is evaluated against an allowlist before it runs. rm -rf, curl to external URLs, and database commands require explicit approval.' },
      { title: 'Secret store isolation', desc: 'Encrypted secret management with key rotation. Agents request secrets by name — they never see the raw value unless policy permits.' },
      { title: 'Git hook enforcement', desc: 'Pre-commit and pre-push hooks enforce policy at the git layer. Sensitive files cannot be committed accidentally.' },
      { title: 'Risk scoring (0–100)', desc: 'Every action receives a composite risk score based on file sensitivity, command blast radius, and agent role. High-risk actions trigger HITL approval.' },
      { title: 'Human-in-the-loop approval', desc: 'HOLD and NEEDS_APPROVAL verdicts pause the agent and surface the action for human review before execution.' },
      { title: 'Full audit trail', desc: 'Every file access, command, git operation, and secret request is logged with agent identity, timestamp, verdict, and risk score.' },
    ],
    outcomes: [
      'Your coding agent cannot touch production configs, Terraform, or .env files without explicit approval',
      'Every file write and shell command is on record — know exactly what your agent did and when',
      'Reviewers get a signed log of every agent action — not a hope and a prayer',
      'Junior agents get junior permissions — RBAC at the agent level, not the human level',
      'Secrets never appear in agent context — only the value the agent is authorised to use',
    ],
    comparison: [
      { feature: 'Enforcement layer', us: 'Blocks before execution', them: 'Alerts after the fact' },
      { feature: 'Policy scope', us: 'Files, commands, secrets, git, budget', them: 'Prompt filtering only' },
      { feature: 'Agent identity', us: 'Per-agent role + risk score', them: 'No agent-level RBAC' },
      { feature: 'Audit trail', us: 'Cryptographic receipts via WitnessCtl', them: 'Log files (mutable)' },
      { feature: 'HITL approval', us: 'Built-in, per-action', them: 'Not supported' },
      { feature: 'Secret isolation', us: 'Encrypted store, agents never see raw keys', them: 'Env vars in agent context' },
    ],
    howToUse: [
      { step: 'Open try.cnktros.com/trial', detail: 'Enter your email. That address owns a private 90-minute node. Other emails cannot see your agents.' },
      { step: 'Start 90 minutes', detail: 'You land on RUN with one Demo agent. Open the DevGuard console to stamp a repo cage. Paste a GitHub URL or org/repo. Git manages the files — this node does not clone them.' },
      { step: 'Address, config, cage', detail: 'DevGuard issues one address for the checkout. Drop .devguard/connector.json and run `devguard init && devguard cage start`. After that, Cursor, Claude Code, Codex, or any other agent in the folder follows the same rules.' },
      { step: 'Same email can start again', detail: 'Idle 90 minutes and the session ends. Start again and you get a new Demo session. Up to ten people at once.' },
      { step: 'Take it home', detail: 'A paid pilot drops the binary on your infrastructure. Point Cursor or Claude Code at CONNECTOR_BASE_URL and write devguard.yaml.' },
    ],
    poweredBy: 'DevGuard is powered by the Connector OS. Risk scoring runs at Ring 5. Receipts are sealed at Ring 8.',
  },

  {
    slug: 'tracetramp',
    name: 'TraceTramp',
    color: '#5ba8ff',
    tagline: 'Full execution graph for every agent — zero instrumentation',
    problem:
      'When an agent misbehaves, produces wrong output, or causes an incident, you have no idea what it did. Which tools it called. In what order. What data it read. What it decided. You have logs, but logs are not a trace. You cannot replay, explain, or prove what happened.',
    what:
      'TraceTramp captures the complete execution graph of every agent call — language agnostic, framework agnostic, zero instrumentation required. Every tool call, every LLM decision, every memory read, every output is captured as a content-addressed DAG node. Reconstruct the path on governed traffic. Full replay of world effects is not the product bar.',
    capabilities: [
      { title: 'Zero-instrumentation capture', desc: 'TraceTramp captures at the kernel layer — no SDK, no decorator, no wrapper. Works with any agent regardless of language or framework.' },
      { title: 'DAG-structured execution graph', desc: 'Every agent run is a directed acyclic graph of decisions, tool calls, memory reads, and outputs. CID-addressed — tamper-evident by construction.' },
      { title: 'Decision explanation', desc: 'connectorctl explain decision <id> returns the full context: why the agent made the decision, what policy applied, what data was in context.' },
      { title: 'Path reconstruction', desc: 'Reconstruct a governed run: tools, order, identity. Full deterministic replay of world effects is not the product bar — stop is not undo.' },
      { title: 'Latency and cost attribution', desc: 'Each node in the graph carries latency, token count, and cost. Find which tool call or LLM hop is responsible for slow or expensive runs.' },
      { title: 'Cross-agent trace linking', desc: 'Multi-agent pipelines produce a linked trace graph — follow the decision chain across agent boundaries.' },
    ],
    outcomes: [
      'Know exactly what every agent did — tool by tool, decision by decision',
      'Explain any agent output to a reviewer in one command',
      'Reconstruct a governed path when a run breaks — not a promise to rewind the world',
      'Find which LLM call or tool hop is costing you — per agent, per run',
      'Cross-agent traces for multi-agent pipelines — no more black boxes between agents',
    ],
    comparison: [
      { feature: 'Instrumentation required', us: 'Zero — kernel layer capture', them: 'SDK wrappers / decorators required' },
      { feature: 'Trace structure', us: 'CID-addressed DAG — tamper-evident', them: 'Flat log files' },
      { feature: 'Decision explanation', us: 'Full context: policy, data, reasoning', them: 'Input/output pairs only' },
      { feature: 'Replay', us: 'Path reconstruction on governed traffic', them: 'Not supported' },
      { feature: 'Multi-agent linking', us: 'Cross-agent trace graph', them: 'Per-agent only' },
      { feature: 'Tamper evidence', us: 'HMAC-chained, CID-addressed', them: 'None' },
    ],
    howToUse: [
      { step: 'Open try.cnktros.com/trial', detail: 'Enter your email. That address owns a private 90-minute node. Other emails cannot see your agents.' },
      { step: 'Start 90 minutes', detail: 'TraceTramp is already on the node. You land in the live dashboard — not a key dump.' },
      { step: 'See who did what', detail: 'Open the agent path: tools, order, identity. Reconstruct a run without reading interleaved logs.' },
      { step: 'Same email can start again', detail: 'Idle 90 minutes and the session ends. Start again and you get a new Demo session. Up to ten people at once.' },
      { step: 'Take it home', detail: 'A paid pilot is a node you operate. Point your agent at it — tracing starts at the kernel. No SDK required.' },
    ],
    poweredBy: 'TraceTramp is powered by the Connector OS. Traces are captured at Ring 7, sealed at Ring 8, and surfaced at Ring 9.',
  },

  {
    slug: 'conductor',
    name: 'Conductor',
    color: '#a78bfa',
    tagline: 'Multi-agent orchestration without a framework',
    problem:
      'Multi-agent pipelines are hand-wired in code. One agent failing silently cascades into corrupted state. Delegation between agents is unverified — any agent can claim any authority. There is no audit trail of which agent made which decision. Debugging requires reading through interleaved logs from five different services.',
    what:
      'Conductor is a planned declarative multi-agent orchestration institution. You would define agent roles, delegation chains, and consensus requirements in a contract. It is not in the playground today.',
    capabilities: [
      { title: 'Declarative pipeline contracts', desc: 'Define multi-agent workflows in CCL (Connector Contract Language). Agent roles, task routing, delegation authority, and consensus rules — all in one contract.' },
      { title: 'Delegation chain verification', desc: 'Every inter-agent delegation is verified against the UCAN capability chain. An agent cannot claim authority it was not explicitly granted.' },
      { title: 'Conflict resolution', desc: 'When agents disagree, Conductor applies the conflict resolution rules from the contract — escalate, vote, or defer to a named authority agent.' },
      { title: 'Failure isolation', desc: 'Agent failures are isolated — they do not cascade. Conductor routes around failed agents or escalates per contract policy.' },
      { title: 'Consensus gating', desc: 'High-stakes decisions require N-of-M agent agreement before execution. Conductor enforces the quorum and seals the consensus record.' },
      { title: 'Cross-agent audit trail', desc: 'Every inter-agent call, delegation, and decision is recorded in the audit chain with both agent identities.' },
    ],
    outcomes: [
      'Multi-agent pipelines that are declarative, auditable, and failure-safe',
      'No agent can exceed its delegated authority — UCAN-verified at every hop',
      'Debug any multi-agent incident by querying the cross-agent trace graph',
      'Consensus requirements enforced at the kernel level — not in application code',
      'Confident enough to put multi-agent workflows in production-critical paths',
    ],
    comparison: [
      { feature: 'Orchestration model', us: 'Declarative CCL contracts', them: 'Imperative code / framework DSL' },
      { feature: 'Delegation authority', us: 'UCAN-verified at runtime', them: 'Trust-on-first-call / none' },
      { feature: 'Failure isolation', us: 'Contract-defined, kernel-enforced', them: 'Try/catch in application code' },
      { feature: 'Conflict resolution', us: 'Declarative rules + consensus', them: 'Manual / not supported' },
      { feature: 'Audit trail', us: 'Cross-agent HMAC-chained receipts', them: 'Per-agent logs' },
      { feature: 'Framework dependency', us: 'None — works with any agent', them: 'Locked to framework' },
    ],
    howToUse: [
      { step: 'Write a pipeline contract', detail: 'Define agent roles, task routing, and delegation rules in a .ccl file. No code changes to your agents.' },
      { step: 'Register agents with Conductor', detail: 'POST /api/v1/conductor/register each agent with its identity and role.' },
      { step: 'Submit a task', detail: 'POST /api/v1/conductor/task — Conductor routes it to the right agent, enforces delegation, and tracks the full chain.' },
      { step: 'Monitor the pipeline', detail: 'connectorctl conductor status shows every agent, its current task, and delegation chain in real time.' },
      { step: 'Audit any run', detail: 'connectorctl trace pipeline <id> returns the full cross-agent execution graph.' },
    ],
    poweredBy: 'Conductor is powered by the Connector OS. Delegation is verified at Ring 5, consensus is enforced at Ring 5, and every inter-agent decision is sealed at Ring 8.',
  },

  {
    slug: 'agentloop',
    name: 'AgentLoop',
    color: '#34d399',
    tagline: 'Agent lifecycle management at fleet scale',
    problem:
      'Agents start, drift, hang, or go rogue — and you have no single control plane to manage the fleet. Restarting a hung agent requires SSH. Suspending a rogue agent mid-run is impossible without killing the process. There is no governed state machine for what an agent is allowed to do at each lifecycle stage.',
    what:
      'AgentLoop is a planned fleet-lifecycle SKU. Kill/freeze of a governed session exists on the node. The packaged state machine and fleet spawn API are on the map.',
    capabilities: [
      { title: 'Governed state machine', desc: 'Agents move through a defined lifecycle. Invalid transitions are blocked. You cannot skip from STARTING to TERMINATED without going through RUNNING.' },
      { title: 'Fleet-scale spawn', desc: 'Spawn hundreds of agents from a single API call with inherited policy contracts and budget limits.' },
      { title: 'Remote suspend and resume', desc: 'Suspend any running agent via API or CLI. The agent state is checkpointed and resumable — no lost work.' },
      { title: 'Drift detection', desc: 'AgentLoop monitors agent behaviour against its registered policy contract. Drift triggers an alert and optional auto-suspend.' },
      { title: 'Health checks and auto-recovery', desc: 'Configurable health check intervals with automatic restart or escalation on failure.' },
      { title: 'Budget inheritance', desc: 'Child agents inherit a share of their parent budget. Budget exhaustion suspends the agent — it does not crash it.' },
    ],
    outcomes: [
      'Manage your entire agent fleet from one API or CLI — no SSH, no process kills',
      'Suspend a rogue agent mid-run without data loss or corrupted state',
      'Every lifecycle transition is in the audit trail — who started it, who suspended it, why',
      'Fleet-scale spawning with inherited policy — consistent governance at any scale',
      'Agents that drift from their contract are caught and contained automatically',
    ],
    comparison: [
      { feature: 'Lifecycle model', us: 'Governed state machine, policy-gated', them: 'Process start/stop only' },
      { feature: 'Remote suspend', us: 'API/CLI, state checkpointed', them: 'Process kill (no state)' },
      { feature: 'Drift detection', us: 'Continuous, auto-suspend', them: 'Not supported' },
      { feature: 'Fleet spawn', us: 'Single API call, policy inherited', them: 'Manual / bespoke' },
      { feature: 'Budget inheritance', us: 'Parent → child, hard gate', them: 'Not supported' },
      { feature: 'Audit trail', us: 'Every transition sealed at Ring 8', them: 'Log files' },
    ],
    howToUse: [
      { step: 'Register an agent', detail: 'POST /api/v1/agents/register with identity, role, policy contract, and budget.' },
      { step: 'Start the agent', detail: 'POST /api/v1/agents/<id>/start — AgentLoop transitions it to RUNNING and begins monitoring.' },
      { step: 'Monitor the fleet', detail: 'connectorctl agents list shows every agent, its state, health, and budget consumption.' },
      { step: 'Suspend or resume', detail: 'connectorctl agents suspend <id> or resume <id> — state is checkpointed and restored.' },
      { step: 'Inspect lifecycle history', detail: 'connectorctl agents history <id> returns the full state machine log with timestamps and policy verdicts.' },
    ],
    poweredBy: 'AgentLoop is powered by the Connector OS. State transitions are evaluated at Ring 5, health is monitored at Ring 2, and lifecycle events are sealed at Ring 8.',
  },

  {
    slug: 'ledgerlens',
    name: 'LedgerLens',
    color: '#fbbf24',
    tagline: 'Real-time cost attribution and hard budget gates',
    problem:
      'AI infrastructure costs are invisible until the bill arrives. No breakdown by agent, team, model, or workflow. No gates that stop runaway spend before it happens. Engineering discovers a $40K overnight bill the next morning — after it is already charged.',
    what:
      'LedgerLens is a planned cost-attribution SKU. The gateway already has a cost-cap hard-stop posture. Per-team chargeback reports and a packaged LedgerLens product are on the map, not ready to try.',
    capabilities: [
      { title: 'Per-agent cost ledger', desc: 'Running token count, cost, model breakdown, and call count per agent — updated in real time, accessible via API and CLI.' },
      { title: 'Per-team attribution', desc: 'Aggregate cost per team, per project, or per workflow. Chargeback-ready reports with model breakdown.' },
      { title: 'Hard budget gates', desc: 'Set daily, weekly, or per-run budget limits per agent or team. Agents that hit the limit are suspended — execution stops before overspend.' },
      { title: 'Model cost comparison', desc: 'Side-by-side cost comparison across models for the same task. Know whether GPT-4o or Claude 3 Haiku is cheaper for your specific workload.' },
      { title: 'Alert thresholds', desc: 'Get notified at 50%, 80%, and 100% of budget via webhook or dashboard. Act before the gate hits.' },
      { title: 'Cost-per-outcome', desc: 'Combine with TraceTramp to calculate cost per agent decision, not just per token. Know the ROI of each agent task.' },
    ],
    outcomes: [
      'Never receive a surprise $40K LLM bill — hard gates stop spend before it happens',
      'Know exactly which agent, team, and model is responsible for every dollar',
      'Chargeback AI costs to the right team with model-level granularity',
      'Compare model costs for the same task and make data-driven model routing decisions',
      'Budget alerts before the gate — not after the incident',
    ],
    comparison: [
      { feature: 'Budget enforcement', us: 'Hard gate — suspends agent at limit', them: 'Soft alert — notifies after spend' },
      { feature: 'Attribution granularity', us: 'Per agent, team, model, workflow', them: 'Per API key only' },
      { feature: 'Real-time', us: 'Updated per token, per call', them: 'Batched / delayed' },
      { feature: 'Model comparison', us: 'Side-by-side for same workload', them: 'Not supported' },
      { feature: 'Cost-per-outcome', us: 'Yes — via TraceTramp integration', them: 'Tokens only' },
      { feature: 'Chargeback reports', us: 'Built-in, exportable', them: 'Manual / bespoke' },
    ],
    howToUse: [
      { step: 'Set a budget on registration', detail: 'Include budget_daily and budget_per_run in agent registration. No other configuration required.' },
      { step: 'Monitor in real time', detail: 'connectorctl ledger agent <id> shows running cost, token count, and remaining budget.' },
      { step: 'Pull team reports', detail: 'connectorctl ledger team <team_id> generates a chargeback-ready report with model breakdown.' },
      { step: 'Configure alert webhooks', detail: 'POST /api/v1/ledger/alerts to set threshold notifications at 50%, 80%, 100%.' },
      { step: 'Gates are automatic', detail: 'No action needed — when an agent hits its limit it is suspended. Resume after budget reset or manual override.' },
    ],
    poweredBy: 'LedgerLens is powered by the Connector OS. Budget checks run at Ring 5 before every LLM call. Cost events are sealed at Ring 8.',
  },

  {
    slug: 'witnessctl',
    name: 'WitnessCtl',
    color: '#3ecf8e',
    tagline: 'HMAC-chained receipts for every admitted action',
    problem:
      'Reviewers ask for AI decision logs. You hand them a CSV export from your logging service — mutable, unsigned, and hard to verify. Log files describe what happened. They do not prove it.',
    what:
      'WitnessCtl produces HMAC-chained audit receipts for every admitted action — content-addressed and inspectable with the issuer key. The receipt includes what happened, when, by which agent, under which policy, and with what evidence. It is sealed at Ring 8. Issuer HMAC is not court-grade custody and not N-of-M quorum.',
    capabilities: [
      { title: 'HMAC-chained journal', desc: 'Every event is linked to the previous via HMAC. Any gap or modification breaks the chain. Detectable with the issuer key — not a public-key court record.' },
      { title: 'Content-addressed receipts', desc: 'Receipts are CID-addressed. The CID is derived from the content — tampering changes the CID, which breaks the chain.' },
      { title: 'Per-action receipts', desc: 'Every agent action — LLM call, tool invocation, memory read, policy decision — produces a signed receipt.' },
      { title: 'Proof bundle generation', desc: 'connectorctl prove agent <id> assembles a proof bundle covering the full agent session — JSON, Markdown, or PDF.' },
      { title: 'Reviewer-oriented bundles', desc: 'Receipts can be assembled into a bundle a reviewer inspects. Framework mapping (SOC 2, HIPAA, and similar) is a design-partner path — not a certification we sell today.' },
      { title: 'Issuer verification', desc: 'A reviewer with the issuer key can inspect the chain. This is not independent third-party cryptography and not court-grade quorum.' },
    ],
    outcomes: [
      'Hand a reviewer a hash-chained proof bundle, not a spreadsheet',
      'Show who accessed what, when, under which identity',
      'Keep a chain a third party can inspect without trusting a dashboard screenshot',
      'Evidence for a conversation with legal — not a sold certification',
      'Tamper-evident by construction — any alteration breaks the chain',
    ],
    comparison: [
      { feature: 'Tamper evidence', us: 'HMAC chain + CID addressing', them: 'None — log files are mutable' },
      { feature: 'Third-party verifiable', us: 'Inspectable with issuer key — not court-grade', them: 'No' },
      { feature: 'Proof bundle', us: 'One command — JSON/MD/PDF', them: 'Manual export + formatting' },
      { feature: 'Compliance mapping', us: 'Design-partner path — not a sold certification', them: 'None built-in' },
      { feature: 'Per-action receipts', us: 'Every action — LLM, tool, memory, policy', them: 'API call level only' },
      { feature: 'Chain gap detection', us: 'Automatic — any gap is flagged', them: 'Not supported' },
    ],
    howToUse: [
      { step: 'Open try.cnktros.com/trial', detail: 'Enter your email. That address owns a private 90-minute node. Other emails cannot see your agents.' },
      { step: 'Start 90 minutes', detail: 'WitnessCtl is a sidecar on the node. Prove on Demo writes playground receipts you can inspect. Demo Admit does not ingest WitnessCtl sessions on the hosted trial.' },
      { step: 'Inspect a receipt', detail: 'Open the journal in the dashboard. A reviewer can inspect the chain. That is evidence, not a SOC 2 certificate.' },
      { step: 'Same email can start again', detail: 'Idle 90 minutes and the session ends. Start again and you get a new Demo session. Up to ten people at once.' },
      { step: 'Take it home', detail: 'A paid pilot is a node you operate. connectorctl prove agent <id> assembles a session bundle. Framework mapping is a design-partner path.' },
    ],
    poweredBy: 'WitnessCtl is powered by the Connector OS. Receipts are produced at Ring 8. Proof bundles are assembled and rendered at Ring 9.',
  },

  {
    slug: 'agentpassport',
    name: 'AgentPassport',
    color: '#fb923c',
    tagline: 'W3C DID identity for every agent — verifiable everywhere',
    problem:
      'Agents have no identity. Any process can claim to be any agent. An agent impersonating a privileged agent is undetectable. When you need to revoke a compromised agent, you restart a process — there is no credential to revoke. Multi-system agent deployments have no shared identity plane.',
    what:
      'AgentPassport is the planned identity SKU: W3C DID packaging, UCAN delegation, portable revoke. Identity at boot exists on the node today. The DID product is not ready to try.',
    capabilities: [
      { title: 'W3C DID issuance', desc: 'Every agent gets a DID at registration — did:connector:<node-id>:<agent-id>. Globally unique, resolvable, and standards-compliant.' },
      { title: 'Ed25519 signing', desc: 'Every agent action is signed with the agent\'s Ed25519 private key. Verification requires only the public key — no system access needed.' },
      { title: 'UCAN capability delegation', desc: 'Agents can delegate specific capabilities to other agents using UCAN tokens. Delegation chains are verifiable and time-bounded.' },
      { title: 'Instant revocation', desc: 'Revoke an agent\'s DID and all downstream delegation chains are immediately invalidated — across all systems that trust the ConnectorOS root.' },
      { title: 'Cross-system portability', desc: 'AgentPassport DIDs work across any system that supports W3C DID resolution. Your agent identity is not locked to one vendor.' },
      { title: 'Identity audit trail', desc: 'Every identity event — issuance, delegation, revocation, verification failure — is in the audit chain.' },
    ],
    outcomes: [
      'Every agent has a cryptographic identity — impersonation is verifiably detectable',
      'Revoke a compromised agent in one command — all delegation chains collapse immediately',
      'Portable identity across systems — no vendor lock-in for agent identity',
      'UCAN delegation chains are auditable — know who delegated what to whom and when',
      'Standards-compliant — W3C DID, Ed25519, UCAN — verifiable by any standards-aware system',
    ],
    comparison: [
      { feature: 'Identity standard', us: 'W3C DID — globally portable', them: 'Internal ID / API key' },
      { feature: 'Signing', us: 'Ed25519, per-action', them: 'None' },
      { feature: 'Revocation', us: 'Instant, cascades through delegation chains', them: 'Rotate API key (manual)' },
      { feature: 'Delegation', us: 'UCAN — verifiable, time-bounded', them: 'Hardcoded permissions' },
      { feature: 'Cross-system portability', us: 'Yes — W3C DID resolution', them: 'Vendor-specific' },
      { feature: 'Identity audit trail', us: 'Every event sealed at Ring 8', them: 'None' },
    ],
    howToUse: [
      { step: 'DID issued on registration', detail: 'Every agent registered with ConnectorOS receives a DID automatically. No additional configuration.' },
      { step: 'Verify an agent identity', detail: 'connectorctl passport verify <did> resolves the DID and confirms the agent\'s current status.' },
      { step: 'Delegate a capability', detail: 'connectorctl passport delegate <did> --cap <capability> --to <target-did> --ttl 1h' },
      { step: 'Revoke an agent', detail: 'connectorctl passport revoke <did> — immediate, cascading revocation across all delegation chains.' },
      { step: 'Cross-system verification', detail: 'Share the DID with any W3C DID-compatible system. No ConnectorOS dependency for verification.' },
    ],
    poweredBy: 'AgentPassport is powered by the Connector OS. Identity is established at Ring 1. UCAN verification runs at Ring 5. All identity events are sealed at Ring 8.',
  },

  {
    slug: 'relay',
    name: 'Relay',
    color: '#38bdf8',
    tagline: 'Any HTTP endpoint. Full ConnectorOS governance. One env var.',
    problem:
      'Adding governance to an existing agent means rewriting it to use a framework or SDK. Teams skip governance because the integration cost is too high. Services written in Go, Ruby, Java, or shell scripts cannot use Python SDKs. The governance gap is largest where the integration effort is highest.',
    what:
      'Relay is a planned zero-framework governance gateway. Register any HTTP endpoint. The ready path today is pointing OpenAI- or Anthropic-compatible /v1 at this node.',
    capabilities: [
      { title: 'Zero-code governance', desc: 'Register any HTTP endpoint — REST, gRPC-transcoded, WebSocket. No SDK. No framework. No code changes to the function.' },
      { title: 'Sync and async invocation', desc: 'Call functions synchronously or submit async jobs with a job ID. Async results are retrieved via polling or webhook callback.' },
      { title: 'Full 9-ring governance', desc: 'Every Relay invocation passes through all nine ConnectorOS enforcement rings — identity, firewall, memory, policy, budget, audit.' },
      { title: 'Function registry', desc: 'Register, list, update, deregister, suspend, and resume functions via the Relay API. Health status and stats per function.' },
      { title: 'Memory and tool injection', desc: 'Relay can inject relevant memory and tool context into the function invocation — without the function knowing.' },
      { title: 'PII scrubbing on response', desc: 'Relay scrubs PII from function responses before they are returned to the caller — policy-configurable.' },
    ],
    outcomes: [
      'Govern any existing service — Go, Java, Ruby, shell — without rewriting it',
      'Legacy endpoints get the same governance as new AI agents — same audit trail, same budget gate',
      'One env var is the entire integration: CONNECTOR_RELAY_URL=http://connector:9091',
      'Async agent workflows without a queue service — Relay handles the job management',
      'PII scrubbed at the proxy when that policy is on — not a claim that no bytes ever leave the host',
    ],
    comparison: [
      { feature: 'Integration requirement', us: 'One env var — no code changes', them: 'SDK integration, framework adoption' },
      { feature: 'Language support', us: 'Any language — HTTP is the interface', them: 'SDK language limited' },
      { feature: 'Governance coverage', us: 'Full 9-ring stack', them: 'Partial — depends on integration depth' },
      { feature: 'Async support', us: 'Built-in job queue, webhook callbacks', them: 'Requires separate queue service' },
      { feature: 'PII scrubbing', us: 'Response-level, policy-configurable', them: 'Not supported' },
      { feature: 'Legacy service support', us: 'Yes — any HTTP endpoint', them: 'Greenfield only' },
    ],
    howToUse: [
      { step: 'Register your function', detail: 'POST /api/v1/relay/functions with your function name, URI, and policy contract.' },
      { step: 'Set the env var', detail: 'CONNECTOR_RELAY_URL=http://connector:9091. Your callers now route through Relay.' },
      { step: 'Invoke synchronously', detail: 'POST /api/v1/relay/functions/<name>/invoke — Relay governs the call and returns the result.' },
      { step: 'Submit async jobs', detail: 'POST /api/v1/relay/functions/<name>/invoke/async — get a job ID, poll or webhook for result.' },
      { step: 'Check health and stats', detail: 'GET /api/v1/relay/functions/<name>/stats — invocation count, latency, error rate, budget consumed.' },
    ],
    poweredBy: 'Relay is powered by the Connector OS. Every invocation passes through all 9 enforcement rings. Audit receipts are sealed at Ring 8.',
  },

  {
    slug: 'engram',
    name: 'Engram',
    color: '#c084fc',
    tagline: 'Enterprise memory with entropy scoring and dehallucination',
    problem:
      'Agents hallucinate because their memory is ungoverned. They write anything to memory — including hallucinated facts — and retrieve it later as ground truth. Memory grows without pruning. Irrelevant context floods the LLM window. Sensitive data mixes with public data. And there is no proof of what data the agent actually used.',
    what:
      'Engram is a planned governed memory SKU. The node already has a memory kernel. Entropy scoring, dehallucination, and HIPAA-shaped proof bundles are the intended product — not a download today.',
    capabilities: [
      { title: 'Entropy scoring', desc: 'Every memory write receives an entropy score measuring information quality and novelty. Low-entropy writes (repetition, noise) are deprioritised or rejected.' },
      { title: 'Namespace isolation', desc: 'Memory is partitioned by namespace — private (/p/), shared (/s/), and public (/pub/). Private memory never reaches the LLM context.' },
      { title: 'Dehallucination enforcement', desc: 'Every memory read that feeds an LLM response is verified against its source. If the source cannot be confirmed, the memory is withheld.' },
      { title: 'VAC memory tiers', desc: 'Hot (in-context), warm (fast retrieval), cold (archived), and vault (encrypted, access-controlled) tiers. Data moves between tiers by policy.' },
      { title: 'Selective context construction', desc: 'Engram is planned to build the LLM context window from the minimum necessary memory. HIPAA/GDPR mapping is a design-partner path — not a sold certification.' },
      { title: 'Memory provenance receipts', desc: 'Every memory read that contributes to an agent response is receipted — proving which data the agent used and that it was authorised.' },
    ],
    outcomes: [
      'Agents remember correctly — or they don\'t respond rather than hallucinate',
      'Private namespaces can be withheld from the model — vendor LLM HTTP may still leave the host when a model is granted',
      'Intended: data-minimization receipts for a reviewer. Not sold: HIPAA or GDPR certification',
      'Memory quality improves over time — entropy scoring prunes low-quality writes',
      'Know exactly which memory the agent used in any response — provenance receipts per retrieval',
    ],
    comparison: [
      { feature: 'Hallucination prevention', us: 'Dehallucination enforcement — withholds unverifiable memory', them: 'None — retrieval only' },
      { feature: 'Namespace isolation', us: 'Kernel-enforced — private never reaches LLM', them: 'Application-layer filtering' },
      { feature: 'Memory quality', us: 'Entropy scoring per write', them: 'No quality signal' },
      { feature: 'Data minimization proof', us: 'Selective context construction + receipt', them: 'Not supported' },
      { feature: 'Memory provenance', us: 'Per-read receipt at Ring 8', them: 'No provenance' },
      { feature: 'Tiered storage', us: 'Hot/warm/cold/vault with policy routing', them: 'Single store' },
    ],
    howToUse: [
      { step: 'Write to memory', detail: 'POST /api/v1/memory/write with namespace, content, and sensitivity tag. Engram scores entropy and stores it in the appropriate tier.' },
      { step: 'Read with relevance ranking', detail: 'POST /api/v1/memory/retrieve with a query. Engram returns namespace-fenced, relevance-ranked, dehallucination-verified results.' },
      { step: 'Inspect memory quality', detail: 'connectorctl memory stats shows entropy distribution, tier breakdown, and namespace usage.' },
      { step: 'Verify a context construction', detail: 'connectorctl memory prove <agent-id> <run-id> returns the provenance receipt for every memory read in a given run.' },
      { step: 'Prune low-quality memory', detail: 'connectorctl memory prune --below-entropy 0.3 removes low-quality writes below threshold.' },
    ],
    poweredBy: 'Engram is powered by the Connector OS. Memory operations are governed at Ring 4. Dehallucination runs at Ring 6. Provenance receipts are sealed at Ring 8.',
  },
]

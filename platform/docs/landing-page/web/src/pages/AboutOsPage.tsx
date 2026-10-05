import { Nav } from '../components/Nav'
import { useMeta } from '../hooks/useMeta'
import { Footer } from '../components/Footer'

const RINGS = [
  { n: '1', name: 'Identity & Boot',       desc: 'Node keypair, 12-stage boot, auth tokens. Boot aborts if anything fails.' },
  { n: '2', name: 'Network & Gateway',     desc: 'HTTP/2, TLS termination, rate limiting, session routing.' },
  { n: '3', name: 'Firewall & Guard',      desc: '5-layer content inspection — injection, PII, hallucination, schema, intent.' },
  { n: '4', name: 'Memory Kernel',         desc: 'CID-addressed storage, namespace isolation. Policy decides what reaches the model. Vendor LLM HTTP may still leave the host when a model is granted.' },
  { n: '5', name: 'Policy & Governance',   desc: 'CCL contract execution, HITL gates, budget enforcement. Violations blocked — not flagged.' },
  { n: '6', name: 'Reasoning & LLM',       desc: 'Selective context construction, grounding, LLM routing. Only what policy allows reaches the model.' },
  { n: '7', name: 'Tool Execution',        desc: 'World grants, dest-pinned Landlock child (pore table, default DROP), schema validation, allowlist, receipt per effect.' },
  { n: '8', name: 'Audit Chain',           desc: 'HMAC-chained monotonic journal. Every admitted event recorded. Any gap is detectable. Issuer HMAC is not court-grade custody.' },
  { n: '9', name: 'Surface Output',        desc: 'Role-based rendering. Redacted output for unauthorized viewers. Proof bundles on demand.' },
]

const WHAT_IT_IS_NOT = [
  { label: 'Not an LLM',             body: 'Connector contains no language model. It governs access to models you already use — OpenAI, Anthropic, Ollama, or your own.' },
  { label: 'Not an agent framework', body: 'Keep your agents, SDKs, graphs, or IDEs. Connector is the OS underneath. You write the agent. We admit or refuse the effect.' },
  { label: 'Not a coding-agent product', body: 'DevGuard is the institution for workstation coding tools. The kernel is generic: Talk, MCP, HAL, HTTP APIs, and a granted browser world.' },
  { label: 'Not a monitoring tool',  body: 'Monitoring watches after the fact. Connector admits or refuses at runtime, then records a receipt.' },
  { label: 'Not a certification',    body: 'Receipts are evidence a reviewer can inspect. We are not SOC 2, HIPAA, or FedRAMP certified, and we do not sell those as a checkbox.' },
  { label: 'Not Firecracker-by-default', body: 'World dials today use dest-pinned Landlock children. MicroCell/Firecracker is a separate isolation plane, not the claim of this page.' },
]

const DATA_PATHS = [
  {
    title: 'Chat invocation',
    endpoint: 'POST /v1/chat/completions',
    steps: [
      'Ring 1 — Verify caller identity + agent ID',
      'Ring 2 — TLS termination, rate check',
      'Ring 3 — Firewall inspect prompt (5 layers)',
      'Ring 4 — Retrieve relevant memory (namespace-fenced)',
      'Ring 5 — Policy check (CCL contract evaluation)',
      'Ring 6 — Selective context → LLM call (vendor HTTP in the LLM cage when enforced)',
      'Ring 7 — Effects only through granted world addresses / tool plane',
      'Ring 8 — Journal entry + receipt',
      'Ring 9 — Surface rendering + audit_cid in response',
    ],
  },
  {
    title: 'Tool dispatch',
    endpoint: 'POST /api/v1/tools/mcp/invoke',
    steps: [
      'Ring 1 — Auth',
      'Ring 3 — Schema validation on tool args',
      'Ring 4 — Namespace policy for tool scope',
      'Ring 5 — Allowlist check + budget check',
      'Ring 7 — Dest-pinned Landlock child when enforced + receipt generation',
      'Ring 8 — Receipt chained + journal entry',
    ],
  },
  {
    title: 'Proof generation',
    endpoint: 'POST /api/v1/proof/generate',
    steps: [
      'Ring 1 — Auth',
      'Ring 5 — Policy check (who can generate proofs)',
      'Ring 8 — Traverse all 9 chains → assemble bundle',
      'Ring 9 — Render proof (JSON / Markdown / PDF)',
    ],
  },
]

export function AboutOsPage() {
  useMeta({
    title: 'ConnectorOS Architecture — 9-ring OS for intelligence | Connector',
    description: 'How ConnectorOS works: identity, firewall, policy, memory, dest-pinned world dials, HMAC-chained receipts. Institutions sit on the OS. They are not the OS.',
    canonical: 'https://cnktros.com/about-os',
  })
  return (
    <>
      <Nav />
      <main>

        {/* ── Page hero ─────────────────────────────────────────────────── */}
        <section className="section section--hero" style={{ paddingBottom: '3rem' }}>
          <div className="section__inner" style={{ maxWidth: '760px' }}>
            <p className="hero-category-label">Connector — operating substrate for intelligence</p>
            <h1 className="hero-title" style={{ fontSize: 'clamp(2rem, 5vw, 3rem)', marginBottom: '1rem' }}>
              Isolate. Govern. Stop. Prove.
            </h1>
            <p className="hero-sub">
              A self-hosted OS for agents, models, tools, and workflows. Identity, admission, isolation, memory, and audit — one node. Institutions sit on that OS. They are not the OS. Three you can try. Seven more are the plan.
            </p>
            <div style={{ display: 'flex', gap: '1rem', marginTop: '2rem', flexWrap: 'wrap' }}>
              <a href="https://try.cnktros.com/trial" className="btn btn--primary">Try 90 minutes</a>
              <a href="/#interest" className="btn btn--ghost">Run one workflow with us</a>
            </div>
          </div>
        </section>

        {/* ── The infrastructure problem ────────────────────────────────── */}
        <section className="section section--bordered">
          <div className="section__inner" style={{ maxWidth: '760px' }}>
            <p className="section-label">The problem</p>
            <h2 className="section__title">LLMs are powerful. They have no enforcement layer.</h2>
            <p className="section__lead">
              When an LLM calls a tool, reads from a database, or produces an output that gets acted upon — by default, nothing stops it, records it, or proves it happened correctly.
            </p>
            <div className="about-problem-grid">
              {[
                ['No audit trail',              'There is no record of why the decision was made.'],
                ['No enforcement boundary',     'Nothing stops the LLM from accessing data it should not see.'],
                ['No grounding proof',          'There is no proof the output was based on real, permitted data.'],
                ['No evidence',                 'A reviewer asks what the agent decided. You have mutable logs, not a chain.'],
                ['No cost control',             'Agents run without limits. A single loop burns thousands overnight.'],
                ['No identity',                 'Any agent has the same access as any other. No roles, no scoping.'],
              ].map(([title, body]) => (
                <div key={title} className="about-problem-card">
                  <p className="about-problem-card__title">{title}</p>
                  <p className="about-problem-card__body">{body}</p>
                </div>
              ))}
            </div>
            <p className="hero-vision" style={{ marginTop: '2rem' }}>
              This is not a model problem. It is an infrastructure problem. ConnectorOS is the infrastructure that solves it structurally.
            </p>
          </div>
        </section>

        {/* ── Mental model ─────────────────────────────────────────────── */}
        <section className="section">
          <div className="section__inner" style={{ maxWidth: '760px' }}>
            <p className="section-label">Mental model</p>
            <h2 className="section__title">Connector is an OS for intelligence.</h2>
            <p className="section__lead">
              Just as an OS kernel mediates between application code and hardware — enforcing isolation, managing resources, auditing system calls — Connector mediates between your agents and the worlds they can reach.
            </p>
            <div className="about-comparison">
              <div className="about-comparison__col">
                <p className="about-comparison__label">Linux kernel</p>
                <ul className="about-list">
                  <li>Application calls syscall</li>
                  <li>Kernel checks privilege</li>
                  <li>Kernel allocates resources</li>
                  <li>Kernel logs the call</li>
                  <li>Proof: syscall-level audit</li>
                </ul>
              </div>
              <div className="about-comparison__divider" aria-hidden="true">vs</div>
              <div className="about-comparison__col">
                <p className="about-comparison__label">ConnectorOS kernel</p>
                <ul className="about-list">
                  <li>Agent calls LLM / tool</li>
                  <li>Connector verifies identity + policy</li>
                  <li>Connector enforces budget + namespace</li>
                  <li>Connector records every admitted decision</li>
                  <li>Proof: HMAC-chained receipt a reviewer can inspect</li>
                </ul>
              </div>
            </div>
            <p className="about-callout-text">
              A Linux kernel audit log proves what happened at the syscall level.<br />
              Connector's journal proves what happened at the <strong>decision level</strong> — including why, by whom, and with what evidence. Issuer HMAC is inspectable evidence, not court-grade custody.
            </p>
          </div>
        </section>

        {/* ── 3-layer product model ─────────────────────────────────────── */}
        <section className="section section--bordered">
          <div className="section__inner" style={{ maxWidth: '760px' }}>
            <p className="section-label">Product model</p>
            <h2 className="section__title">Three layers. One coherent OS.</h2>
            <figure className="diagram-figure">
              <img
                src="/img/os-stack.png"
                alt="Connector stack: substrate, connector-platform kernel, three institutions on the OS, operator control plane"
                width={1376}
                height={768}
                loading="lazy"
              />
              <figcaption className="diagram-caption">
                Institutions sit on the OS. They are not the OS.
              </figcaption>
            </figure>
            <div className="about-layers">
              <div className="about-layer">
                <span className="about-layer__num">1</span>
                <div>
                  <p className="about-layer__name">The node</p>
                  <p className="about-layer__desc">
                    The <code>connector-platform</code> binary. Self-hosted on your infrastructure. Contains all nine enforcement rings, the memory kernel, the policy engine, the audit journal, and the world cage. Default listen is <code>:9091</code>.
                  </p>
                </div>
              </div>
              <div className="about-layer">
                <span className="about-layer__num">2</span>
                <div>
                  <p className="about-layer__name">Operator surface</p>
                  <p className="about-layer__desc">
                    CLI (<code>connectorctl</code>), HTTP API (<code>/api/v1/</code> and <code>/v1</code>), Python SDK, and the CCL contract language. Same intent in YAML, Python, or CLI — same admitted path, same journal.
                  </p>
                </div>
              </div>
              <div className="about-layer">
                <span className="about-layer__num">3</span>
                <div>
                  <p className="about-layer__name">Institutions and workloads</p>
                  <p className="about-layer__desc">
                    DevGuard, TraceTramp, and WitnessCtl are institutions <em>on</em> the OS. Keep your agents, graphs, or IDEs. Every agent is a governed context: identity, namespace, policy, memory, cost posture. You write the agent. The node admits or refuses the effect.
                  </p>
                </div>
              </div>
            </div>
            <figure className="diagram-figure">
              <img
                src="/img/ui-agent-runtime.png"
                alt="Concept operator surface for agent runtime. Not a screenshot of the shipping dashboard."
                width={1376}
                height={768}
                loading="lazy"
              />
              <figcaption className="diagram-caption">
                Concept operator surface — not the shipping UI. Firecracker labels in the mock are a separate isolation plane.
              </figcaption>
            </figure>
          </div>
        </section>

        {/* ── World cage ─────────────────────────────────────────────── */}
        <section className="section">
          <div className="section__inner" style={{ maxWidth: '760px' }}>
            <p className="section-label">World cage</p>
            <h2 className="section__title">Granted worlds. Dest-pinned dials. Default DROP.</h2>
            <p className="section__lead">
              Agents that act — tools, HTTP, machines, the web — routinely talk past the gate. Connector’s answer is not a prompt that says “please don’t.” It is a world cage that is the same for every agent.
            </p>
            <figure className="diagram-figure">
              <img
                src="/img/world-cage.png"
                alt="World cage: connector-platform parent admits, Landlock child dials one dest, pore table default DROP"
                width={1376}
                height={768}
                loading="lazy"
              />
              <figcaption className="diagram-caption">
                Grant (agent × address) → pore table default DROP → dest-pinned <code>connector-platform --pore-worker</code>. Empty dest is DROP. Not Firecracker-by-default.
              </figcaption>
            </figure>
            <div className="about-problem-grid">
              {[
                ['Pore table', 'Every world address is a lock point. ACCEPT only after an owner grant. Ungranted destinations fail closed.'],
                ['Landlock child', 'The parent does not dial agent world sockets when the child is on. The child speaks only to CONNECTOR_PORE_DEST.'],
                ['Vendor cut', 'Direct vendor HTTPS from this host can DROP once a session is connected. Needs CAP_NET_ADMIN. Playground often cannot apply nft.'],
                ['Browser world', 'A granted origin, one GET, recorded fundamentals. Not Chromium computer-use.'],
              ].map(([title, body]) => (
                <div key={title} className="about-problem-card">
                  <p className="about-problem-card__title">{title}</p>
                  <p className="about-problem-card__body">{body}</p>
                </div>
              ))}
            </div>
            <figure className="diagram-figure" style={{ marginTop: '2rem' }}>
              <img
                src="/img/vendor-cut.png"
                alt="Split path: client to vendor DROP versus client to connector-platform :9091 then marked Landlock child ACCEPT"
                width={1376}
                height={768}
                loading="lazy"
              />
              <figcaption className="diagram-caption">
                Pointing a client at <code>/v1</code> is voluntary until the host cut applies. Memory and journals stay on the node; vendor LLM HTTP may leave when a model is granted.
              </figcaption>
            </figure>
          </div>
        </section>

        {/* ── 9-ring architecture ───────────────────────────────────────── */}
        <section className="section section--bordered">
          <div className="section__inner">
            <p className="section-label">Architecture</p>
            <h2 className="section__title">Nine enforcement rings. Every request passes through every one.</h2>
            <p className="section__lead" style={{ maxWidth: '640px' }}>
              No ring can be skipped. All rings fail closed — a failure at any ring denies the request. There is no path to LLM or tool execution that bypasses a ring.
            </p>
            <figure className="diagram-figure">
              <img
                src="/img/nine-rings.png"
                alt="Nine enforcement rings. Ring 7 is tool and world: grants, dest-pinned Landlock child, default DROP."
                width={1376}
                height={768}
                loading="lazy"
              />
              <figcaption className="diagram-caption">
                Ring 7 is the world cage. MicroCell / Firecracker is a separate plane.
              </figcaption>
            </figure>

            <div className="rings-grid">
              {RINGS.map(r => (
                <div key={r.n} className="ring-card">
                  <span className="ring-card__num">R{r.n}</span>
                  <div>
                    <p className="ring-card__name">{r.name}</p>
                    <p className="ring-card__desc">{r.desc}</p>
                  </div>
                </div>
              ))}
            </div>

            <div className="about-terminal-block">
              <p className="about-terminal-label">Every request, same path:</p>
              <pre className="terminal__body" style={{ margin: 0, borderRadius: '8px', padding: '1.25rem' }}>
                <code>{`Your Application
       │
       ▼
┌─────────────────────────────────────────────┐
│              CONNECTOR NODE                  │
│  Ring 1: Identity        Ring 6: Reasoning   │
│  Ring 2: Network         Ring 7: Tool Exec   │
│  Ring 3: Firewall        Ring 8: Audit Chain │
│  Ring 4: Memory          Ring 9: Output      │
│  Ring 5: Governance                          │
└─────────────────────────────────────────────┘
       │
       ▼
   LLM / Tools / APIs`}</code>
              </pre>
            </div>
          </div>
        </section>

        {/* ── Data paths ───────────────────────────────────────────────── */}
        <section className="section section--bordered">
          <div className="section__inner">
            <p className="section-label">How it flows</p>
            <h2 className="section__title">Three primary data paths through the kernel.</h2>
            <div className="data-paths-grid">
              {DATA_PATHS.map(dp => (
                <div key={dp.title} className="data-path-card">
                  <p className="data-path-card__title">{dp.title}</p>
                  <code className="data-path-card__endpoint">{dp.endpoint}</code>
                  <ol className="data-path-card__steps">
                    {dp.steps.map(s => <li key={s}>{s}</li>)}
                  </ol>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* ── What it is not ───────────────────────────────────────────── */}
        <section className="section">
          <div className="section__inner" style={{ maxWidth: '760px' }}>
            <p className="section-label">Clarity</p>
            <h2 className="section__title">What ConnectorOS is not.</h2>
            <div className="about-not-grid">
              {WHAT_IT_IS_NOT.map(item => (
                <div key={item.label} className="about-not-card">
                  <p className="about-not-card__label">{item.label}</p>
                  <p className="about-not-card__body">{item.body}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* ── What we prove ─────────────────────────────────────────────── */}
        <section className="section section--bordered">
          <div className="section__inner" style={{ maxWidth: '760px' }}>
            <p className="section-label">Evidence</p>
            <h2 className="section__title">Receipts you can inspect. Not a certificate we sell.</h2>
            <p className="section__lead">
              WitnessCtl is one of three ready institutions. It produces an HMAC-chained journal of admitted actions. A reviewer can inspect the chain. Issuer HMAC is not court-grade custody. Framework mapping for SOC 2, HIPAA, GDPR, or the EU AI Act is a design-partner path — not a live SKU and not a certification.
            </p>
            <figure className="diagram-figure">
              <img
                src="/img/hmac-chain.png"
                alt="HMAC-chained receipts: linked journal entries, tamper detectable, issuer HMAC not court-grade quorum"
                width={1376}
                height={768}
                loading="lazy"
              />
              <figcaption className="diagram-caption">
                Inspectable evidence. Not a certificate we sell. Not N-of-M quorum.
              </figcaption>
            </figure>
            <div className="about-terminal-block" style={{ marginTop: '2rem' }}>
              <p className="about-terminal-label">What you can run today:</p>
              <pre className="terminal__body" style={{ margin: 0, borderRadius: '8px', padding: '1.25rem' }}>
                <code>{`connectorctl trace agent 009
connectorctl explain decision dec_xxx
connectorctl prove agent 009
# → hash-chained receipts
# → JSON / Markdown / PDF
# → evidence, not a SOC 2 certificate`}</code>
              </pre>
            </div>
          </div>
        </section>

        {/* ── Key properties ───────────────────────────────────────────── */}
        <section className="section">
          <div className="section__inner" style={{ maxWidth: '760px' }}>
            <p className="section-label">Key properties</p>
            <h2 className="section__title">How the kernel behaves by design.</h2>
            <div className="about-props-grid">
              {[
                ['Fail closed',          'Every ring has a defined failure mode that denies the request. There is no path to LLM or tool execution that bypasses a ring.'],
                ['Independent operation','Each ring can be evaluated independently. A firewall can be tested without a running LLM. A proof can be generated without active agents.'],
                ['Monotonic journal',    'Ring 8 records every event from every other ring. The journal sequence is monotonically increasing. Any gap is detectable.'],
                ['CID addressing',       'Every piece of data — memory packets, contracts, proof bundles — has a content-addressed identifier. Tampering changes the CID.'],
                ['No code changes',      'Point OPENAI_BASE_URL at your Connector node on :9091. Your agent code changes nothing. The governance layer appears on the path in.'],
                ['Self-hosted',          'Runs on your infrastructure. Memory and journals stay on the node. Vendor LLM HTTP may leave when a model is granted.'],
              ].map(([title, body]) => (
                <div key={title} className="about-prop-card">
                  <p className="about-prop-card__title">{title}</p>
                  <p className="about-prop-card__body">{body}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* ── Bottom CTA ───────────────────────────────────────────────── */}
        <section className="section section--bordered">
          <div className="section__inner" style={{ maxWidth: '640px', textAlign: 'center' }}>
            <h2 className="section__title">Try the three ready institutions.</h2>
            <p className="section__lead">
              DevGuard, TraceTramp, WitnessCtl sit on the OS. Your email opens a private 90-minute node.
            </p>
            <div className="about-terminal-block" style={{ textAlign: 'left', marginBottom: '2rem' }}>
              <pre className="terminal__body" style={{ margin: 0, borderRadius: '8px', padding: '1.25rem' }}>
                <code>{`# Point your agent at the Connector node (default :9091)
OPENAI_BASE_URL=http://connector:9091/v1

# Your agent code changes nothing
# BASE_URL is voluntary until the host vendor cut applies`}</code>
              </pre>
            </div>
            <div style={{ display: 'flex', gap: '1rem', justifyContent: 'center', flexWrap: 'wrap' }}>
              <a href="https://try.cnktros.com/trial" className="btn btn--primary">Try 90 minutes</a>
              <a href="/#interest" className="btn btn--ghost">Run one workflow with us</a>
            </div>
          </div>
        </section>

        <Footer />

      </main>
    </>
  )
}

import { useState } from 'react'
import { Nav } from '../components/Nav'
import { HeroSection } from '../components/HeroSection'
import { FaqSection } from '../components/FaqSection'
import { VisionFormSection } from '../components/VisionFormSection'
import { Footer } from '../components/Footer'
import { playgroundUrl } from '../config'
import { READY_WORKFLOWS, PLANNED_WORKFLOWS } from '../data/workflows'

const VERBS = [
  { name: 'Isolate', line: 'Granted worlds. Default DROP.' },
  { name: 'Govern', line: 'Policy before the call.' },
  { name: 'Stop', line: 'Kill the loop. Not undo.' },
  { name: 'Prove', line: 'HMAC chain. Inspect it.' },
]

const STAGES = [
  {
    id: 'os',
    label: 'The OS',
    title: 'Institutions sit on it. They are not it.',
    body: 'Substrate. connector-platform. Three institutions ready. Operator on top.',
    src: '/img/os-stack.png',
    alt: 'Connector stack: substrate, connector-platform kernel, three institutions on the OS, operator control plane',
    caption: 'DevGuard, TraceTramp, WitnessCtl are on the OS — not a coding-agent product.',
  },
  {
    id: 'cage',
    label: 'World cage',
    title: 'Ungranted destinations fail closed.',
    body: 'Pore table default DROP. Dest-pinned Landlock child. Empty dest is DROP.',
    src: '/img/world-cage.png',
    alt: 'World cage: connector-platform parent admits, Landlock child dials one dest, pore table default DROP',
    caption: 'Same cage for Talk, MCP, HAL, HTTP, and a one-GET browser world.',
  },
  {
    id: 'prove',
    label: 'Receipts',
    title: 'A reviewer can inspect the chain.',
    body: 'HMAC-chained journal of admitted actions. Evidence — not a certificate we sell.',
    src: '/img/hmac-chain.png',
    alt: 'HMAC-chained receipts: linked journal entries, tamper detectable, issuer HMAC not court-grade quorum',
    caption: 'Issuer HMAC. Not court-grade quorum. Not SOC 2 in a box.',
  },
] as const

export function HomePage() {
  const [stage, setStage] = useState<(typeof STAGES)[number]['id']>('os')
  const current = STAGES.find(s => s.id === stage) ?? STAGES[0]

  return (
    <>
      <Nav />
      <main>
        <HeroSection />

        <section className="pulse" aria-label="Four verbs">
          {VERBS.map(v => (
            <article key={v.name} className="pulse__cell">
              <h2>{v.name}</h2>
              <p>{v.line}</p>
            </article>
          ))}
        </section>

        <section className="stage" id="how">
          <div className="stage__inner">
            <p className="stage__kicker">How it works</p>
            <div className="stage__tabs" role="tablist" aria-label="Architecture">
              {STAGES.map(s => (
                <button
                  key={s.id}
                  type="button"
                  role="tab"
                  aria-selected={stage === s.id}
                  className={`stage__tab${stage === s.id ? ' stage__tab--on' : ''}`}
                  onClick={() => setStage(s.id)}
                >
                  {s.label}
                </button>
              ))}
            </div>
            <div className="stage__panel">
              <div className="stage__copy">
                <h2>{current.title}</h2>
                <p>{current.body}</p>
                <a href="/about-os" className="stage__more">
                  Full OS story →
                </a>
              </div>
              <figure className="stage__figure">
                <img
                  src={current.src}
                  alt={current.alt}
                  width={1376}
                  height={768}
                  loading="lazy"
                />
                <figcaption>{current.caption}</figcaption>
              </figure>
            </div>
          </div>
        </section>

        <section className="ready" id="ready">
          <div className="ready__inner">
            <p className="stage__kicker">Ready now</p>
            <h2 className="ready__h">Three institutions. Ninety minutes.</h2>
            <p className="ready__sub">Your email. A private node. Nobody else sees it.</p>
            <div className="ready__grid">
              {READY_WORKFLOWS.map(w => (
                <a key={w.slug} href={w.href ?? playgroundUrl} className="ready__card">
                  <span className="ready__glow" style={{ background: w.color }} />
                  <span className="wf-badge wf-badge--ready">Ready</span>
                  <h3>{w.name}</h3>
                  <p>{w.outcome}</p>
                  <span className="ready__go">Open {w.name}</span>
                </a>
              ))}
            </div>
            <p className="ready__map-label">On the map</p>
            <div className="ready__map">
              {PLANNED_WORKFLOWS.map(w => (
                <a key={w.slug} href={w.href ?? '/use-cases#planned'} className="ready__chip">
                  {w.name}
                </a>
              ))}
            </div>
          </div>
        </section>

        <section className="devs" id="developers">
          <div className="devs__inner">
            <p className="stage__kicker">For developers</p>
            <h2 className="devs__h">Keep your stack. Admit the world.</h2>
            <p className="devs__sub">
              Binary is <code>connector-platform</code>. Default listen is <code>:9091</code>.
              Point the client at <code>/v1</code>. Ungranted destinations DROP.
            </p>
            <div className="devs-grid">
              <article className="devs-card">
                <h3>Aim /v1</h3>
                <p>Set BASE_URL at the node. Direct vendor HTTP can DROP when the host cut is on.</p>
              </article>
              <article className="devs-card">
                <h3>Default DROP</h3>
                <p>Pore table. Dest-pinned Landlock child. Empty dest is DROP — not Firecracker-by-default.</p>
              </article>
              <article className="devs-card">
                <h3>Inspect the chain</h3>
                <p>HMAC journal on the node. Evidence a reviewer can read — not a certificate we sell.</p>
              </article>
            </div>
            <pre className="devs-pre">{`export OPENAI_BASE_URL=http://127.0.0.1:9091/v1
curl -fsS http://127.0.0.1:9091/healthz`}</pre>
            <div className="devs__actions">
              <a href="/developers" className="btn btn--primary">
                Developer path
              </a>
              <a href={playgroundUrl} className="btn btn--ghost">
                Try 90 minutes
              </a>
            </div>
          </div>
        </section>

        <FaqSection />
        <VisionFormSection />
      </main>
      <Footer />
    </>
  )
}

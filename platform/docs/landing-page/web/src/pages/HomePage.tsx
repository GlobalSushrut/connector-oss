import { useState } from 'react'
import { Nav } from '../components/Nav'
import { HeroSection } from '../components/HeroSection'
import { FaqSection } from '../components/FaqSection'
import { Maintainer } from '../components/Maintainer'
import { Footer } from '../components/Footer'
import { FUTURE, OUTCOMES } from '../data/story'

const STAGES = [
  {
    id: 'os',
    label: 'The path',
    title: 'One effect. One admission.',
    body: 'An agent proposes an effect. PATE admits or refuses it. Runtime can still deny a permit. Then the effect, then the receipt.',
    src: '/connector-os-architecture.svg',
    alt: 'Connector OS. One admission, runtime enforcement, a receipt, and Cease. agentgateway is still a target.',
    caption: 'The government of one effect. Backend integrations are partial.',
  },
  {
    id: 'cage',
    label: 'The world',
    title: 'Ungranted destinations fail closed.',
    body: 'Pore table default DROP. Dest-pinned Landlock child. Empty dest is DROP. This is not a Firecracker microVM.',
    src: '/img/world-cage.png',
    alt: 'World cage: connector-platform parent admits, Landlock child dials one dest, pore table default DROP',
    caption: 'Same cage for Talk, MCP, HAL, HTTP, and a granted browser world.',
  },
  {
    id: 'prove',
    label: 'The receipt',
    title: 'A reviewer can inspect the chain.',
    body: 'HMAC-chained journal of admitted actions. Evidence a person can read. Not a certificate.',
    src: '/img/hmac-chain.png',
    alt: 'HMAC-chained receipts: linked journal entries a reviewer can inspect',
    caption: 'Issuer HMAC. Not a SOC 2, HIPAA, or FedRAMP certificate.',
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

        <section className="ready" id="outcomes">
          <div className="ready__inner">
            <p className="stage__kicker">Outcomes</p>
            <h2 className="ready__h">What you get today.</h2>
            <p className="ready__sub">
              These are the results of running Connector. They are not a product catalog.
            </p>
            <div className="ready__grid">
              {OUTCOMES.map(item => (
                <article key={item.title} className="ready__card ready__card--static">
                  <h3>{item.title}</h3>
                  <p>{item.body}</p>
                </article>
              ))}
            </div>
          </div>
        </section>

        <section className="ready ready--future" id="future">
          <div className="ready__inner">
            <p className="stage__kicker">Future</p>
            <h2 className="ready__h">What is next, and is not claimed yet.</h2>
            <p className="ready__sub">
              Each item below is a gap. It stays on this page so the outcome above is not read as more than it is.
            </p>
            <div className="ready__grid ready__grid--future">
              {FUTURE.map(item => (
                <article key={item.title} className="ready__card ready__card--static">
                  <span className="wf-badge wf-badge--soon">Not yet</span>
                  <h3>{item.title}</h3>
                  <p>{item.body}</p>
                </article>
              ))}
            </div>
          </div>
        </section>

        <section className="stage" id="how">
          <div className="stage__inner">
            <p className="stage__kicker">How an action is governed</p>
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
                  What it is →
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

        <FaqSection />
        <Maintainer />
      </main>
      <Footer />
    </>
  )
}

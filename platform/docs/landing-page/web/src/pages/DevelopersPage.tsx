import { Nav } from '../components/Nav'
import { Footer } from '../components/Footer'
import { useMeta } from '../hooks/useMeta'

export function DevelopersPage() {
  useMeta({
    title: 'For developers — connector-platform, /v1, world cage',
    description:
      'Run connector-platform on :9091. Point your agent at /v1. Ungranted destinations fail closed. Self-hosted. Dest-pinned Landlock, not Firecracker-by-default.',
    canonical: 'https://cnktros.com/developers',
  })

  return (
    <>
      <Nav />
      <main>
        <section className="section section--hero" style={{ paddingBottom: '2.5rem' }}>
          <div className="section__inner" style={{ maxWidth: '760px' }}>
            <p className="hero-category-label">For developers</p>
            <h1 className="hero-title" style={{ fontSize: 'clamp(1.8rem,4vw,2.8rem)', margin: '1rem 0 0.75rem' }}>
              Keep your stack.<br />Admit the world.
            </h1>
            <p className="hero-sub">
              Connector is the OS under the agent — not a new agent. Binary is{' '}
              <code>connector-platform</code>. Default listen is <code>:9091</code>.
              Point the client at <code>/v1</code>. Ungranted destinations DROP.
            </p>
            <div style={{ display: 'flex', gap: '1rem', marginTop: '1.75rem', flexWrap: 'wrap' }}>
              <a href="https://github.com/GlobalSushrut/connector-oss" className="btn btn--primary">
                Clone and run ./up.sh
              </a>
              <a href="/#future" className="btn btn--ghost">
                What is not proven
              </a>
            </div>
            <p className="hero-sub" style={{ marginTop: '1.25rem' }}>
              The first boot downloads the seven backends and the traffic-plane image.
              Firecracker is the binary only. agentgateway forwarding is still unproven.
              This is not a production-ready claim.
            </p>
          </div>
        </section>

        <section className="section section--bordered">
          <div className="section__inner" style={{ maxWidth: '760px' }}>
            <p className="section-label">One URL in</p>
            <h2 className="section__title">Aim the client at the node.</h2>
            <p className="section__lead">
              BASE_URL is voluntary until the host vendor cut applies. Direct vendor HTTP
              can DROP. Journals stay on the node; vendor LLM HTTP may leave when a model is granted.
            </p>
            <pre className="devs-pre">{`export OPENAI_BASE_URL=http://127.0.0.1:9091/v1
export OPENAI_API_KEY=dev-token

curl -fsS http://127.0.0.1:9091/healthz
connectorctl doctor`}</pre>
            <p className="devs-note">
              Isolation today is dest-pinned Landlock, not Firecracker-by-default. Stop kills the loop — it does not undo world effects.
            </p>
          </div>
        </section>

        <section className="section section--bordered">
          <div className="section__inner" style={{ maxWidth: '960px' }}>
            <p className="section-label">What you get</p>
            <div className="devs-grid">
              <article className="devs-card">
                <h3>Node</h3>
                <p>
                  <code>connector-platform</code> on Linux. Pore table default DROP. One dest-pinned child dials what you granted.
                </p>
              </article>
              <article className="devs-card">
                <h3>CLI</h3>
                <p>
                  <code>connectorctl</code> for the node. <code>cnktros</code> for bind, surfaces, invoke, receipts — not a replacement agent runtime.
                </p>
              </article>
              <article className="devs-card">
                <h3>Proof</h3>
                <p>
                  HMAC-chained journal a reviewer can inspect. Issuer HMAC is evidence — not court-grade quorum, not a sold SOC 2 checkbox.
                </p>
              </article>
            </div>
          </div>
        </section>

        <section className="section">
          <div className="section__inner" style={{ maxWidth: '760px' }}>
            <p className="section-label">Go deeper</p>
            <ul className="devs-links">
              <li>
                <a href="/about-os">What it is</a> — one admission, a receipt, and the limits.
              </li>
              <li>
                <a href="/get-started">Run it</a> — clone and <code>./up.sh</code>.
              </li>
              <li>
                <a href="https://github.com/GlobalSushrut/connector-oss" target="_blank" rel="noopener noreferrer">
                  connector-oss on GitHub
                </a>
                {' '}
                — crates, not the hosted playground.
              </li>
            </ul>
          </div>
        </section>
      </main>
      <Footer />
    </>
  )
}

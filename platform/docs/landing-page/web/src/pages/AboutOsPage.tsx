import { Nav } from '../components/Nav'
import { Footer } from '../components/Footer'
import { Maintainer } from '../components/Maintainer'
import { useMeta } from '../hooks/useMeta'

export function AboutOsPage() {
  useMeta({
    title: 'What Connector is',
    description:
      'Connector admits or refuses each agent action, lets an operator stop the next one, and keeps a receipt. Not an agent framework. Not a certificate.',
    canonical: 'https://cnktros.com/about-os',
  })
  return (
    <>
      <Nav />
      <main>
        <section className="section section--hero" style={{ paddingBottom: '2.5rem' }}>
          <div className="section__inner" style={{ maxWidth: '760px' }}>
            <p className="hero-category-label">What it is</p>
            <h1 className="hero-title" style={{ fontSize: 'clamp(1.8rem,4vw,2.8rem)', margin: '1rem 0 0.75rem' }}>
              A control plane for agents that act.
            </h1>
            <p className="hero-sub">
              Connector gives an agent an identity, explicit authority, one
              admission per action, runtime enforcement, an operator stop, and
              a receipt. It does not contain a language model. It is not an
              agent framework. It is not a certificate.
            </p>
          </div>
        </section>

        <section className="section section--bordered">
          <div className="section__inner" style={{ maxWidth: '760px' }}>
            <p className="section-label">Why it matters</p>
            <h2 className="section__title">The question the other tools leave open.</h2>
            <p className="section__lead">
              Agent frameworks help an agent reason and use tools. Gateways
              route traffic. Policy engines evaluate rules. Observability
              records what already happened. None of those alone answers:
              should this agent be allowed to perform this action, in this
              situation, right now — and can an operator stop the next action?
            </p>
          </div>
        </section>

        <section className="section">
          <div className="section__inner" style={{ maxWidth: '960px' }}>
            <p className="section-label">The action path</p>
            <h2 className="section__title">Proposed effect, then a decision, then a receipt.</h2>
            <figure className="diagram-figure">
              <img
                src="/connector-os-architecture.svg"
                alt="Connector OS. One admission, runtime enforcement, a receipt, and Cease."
                width={1376}
                height={997}
              />
              <figcaption className="diagram-caption">
                agent → proposed effect → PATE admission → runtime enforcement → external effect → receipt.
                A permit can still be denied at runtime. Cease stops the next admission.
              </figcaption>
            </figure>
            <pre className="devs-pre">{`agent → proposed effect → PATE admission → runtime enforcement
      → external effect → receipt and observed consequence`}</pre>
          </div>
        </section>

        <section className="section section--bordered">
          <div className="section__inner" style={{ maxWidth: '760px' }}>
            <p className="section-label">What this page does not say</p>
            <h2 className="section__title">Limits that stay in force.</h2>
            <ul className="pill-list">
              <li>Firecracker boot downloads the binary and jailer. It does not create a microVM.</li>
              <li>agentgateway can start. Forwarding has not been proven and stays denied.</li>
              <li>Starting a backend does not prove every effect passed through it.</li>
              <li>No production, security, correctness, safety, or compliance claim.</li>
            </ul>
            <div style={{ display: 'flex', gap: '1rem', marginTop: '1.75rem', flexWrap: 'wrap' }}>
              <a href="/#outcomes" className="btn btn--primary">What you get</a>
              <a href="/#future" className="btn btn--ghost">What is next</a>
              <a href="/get-started" className="btn btn--ghost">Run it</a>
            </div>
          </div>
        </section>
        <Maintainer />
      </main>
      <Footer />
    </>
  )
}

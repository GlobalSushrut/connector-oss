import { Nav } from '../components/Nav'
import { useMeta } from '../hooks/useMeta'
import { Footer } from '../components/Footer'
import { playgroundUrl } from '../config'
import { READY_WORKFLOWS } from '../data/workflows'

export function UseCasesPage() {
  useMeta({
    title: 'What Connector ships today | Connector',
    description:
      'Three institutions on one workspace: coding-agent guardrails, an action record, and a receipt. Incomplete products are not listed here.',
    canonical: 'https://cnktros.com/use-cases',
  })
  return (
    <>
      <Nav />
      <main>

        <section className="section section--hero" style={{ paddingBottom: '2.5rem' }}>
          <div className="section__inner" style={{ maxWidth: '760px' }}>
            <p className="hero-category-label">Connector — use cases</p>
            <h1 className="hero-title" style={{ fontSize: 'clamp(1.8rem, 4vw, 2.8rem)', marginBottom: '1rem' }}>
              Three ways the workspace is used today.
            </h1>
            <p className="hero-sub">
              Guard a coding agent. Record the action. Keep a receipt.
              That is the product. Unfinished workflows are not listed here.
            </p>
            <div style={{ display: 'flex', gap: '1rem', marginTop: '1.75rem', flexWrap: 'wrap' }}>
              <a href={playgroundUrl} className="btn btn--primary">Try it</a>
              <a href="#ready" className="btn btn--ghost">What ships</a>
            </div>
          </div>
        </section>

        <section className="section section--bordered">
          <div className="section__inner" style={{ maxWidth: '760px' }}>
            <p className="section-label">How to read this</p>
            <h2 className="section__title">OS first. Workflows second.</h2>
            <p className="section__lead">
              Connector sits beneath your agents, models, tools, and workflows.
              Isolate, govern, stop, prove. DevGuard, TraceTramp, and WitnessCtl
              are institutions on that OS — not three separate products, and
              not the OS itself.
            </p>
            <figure className="diagram-figure">
              <img
                src="/img/ui-fabric.png"
                alt="Concept fabric of multiple agents on one controlled world. Not a screenshot of the shipping dashboard."
                width={1376}
                height={768}
                loading="lazy"
              />
              <figcaption className="diagram-caption">
                Concept operator surface — not the shipping UI. Isolation today is dest-pinned Landlock children, not Firecracker-by-default.
              </figcaption>
            </figure>
          </div>
        </section>

        <section id="ready" className="section section--bordered">
          <div className="section__inner">
            <p className="section-label">Ready</p>
            <h2 className="section__title">Three workflows. Try them in 90 minutes.</h2>
            <p className="section__lead" style={{ maxWidth: '640px' }}>
              Enter your email. That address owns a private node for 90 minutes. Up to ten people at once. Same email can start again and gets new agents.
            </p>

            <div className="uc-today-grid">
              {READY_WORKFLOWS.map(w => (
                <div key={w.slug} className="uc-today-card">
                  <div className="uc-today-card__bar" style={{ background: w.color }} />
                  <div className="uc-today-card__inner">
                    <div className="uc-today-card__head">
                      <p className="uc-today-card__name">{w.name}</p>
                      <span className="wf-badge wf-badge--ready">Ready</span>
                    </div>
                    <p className="uc-today-card__problem">
                      <span className="uc-label">Problem</span>
                      {w.problem}
                    </p>
                    <p className="uc-today-card__outcome">
                      <span className="uc-label uc-label--green">Outcome</span>
                      {w.outcome}
                    </p>
                    <a href={w.href ?? playgroundUrl} className="uc-today-card__cta">
                      See {w.name} →
                    </a>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section className="section">
          <div className="section__inner" style={{ maxWidth: '640px', textAlign: 'center' }}>
            <h2 className="section__title">Start with one of the three institutions.</h2>
            <p className="section__lead">
              Guard a coding agent. Record who did what. Keep a receipt.
              That is what ships today.
            </p>
            <div style={{ display: 'flex', gap: '1rem', justifyContent: 'center', flexWrap: 'wrap' }}>
              <a href={playgroundUrl} className="btn btn--primary">Try 90 minutes</a>
              <a href="/#interest" className="btn btn--ghost">Run one workflow with us</a>
            </div>
          </div>
        </section>

        <Footer />

      </main>
    </>
  )
}

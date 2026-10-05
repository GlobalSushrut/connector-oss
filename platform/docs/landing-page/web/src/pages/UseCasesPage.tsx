import { Nav } from '../components/Nav'
import { useMeta } from '../hooks/useMeta'
import { Footer } from '../components/Footer'
import { playgroundUrl } from '../config'
import { READY_WORKFLOWS, PLANNED_WORKFLOWS } from '../data/workflows'

const CUSTOM_WORKFLOWS = [
  {
    industry: 'Healthcare',
    color: '#3ecf8e',
    problem:
      'Clinical AI needs named access, PHI isolation, and a trail a reviewer can inspect — not a spreadsheet.',
    workflow:
      'Design-partner path: namespace isolation + WitnessCtl receipts + policy on tools that touch records.',
    plugins: ['DevGuard', 'WitnessCtl'],
    outcome: 'On the map. Not a packaged HIPAA SKU today.',
  },
  {
    industry: 'Legal',
    color: '#5ba8ff',
    problem:
      'Legal AI must keep privileged matter in its lane and show who retrieved what.',
    workflow:
      'Design-partner path: per-matter isolation + traces + receipts for retrieval.',
    plugins: ['TraceTramp', 'WitnessCtl'],
    outcome: 'On the map. Privilege enforcement is not a day-one SKU.',
  },
  {
    industry: 'Government',
    color: '#fb923c',
    problem:
      'Inspectors want isolation, a kill switch, and a trail — on infrastructure you operate.',
    workflow:
      'Design-partner path: self-hosted node + identity + evidence chain.',
    plugins: ['DevGuard', 'WitnessCtl'],
    outcome: 'On the map. Not FedRAMP-certified. Not sold as such.',
  },
  {
    industry: 'Financial services',
    color: '#fbbf24',
    problem:
      'Trading and risk agents need who-did-what, a budget stop, and a chain a reviewer can read.',
    workflow:
      'Design-partner path: traces + receipts. Gateway cost-cap posture exists; the LedgerLens SKU is planned.',
    plugins: ['TraceTramp', 'WitnessCtl', 'LedgerLens'],
    outcome: 'On the map. Cost-cap posture exists in the gateway; LedgerLens is not a ready SKU.',
  },
]

export function UseCasesPage() {
  useMeta({
    title: 'AI agent workflows — 3 ready institutions, 7 planned | Connector',
    description:
      'Ten workflows on one OS. Three institutions you can try in 90 minutes: coding-agent guardrails, who-did-what traces, and reviewer-ready evidence. Seven more are the plan.',
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
              Ten workflows. Three you can try today.
            </h1>
            <p className="hero-sub">
              Ready means your email opens a private 90-minute node:
              DevGuard, TraceTramp, and WitnessCtl — three institutions on
              one OS. The other seven are the plan — we explain them so you
              can see the market, not so we pretend they ship.
            </p>
            <div style={{ display: 'flex', gap: '1rem', marginTop: '1.75rem', flexWrap: 'wrap' }}>
              <a href={playgroundUrl} className="btn btn--primary">Try 90 minutes</a>
              <a href="#ready" className="btn btn--ghost">Ready now</a>
              <a href="#planned" className="btn btn--ghost">On the map</a>
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

        <section id="planned" className="section">
          <div className="section__inner">
            <p className="section-label">Planned</p>
            <h2 className="section__title">Seven more. The plan, not the SKU.</h2>
            <p className="section__lead" style={{ maxWidth: '640px' }}>
              These are real buyer problems. They are not ready to try. If one
              of these is the reason you would pay, talk to us — that is a
              design partnership, not a download.
            </p>

            <div className="uc-today-grid">
              {PLANNED_WORKFLOWS.map(w => (
                <div key={w.slug} className="uc-today-card">
                  <div className="uc-today-card__bar" style={{ background: w.color }} />
                  <div className="uc-today-card__inner">
                    <div className="uc-today-card__head">
                      <p className="uc-today-card__name">{w.name}</p>
                      <span className="wf-badge wf-badge--soon">Planned</span>
                    </div>
                    <p className="uc-today-card__problem">
                      <span className="uc-label">Problem</span>
                      {w.problem}
                    </p>
                    <p className="uc-today-card__outcome">
                      <span className="uc-label">Intended outcome</span>
                      {w.outcome}
                    </p>
                    {w.href ? (
                      <a href={w.href} className="uc-today-card__cta">
                        Read the plan →
                      </a>
                    ) : (
                      <a href="/#interest" className="uc-today-card__cta">
                        Talk about this workflow →
                      </a>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section id="custom" className="section section--bordered">
          <div className="section__inner">
            <p className="section-label">Regulated industries</p>
            <h2 className="section__title">Design partners — not a certified product line.</h2>
            <p className="section__lead" style={{ maxWidth: '640px' }}>
              Healthcare, legal, government, and finance need the same kernel
              with tighter policy. We will build those with you. We do not sell
              SOC 2, HIPAA, or FedRAMP as a checkbox today.
            </p>

            <div className="uc-custom-grid">
              {CUSTOM_WORKFLOWS.map(w => (
                <div key={w.industry} className="uc-custom-card">
                  <div className="uc-custom-card__header" style={{ borderLeftColor: w.color }}>
                    <p className="uc-custom-card__industry">{w.industry}</p>
                    <span className="wf-badge wf-badge--soon">Planned</span>
                  </div>
                  <p className="uc-custom-card__problem">
                    <span className="uc-label">Problem today</span>
                    {w.problem}
                  </p>
                  <p className="uc-custom-card__workflow">
                    <span className="uc-label uc-label--blue">Path</span>
                    {w.workflow}
                  </p>
                  <div className="uc-custom-card__plugins">
                    {w.plugins.map(p => (
                      <span key={p} className="persona-plugin-tag">{p}</span>
                    ))}
                  </div>
                  <p className="uc-custom-card__outcome">{w.outcome}</p>
                </div>
              ))}
            </div>

            <div className="about-os-callout" style={{ marginTop: '3rem' }}>
              <p>If your workflow is one of the seven, start a design conversation — not a pretend install.</p>
              <a href="/#interest" className="btn btn--primary">Talk to us →</a>
            </div>
          </div>
        </section>

        <section className="section">
          <div className="section__inner" style={{ maxWidth: '640px', textAlign: 'center' }}>
            <h2 className="section__title">Start with one of the three institutions.</h2>
            <p className="section__lead">
              Guard a coding agent. Reconstruct who did what. Keep a receipt.
              That is what is ready. The rest is the map.
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

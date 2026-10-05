import { WORKFLOWS } from '../data/workflows'

export function ServicesSection() {
  return (
    <section id="services" className="section section--bordered">
      <div className="section__inner">
        <h2 className="section__title">Ten workflows. Three ready. Seven planned.</h2>
        <p className="section__lead section__lead--flush">
          The OS is one product. Workflows are how buyers use it.
          Ready means your email opens a private 90-minute node.
          Planned means we will sell it — it is not live today.
        </p>

        <div className="plugin-grid">
          {WORKFLOWS.map(p => (
            <a
              key={p.slug}
              href={p.href ?? '/use-cases#planned'}
              className={`plugin-card ${p.status === 'planned' ? 'plugin-card--soon' : ''}`}
            >
              <div className="plugin-card__accent" style={{ background: p.color }} />
              <div className="plugin-card__body">
                <div className="plugin-card__head">
                  <p className="plugin-card__name">{p.name}</p>
                  <span className={`wf-badge ${p.status === 'ready' ? 'wf-badge--ready' : 'wf-badge--soon'}`}>
                    {p.status === 'ready' ? 'Ready' : 'Planned'}
                  </span>
                </div>
                <p className="plugin-card__tagline">{p.tagline}</p>
                <div className="plugin-card__divider" />
                <p className="plugin-card__outcome">{p.outcome}</p>
                <span className="plugin-card__cta">
                  {p.status === 'ready' ? 'Try this workflow →' : 'On the map →'}
                </span>
              </div>
            </a>
          ))}
        </div>

        <p style={{ textAlign: 'center', marginTop: '2rem' }}>
          <a href="/use-cases" className="btn btn--ghost">See problems, outcomes, and the plan →</a>
        </p>

        <div className="about-os-callout">
          <p>
            Want the OS story — identity, isolation, admit, stop, prove?
          </p>
          <a href="/about-os" className="btn btn--ghost">
            How Connector works →
          </a>
        </div>
      </div>
    </section>
  )
}

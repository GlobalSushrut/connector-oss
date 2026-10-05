import { Nav } from '../components/Nav'
import { Footer } from '../components/Footer'

const INDUSTRIES = [
  {
    name: 'Healthcare',
    color: '#3ecf8e',
    problem: 'Clinical AI needs named access, isolation, and a trail a reviewer can inspect — not a spreadsheet.',
    what: 'Design-partner path on the same kernel. Start from ready receipts and isolation. PHI-specific mapping is not a packaged HIPAA SKU.',
    plugins: ['DevGuard', 'WitnessCtl'],
    outcomes: [
      'Intended: named owner for every tool that touches records',
      'Intended: receipts a reviewer can inspect',
      'Not sold: HIPAA certification or a mapped bundle out of the box',
    ],
    howToUse: [
      { step: 'Talk to us', detail: 'If healthcare is why you would buy, that is a design partnership.' },
      { step: 'Start from what is ready', detail: 'DevGuard and WitnessCtl exist. The rest is scoped with you.' },
      { step: 'Do not expect a checkbox', detail: 'We will not hand you a HIPAA certificate.' },
    ],
  },
  {
    name: 'Legal',
    color: '#5ba8ff',
    problem: 'Legal AI must keep privileged matter in its lane and show who retrieved what.',
    what: 'Design-partner path: isolation plus traces plus receipts. Privilege enforcement is not a day-one SKU.',
    plugins: ['TraceTramp', 'WitnessCtl'],
    outcomes: [
      'Intended: who retrieved which document, under which identity',
      'Intended: a chain a reviewer can inspect',
      'Not sold: attorney-client privilege as a guaranteed kernel property today',
    ],
    howToUse: [
      { step: 'Talk to us', detail: 'Matter isolation and retrieval traces are the conversation, not a download.' },
      { step: 'Start from what is ready', detail: 'TraceTramp and WitnessCtl. Identity and memory plugins are planned.' },
    ],
  },
  {
    name: 'Government',
    color: '#fb923c',
    problem: 'Inspectors want isolation, a kill switch, and a trail — on infrastructure you operate.',
    what: 'Design-partner path: self-hosted node plus identity plus evidence. Not FedRAMP-certified. Not sold as such.',
    plugins: ['DevGuard', 'WitnessCtl'],
    outcomes: [
      'Intended: self-hosted, you operate the node',
      'Intended: receipts exportable for a reviewer',
      'Not sold: FedRAMP, FISMA, or classified accreditation',
    ],
    howToUse: [
      { step: 'Talk to us', detail: 'If inspection is the job, we scope a node with you. We do not sell a FedRAMP badge.' },
    ],
  },
  {
    name: 'Financial Services',
    color: '#fbbf24',
    problem: 'Trading and risk agents need who-did-what, a stop button, and a chain a reviewer can read.',
    what: 'Design-partner path: traces and receipts now. Gateway cost-cap posture exists; the LedgerLens SKU is planned.',
    plugins: ['TraceTramp', 'WitnessCtl', 'LedgerLens'],
    outcomes: [
      'Intended: who decided what, under which identity',
      'Planned: hard cost caps per strategy',
      'Not sold: SOX / MiFID II certification',
    ],
    howToUse: [
      { step: 'Talk to us', detail: 'Start from TraceTramp and WitnessCtl. Cost gates are on the map.' },
    ],
  },
]

export function CustomWorkflowPage() {
  return (
    <>
      <Nav />
      <main>

        {/* ── Hero ──────────────────────────────────────────────────── */}
        <section className="section section--hero" style={{ paddingBottom: '2.5rem' }}>
          <div className="section__inner" style={{ maxWidth: '760px' }}>
            <p className="hero-category-label">
              Custom workflows — planned, design partners only
            </p>
            <h1 className="hero-title" style={{ fontSize: 'clamp(1.8rem,4vw,2.8rem)', margin: '1rem 0 0.75rem' }}>
              Regulated industries are on the map.<br />Not a certified SKU today.
            </h1>
            <p className="hero-sub">
              Three institutions are ready: DevGuard, TraceTramp, and
              WitnessCtl. Healthcare, legal, government, and finance are
              design-partner programs. We do not sell SOC 2, HIPAA, or FedRAMP
              as a checkbox.
            </p>
            <div style={{ display: 'flex', gap: '1rem', marginTop: '1.75rem', flexWrap: 'wrap' }}>
              <a href="/#interest" className="btn btn--primary">Apply for custom workflow</a>
              <a href="/use-cases" className="btn btn--ghost">See all use cases →</a>
            </div>
          </div>
        </section>

        {/* ── What a custom workflow is ─────────────────────────────── */}
        <section className="section section--bordered">
          <div className="section__inner" style={{ maxWidth: '760px' }}>
            <p className="section-label">What it is</p>
            <h2 className="section__title">Not a product. A designed program.</h2>
            <p className="section__lead">
              A custom workflow is not something you download. It is a design
              partnership on the same kernel: isolate, govern, stop, prove —
              with policy written for your threat model. The industry pages
              below describe the intended path. They are not live products.
            </p>
            <div className="pp-steps" style={{ marginTop: '1.75rem' }}>
              {[
                { step: 'You apply', detail: 'Tell us your industry, your compliance requirements, and your use case. We read every submission.' },
                { step: 'We design the workflow', detail: 'Our team selects the right plugin composition, writes the policy contracts, and configures the proof bundle templates for your framework.' },
                { step: 'You get the binary', detail: 'Self-hosted ConnectorOS node with your custom workflow pre-configured. Your infrastructure. Your data. No cloud dependency.' },
                { step: 'We polish it with you', detail: 'If we take the partnership, we tune policy with you. We do not promise a certification at the end.' },
              ].map((s, i) => (
                <div key={s.step} className="pp-step">
                  <div className="pp-step__num" style={{ background: 'var(--accent)' }}>{i + 1}</div>
                  <div className="pp-step__body">
                    <p className="pp-step__title">{s.step}</p>
                    <p className="pp-step__detail">{s.detail}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* ── 4 industry workflows ─────────────────────────────────── */}
        {INDUSTRIES.map((ind, idx) => (
          <section
            key={ind.name}
            className={`section ${idx % 2 === 0 ? 'section--bordered' : ''}`}
          >
            <div className="section__inner" style={{ maxWidth: '820px' }}>
              <div className="cw-industry-header" style={{ borderLeftColor: ind.color }}>
                <p className="cw-industry-name" style={{ color: ind.color }}>{ind.name}</p>
              </div>

              <p className="pp-problem" style={{ marginBottom: '1.25rem' }}>{ind.problem}</p>

              <h3 className="cw-section-sub">The workflow</h3>
              <p className="pp-what">{ind.what}</p>

              <div className="cw-plugins">
                {ind.plugins.map(p => (
                  <a key={p} href={`/products/${p.toLowerCase()}`} className="os-stack__chip os-stack__chip--plugin" style={{ textDecoration: 'none' }}>{p}</a>
                ))}
              </div>

              <h3 className="cw-section-sub">Outcomes</h3>
              <ul className="pp-outcomes">
                {ind.outcomes.map(o => (
                  <li key={o} className="pp-outcome-item">
                    <span className="pp-outcome-check" style={{ color: ind.color }}>✓</span>
                    <span>{o}</span>
                  </li>
                ))}
              </ul>

              <h3 className="cw-section-sub">How it works after you get the binary</h3>
              <div className="pp-steps" style={{ marginTop: '0.75rem' }}>
                {ind.howToUse.map((s, i) => (
                  <div key={s.step} className="pp-step">
                    <div className="pp-step__num" style={{ background: ind.color }}>{i + 1}</div>
                    <div className="pp-step__body">
                      <p className="pp-step__title">{s.step}</p>
                      <p className="pp-step__detail">{s.detail}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </section>
        ))}

        {/* ── Apply CTA ─────────────────────────────────────────────── */}
        <section className="section section--bordered">
          <div className="section__inner" style={{ maxWidth: '640px' }}>
            <div className="pp-cta-block">
              <p className="pp-cta-block__eyebrow" style={{ color: 'var(--accent)' }}>
                Custom Workflows · Controlled access
              </p>
              <h2 className="pp-cta-block__title">
                Apply. We'll design it with you.
              </h2>
              <p className="pp-cta-block__body">
                If your industry is not listed or your requirements go beyond the standard programs — tell us. We design custom workflow programs for defence, critical infrastructure, insurance, energy, and other high-risk environments.
              </p>
              <ul className="pp-cta-checklist">
                <li><span style={{ color: 'var(--accent)' }}>✓</span> Self-hosted binary — your infrastructure</li>
                <li><span style={{ color: 'var(--accent)' }}>✓</span> Policy contracts written for your compliance framework</li>
                <li><span style={{ color: 'var(--accent)' }}>✓</span> Proof bundle templates validated against your auditors' requirements</li>
                <li><span style={{ color: 'var(--accent)' }}>✓</span> 30-day onboarding — we polish the workflow with you</li>
                <li><span style={{ color: 'var(--accent)' }}>✓</span> Offline / restricted-network posture is a design-partner path — not a sold air-gap SKU</li>
              </ul>
              <a href="/#interest" className="btn btn--primary">Apply for custom workflow</a>
            </div>
          </div>
        </section>

        {/* ── Powered by ───────────────────────────────────────────── */}
        <section className="section">
          <div className="section__inner" style={{ maxWidth: '760px' }}>
            <div className="pp-powered-by">
              <span className="pp-powered-by__label">Powered by</span>
              <a href="/about-os" className="pp-powered-by__link">
                ConnectorOS — operating substrate for intelligence
              </a>
            </div>
            <p className="pp-powered-by__detail">
              Same kernel: isolate, govern, stop, prove. Industry policy is written with you. We do not sell a compliance badge.
            </p>
          </div>
        </section>

        <Footer />

      </main>
    </>
  )
}

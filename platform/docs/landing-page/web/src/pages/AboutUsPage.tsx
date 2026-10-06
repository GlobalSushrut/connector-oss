import { Nav } from '../components/Nav'
import { useMeta } from '../hooks/useMeta'
import { Footer } from '../components/Footer'

// BELIEFS placeholder
const BELIEFS = [
  {
    title: 'AI infrastructure is broken by design.',
    body: 'Every AI platform gives you more capability. Nobody gives you control over it. The audit trail, the enforcement boundary, the proof of what happened — those were assumed to be someone else\'s problem. We think that is the wrong default.',
  },
  {
    title: 'Governance is infrastructure, not compliance theater.',
    body: 'Filling out questionnaires and generating policy PDFs is not governance. Governance is enforcement — at runtime, before the action, with a receipt. If you cannot prove it happened, it did not happen.',
  },
  {
    title: 'The OS model is the right model.',
    body: 'The reason Linux works at scale is that the kernel does not trust any process. It mediates, enforces, and records. We are applying that model to AI — not as a metaphor, but structurally. The rings are real. The receipts are real.',
  },
  {
    title: 'Self-hosted is a feature, not a constraint.',
    body: 'Your sensitive data, your agent behavior, your audit trail — these should not live in a vendor\'s cloud. ConnectorOS runs on your infrastructure. You own the binary. You own the receipts. No third party sees your agent behavior.',
  },
  {
    title: 'Proof beats trust.',
    body: 'We are not asking reviewers to trust your AI. We are giving them an HMAC-chained journal they can inspect. Issuer HMAC is evidence, not court-grade custody. Trust is fragile. Proof is durable.',
  },
]

const BUILDING_FOR = [
  {
    role: 'CTO',
    signal: 'You are shipping AI into production and you are not confident you can explain what it did if something goes wrong.',
    value: 'ConnectorOS is the layer that makes your AI systems auditable, bounded, and defensible — before the incident, not after.',
  },
  {
    role: 'CISO',
    signal: 'Your security team is being asked to approve AI systems with no enforcement boundary and no audit trail.',
    value: 'ConnectorOS gives security a real control surface — policy gates, identity, firewall, and a tamper-evident record of every agent action.',
  },
  {
    role: 'Compliance Officer',
    signal: 'You are being asked what the agent decided, with nothing more than a policy PDF and a log export.',
    value: 'Connector produces hash-chained receipts a reviewer can inspect. Framework mapping is a design-partner path. We do not sell a certification.',
  },
  {
    role: 'Platform Engineer',
    signal: 'You are building the internal platform that other teams will ship AI on top of — and you need governance baked in, not bolted on.',
    value: 'ConnectorOS is the governance kernel for your platform. Every agent, every workflow, every model call goes through the same enforcement stack — regardless of which team built it.',
  },
  {
    role: 'ML Engineer',
    signal: 'You are shipping models into production and you are the one who gets paged when they misbehave — but you have no visibility into what the agent actually did.',
    value: 'ConnectorOS gives you full execution traces, drift detection, and replay — so you can debug agent behavior at the decision level, not the log level.',
  },
]

const PRINCIPLES = [
  { num: '01', title: 'Fail closed', body: 'When ConnectorOS cannot make a decision, it denies. Not because we are conservative — because that is what infrastructure does when it cannot verify.' },
  { num: '02', title: 'No shortcuts', body: 'Nine rings. Every request. No ring can be skipped for performance, convenience, or backwards compatibility. The enforcement is the product.' },
  { num: '03', title: 'Receipts, not promises', body: 'Every claim we make about governance is backed by a verifiable receipt. We do not ask you to trust our description of what happened.' },
  { num: '04', title: 'You own your data', body: 'ConnectorOS runs on your infrastructure. We do not collect your agent behavior, your audit trail, or your policy contracts. We never will.' },
  { num: '05', title: 'Standards-first', body: 'HMAC-chained journals and CID addressing ship today. W3C DID and UCAN are the AgentPassport plan — not a live SKU. Your proof chain should not require a dashboard screenshot.' },
  { num: '06', title: 'One workflow first', body: 'We do not do kitchen-sink pilots. We start with one workflow, one team, 30 days. Prove control before you commit. That discipline is intentional.' },
]

export function AboutUsPage() {
  useMeta({
    title: 'About Us — Why We Built Connector | Connector',
    description: 'The team building ConnectorOS: AI agent governance infrastructure for regulated industries. Our thesis, beliefs, and why governance is infrastructure — not compliance theater.',
    canonical: 'https://cnktros.com/about-us',
  })
  return (
    <>
      <Nav />
      <main>

        {/* ── Hero ─────────────────────────────────────────────────── */}
        <section className="section section--hero" style={{ paddingBottom: '2.5rem' }}>
          <div className="section__inner" style={{ maxWidth: '760px' }}>
            <p className="hero-category-label">About Us</p>
            <h1 className="hero-title" style={{ fontSize: 'clamp(1.8rem,4vw,2.8rem)', margin: '1rem 0 0.75rem' }}>
              We are building the enforcement layer<br />that AI infrastructure never had.
            </h1>
            <p className="hero-sub">
              ConnectorOS exists because every AI platform gives you more capability and nobody gives you control. We think governance is infrastructure — not compliance theater, not a dashboard, not a policy PDF. Real enforcement. At runtime. With a receipt.
            </p>
          </div>
        </section>

        {/* ── Origin / Why ─────────────────────────────────────────── */}
        <section className="section section--bordered">
          <div className="section__inner" style={{ maxWidth: '760px' }}>
            <p className="section-label">Origin</p>
            <h2 className="section__title">Why we exist.</h2>

            <div className="au-origin-grid">
              <div className="au-origin-block">
                <p className="au-origin-block__label">The gap we saw</p>
                <p className="au-origin-block__body">
                  Every enterprise shipping AI hit the same wall. Models were capable. Infrastructure was not ready. When an agent accessed the wrong data, ran the wrong command, or produced output that drove a wrong decision — there was no trail. No enforcement. No proof.
                </p>
                <p className="au-origin-block__body" style={{ marginTop: '0.75rem' }}>
                  The answer from the market was better prompts, better models, better monitoring. None of those are the answer. The answer is a kernel — a layer that mediates, enforces, and records at the infrastructure level.
                </p>
              </div>
              <div className="au-origin-block">
                <p className="au-origin-block__label">What we built</p>
                <p className="au-origin-block__body">
                  A self-hosted OS for intelligence. Isolate, govern, stop, prove. Three institutions are ready: coding-agent guardrails, who-did-what traces, and evidence. Seven more are the plan.
                </p>
                <p className="au-origin-block__body" style={{ marginTop: '0.75rem' }}>
                  It is not an agent framework. It is not a monitoring tool. It is not another AI platform. It is the layer that sits below everything else — governing every agent, every tool call, every model interaction — with a receipt.
                </p>
              </div>
            </div>

            <blockquote className="au-quote">
              <p>"This is not a model problem. It is an infrastructure problem."</p>
              <cite>— ConnectorOS founding thesis</cite>
            </blockquote>
          </div>
        </section>

        {/* ── Mission / Vision / Category ──────────────────────────── */}
        <section className="section">
          <div className="section__inner" style={{ maxWidth: '760px' }}>
            <p className="section-label">Mission · Vision · Category</p>
            <h2 className="section__title">What we stand for. Where we are going.</h2>

            <div className="au-mvp-grid">
              <div className="au-mvp-card au-mvp-card--mission">
                <p className="au-mvp-card__type">Mission</p>
                <p className="au-mvp-card__statement">
                  Make AI agents trustworthy — not by making them smarter, but by making everything they do verifiable, bounded, and provable in production.
                </p>
              </div>
              <div className="au-mvp-card au-mvp-card--vision">
                <p className="au-mvp-card__type">Vision</p>
                <p className="au-mvp-card__statement">
                  A world where any enterprise can ship AI into regulated, high-stakes, and critical environments — because the governance layer is infrastructure, not an afterthought.
                </p>
              </div>
              <div className="au-mvp-card au-mvp-card--category">
                <p className="au-mvp-card__type">Category</p>
                <p className="au-mvp-card__statement">
                  <strong>Operating substrate for intelligence.</strong> Not an AI platform. Not a monitoring tool. Not an agent framework. Not a coding-agent product. The OS that everything else runs on.
                </p>
              </div>
            </div>

            <div className="au-positioning-block">
              <p className="au-positioning-block__label">Unique Positioning Statement</p>
              <p className="au-positioning-block__statement">
                Connector sits beneath the stack you already have. Identity, policy, a kill switch, and a receipt. Not another agent framework. Not a SOC 2 certificate.
              </p>
              <div className="au-positioning-pillars">
                <div className="au-pos-pillar">
                  <span className="au-pos-pillar__word">Isolate</span>
                  <span className="au-pos-pillar__def">Agents cannot reach data, systems, or capabilities outside their policy boundary</span>
                </div>
                <div className="au-pos-pillar">
                  <span className="au-pos-pillar__word">Govern</span>
                  <span className="au-pos-pillar__def">Every decision is evaluated against a policy before it executes — not observed after</span>
                </div>
                <div className="au-pos-pillar">
                  <span className="au-pos-pillar__word">Stop</span>
                  <span className="au-pos-pillar__def">Cut grants, freeze the session, kill the loop. Stop is not undo.</span>
                </div>
                <div className="au-pos-pillar">
                  <span className="au-pos-pillar__word">Prove</span>
                  <span className="au-pos-pillar__def">Hash-chained receipts a reviewer can inspect — evidence, not a certificate</span>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* ── 2027 / 2028 Correction Year thesis ───────────────────── */}
        <section className="section section--bordered">
          <div className="section__inner" style={{ maxWidth: '760px' }}>
            <p className="section-label">The thesis</p>
            <h2 className="section__title">We are preparing for the correction years: 2027 and 2028.</h2>
            <p className="section__lead" style={{ maxWidth: '640px' }}>
              The AI hype cycle has a reckoning built into it. We know when it is coming. We are building for the aftermath.
            </p>

            <div className="au-correction-timeline">

              <div className="au-ct-row">
                <div className="au-ct-year">2024 – 2026</div>
                <div className="au-ct-body">
                  <p className="au-ct-title">The capability race</p>
                  <p className="au-ct-desc">
                    Every enterprise is rushing AI into production. Budgets are uncapped. Guardrails are optional. The question being asked is <em>"what can AI do?"</em> — not <em>"what happens when it does something wrong?"</em> This is the era of AI optimism. Demos ship. Receipts don't.
                  </p>
                </div>
              </div>

              <div className="au-ct-divider">↓</div>

              <div className="au-ct-row au-ct-row--highlight">
                <div className="au-ct-year au-ct-year--warn">2027</div>
                <div className="au-ct-body">
                  <p className="au-ct-title">The first correction</p>
                  <p className="au-ct-desc">
                    The first major AI incidents reach the scale of regulatory consequence. A financial services firm cannot produce the audit trail required by MiFID II. A healthcare AI system fails a HIPAA audit with no technical evidence of compliance. An autonomous agent causes an incident that kills a deal, triggers a lawsuit, or ends a career. Enterprises that shipped AI without governance face the bill.
                  </p>
                  <p className="au-ct-desc" style={{ marginTop: '0.5rem' }}>
                    The question changes overnight from <em>"what can AI do?"</em> to <em>"can you prove what it did?"</em>
                  </p>
                </div>
              </div>

              <div className="au-ct-divider">↓</div>

              <div className="au-ct-row au-ct-row--highlight">
                <div className="au-ct-year au-ct-year--warn">2028</div>
                <div className="au-ct-body">
                  <p className="au-ct-title">The regulatory reckoning</p>
                  <p className="au-ct-desc">
                    EU AI Act enforcement teeth are fully active. US AI liability frameworks crystallise after the first wave of incidents. Board-level AI risk governance becomes a requirement, not a best practice. The enterprises that survive are the ones that can hand an auditor a verifiable proof chain — not a policy document and a spreadsheet.
                  </p>
                  <p className="au-ct-desc" style={{ marginTop: '0.5rem' }}>
                    The infrastructure layer that was optional yesterday is the table-stakes requirement of the correction years. Every AI system shipped without it will need to be rebuilt or retired.
                  </p>
                </div>
              </div>

              <div className="au-ct-divider">↓</div>

              <div className="au-ct-row au-ct-row--green">
                <div className="au-ct-year au-ct-year--green">ConnectorOS</div>
                <div className="au-ct-body">
                  <p className="au-ct-title">Why we are building now</p>
                  <p className="au-ct-desc">
                    Governance infrastructure takes 2–3 years to mature, adopt, and prove in production. The enterprises deploying ConnectorOS today are the ones who will have a working, audited, regulator-ready governance layer when the correction hits. The ones who wait until 2027 will be rebuilding under pressure with no time to prove it.
                  </p>
                  <p className="au-ct-desc" style={{ marginTop: '0.5rem' }}>
                    We are not building for the hype. We are building for the correction. <strong>The right time to install a kernel is before you need it.</strong>
                  </p>
                </div>
              </div>

            </div>
          </div>
        </section>

        {/* ── What we believe ──────────────────────────────────────── */}
        <section className="section">
          <div className="section__inner" style={{ maxWidth: '900px' }}>
            <p className="section-label">What we believe</p>
            <h2 className="section__title">Five things we will not compromise on.</h2>
            <div className="au-beliefs-grid">
              {BELIEFS.map(b => (
                <div key={b.title} className="au-belief-card">
                  <p className="au-belief-card__title">{b.title}</p>
                  <p className="au-belief-card__body">{b.body}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* ── Who we are building for ───────────────────────────────── */}
        <section className="section section--bordered">
          <div className="section__inner" style={{ maxWidth: '900px' }}>
            <p className="section-label">Who we're building for</p>
            <h2 className="section__title">You recognise yourself in one of these.</h2>
            <div className="au-for-grid">
              {BUILDING_FOR.map(p => (
                <div key={p.role} className="au-for-card">
                  <p className="au-for-card__role">{p.role}</p>
                  <p className="au-for-card__signal">
                    <span className="uc-label">Signal</span>
                    {p.signal}
                  </p>
                  <p className="au-for-card__value">
                    <span className="uc-label uc-label--green">What you get</span>
                    {p.value}
                  </p>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* ── Principles ───────────────────────────────────────────── */}
        <section className="section">
          <div className="section__inner" style={{ maxWidth: '900px' }}>
            <p className="section-label">How we operate</p>
            <h2 className="section__title">Six principles we enforce on ourselves.</h2>
            <div className="au-principles-grid">
              {PRINCIPLES.map(p => (
                <div key={p.num} className="au-principle-card">
                  <span className="au-principle-card__num">{p.num}</span>
                  <div>
                    <p className="au-principle-card__title">{p.title}</p>
                    <p className="au-principle-card__body">{p.body}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* ── Status ───────────────────────────────────────────────── */}
        <section className="section section--bordered">
          <div className="section__inner" style={{ maxWidth: '760px' }}>
            <p className="section-label">Where we are</p>
            <h2 className="section__title">What we provide today.</h2>
            <div className="au-status-grid">
              <div className="au-status-card au-status-card--live">
                <p className="au-status-card__label">Ships now</p>
                <ul className="au-status-list">
                  <li>A workspace for who the agent is and what it may cause</li>
                  <li>One admission for each effect, then a receipt</li>
                  <li>Cease — an operator can stop the next action</li>
                  <li>DevGuard, TraceTramp, and WitnessCtl</li>
                  <li>A self-hosted node, or a 90-minute playground</li>
                </ul>
              </div>
            </div>
            <p className="hero-vision" style={{ marginTop: '1.5rem' }}>
              We are inviting design partners who need receipts, not vibes. One workflow. One team. 30 days. Prove control before you commit.
            </p>
          </div>
        </section>

        {/* ── CTA ──────────────────────────────────────────────────── */}
        <section className="section">
          <div className="section__inner" style={{ maxWidth: '640px' }}>
            <div className="pp-cta-block" style={{ borderColor: 'var(--accent)' + '44' }}>
              <p className="pp-cta-block__eyebrow" style={{ color: 'var(--accent)' }}>
                ConnectorOS · Controlled access
              </p>
              <h2 className="pp-cta-block__title">
                Work with us.
              </h2>
              <p className="pp-cta-block__body">
                We are a small team with deep conviction about what AI infrastructure should look like. If you are an enterprise shipping AI that needs to be auditable, bounded, and defensible — we want to work with you as a design partner.
              </p>
              <ul className="pp-cta-checklist">
                <li><span style={{ color: 'var(--accent)' }}>✓</span> Design partners get direct access to the team</li>
                <li><span style={{ color: 'var(--accent)' }}>✓</span> We co-design the workflow that fits your compliance requirements</li>
                <li><span style={{ color: 'var(--accent)' }}>✓</span> 30-day pilot — one workflow, full governance, real receipts</li>
                <li><span style={{ color: 'var(--accent)' }}>✓</span> Self-hosted — your infrastructure, your data, always</li>
              </ul>
              <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
                <a href="/#interest" className="btn btn--primary">Become a design partner</a>
                <a href="/about-os" className="btn btn--ghost">How ConnectorOS works →</a>
              </div>
            </div>
          </div>
        </section>

        <Footer />

      </main>
    </>
  )
}

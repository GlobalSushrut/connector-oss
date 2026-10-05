import { Nav } from '../components/Nav'
import { PILOT_TIERS, WHY_PAY, IS_FIT, NOT_FIT, PROCESS } from '../data/getstarted'
import { playgroundUrl } from '../config'
import { useMeta } from '../hooks/useMeta'
import { Footer } from '../components/Footer'

export function GetStartedPage() {
  useMeta({
    title: 'Get Started with Connector — Try 90 minutes or apply for a pilot',
    description: 'Enter your email at try.cnktros.com. You get a private 90-minute node with one Demo agent (Isolate, Govern, Stop, Prove) and three institutions on the OS. Paid pilots are one production workflow on infrastructure you operate.',
    canonical: 'https://cnktros.com/get-started',
  })
  return (
    <>
      <Nav />
      <main>

        {/* Hero */}
        <section className="section section--hero" style={{ paddingBottom: '2.5rem' }}>
          <div className="section__inner" style={{ maxWidth: '760px' }}>
            <p className="hero-category-label">Get Started · Playground or paid pilot</p>
            <h1 className="hero-title" style={{ fontSize: 'clamp(1.8rem,4vw,2.8rem)', margin: '1rem 0 0.75rem' }}>
              Try for 90 minutes.<br />Pilot if you mean it.
            </h1>
            <p className="hero-sub">
              Your email opens a private playground on Fly.io — one Demo agent
              with Isolate, Govern, Stop, and Prove. DevGuard, TraceTramp, and
              WitnessCtl are institutions on that node, not extra agents. Up to
              ten people at once. Same email can start again and gets a new
              Demo session. A paid pilot is a node you operate.
            </p>
            <div style={{ display: 'flex', gap: '1rem', marginTop: '1.75rem', flexWrap: 'wrap' }}>
              <a href={playgroundUrl} className="btn btn--primary">Try 90 minutes</a>
              <a href="#apply" className="btn btn--ghost">Apply for a pilot</a>
            </div>
          </div>
        </section>

        <section className="section section--bordered">
          <div className="section__inner" style={{ maxWidth: '760px' }}>
            <p className="section-label">How to use the playground</p>
            <h2 className="section__title">Four steps. Then you are in the product.</h2>
            <p className="section__lead">
              The playground is a Connector node. You land on RUN with one Demo
              agent — not in DevGuard. Connector is the OS. DevGuard is an
              institution on it, not a coding-agent product.
            </p>
            <ol className="pp-steps" style={{ marginTop: '1.5rem' }}>
              <li className="pp-step">
                <div className="pp-step__num">1</div>
                <div className="pp-step__body">
                  <p className="pp-step__title">Open try.cnktros.com/trial</p>
                  <p className="pp-step__detail">Not Vercel. This is the Fly.io trial node.</p>
                </div>
              </li>
              <li className="pp-step">
                <div className="pp-step__num">2</div>
                <div className="pp-step__body">
                  <p className="pp-step__title">Enter your email</p>
                  <p className="pp-step__detail">That address owns the session. Five emails means five separate playgrounds. Nobody else sees your Demo agent or memory.</p>
                </div>
              </li>
              <li className="pp-step">
                <div className="pp-step__num">3</div>
                <div className="pp-step__body">
                  <p className="pp-step__title">Start 90 minutes</p>
                  <p className="pp-step__detail">You land on /run. One Demo agent is already there. Isolate, Govern, Stop, and Prove enqueue real Workbench orders. No LLM key required.</p>
                </div>
              </li>
              <li className="pp-step">
                <div className="pp-step__num">4</div>
                <div className="pp-step__body">
                  <p className="pp-step__title">Do the work</p>
                  <p className="pp-step__detail">Admit runs identity → PATE → ToolDispatch. Stop kills the loop and is not undo. Open DevGuard if you want a repo cage — that is a separate institution. Idle 90 minutes and it ends — same email can start again.</p>
                </div>
              </li>
            </ol>
            <figure className="diagram-figure" style={{ marginTop: '2rem' }}>
              <img
                src="/img/vendor-cut.png"
                alt="Split path: client to vendor DROP versus client to connector-platform :9091 then marked Landlock child ACCEPT"
                width={1376}
                height={768}
                loading="lazy"
              />
              <figcaption className="diagram-caption">
                Point your agent at <code>/v1</code> on the node (default :9091). BASE_URL is voluntary until the host vendor cut applies.
              </figcaption>
            </figure>
          </div>
        </section>

        {/* Fit check */}
        <section className="section section--bordered">
          <div className="section__inner" style={{ maxWidth: '820px' }}>
            <p className="section-label">Fit check</p>
            <h2 className="section__title">Are you the right candidate?</h2>
            <p className="section__lead" style={{ maxWidth: '540px' }}>
              Read both lists. Be honest with yourself. We would rather you self-select out than waste your time and ours.
            </p>
            <div className="gs-fit-grid">
              <div className="gs-fit-card gs-fit-card--yes">
                <p className="gs-fit-card__label gs-fit-card__label--yes">You are a fit if —</p>
                <ul className="gs-fit-list">
                  {IS_FIT.map(r => (
                    <li key={r}><span className="gs-fit-check gs-fit-check--yes">✓</span>{r}</li>
                  ))}
                </ul>
              </div>
              <div className="gs-fit-card gs-fit-card--no">
                <p className="gs-fit-card__label gs-fit-card__label--no">You are not a fit if —</p>
                <ul className="gs-fit-list">
                  {NOT_FIT.map(r => (
                    <li key={r}><span className="gs-fit-check gs-fit-check--no">✕</span>{r}</li>
                  ))}
                </ul>
              </div>
            </div>
          </div>
        </section>

        {/* Three tiers */}
        <section id="tiers" className="section">
          <div className="section__inner" style={{ maxWidth: '960px' }}>
            <p className="section-label">Pilot tiers</p>
            <h2 className="section__title">Three ways to work with us.</h2>
            <p className="section__lead" style={{ maxWidth: '540px' }}>
              Every tier is paid. Every tier includes direct engineering access. The scope differs — the commitment to your success does not.
            </p>
            <div className="gs-tiers-grid">
              {PILOT_TIERS.map(t => (
                <div key={t.id} className="gs-tier-card">
                  <div className="gs-tier-card__top">
                    <span className="gs-tier-badge" style={{ color: t.color, borderColor: t.color + '44', background: t.color + '12' }}>
                      {t.badge}
                    </span>
                    <span className="gs-tier-price">Paid</span>
                  </div>
                  <h3 className="gs-tier-title">{t.title}</h3>
                  <p className="gs-tier-for"><span className="uc-label">For</span>{t.forWho}</p>
                  <div className="gs-tier-divider" />
                  <p className="gs-tier-section-label">What you get</p>
                  <ul className="gs-tier-list">
                    {t.gets.map(g => (
                      <li key={g}><span style={{ color: t.color }}>✓</span> {g}</li>
                    ))}
                  </ul>
                  <div className="gs-tier-divider" />
                  <p className="gs-tier-outcome">{t.outcome}</p>
                  <p className="gs-tier-commitment">{t.commitment}</p>
                  <a href="#apply" className="btn btn--primary" style={{ marginTop: 'auto', textAlign: 'center' }}>
                    Apply for {t.badge} →
                  </a>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* Why pay */}
        <section className="section section--bordered">
          <div className="section__inner" style={{ maxWidth: '760px' }}>
            <p className="section-label">Why paid</p>
            <h2 className="section__title">Why pay to test something?</h2>
            <div className="gs-why-grid">
              {WHY_PAY.map(w => (
                <div key={w.q} className="gs-why-card">
                  <p className="gs-why-card__q">{w.q}</p>
                  <p className="gs-why-card__a">{w.a}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* Process */}
        <section className="section">
          <div className="section__inner" style={{ maxWidth: '760px' }}>
            <p className="section-label">The process</p>
            <h2 className="section__title">What happens after you apply.</h2>
            <div className="pp-steps" style={{ marginTop: '1.75rem' }}>
              {PROCESS.map(s => (
                <div key={s.num} className="pp-step">
                  <div className="pp-step__num" style={{ background: 'var(--accent)', fontFamily: 'var(--mono)', fontSize: '0.72rem' }}>
                    {s.num}
                  </div>
                  <div className="pp-step__body">
                    <p className="pp-step__title">{s.title}</p>
                    <p className="pp-step__detail">{s.detail}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* Apply CTA */}
        <section id="apply" className="section section--bordered">
          <div className="section__inner" style={{ maxWidth: '640px' }}>
            <div className="pp-cta-block" style={{ borderColor: 'rgba(62,207,142,0.3)' }}>
              <p className="pp-cta-block__eyebrow" style={{ color: 'var(--accent)' }}>
                Controlled Beta · Selected teams only
              </p>
              <h2 className="pp-cta-block__title">Apply. We'll be in touch within 48 hours.</h2>
              <p className="pp-cta-block__body">
                Fill the form — tell us your use case, compliance requirement, and which pilot tier fits. We read every submission and respond to teams that are a fit.
              </p>
              <ul className="pp-cta-checklist">
                <li><span style={{ color: 'var(--accent)' }}>✓</span> No sales call required to apply</li>
                <li><span style={{ color: 'var(--accent)' }}>✓</span> 48-hour response to every accepted submission</li>
                <li><span style={{ color: 'var(--accent)' }}>✓</span> Self-hosted — memory and journals stay on your node; vendor LLM HTTP may leave when a model is granted</li>
                <li><span style={{ color: 'var(--accent)' }}>✓</span> No lock-in — the 30-day pilot has no further obligation</li>
              </ul>
              <a href="/#interest" className="btn btn--primary">Go to application form →</a>
            </div>
          </div>
        </section>

        {/* Closing line */}
        <section className="section">
          <div className="section__inner" style={{ maxWidth: '600px', textAlign: 'center' }}>
            <p style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--text)', lineHeight: 1.4, margin: '0 0 0.5rem' }}>
              The right time to install governance is before you need it.
            </p>
            <p style={{ fontSize: '0.82rem', color: 'var(--muted)', margin: '0 0 1.5rem' }}>
              The teams who start now are the ones who have a receipt when they need it.
            </p>
            <div style={{ display: 'flex', gap: '1rem', justifyContent: 'center', flexWrap: 'wrap' }}>
              <a href="/#interest" className="btn btn--primary">Apply now</a>
              <a href="/about-us" className="btn btn--ghost">Read our thesis →</a>
            </div>
          </div>
        </section>

        <Footer />

      </main>
    </>
  )
}

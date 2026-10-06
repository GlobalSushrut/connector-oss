import { useParams, Navigate } from 'react-router-dom'
import { Nav } from '../components/Nav'
import { PLUGINS } from '../data/plugins'
import { isWorkflowReady } from '../data/workflows'
import { playgroundUrl } from '../config'
import { useMeta } from '../hooks/useMeta'
import { Footer } from '../components/Footer'

const PRODUCT_ART: Record<string, { src: string; alt: string; caption: string }> = {
  witnessctl: {
    src: '/img/hmac-chain.png',
    alt: 'HMAC-chained receipts: linked journal entries, tamper detectable, issuer HMAC not court-grade quorum',
    caption: 'Issuer HMAC. Inspectable evidence. Not court-grade quorum.',
  },
  tracetramp: {
    src: '/img/ui-agent-runtime.png',
    alt: 'Concept operator surface for agent runtime. Not a screenshot of the shipping dashboard.',
    caption: 'Concept operator surface — not the shipping UI. Reconstruct a governed path; full replay is not the product bar.',
  },
  devguard: {
    src: '/img/world-cage.png',
    alt: 'World cage: dest-pinned Landlock child, pore table default DROP',
    caption: 'Same world cage for coding agents as for Talk, MCP, HAL, and HTTP. Dest-pinned Landlock children — not Firecracker-by-default.',
  },
}

export function ProductPage() {
  const { slug } = useParams<{ slug: string }>()
  const plugin = PLUGINS.find(p => p.slug === slug)
  const ready = plugin ? isWorkflowReady(plugin.slug) : false
  useMeta({
    title: plugin ? `${plugin.name} — ${plugin.tagline} | Connector` : 'Connector Plugin',
    description: plugin ? plugin.problem.slice(0, 155) + '...' : 'An institution on the Connector OS.',
    canonical: plugin ? `https://cnktros.com/products/${plugin.slug}` : undefined,
  })
  if (!plugin || !ready) return <Navigate to="/" replace />

  return (
    <>
      <Nav />
      <main>

        {/* ── 1. Hero / positioning ──────────────────────────────────── */}
        <section className="section section--hero pp-hero" style={{ paddingBottom: '2.5rem' }}>
          <div className="section__inner" style={{ maxWidth: '760px' }}>
            <p className="hero-category-label">
              {plugin.name} — {ready ? 'ready to try' : 'on the map'}
            </p>
            <div className="pp-color-bar" style={{ background: plugin.color }} />
            <h1 className="hero-title" style={{ fontSize: 'clamp(1.8rem,4vw,2.8rem)', margin: '1rem 0 0.75rem' }}>
              {plugin.tagline}
            </h1>
            <p className="hero-sub" style={{ marginTop: '0.75rem' }}>
              {ready
                ? 'This is one of the three institutions you can try in 90 minutes. It sits on the OS — it is not the OS.'
                : 'This institution is planned. It is not in the playground today. Everything below is the intended SKU, not a download. Design partners go first.'}
            </p>
            <div style={{ display: 'flex', gap: '1rem', marginTop: '1.5rem', flexWrap: 'wrap' }}>
              {ready ? (
                <a href={playgroundUrl} className="btn btn--primary">Try 90 minutes</a>
              ) : (
                <a href="/#interest" className="btn btn--primary">Talk about this workflow</a>
              )}
              <a href="/use-cases" className="btn btn--ghost">All ten workflows →</a>
            </div>
          </div>
        </section>

        {/* ── 2. Problem statement ───────────────────────────────────── */}
        <section className="section section--bordered">
          <div className="section__inner" style={{ maxWidth: '760px' }}>
            <p className="section-label">Problem</p>
            <h2 className="section__title">Why this exists.</h2>
            <p className="pp-problem">{plugin.problem}</p>
          </div>
        </section>

        {/* ── 3. What it is + capabilities ──────────────────────────── */}
        <section className="section">
          <div className="section__inner" style={{ maxWidth: '900px' }}>
            <p className="section-label">What it is</p>
            <h2 className="section__title">{plugin.name} — defined.</h2>
            {!ready && (
              <p className="section__lead">
                Planned SKU. The copy below is the intended product, not a claim that it ships today.
              </p>
            )}
            <p className="pp-what">{plugin.what}</p>
            {PRODUCT_ART[plugin.slug] && (
              <figure className="diagram-figure">
                <img
                  src={PRODUCT_ART[plugin.slug].src}
                  alt={PRODUCT_ART[plugin.slug].alt}
                  width={1376}
                  height={768}
                  loading="lazy"
                />
                <figcaption className="diagram-caption">
                  {PRODUCT_ART[plugin.slug].caption}
                </figcaption>
              </figure>
            )}

            <div className="pp-capabilities">
              {plugin.capabilities.map(c => (
                <div key={c.title} className="pp-cap-card">
                  <div className="pp-cap-card__bar" style={{ background: plugin.color }} />
                  <div className="pp-cap-card__body">
                    <p className="pp-cap-card__title">{c.title}</p>
                    <p className="pp-cap-card__desc">{c.desc}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* ── 4. Outcomes ───────────────────────────────────────────── */}
        <section className="section section--bordered">
          <div className="section__inner" style={{ maxWidth: '760px' }}>
            <p className="section-label">Outcomes</p>
            <h2 className="section__title">What you achieve.</h2>
            <ul className="pp-outcomes">
              {plugin.outcomes.map(o => (
                <li key={o} className="pp-outcome-item">
                  <span className="pp-outcome-check" style={{ color: plugin.color }}>✓</span>
                  <span>{o}</span>
                </li>
              ))}
            </ul>
          </div>
        </section>

        {/* ── 5. Comparison checklist ───────────────────────────────── */}
        <section className="section">
          <div className="section__inner" style={{ maxWidth: '760px' }}>
            <p className="section-label">Comparison</p>
            <h2 className="section__title">{plugin.name} vs everything else.</h2>
            <div className="pp-comparison">
              <div className="pp-comparison__header">
                <span className="pp-comparison__col-head pp-comparison__col-head--feature">Feature</span>
                <span className="pp-comparison__col-head pp-comparison__col-head--us">{plugin.name}</span>
                <span className="pp-comparison__col-head pp-comparison__col-head--them">Others</span>
              </div>
              {plugin.comparison.map(row => (
                <div key={row.feature} className="pp-comparison__row">
                  <span className="pp-comparison__feature">{row.feature}</span>
                  <span className="pp-comparison__us">
                    <span className="pp-check" style={{ color: plugin.color }}>✓</span> {row.us}
                  </span>
                  <span className="pp-comparison__them">{row.them}</span>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* ── 6. How to use ─────────────────────────────────────────── */}
        <section className="section section--bordered">
          <div className="section__inner" style={{ maxWidth: '760px' }}>
            <p className="section-label">How to use</p>
            <h2 className="section__title">
              {ready ? 'Your email. Then the product.' : 'After you get the binary.'}
            </h2>
            <p className="section__lead" style={{ maxWidth: '560px' }}>
              {ready
                ? `No install. Enter your email at try.cnktros.com. ${plugin.name} is already on your private 90-minute node.`
                : `This is the intended operator path after the SKU ships. It is not in the playground today.`}
            </p>
            <div className="pp-steps">
              {plugin.howToUse.map((s, i) => (
                <div key={s.step} className="pp-step">
                  <div className="pp-step__num" style={{ background: plugin.color }}>
                    {i + 1}
                  </div>
                  <div className="pp-step__body">
                    <p className="pp-step__title">{s.step}</p>
                    <p className="pp-step__detail">{s.detail}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* ── 7. Apply / access CTA ─────────────────────────────────── */}
        <section className="section">
          <div className="section__inner" style={{ maxWidth: '640px' }}>
            <div className="pp-cta-block" style={{ borderColor: plugin.color + '44' }}>
              <p className="pp-cta-block__eyebrow" style={{ color: plugin.color }}>
                {plugin.name} · {ready ? 'Ready to try' : 'On the map'}
              </p>
              <h2 className="pp-cta-block__title">
                {ready ? 'Try it in 90 minutes, or run one workflow with us.' : 'This workflow is planned. Talk to us if it is why you would buy.'}
              </h2>
              <p className="pp-cta-block__body">
                {ready
                  ? `${plugin.name} is one of three ready institutions on the OS. Your email opens a private 90-minute node. A paid pilot is a self-hosted node on your infrastructure — one workflow, not all ten.`
                  : `${plugin.name} is not in the playground today. If this is the job you need, that is a design partnership. We will not pretend it ships.`}
              </p>
              <ul className="pp-cta-checklist">
                <li><span style={{ color: plugin.color }}>✓</span> Self-hosted — memory and journals stay on the node; vendor LLM HTTP may leave when a model is granted</li>
                {ready ? (
                  <li><span style={{ color: plugin.color }}>✓</span> Playground — your email, 90 minutes, one Demo agent plus this institution on the node</li>
                ) : (
                  <li><span style={{ color: plugin.color }}>✓</span> Planned — design partners go first</li>
                )}
                <li><span style={{ color: plugin.color }}>✓</span> Paid pilot is one workflow, not all ten</li>
                <li><span style={{ color: plugin.color }}>✓</span> We do not sell SOC 2 or court-grade as a checkbox</li>
              </ul>
              <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
                {ready ? (
                  <a href={playgroundUrl} className="btn btn--primary">Try 90 minutes</a>
                ) : (
                  <a href="/#interest" className="btn btn--primary">Talk about this workflow</a>
                )}
                <a href="/use-cases" className="btn btn--ghost">All ten workflows →</a>
              </div>
            </div>
          </div>
        </section>

        {/* ── 8. Powered by banner ──────────────────────────────────── */}
        <section className="section section--bordered">
          <div className="section__inner" style={{ maxWidth: '760px' }}>
            <div className="pp-powered-by">
              <span className="pp-powered-by__label">Powered by</span>
              <a href="/about-os" className="pp-powered-by__link">
                ConnectorOS — operating substrate for intelligence
              </a>
            </div>
            <p className="pp-powered-by__detail">{plugin.poweredBy}</p>
          </div>
        </section>

        <Footer />

      </main>
    </>
  )
}

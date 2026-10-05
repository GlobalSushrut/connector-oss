import { PilotInterestForm } from './PilotInterestForm'
import { Footer } from './Footer'

export function VisionFormSection() {
  return (
    <section id="vision" className="section">
      <div className="section__inner">
        <h2 className="section__title">A node you operate</h2>
        <p className="section__lead vision-copy">
          Self-hosted <code>connector-platform</code>. Isolate, govern, stop, prove.
          Finance, security, and ops get a named owner and a receipt — not a story.
        </p>
        <div className="status-badge card">
          <strong>3 institutions ready · 7 on the map</strong>
          <p>
            Enter your email at try.cnktros.com. You get a private 90-minute
            node. Other emails cannot see yours. Up to ten people at once.
            The other seven workflows are the plan.
          </p>
        </div>
        <h2 className="section__title section__title--small">Become a design partner</h2>
        <ul className="pill-list">
          <li>One critical workflow — not a kitchen-sink POC</li>
          <li>One team — clear owner and success metric</li>
          <li>30-day posture: prove control before you commit</li>
        </ul>
      </div>

      <div className="section section--cta-strip">
        <div className="section__inner cta-strip">
          <h2 className="cta-strip__title">Run one workflow with us.</h2>
          <p className="cta-strip__subtitle">
            See the control before you commit.
          </p>
          <ul className="cta-strip__chips" aria-label="Pilot terms">
            <li>30 days</li>
            <li>One workflow</li>
            <li>Named owner</li>
            <li>Receipts you can inspect</li>
          </ul>
          <a href="#interest" className="btn btn--primary cta-strip__btn">
            Request access
          </a>
        </div>
      </div>

      <div id="interest" className="section section--form">
        <div className="section__inner">
          <h2 className="section__title">Request access</h2>
          <p className="section__lead">
            Tell us what you&apos;re building. We read every submission.
          </p>

          <p className="form-theme-note form-theme-note--native">
            Submissions are stored directly by Connector so your team can review
            and use them later.
          </p>

          <PilotInterestForm />
          <p className="muted privacy">
            We use your email only to follow up about the pilot — no resold
            lists.
          </p>
        </div>
      </div>

      <Footer />
    </section>
  )
}

export function Footer() {
  return (
    <footer className="site-footer-main">

      {/* Community banner */}
      <div className="footer-community">
        <div className="footer-community__inner">
          <div className="footer-community__text">
            <p className="footer-community__headline">We are early. Building slow and steady.</p>
            <p className="footer-community__sub">
              ConnectorOS is a small team with deep conviction. We are not racing to scale —
              we are building infrastructure that lasts. Follow along as we build in public.
            </p>
          </div>
          <div className="footer-community__links">
            <a
              href="https://github.com/GlobalSushrut/connector-oss"
              target="_blank"
              rel="noopener noreferrer"
              className="footer-social-btn"
            >
              <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
                <path d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"/>
              </svg>
              GitHub
            </a>
            <a
              href="https://www.youtube.com/@ConnectorProto_OS"
              target="_blank"
              rel="noopener noreferrer"
              className="footer-social-btn"
            >
              <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
                <path d="M23.498 6.186a3.016 3.016 0 00-2.122-2.136C19.505 3.545 12 3.545 12 3.545s-7.505 0-9.377.505A3.017 3.017 0 00.502 6.186C0 8.07 0 12 0 12s0 3.93.502 5.814a3.016 3.016 0 002.122 2.136c1.871.505 9.376.505 9.376.505s7.505 0 9.377-.505a3.015 3.015 0 002.122-2.136C24 15.93 24 12 24 12s0-3.93-.502-5.814zM9.545 15.568V8.432L15.818 12l-6.273 3.568z"/>
              </svg>
              YouTube
            </a>
            <a
              href="https://discord.gg/SPXfDUXX"
              target="_blank"
              rel="noopener noreferrer"
              className="footer-social-btn"
            >
              <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
                <path d="M20.317 4.37a19.791 19.791 0 00-4.885-1.515.074.074 0 00-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 00-5.487 0 12.64 12.64 0 00-.617-1.25.077.077 0 00-.079-.037A19.736 19.736 0 003.677 4.37a.07.07 0 00-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 00.031.057 19.9 19.9 0 005.993 3.03.078.078 0 00.084-.028 14.09 14.09 0 001.226-1.994.076.076 0 00-.041-.106 13.107 13.107 0 01-1.872-.892.077.077 0 01-.008-.128 10.2 10.2 0 00.372-.292.074.074 0 01.077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 01.078.01c.12.098.246.198.373.292a.077.077 0 01-.006.127 12.299 12.299 0 01-1.873.892.077.077 0 00-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 00.084.028 19.839 19.839 0 006.002-3.03.077.077 0 00.032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 00-.031-.03zM8.02 15.33c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.956 2.418-2.157 2.418zm7.975 0c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.955-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.946 2.418-2.157 2.418z"/>
              </svg>
              Discord
            </a>
            <a
              href="https://www.reddit.com/r/Connector_AGOS"
              target="_blank"
              rel="noopener noreferrer"
              className="footer-social-btn"
            >
              <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
                <path d="M12 0A12 12 0 0 0 0 12a12 12 0 0 0 12 12 12 12 0 0 0 12-12A12 12 0 0 0 12 0zm5.01 4.744c.688 0 1.25.561 1.25 1.249a1.25 1.25 0 0 1-2.498.056l-2.597-.547-.8 3.747c1.824.07 3.48.632 4.674 1.488.308-.309.73-.491 1.207-.491.968 0 1.754.786 1.754 1.754 0 .716-.435 1.333-1.01 1.614a3.111 3.111 0 0 1 .042.52c0 2.694-3.13 4.87-7.004 4.87-3.874 0-7.004-2.176-7.004-4.87 0-.183.015-.366.043-.534A1.748 1.748 0 0 1 4.028 12c0-.968.786-1.754 1.754-1.754.463 0 .898.196 1.207.49 1.207-.883 2.878-1.43 4.744-1.487l.885-4.182a.342.342 0 0 1 .14-.197.35.35 0 0 1 .238-.042l2.906.617a1.214 1.214 0 0 1 1.108-.701zM9.25 12C8.561 12 8 12.562 8 13.25c0 .687.561 1.248 1.25 1.248.687 0 1.248-.561 1.248-1.249 0-.688-.561-1.249-1.249-1.249zm5.5 0c-.687 0-1.248.561-1.248 1.25 0 .687.561 1.248 1.249 1.248.688 0 1.249-.561 1.249-1.249 0-.687-.562-1.249-1.25-1.249zm-5.466 3.99a.327.327 0 0 0-.231.094.33.33 0 0 0 0 .463c.842.842 2.484.913 2.961.913.477 0 2.105-.056 2.961-.913a.361.361 0 0 0 .029-.463.33.33 0 0 0-.464 0c-.547.533-1.684.73-2.512.73-.828 0-1.979-.196-2.512-.73a.326.326 0 0 0-.232-.095z"/>
              </svg>
              Reddit
            </a>
            <a
              href="https://connectoragos.substack.com/"
              target="_blank"
              rel="noopener noreferrer"
              className="footer-social-btn"
            >
              <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
                <path d="M22.539 8.242H1.46V5.406h21.08v2.836zM1.46 10.812V24L12 18.11 22.54 24V10.812H1.46zM22.54 0H1.46v2.836h21.08V0z"/>
              </svg>
              Substack
            </a>
          </div>
        </div>
      </div>

      {/* Main footer */}
      <div className="footer-main">
        <div className="footer-main__inner">

          {/* Brand col */}
          <div className="footer-col footer-col--brand">
            <a href="/" aria-label="Connector — Home">
              <img src="/logo.png" alt="cnktros" style={{ height: '56px', width: 'auto', display: 'block', marginBottom: '0.6rem' }} />
            </a>
            <p className="footer-brand-tagline">Operating substrate for intelligence</p>
            <p className="footer-brand-desc">
              Isolate. Govern. Stop. Prove.<br />Three institutions ready. Seven planned.
            </p>
            <p className="footer-badge">
              Self-hosted · Model-agnostic · /v1 on the path in
            </p>
          </div>

          {/* Product col */}
          <div className="footer-col">
            <p className="footer-col__title">Institutions</p>
            <ul className="footer-links">
              {[
                ['DevGuard · Ready',      '/products/devguard'],
                ['TraceTramp · Ready',    '/products/tracetramp'],
                ['WitnessCtl · Ready',    '/products/witnessctl'],
                ['Conductor · Planned',     '/products/conductor'],
                ['AgentLoop · Planned',     '/products/agentloop'],
                ['LedgerLens · Planned',    '/products/ledgerlens'],
                ['AgentPassport · Planned', '/products/agentpassport'],
                ['Relay · Planned',         '/products/relay'],
                ['Engram · Planned',        '/products/engram'],
              ].map(([name, href]) => (
                <li key={href}><a href={href}>{name}</a></li>
              ))}
            </ul>
          </div>

          {/* Platform col */}
          <div className="footer-col">
            <p className="footer-col__title">Platform</p>
            <ul className="footer-links">
              <li><a href="/about-os">About OS</a></li>
              <li><a href="/use-cases">Use Cases</a></li>
              <li><a href="/custom-workflows">Custom Workflows</a></li>
              <li><a href="/developers">Developers</a></li>
              <li><a href="/get-started">Get Started</a></li>
              <li><a href="/#faq">FAQ</a></li>
            </ul>
            <p className="footer-col__title" style={{ marginTop: '1.5rem' }}>Company</p>
            <ul className="footer-links">
              <li><a href="/about-us">About Us</a></li>
              <li><a href="/about-us#thesis">Our Thesis</a></li>
              <li><a href="/#interest">Contact</a></li>
            </ul>
          </div>

          <div className="footer-col">
            <p className="footer-col__title">Workflows</p>
            <ul className="footer-links">
              <li><a href="/products/devguard">DevGuard · Ready</a></li>
              <li><a href="/products/tracetramp">TraceTramp · Ready</a></li>
              <li><a href="/products/witnessctl">WitnessCtl · Ready</a></li>
              <li><a href="/use-cases#planned">Seven more · Planned</a></li>
              <li><a href="/custom-workflows">Regulated industries · Planned</a></li>
            </ul>
            <div className="footer-trust-badges">
              <span className="footer-trust-badge">Self-hosted</span>
              <span className="footer-trust-badge">HMAC receipts</span>
              <span className="footer-trust-badge">Linux world cage</span>
            </div>
          </div>

        </div>

        {/* Bottom bar */}
        <div className="footer-bottom">
          <p className="footer-bottom__copy">
            © {new Date().getFullYear()} ConnectorOS. All rights reserved.
          </p>
          <p className="footer-bottom__note">
            We are early. Building in public.{' '}
            <a href="https://github.com/GlobalSushrut/connector-oss" target="_blank" rel="noopener noreferrer">
              Star us on GitHub →
            </a>
          </p>
        </div>
      </div>

    </footer>
  )
}

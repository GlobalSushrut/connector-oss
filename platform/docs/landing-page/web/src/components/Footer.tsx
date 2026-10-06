import { MAINTAINER } from '../data/story'

export function Footer() {
  return (
    <footer className="site-footer-main">
      <div className="footer-main">
        <div className="footer-main__inner">
          <div className="footer-col footer-col--brand">
            <a href="/" aria-label="cnktros — Home">
              <img src="/logo.png" alt="cnktros" style={{ height: '56px', width: 'auto', display: 'block', marginBottom: '0.6rem' }} />
            </a>
            <p className="footer-brand-tagline">Control the action. Keep the receipt.</p>
            <p className="footer-brand-desc">
              One admission per effect. An operator can stop the next one.
              A receipt a reviewer can inspect.
            </p>
          </div>

          <div className="footer-col">
            <p className="footer-col__title">On this site</p>
            <ul className="footer-links">
              <li><a href="/#outcomes">Outcomes</a></li>
              <li><a href="/#future">Future</a></li>
              <li><a href="/about-os">What it is</a></li>
              <li><a href="/get-started">Run it</a></li>
              <li><a href="/developers">Developers</a></li>
            </ul>
          </div>

          <div className="footer-col">
            <p className="footer-col__title">Maintained by</p>
            <ul className="footer-links">
              <li>{MAINTAINER.name}</li>
              <li><a href={`mailto:${MAINTAINER.email}`}>{MAINTAINER.email}</a></li>
              <li>
                <a href={MAINTAINER.linkedin} target="_blank" rel="noopener noreferrer">
                  LinkedIn
                </a>
              </li>
              <li>
                <a href="https://github.com/GlobalSushrut/connector-oss" target="_blank" rel="noopener noreferrer">
                  connector-oss
                </a>
              </li>
            </ul>
          </div>
        </div>

        <div className="footer-bottom">
          <p className="footer-bottom__copy">
            © {new Date().getFullYear()} Connector. Maintained by {MAINTAINER.name}.
          </p>
          <p className="footer-bottom__note">
            Outcomes above are what runs today. Future items are not claimed.
          </p>
        </div>
      </div>
    </footer>
  )
}

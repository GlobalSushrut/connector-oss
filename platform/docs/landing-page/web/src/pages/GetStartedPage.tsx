import { Nav } from '../components/Nav'
import { Footer } from '../components/Footer'
import { Maintainer } from '../components/Maintainer'
import { useMeta } from '../hooks/useMeta'

export function GetStartedPage() {
  useMeta({
    title: 'Run Connector — ./up.sh',
    description:
      'Clone connector-oss and run ./up.sh. Open http://127.0.0.1:9091/. This is not a production-ready claim.',
    canonical: 'https://cnktros.com/get-started',
  })
  return (
    <>
      <Nav />
      <main>
        <section className="section section--hero" style={{ paddingBottom: '2.5rem' }}>
          <div className="section__inner" style={{ maxWidth: '760px' }}>
            <p className="hero-category-label">Run it</p>
            <h1 className="hero-title" style={{ fontSize: 'clamp(1.8rem,4vw,2.8rem)', margin: '1rem 0 0.75rem' }}>
              One command. Then the workspace.
            </h1>
            <p className="hero-sub">
              Linux, Docker, Rust, and Node.js. The first boot downloads the
              pinned backends and starts them behind Connector. You do not
              operate those backends yourself. This boot is local. It is not
              a production-ready claim.
            </p>
            <pre className="devs-pre">{`git clone https://github.com/GlobalSushrut/connector-oss.git
cd connector-oss
./up.sh`}</pre>
            <p className="hero-sub">
              Open <a href="http://127.0.0.1:9091/">http://127.0.0.1:9091/</a> and
              choose <strong>Open on this machine</strong>. The local development
              token stays on your computer.
            </p>
            <ol className="pp-steps" style={{ marginTop: '1.5rem' }}>
              <li className="pp-step">
                <div className="pp-step__num">1</div>
                <div className="pp-step__body">
                  <p className="pp-step__title">See the governed path</p>
                  <p className="pp-step__detail">Open Run → Demo.</p>
                </div>
              </li>
              <li className="pp-step">
                <div className="pp-step__num">2</div>
                <div className="pp-step__body">
                  <p className="pp-step__title">Bring an agent you already have</p>
                  <p className="pp-step__detail">Use Bring your agent. Point an OpenAI-compatible client at http://127.0.0.1:9091/v1.</p>
                </div>
              </li>
              <li className="pp-step">
                <div className="pp-step__num">3</div>
                <div className="pp-step__body">
                  <p className="pp-step__title">Decide, stop, inspect</p>
                  <p className="pp-step__detail">Approve holds a person must decide. Fix holds a runtime pause. Watch shows the decision and the receipt. Cease stops the next admission.</p>
                </div>
              </li>
            </ol>
            <div style={{ display: 'flex', gap: '1rem', marginTop: '1.75rem', flexWrap: 'wrap' }}>
              <a href="https://github.com/GlobalSushrut/connector-oss" className="btn btn--primary">
                Clone the source
              </a>
              <a href="/#outcomes" className="btn btn--ghost">What you get</a>
              <a href="/#future" className="btn btn--ghost">What is next</a>
            </div>
          </div>
        </section>
        <Maintainer />
      </main>
      <Footer />
    </>
  )
}

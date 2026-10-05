export function SolutionSection() {
  return (
    <section id="solution" className="section section--bordered">
      <div className="section__inner">
        <p className="section-label">Solution</p>
        <h2 className="solution-title">Isolate. Govern. Stop. Prove.</h2>
        <p className="solution-subhead">
          A self-hosted OS between your agents and production. Keep your
          stack. We sit on the path in.
        </p>

        <div className="pillar-grid">
          <article className="card card--pillar">
            <h3 className="card--pillar__title">Isolate</h3>
            <p>
              World addresses are granted. Dials run in dest-pinned Landlock
              children. Ungranted destinations fail closed.
            </p>
          </article>
          <article className="card card--pillar">
            <h3 className="card--pillar__title">Govern</h3>
            <p>
              Policy and tool access evaluated at runtime. Violations are
              blocked, not flagged after the fact.
            </p>
          </article>
          <article className="card card--pillar">
            <h3 className="card--pillar__title">Stop</h3>
            <p>
              Cut grants, freeze the session, kill the loop. Stop is not undo.
              World effects that already happened stay happened.
            </p>
          </article>
          <article className="card card--pillar">
            <h3 className="card--pillar__title">Prove</h3>
            <p>
              Hash-chained receipts for admitted actions. A reviewer can
              inspect the chain. This is evidence, not a SOC 2 certificate.
            </p>
          </article>
        </div>

        <ul className="value-props" aria-label="Outcomes">
          <li>Inspect and admit effects before they run</li>
          <li>Enforce budget posture and policy at runtime</li>
          <li>HMAC-chained receipts a reviewer can inspect</li>
        </ul>

        <figure className="diagram-figure diagram-figure--story">
          <img
            src="/img/os-stack.png"
            alt="Connector stack: substrate, connector-platform kernel, three institutions on the OS, operator control plane"
            width={1376}
            height={768}
            loading="lazy"
          />
          <figcaption className="diagram-caption">
            Institutions sit on the OS. They are not the OS.
          </figcaption>
        </figure>

        <p className="operators-note">Operators: trace, explain, prove — from the shell or API.</p>
        <div className="cli-block card" aria-label="Example CLI commands">
          <pre>
            <code>{`connectorctl trace agent 009
connectorctl explain decision dec_xxx
connectorctl prove agent 009`}</code>
          </pre>
        </div>
      </div>
    </section>
  )
}

export function ArchSection() {
  return (
    <section id="architecture" className="section">
      <div className="section__inner">
        <h2 className="section__title">How it works</h2>
        <p className="section__lead">
          Under the hood, the same story: isolate world dials, govern every
          admitted effect, record an HMAC-chained receipt — mapped here to
          nine rings and the world cage.
        </p>
        <figure className="diagram-figure">
          <img
            src="/img/nine-rings.png"
            alt="Nine enforcement rings. Ring 7 is tool and world: grants, dest-pinned Landlock child, default DROP."
            width={1376}
            height={768}
            loading="lazy"
          />
          <figcaption className="diagram-caption">
            Every request passes every ring. Fail closed. Ring 7 is the world cage, not Firecracker-by-default.
          </figcaption>
        </figure>
        <figure className="diagram-figure">
          <img
            src="/img/world-cage.png"
            alt="World cage: connector-platform parent admits, Landlock child dials one dest, pore table default DROP"
            width={1376}
            height={768}
            loading="lazy"
          />
          <figcaption className="diagram-caption">
            Pore table default DROP. Dest-pinned Landlock child. Empty dest is DROP.
          </figcaption>
        </figure>
        <div className="arch-micro card">
          <p>
            <strong>Task</strong> — intent enters with context.
          </p>
          <p>
            <strong>Connector</strong> — runtime mediates execution.
          </p>
          <p>
            <strong>Policy</strong> — allow, deny, or scope actions.
          </p>
          <p>
            <strong>Receipt</strong> — verifiable record per step.
          </p>
        </div>
      </div>
    </section>
  )
}

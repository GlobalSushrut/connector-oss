export function HeroSection() {
  return (
    <section id="hero" className="cinematic">
      <div className="cinematic__inner">
        <div className="cinematic__copy">
          <p className="cinematic__kicker">cnktros</p>
          <h1 className="cinematic__h1">
            Control the
            <br />
            action.
            <br />
            Keep the
            <br />
            receipt.
          </h1>
          <p className="cinematic__line">
            Connector decides whether this agent may take this action, in this
            situation, right now — and an operator can stop the next one.
          </p>
          <div className="cinematic__actions">
            <a href="#outcomes" className="btn btn--primary btn--xl">
              What you get
            </a>
            <a href="#future" className="btn btn--ghost btn--xl">
              What is next
            </a>
          </div>
        </div>

        <figure className="cinematic__shot">
          <img
            src="/connector-os-architecture.svg"
            alt="Connector OS. One admission, runtime enforcement, a receipt, and Cease. agentgateway is still a target."
            width={1376}
            height={997}
          />
          <figcaption>
            One effect, one admission, one receipt. agentgateway forwarding is not proven. This is not a production claim.
          </figcaption>
        </figure>
      </div>
    </section>
  )
}

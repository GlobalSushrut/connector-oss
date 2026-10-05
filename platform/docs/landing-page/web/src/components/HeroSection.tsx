import { playgroundUrl } from '../config'

export function HeroSection() {
  return (
    <section id="hero" className="cinematic">
      <div className="cinematic__inner">
        <div className="cinematic__copy">
          <p className="cinematic__kicker">The OS under intelligence</p>
          <h1 className="cinematic__h1">
            Isolate.
            <br />
            Govern.
            <br />
            Stop.
            <br />
            Prove.
          </h1>
          <p className="cinematic__line">
            One self-hosted node. Agents keep their stack.
            You admit the world — or you don’t.
          </p>
          <div className="cinematic__actions">
            <a href={playgroundUrl} className="btn btn--primary btn--xl">
              Try 90 minutes
            </a>
            <a href="#ready" className="btn btn--ghost btn--xl">
              Three ready now
            </a>
          </div>
        </div>

        <figure className="cinematic__shot">
          <img
            src="/img/ui-controlled-world.png"
            alt="Concept operator surface for a controlled world — not the shipping dashboard"
            width={1376}
            height={768}
          />
          <figcaption>
            Concept operator surface — not the shipping UI. Isolation today is dest-pinned Landlock, not Firecracker-by-default.
          </figcaption>
        </figure>
      </div>
    </section>
  )
}

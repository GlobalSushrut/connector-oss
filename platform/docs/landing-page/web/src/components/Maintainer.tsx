import { MAINTAINER } from '../data/story'

export function Maintainer() {
  return (
    <section id="maintainer" className="section section--bordered">
      <div className="section__inner maintainer">
        <p className="section-label">Maintainer</p>
        <h2 className="section__title">Maintained by {MAINTAINER.name}</h2>
        <p className="section__lead">
          There is no application form. Write if you want to talk about what
          ships today, or about the limits listed under Future.
        </p>
        <ul className="maintainer__list">
          <li>
            <span>Email</span>
            <a href={`mailto:${MAINTAINER.email}`}>{MAINTAINER.email}</a>
          </li>
          <li>
            <span>LinkedIn</span>
            <a href={MAINTAINER.linkedin} target="_blank" rel="noopener noreferrer">
              {MAINTAINER.linkedinLabel}
            </a>
          </li>
        </ul>
      </div>
    </section>
  )
}

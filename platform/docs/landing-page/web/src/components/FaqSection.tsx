import { useState } from 'react'
import { FAQ, FAQ_CATEGORIES } from '../data/faq'

export function FaqSection() {
  const [activeCategory, setActiveCategory] = useState('General')
  const [openIndex, setOpenIndex] = useState<number | null>(0)

  const filtered = FAQ.filter(f => f.category === activeCategory)

  return (
    <section id="faq" className="section section--bordered">
      <div className="section__inner" style={{ maxWidth: '820px' }}>
        <p className="section-label">FAQ</p>
        <h2 className="section__title">Straight answers.</h2>
        <p className="section__lead" style={{ maxWidth: '540px' }}>
          Three institutions ready. Seven planned. Evidence, not a certificate.
        </p>

        {/* Category tabs */}
        <div className="faq-tabs" role="tablist">
          {FAQ_CATEGORIES.map(cat => (
            <button
              key={cat}
              role="tab"
              aria-selected={activeCategory === cat}
              className={`faq-tab${activeCategory === cat ? ' faq-tab--active' : ''}`}
              onClick={() => { setActiveCategory(cat); setOpenIndex(0) }}
            >
              {cat}
            </button>
          ))}
        </div>

        {/* Accordion */}
        <div className="faq-list">
          {filtered.map((item, i) => (
            <div
              key={item.q}
              className={`faq-item${openIndex === i ? ' faq-item--open' : ''}`}
            >
              <button
                className="faq-item__q"
                onClick={() => setOpenIndex(openIndex === i ? null : i)}
                aria-expanded={openIndex === i}
              >
                <span>{item.q}</span>
                <span className="faq-item__chevron" aria-hidden="true">
                  {openIndex === i ? '−' : '+'}
                </span>
              </button>
              {openIndex === i && (
                <div className="faq-item__a">
                  <p>{item.a}</p>
                </div>
              )}
            </div>
          ))}
        </div>

        <p className="faq-footer-note">
          More questions?{' '}
          <a href="/#interest">Reach out through the pilot form</a> — we respond to every submission.
        </p>
      </div>
    </section>
  )
}

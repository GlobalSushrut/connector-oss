import { useState, useEffect } from 'react'

const LINKS = [
  { href: '/#outcomes', label: 'Outcomes' },
  { href: '/#future', label: 'Future' },
  { href: '/about-os', label: 'What it is' },
  { href: '/get-started', label: 'Run it' },
] as const

export function Nav() {
  const [drawerOpen, setDrawerOpen] = useState(false)

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') setDrawerOpen(false)
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [])

  return (
    <>
      <header className="site-nav">
        <a href="/" className="site-nav__brand" aria-label="cnktros — Home">
          <img src="/logo.png" alt="cnktros" width={180} height={48} />
        </a>

        <nav aria-label="Site navigation">
          <ul className="site-nav__links">
            {LINKS.map(l => (
              <li key={l.href}>
                <a href={l.href}>{l.label}</a>
              </li>
            ))}
          </ul>
        </nav>

        <a
          href="https://github.com/GlobalSushrut/connector-oss"
          className="site-nav__cta btn btn--primary"
        >
          Source
        </a>

        <button
          className="site-nav__hamburger"
          aria-label={drawerOpen ? 'Close menu' : 'Open menu'}
          aria-expanded={drawerOpen}
          onClick={() => setDrawerOpen(o => !o)}
        >
          <span />
          <span />
          <span />
        </button>
      </header>

      <div className={`site-nav__drawer ${drawerOpen ? 'site-nav__drawer--open' : ''}`} aria-hidden={!drawerOpen}>
        {LINKS.map(l => (
          <a key={l.href} href={l.href} className="drawer-link" onClick={() => setDrawerOpen(false)}>
            {l.label}
          </a>
        ))}
        <a href="/#maintainer" className="drawer-link" onClick={() => setDrawerOpen(false)}>
          Maintainer
        </a>
        <a
          href="https://github.com/GlobalSushrut/connector-oss"
          className="btn btn--primary"
          style={{ marginTop: '1rem', textAlign: 'center' }}
          onClick={() => setDrawerOpen(false)}
        >
          Source
        </a>
      </div>
    </>
  )
}

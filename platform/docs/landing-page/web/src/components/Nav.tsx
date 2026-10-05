import { useState, useEffect, useRef } from 'react'
import { playgroundUrl, portalSignupUrl } from '../config'
import { plugins } from '../catalog'
import { isWorkflowReady } from '../data/workflows'

// Megamenu rows are derived from the canonical product catalog
// (`platform/products/catalog.json`). The dashboard sidebar and the
// platform server consume the same file — see `catalog.ts` for the
// loader and `services/catalog.rs` server-side.
const PLUGINS = plugins.map(p => ({
  slug: p.slug,
  name: p.name,
  desc: p.short_desc,
}))

export function Nav() {
  const [menuOpen, setMenuOpen]       = useState(false)
  const [drawerOpen, setDrawerOpen]   = useState(false)
  const dropdownRef                   = useRef<HTMLLIElement>(null)

  // Close megamenu on outside click
  useEffect(() => {
    function onPointerDown(e: PointerEvent) {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) {
        setMenuOpen(false)
      }
    }
    document.addEventListener('pointerdown', onPointerDown)
    return () => document.removeEventListener('pointerdown', onPointerDown)
  }, [])

  // Close drawer on Escape
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') { setMenuOpen(false); setDrawerOpen(false) }
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [])

  return (
    <>
      <header className="site-nav">
        <a href="/" className="site-nav__brand" aria-label="Connector — Home">
          <img src="/logo.png" alt="Connector" width={180} height={48} />
        </a>

        {/* Desktop links */}
        <nav aria-label="Site navigation">
          <ul className="site-nav__links">
            {/* Products megamenu */}
            <li ref={dropdownRef} className={`nav-dropdown ${menuOpen ? 'nav-dropdown--open' : ''}`}>
              <button
                className="nav-dropdown__trigger"
                aria-expanded={menuOpen}
                aria-haspopup="true"
                onClick={() => setMenuOpen(o => !o)}
              >
                Products
                <svg className="nav-dropdown__chevron" width="12" height="8" viewBox="0 0 12 8" fill="none" aria-hidden="true">
                  <path d="M1 1l5 5 5-5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
                </svg>
              </button>
              <div className="nav-dropdown__menu" role="menu">
                <div className="nav-dropdown__grid">
                  {PLUGINS.map(p => (
                    <a
                      key={p.slug}
                      href={`/products/${p.slug}`}
                      className="nav-plugin-link"
                      role="menuitem"
                      onClick={() => setMenuOpen(false)}
                    >
                      <span className="nav-plugin-link__name">
                        {p.name}
                        {!isWorkflowReady(p.slug) && (
                          <span className="wf-badge wf-badge--soon" style={{ marginLeft: '0.4rem' }}>Planned</span>
                        )}
                      </span>
                      <span className="nav-plugin-link__desc">{p.desc}</span>
                    </a>
                  ))}
                </div>
                <div className="nav-dropdown__footer">
                  <a href="/use-cases">Three ready · seven planned →</a>
                  <a href="/about-os">About ConnectorOS</a>
                </div>
              </div>
            </li>

            <li><a href="/use-cases">Use Cases</a></li>
            <li><a href="/about-os">About OS</a></li>
            <li><a href="/blog">Blog</a></li>
            <li><a href="/about-us">About Us</a></li>
            <li><a href="/developers">Developers</a></li>
            <li><a href="/get-started">Get Started</a></li>
          </ul>
        </nav>

        <a href={playgroundUrl} className="site-nav__cta btn btn--ghost" style={{ marginRight: '0.5rem' }}>
          Try Me
        </a>
        <a href={portalSignupUrl} className="site-nav__cta btn btn--primary">
          Dive In
        </a>

        {/* Mobile hamburger */}
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

      {/* Mobile drawer */}
      <div className={`site-nav__drawer ${drawerOpen ? 'site-nav__drawer--open' : ''}`} aria-hidden={!drawerOpen}>
        <p className="drawer-section-title">Products</p>
        {PLUGINS.map(p => (
          <a key={p.slug} href={`/products/${p.slug}`} className="drawer-link" onClick={() => setDrawerOpen(false)}>
            {p.name}{!isWorkflowReady(p.slug) ? ' · Planned' : ' · Ready'} — {p.desc}
          </a>
        ))}
        <a href="/use-cases" className="drawer-link" onClick={() => setDrawerOpen(false)}>Three ready · seven planned →</a>

        <p className="drawer-section-title">Navigate</p>
        <a href="/use-cases"     className="drawer-link" onClick={() => setDrawerOpen(false)}>Use Cases</a>
        <a href="/about-os"      className="drawer-link" onClick={() => setDrawerOpen(false)}>About OS</a>
        <a href="/blog"          className="drawer-link" onClick={() => setDrawerOpen(false)}>Blog</a>
        <a href="/developers"    className="drawer-link" onClick={() => setDrawerOpen(false)}>Developers</a>
        <a href="/get-started"   className="drawer-link" onClick={() => setDrawerOpen(false)}>Get Started</a>
        <a href="/about-us"      className="drawer-link" onClick={() => setDrawerOpen(false)}>About Us</a>
        <a href="/#interest"     className="drawer-link" onClick={() => setDrawerOpen(false)}>Contact</a>

        <div style={{ display: 'flex', gap: '0.5rem', marginTop: '1rem' }}>
          <a href={playgroundUrl}  className="btn btn--ghost" style={{ flex: 1, textAlign: 'center' }} onClick={() => setDrawerOpen(false)}>
            Try Me
          </a>
          <a href={portalSignupUrl} className="btn btn--primary" style={{ flex: 1, textAlign: 'center' }} onClick={() => setDrawerOpen(false)}>
            Dive In
          </a>
        </div>
      </div>
    </>
  )
}

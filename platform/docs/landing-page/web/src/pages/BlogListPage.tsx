import { useState } from 'react'
import { Nav } from '../components/Nav'
import { BLOG_POSTS, BLOG_CATEGORIES, type BlogPost } from '../data/blogs'
import { useMeta } from '../hooks/useMeta'
import { Footer } from '../components/Footer'

const PREDICTION_POSTS = BLOG_POSTS.filter(p => p.date.includes('Forecast'))
const CURRENT_POSTS = BLOG_POSTS.filter(p => !p.date.includes('Forecast'))

function BlogCard({ post }: { post: BlogPost }) {
  return (
    <article className="blog-card">
      <div className="blog-card__meta">
        <span className="blog-card__category" style={{ color: post.color }}>
          {post.category}
        </span>
        <span className="blog-card__dot">·</span>
        <span className="blog-card__date">{post.date}</span>
        <span className="blog-card__dot">·</span>
        <span className="blog-card__read-time">{post.readTime}</span>
      </div>
      <h2 className="blog-card__title">
        <a href={`/blog/${post.slug}`}>{post.title}</a>
      </h2>
      <p className="blog-card__subtitle">{post.subtitle}</p>
      <p className="blog-card__excerpt">{post.problem.headline}</p>
      <div className="blog-card__footer">
        <a href={`/blog/${post.slug}`} className="blog-card__link" style={{ color: post.color }}>
          Read analysis →
        </a>
        <div className="blog-card__plugins">
          {post.relatedPlugins.slice(0, 3).map((plugin, i) => (
            <span key={plugin} className="blog-card__plugin-tag">
              {plugin}
              {i < Math.min(post.relatedPlugins.length, 3) - 1 && post.relatedPlugins.length > 1 && (
                <span className="blog-card__plugin-sep">·</span>
              )}
            </span>
          ))}
        </div>
      </div>
    </article>
  )
}

export function BlogListPage() {
  useMeta({
    title: 'The Signal — AI Agent Governance & Security Analysis | Connector',
    description: 'Deep analysis on AI agent security, compliance, and market signals. Covering EU AI Act, NIST standards, MCP security, agentic AI predictions for 2026–2028.',
    canonical: 'https://cnktros.com/blog',
  })
  const [activeCategory, setActiveCategory] = useState<string>('all')
  const [activeTab, setActiveTab] = useState<'current' | 'predictions'>('current')
  
  const sourcePosts = activeTab === 'predictions' ? PREDICTION_POSTS : CURRENT_POSTS
  const filteredPosts = activeCategory === 'all' 
    ? sourcePosts 
    : sourcePosts.filter(p => p.category === activeCategory)

  return (
    <>
      <Nav />
      <main>
        {/* Hero Section */}
        <section className="section section--hero" style={{ paddingBottom: '2rem' }}>
          <div className="section__inner" style={{ maxWidth: '800px' }}>
            <p className="hero-category-label">Market Intelligence · Security Research · Compliance Analysis</p>
            <h1 className="hero-title" style={{ fontSize: 'clamp(1.8rem, 4vw, 2.6rem)' }}>
              The Signal
            </h1>
            <p className="hero-subtitle">
              Essays on the problem space — incidents, standards, and why an OS
              under agents matters. They are analysis, not a product certification.
              Three institutions are ready today. Seven are planned.
            </p>
            <p className="hero-sub" style={{ marginTop: '1rem' }}>
              If an essay names SOC 2, HIPAA, or a plugin that is not DevGuard,
              TraceTramp, or WitnessCtl, read it as the job to be done — not as
              a claim that we ship that SKU today.
            </p>
          </div>
        </section>

        {/* Tab Navigation: Current Signals vs Predictions */}
        <section className="section" style={{ padding: '0 1.25rem', borderBottom: '1px solid var(--border)' }}>
          <div className="section__inner" style={{ maxWidth: '1100px' }}>
            <div className="blog-tabs">
              <button
                className={`blog-tabs__btn ${activeTab === 'current' ? 'blog-tabs__btn--active' : ''}`}
                onClick={() => { setActiveTab('current'); setActiveCategory('all') }}
              >
                <span className="blog-tabs__label">Current Signals</span>
                <span className="blog-tabs__count">{CURRENT_POSTS.length}</span>
              </button>
              <button
                className={`blog-tabs__btn ${activeTab === 'predictions' ? 'blog-tabs__btn--active' : ''}`}
                onClick={() => { setActiveTab('predictions'); setActiveCategory('all') }}
              >
                <span className="blog-tabs__label">Predictions 2026–2028</span>
                <span className="blog-tabs__count">{PREDICTION_POSTS.length}</span>
              </button>
            </div>
          </div>
        </section>

        {/* Category Filter */}
        <section className="section" style={{ padding: '1rem 1.25rem', borderBottom: '1px solid var(--border)' }}>
          <div className="section__inner" style={{ maxWidth: '1100px' }}>
            <div className="blog-filter">
              {BLOG_CATEGORIES.map(cat => (
                <button
                  key={cat.id}
                  className={`blog-filter__btn ${activeCategory === cat.id ? 'blog-filter__btn--active' : ''}`}
                  onClick={() => setActiveCategory(cat.id)}
                >
                  {cat.name}
                </button>
              ))}
            </div>
          </div>
        </section>

        {/* Blog Grid */}
        <section className="section">
          <div className="section__inner" style={{ maxWidth: '1100px' }}>
            <div className="blog-grid">
              {filteredPosts.map(post => (
                <BlogCard key={post.slug} post={post} />
              ))}
            </div>
            {filteredPosts.length === 0 && (
              <p style={{ color: 'var(--muted)', textAlign: 'center', padding: '2rem' }}>
                No posts in this category. Try a different filter.
              </p>
            )}
          </div>
        </section>

        {/* Predictions Overview Section - only shown on predictions tab */}
        {activeTab === 'predictions' && (
          <section className="section section--bordered">
            <div className="section__inner" style={{ maxWidth: '900px' }}>
              <p className="section-label" style={{ color: '#ef4444' }}>Market Forecast 2026–2028</p>
              <h2 className="section__title">The Predictions Dashboard</h2>
              <p className="section__body" style={{ marginBottom: '2rem' }}>
                Research-backed forecasts from Gartner, IDC, Deloitte, McKinsey, and industry analysts 
                showing where the market is heading—and where Connector fits in each scenario.
              </p>

              <div className="predictions-grid">
                <div className="prediction-card">
                  <span className="prediction-card__year">2026</span>
                  <h3 className="prediction-card__title">The Governance Inflection Point</h3>
                  <ul className="prediction-card__list">
                    <li><strong>40%</strong> of agentic AI projects canceled (Gartner)</li>
                    <li><strong>40%</strong> of enterprise apps feature task-specific agents (Gartner)</li>
                    <li>AI governance market reaches <strong>$0.61B</strong> (Research and Markets)</li>
                    <li>EU AI Act prohibitions enforceable since Feb 2025</li>
                    <li>AI security market: <strong>$24.3B</strong> and growing at 21.9% CAGR</li>
                  </ul>
                </div>

                <div className="prediction-card">
                  <span className="prediction-card__year">2027</span>
                  <h3 className="prediction-card__title">The Compliance Deadline Year</h3>
                  <ul className="prediction-card__list">
                    <li><strong>86%</strong> of organizations deploy AI agents (OneReach.ai)</li>
                    <li>AI-enabled fraud losses reach <strong>$40B</strong> in US (Deloitte)</li>
                    <li><strong>35%</strong> of countries locked into region-specific AI (Gartner)</li>
                    <li>Task-specific models used <strong>3x</strong> more than LLMs (Gartner)</li>
                    <li>HITL oversight becomes <strong>mandatory</strong> for high-risk AI (EU AI Act)</li>
                  </ul>
                </div>

                <div className="prediction-card">
                  <span className="prediction-card__year">2028</span>
                  <h3 className="prediction-card__title">The Agent Economy Arrives</h3>
                  <ul className="prediction-card__list">
                    <li><strong>$15T</strong> B2B spend through agent exchanges (Gartner)</li>
                    <li><strong>15%</strong> of work decisions made autonomously (Gartner)</li>
                    <li><strong>33%</strong> of enterprise software includes agentic AI (Gartner)</li>
                    <li><strong>80%</strong> of governments deploy AI agents (Gartner)</li>
                    <li>AI governance market approaches <strong>$1B</strong> (Gartner)</li>
                  </ul>
                </div>
              </div>

              <div className="predictions-connector-fit" style={{ marginTop: '2rem' }}>
                <h3 className="prediction-card__title" style={{ marginBottom: '1rem' }}>
                  Where Connector Fits in Every Prediction
                </h3>
                <div className="predictions-fit-grid">
                  <div className="predictions-fit-item">
                    <span className="predictions-fit-item__icon" style={{ color: '#ef4444' }}>⚠</span>
                    <div>
                      <strong>Threat:</strong> 40% project cancellation → <strong>Connector:</strong> identity, admission, isolation, memory, audit — designed to address those failure modes, not a claim they become impossible
                    </div>
                  </div>
                  <div className="predictions-fit-item">
                    <span className="predictions-fit-item__icon" style={{ color: '#0ea5e9' }}>💰</span>
                    <div>
                      <strong>Opportunity:</strong> $15T agent commerce → <strong>Connector:</strong> Trust infrastructure for agent transactions
                    </div>
                  </div>
                  <div className="predictions-fit-item">
                    <span className="predictions-fit-item__icon" style={{ color: '#f59e0b' }}>📋</span>
                    <div>
                      <strong>Compliance:</strong> $1B governance market → <strong>Connector:</strong> HMAC receipts a reviewer can inspect; framework mapping is a design-partner path
                    </div>
                  </div>
                  <div className="predictions-fit-item">
                    <span className="predictions-fit-item__icon" style={{ color: '#dc2626' }}>🔒</span>
                    <div>
                      <strong>Security:</strong> $133.8B AI security market → <strong>Connector:</strong> Pre-execution governance at machine speed
                    </div>
                  </div>
                  <div className="predictions-fit-item">
                    <span className="predictions-fit-item__icon" style={{ color: '#7c3aed' }}>🎭</span>
                    <div>
                      <strong>Threat:</strong> $40B deepfake fraud → <strong>Connector:</strong> identity at boot; AgentPassport DID packaging is planned
                    </div>
                  </div>
                  <div className="predictions-fit-item">
                    <span className="predictions-fit-item__icon" style={{ color: '#8b5cf6' }}>🧠</span>
                    <div>
                      <strong>Opportunity:</strong> 15% autonomous decisions → <strong>Connector:</strong> Decision governance with audit trails
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </section>
        )}

        {/* Key Insights Summary - only shown on current tab */}
        {activeTab === 'current' && (
          <section className="section section--bordered">
            <div className="section__inner" style={{ maxWidth: '800px' }}>
              <p className="section-label">Market Assessment</p>
              <h2 className="section__title">Five Strategic Conclusions</h2>
              
              <div className="blog-insights">
                <div className="blog-insight">
                  <span className="blog-insight__num">01</span>
                  <div className="blog-insight__content">
                    <h3>Timing is better than it looked a month ago</h3>
                    <p>Between the Vercel incident, MCP advisory, NIST initiative, and EU AI Act enforcement, the market has more concrete reasons to buy governance than ever before.</p>
                  </div>
                </div>
                
                <div className="blog-insight">
                  <span className="blog-insight__num">02</span>
                  <div className="blog-insight__content">
                    <h3>The wedge is "governed execution + proof"</h3>
                    <p>Security alone is crowded. The gap is provability—who can prove what happened, why it was allowed, what was denied, and what policy version applied.</p>
                  </div>
                </div>
                
                <div className="blog-insight">
                  <span className="blog-insight__num">03</span>
                  <div className="blog-insight__content">
                    <h3>Protocols spread faster than controls</h3>
                    <p>MCP and A2A ecosystems are expanding, but control surfaces remain immature. Connector stays protocol-compatible while being explicitly protocol-skeptical.</p>
                  </div>
                </div>
                
                <div className="blog-insight">
                  <span className="blog-insight__num">04</span>
                  <div className="blog-insight__content">
                    <h3>Buyer language is shifting</h3>
                    <p>Microsoft's Zero Trust for AI, identity governance, and observability narratives validate Connector's positioning. Sales should speak in these terms.</p>
                  </div>
                </div>
                
                <div className="blog-insight">
                  <span className="blog-insight__num">05</span>
                  <div className="blog-insight__content">
                    <h3>August 2, 2026 is the critical deadline</h3>
                    <p>EU AI Act enforcement creates procurement pressure worldwide. Organizations need evidence systems operational before that date.</p>
                  </div>
                </div>
              </div>
            </div>
          </section>
        )}

        {/* CTA Section */}
        <section className="section">
          <div className="section__inner" style={{ maxWidth: '640px', textAlign: 'center' }}>
            <div className="pp-cta-block">
              <p className="pp-cta-block__eyebrow" style={{ color: 'var(--accent)' }}>
                Governed AI Execution
              </p>
              <h2 className="pp-cta-block__title">
                Build on the validated thesis.
              </h2>
              <p className="pp-cta-block__body">
                The market is bending toward governed agent execution from five directions: 
                security failures, standards formation, regulatory deadlines, platform evolution, 
                and enterprise demand. Connector is the infrastructure for this transition.
              </p>
              <div style={{ display: 'flex', gap: '1rem', justifyContent: 'center', flexWrap: 'wrap' }}>
                <a href="/#interest" className="btn btn--primary">Apply for access</a>
                <a href="/about-os" className="btn btn--ghost">About ConnectorOS →</a>
              </div>
            </div>
          </div>
        </section>

        <Footer />
      </main>
    </>
  )
}

import { useParams, Navigate } from 'react-router-dom'
import { Nav } from '../components/Nav'
import { getBlogBySlug, BLOG_POSTS, type BlogPost } from '../data/blogs'
import { useMeta } from '../hooks/useMeta'
import { Footer } from '../components/Footer'

function RelatedBlogCard({ post }: { post: BlogPost }) {
  return (
    <a href={`/blog/${post.slug}`} className="blog-related-card">
      <span className="blog-related-card__category" style={{ color: post.color }}>
        {post.category}
      </span>
      <h4 className="blog-related-card__title">{post.title}</h4>
      <p className="blog-related-card__excerpt">{post.problem.headline.slice(0, 100)}...</p>
    </a>
  )
}

export function BlogPostPage() {
  const { slug } = useParams<{ slug: string }>()
  const post = getBlogBySlug(slug || '')
  useMeta({
    title: post ? `${post.title} | Connector Blog` : 'Connector Blog',
    description: post ? post.subtitle : 'AI agent governance analysis and market signals.',
    canonical: post ? `https://cnktros.com/blog/${post.slug}` : undefined,
  })
  if (!post) return <Navigate to="/blog" replace />
  
  const relatedPosts = BLOG_POSTS
    .filter(p => p.slug !== post.slug && p.category === post.category)
    .slice(0, 2)

  return (
    <>
      <Nav />
      <main>
        {/* Hero / Header */}
        <section className="section section--hero blog-post-hero">
          <div className="section__inner" style={{ maxWidth: '800px' }}>
            <div className="blog-post-hero__meta">
              <span className="blog-post-hero__category" style={{ 
                color: post.color,
                background: `${post.color}15`,
                padding: '0.25rem 0.75rem',
                borderRadius: '4px',
                fontSize: '0.75rem',
                fontWeight: 600,
                textTransform: 'uppercase',
                letterSpacing: '0.05em'
              }}>
                {post.category}
              </span>
              <span className="blog-post-hero__dot">·</span>
              <span className="blog-post-hero__date">{post.date}</span>
              <span className="blog-post-hero__dot">·</span>
              <span className="blog-post-hero__read-time">{post.readTime} read</span>
            </div>
            
            <h1 className="blog-post-hero__title">{post.title}</h1>
            <p className="blog-post-hero__subtitle">{post.subtitle}</p>
            <p className="hero-sub" style={{ marginTop: '1rem' }}>
              This essay is analysis of the problem. It is not a claim that Connector
              is certified, or that every named workflow ships today. Ready now:
              DevGuard, TraceTramp, WitnessCtl.
            </p>
            
            <div className="blog-post-hero__accent-bar" style={{ background: post.color }} />
          </div>
        </section>

        {/* Problem Section */}
        <section className="section">
          <div className="section__inner" style={{ maxWidth: '720px' }}>
            <p className="section-label" style={{ color: post.color }}>The Problem</p>
            <h2 className="blog-post__section-title">{post.problem.headline}</h2>
            <div className="blog-post__body">
              <p>{post.problem.technical}</p>
            </div>
          </div>
        </section>

        {/* Solution Overview */}
        <section className="section section--bordered">
          <div className="section__inner" style={{ maxWidth: '720px' }}>
            <p className="section-label" style={{ color: post.color }}>The Solution</p>
            <h2 className="blog-post__section-title">What the market needs.</h2>
            <div className="blog-post__solution-box" style={{ borderLeftColor: post.color }}>
              <p className="blog-post__solution-overview">{post.solution.overview}</p>
            </div>
            <p className="blog-post__body">{post.solution.connectorRole}</p>
          </div>
        </section>

        {/* Technical Deep Dive */}
        <section className="section">
          <div className="section__inner" style={{ maxWidth: '720px' }}>
            <p className="section-label" style={{ color: post.color }}>Technical Analysis</p>
            <h2 className="blog-post__section-title">How it works—and breaks.</h2>
            
            {post.technicalDeepDive.attackVector && (
              <div className="blog-post__tech-block">
                <h3 className="blog-post__tech-title">Attack Vector</h3>
                <p className="blog-post__body">{post.technicalDeepDive.attackVector}</p>
              </div>
            )}
            
            {post.technicalDeepDive.impactScope && (
              <div className="blog-post__tech-block">
                <h3 className="blog-post__tech-title">Impact Scope</h3>
                <p className="blog-post__body">{post.technicalDeepDive.impactScope}</p>
              </div>
            )}
            
            <div className="blog-post__tech-block">
              <h3 className="blog-post__tech-title">Mitigation Strategy</h3>
              <p className="blog-post__body">{post.technicalDeepDive.mitigationStrategy}</p>
            </div>
          </div>
        </section>

        {/* Connector Advantage */}
        <section className="section section--bordered">
          <div className="section__inner" style={{ maxWidth: '720px' }}>
            <p className="section-label" style={{ color: post.color }}>Connector Advantage</p>
            <h2 className="blog-post__section-title">{post.connectorAdvantage.title}</h2>
            
            <ul className="blog-post__advantage-list">
              {post.connectorAdvantage.points.map((point, i) => (
                <li key={i} className="blog-post__advantage-item">
                  <span className="blog-post__advantage-check" style={{ color: post.color }}>✓</span>
                  <span>{point}</span>
                </li>
              ))}
            </ul>
          </div>
        </section>

        {/* Compliance Mapping */}
        {post.complianceMapping && (
          <section className="section">
            <div className="section__inner" style={{ maxWidth: '720px' }}>
              <p className="section-label" style={{ color: post.color }}>Compliance Mapping</p>
              <h2 className="blog-post__section-title">{post.complianceMapping.framework}</h2>
              
              <div className="blog-post__compliance-box">
                <ul className="blog-post__compliance-list">
                  {post.complianceMapping.requirements.map((req, i) => (
                    <li key={i} className="blog-post__compliance-item">
                      <span className="blog-post__compliance-bullet" style={{ color: post.color }}>•</span>
                      <span>{req}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          </section>
        )}

        {/* Related Plugins */}
        <section className="section section--bordered">
          <div className="section__inner" style={{ maxWidth: '720px' }}>
            <p className="section-label" style={{ color: post.color }}>Relevant Connector Plugins</p>
            <h2 className="blog-post__section-title">Tools for this threat model.</h2>
            
            <div className="blog-post__plugins">
              {post.relatedPlugins.map(plugin => (
                <a 
                  key={plugin} 
                  href={`/products/${plugin.toLowerCase()}`}
                  className="blog-post__plugin-link"
                  style={{ 
                    borderColor: `${post.color}30`,
                    background: `${post.color}08`
                  }}
                >
                  <span className="blog-post__plugin-name" style={{ color: post.color }}>
                    {plugin}
                  </span>
                  <span className="blog-post__plugin-arrow">→</span>
                </a>
              ))}
            </div>
          </div>
        </section>

        {/* Related Posts */}
        {relatedPosts.length > 0 && (
          <section className="section">
            <div className="section__inner" style={{ maxWidth: '720px' }}>
              <p className="section-label">Related Analysis</p>
              <h2 className="blog-post__section-title">More in {post.category}</h2>
              
              <div className="blog-post__related">
                {relatedPosts.map(related => (
                  <RelatedBlogCard key={related.slug} post={related} />
                ))}
              </div>
            </div>
          </section>
        )}

        {/* CTA */}
        <section className="section">
          <div className="section__inner" style={{ maxWidth: '640px' }}>
            <div className="pp-cta-block" style={{ borderColor: `${post.color}30` }}>
              <p className="pp-cta-block__eyebrow" style={{ color: post.color }}>
                Governed AI Execution
              </p>
              <h2 className="pp-cta-block__title">
                Apply for access.
              </h2>
              <p className="pp-cta-block__body">
                Connector is the OS underneath: isolate, govern, stop, prove.
                Ready today: DevGuard, TraceTramp, WitnessCtl. Essays name
                planned institutions as the job to be done — not as a live SKU.
              </p>
              <ul className="pp-cta-checklist">
                <li><span style={{ color: post.color }}>✓</span> Pre-execution admit or refuse</li>
                <li><span style={{ color: post.color }}>✓</span> HMAC-chained receipts a reviewer can inspect</li>
                <li><span style={{ color: post.color }}>✓</span> Self-hosted node — not a coding-agent product</li>
                <li><span style={{ color: post.color }}>✓</span> Framework mapping is a design-partner path</li>
              </ul>
              <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
                <a href="/#interest" className="btn btn--primary">Apply for access</a>
                <a href="/blog" className="btn btn--ghost">← All analysis</a>
              </div>
            </div>
          </div>
        </section>

        <Footer />
      </main>
    </>
  )
}

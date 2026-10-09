import SlideShell from './SlideShell';

export default function Slide17() {
  return (
    <SlideShell sid="s17" contentClassName="slide-content left-focus-layout pdf-safe">
      <div className="focus-stack">
        <div className="tag">Enterprise readiness</div>
        <h1 className="slide-title slide-title-sm">Signals buyers already use to say yes—or no</h1>
        <p className="slide-sub">
          YouTube viewers may be builders; procurement viewers want vocabulary they can paste into an RFC. This slide bridges both.
        </p>
      </div>
      <div className="focus-visual">
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, width: '100%' }}>
          {[
            { t: 'Security', d: 'Capabilities, injection-aware gates, secrets hygiene, SSO roadmap alignment', i: 'red' },
            { t: 'Data & residency', d: 'Clear memory model, retention hooks, export for e-discovery discussions', i: 'purple' },
            { t: 'Operability', d: 'Health, metrics, runbooks—not only happy-path screenshots', i: 'blue' },
            { t: 'Integration', d: 'API-first posture that fits CI/CD and enterprise service catalogs', i: 'green' },
          ].map((x) => (
            <div key={x.t} className="feature-item" style={{ alignItems: 'flex-start', padding: '18px 20px' }}>
              <div className={`feature-icon ${x.i}`} style={{ fontSize: 18 }}>
                ✓
              </div>
              <div className="feature-text">
                <div className="feature-title">{x.t}</div>
                <div className="feature-desc">{x.d}</div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </SlideShell>
  );
}

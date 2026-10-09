import SlideShell from './SlideShell';

export default function Slide13() {
  return (
    <SlideShell sid="s13" contentClassName="slide-content left-focus-layout pdf-safe">
      <div className="focus-stack">
        <div className="tag">Use case</div>
        <h1 className="slide-title slide-title-sm">Workflow automation with <span style={{ color: '#10d98a' }}>receipts</span></h1>
        <p className="slide-sub">
          RPA grew up on brittle selectors. Agentic workflows need the same deterministic accountability—who approved, what changed, what was tried when something failed.
        </p>
        <ul className="clean-list">
          <li>
            <span className="clean-dot" style={{ background: '#10d98a' }} />
            Sagas and handoffs across tools with append-only narrative.
          </li>
          <li>
            <span className="clean-dot" />
            Easier to plug into ITSM and SOAR: “here is the bundle for ticket 44102.”
          </li>
        </ul>
      </div>
      <div className="focus-visual">
        <div className="hero-visual-card" style={{ padding: 26 }}>
          <div className="mini-label" style={{ marginBottom: 12 }}>
            Storyboard
          </div>
          <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'stretch' }}>
            {['Trigger', 'Plan', 'Gate', 'Act', 'Verify', 'Archive'].map((step, i) => (
              <div
                key={step}
                style={{
                  flex: '1 1 72px',
                  padding: '12px 10px',
                  borderRadius: 12,
                  border: '1px solid rgba(255,255,255,0.1)',
                  background: i === 2 ? 'rgba(245,158,11,0.12)' : 'rgba(255,255,255,0.03)',
                  textAlign: 'center',
                }}
              >
                <div style={{ fontSize: 11, fontWeight: 800, color: '#4a6077', letterSpacing: '0.1em' }}>{String(i + 1).padStart(2, '0')}</div>
                <div style={{ fontSize: 14, fontWeight: 700, color: '#f0f6ff', marginTop: 6 }}>{step}</div>
              </div>
            ))}
          </div>
          <p style={{ fontSize: 14, color: '#8ba4be', marginTop: 18, lineHeight: 1.5 }}>
            Connector is the layer that makes automation <em style={{ color: '#f0f6ff', fontStyle: 'normal' }}>demonstrable</em>—ideal for IT leaders evaluating long-term maintainability.
          </p>
        </div>
      </div>
    </SlideShell>
  );
}

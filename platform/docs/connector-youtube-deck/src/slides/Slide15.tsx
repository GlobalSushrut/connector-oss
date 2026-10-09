import SlideShell from './SlideShell';

export default function Slide15() {
  return (
    <SlideShell sid="s15" contentClassName="slide-content left-focus-layout pdf-safe">
      <div className="focus-stack">
        <div className="tag">Workflow pattern</div>
        <h1 className="slide-title slide-title-sm">Multi-step pipelines &amp; sagas</h1>
        <p className="slide-sub">
          Real work is rarely one prompt. Connector is built for sequences: branch, compensate, retry with policy, and keep a coherent journal across steps.
        </p>
        <ul className="clean-list">
          <li>
            <span className="clean-dot" />
            Onboarding flows: validate docs → create accounts → notify stakeholders.
          </li>
          <li>
            <span className="clean-dot" style={{ background: '#a78bfa' }} />
            Data ops: extract → score quality → route exceptions to specialists.
          </li>
          <li>
            <span className="clean-dot" style={{ background: '#00c8f8' }} />
            Each step inherits capabilities from the same spine—no sprawl of secrets.
          </li>
        </ul>
      </div>
      <div className="focus-visual">
        <div className="hero-visual-card" style={{ padding: 22 }}>
          <div className="pipeline-container" style={{ gap: 10 }}>
            {['Ingest', 'Classify', 'Enrich', 'Decide', 'Emit'].map((label, i, arr) => (
              <div key={label} style={{ display: 'flex', alignItems: 'center', width: '100%', gap: 10 }}>
                <div
                  className="pipeline-node"
                  style={{
                    flex: 1,
                    flexDirection: 'column',
                    alignItems: 'flex-start',
                    justifyContent: 'center',
                    gap: 6,
                    borderColor: i === 3 ? 'rgba(0,200,248,0.35)' : undefined,
                    background: i === 3 ? 'rgba(0,200,248,0.1)' : undefined,
                  }}
                >
                  <span style={{ fontWeight: 800, color: '#00c8f8', fontSize: 13 }}>{`Step ${i + 1}`}</span>
                  <span style={{ fontSize: 16, fontWeight: 700, color: '#f0f6ff' }}>{label}</span>
                </div>
                {i < arr.length - 1 && (
                  <div style={{ fontSize: 18, color: '#4a6077', flexShrink: 0 }}>→</div>
                )}
              </div>
            ))}
          </div>
        </div>
      </div>
    </SlideShell>
  );
}

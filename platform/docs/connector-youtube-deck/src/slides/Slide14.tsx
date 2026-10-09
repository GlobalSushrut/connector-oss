import SlideShell from './SlideShell';

export default function Slide14() {
  return (
    <SlideShell sid="s14" contentClassName="slide-content left-focus-layout pdf-safe">
      <div className="focus-stack">
        <div className="tag">Workflow pattern</div>
        <h1 className="slide-title slide-title-sm">Human-in-the-loop, without losing momentum</h1>
        <p className="slide-sub">
          Some decisions must never be fully autonomous. Pattern: agent proposes → policy routes to a person → Connector records the approval artifact → execution resumes.
        </p>
        <ul className="clean-list">
          <li>
            <span className="clean-dot" style={{ background: '#f59e0b' }} />
            Works for refunds, access grants, outbound comms, and model-assisted coding in sensitive repos.
          </li>
          <li>
            <span className="clean-dot" />
            Auditors see a causal chain—not a mystery box labeled “AI approved it.”
          </li>
        </ul>
      </div>
      <div className="focus-visual">
        <div className="hero-visual-card" style={{ padding: 30, justifyContent: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap', justifyContent: 'center' }}>
            {[
              { t: 'Agent', c: 'rgba(244,63,94,0.12)' },
              { t: 'Policy', c: 'rgba(245,158,11,0.12)' },
              { t: 'Human', c: 'rgba(0,200,248,0.12)' },
              { t: 'Execute', c: 'rgba(16,217,138,0.12)' },
            ].map((b, i, arr) => (
              <div key={b.t} style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                <div
                  className="diagram-node"
                  style={{ minWidth: 120, background: b.c, padding: '18px 16px' }}
                >
                  <div className="diagram-title" style={{ fontSize: 17 }}>
                    {b.t}
                  </div>
                </div>
                {i < arr.length - 1 && <div className="diagram-line" style={{ width: 28 }} />}
              </div>
            ))}
          </div>
          <p style={{ textAlign: 'center', fontSize: 14, color: '#4a6077', marginTop: 22 }}>
            Pause is a first-class state—timed, attributed, and exportable.
          </p>
        </div>
      </div>
    </SlideShell>
  );
}

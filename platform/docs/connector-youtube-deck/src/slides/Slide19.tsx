import SlideShell from './SlideShell';

export default function Slide19() {
  return (
    <SlideShell sid="s19" contentClassName="slide-content left-focus-layout pdf-safe">
      <div className="focus-stack">
        <div className="tag">Adoption</div>
        <h1 className="slide-title slide-title-sm">Land with a narrow story, widen with credibility</h1>
        <p className="slide-sub">
          Pick a workflow where failure is visible and memory matters. Prove control + proof there; expand rings only after stakeholders trust the flight recorder.
        </p>
        <ol style={{ marginTop: 12, paddingLeft: 22, color: '#8ba4be', fontSize: 16, lineHeight: 1.55, maxWidth: '50ch' }}>
          <li style={{ marginBottom: 10 }}>
            <strong style={{ color: '#f0f6ff' }}>Scope:</strong> one agent surface, one critical tool, one data class.
          </li>
          <li style={{ marginBottom: 10 }}>
            <strong style={{ color: '#f0f6ff' }}>Prove:</strong> export an evidence bundle internal reviewers respect.
          </li>
          <li>
            <strong style={{ color: '#f0f6ff' }}>Scale:</strong> clone the pattern—policy and adapters are the reusable assets.
          </li>
        </ol>
      </div>
      <div className="focus-visual">
        <div className="hero-visual-card" style={{ padding: 26 }}>
          <div className="wide-panel">
            <div className="wide-panel-title">Talk track</div>
            <p className="wide-panel-copy">
              “We did not boil the ocean. We picked the riskiest happy path, wrapped it in Connector, and suddenly security could reason about agent behavior the same way they reason about services.”
            </p>
          </div>
          <div style={{ display: 'flex', gap: 12, marginTop: 14 }}>
            <div className="safe-panel" style={{ flex: 1 }}>
              <div className="mini-label">Labs / pilots</div>
              <p style={{ fontSize: 14, color: '#8ba4be', marginTop: 8 }}>Measure time-to-answer for “what happened?”</p>
            </div>
            <div className="safe-panel" style={{ flex: 1 }}>
              <div className="mini-label">Production</div>
              <p style={{ fontSize: 14, color: '#8ba4be', marginTop: 8 }}>Measure blocked bad actions + mean recovery time.</p>
            </div>
          </div>
        </div>
      </div>
    </SlideShell>
  );
}

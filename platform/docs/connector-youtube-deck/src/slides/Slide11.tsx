import SlideShell from './SlideShell';

export default function Slide11() {
  return (
    <SlideShell sid="s11" contentClassName="slide-content left-focus-layout pdf-safe">
      <div className="focus-stack">
        <div className="tag">Use case</div>
        <h1 className="slide-title slide-title-sm">
          Regulated &amp; <span className="accent-blue">high-stakes</span> AI
        </h1>
        <p className="slide-sub">
          When a wrong suggestion has real-world consequences, you need lineage: what policy allowed this output, which sources were read, which tools fired.
        </p>
        <ul className="clean-list">
          <li>
            <span className="clean-dot" />
            Clinical, financial, and public-sector workflows where “we think the model did X” is not enough.
          </li>
          <li>
            <span className="clean-dot" style={{ background: '#10d98a' }} />
            Partner reviews where you bring receipts, not vibes.
          </li>
        </ul>
      </div>
      <div className="focus-visual">
        <div className="hero-visual-card" style={{ padding: 28, display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div className="diagram-chip" style={{ minWidth: 'auto', width: '100%' }}>
            <span className="chip-label">On-camera checklist</span>
            <div className="chip-values" style={{ flexWrap: 'wrap', justifyContent: 'center', gap: 16 }}>
              <span className="val-red">Policy</span>
              <span className="val-blue">Lineage</span>
              <span className="val-green">Attest</span>
            </div>
          </div>
          <div className="safe-panel">
            <div className="mini-label">Sample line</div>
            <p style={{ fontSize: 16, color: '#f0f6ff', marginTop: 8, lineHeight: 1.5, fontWeight: 600 }}>
              “If you cannot replay the reasoning path and the data path together, you are not ready for governed AI—Connector is how you wire both.”
            </p>
          </div>
        </div>
      </div>
    </SlideShell>
  );
}

import SlideShell from './SlideShell';

export default function Slide7() {
  return (
    <SlideShell sid="s07" contentClassName="slide-content left-focus-layout pdf-safe">
      <div className="focus-stack">
        <div className="tag">Definition</div>
        <h1 className="slide-title slide-title-sm">
          Connector is a <span className="accent-blue">runtime control plane</span> for AI systems
        </h1>
        <p className="slide-sub">
          Not “another chat UI.” A backbone that sits next to your agents, your tools, and your data—so every step is policy-aware, recorded, and explainable.
        </p>
        <ul className="clean-list" style={{ marginTop: 8 }}>
          <li>
            <span className="clean-dot" />
            Owns memory, capabilities, and execution gates in one place instead of ad-hoc scripts.
          </li>
          <li>
            <span className="clean-dot" style={{ background: '#10d98a' }} />
            Speaks both research-friendly APIs and serious audit language.
          </li>
          <li>
            <span className="clean-dot" style={{ background: '#a78bfa' }} />
            Designed for teams that will be asked “prove it” after the demo ends.
          </li>
        </ul>
      </div>
      <div className="focus-visual">
        <div className="hero-visual-card" style={{ padding: 28 }}>
          <div className="wide-panel" style={{ marginBottom: 14 }}>
            <div className="wide-panel-title">Say this on camera</div>
            <p className="wide-panel-copy">
              “Connector is where agent behavior meets enterprise reality: identity, policy, durable state, and receipts that survive scrutiny.”
            </p>
          </div>
          <div className="safe-panel">
            <div className="mini-label">Not the same as</div>
            <p style={{ fontSize: 15, color: '#8ba4be', marginTop: 10, lineHeight: 1.5 }}>
              A model host only · a vector DB only · a generic workflow tool with no cryptographic lineage story.
            </p>
          </div>
        </div>
      </div>
    </SlideShell>
  );
}

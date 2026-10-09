import SlideShell from './SlideShell';

export default function Slide8() {
  return (
    <SlideShell sid="s08" contentClassName="slide-content left-focus-layout pdf-safe">
      <div className="focus-stack">
        <div className="tag">Why this exists</div>
        <h1 className="slide-title slide-title-sm">
          Smart demos, <span style={{ color: '#f43f5e' }}>fragile production</span>
        </h1>
        <p className="slide-sub">
          The failure mode is not “model was dumb.” It is nobody can link a customer outcome to policy, tools, and data touched—especially under stress.
        </p>
        <ul className="clean-list">
          <li>
            <span className="clean-dot" style={{ background: '#f43f5e' }} />
            Shadow integrations: agents calling APIs with no durable capability story.
          </li>
          <li>
            <span className="clean-dot" style={{ background: '#f59e0b' }} />
            Mushy logs: transcripts that cannot satisfy security or legal review.
          </li>
          <li>
            <span className="clean-dot" />
            Org paralysis: platform teams block launches because risk is unknowable.
          </li>
        </ul>
      </div>
      <div className="focus-visual">
        <div className="hero-visual-card" style={{ padding: 26 }}>
          <div className="pipeline-container" style={{ padding: '8px 12px', gap: 12 }}>
            <div className="pipeline-node">
              <span style={{ fontSize: 15, fontWeight: 700, color: '#f0f6ff' }}>Prototype velocity ↑</span>
              <span style={{ fontSize: 13, color: '#8ba4be' }}>anyone can glue an agent together</span>
            </div>
            <div className="pipeline-node highlight">
              <span style={{ fontSize: 15, fontWeight: 800, color: '#00c8f8' }}>Connector· governance gap closes</span>
              <span style={{ fontSize: 13, color: '#8ba4be' }}>record · enforce · prove · replay</span>
            </div>
            <div className="pipeline-node">
              <span style={{ fontSize: 15, fontWeight: 700, color: '#f0f6ff' }}>Enterprise adoption ↑</span>
              <span style={{ fontSize: 13, color: '#8ba4be' }}>security &amp; compliance become partners</span>
            </div>
          </div>
        </div>
      </div>
    </SlideShell>
  );
}

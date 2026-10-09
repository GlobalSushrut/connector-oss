import SlideShell from './SlideShell';

export default function Slide9() {
  return (
    <SlideShell sid="s09" contentClassName="slide-content left-focus-layout pdf-safe">
      <div className="focus-stack">
        <div className="tag">Product story</div>
        <h1 className="slide-title slide-title-sm">Three pillars you can draw from memory</h1>
        <p className="slide-sub">Repeatable on any slide of a customer deck—each pillar maps to buyer questions.</p>
      </div>
      <div className="focus-visual">
        <div style={{ display: 'flex', flexDirection: 'column', gap: 14, width: '100%' }}>
          <div className="wide-panel" style={{ borderColor: 'rgba(0,200,248,0.25)', background: 'rgba(0,200,248,0.06)' }}>
            <div className="wide-panel-title" style={{ color: '#00c8f8' }}>
              1 · Control
            </div>
            <p className="wide-panel-copy">Policy, risk scoring, gates on tools and data—before expensive mistakes ship.</p>
          </div>
          <div className="wide-panel" style={{ borderColor: 'rgba(124,58,237,0.25)', background: 'rgba(124,58,237,0.06)' }}>
            <div className="wide-panel-title" style={{ color: '#a78bfa' }}>
              2 · Memory
            </div>
            <p className="wide-panel-copy">Durable, structured state—not just ephemeral prompts—so teams can ground, resume, and audit.</p>
          </div>
          <div className="wide-panel" style={{ borderColor: 'rgba(16,217,138,0.25)', background: 'rgba(16,217,138,0.06)' }}>
            <div className="wide-panel-title" style={{ color: '#10d98a' }}>
              3 · Proof
            </div>
            <p className="wide-panel-copy">Artifacts, timelines, and cryptographic anchors that support serious review—not screenshots.</p>
          </div>
        </div>
      </div>
    </SlideShell>
  );
}

import SlideShell from './SlideShell';

export default function Slide6() {
  return (
    <SlideShell sid="s06" contentClassName="slide-content left-focus-layout pdf-safe">
      <div className="focus-stack">
        <div className="tag">YouTube cold open</div>
        <h1 className="slide-title">
          What if every <span className="accent-blue">AI action</span> had a flight recorder?
        </h1>
        <p className="calm-quote" style={{ maxWidth: '20ch' }}>
          That is the idea behind Connector.
        </p>
        <p className="slide-sub">
          This deck is tuned for crisp voice-over: 5 architecture frames first, then business story. Download the PDF when you are done recording B-roll.
        </p>
        <div className="stat-strip">
          <div className="stat-pill">
            <strong>Format</strong>20 slides · 16∶9
          </div>
          <div className="stat-pill">
            <strong>Tone</strong>Enterprise-credible, plain language
          </div>
        </div>
      </div>
      <div className="focus-visual">
        <div className="hero-visual-card" style={{ padding: 36, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <div style={{ textAlign: 'center', maxWidth: 420 }}>
            <div style={{ fontSize: 72, lineHeight: 1, marginBottom: 16 }}>🎬</div>
            <p style={{ fontSize: 22, fontWeight: 800, color: '#f0f6ff', letterSpacing: '-0.02em' }}>Hook in 8 seconds</p>
            <p style={{ fontSize: 16, color: '#8ba4be', marginTop: 12, lineHeight: 1.5 }}>
              “Agents are shipping fast—but enterprises freeze without controls. Connector is the layer that makes advanced AI boringly safe to run.”
            </p>
          </div>
        </div>
      </div>
    </SlideShell>
  );
}

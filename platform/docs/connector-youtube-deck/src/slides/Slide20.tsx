import SlideShell from './SlideShell';

export default function Slide20() {
  return (
    <SlideShell sid="s20" contentClassName="slide-content left-focus-layout pdf-safe">
      <div className="focus-stack">
        <div className="tag">Close</div>
        <h1 className="slide-title slide-title-sm">
          Connector: <span className="accent-blue">control</span>, memory, proof
        </h1>
        <p className="slide-sub">
          If your viewers remember one sentence: AI agents need an enterprise-grade runtime—not only a model endpoint—and that runtime is Connector’s focus.
        </p>
        <div className="closing-card" style={{ maxWidth: 400 }}>
          <div className="mini-label">Download</div>
          <p style={{ fontSize: 15, color: '#8ba4be', marginTop: 8, lineHeight: 1.5 }}>
            Use the PDF button in the top bar for a deck you can print, attach to pitch emails, or feed to video editors as stills.
          </p>
        </div>
        <div className="stat-strip">
          <div className="stat-pill">
            <strong>Slides 1–5</strong>architecture
          </div>
          <div className="stat-pill">
            <strong>Slides 6–20</strong>story &amp; motion
          </div>
        </div>
      </div>
      <div className="focus-visual">
        <div className="hero-visual-card" style={{ padding: 32, justifyContent: 'center' }}>
          <div style={{ textAlign: 'center' }}>
            <p style={{ fontSize: 26, fontWeight: 800, color: '#f0f6ff', letterSpacing: '-0.02em', lineHeight: 1.25 }}>
              “Ship agents your governance team
              <br />
              does not have to fight.”
            </p>
            <p style={{ fontSize: 14, color: '#4a6077', marginTop: 20, letterSpacing: '0.12em', fontWeight: 700 }}>
              CONNECTOR · DOCS DECK · {new Date().getFullYear()}
            </p>
          </div>
        </div>
      </div>
    </SlideShell>
  );
}

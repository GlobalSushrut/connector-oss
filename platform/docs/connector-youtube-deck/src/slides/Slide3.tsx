import SlideShell from './SlideShell';
import { archDiagramTag } from './archTag';

const steps = [
  'Intent arrives — user, system, or agent',
  'Policy · firewall scores risk — allow / shape / block',
  'Memory kernel · structured state & lineage',
  'Capabilities · least-privilege tool & data access',
  'Execution · model / tools / pipelines under watch',
  'Trust surfaces · audit, replay, evidence',
];

export default function Slide3() {
  return (
    <SlideShell sid="s03" contentClassName="slide-content diagram-arch-layout pdf-safe">
      <div className="tag">{archDiagramTag(3)}</div>
      <h1 className="slide-title slide-title-sm">One request, end to end</h1>
      <p className="slide-sub" style={{ maxWidth: '68ch' }}>
        Whether you are on YouTube or in a board room, this is the story: every hop is explicit so you can explain—and prove—the path.
      </p>
      <div className="diagram-arch-body">
        <div className="hero-visual-card" style={{ padding: '18px 36px', display: 'flex', gap: 28, alignItems: 'stretch' }}>
          <svg viewBox="0 0 420 460" width="340" xmlns="http://www.w3.org/2000/svg">
            <defs>
              <marker id="s03-m" markerWidth="10" markerHeight="10" refX="9" refY="5" orient="auto">
                <polygon points="0 0, 10 5, 0 10" fill="#00c8f8" />
              </marker>
            </defs>
            {[0, 1, 2, 3, 4, 5].map((i) => {
              const y = 28 + i * 68;
              const highlight = i === 2 || i === 4;
              return (
                <g key={i}>
                  <rect
                    x="24"
                    y={y}
                    width="372"
                    height="56"
                    rx="14"
                    fill={highlight ? 'rgba(0,200,248,0.18)' : 'rgba(255,255,255,0.04)'}
                    stroke={highlight ? 'rgba(0,200,248,0.45)' : 'rgba(255,255,255,0.1)'}
                    strokeWidth={highlight ? 2.5 : 1.5}
                  />
                  <text x="42" y={y + 36} fill="#f0f6ff" fontSize="15" fontWeight="700" fontFamily="Inter, system-ui, sans-serif">
                    {steps[i]}
                  </text>
                  {i < 5 && (
                    <line x1="210" y1={y + 56} x2="210" y2={y + 68} stroke="#3a6387" strokeWidth="2.5" markerEnd="url(#s03-m)" />
                  )}
                </g>
              );
            })}
          </svg>
          <div style={{ flex: 1, display: 'flex', flexDirection: 'column', justifyContent: 'center', gap: 18 }}>
            <div className="safe-panel">
              <div className="mini-label">Narration cue</div>
              <p style={{ fontSize: 17, lineHeight: 1.5, color: '#8ba4be', marginTop: 8 }}>
                “Nothing magical happens in the gap between prompt and database write—Connector is that gap, instrumented.”
              </p>
            </div>
            <div className="safe-panel">
              <div className="mini-label">Enterprise angle</div>
              <p style={{ fontSize: 17, lineHeight: 1.5, color: '#8ba4be', marginTop: 8 }}>
                Security and compliance teams get a continuous story: who, what, which policy, which artifact—ideal for post-incident review and design partners.
              </p>
            </div>
          </div>
        </div>
      </div>
    </SlideShell>
  );
}

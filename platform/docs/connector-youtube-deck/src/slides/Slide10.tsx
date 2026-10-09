import SlideShell from './SlideShell';

const personas = [
  { role: 'Platform & AI infra', want: 'One spine for many agents · fewer one-off frameworks', color: '#00c8f8' },
  { role: 'Security & risk', want: 'Explainable blast radius · policy as code · evidence packs', color: '#f43f5e' },
  { role: 'Compliance & legal', want: 'Retention, access, defensible narrative for regulators', color: '#a78bfa' },
  { role: 'Product & ops owners', want: 'Ship copilots without betting the brand on a fragile demo', color: '#10d98a' },
];

export default function Slide10() {
  return (
    <SlideShell sid="s10" contentClassName="slide-content left-focus-layout pdf-safe">
      <div className="focus-stack">
        <div className="tag">Audience</div>
        <h1 className="slide-title slide-title-sm">Who gets value first</h1>
        <p className="slide-sub">
          Connector is multi-player. The same runtime answers different OKRs—speed for builders, assurance for governors.
        </p>
        <p className="slide-sub" style={{ fontSize: 16, marginTop: 8 }}>
          On video: pick <strong style={{ color: '#f0f6ff' }}>one persona per segment</strong> so viewers self-identify fast.
        </p>
      </div>
      <div className="focus-visual">
        <div className="vertical-cards" style={{ width: '100%' }}>
          {personas.map((p) => (
            <div
              key={p.role}
              className="safe-panel"
              style={{ borderLeft: `4px solid ${p.color}` }}
            >
              <div style={{ fontSize: 18, fontWeight: 800, color: '#f0f6ff' }}>{p.role}</div>
              <div style={{ fontSize: 15, color: '#8ba4be', marginTop: 6, lineHeight: 1.45 }}>{p.want}</div>
            </div>
          ))}
        </div>
      </div>
    </SlideShell>
  );
}

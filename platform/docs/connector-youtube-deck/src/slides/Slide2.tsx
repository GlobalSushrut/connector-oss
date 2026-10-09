import SlideShell from './SlideShell';
import { archDiagramTag } from './archTag';

const rows = [
  { label: 'Language & clients', sub: 'Python FFI, REST, SDKs — how your org invokes Connector', c: 'rgba(167,139,250,0.12)', b: 'rgba(167,139,250,0.35)' },
  { label: 'Connector API', sub: 'Agents, pipelines, trust & compliance surfaces', c: 'rgba(0,200,248,0.10)', b: 'rgba(0,200,248,0.4)' },
  { label: 'Engine core', sub: 'Dispatch, firewall, routing, behavior analysis', c: 'rgba(245,158,11,0.08)', b: 'rgba(245,158,11,0.35)' },
  { label: 'Memory & action kernels', sub: 'VAC (memory) + AAPI (governed actions & capabilities)', c: 'rgba(16,217,138,0.08)', b: 'rgba(16,217,138,0.38)' },
  { label: 'Cryptographic base', sub: 'CIDs, signatures — anchoring what is stored and proven', c: 'rgba(244,63,94,0.06)', b: 'rgba(244,63,94,0.28)' },
];

export default function Slide2() {
  return (
    <SlideShell sid="s02" contentClassName="slide-content diagram-arch-layout pdf-safe">
      <div className="tag">{archDiagramTag(2)}</div>
      <h1 className="slide-title slide-title-sm">A layered platform, not a single microservice</h1>
      <p className="slide-sub" style={{ maxWidth: '70ch' }}>
        Think rings: bindings at the top, execution in the middle, durable kernels underneath, crypto at the bottom—each layer has a crisp job.
      </p>
      <div className="diagram-arch-body">
        <div className="hero-visual-card" style={{ display: 'flex', flexDirection: 'column', justifyContent: 'center', gap: 10, padding: '20px 32px' }}>
          {rows.map((r, i) => (
            <div
              key={r.label}
              style={{
                borderRadius: 14,
                border: `2px solid ${r.b}`,
                background: r.c,
                padding: '14px 22px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                gap: 20,
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
                <span
                  style={{
                    width: 36,
                    height: 36,
                    borderRadius: 10,
                    background: 'rgba(0,0,0,0.35)',
                    border: '1px solid rgba(255,255,255,0.1)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    fontSize: 15,
                    fontWeight: 800,
                    color: '#00c8f8',
                  }}
                >
                  {i + 1}
                </span>
                <div>
                  <div style={{ fontSize: 20, fontWeight: 800, color: '#f0f6ff' }}>{r.label}</div>
                  <div style={{ fontSize: 14, color: '#8ba4be', marginTop: 4 }}>{r.sub}</div>
                </div>
              </div>
              {i < rows.length - 1 && (
                <div style={{ fontSize: 11, fontWeight: 800, letterSpacing: '0.14em', color: '#4a6077' }}>▼</div>
              )}
            </div>
          ))}
        </div>
      </div>
    </SlideShell>
  );
}

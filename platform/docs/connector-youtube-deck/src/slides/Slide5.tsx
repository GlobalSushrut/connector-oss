import SlideShell from './SlideShell';
import { archDiagramTag } from './archTag';

const N = 5;
const CX = 500;
/** Lower center + tighter ring so all five cards stay inside the viewBox (no clipped “stray” strokes). */
const CY = 248;
const RING = 168;
const items = [
  { label: 'Define policy', sub: 'Rules, data classes, tool tiers', color: '#f43f5e' },
  { label: 'Enforce live', sub: 'Firewall · capabilities · gates', color: '#00c8f8' },
  { label: 'Record facts', sub: 'Audit + artifacts + lineage', color: '#10d98a' },
  { label: 'Review & replay', sub: 'Investigations · RCA', color: '#a78bfa' },
  { label: 'Tune & attest', sub: 'Evidence for security / legal', color: '#f59e0b' },
];

function ringPos(i: number) {
  const a = (i / N) * Math.PI * 2 - Math.PI / 2;
  return { x: CX + Math.cos(a) * RING, y: CY + Math.sin(a) * RING };
}

function chordEndpoints(p: { x: number; y: number }, q: { x: number; y: number }) {
  const dx = q.x - p.x;
  const dy = q.y - p.y;
  const len = Math.hypot(dx, dy) || 1;
  const ux = dx / len;
  const uy = dy / len;
  /** Pentagon side ≈198px @ RING=168; cap inset so segments stay visible and clear the hub. */
  const inset = Math.min(92, Math.max(36, len * 0.42));
  return {
    x1: p.x + ux * inset,
    y1: p.y + uy * inset,
    x2: q.x - ux * inset,
    y2: q.y - uy * inset,
  };
}

export default function Slide5() {
  const pts = items.map((_, i) => ringPos(i));

  return (
    <SlideShell sid="s05" contentClassName="slide-content diagram-arch-layout pdf-safe">
      <div className="tag">{archDiagramTag(5)}</div>
      <h1 className="slide-title slide-title-sm">Governance is a closed loop</h1>
      <p className="slide-sub" style={{ maxWidth: '70ch' }}>
        Enterprises buy defensible operations. Connector ties policy, runtime enforcement, and evidentiary artifacts into one repeating cycle you can show on camera.
      </p>
      <div className="diagram-arch-body">
        <div className="hero-visual-card" style={{ padding: '12px 20px' }}>
          <svg viewBox="0 0 1000 460" width="100%" style={{ maxHeight: 420 }} xmlns="http://www.w3.org/2000/svg">
            <defs>
              <marker id="s05-m" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
                <polygon points="0 0, 8 4, 0 8" fill="#5a8aaa" />
              </marker>
            </defs>
            <ellipse cx={CX} cy={CY} rx="400" ry="148" fill="none" stroke="rgba(0,200,248,0.1)" strokeWidth="1.5" strokeDasharray="5 10" />
            {pts.map((p, i) => {
              const q = pts[(i + 1) % N];
              const { x1, y1, x2, y2 } = chordEndpoints(p, q);
              return (
                <line
                  key={`e-${i}`}
                  x1={x1}
                  y1={y1}
                  x2={x2}
                  y2={y2}
                  stroke="rgba(0,200,248,0.32)"
                  strokeWidth="2"
                  markerEnd="url(#s05-m)"
                />
              );
            })}
            {items.map((it, i) => {
              const { x, y } = pts[i];
              return (
                <g key={it.label} transform={`translate(${x}, ${y})`}>
                  <rect x="-118" y="-44" width="236" height="88" rx="16" fill="rgba(6,17,30,0.96)" stroke={`${it.color}99`} strokeWidth="2" />
                  <text x="0" y="-10" textAnchor="middle" fill="#f0f6ff" fontSize="16" fontWeight="800" fontFamily="Inter, system-ui, sans-serif">
                    {it.label}
                  </text>
                  <text x="0" y="14" textAnchor="middle" fill="#8ba4be" fontSize="12" fontFamily="Inter, system-ui, sans-serif">
                    {it.sub}
                  </text>
                </g>
              );
            })}
            <circle cx={CX} cy={CY} r="54" fill="rgba(0,200,248,0.14)" stroke="rgba(0,200,248,0.5)" strokeWidth="2.5" />
            <text x={CX} y={CY - 4} textAnchor="middle" fill="#f0f6ff" fontSize="14" fontWeight="800" fontFamily="Inter, system-ui, sans-serif">
              TRUST
            </text>
            <text x={CX} y={CY + 16} textAnchor="middle" fill="#00c8f8" fontSize="11" fontWeight="700" fontFamily="Inter, system-ui, sans-serif" letterSpacing="0.12em">
              CORE
            </text>
          </svg>
        </div>
      </div>
    </SlideShell>
  );
}

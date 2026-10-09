import SlideShell from './SlideShell';

export default function Slide12() {
  return (
    <SlideShell sid="s12" contentClassName="slide-content left-focus-layout pdf-safe">
      <div className="focus-stack">
        <div className="tag">Use case</div>
        <h1 className="slide-title slide-title-sm">Internal agent platforms &amp; copilots</h1>
        <p className="slide-sub">
          Teams ship dozens of small agents. Without a shared control plane, every team reinvents authz, logging, and failure handling—badly.
        </p>
        <ul className="clean-list">
          <li>
            <span className="clean-dot" />
            Central place for capabilities, memory layout, and execution policies.
          </li>
          <li>
            <span className="clean-dot" style={{ background: '#a78bfa' }} />
            Consistent integration patterns for CRM, tickets, docs, and code hosts.
          </li>
          <li>
            <span className="clean-dot" style={{ background: '#00c8f8' }} />
            Easier to sunset experiments without losing audit history.
          </li>
        </ul>
      </div>
      <div className="focus-visual">
        <div className="hero-visual-card" style={{ padding: 24 }}>
          <svg viewBox="0 0 520 360" width="100%" height="100%">
            <rect x="30" y="40" width="460" height="70" rx="14" fill="rgba(0,200,248,0.1)" stroke="rgba(0,200,248,0.35)" strokeWidth="2" />
            <text x="260" y="82" textAnchor="middle" fill="#f0f6ff" fontSize="17" fontWeight="800" fontFamily="Inter, system-ui, sans-serif">
              Shared Connector spine
            </text>
            <text x="260" y="265" textAnchor="middle" fill="#4a6077" fontSize="12" fontFamily="Inter, system-ui, sans-serif">
              Many surfaces · one policy &amp; memory contract
            </text>
            <path d="M 120 110 L 120 145 M 260 110 L 260 145 M 400 110 L 400 145" stroke="#3a6387" strokeWidth="2" />
            <path d="M 120 145 L 120 175 L 400 175 L 400 145" fill="none" stroke="#3a6387" strokeWidth="2" />
            {[
              { x: 70, label: 'Support bot' },
              { x: 210, label: 'Sales copilot' },
              { x: 350, label: 'Eng assistant' },
            ].map((b) => (
              <g key={b.label}>
                <rect x={b.x} y="185" width="120" height="56" rx="12" fill="rgba(255,255,255,0.04)" stroke="rgba(255,255,255,0.12)" strokeWidth="1.5" />
                <text x={b.x + 60} y="218" textAnchor="middle" fill="#8ba4be" fontSize="13" fontWeight="600" fontFamily="Inter, system-ui, sans-serif">
                  {b.label}
                </text>
              </g>
            ))}
          </svg>
        </div>
      </div>
    </SlideShell>
  );
}

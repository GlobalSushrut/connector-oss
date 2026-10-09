import SlideShell from './SlideShell';

export default function Slide16() {
  return (
    <SlideShell sid="s16" contentClassName="slide-content left-focus-layout pdf-safe">
      <div className="focus-stack">
        <div className="tag">Workflow pattern</div>
        <h1 className="slide-title slide-title-sm">APIs, events, and system-to-system calls</h1>
        <p className="slide-sub">
          Agents are not only chat. They are webhooks, scheduled jobs, and microservices issuing tool calls—each needs the same control envelope.
        </p>
        <ul className="clean-list">
          <li>
            <span className="clean-dot" />
            Event buses and queues can hand work to Connector-shaped workers with stable ids.
          </li>
          <li>
            <span className="clean-dot" style={{ background: '#10d98a' }} />
            Partner APIs: throttle, attest outbound payloads, and document cross-org handoffs.
          </li>
        </ul>
      </div>
      <div className="focus-visual">
        <div className="hero-visual-card" style={{ padding: 26 }}>
          <svg viewBox="0 0 520 320" width="100%">
            <rect x="40" y="50" width="120" height="56" rx="12" fill="rgba(167,139,250,0.12)" stroke="rgba(167,139,250,0.35)" strokeWidth="1.5" />
            <text x="100" y="84" textAnchor="middle" fill="#f0f6ff" fontSize="14" fontWeight="700" fontFamily="Inter, system-ui, sans-serif">
              Webhook
            </text>
            <rect x="40" y="150" width="120" height="56" rx="12" fill="rgba(167,139,250,0.12)" stroke="rgba(167,139,250,0.35)" strokeWidth="1.5" />
            <text x="100" y="184" textAnchor="middle" fill="#f0f6ff" fontSize="14" fontWeight="700" fontFamily="Inter, system-ui, sans-serif">
              Schedule
            </text>
            <path d="M 160 78 L 220 128 L 160 178" fill="none" stroke="#3a6387" strokeWidth="2" />
            <rect x="220" y="100" width="140" height="80" rx="16" fill="rgba(0,200,248,0.15)" stroke="rgba(0,200,248,0.45)" strokeWidth="2" />
            <text x="290" y="138" textAnchor="middle" fill="#f0f6ff" fontSize="15" fontWeight="800" fontFamily="Inter, system-ui, sans-serif">
              Connector
            </text>
            <text x="290" y="158" textAnchor="middle" fill="#00c8f8" fontSize="11" fontWeight="700" fontFamily="Inter, system-ui, sans-serif">
              API + events
            </text>
            <path d="M 360 140 L 420 140" stroke="#3a6387" strokeWidth="2" markerEnd="url(#s16m)" />
            <rect x="420" y="110" width="100" height="60" rx="12" fill="rgba(16,217,138,0.12)" stroke="rgba(16,217,138,0.35)" strokeWidth="1.5" />
            <text x="470" y="145" textAnchor="middle" fill="#f0f6ff" fontSize="13" fontWeight="700" fontFamily="Inter, system-ui, sans-serif">
              Downstream
            </text>
            <defs>
              <marker id="s16m" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
                <polygon points="0 0, 8 4, 0 8" fill="#3a6387" />
              </marker>
            </defs>
          </svg>
          <p style={{ fontSize: 14, color: '#8ba4be', lineHeight: 1.45, marginTop: 8 }}>
            Same durability story whether the caller is a human in Slack or a Lambda at 3 a.m.
          </p>
        </div>
      </div>
    </SlideShell>
  );
}

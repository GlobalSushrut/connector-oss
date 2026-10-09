import SlideShell from './SlideShell';
import { archDiagramTag } from './archTag';

export default function Slide1() {
  return (
    <SlideShell sid="s01" contentClassName="slide-content diagram-arch-layout pdf-safe">
      <div className="tag">{archDiagramTag(1)}</div>
      <h1 className="slide-title slide-title-sm">
        Where <span className="accent-blue">Connector</span> sits in your stack
      </h1>
      <p className="slide-sub" style={{ maxWidth: '72ch' }}>
        AI agents act; Connector is the governed runtime in the middle—between models and tools and the systems your business already trusts.
      </p>
      <div className="diagram-arch-body">
        <div className="hero-visual-card">
          <svg viewBox="0 0 1100 440" width="100%" height="100%" xmlns="http://www.w3.org/2000/svg" style={{ maxHeight: 420 }}>
            <defs>
              <marker id="s01-m" markerWidth="10" markerHeight="10" refX="9" refY="5" orient="auto">
                <polygon points="0 0, 10 5, 0 10" fill="#3a6387" />
              </marker>
            </defs>
            <rect x="40" y="24" width="1020" height="88" rx="18" fill="rgba(244,63,94,0.08)" stroke="rgba(244,63,94,0.35)" strokeWidth="2" />
            <text x="550" y="58" textAnchor="middle" fill="#f0f6ff" fontSize="22" fontWeight="800" fontFamily="Inter, system-ui, sans-serif">
              Models &amp; agents
            </text>
            <text x="550" y="88" textAnchor="middle" fill="#f43f5e" fontSize="14" fontFamily="Inter, system-ui, sans-serif">
              LLMs · planners · tool-callers · autonomous workflows
            </text>
            <path d="M 550 112 L 550 142" stroke="#3a6387" strokeWidth="3" markerEnd="url(#s01-m)" />
            <rect x="40" y="142" width="1020" height="128" rx="22" fill="rgba(0,200,248,0.12)" stroke="rgba(0,200,248,0.55)" strokeWidth="3" />
            <text x="550" y="182" textAnchor="middle" fill="#f0f6ff" fontSize="28" fontWeight="800" fontFamily="Inter, system-ui, sans-serif">
              CONNECTOR
            </text>
            <text x="550" y="218" textAnchor="middle" fill="#00c8f8" fontSize="15" fontWeight="700" fontFamily="Inter, system-ui, sans-serif" letterSpacing="0.12em">
              CONTROL · MEMORY · POLICY · PROOF
            </text>
            <text x="550" y="248" textAnchor="middle" fill="#8ba4be" fontSize="13" fontFamily="Inter, system-ui, sans-serif">
              Runtime that records what happened, enforces gates, and hands you evidence—not vibes.
            </text>
            <path d="M 550 270 L 550 300" stroke="#3a6387" strokeWidth="3" markerEnd="url(#s01-m)" />
            <rect x="40" y="300" width="1020" height="112" rx="18" fill="rgba(16,217,138,0.08)" stroke="rgba(16,217,138,0.35)" strokeWidth="2" />
            <text x="550" y="338" textAnchor="middle" fill="#f0f6ff" fontSize="22" fontWeight="800" fontFamily="Inter, system-ui, sans-serif">
              Enterprise reality
            </text>
            <text x="550" y="368" textAnchor="middle" fill="#10d98a" fontSize="14" fontFamily="Inter, system-ui, sans-serif">
              Identity · data stores · line-of-business apps · tickets · CRM · audit repositories
            </text>
            <text x="550" y="398" textAnchor="middle" fill="#4a6077" fontSize="12" fontFamily="Inter, system-ui, sans-serif">
              Systems that must see defensible records when AI touches production data
            </text>
          </svg>
        </div>
      </div>
    </SlideShell>
  );
}

import SlideShell from './SlideShell';
import { archDiagramTag } from './archTag';

export default function Slide4() {
  return (
    <SlideShell sid="s04" contentClassName="slide-content diagram-arch-layout pdf-safe">
      <div className="tag">{archDiagramTag(4)}</div>
      <h1 className="slide-title slide-title-sm">Two kernels, one coherent runtime</h1>
      <p className="slide-sub" style={{ maxWidth: '72ch' }}>
        <strong style={{ color: '#f0f6ff' }}>Memory</strong> answers “what do we know, with lineage?” · <strong style={{ color: '#f0f6ff' }}>Actions</strong> answer “what are we allowed to do, with receipts?”
      </p>
      <div className="diagram-arch-body">
        <div className="hero-visual-card" style={{ padding: '14px 28px' }}>
          <svg viewBox="0 0 1040 400" width="100%" height="100%" style={{ maxHeight: 400 }}>
            <defs>
              <marker id="s04-m" markerWidth="10" markerHeight="10" refX="9" refY="5" orient="auto">
                <polygon points="0 0, 10 5, 0 10" fill="#3a6387" />
              </marker>
            </defs>
            <rect x="20" y="40" width="480" height="320" rx="22" fill="rgba(124,58,237,0.08)" stroke="rgba(167,139,250,0.4)" strokeWidth="2" />
            <text x="260" y="86" textAnchor="middle" fill="#a78bfa" fontSize="13" fontWeight="800" letterSpacing="0.14em" fontFamily="Inter, system-ui, sans-serif">
              MEMORY KERNEL (VAC)
            </text>
            <text x="260" y="120" textAnchor="middle" fill="#f0f6ff" fontSize="22" fontWeight="800" fontFamily="Inter, system-ui, sans-serif">
              Durable, queryable state
            </text>
            <text x="260" y="155" textAnchor="middle" fill="#8ba4be" fontSize="15" fontFamily="Inter, system-ui, sans-serif">
              Structured packets · namespaces · Merkle-friendly stores
            </text>
            <text x="260" y="195" textAnchor="middle" fill="#8ba4be" fontSize="15" fontFamily="Inter, system-ui, sans-serif">
              Audit entries per syscall—not a vague chat log
            </text>
            <text x="260" y="250" textAnchor="middle" fill="#4a6077" fontSize="13" fontFamily="Inter, system-ui, sans-serif" fontStyle="italic">
              Great for grounding, replay, and forensic narrative
            </text>

            <rect x="540" y="40" width="480" height="320" rx="22" fill="rgba(16,217,138,0.08)" stroke="rgba(16,217,138,0.4)" strokeWidth="2" />
            <text x="780" y="86" textAnchor="middle" fill="#10d98a" fontSize="13" fontWeight="800" letterSpacing="0.14em" fontFamily="Inter, system-ui, sans-serif">
              ACTION KERNEL (AAPI)
            </text>
            <text x="780" y="120" textAnchor="middle" fill="#f0f6ff" fontSize="22" fontWeight="800" fontFamily="Inter, system-ui, sans-serif">
              Governed execution
            </text>
            <text x="780" y="155" textAnchor="middle" fill="#8ba4be" fontSize="15" fontFamily="Inter, system-ui, sans-serif">
              Capabilities · pipelines · adapters to HTTP / DB / files
            </text>
            <text x="780" y="195" textAnchor="middle" fill="#8ba4be" fontSize="15" fontFamily="Inter, system-ui, sans-serif">
              Cryptographic hooks for “this action was authorized”
            </text>
            <text x="780" y="250" textAnchor="middle" fill="#4a6077" fontSize="13" fontFamily="Inter, system-ui, sans-serif" fontStyle="italic">
              Great for least privilege and integration safety
            </text>

            <rect x="430" y="160" width="180" height="80" rx="16" fill="rgba(0,200,248,0.2)" stroke="rgba(0,200,248,0.55)" strokeWidth="2.5" />
            <text x="520" y="195" textAnchor="middle" fill="#f0f6ff" fontSize="16" fontWeight="800" fontFamily="Inter, system-ui, sans-serif">
              CONNECTOR
            </text>
            <text x="520" y="220" textAnchor="middle" fill="#00c8f8" fontSize="12" fontWeight="700" fontFamily="Inter, system-ui, sans-serif">
              orchestrates both
            </text>
            <path d="M 260 200 L 430 200" stroke="#3a6387" strokeWidth="2.5" markerEnd="url(#s04-m)" />
            <path d="M 610 200 L 780 200" stroke="#3a6387" strokeWidth="2.5" markerEnd="url(#s04-m)" />
          </svg>
        </div>
      </div>
    </SlideShell>
  );
}

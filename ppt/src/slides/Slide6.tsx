export default function Slide6() {
  return (
    <div className="slide">
      <svg className="slide-bg" viewBox="0 0 1280 720" xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="xMidYMid slice">
        <defs>
          <radialGradient id="s6g" cx="30%" cy="46%" r="60%"><stop offset="0%" stopColor="#0d1c16"/><stop offset="100%" stopColor="#06111e"/></radialGradient>
          <pattern id="s6grid" width="64" height="64" patternUnits="userSpaceOnUse"><path d="M64 0L0 0 0 64" fill="none" stroke="#11263c" strokeWidth="1"/></pattern>
        </defs>
        <rect width="1280" height="720" fill="url(#s6g)"/>
        <rect width="1280" height="720" fill="url(#s6grid)" opacity="0.42"/>
      </svg>
      <div className="slide-content left-focus-layout pdf-safe">
        <div className="focus-stack">
          <div className="tag">06 · TECH</div>
          <h1 className="slide-title">The product feels simple because the technical depth is <span className="accent-green">hidden behind one layer</span></h1>
          <p className="slide-sub">Do not lead with 28 crates and 5 rings. Lead with one technical moat that delivers control, proof, and self-hosting in the same system.</p>
          <div className="wide-panel">
            <div className="wide-panel-title">Technical positioning</div>
            <div className="wide-panel-copy">This is infrastructure that sits under agent behavior and makes production AI defensible.</div>
          </div>
        </div>
        <div className="focus-visual">
          <div className="hero-visual-card" style={{display:'flex', alignItems:'center', justifyContent:'center', width:'100%'}}>
            <svg viewBox="0 0 580 420" width="100%" height="100%" xmlns="http://www.w3.org/2000/svg" style={{ maxWidth: '100%', maxHeight: '100%' }}>
              {/* Stack architecture - layered */}
              
              {/* Layer 4 - Application */}
              <rect x="72" y="60" width="396" height="60" rx="14" fill="rgba(139,164,190,0.08)" stroke="rgba(139,164,190,0.3)" strokeWidth="2"/>
              <text x="290" y="85" textAnchor="middle" fill="#f0f6ff" fontSize="16" fontWeight="700" fontFamily="Inter, sans-serif">Application Layer</text>
              <text x="290" y="103" textAnchor="middle" fill="#8ba4be" fontSize="12" fontFamily="Inter, sans-serif">Your AI agents · Tools · Workflows</text>
              
              {/* Arrow */}
              <path d="M 290 120 L 290 135" stroke="#3a6387" strokeWidth="2" markerEnd="url(#arrow6)"/>
              
              {/* Layer 3 - Control Plane (highlighted) */}
              <rect x="62" y="135" width="432" height="80" rx="16" fill="rgba(0,200,248,0.15)" stroke="rgba(0,200,248,0.5)" strokeWidth="3"/>
              <circle cx="62" cy="175" r="5" fill="#00c8f8"/>
              <circle cx="494" cy="175" r="5" fill="#00c8f8"/>
              <text x="290" y="165" textAnchor="middle" fill="#f0f6ff" fontSize="20" fontWeight="800" fontFamily="Inter, sans-serif">CONNECTOR CONTROL PLANE</text>
              <text x="290" y="188" textAnchor="middle" fill="#00c8f8" fontSize="13" fontWeight="700" fontFamily="Inter, sans-serif" letterSpacing="0.08em">MEMORY · POLICY · PROOF ENGINE</text>
              <text x="290" y="204" textAnchor="middle" fill="#8ba4be" fontSize="11" fontFamily="Inter, sans-serif">150K+ lines Rust · 1,700+ tests · 228+ API routes</text>
              
              {/* Arrow */}
              <path d="M 290 215 L 290 230" stroke="#3a6387" strokeWidth="2" markerEnd="url(#arrow6)"/>
              
              {/* Layer 2 - Storage */}
              <rect x="72" y="230" width="396" height="60" rx="14" fill="rgba(167,139,250,0.08)" stroke="rgba(167,139,250,0.3)" strokeWidth="2"/>
              <text x="290" y="255" textAnchor="middle" fill="#f0f6ff" fontSize="16" fontWeight="700" fontFamily="Inter, sans-serif">Tamper-Resistant Storage</text>
              <text x="290" y="273" textAnchor="middle" fill="#a78bfa" fontSize="12" fontFamily="Inter, sans-serif">Cryptographic proofs · Audit trails · Immutable logs</text>
              
              {/* Arrow */}
              <path d="M 290 290 L 290 305" stroke="#3a6387" strokeWidth="2" markerEnd="url(#arrow6)"/>
              
              {/* Layer 1 - Infrastructure */}
              <rect x="92" y="305" width="356" height="60" rx="14" fill="rgba(16,217,138,0.08)" stroke="rgba(16,217,138,0.3)" strokeWidth="2"/>
              <text x="290" y="330" textAnchor="middle" fill="#f0f6ff" fontSize="16" fontWeight="700" fontFamily="Inter, sans-serif">Self-Hosted Infrastructure</text>
              <text x="290" y="348" textAnchor="middle" fill="#10d98a" fontSize="12" fontFamily="Inter, sans-serif">On-prem · VPC · Air-gapped deployment options</text>
            
              <defs>
                <marker id="arrow6" markerWidth="8" markerHeight="8" refX="4" refY="4" orient="auto">
                  <polygon points="0 0, 8 4, 0 8" fill="#3a6387"/>
                </marker>
              </defs>
            </svg>
          </div>
        </div>
      </div>
    </div>
  );
}

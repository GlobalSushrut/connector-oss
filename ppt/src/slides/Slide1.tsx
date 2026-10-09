export default function Slide1() {
  return (
    <div className="slide">
      <svg className="slide-bg" viewBox="0 0 1280 720" xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="xMidYMid slice">
        <defs>
          <radialGradient id="s1g1" cx="24%" cy="34%" r="58%"><stop offset="0%" stopColor="#0d2238"/><stop offset="100%" stopColor="#06111e"/></radialGradient>
          <pattern id="s1grid" width="64" height="64" patternUnits="userSpaceOnUse"><path d="M64 0L0 0 0 64" fill="none" stroke="#11263c" strokeWidth="1"/></pattern>
        </defs>
        <rect width="1280" height="720" fill="url(#s1g1)"/>
        <rect width="1280" height="720" fill="url(#s1grid)" opacity="0.42"/>
      </svg>
      <div className="slide-content left-focus-layout pdf-safe">
        <div className="focus-stack">
          <div className="tag">01 · TITLE</div>
          <div className="hero-kicker">Connector</div>
          <h1 className="slide-title">The <span className="accent-blue">control plane for AI agents</span></h1>
          <div className="calm-quote">Control AI agents. Prove what happened.</div>
          <p className="slide-sub">Built for teams that need visible execution, hard controls, and defensible records in high-risk or regulated environments.</p>
          <div className="stat-strip">
            <div className="stat-pill"><strong>Category</strong>AI control plane</div>
            <div className="stat-pill"><strong>Buyer</strong>Platform, security, compliance</div>
          </div>
          <div className="hero-stats">
            <div className="hero-stat"><strong>150K+</strong><span>lines of production Rust</span></div>
            <div className="hero-stat"><strong>1,700+</strong><span>tests in place</span></div>
            <div className="hero-stat"><strong>228+</strong><span>API routes</span></div>
          </div>
        </div>
        <div className="focus-visual">
          <div className="hero-visual-card" style={{display:'flex', alignItems:'center', justifyContent:'center', width:'100%'}}>
            <svg viewBox="0 0 580 420" width="100%" height="100%" xmlns="http://www.w3.org/2000/svg" style={{ maxWidth: '100%', maxHeight: '100%' }}>
              {/* Architecture layers */}
              <rect x="40" y="80" width="500" height="80" rx="16" fill="rgba(244,63,94,0.08)" stroke="rgba(244,63,94,0.3)" strokeWidth="2"/>
              <text x="290" y="110" textAnchor="middle" fill="#f0f6ff" fontSize="20" fontWeight="700" fontFamily="Inter, sans-serif">AI Agent Layer</text>
              <text x="290" y="135" textAnchor="middle" fill="#f43f5e" fontSize="14" fontFamily="Inter, sans-serif">Autonomous actions · Tool calls · Memory access</text>
              
              {/* Arrow down */}
              <path d="M 290 160 L 290 185" stroke="#3a6387" strokeWidth="3" markerEnd="url(#arrowhead1)"/>
              
              {/* Control plane - highlighted */}
              <rect x="40" y="185" width="500" height="100" rx="20" fill="rgba(0,200,248,0.15)" stroke="rgba(0,200,248,0.5)" strokeWidth="3"/>
              <circle cx="40" cy="235" r="6" fill="#00c8f8"/>
              <circle cx="540" cy="235" r="6" fill="#00c8f8"/>
              <text x="290" y="220" textAnchor="middle" fill="#f0f6ff" fontSize="24" fontWeight="800" fontFamily="Inter, sans-serif">CONNECTOR</text>
              <text x="290" y="245" textAnchor="middle" fill="#00c8f8" fontSize="15" fontWeight="700" fontFamily="Inter, sans-serif" letterSpacing="0.08em">CONTROL · MEMORY · PROOF</text>
              <text x="290" y="268" textAnchor="middle" fill="#8ba4be" fontSize="12" fontFamily="Inter, sans-serif">Runtime control plane for AI systems</text>
              
              {/* Arrow down */}
              <path d="M 290 285 L 290 310" stroke="#3a6387" strokeWidth="3" markerEnd="url(#arrowhead1)"/>
              
              {/* Output layer */}
              <rect x="40" y="310" width="500" height="80" rx="16" fill="rgba(16,217,138,0.08)" stroke="rgba(16,217,138,0.3)" strokeWidth="2"/>
              <text x="290" y="340" textAnchor="middle" fill="#f0f6ff" fontSize="20" fontWeight="700" fontFamily="Inter, sans-serif">Enterprise Teams</text>
              <text x="290" y="365" textAnchor="middle" fill="#10d98a" fontSize="14" fontFamily="Inter, sans-serif">Audit-ready records · Compliance proof · Cost control</text>
              
              {/* Arrow marker */}
              <defs>
                <marker id="arrowhead1" markerWidth="10" markerHeight="10" refX="5" refY="5" orient="auto">
                  <polygon points="0 0, 10 5, 0 10" fill="#3a6387"/>
                </marker>
              </defs>
            </svg>
          </div>
        </div>
      </div>
    </div>
  );
}

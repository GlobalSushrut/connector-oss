export default function Slide2() {
  return (
    <div className="slide">
      <svg className="slide-bg" viewBox="0 0 1280 720" xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="xMidYMid slice">
        <defs>
          <radialGradient id="s2g" cx="60%" cy="28%" r="60%"><stop offset="0%" stopColor="#101b2f"/><stop offset="100%" stopColor="#06111e"/></radialGradient>
          <pattern id="s2grid" width="64" height="64" patternUnits="userSpaceOnUse"><path d="M64 0L0 0 0 64" fill="none" stroke="#11263c" strokeWidth="1"/></pattern>
        </defs>
        <rect width="1280" height="720" fill="url(#s2g)"/>
        <rect width="1280" height="720" fill="url(#s2grid)" opacity="0.42"/>
      </svg>
      <div className="slide-content left-focus-layout pdf-safe">
        <div className="focus-stack">
          <div className="tag">02 · THE PROBLEM</div>
          <h1 className="slide-title">AI agents are getting deployed faster than teams can <span className="accent-red">control or explain them</span></h1>
          <p className="slide-sub">Frameworks make LLM calls easy. They do not make risky behavior controllable, explainable, or provable after the fact.</p>
          <div className="stat-strip">
            <div className="stat-pill"><strong>Gap</strong>no control plane</div>
            <div className="stat-pill"><strong>Result</strong>risk, cost, weak trust</div>
          </div>
        </div>
        <div className="focus-visual">
          <div className="hero-visual-card" style={{display:'flex', alignItems:'center', justifyContent:'center', width:'100%'}}>
            <svg viewBox="0 0 580 420" width="100%" height="100%" xmlns="http://www.w3.org/2000/svg" style={{ maxWidth: '100%', maxHeight: '100%' }}>
              {/* Without Connector - top half */}
              <text x="290" y="50" textAnchor="middle" fill="#f43f5e" fontSize="13" fontWeight="800" fontFamily="Inter, sans-serif" letterSpacing="0.15em">WITHOUT CONNECTOR</text>
              
              <rect x="80" y="70" width="140" height="70" rx="14" fill="rgba(255,255,255,0.03)" stroke="rgba(255,255,255,0.1)" strokeWidth="1.5"/>
              <text x="150" y="100" textAnchor="middle" fill="#f0f6ff" fontSize="16" fontWeight="700" fontFamily="Inter, sans-serif">AI Agent</text>
              <text x="150" y="120" textAnchor="middle" fill="#8ba4be" fontSize="11" fontFamily="Inter, sans-serif">opaque</text>
              
              <path d="M 220 105 L 260 105" stroke="#f43f5e" strokeWidth="2" strokeDasharray="4 4"/>
              <circle cx="270" cy="105" r="4" fill="#f43f5e"/>
              
              <rect x="280" y="70" width="220" height="70" rx="14" fill="rgba(244,63,94,0.08)" stroke="rgba(244,63,94,0.3)" strokeWidth="2"/>
              <text x="390" y="95" textAnchor="middle" fill="#f0f6ff" fontSize="15" fontWeight="700" fontFamily="Inter, sans-serif">Production</text>
              <text x="390" y="113" textAnchor="middle" fill="#f43f5e" fontSize="11" fontFamily="Inter, sans-serif">✗ No proof</text>
              <text x="390" y="128" textAnchor="middle" fill="#f43f5e" fontSize="11" fontFamily="Inter, sans-serif">✗ No control</text>
              
              {/* Divider */}
              <line x1="40" y1="180" x2="540" y2="180" stroke="rgba(0,200,248,0.3)" strokeWidth="2"/>
              
              {/* With Connector - bottom half */}
              <text x="290" y="210" textAnchor="middle" fill="#10d98a" fontSize="13" fontWeight="800" fontFamily="Inter, sans-serif" letterSpacing="0.15em">WITH CONNECTOR</text>
              
              <rect x="40" y="230" width="120" height="60" rx="12" fill="rgba(255,255,255,0.03)" stroke="rgba(255,255,255,0.1)" strokeWidth="1.5"/>
              <text x="100" y="255" textAnchor="middle" fill="#f0f6ff" fontSize="14" fontWeight="700" fontFamily="Inter, sans-serif">AI Agent</text>
              <text x="100" y="273" textAnchor="middle" fill="#8ba4be" fontSize="10" fontFamily="Inter, sans-serif">visible</text>
              
              <path d="M 160 260 L 200 260" stroke="#00c8f8" strokeWidth="3"/>
              <circle cx="210" cy="260" r="4" fill="#00c8f8"/>
              
              <rect x="210" y="230" width="160" height="60" rx="14" fill="rgba(0,200,248,0.15)" stroke="rgba(0,200,248,0.5)" strokeWidth="2.5"/>
              <text x="290" y="253" textAnchor="middle" fill="#f0f6ff" fontSize="16" fontWeight="800" fontFamily="Inter, sans-serif">CONNECTOR</text>
              <text x="290" y="272" textAnchor="middle" fill="#00c8f8" fontSize="11" fontWeight="700" fontFamily="Inter, sans-serif">Control · Proof</text>
              
              <path d="M 370 260 L 410 260" stroke="#10d98a" strokeWidth="3"/>
              <circle cx="420" cy="260" r="4" fill="#10d98a"/>
              
              <rect x="420" y="230" width="120" height="60" rx="12" fill="rgba(16,217,138,0.08)" stroke="rgba(16,217,138,0.3)" strokeWidth="2"/>
              <text x="480" y="253" textAnchor="middle" fill="#f0f6ff" fontSize="14" fontWeight="700" fontFamily="Inter, sans-serif">Production</text>
              <text x="480" y="271" textAnchor="middle" fill="#10d98a" fontSize="10" fontFamily="Inter, sans-serif">✓ Defensible</text>
              
              {/* Key outcomes */}
              <rect x="80" y="320" width="140" height="70" rx="12" fill="rgba(0,200,248,0.06)" stroke="rgba(0,200,248,0.2)" strokeWidth="1.5"/>
              <text x="150" y="345" textAnchor="middle" fill="#00c8f8" fontSize="13" fontWeight="700" fontFamily="Inter, sans-serif">Observe</text>
              <text x="150" y="363" textAnchor="middle" fill="#8ba4be" fontSize="10" fontFamily="Inter, sans-serif">See what happened</text>
              <text x="150" y="378" textAnchor="middle" fill="#8ba4be" fontSize="10" fontFamily="Inter, sans-serif">Debug faster</text>
              
              <rect x="240" y="320" width="140" height="70" rx="12" fill="rgba(167,139,250,0.06)" stroke="rgba(167,139,250,0.2)" strokeWidth="1.5"/>
              <text x="310" y="345" textAnchor="middle" fill="#a78bfa" fontSize="13" fontWeight="700" fontFamily="Inter, sans-serif">Enforce</text>
              <text x="310" y="363" textAnchor="middle" fill="#8ba4be" fontSize="10" fontFamily="Inter, sans-serif">Block bad actions</text>
              <text x="310" y="378" textAnchor="middle" fill="#8ba4be" fontSize="10" fontFamily="Inter, sans-serif">Control costs</text>
              
              <rect x="400" y="320" width="140" height="70" rx="12" fill="rgba(16,217,138,0.06)" stroke="rgba(16,217,138,0.2)" strokeWidth="1.5"/>
              <text x="470" y="345" textAnchor="middle" fill="#10d98a" fontSize="13" fontWeight="700" fontFamily="Inter, sans-serif">Prove</text>
              <text x="470" y="363" textAnchor="middle" fill="#8ba4be" fontSize="10" fontFamily="Inter, sans-serif">Tamper-proof logs</text>
              <text x="470" y="378" textAnchor="middle" fill="#8ba4be" fontSize="10" fontFamily="Inter, sans-serif">Audit ready</text>
            </svg>
          </div>
        </div>
      </div>
    </div>
  );
}

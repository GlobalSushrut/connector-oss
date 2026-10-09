export default function Slide10() {
  return (
    <div className="slide">
      <svg className="slide-bg" viewBox="0 0 1280 720" xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="xMidYMid slice">
        <defs>
          <radialGradient id="s10g" cx="48%" cy="52%" r="62%"><stop offset="0%" stopColor="#0e1a28"/><stop offset="100%" stopColor="#06111e"/></radialGradient>
          <pattern id="s10grid" width="64" height="64" patternUnits="userSpaceOnUse"><path d="M64 0L0 0 0 64" fill="none" stroke="#11263c" strokeWidth="1"/></pattern>
        </defs>
        <rect width="1280" height="720" fill="url(#s10g)"/>
        <rect width="1280" height="720" fill="url(#s10grid)" opacity="0.42"/>
      </svg>
      <div className="slide-content left-focus-layout pdf-safe">
        <div className="focus-stack">
          <div className="tag">10 · COMPETITIVE POSITION</div>
          <h1 className="slide-title">Most tools give you observability.<br/><span className="accent-blue">We give you control and proof.</span></h1>
          <p className="slide-sub">The competitive moat is not "better dashboards." It is tamper-resistant memory, hard policy enforcement, and self-hosted deployment for regulated buyers.</p>
          <div className="wide-panel">
            <div className="wide-panel-title">Differentiation</div>
            <div className="wide-panel-copy">Observability tools see what happened. Connector controls what can happen and proves what happened afterward.</div>
          </div>
        </div>
        <div className="focus-visual">
          <div className="hero-visual-card" style={{display:'flex', alignItems:'center', justifyContent:'center', width:'100%'}}>
            <svg viewBox="0 0 580 420" width="100%" height="100%" xmlns="http://www.w3.org/2000/svg" style={{ maxWidth: '100%', maxHeight: '100%' }}>
              {/* Comparison matrix */}
              
              {/* Header row */}
              <text x="60" y="70" fill="#8ba4be" fontSize="12" fontWeight="700" fontFamily="Inter, sans-serif">Feature</text>
              <text x="260" y="70" textAnchor="middle" fill="#f43f5e" fontSize="12" fontWeight="700" fontFamily="Inter, sans-serif">Observability Tools</text>
              <text x="460" y="70" textAnchor="middle" fill="#10d98a" fontSize="12" fontWeight="700" fontFamily="Inter, sans-serif">Connector</text>
              
              <line x1="40" y1="80" x2="540" y2="80" stroke="rgba(255,255,255,0.15)" strokeWidth="2"/>
              
              {/* Row 1: Visibility */}
              <rect x="40" y="90" width="180" height="50" rx="10" fill="rgba(255,255,255,0.02)" stroke="rgba(255,255,255,0.08)" strokeWidth="1"/>
              <text x="130" y="112" textAnchor="middle" fill="#f0f6ff" fontSize="13" fontWeight="700" fontFamily="Inter, sans-serif">Visibility</text>
              <text x="130" y="128" textAnchor="middle" fill="#8ba4be" fontSize="10" fontFamily="Inter, sans-serif">See agent actions</text>
              
              <rect x="230" y="90" width="60" height="50" rx="10" fill="rgba(0,200,248,0.08)" stroke="rgba(0,200,248,0.3)" strokeWidth="1.5"/>
              <text x="260" y="122" textAnchor="middle" fill="#00c8f8" fontSize="18" fontWeight="700" fontFamily="Inter, sans-serif">✓</text>
              
              <rect x="430" y="90" width="60" height="50" rx="10" fill="rgba(16,217,138,0.12)" stroke="rgba(16,217,138,0.4)" strokeWidth="2"/>
              <text x="460" y="122" textAnchor="middle" fill="#10d98a" fontSize="18" fontWeight="700" fontFamily="Inter, sans-serif">✓</text>
              
              {/* Row 2: Control */}
              <rect x="40" y="150" width="180" height="50" rx="10" fill="rgba(255,255,255,0.02)" stroke="rgba(255,255,255,0.08)" strokeWidth="1"/>
              <text x="130" y="172" textAnchor="middle" fill="#f0f6ff" fontSize="13" fontWeight="700" fontFamily="Inter, sans-serif">Hard Control</text>
              <text x="130" y="188" textAnchor="middle" fill="#8ba4be" fontSize="10" fontFamily="Inter, sans-serif">Block bad actions</text>
              
              <rect x="230" y="150" width="60" height="50" rx="10" fill="rgba(244,63,94,0.08)" stroke="rgba(244,63,94,0.3)" strokeWidth="1.5"/>
              <text x="260" y="182" textAnchor="middle" fill="#f43f5e" fontSize="18" fontWeight="700" fontFamily="Inter, sans-serif">✗</text>
              
              <rect x="430" y="150" width="60" height="50" rx="10" fill="rgba(16,217,138,0.12)" stroke="rgba(16,217,138,0.4)" strokeWidth="2"/>
              <text x="460" y="182" textAnchor="middle" fill="#10d98a" fontSize="18" fontWeight="700" fontFamily="Inter, sans-serif">✓</text>
              
              {/* Row 3: Tamper-proof */}
              <rect x="40" y="210" width="180" height="50" rx="10" fill="rgba(255,255,255,0.02)" stroke="rgba(255,255,255,0.08)" strokeWidth="1"/>
              <text x="130" y="232" textAnchor="middle" fill="#f0f6ff" fontSize="13" fontWeight="700" fontFamily="Inter, sans-serif">Tamper-Proof</text>
              <text x="130" y="248" textAnchor="middle" fill="#8ba4be" fontSize="10" fontFamily="Inter, sans-serif">Cryptographic proof</text>
              
              <rect x="230" y="210" width="60" height="50" rx="10" fill="rgba(244,63,94,0.08)" stroke="rgba(244,63,94,0.3)" strokeWidth="1.5"/>
              <text x="260" y="242" textAnchor="middle" fill="#f43f5e" fontSize="18" fontWeight="700" fontFamily="Inter, sans-serif">✗</text>
              
              <rect x="430" y="210" width="60" height="50" rx="10" fill="rgba(16,217,138,0.12)" stroke="rgba(16,217,138,0.4)" strokeWidth="2"/>
              <text x="460" y="242" textAnchor="middle" fill="#10d98a" fontSize="18" fontWeight="700" fontFamily="Inter, sans-serif">✓</text>
              
              {/* Row 4: Self-hosted */}
              <rect x="40" y="270" width="180" height="50" rx="10" fill="rgba(255,255,255,0.02)" stroke="rgba(255,255,255,0.08)" strokeWidth="1"/>
              <text x="130" y="292" textAnchor="middle" fill="#f0f6ff" fontSize="13" fontWeight="700" fontFamily="Inter, sans-serif">Self-Hosted</text>
              <text x="130" y="308" textAnchor="middle" fill="#8ba4be" fontSize="10" fontFamily="Inter, sans-serif">On-prem / air-gap</text>
              
              <rect x="230" y="270" width="60" height="50" rx="10" fill="rgba(244,63,94,0.08)" stroke="rgba(244,63,94,0.3)" strokeWidth="1.5"/>
              <text x="260" y="302" textAnchor="middle" fill="#f43f5e" fontSize="18" fontWeight="700" fontFamily="Inter, sans-serif">✗</text>
              
              <rect x="430" y="270" width="60" height="50" rx="10" fill="rgba(16,217,138,0.12)" stroke="rgba(16,217,138,0.4)" strokeWidth="2"/>
              <text x="460" y="302" textAnchor="middle" fill="#10d98a" fontSize="18" fontWeight="700" fontFamily="Inter, sans-serif">✓</text>
              
              {/* Bottom summary */}
              <rect x="80" y="340" width="200" height="60" rx="12" fill="rgba(244,63,94,0.08)" stroke="rgba(244,63,94,0.3)" strokeWidth="2"/>
              <text x="180" y="362" textAnchor="middle" fill="#f43f5e" fontSize="14" fontWeight="700" fontFamily="Inter, sans-serif">Observability Only</text>
              <text x="180" y="380" textAnchor="middle" fill="#8ba4be" fontSize="11" fontFamily="Inter, sans-serif">See what happened</text>
              <text x="180" y="394" textAnchor="middle" fill="#8ba4be" fontSize="11" fontFamily="Inter, sans-serif">Cannot control outcomes</text>
              
              <rect x="300" y="340" width="200" height="60" rx="12" fill="rgba(16,217,138,0.12)" stroke="rgba(16,217,138,0.5)" strokeWidth="3"/>
              <text x="400" y="362" textAnchor="middle" fill="#10d98a" fontSize="14" fontWeight="700" fontFamily="Inter, sans-serif">Control + Proof</text>
              <text x="400" y="380" textAnchor="middle" fill="#10d98a" fontSize="11" fontWeight="700" fontFamily="Inter, sans-serif">Control what can happen</text>
              <text x="400" y="394" textAnchor="middle" fill="#10d98a" fontSize="11" fontWeight="700" fontFamily="Inter, sans-serif">Prove what happened</text>
            </svg>
          </div>
        </div>
      </div>
    </div>
  );
}

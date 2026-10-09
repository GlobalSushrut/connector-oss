export default function Slide9() {
  return (
    <div className="slide">
      <svg className="slide-bg" viewBox="0 0 1280 720" xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="xMidYMid slice">
        <defs>
          <radialGradient id="s9g1" cx="50%" cy="50%" r="70%"><stop offset="0%" stopColor="#0d1828"/><stop offset="100%" stopColor="#06111e"/></radialGradient>
          <pattern id="s9grid" width="64" height="64" patternUnits="userSpaceOnUse"><path d="M64 0L0 0 0 64" fill="none" stroke="#11263c" strokeWidth="1"/></pattern>
        </defs>
        <rect width="1280" height="720" fill="url(#s9g1)"/>
        <rect width="1280" height="720" fill="url(#s9grid)" opacity="0.42"/>
      </svg>
      <div className="slide-content left-focus-layout pdf-safe">
        <div className="focus-stack">
          <div className="tag">09 · GO-TO-MARKET</div>
          <h1 className="slide-title">Land with a painful technical problem.<br/><span className="accent-blue">Expand with governance.</span></h1>
          <p className="slide-sub">The first sale is not "buy an AI governance platform." The first sale is usually "fix cost, trace behavior, stabilize production agents, or satisfy a security/compliance blocker" inside a company that already feels the pain.</p>
          <div className="wide-panel">
            <div className="wide-panel-title">Presenter cue</div>
            <div className="wide-panel-copy">Lead with immediate operational value. Then position Connector as a Canadian company building the control and evidence layer those accounts standardize on once AI moves into regulated production.</div>
          </div>
        </div>
        <div className="focus-visual">
          <div className="hero-visual-card" style={{display:'flex', alignItems:'center', justifyContent:'center', width:'100%'}}>
            <svg viewBox="0 0 580 420" width="100%" height="100%" xmlns="http://www.w3.org/2000/svg" style={{ maxWidth: '100%', maxHeight: '100%' }}>
              <rect x="44" y="86" width="132" height="88" rx="18" fill="rgba(0,200,248,0.12)" stroke="rgba(0,200,248,0.42)" strokeWidth="2.4"/>
              <text x="64" y="112" fill="#00c8f8" fontSize="10.6" fontWeight="800" fontFamily="Inter, sans-serif">STAGE 1</text>
              <text x="64" y="140" fill="#eef6ff" fontSize="21" fontWeight="800" fontFamily="Inter, sans-serif">Land</text>
              <text x="64" y="160" fill="#8ba4be" fontSize="10.5" fontFamily="Inter, sans-serif">fix one blocker</text>

              <path d="M 176 130 L 214 130" stroke="#3a6387" strokeWidth="3" strokeLinecap="round"/>

              <rect x="214" y="86" width="138" height="88" rx="18" fill="rgba(167,139,250,0.12)" stroke="rgba(167,139,250,0.42)" strokeWidth="2.4"/>
              <text x="234" y="112" fill="#a78bfa" fontSize="10.6" fontWeight="800" fontFamily="Inter, sans-serif">STAGE 2</text>
              <text x="234" y="140" fill="#eef6ff" fontSize="21" fontWeight="800" fontFamily="Inter, sans-serif">Expand</text>
              <text x="234" y="160" fill="#8ba4be" fontSize="10.5" fontFamily="Inter, sans-serif">security teams</text>

              <path d="M 352 130 L 388 130" stroke="#3a6387" strokeWidth="3" strokeLinecap="round"/>

              <rect x="388" y="74" width="156" height="112" rx="20" fill="rgba(16,217,138,0.12)" stroke="rgba(16,217,138,0.42)" strokeWidth="2.4"/>
              <text x="408" y="102" fill="#10d98a" fontSize="10.6" fontWeight="800" fontFamily="Inter, sans-serif">STAGE 3</text>
              <text x="408" y="132" fill="#eef6ff" fontSize="22" fontWeight="800" fontFamily="Inter, sans-serif">Standardize</text>
              <text x="408" y="154" fill="#10d98a" fontSize="11.8" fontWeight="700" fontFamily="Inter, sans-serif">$100K-$500K ARR</text>

              <text x="290" y="236" textAnchor="middle" fill="#8ba4be" fontSize="11" fontWeight="800" fontFamily="Inter, sans-serif" letterSpacing="0.08em">ENTRY POINTS</text>

              <rect x="52" y="256" width="136" height="42" rx="12" fill="rgba(244,63,94,0.08)" stroke="rgba(244,63,94,0.28)" strokeWidth="1.8"/>
              <text x="120" y="281" textAnchor="middle" fill="#f43f5e" fontSize="11.4" fontWeight="700" fontFamily="Inter, sans-serif">Cost crisis</text>

              <rect x="202" y="256" width="136" height="42" rx="12" fill="rgba(0,200,248,0.08)" stroke="rgba(0,200,248,0.28)" strokeWidth="1.8"/>
              <text x="270" y="281" textAnchor="middle" fill="#00c8f8" fontSize="11.4" fontWeight="700" fontFamily="Inter, sans-serif">Debug trace</text>

              <rect x="352" y="256" width="136" height="42" rx="12" fill="rgba(245,158,11,0.08)" stroke="rgba(245,158,11,0.28)" strokeWidth="1.8"/>
              <text x="420" y="281" textAnchor="middle" fill="#f59e0b" fontSize="11.4" fontWeight="700" fontFamily="Inter, sans-serif">Compliance</text>
            </svg>
          </div>
        </div>
      </div>
    </div>
  );
}

export default function Slide8() {
  return (
    <div className="slide">
      <svg className="slide-bg" viewBox="0 0 1280 720" xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="xMidYMid slice">
        <defs>
          <radialGradient id="s8g" cx="52%" cy="48%" r="60%"><stop offset="0%" stopColor="#0d1727"/><stop offset="100%" stopColor="#06111e"/></radialGradient>
          <pattern id="s8grid" width="64" height="64" patternUnits="userSpaceOnUse"><path d="M64 0L0 0 0 64" fill="none" stroke="#11263c" strokeWidth="1"/></pattern>
        </defs>
        <rect width="1280" height="720" fill="url(#s8g)"/>
        <rect width="1280" height="720" fill="url(#s8grid)" opacity="0.42"/>
      </svg>
      <div className="slide-content left-focus-layout pdf-safe">
        <div className="focus-stack">
          <div className="tag">08 · MARKET VALIDATION</div>
          <h1 className="slide-title">The market is not hypothetical.<br/><span className="accent-blue">The need is already visible.</span></h1>
          <p className="slide-sub">Enterprise signals are already visible: AI adoption is rising, regulatory audits are starting, and LLM cost overruns are now a budget problem.</p>
          <div className="wide-panel">
            <div className="wide-panel-title">Bottom line</div>
            <div className="wide-panel-copy">Connector is not inventing a new market. It is packaging a response to adoption growth, enforcement pressure, and already-funded operational pain.</div>
          </div>
        </div>
        <div className="focus-visual">
          <div className="hero-visual-card" style={{display:'flex', alignItems:'center', justifyContent:'center', width:'100%'}}>
            <svg viewBox="0 0 580 420" width="100%" height="100%" xmlns="http://www.w3.org/2000/svg" style={{ maxWidth: '100%', maxHeight: '100%' }}>
              <text x="74" y="84" fill="#8ba4be" fontSize="9.4" fontWeight="800" fontFamily="Inter, sans-serif" letterSpacing="0.12em">WHY BUDGET ALREADY EXISTS</text>

              <rect x="64" y="112" width="214" height="52" rx="16" fill="rgba(255,255,255,0.03)" stroke="rgba(255,255,255,0.06)" strokeWidth="1.2"/>
              <circle cx="88" cy="138" r="5" fill="#00c8f8"/>
              <text x="102" y="132" fill="#00c8f8" fontSize="9.2" fontWeight="800" fontFamily="Inter, sans-serif">ADOPTION</text>
              <text x="102" y="148" fill="#eef6ff" fontSize="15.8" fontWeight="800" fontFamily="Inter, sans-serif">40% YoY AI spend</text>

              <rect x="64" y="184" width="214" height="52" rx="16" fill="rgba(255,255,255,0.03)" stroke="rgba(255,255,255,0.06)" strokeWidth="1.2"/>
              <circle cx="88" cy="210" r="5" fill="#a78bfa"/>
              <text x="102" y="204" fill="#a78bfa" fontSize="9.2" fontWeight="800" fontFamily="Inter, sans-serif">REGULATION</text>
              <text x="102" y="220" fill="#eef6ff" fontSize="15.8" fontWeight="800" fontFamily="Inter, sans-serif">EU AI Act audits</text>

              <rect x="64" y="256" width="214" height="52" rx="16" fill="rgba(255,255,255,0.03)" stroke="rgba(255,255,255,0.06)" strokeWidth="1.2"/>
              <circle cx="88" cy="282" r="5" fill="#f59e0b"/>
              <text x="102" y="276" fill="#f59e0b" fontSize="9.2" fontWeight="800" fontFamily="Inter, sans-serif">BUDGET</text>
              <text x="102" y="292" fill="#eef6ff" fontSize="15" fontWeight="800" fontFamily="Inter, sans-serif">LLM overruns funded</text>

              <line x1="298" y1="126" x2="298" y2="304" stroke="rgba(255,255,255,0.08)" strokeWidth="1.5"/>

              <rect x="314" y="110" width="216" height="188" rx="24" fill="rgba(255,255,255,0.04)" stroke="rgba(255,255,255,0.08)" strokeWidth="1.4"/>
              <text x="338" y="138" fill="#10d98a" fontSize="10.2" fontWeight="800" fontFamily="Inter, sans-serif">CONNECTOR FIT</text>
              <text x="338" y="172" fill="#eef6ff" fontSize="22.5" fontWeight="800" fontFamily="Inter, sans-serif">Market exists.</text>
              <text x="338" y="198" fill="#eef6ff" fontSize="22.5" fontWeight="800" fontFamily="Inter, sans-serif">Need is active.</text>
              <text x="338" y="238" fill="#8ba4be" fontSize="9.8" fontWeight="700" fontFamily="Inter, sans-serif">adoption growth</text>
              <text x="338" y="252" fill="#8ba4be" fontSize="9.8" fontWeight="700" fontFamily="Inter, sans-serif">policy pressure</text>
              <text x="338" y="266" fill="#8ba4be" fontSize="9.8" fontWeight="700" fontFamily="Inter, sans-serif">already-funded pain</text>
            </svg>
          </div>
        </div>
      </div>
    </div>
  );
}

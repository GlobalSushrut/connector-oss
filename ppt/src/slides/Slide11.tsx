export default function Slide11() {
  return (
    <div className="slide">
      <svg className="slide-bg" viewBox="0 0 1280 720" xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="xMidYMid slice">
        <defs>
          <radialGradient id="s11g" cx="50%" cy="50%" r="60%"><stop offset="0%" stopColor="#0d1a26"/><stop offset="100%" stopColor="#06111e"/></radialGradient>
          <pattern id="s11grid" width="64" height="64" patternUnits="userSpaceOnUse"><path d="M64 0L0 0 0 64" fill="none" stroke="#11263c" strokeWidth="1"/></pattern>
        </defs>
        <rect width="1280" height="720" fill="url(#s11g)"/>
        <rect width="1280" height="720" fill="url(#s11grid)" opacity="0.42"/>
      </svg>
      <div className="slide-content left-focus-layout pdf-safe">
        <div className="focus-stack">
          <div className="tag">11 · SWOT</div>
          <h1 className="slide-title">We know where we are strong and where we need to <span className="accent-blue">move fast</span></h1>
          <p className="slide-sub">This is not a perfect product in a perfect market. But the strengths align with urgent buyer needs, and the threats are manageable if we execute quickly.</p>
          <div className="wide-panel">
            <div className="wide-panel-title">Strategic clarity</div>
            <div className="wide-panel-copy">The 2×2 shows what we leverage, what we fix, what we chase, and what we defend against.</div>
          </div>
        </div>
        <div className="focus-visual">
          <div className="hero-visual-card" style={{display:'flex', alignItems:'center', justifyContent:'center', width:'100%'}}>
            <svg viewBox="0 0 580 420" width="100%" height="100%" xmlns="http://www.w3.org/2000/svg" style={{ maxWidth: '100%', maxHeight: '100%' }}>
              <rect x="74" y="62" width="428" height="296" rx="22" fill="rgba(255,255,255,0.02)" stroke="rgba(255,255,255,0.06)" strokeWidth="1.2"/>
              <line x1="181" y1="62" x2="181" y2="358" stroke="rgba(255,255,255,0.05)" strokeWidth="1"/>
              <line x1="288" y1="62" x2="288" y2="358" stroke="rgba(255,255,255,0.16)" strokeWidth="2"/>
              <line x1="395" y1="62" x2="395" y2="358" stroke="rgba(255,255,255,0.05)" strokeWidth="1"/>
              <line x1="74" y1="136" x2="502" y2="136" stroke="rgba(255,255,255,0.05)" strokeWidth="1"/>
              <line x1="74" y1="210" x2="502" y2="210" stroke="rgba(255,255,255,0.16)" strokeWidth="2"/>
              <line x1="74" y1="284" x2="502" y2="284" stroke="rgba(255,255,255,0.05)" strokeWidth="1"/>

              <text x="288" y="44" textAnchor="middle" fill="#8ba4be" fontSize="11" fontWeight="700" fontFamily="Inter, sans-serif">EXECUTION READINESS →</text>
              <text x="44" y="214" fill="#8ba4be" fontSize="11" fontWeight="700" fontFamily="Inter, sans-serif" transform="rotate(-90 44 214)">MARKET FORCE →</text>

              <text x="112" y="98" fill="#10d98a" fontSize="12" fontWeight="800" fontFamily="Inter, sans-serif">LEVERAGE</text>
              <text x="360" y="98" fill="#f43f5e" fontSize="12" fontWeight="800" fontFamily="Inter, sans-serif">FIX FAST</text>
              <text x="108" y="336" fill="#00c8f8" fontSize="12" fontWeight="800" fontFamily="Inter, sans-serif">CHASE</text>
              <text x="360" y="336" fill="#f59e0b" fontSize="12" fontWeight="800" fontFamily="Inter, sans-serif">DEFEND</text>

              <circle cx="142" cy="118" r="8" fill="#10d98a"/>
              <text x="156" y="122" fill="#dff8ee" fontSize="10.5" fontWeight="700" fontFamily="Inter, sans-serif">Rust core</text>

              <circle cx="166" cy="150" r="8" fill="#10d98a"/>
              <text x="180" y="154" fill="#dff8ee" fontSize="10.5" fontWeight="700" fontFamily="Inter, sans-serif">Proof layer</text>

              <circle cx="382" cy="132" r="8" fill="#f43f5e"/>
              <text x="396" y="136" fill="#ffd9df" fontSize="10.5" fontWeight="700" fontFamily="Inter, sans-serif">Awareness gap</text>

              <circle cx="404" cy="164" r="8" fill="#f43f5e"/>
              <text x="418" y="168" fill="#ffd9df" fontSize="10.5" fontWeight="700" fontFamily="Inter, sans-serif">Positioning</text>

              <circle cx="144" cy="260" r="8" fill="#00c8f8"/>
              <text x="158" y="264" fill="#d7f6ff" fontSize="10.5" fontWeight="700" fontFamily="Inter, sans-serif">AI adoption</text>

              <circle cx="172" cy="300" r="8" fill="#00c8f8"/>
              <text x="186" y="304" fill="#d7f6ff" fontSize="10.5" fontWeight="700" fontFamily="Inter, sans-serif">EU AI Act</text>

              <circle cx="378" cy="276" r="8" fill="#f59e0b"/>
              <text x="392" y="280" fill="#ffe4ba" fontSize="10.5" fontWeight="700" fontFamily="Inter, sans-serif">Vendor noise</text>

              <circle cx="400" cy="308" r="8" fill="#f59e0b"/>
              <text x="414" y="312" fill="#ffe4ba" fontSize="10.5" fontWeight="700" fontFamily="Inter, sans-serif">Slow sales</text>

              <rect x="226" y="182" width="124" height="54" rx="14" fill="rgba(255,255,255,0.035)" stroke="rgba(255,255,255,0.08)" strokeWidth="1.1"/>
              <text x="288" y="204" textAnchor="middle" fill="#eef6ff" fontSize="15" fontWeight="800" fontFamily="Inter, sans-serif">Stage truth</text>
              <text x="288" y="222" textAnchor="middle" fill="#8ba4be" fontSize="9.8" fontWeight="700" fontFamily="Inter, sans-serif">strong core, execution risk</text>
            </svg>
          </div>
        </div>
      </div>
    </div>
  );
}

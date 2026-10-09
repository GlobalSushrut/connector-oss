export default function Slide3() {
  return (
    <div className="slide">
      <svg className="slide-bg" viewBox="0 0 1280 720" xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="xMidYMid slice">
        <defs>
          <radialGradient id="s3g" cx="42%" cy="38%" r="58%"><stop offset="0%" stopColor="#0e1f2e"/><stop offset="100%" stopColor="#06111e"/></radialGradient>
          <pattern id="s3grid" width="64" height="64" patternUnits="userSpaceOnUse"><path d="M64 0L0 0 0 64" fill="none" stroke="#11263c" strokeWidth="1"/></pattern>
        </defs>
        <rect width="1280" height="720" fill="url(#s3g)"/>
        <rect width="1280" height="720" fill="url(#s3grid)" opacity="0.42"/>
      </svg>
      <div className="slide-content left-focus-layout pdf-safe">
        <div className="focus-stack">
          <div className="tag">03 · WHY NOW</div>
          <h1 className="slide-title">Why now: AI scale pushes <span className="accent-blue">cost, energy, and human impact</span> at the same time</h1>
          <p className="slide-sub">From 2022 to 2035, adoption rises first. Then regulation hardens, cost and energy load increase, and social dependence deepens.</p>
          <div className="wide-panel">
            <div className="wide-panel-title">Market signal</div>
            <div className="wide-panel-copy">The market does not move in one smooth boom. It moves from optimism to correction, then into selective scaling and finally dependence with scrutiny.</div>
          </div>
        </div>
        <div className="focus-visual">
          <div className="hero-visual-card" style={{display:'flex', alignItems:'center', justifyContent:'center', width:'100%'}}>
            <svg viewBox="0 0 580 420" width="100%" height="100%" xmlns="http://www.w3.org/2000/svg" style={{ maxWidth: '100%', maxHeight: '100%' }}>
              <text x="290" y="28" textAnchor="middle" fill="#d9e7f5" fontSize="12" fontWeight="700" fontFamily="Inter, sans-serif">AI market transition map</text>

              <line x1="108" y1="258" x2="490" y2="258" stroke="rgba(255,255,255,0.18)" strokeWidth="2"/>
              <line x1="108" y1="104" x2="108" y2="258" stroke="rgba(255,255,255,0.12)" strokeWidth="2"/>
              <line x1="108" y1="218" x2="490" y2="218" stroke="rgba(255,255,255,0.05)" strokeWidth="1" strokeDasharray="4 6"/>
              <line x1="108" y1="178" x2="490" y2="178" stroke="rgba(255,255,255,0.05)" strokeWidth="1" strokeDasharray="4 6"/>
              <line x1="108" y1="138" x2="490" y2="138" stroke="rgba(255,255,255,0.05)" strokeWidth="1" strokeDasharray="4 6"/>

              <text x="74" y="182" textAnchor="middle" fill="#8ba4be" fontSize="10" fontWeight="700" fontFamily="Inter, sans-serif" transform="rotate(-90 74 182)">INTENSITY</text>

              <path d="M 116 246 C 166 242, 206 226, 242 198 C 282 166, 324 134, 368 106 C 410 80, 450 66, 490 60" fill="none" stroke="#00d9ff" strokeWidth="4.8" strokeLinecap="round"/>
              <path d="M 116 252 C 176 250, 222 242, 262 230 C 304 216, 346 192, 388 156 C 426 126, 458 104, 490 86" fill="none" stroke="#9b6bff" strokeWidth="3.6" strokeLinecap="round" strokeDasharray="10 7"/>
              <path d="M 116 256 C 176 255, 226 252, 272 244 C 318 234, 360 218, 402 194 C 438 174, 466 146, 490 124" fill="none" stroke="#ffb020" strokeWidth="3.6" strokeLinecap="round"/>

              <line x1="398" y1="-30" x2="420" y2="-30" stroke="#00d9ff" strokeWidth="3.2" strokeLinecap="round"/>
              <text x="428" y="-26" fill="#00d9ff" fontSize="9.4" fontWeight="800" fontFamily="Inter, sans-serif">Adoption</text>
              <line x1="398" y1="-14" x2="420" y2="-14" stroke="#9b6bff" strokeWidth="3.2" strokeLinecap="round" strokeDasharray="9 6"/>
              <text x="428" y="-10" fill="#c8adff" fontSize="9.4" fontWeight="800" fontFamily="Inter, sans-serif">Regulation</text>
              <line x1="398" y1="2" x2="420" y2="2" stroke="#ffb020" strokeWidth="3.2" strokeLinecap="round"/>
              <text x="428" y="6" fill="#ffd089" fontSize="9.4" fontWeight="800" fontFamily="Inter, sans-serif">Cost / energy</text>

              <line x1="290" y1="104" x2="290" y2="258" stroke="rgba(245,158,11,0.26)" strokeWidth="1.4" strokeDasharray="5 6"/>
              <rect x="246" y="82" width="88" height="18" rx="9" fill="rgba(245,158,11,0.12)" stroke="rgba(245,158,11,0.24)" strokeWidth="1"/>
              <text x="290" y="94" textAnchor="middle" fill="#ffd089" fontSize="8.8" fontWeight="800" fontFamily="Inter, sans-serif">CONNECTOR NEEDED</text>

              <text x="170" y="191" textAnchor="middle" fill="#ff5c5c" fontSize="12" fontWeight="900" fontFamily="Inter, sans-serif">★</text>
              <text x="242" y="198" textAnchor="middle" fill="#22c55e" fontSize="12" fontWeight="900" fontFamily="Inter, sans-serif">★</text>
              <text x="368" y="106" textAnchor="middle" fill="#0b0f14" stroke="#d9e7f5" strokeWidth="0.6" fontSize="12" fontWeight="900" fontFamily="Inter, sans-serif">★</text>
              <text x="442" y="102" textAnchor="middle" fill="#9b6bff" fontSize="12" fontWeight="900" fontFamily="Inter, sans-serif">★</text>
              <text x="490" y="60" textAnchor="middle" fill="#ffd84d" fontSize="12" fontWeight="900" fontFamily="Inter, sans-serif">★</text>

              <circle cx="242" cy="198" r="4" fill="#00d9ff"/>
              <line x1="242" y1="198" x2="242" y2="172" stroke="rgba(0,200,248,0.22)" strokeWidth="1.2"/>
              <text x="242" y="162" textAnchor="middle" fill="#00d9ff" fontSize="9.4" fontWeight="800" fontFamily="Inter, sans-serif">2026</text>

              <circle cx="410" cy="138" r="4" fill="#9b6bff"/>
              <line x1="410" y1="138" x2="410" y2="112" stroke="rgba(139,92,246,0.24)" strokeWidth="1.2"/>
              <text x="410" y="102" textAnchor="middle" fill="#c8adff" fontSize="9.4" fontWeight="800" fontFamily="Inter, sans-serif">2030</text>

              <circle cx="490" cy="86" r="4" fill="#ffb020"/>
              <line x1="490" y1="86" x2="490" y2="62" stroke="rgba(245,158,11,0.22)" strokeWidth="1.2"/>
              <text x="490" y="52" textAnchor="end" fill="#ffd089" fontSize="9.4" fontWeight="800" fontFamily="Inter, sans-serif">2035</text>

              <text x="116" y="278" fill="#8ba4be" fontSize="9.4" fontFamily="Inter, sans-serif">2022</text>
              <text x="172" y="278" fill="#8ba4be" fontSize="9.4" fontFamily="Inter, sans-serif">2024</text>
              <text x="236" y="278" fill="#8ba4be" fontSize="9.4" fontFamily="Inter, sans-serif">2026</text>
              <text x="286" y="278" fill="#8ba4be" fontSize="9.4" fontFamily="Inter, sans-serif">2027</text>
              <text x="398" y="278" fill="#8ba4be" fontSize="9.4" fontFamily="Inter, sans-serif">2030</text>
              <text x="490" y="278" textAnchor="end" fill="#8ba4be" fontSize="9.4" fontFamily="Inter, sans-serif">2035</text>
              <text x="300" y="299" textAnchor="middle" fill="#6f87a1" fontSize="10" fontWeight="700" fontFamily="Inter, sans-serif">Time</text>

              <rect x="110" y="318" width="380" height="16" rx="8" fill="rgba(255,255,255,0.03)" stroke="rgba(255,255,255,0.06)" strokeWidth="1"/>
              <rect x="110" y="318" width="70" height="16" rx="8" fill="rgba(0,200,248,0.12)"/>
              <rect x="180" y="318" width="76" height="16" fill="rgba(34,211,238,0.12)"/>
              <rect x="256" y="318" width="78" height="16" fill="rgba(245,158,11,0.12)"/>
              <rect x="334" y="318" width="84" height="16" fill="rgba(139,92,246,0.12)"/>
              <rect x="418" y="318" width="72" height="16" rx="8" fill="rgba(16,217,138,0.12)"/>
              <text x="126" y="329" fill="#00c8f8" fontSize="8.2" fontWeight="700" fontFamily="Inter, sans-serif">Optimism</text>
              <text x="196" y="329" fill="#22d3ee" fontSize="8.2" fontWeight="700" fontFamily="Inter, sans-serif">Surge</text>
              <text x="276" y="329" fill="#f59e0b" fontSize="8.2" fontWeight="700" fontFamily="Inter, sans-serif">Pressure</text>
              <text x="352" y="329" fill="#b79cff" fontSize="8.2" fontWeight="700" fontFamily="Inter, sans-serif">Selective</text>
              <text x="435" y="329" fill="#10d98a" fontSize="8.2" fontWeight="700" fontFamily="Inter, sans-serif">Dependence</text>

              <text x="110" y="360" fill="#8ba4be" fontSize="8.4" fontWeight="700" fontFamily="Inter, sans-serif">Phase stars</text>
              <text x="170" y="360" fill="#ff5c5c" fontSize="9.6" fontWeight="800" fontFamily="Inter, sans-serif">★</text>
              <text x="181" y="360" fill="#6f87a1" fontSize="8.4" fontFamily="Inter, sans-serif">copilot</text>
              <text x="230" y="360" fill="#22c55e" fontSize="9.6" fontWeight="800" fontFamily="Inter, sans-serif">★</text>
              <text x="241" y="360" fill="#6f87a1" fontSize="8.4" fontFamily="Inter, sans-serif">agentic</text>
              <text x="298" y="360" fill="#0b0f14" stroke="#d9e7f5" strokeWidth="0.5" fontSize="9.6" fontWeight="800" fontFamily="Inter, sans-serif">★</text>
              <text x="309" y="360" fill="#6f87a1" fontSize="8.4" fontFamily="Inter, sans-serif">enterprise</text>
              <text x="380" y="360" fill="#9b6bff" fontSize="9.6" fontWeight="800" fontFamily="Inter, sans-serif">★</text>
              <text x="391" y="360" fill="#6f87a1" fontSize="8.4" fontFamily="Inter, sans-serif">augmented</text>
              <text x="456" y="360" fill="#ffd84d" fontSize="9.6" fontWeight="800" fontFamily="Inter, sans-serif">★</text>
              <text x="467" y="360" fill="#6f87a1" fontSize="8.4" fontFamily="Inter, sans-serif">edge</text>
            </svg>
          </div>
        </div>
      </div>
    </div>
  );
}

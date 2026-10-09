export default function Slide7() {
  return (
    <div className="slide">
      <svg className="slide-bg" viewBox="0 0 1280 720" xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="xMidYMid slice">
        <defs>
          <radialGradient id="s7g" cx="54%" cy="40%" r="56%"><stop offset="0%" stopColor="#10162a"/><stop offset="100%" stopColor="#06111e"/></radialGradient>
          <pattern id="s7grid" width="64" height="64" patternUnits="userSpaceOnUse"><path d="M64 0L0 0 0 64" fill="none" stroke="#11263c" strokeWidth="1"/></pattern>
        </defs>
        <rect width="1280" height="720" fill="url(#s7g)"/>
        <rect width="1280" height="720" fill="url(#s7grid)" opacity="0.42"/>
      </svg>
      <div className="slide-content left-focus-layout pdf-safe">
        <div className="focus-stack">
          <div className="tag">07 · BUSINESS</div>
          <h1 className="slide-title">The business case is simple:<br/><span className="accent-green">money saved, risk reduced, trust gained</span></h1>
          <p className="slide-sub">The deck should show why this gets budget. The buyer story is not technical admiration. It is operational value.</p>
          <div className="wide-panel">
            <div className="wide-panel-title">Why this gets budget</div>
            <div className="wide-panel-copy">Engineering buys faster debugging and lower spend. Security and compliance buy lower operational risk and stronger evidence.</div>
          </div>
        </div>
        <div className="focus-visual">
          <div className="hero-visual-card" style={{display:'flex', alignItems:'center', justifyContent:'center', width:'100%'}}>
            <svg viewBox="0 0 580 420" width="100%" height="100%" xmlns="http://www.w3.org/2000/svg" style={{ maxWidth: '100%', maxHeight: '100%' }}>
              <rect x="72" y="56" width="436" height="72" rx="18" fill="rgba(0,200,248,0.12)" stroke="rgba(0,200,248,0.38)" strokeWidth="2.5"/>
              <text x="290" y="83" textAnchor="middle" fill="#00c8f8" fontSize="11" fontWeight="800" fontFamily="Inter, sans-serif" letterSpacing="0.12em">BUSINESS IMPACT</text>
              <text x="290" y="112" textAnchor="middle" fill="#f0f6ff" fontSize="32" fontWeight="900" fontFamily="Inter, sans-serif">3x-5x ROI case</text>

              <rect x="66" y="156" width="140" height="164" rx="20" fill="rgba(0,200,248,0.08)" stroke="rgba(0,200,248,0.28)" strokeWidth="2"/>
              <text x="138" y="186" textAnchor="middle" fill="#00c8f8" fontSize="13" fontWeight="800" fontFamily="Inter, sans-serif" letterSpacing="0.08em">ENGINEERING</text>
              <text x="136" y="244" textAnchor="middle" fill="#f0f6ff" fontSize="32" fontWeight="900" fontFamily="Inter, sans-serif">40-60%</text>
              <text x="136" y="268" textAnchor="middle" fill="#8ba4be" fontSize="11" fontFamily="Inter, sans-serif">lower AI cost</text>
              <text x="138" y="298" textAnchor="middle" fill="#f0f6ff" fontSize="21" fontWeight="800" fontFamily="Inter, sans-serif">70%</text>
              <text x="138" y="315" textAnchor="middle" fill="#8ba4be" fontSize="10.4" fontFamily="Inter, sans-serif">faster debugging</text>

              <rect x="220" y="156" width="140" height="164" rx="20" fill="rgba(167,139,250,0.08)" stroke="rgba(167,139,250,0.28)" strokeWidth="2"/>
              <text x="290" y="186" textAnchor="middle" fill="#a78bfa" fontSize="13" fontWeight="800" fontFamily="Inter, sans-serif" letterSpacing="0.08em">SECURITY</text>
              <text x="290" y="244" textAnchor="middle" fill="#f0f6ff" fontSize="28" fontWeight="900" fontFamily="Inter, sans-serif">Lower</text>
              <text x="290" y="268" textAnchor="middle" fill="#8ba4be" fontSize="12" fontFamily="Inter, sans-serif">risk</text>
              <text x="290" y="298" textAnchor="middle" fill="#f0f6ff" fontSize="21" fontWeight="800" fontFamily="Inter, sans-serif">Hard</text>
              <text x="290" y="315" textAnchor="middle" fill="#8ba4be" fontSize="11" fontFamily="Inter, sans-serif">control</text>

              <rect x="374" y="156" width="140" height="164" rx="20" fill="rgba(16,217,138,0.08)" stroke="rgba(16,217,138,0.28)" strokeWidth="2"/>
              <text x="442" y="186" textAnchor="middle" fill="#10d98a" fontSize="13" fontWeight="800" fontFamily="Inter, sans-serif" letterSpacing="0.08em">COMPLIANCE</text>
              <text x="444" y="244" textAnchor="middle" fill="#f0f6ff" fontSize="30" fontWeight="900" fontFamily="Inter, sans-serif">80%</text>
              <text x="444" y="268" textAnchor="middle" fill="#8ba4be" fontSize="11" fontFamily="Inter, sans-serif">less audit prep</text>
              <text x="442" y="298" textAnchor="middle" fill="#f0f6ff" fontSize="21" fontWeight="800" fontFamily="Inter, sans-serif">Day 1</text>
              <text x="442" y="315" textAnchor="middle" fill="#8ba4be" fontSize="10.4" fontFamily="Inter, sans-serif">proof ready</text>

              <text x="290" y="364" textAnchor="middle" fill="#00c8f8" fontSize="11" fontWeight="800" fontFamily="Inter, sans-serif" letterSpacing="0.12em">WHY BUDGET HAPPENS</text>
              <text x="290" y="380" textAnchor="middle" fill="#8ba4be" fontSize="9.8" fontFamily="Inter, sans-serif">40-60% lower cost · 70% faster debug · 80% less audit prep</text>
            </svg>
          </div>
        </div>
      </div>
    </div>
  );
}

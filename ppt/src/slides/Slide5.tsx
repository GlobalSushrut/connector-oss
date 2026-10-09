export default function Slide5() {
  return (
    <div className="slide">
      <svg className="slide-bg" viewBox="0 0 1280 720" xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="xMidYMid slice">
        <defs>
          <radialGradient id="s5g" cx="68%" cy="32%" r="56%"><stop offset="0%" stopColor="#16152a"/><stop offset="100%" stopColor="#06111e"/></radialGradient>
          <pattern id="s5grid" width="64" height="64" patternUnits="userSpaceOnUse"><path d="M64 0L0 0 0 64" fill="none" stroke="#11263c" strokeWidth="1"/></pattern>
        </defs>
        <rect width="1280" height="720" fill="url(#s5g)"/>
        <rect width="1280" height="720" fill="url(#s5grid)" opacity="0.42"/>
      </svg>
      <div className="slide-content left-focus-layout pdf-safe">
        <div className="focus-stack">
          <div className="tag">05 · SOLUTION</div>
          <h1 className="slide-title">Connector turns agent systems from <span className="accent-purple">opaque</span> into <span className="accent-blue">controlled</span></h1>
          <p className="slide-sub">The core value is simple: make AI execution visible, policy-aware, and defensible without forcing teams to rebuild their stack.</p>
          <div className="wide-panel">
            <div className="wide-panel-title">Three things happen after install</div>
            <div className="wide-panel-copy">Instead of asking teams to trust an agent stack, Connector makes its execution visible, controllable, and defensible.</div>
          </div>
        </div>
        <div className="focus-visual">
          <div className="hero-visual-card" style={{display:'flex', alignItems:'center', justifyContent:'center', width:'100%'}}>
            <svg viewBox="0 0 580 420" width="100%" height="100%" xmlns="http://www.w3.org/2000/svg" style={{ maxWidth: '100%', maxHeight: '100%' }}>
              <rect x="38" y="154" width="120" height="112" rx="18" fill="rgba(244,63,94,0.08)" stroke="rgba(244,63,94,0.35)" strokeWidth="2"/>
              <text x="98" y="188" textAnchor="middle" fill="#f43f5e" fontSize="13" fontWeight="800" fontFamily="Inter, sans-serif" letterSpacing="0.08em">BEFORE</text>
              <text x="98" y="214" textAnchor="middle" fill="#f0f6ff" fontSize="21" fontWeight="800" fontFamily="Inter, sans-serif">Opaque</text>
              <text x="98" y="236" textAnchor="middle" fill="#8ba4be" fontSize="12" fontFamily="Inter, sans-serif">weak logs</text>
              <text x="98" y="254" textAnchor="middle" fill="#8ba4be" fontSize="12" fontFamily="Inter, sans-serif">no controls</text>

              <path d="M 158 210 L 194 210" fill="none" stroke="#3a6387" strokeWidth="3" markerEnd="url(#arrow5)"/>

              <rect x="194" y="140" width="192" height="140" rx="22" fill="rgba(0,200,248,0.14)" stroke="rgba(0,200,248,0.52)" strokeWidth="3"/>
              <text x="290" y="176" textAnchor="middle" fill="#f0f6ff" fontSize="23" fontWeight="800" fontFamily="Inter, sans-serif">Connector</text>
              <text x="290" y="200" textAnchor="middle" fill="#00c8f8" fontSize="12" fontWeight="800" fontFamily="Inter, sans-serif" letterSpacing="0.12em">CONTROL PLANE</text>

              <rect x="214" y="220" width="48" height="36" rx="10" fill="rgba(0,200,248,0.1)" stroke="rgba(0,200,248,0.25)" strokeWidth="1.5"/>
              <text x="238" y="242" textAnchor="middle" fill="#00c8f8" fontSize="12" fontWeight="800" fontFamily="Inter, sans-serif">O</text>
              <text x="238" y="272" textAnchor="middle" fill="#8ba4be" fontSize="11" fontFamily="Inter, sans-serif">Observe</text>

              <rect x="266" y="220" width="48" height="36" rx="10" fill="rgba(167,139,250,0.1)" stroke="rgba(167,139,250,0.25)" strokeWidth="1.5"/>
              <text x="290" y="242" textAnchor="middle" fill="#a78bfa" fontSize="12" fontWeight="800" fontFamily="Inter, sans-serif">E</text>
              <text x="290" y="272" textAnchor="middle" fill="#8ba4be" fontSize="11" fontFamily="Inter, sans-serif">Enforce</text>

              <rect x="318" y="220" width="48" height="36" rx="10" fill="rgba(16,217,138,0.1)" stroke="rgba(16,217,138,0.25)" strokeWidth="1.5"/>
              <text x="342" y="242" textAnchor="middle" fill="#10d98a" fontSize="12" fontWeight="800" fontFamily="Inter, sans-serif">P</text>
              <text x="342" y="272" textAnchor="middle" fill="#8ba4be" fontSize="11" fontFamily="Inter, sans-serif">Prove</text>

              <path d="M 386 210 L 424 210" fill="none" stroke="#3a6387" strokeWidth="3" markerEnd="url(#arrow5)"/>

              <rect x="424" y="134" width="118" height="152" rx="18" fill="rgba(16,217,138,0.1)" stroke="rgba(16,217,138,0.38)" strokeWidth="2.5"/>
              <text x="483" y="168" textAnchor="middle" fill="#10d98a" fontSize="13" fontWeight="800" fontFamily="Inter, sans-serif" letterSpacing="0.08em">AFTER</text>
              <text x="483" y="194" textAnchor="middle" fill="#f0f6ff" fontSize="21" fontWeight="800" fontFamily="Inter, sans-serif">Controlled</text>
              <text x="483" y="220" textAnchor="middle" fill="#8ba4be" fontSize="12" fontFamily="Inter, sans-serif">visible execution</text>
              <text x="483" y="238" textAnchor="middle" fill="#8ba4be" fontSize="12" fontFamily="Inter, sans-serif">policy-aware path</text>
              <text x="483" y="256" textAnchor="middle" fill="#8ba4be" fontSize="12" fontFamily="Inter, sans-serif">defensible records</text>

              <text x="290" y="332" textAnchor="middle" fill="#00c8f8" fontSize="12" fontWeight="800" fontFamily="Inter, sans-serif" letterSpacing="0.12em">REAL INCIDENT EXAMPLE</text>
              <text x="290" y="352" textAnchor="middle" fill="#8ba4be" fontSize="11.4" fontFamily="Inter, sans-serif">unsafe tool call → without Connector: no block, weak logs → with Connector: blocked + proof trail</text>

              <defs>
                <marker id="arrow5" markerWidth="10" markerHeight="10" refX="5" refY="5" orient="auto">
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

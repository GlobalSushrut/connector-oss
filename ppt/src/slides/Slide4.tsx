export default function Slide4() {
  return (
    <div className="slide">
      <svg className="slide-bg" viewBox="0 0 1280 720" xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="xMidYMid slice">
        <defs>
          <radialGradient id="s4g" cx="50%" cy="46%" r="60%"><stop offset="0%" stopColor="#0c1a2a"/><stop offset="100%" stopColor="#06111e"/></radialGradient>
          <pattern id="s4grid" width="64" height="64" patternUnits="userSpaceOnUse"><path d="M64 0L0 0 0 64" fill="none" stroke="#11263c" strokeWidth="1"/></pattern>
        </defs>
        <rect width="1280" height="720" fill="url(#s4g)"/>
        <rect width="1280" height="720" fill="url(#s4grid)" opacity="0.42"/>
      </svg>
      <div className="slide-content left-focus-layout pdf-safe">
        <div className="focus-stack" style={{gap: 10, minHeight: 0}}>
          <div className="tag">04 · ENTRY POINT</div>
          <h1 className="slide-title" style={{fontSize: 34, lineHeight: 1.0, maxWidth: '13ch'}}>We do not sell “governance” first.<br/><span className="accent-blue">We land on a painful problem.</span></h1>
          <p className="slide-sub" style={{fontSize: 13, lineHeight: 1.24, maxWidth: '38ch'}}>We start with one urgent issue: runaway spend, weak observability, or a compliance blocker slowing deployment.</p>
          <div className="vertical-cards" style={{gap: 8}}>
            <div className="wide-panel" style={{padding: '12px 16px'}}>
              <div className="wide-panel-title accent-blue" style={{fontSize: 15, marginBottom: 5}}>Cost spikes</div>
              <div className="wide-panel-copy" style={{fontSize: 10.5, lineHeight: 1.2}}>Connector lands as a cost-control layer when model usage becomes unpredictable.</div>
            </div>
            <div className="wide-panel" style={{padding: '12px 16px'}}>
              <div className="wide-panel-title accent-purple" style={{fontSize: 15, marginBottom: 5}}>Debugging fails</div>
              <div className="wide-panel-copy" style={{fontSize: 10.5, lineHeight: 1.2}}>Connector lands when engineers need to trace why agents behaved that way in production.</div>
            </div>
            <div className="safe-panel" style={{padding: '12px 16px', display: 'flex', gap: 10, alignItems: 'center'}}>
              <div style={{fontSize: 10, fontWeight: 800, letterSpacing: '.12em', color: '#10d98a', textTransform: 'uppercase', flexShrink: 0}}>Blocker</div>
              <div style={{fontSize: 12, lineHeight: 1.3, color: '#8ba4be'}}>Approval stalls when security or compliance asks for evidence the current stack cannot produce.</div>
            </div>
          </div>
        </div>
        <div className="focus-visual">
          <div className="hero-visual-card" style={{display:'flex', alignItems:'center', justifyContent:'center', width:'100%'}}>
            <svg viewBox="0 0 560 400" width="100%" height="100%" xmlns="http://www.w3.org/2000/svg" style={{ maxWidth: '100%', maxHeight: '100%' }}>
              <g transform="translate(18 28) scale(0.84)">
                {/* Left side: Pain points */}
                <rect x="30" y="60" width="128" height="52" rx="14" fill="rgba(244,63,94,0.1)" stroke="rgba(244,63,94,0.4)" strokeWidth="2"/>
                <text x="94" y="91" textAnchor="middle" fill="#f0f6ff" fontSize="17" fontWeight="700" fontFamily="Inter, sans-serif">Cost</text>

                <rect x="30" y="145" width="128" height="52" rx="14" fill="rgba(244,63,94,0.1)" stroke="rgba(244,63,94,0.4)" strokeWidth="2"/>
                <text x="94" y="176" textAnchor="middle" fill="#f0f6ff" fontSize="17" fontWeight="700" fontFamily="Inter, sans-serif">Debugging</text>

                <rect x="30" y="230" width="128" height="52" rx="14" fill="rgba(244,63,94,0.1)" stroke="rgba(244,63,94,0.4)" strokeWidth="2"/>
                <text x="94" y="261" textAnchor="middle" fill="#f0f6ff" fontSize="17" fontWeight="700" fontFamily="Inter, sans-serif">Compliance</text>

                {/* Converging lines to center */}
                <path d="M 158 86 Q 214 86, 258 196" fill="none" stroke="#3a6387" strokeWidth="3" strokeLinecap="round"/>
                <path d="M 158 171 L 258 196" fill="none" stroke="#3a6387" strokeWidth="3" strokeLinecap="round"/>
                <path d="M 158 256 Q 214 256, 258 196" fill="none" stroke="#3a6387" strokeWidth="3" strokeLinecap="round"/>

                {/* Center: Connector */}
                <rect x="258" y="154" width="158" height="82" rx="18" fill="rgba(0,200,248,0.15)" stroke="rgba(0,200,248,0.6)" strokeWidth="3"/>
                <circle cx="258" cy="196" r="5" fill="#00c8f8"/>
                <circle cx="416" cy="196" r="5" fill="#00c8f8"/>
                <text x="337" y="189" textAnchor="middle" fill="#f0f6ff" fontSize="21" fontWeight="800" fontFamily="Inter, sans-serif">Connector</text>
                <text x="337" y="212" textAnchor="middle" fill="#00c8f8" fontSize="13" fontWeight="700" fontFamily="Inter, sans-serif" letterSpacing="0.08em">LAND</text>

                {/* Arrow to right */}
                <path d="M 416 196 L 456 196" fill="none" stroke="#3a6387" strokeWidth="3" markerEnd="url(#arrow4)"/>

                {/* Right: Governance */}
                <rect x="456" y="161" width="118" height="70" rx="16" fill="rgba(16,217,138,0.12)" stroke="rgba(16,217,138,0.5)" strokeWidth="2.5"/>
                <text x="515" y="190" textAnchor="middle" fill="#f0f6ff" fontSize="18" fontWeight="800" fontFamily="Inter, sans-serif">Governance</text>
                <text x="515" y="210" textAnchor="middle" fill="#10d98a" fontSize="11" fontWeight="700" fontFamily="Inter, sans-serif" letterSpacing="0.06em">EXPAND</text>

                {/* Bottom labels */}
                <text x="94" y="326" textAnchor="middle" fill="#f43f5e" fontSize="11" fontWeight="800" fontFamily="Inter, sans-serif" letterSpacing="0.1em">PAIN POINTS</text>
                <text x="337" y="326" textAnchor="middle" fill="#00c8f8" fontSize="11" fontWeight="800" fontFamily="Inter, sans-serif" letterSpacing="0.1em">ENTRY</text>
                <text x="515" y="326" textAnchor="middle" fill="#10d98a" fontSize="11" fontWeight="800" fontFamily="Inter, sans-serif" letterSpacing="0.1em">EXPANSION</text>
              </g>

              <defs>
                <marker id="arrow4" markerWidth="10" markerHeight="10" refX="5" refY="5" orient="auto">
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

export default function Slide12() {
  return (
    <div className="slide">
      <svg className="slide-bg" viewBox="0 0 1280 720" xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="xMidYMid slice">
        <defs>
          <radialGradient id="s12g" cx="50%" cy="50%" r="68%"><stop offset="0%" stopColor="#0f1d2e"/><stop offset="100%" stopColor="#06111e"/></radialGradient>
          <pattern id="s12grid" width="64" height="64" patternUnits="userSpaceOnUse"><path d="M64 0L0 0 0 64" fill="none" stroke="#11263c" strokeWidth="1"/></pattern>
          <linearGradient id="s12glow" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#00c8f8"/>
            <stop offset="50%" stopColor="#a78bfa"/>
            <stop offset="100%" stopColor="#10d98a"/>
          </linearGradient>
        </defs>
        <rect width="1280" height="720" fill="url(#s12g)"/>
        <rect width="1280" height="720" fill="url(#s12grid)" opacity="0.42"/>
        <circle cx="640" cy="360" r="280" fill="none" stroke="url(#s12glow)" strokeWidth="1" opacity="0.15"/>
        <circle cx="640" cy="360" r="180" fill="none" stroke="url(#s12glow)" strokeWidth="1" opacity="0.2"/>
      </svg>
      <div className="slide-content pdf-safe" style={{display:'flex', flexDirection:'column', alignItems:'center', justifyContent:'center', textAlign:'center', gap:24}}>
        <div className="tag" style={{margin:'0 auto'}}>12 · CLOSE</div>
        <h1 className="slide-title" style={{fontSize:56, maxWidth:'18ch', margin:'0 auto'}}>
          Control AI agents.<br/>
          <span className="accent-blue">Prove what happened.</span>
        </h1>
        <div className="calm-quote" style={{fontSize:20, maxWidth:'42ch', margin:'0 auto'}}>
          Connector is a company building the runtime governance layer for production AI systems, with the intent to anchor the product, IP, and customer trust layer in Canada.
        </div>
        
        <div style={{display:'flex', gap:24, marginTop:20, flexWrap:'wrap', justifyContent:'center'}}>
          <div className="hero-stat" style={{minWidth:180}}>
            <strong style={{fontSize:32, color:'#00c8f8'}}>Control</strong>
            <span>Hard policy enforcement</span>
          </div>
          <div className="hero-stat" style={{minWidth:180}}>
            <strong style={{fontSize:32, color:'#a78bfa'}}>Memory</strong>
            <span>Tamper-resistant storage</span>
          </div>
          <div className="hero-stat" style={{minWidth:180}}>
            <strong style={{fontSize:32, color:'#10d98a'}}>Proof</strong>
            <span>Audit-ready evidence</span>
          </div>
        </div>
        
        <div style={{display:'flex', gap:18, flexWrap:'wrap', justifyContent:'center', marginTop:10}}>
          <div className="contact-card" style={{minWidth:220, maxWidth:220, textAlign:'left'}}>
            <div className="contact-label">BY END OF AUGUST</div>
            <div className="contact-val">2 signed pilots</div>
            <div style={{fontSize:13, color:'#8ba4be', marginTop:8}}>In regulated or high-consequence workflows where hallucination risk and operational instability already hurt the buyer.</div>
          </div>
          <div className="contact-card" style={{minWidth:220, maxWidth:220, textAlign:'left'}}>
            <div className="contact-label">COMMERCIAL TARGET</div>
            <div className="contact-val">4-5 LOIs</div>
            <div style={{fontSize:13, color:'#8ba4be', marginTop:8}}>Canadian accounts show domestic impact; U.S. accounts show export potential and category pull.</div>
          </div>
          <div className="contact-card" style={{minWidth:220, maxWidth:220, textAlign:'left'}}>
            <div className="contact-label">FUNDRAISING TARGET</div>
            <div className="contact-val">$30K-$100K</div>
            <div style={{fontSize:13, color:'#8ba4be', marginTop:8}}>Early pre-seed investor conversations backed by pilot proof, design-partner evidence, and a clear use-of-proceeds story.</div>
          </div>
        </div>

        <div style={{marginTop:14, display:'flex', flexDirection:'column', gap:16, alignItems:'center'}}>
          <div style={{
            fontSize:18,
            fontWeight:700,
            letterSpacing:'.12em',
            textTransform:'uppercase',
            color:'#00c8f8'
          }}>
            WHY THE COMPANY NEEDS TO WIN NOW
          </div>
          <div style={{fontSize:15, color:'#8ba4be', maxWidth:'62ch'}}>
            This is not about one founder needing an outcome. It is about Connector becoming a durable Canadian company that keeps the product surface, core runtime R&amp;D, and governance IP in Canada while serving regulated buyers who need a sovereign control layer for agentic systems.
          </div>
        </div>
        
        <div className="contact-row" style={{marginTop:32, justifyContent:'center'}}>
          <div className="contact-card">
            <div className="contact-label">WEBSITE</div>
            <div className="contact-val">connector.dev</div>
          </div>
          <div className="contact-card">
            <div className="contact-label">EMAIL</div>
            <div className="contact-val">hello@connector.dev</div>
          </div>
          <div className="contact-card">
            <div className="contact-label">GITHUB</div>
            <div className="contact-val">github.com/connector</div>
          </div>
        </div>
      </div>
    </div>
  );
}

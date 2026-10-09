import { useState, useRef, useCallback, useEffect } from 'react';
import './App.css';
import { slides } from './slides/data';
import Slide1 from './slides/Slide1';
import Slide2 from './slides/Slide2';
import Slide3 from './slides/Slide3';
import Slide4 from './slides/Slide4';
import Slide5 from './slides/Slide5';
import Slide6 from './slides/Slide6';
import Slide7 from './slides/Slide7';
import Slide8 from './slides/Slide8';
import Slide9 from './slides/Slide9';
import Slide10 from './slides/Slide10';
import Slide11 from './slides/Slide11';
import Slide12 from './slides/Slide12';
import html2canvas from 'html2canvas';
import jsPDF from 'jspdf';

const SLIDE_COMPONENTS = [Slide1, Slide2, Slide3, Slide4, Slide5, Slide6, Slide7, Slide8, Slide9, Slide10, Slide11, Slide12];
const THUMB_COLORS = ['#00c8f8','#f43f5e','#f59e0b','#00c8f8','#a78bfa','#10d98a','#a78bfa','#10d98a','#00c8f8','#10d98a','#f59e0b','#a78bfa'];

// Fixed 16:9 slide dimensions used for capture
const SLIDE_W = 1280;
const SLIDE_H = 720;

function ThumbSlide({ idx }: { idx: number }) {
  const C = SLIDE_COMPONENTS[idx];
  const col = THUMB_COLORS[idx];
  const scale = 108 / SLIDE_W; // thumbnail width / actual width
  return (
    <div style={{
      position: 'absolute', top: 0, left: 0,
      width: SLIDE_W, height: SLIDE_H,
      transform: `scale(${scale})`,
      transformOrigin: 'top left',
      pointerEvents: 'none',
    }}>
      <C />
      <div style={{ position: 'absolute', inset: 0, border: `4px solid ${col}`, borderRadius: 10, opacity: 0.2, pointerEvents: 'none' }} />
    </div>
  );
}

export default function App() {
  const [current, setCurrent] = useState(0);
  const [status, setStatus] = useState('');
  const frameRef = useRef<HTMLDivElement>(null);
  // hidden render container for PDF capture
  const captureRef = useRef<HTMLDivElement>(null);

  const CurrentSlide = SLIDE_COMPONENTS[current];

  // Dynamically compute scale so the fixed-1280x720 slide fills the frame exactly
  useEffect(() => {
    const update = () => {
      const frame = frameRef.current;
      if (!frame) return;
      const scaleX = frame.clientWidth  / SLIDE_W;
      const scaleY = frame.clientHeight / SLIDE_H;
      const scale  = Math.min(scaleX, scaleY);
      frame.style.setProperty('--slide-scale', String(scale));
    };
    update();
    const ro = new ResizeObserver(update);
    if (frameRef.current) ro.observe(frameRef.current);
    return () => ro.disconnect();
  }, []);

  const go = (dir: number) => setCurrent(c => Math.max(0, Math.min(slides.length - 1, c + dir)));

  const handleKey = useCallback((e: React.KeyboardEvent) => {
    if (e.key === 'ArrowRight' || e.key === 'ArrowDown') go(1);
    if (e.key === 'ArrowLeft'  || e.key === 'ArrowUp')   go(-1);
  }, []);

  // Render a slide at fixed 1280x720 off-screen and capture it
  const captureSlide = async (idx: number): Promise<HTMLCanvasElement> => {
    return new Promise((resolve, reject) => {
      const container = captureRef.current;
      if (!container) { reject(new Error('no container')); return; }

      // Mount the slide component into the capture container
      const C = SLIDE_COMPONENTS[idx];
      import('react-dom/client').then(({ createRoot }) => {
        import('react').then(({ createElement }) => {
          const root = createRoot(container);
          root.render(createElement(C));
          // Wait for render + fonts
          setTimeout(() => {
            html2canvas(container, {
              width: SLIDE_W,
              height: SLIDE_H,
              scale: 1.5,
              useCORS: true,
              backgroundColor: '#06111e',
              logging: false,
            }).then(canvas => {
              root.unmount();
              resolve(canvas);
            }).catch(err => {
              root.unmount();
              reject(err);
            });
          }, 180);
        });
      });
    });
  };

  const downloadPDF = async () => {
    setStatus('Generating PDF… 0/12');
    const pdf = new jsPDF({ orientation: 'landscape', unit: 'px', format: [SLIDE_W, SLIDE_H], compress: true });

    for (let i = 0; i < slides.length; i++) {
      setStatus(`Rendering slide ${i + 1} / ${slides.length}…`);
      try {
        const canvas = await captureSlide(i);
        const imgData = canvas.toDataURL('image/jpeg', 0.95);
        if (i > 0) pdf.addPage([SLIDE_W, SLIDE_H], 'landscape');
        pdf.addImage(imgData, 'JPEG', 0, 0, SLIDE_W, SLIDE_H);
      } catch (e) {
        console.error('slide capture error', e);
      }
    }

    pdf.save('Connector_Platform_Deck_Mar2026.pdf');
    setStatus('');
  };

  const downloadCurrentSVG = () => {
    const i = current;
    const slideNum = String(i + 1).padStart(2, '0');
    const title = slides[i].title.replace(/[^a-zA-Z0-9]+/g, '_').slice(0, 30);
    const el = frameRef.current;
    if (!el) return;

    html2canvas(el, {
      width: SLIDE_W, height: SLIDE_H, scale: 1.5,
      useCORS: true, backgroundColor: '#06111e', logging: false,
    }).then(canvas => {
      canvas.toBlob(blob => {
        if (!blob) return;
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `Connector_Slide_${slideNum}_${title}.png`;
        document.body.appendChild(a); a.click();
        document.body.removeChild(a); URL.revokeObjectURL(url);
      }, 'image/png');
    });
  };

  const isGenerating = status !== '';

  return (
    <div className="ppt-shell" tabIndex={0} onKeyDown={handleKey} style={{ outline: 'none' }}>
      {/* HIDDEN CAPTURE CONTAINER - fixed 1280x720, off screen */}
      <div ref={captureRef} style={{
        position: 'fixed', left: '-9999px', top: 0,
        width: SLIDE_W, height: SLIDE_H, overflow: 'hidden',
        background: '#06111e', zIndex: -1,
        fontFamily: "'Inter','Segoe UI',system-ui,sans-serif",
      }} />

      {/* TOP BAR */}
      <div className="topbar">
        <div className="topbar-logo">🔐 Connector</div>
        <div className="topbar-title">{slides[current].title}</div>
        <div className="topbar-right">
          {isGenerating && <span className="status-label">{status}</span>}
          <button className="dl-btn" onClick={downloadCurrentSVG} disabled={isGenerating} title="Download current slide as PNG">
            <svg width="13" height="13" viewBox="0 0 16 16" fill="currentColor"><path d="M8 12l-4-4h2.5V4h3v4H12L8 12z"/><rect x="2" y="13" width="12" height="1.5" rx="0.75"/></svg>
            PNG
          </button>
          <button className="dl-btn dl-btn-pdf" onClick={downloadPDF} disabled={isGenerating} title="Download full deck as PDF">
            <svg width="13" height="13" viewBox="0 0 16 16" fill="currentColor"><path d="M8 12l-4-4h2.5V4h3v4H12L8 12z"/><rect x="2" y="13" width="12" height="1.5" rx="0.75"/></svg>
            {isGenerating ? status : `PDF (All ${slides.length})`}
          </button>
        </div>
      </div>

      {/* MAIN */}
      <div className="ppt-main">
        {/* SLIDE STAGE */}
        <div className="slide-stage">
          {/* Wrapper that forces exact 16:9 at whatever screen size */}
          <div className="slide-sizer">
            <div className="slide-frame" ref={frameRef}>
              <CurrentSlide />
            </div>
          </div>
        </div>

        {/* THUMBNAIL STRIP */}
        <div className="thumb-strip">
          {slides.map((s, i) => (
            <div
              key={i}
              className={`thumb-item${i === current ? ' active' : ''}`}
              onClick={() => setCurrent(i)}
              title={s.title}
            >
              <div style={{ position: 'relative', width: '100%', paddingTop: '56.25%' }}>
                <div style={{ position: 'absolute', inset: 0, overflow: 'hidden' }}>
                  <ThumbSlide idx={i} />
                </div>
              </div>
              <div className="thumb-meta">
                <span className="thumb-number">{i + 1}</span>
                <span className="thumb-label">{s.title}</span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* BOTTOM NAV */}
      <div className="bottombar">
        <button className="nav-btn" onClick={() => go(-1)} disabled={current === 0}>← Prev</button>
        <div className="dot-nav">
          {slides.map((_, i) => (
            <button key={i} className={`dot-nav-item${i === current ? ' active' : ''}`} onClick={() => setCurrent(i)} />
          ))}
        </div>
        <div className="slide-counter">{current + 1} / {slides.length}</div>
        <button className="nav-btn nav-btn-primary" onClick={() => go(1)} disabled={current === slides.length - 1}>Next →</button>
      </div>
    </div>
  );
}

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
import Slide13 from './slides/Slide13';
import Slide14 from './slides/Slide14';
import Slide15 from './slides/Slide15';
import Slide16 from './slides/Slide16';
import Slide17 from './slides/Slide17';
import Slide18 from './slides/Slide18';
import Slide19 from './slides/Slide19';
import Slide20 from './slides/Slide20';
import html2canvas from 'html2canvas';
import jsPDF from 'jspdf';

const SLIDE_COMPONENTS = [
  Slide1, Slide2, Slide3, Slide4, Slide5, Slide6, Slide7, Slide8, Slide9, Slide10,
  Slide11, Slide12, Slide13, Slide14, Slide15, Slide16, Slide17, Slide18, Slide19, Slide20,
];

const THUMB_PALETTE = ['#00c8f8', '#f43f5e', '#f59e0b', '#a78bfa', '#10d98a'];
const THUMB_COLORS = slides.map((_, i) => THUMB_PALETTE[i % THUMB_PALETTE.length]);

const SLIDE_W = 1280;
const SLIDE_H = 720;

function ThumbSlide({ idx }: { idx: number }) {
  const C = SLIDE_COMPONENTS[idx];
  const col = THUMB_COLORS[idx];
  const scale = 108 / SLIDE_W;
  return (
    <div
      style={{
        position: 'absolute',
        top: 0,
        left: 0,
        width: SLIDE_W,
        height: SLIDE_H,
        transform: `scale(${scale})`,
        transformOrigin: 'top left',
        pointerEvents: 'none',
      }}
    >
      <C />
      <div style={{ position: 'absolute', inset: 0, border: `4px solid ${col}`, borderRadius: 10, opacity: 0.2, pointerEvents: 'none' }} />
    </div>
  );
}

export default function App() {
  const [current, setCurrent] = useState(0);
  const [status, setStatus] = useState('');
  const frameRef = useRef<HTMLDivElement>(null);
  const captureRef = useRef<HTMLDivElement>(null);

  const CurrentSlide = SLIDE_COMPONENTS[current];

  useEffect(() => {
    const update = () => {
      const frame = frameRef.current;
      if (!frame) return;
      const scaleX = frame.clientWidth / SLIDE_W;
      const scaleY = frame.clientHeight / SLIDE_H;
      const scale = Math.min(scaleX, scaleY);
      frame.style.setProperty('--slide-scale', String(scale));
    };
    update();
    const ro = new ResizeObserver(update);
    if (frameRef.current) ro.observe(frameRef.current);
    return () => ro.disconnect();
  }, []);

  const go = (dir: number) => setCurrent((c) => Math.max(0, Math.min(slides.length - 1, c + dir)));

  const handleKey = useCallback((e: React.KeyboardEvent) => {
    if (e.key === 'ArrowRight' || e.key === 'ArrowDown') go(1);
    if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') go(-1);
  }, []);

  const captureSlide = async (idx: number): Promise<HTMLCanvasElement> => {
    return new Promise((resolve, reject) => {
      const container = captureRef.current;
      if (!container) {
        reject(new Error('no container'));
        return;
      }

      const C = SLIDE_COMPONENTS[idx];
      import('react-dom/client').then(({ createRoot }) => {
        import('react').then(({ createElement }) => {
          const root = createRoot(container);
          root.render(createElement(C));
          setTimeout(() => {
            html2canvas(container, {
              width: SLIDE_W,
              height: SLIDE_H,
              scale: 1.5,
              useCORS: true,
              backgroundColor: '#06111e',
              logging: false,
            })
              .then((canvas) => {
                root.unmount();
                resolve(canvas);
              })
              .catch((err) => {
                root.unmount();
                reject(err);
              });
          }, 180);
        });
      });
    });
  };

  const downloadPDF = async () => {
    setStatus(`Generating PDF… 0/${slides.length}`);
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

    pdf.save('Connector_Youtube_Enterprise_Deck.pdf');
    setStatus('');
  };

  const downloadCurrentSVG = () => {
    const i = current;
    const slideNum = String(i + 1).padStart(2, '0');
    const title = slides[i].title.replace(/[^a-zA-Z0-9]+/g, '_').slice(0, 30);
    const el = frameRef.current;
    if (!el) return;

    html2canvas(el, {
      width: SLIDE_W,
      height: SLIDE_H,
      scale: 1.5,
      useCORS: true,
      backgroundColor: '#06111e',
      logging: false,
    }).then((canvas) => {
      canvas.toBlob((blob) => {
        if (!blob) return;
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `Connector_YT_Slide_${slideNum}_${title}.png`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
      }, 'image/png');
    });
  };

  const isGenerating = status !== '';

  return (
    <div className="ppt-shell" tabIndex={0} onKeyDown={handleKey} style={{ outline: 'none' }}>
      <div
        ref={captureRef}
        style={{
          position: 'fixed',
          left: '-9999px',
          top: 0,
          width: SLIDE_W,
          height: SLIDE_H,
          overflow: 'hidden',
          background: '#06111e',
          zIndex: -1,
          fontFamily: "'Inter','Segoe UI',system-ui,sans-serif",
        }}
      />

      <div className="topbar">
        <div className="topbar-logo">Connector · YouTube / Enterprise</div>
        <div className="topbar-title">{slides[current].title}</div>
        <div className="topbar-right">
          {isGenerating && <span className="status-label">{status}</span>}
          <button
            type="button"
            className="dl-btn"
            onClick={downloadCurrentSVG}
            disabled={isGenerating}
            title="Download current slide as PNG"
          >
            <svg width="13" height="13" viewBox="0 0 16 16" fill="currentColor">
              <path d="M8 12l-4-4h2.5V4h3v4H12L8 12z" />
              <rect x="2" y="13" width="12" height="1.5" rx="0.75" />
            </svg>
            PNG
          </button>
          <button
            type="button"
            className="dl-btn dl-btn-pdf"
            onClick={downloadPDF}
            disabled={isGenerating}
            title="Download full deck as PDF (html2canvas + jsPDF)"
          >
            <svg width="13" height="13" viewBox="0 0 16 16" fill="currentColor">
              <path d="M8 12l-4-4h2.5V4h3v4H12L8 12z" />
              <rect x="2" y="13" width="12" height="1.5" rx="0.75" />
            </svg>
            {isGenerating ? status : `PDF (all ${slides.length})`}
          </button>
        </div>
      </div>

      <div className="ppt-main">
        <div className="slide-stage">
          <div className="slide-sizer">
            <div className="slide-frame" ref={frameRef}>
              <CurrentSlide />
            </div>
          </div>
        </div>

        <div className="thumb-strip">
          {slides.map((s, i) => (
            <div
              key={s.id}
              className={`thumb-item${i === current ? ' active' : ''}`}
              onClick={() => setCurrent(i)}
              title={s.title}
              role="presentation"
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

      <div className="bottombar">
        <button type="button" className="nav-btn" onClick={() => go(-1)} disabled={current === 0}>
          ← Prev
        </button>
        <div className="dot-nav">
          {slides.map((_, i) => (
            <button
              key={i}
              type="button"
              className={`dot-nav-item${i === current ? ' active' : ''}`}
              onClick={() => setCurrent(i)}
              aria-label={`Go to slide ${i + 1}`}
            />
          ))}
        </div>
        <div className="slide-counter">
          {current + 1} / {slides.length}
        </div>
        <button type="button" className="nav-btn nav-btn-primary" onClick={() => go(1)} disabled={current === slides.length - 1}>
          Next →
        </button>
      </div>
    </div>
  );
}

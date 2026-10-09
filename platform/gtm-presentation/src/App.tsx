import { useEffect, useMemo, useRef, useState } from 'react'
import { toPng } from 'html-to-image'
import jsPDF from 'jspdf'
import {
  Activity,
  ArrowRight,
  Blocks,
  BrainCircuit,
  Briefcase,
  Building2,
  ChevronLeft,
  ChevronRight,
  CircleDollarSign,
  Download,
  Gauge,
  Maximize,
  ScanSearch,
  ShieldCheck,
  Sparkles,
  Target,
  Workflow,
  Wrench,
} from 'lucide-react'
import { Highlight, Slide, SlideContent, SlideTitle } from './components/Slide'

type DeckSlide = {
  title?: string
  node: React.ReactNode
}

function App() {
  const exportContainerRef = useRef<HTMLDivElement | null>(null)
  const [isExporting, setIsExporting] = useState(false)
  const [exportError, setExportError] = useState<string | null>(null)
  const slides = useMemo<DeckSlide[]>(() => {
    const total = 14

    return [
      {
        title: 'Cover',
        node: (
          <Slide slideNumber={0} totalSlides={total - 1}>
            <div className="flex h-full flex-col items-center justify-center text-center">
              <div className="mb-4 inline-flex items-center gap-2 rounded-full border border-blue-500/30 bg-blue-500/10 px-4 py-1.5 text-[10px] font-semibold uppercase tracking-[0.25em] text-blue-300 xl:text-sm">
                <Sparkles size={16} />
                Connector
              </div>
              <h1 className="max-w-5xl text-4xl font-black tracking-[-0.05em] text-white xl:text-6xl">
                Internal Workflow Control
              </h1>
              <p className="mt-4 max-w-3xl text-base leading-relaxed text-slate-300 xl:text-xl">
                A crystal-clear design partner presentation for teams actively fixing unstable AI workflows.
              </p>
              <div className="mt-6 flex flex-wrap items-center justify-center gap-3 text-xs text-slate-400 xl:text-sm">
                <span className="rounded-full border border-slate-700 bg-slate-800 px-4 py-1.5">Design Partner Deck</span>
                <span className="rounded-full border border-slate-700 bg-slate-800 px-4 py-1.5">PDF Export Ready</span>
                <span className="rounded-full border border-slate-700 bg-slate-800 px-4 py-1.5">2026-03-27</span>
              </div>
            </div>
          </Slide>
        ),
      },
      {
        title: 'What we are selling',
        node: (
          <Slide slideNumber={1} totalSlides={total - 1}>
            <SlideTitle>WHAT WE ARE SELLING</SlideTitle>
            <SlideContent>
              <div className="rounded-3xl border border-blue-500/30 bg-gradient-to-br from-blue-500/10 to-indigo-500/10 p-5 shadow-[0_0_80px_rgba(59,130,246,0.12)]">
                <p className="text-lg font-medium leading-relaxed text-slate-100 xl:text-2xl">
                  Existing tools observe AI — <span className="font-bold text-blue-400">we control and verify execution</span> before damage happens.
                </p>
              </div>
              <div className="grid grid-cols-2 gap-4 pt-2">
                <div className="rounded-2xl border border-slate-800 bg-slate-800/40 p-4">
                  <div className="mb-2 flex items-center gap-2 text-blue-400"><Target size={16} /> <span className="text-sm font-bold uppercase tracking-wider xl:text-base">Focus</span></div>
                  <p className="text-sm text-slate-200 xl:text-lg">Control + proof for <Highlight>internal AI workflows under active development</Highlight>.</p>
                </div>
                <div className="rounded-2xl border border-slate-800 bg-slate-800/40 p-4">
                  <div className="mb-2 flex items-center gap-2 text-blue-400"><Wrench size={16} /> <span className="text-sm font-bold uppercase tracking-wider xl:text-base">Wedge</span></div>
                  <p className="text-sm text-slate-200 xl:text-lg">We fix unstable workflows at the execution level using <Highlight>schema enforcement</Highlight>, <Highlight>tool-call blocking</Highlight>, and <Highlight>state-aware retries</Highlight>.</p>
                </div>
                <div className="rounded-2xl border border-slate-800 bg-slate-800/40 p-4">
                  <div className="mb-2 flex items-center gap-2 text-blue-400"><Briefcase size={16} /> <span className="text-sm font-bold uppercase tracking-wider xl:text-base">Motion</span></div>
                  <p className="text-sm text-slate-200 xl:text-lg">Sold as a <Highlight>pilot collaboration</Highlight> to stabilize and validate one critical workflow.</p>
                </div>
                <div className="rounded-2xl border border-slate-800 bg-slate-800/40 p-4">
                  <div className="mb-2 flex items-center gap-2 text-blue-400"><ShieldCheck size={16} /> <span className="text-sm font-bold uppercase tracking-wider xl:text-base">Outcome</span></div>
                  <p className="text-sm text-slate-200 xl:text-lg">Predictable, debuggable, accountable AI execution.</p>
                </div>
              </div>
            </SlideContent>
          </Slide>
        ),
      },
      {
        title: 'Product surface',
        node: (
          <Slide slideNumber={2} totalSlides={total - 1}>
            <SlideTitle>PRODUCT SURFACE (WHERE WE SIT)</SlideTitle>
            <SlideContent>
              <div className="space-y-2">
                <p className="text-xl text-slate-300 xl:text-2xl">We sit parallel to execution --- like a control shell around agent workflows.</p>
                <p className="text-lg text-blue-200 xl:text-xl">We don&apos;t just observe decisions, we govern them in real time.</p>
              </div>
              <div className="mt-1.5 space-y-2.5">
                <div className="rounded-2xl border border-slate-700 bg-slate-800/30 p-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <div className="text-sm uppercase tracking-[0.3em] text-slate-500">Layer 1</div>
                      <div className="mt-1 text-2xl font-bold text-white xl:text-3xl">LLM / Agent Orchestration</div>
                    </div>
                    <Workflow size={36} className="text-slate-500 xl:h-11 xl:w-11" />
                  </div>
                  <div className="mt-1.5 text-lg text-slate-400 xl:text-xl">Your code: LangChain, custom agents, pipelines, experiment harnesses.</div>
                </div>
                <div className="flex justify-center py-0.5 text-blue-400"><ArrowRight size={28} className="rotate-90 xl:h-8 xl:w-8" /></div>
                <div className="rounded-2xl border-2 border-blue-500 bg-blue-500/10 p-4 shadow-[0_0_50px_rgba(59,130,246,0.15)]">
                  <div className="flex items-center justify-between">
                    <div>
                      <div className="text-sm uppercase tracking-[0.3em] text-blue-300">Layer 2</div>
                      <div className="mt-1 text-2xl font-bold text-white xl:text-3xl">Execution Layer (Us)</div>
                    </div>
                    <Blocks size={38} className="text-blue-400 xl:h-11 xl:w-11" />
                  </div>
                  <div className="mt-2.5 grid grid-cols-3 gap-2 text-sm text-blue-100 xl:text-lg">
                    <div className="rounded-xl border border-blue-500/30 bg-slate-900/40 p-2.5">Schema validation</div>
                    <div className="rounded-xl border border-blue-500/30 bg-slate-900/40 p-2.5">Tool blocking</div>
                    <div className="rounded-xl border border-blue-500/30 bg-slate-900/40 p-2.5">Smart retries</div>
                  </div>
                  <div className="mt-2.5 grid grid-cols-3 gap-2 text-[11px] leading-snug text-slate-200 xl:text-xs">
                    <div className="rounded-xl border border-slate-700/70 bg-slate-950/50 p-2.5">
                      <div className="mb-1 text-[10px] font-bold uppercase tracking-[0.25em] text-blue-300 xl:text-xs">Like air traffic control</div>
                      <p>Guides or blocks unsafe moves while the system is still running.</p>
                    </div>
                    <div className="rounded-xl border border-slate-700/70 bg-slate-950/50 p-2.5">
                      <div className="mb-1 text-[10px] font-bold uppercase tracking-[0.25em] text-blue-300 xl:text-xs">Like a circuit breaker</div>
                      <p>Cuts unsafe execution in the moment, not after damage is done.</p>
                    </div>
                    <div className="rounded-xl border border-slate-700/70 bg-slate-950/50 p-2.5">
                      <div className="mb-1 text-[10px] font-bold uppercase tracking-[0.25em] text-blue-300 xl:text-xs">Like payment authorization</div>
                      <p>Approves, blocks, or reroutes risky actions before they settle.</p>
                    </div>
                  </div>
                </div>
                <div className="flex justify-center py-0.5 text-slate-500"><ArrowRight size={28} className="rotate-90 xl:h-8 xl:w-8" /></div>
                <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-4 opacity-90">
                  <div className="flex items-center justify-between">
                    <div>
                      <div className="text-sm uppercase tracking-[0.3em] text-slate-500">Layer 3</div>
                      <div className="mt-1 text-2xl font-bold text-slate-300 xl:text-3xl">Logs / Observability</div>
                    </div>
                    <ScanSearch size={36} className="text-slate-500 xl:h-11 xl:w-11" />
                  </div>
                  <div className="mt-1.5 text-lg text-slate-500 xl:text-xl">Datadog, Honeycomb, LangSmith, traces and dashboards after execution.</div>
                </div>
              </div>
            </SlideContent>
          </Slide>
        ),
      },
      {
        title: 'Next 6 months',
        node: (
          <Slide slideNumber={3} totalSlides={total - 1}>
            <SlideTitle>NEXT 6 MONTHS: DESIGN PARTNER PHASE</SlideTitle>
            <SlideContent>
              <div className="grid grid-cols-12 gap-3">
                <div className="col-span-7 space-y-3">
                  <div className="rounded-2xl border border-slate-800 bg-slate-800/30 p-3.5">
                    <div className="mb-3 flex items-center gap-2 text-blue-400"><Activity size={16} /> <span className="text-sm font-bold uppercase tracking-wider xl:text-base">Operating model</span></div>
                    <div className="grid grid-cols-3 gap-3">
                      <div className="rounded-2xl border border-slate-700 bg-slate-900/50 p-3">
                        <div className="text-[10px] font-bold uppercase tracking-[0.25em] text-slate-500 xl:text-xs">Target</div>
                        <div className="mt-1.5 text-2xl font-black text-white xl:text-3xl">10–20</div>
                        <div className="mt-0.5 text-sm text-slate-300 xl:text-base">paid pilots</div>
                      </div>
                      <div className="rounded-2xl border border-slate-700 bg-slate-900/50 p-3">
                        <div className="text-[10px] font-bold uppercase tracking-[0.25em] text-slate-500 xl:text-xs">Scope</div>
                        <div className="mt-1.5 text-lg font-bold text-white xl:text-xl">1 workflow</div>
                        <div className="mt-0.5 text-sm text-slate-300 xl:text-base">1 team</div>
                      </div>
                      <div className="rounded-2xl border border-slate-700 bg-slate-900/50 p-3">
                        <div className="text-[10px] font-bold uppercase tracking-[0.25em] text-slate-500 xl:text-xs">Duration</div>
                        <div className="mt-1.5 text-lg font-bold text-white xl:text-xl">3–6 months</div>
                        <div className="mt-0.5 text-sm text-slate-300 xl:text-base">real collaboration</div>
                      </div>
                    </div>
                  </div>
                  <div className="rounded-3xl border-2 border-blue-500 bg-blue-500/10 p-4 shadow-[0_0_50px_rgba(59,130,246,0.12)]">
                    <div className="mb-2 text-[10px] font-bold uppercase tracking-[0.25em] text-blue-300 xl:text-xs">Pilot ROI</div>
                    <p className="text-base leading-relaxed text-white xl:text-xl">Teams like you spend <Highlight>2–6 months</Highlight> stabilizing internal workflows. We compress that into weeks.</p>
                    <p className="mt-2 text-sm text-blue-100 xl:text-base">This is not SaaS onboarding --- it is co-development of one critical workflow with real engineering involvement.</p>
                  </div>
                  <div className="rounded-3xl border-2 border-emerald-500 bg-emerald-500/10 p-4 shadow-[0_0_50px_rgba(16,185,129,0.12)]">
                    <div className="mb-2 text-[10px] font-bold uppercase tracking-[0.25em] text-emerald-300 xl:text-xs">By end of August</div>
                    <div className="grid grid-cols-3 gap-3">
                      <div className="rounded-2xl border border-emerald-500/20 bg-slate-900/40 p-3">
                        <div className="text-xl font-black text-white xl:text-2xl">2</div>
                        <div className="mt-1 text-sm font-semibold text-emerald-200 xl:text-base">signed pilots</div>
                      </div>
                      <div className="rounded-2xl border border-emerald-500/20 bg-slate-900/40 p-3">
                        <div className="text-xl font-black text-white xl:text-2xl">4–5</div>
                        <div className="mt-1 text-sm font-semibold text-emerald-200 xl:text-base">LOIs</div>
                      </div>
                      <div className="rounded-2xl border border-emerald-500/20 bg-slate-900/40 p-3">
                        <div className="text-xl font-black text-white xl:text-2xl">$30K–$100K</div>
                        <div className="mt-1 text-sm font-semibold text-emerald-200 xl:text-base">pre-seed talks</div>
                      </div>
                    </div>
                    <p className="mt-2 text-xs leading-relaxed text-emerald-100 xl:text-sm">The company goal is to prove market validation, export potential, and a fundable operating plan --- not to tell a founder story, but to show Connector has to exist as a durable Canadian company.</p>
                  </div>
                </div>
                <div className="col-span-5 space-y-3">
                  <div className="rounded-3xl border border-emerald-500/20 bg-gradient-to-br from-emerald-500/10 to-slate-900 p-3.5">
                    <div className="mb-3 flex items-center gap-2 text-emerald-300"><CircleDollarSign size={18} /> <span className="text-sm font-bold uppercase tracking-wider xl:text-base">Pilot economics</span></div>
                    <div className="text-2xl font-black text-white xl:text-3xl">$1k–$5k / month</div>
                    <div className="mt-1 text-sm text-slate-400 xl:text-base">3–6 months</div>
                    <ul className="mt-2 space-y-1.5 text-sm text-slate-200 xl:text-base">
                      <li>Engineering involvement</li>
                      <li>Workflow debugging</li>
                      <li>Architecture support</li>
                    </ul>
                  </div>
                  <div className="rounded-2xl border border-slate-800 bg-slate-800/30 p-3.5">
                    <div className="mb-3 flex items-center gap-2 text-blue-400"><Gauge size={16} /> <span className="text-sm font-bold uppercase tracking-wider xl:text-base">Expected output</span></div>
                    <ul className="space-y-1.5 text-sm text-slate-200 xl:text-base">
                      <li>A few completed pilots</li>
                      <li>A few active pilots</li>
                      <li>A few strong opportunities in pipeline</li>
                    </ul>
                  </div>
                  <div className="rounded-2xl border border-amber-500/20 bg-amber-500/10 p-3.5">
                    <div className="mb-2 text-sm font-bold uppercase tracking-wider text-amber-300 xl:text-base">Proof package</div>
                    <ul className="space-y-1.5 text-xs text-slate-100 xl:text-sm">
                      <li>Early pre-seed investor conversations already in motion</li>
                      <li>Patent pending / IP filing shows company-owned global asset</li>
                      <li>2 professor validation reports confirming technical novelty and ecosystem importance</li>
                    </ul>
                  </div>
                </div>
              </div>
            </SlideContent>
          </Slide>
        ),
      },
      {
        title: 'Entry conditions',
        node: (
          <Slide slideNumber={4} totalSlides={total - 1}>
            <SlideTitle>TECHNICAL ENTRY CONDITIONS</SlideTitle>
            <SlideContent>
              <div className="grid grid-cols-3 gap-3">
                <div className="rounded-2xl border border-slate-800 bg-slate-800/30 p-4">
                  <div className="text-3xl font-black text-slate-700">X</div>
                  <div className="mt-1 text-lg font-bold text-blue-400 xl:text-xl">Domain</div>
                  <div className="mt-3 space-y-3 text-sm xl:text-base">
                    <div>
                      <div className="mb-1 font-bold uppercase tracking-widest text-green-400">Easy</div>
                      <div className="text-slate-300">Internal support automation<br />Dev workflow agents</div>
                    </div>
                    <div className="rounded-xl border border-blue-500/20 bg-blue-500/10 p-3">
                      <div className="mb-1 font-bold uppercase tracking-widest text-blue-400">Medium (Best)</div>
                      <div className="text-slate-100">LLM pipelines under iteration<br />Agent orchestration systems<br />Internal experimentation frameworks</div>
                    </div>
                    <div>
                      <div className="mb-1 font-bold uppercase tracking-widest text-red-400">Hard</div>
                      <div className="text-slate-400">Healthcare, finance, legal reasoning systems</div>
                    </div>
                  </div>
                </div>
                <div className="rounded-2xl border border-slate-800 bg-slate-800/30 p-4">
                  <div className="text-3xl font-black text-slate-700">Y</div>
                  <div className="mt-1 text-lg font-bold text-indigo-400 xl:text-xl">Stage</div>
                  <div className="mt-3 space-y-3 text-sm xl:text-base">
                    <div className="rounded-xl border border-indigo-500/20 bg-indigo-500/10 p-3 text-slate-100">
                      <div className="mb-2 font-bold uppercase tracking-widest text-indigo-300">Type 1 (Ideal)</div>
                      Agents in production.<br />Team actively fixing and improving internally.<br />Instability visible.
                    </div>
                    <div className="rounded-xl border border-slate-700 p-3 text-slate-400">
                      <div className="mb-2 font-bold uppercase tracking-widest">Type 2</div>
                      Heavy experimentation phase, trying to reach stability.
                    </div>
                  </div>
                </div>
                <div className="rounded-2xl border border-slate-800 bg-slate-800/30 p-4">
                  <div className="text-3xl font-black text-slate-700">Z</div>
                  <div className="mt-1 text-lg font-bold text-purple-400 xl:text-xl">Environment</div>
                  <div className="mt-3 space-y-2 text-sm text-slate-200 xl:text-base">
                    <div>API-based systems</div>
                    <div>Internal AI platforms</div>
                    <div>SRE / platform engineering ownership</div>
                  </div>
                  <div className="mt-4 rounded-xl border border-purple-500/20 bg-purple-500/10 p-3">
                    <div className="mb-1 font-bold uppercase tracking-widest text-purple-300">Buyer</div>
                    <div className="text-sm text-slate-100 xl:text-lg">Head of AI<br />Engineering Lead (AI systems)<br />CTO</div>
                  </div>
                </div>
              </div>
            </SlideContent>
          </Slide>
        ),
      },
      {
        title: 'ICP1',
        node: (
          <Slide slideNumber={5} totalSlides={total - 1}>
            <SlideTitle>ICP #1: INTERNAL FIX LOOP</SlideTitle>
            <SlideContent>
              <div className="mb-4 inline-flex rounded-full border border-blue-500/30 bg-blue-500/10 px-5 py-2 text-sm font-bold uppercase tracking-[0.3em] text-blue-300">Primary target</div>
              <div className="grid grid-cols-2 gap-6">
                <div className="rounded-2xl border border-slate-800 bg-slate-800/30 p-6">
                  <div className="mb-5 flex items-center gap-3 text-blue-400"><Building2 size={24} /> <span className="text-xl font-bold uppercase tracking-wider">Profile</span></div>
                  <p className="text-2xl text-slate-100 xl:text-3xl">AI-first SaaS / infra companies with agents already deployed internally.</p>
                  <div className="mt-6 rounded-xl border-l-4 border-amber-500 bg-slate-900/60 p-4 text-xl text-slate-300 xl:text-2xl">Teams are actively debugging, patching, and iterating workflows.</div>
                </div>
                <div className="space-y-5">
                  <div className="rounded-2xl border border-red-500/20 bg-red-500/5 p-6">
                    <div className="mb-5 text-xl font-bold uppercase tracking-wider text-red-400">Signals</div>
                    <ul className="space-y-3 text-xl text-slate-200 xl:text-2xl">
                      <li>Repeated fixes and hot-patches</li>
                      <li>Unstable outputs</li>
                      <li>Unclear failure sources</li>
                    </ul>
                  </div>
                  <div className="rounded-2xl border border-blue-500/20 bg-blue-500/10 p-6">
                    <div className="mb-5 text-xl font-bold uppercase tracking-wider text-blue-300">Need</div>
                    <p className="text-2xl text-white xl:text-3xl">Control internal behavior and <Highlight>drastically reduce debugging cycles</Highlight>.</p>
                  </div>
                </div>
              </div>
            </SlideContent>
          </Slide>
        ),
      },
      {
        title: 'ICP2',
        node: (
          <Slide slideNumber={6} totalSlides={total - 1}>
            <SlideTitle>ICP #2: EXPERIMENTATION LABS</SlideTitle>
            <SlideContent>
              <div className="grid grid-cols-12 gap-6">
                <div className="col-span-5 rounded-2xl border border-slate-800 bg-slate-800/30 p-6">
                  <div className="mb-5 flex items-center gap-3 text-indigo-400"><BrainCircuit size={28} /> <span className="text-xl font-bold uppercase tracking-wider">Profile</span></div>
                  <p className="text-2xl text-slate-100 xl:text-3xl">AI labs and startups running <Highlight>continuous experiments</Highlight>.</p>
                </div>
                <div className="col-span-7 space-y-5">
                  <div className="rounded-2xl border border-slate-800 bg-slate-800/30 p-6">
                    <div className="mb-5 text-xl font-bold uppercase tracking-wider text-slate-400">Situation</div>
                    <div className="text-xl text-slate-200 xl:text-2xl">Workflows evolving rapidly. No stable debugging framework. Prompt and context drift keep breaking logic.</div>
                  </div>
                  <div className="rounded-2xl border border-indigo-500/20 bg-indigo-500/10 p-6">
                    <div className="mb-5 text-xl font-bold uppercase tracking-wider text-indigo-300">Need</div>
                    <div className="grid grid-cols-3 gap-3 text-lg text-white xl:text-2xl">
                      <div className="rounded-xl bg-slate-900/40 p-3">Structured visibility</div>
                      <div className="rounded-xl bg-slate-900/40 p-3">Faster iteration</div>
                      <div className="rounded-xl bg-slate-900/40 p-3">Controlled experimentation</div>
                    </div>
                  </div>
                </div>
              </div>
            </SlideContent>
          </Slide>
        ),
      },
      {
        title: 'ICP3',
        node: (
          <Slide slideNumber={7} totalSlides={total - 1}>
            <SlideTitle>ICP #3: REGULATED SYSTEMS</SlideTitle>
            <SlideContent>
              <div className="text-center text-2xl text-slate-400 xl:text-3xl">Healthcare / fintech / legal internal AI</div>
              <div className="mt-6 grid grid-cols-2 gap-6">
                <div className="rounded-2xl border border-amber-500/20 bg-amber-500/5 p-6">
                  <div className="mb-5 text-xl font-bold uppercase tracking-wider text-amber-400">Situation</div>
                  <p className="text-2xl text-slate-100 xl:text-3xl">Internal teams cannot validate decisions reliably, and compliance pressure is increasing.</p>
                </div>
                <div className="rounded-2xl border border-purple-500/20 bg-purple-500/10 p-6">
                  <div className="mb-5 text-xl font-bold uppercase tracking-wider text-purple-300">Need</div>
                  <ul className="space-y-3 text-2xl text-slate-100 xl:text-3xl">
                    <li>Absolute traceability</li>
                    <li>Explainability of every LLM decision</li>
                    <li>Internal audit readiness</li>
                  </ul>
                </div>
              </div>
            </SlideContent>
          </Slide>
        ),
      },
      {
        title: 'Pilot model',
        node: (
          <Slide slideNumber={8} totalSlides={total - 1}>
            <SlideTitle>PILOT MODEL (CO-WORKFLOW ENGINEERING)</SlideTitle>
            <SlideContent>
              <div className="rounded-2xl border border-blue-500/20 bg-blue-500/10 p-4 text-center text-base font-medium text-slate-100 xl:text-2xl">
                One workflow. One team. One high-pain execution problem.
              </div>
              <div className="grid grid-cols-4 gap-3">
                {[
                  ['01', 'Define wedge', 'Agree on one workflow, one team, and one success metric.'],
                  ['02', 'Co-build', 'Instrument, debug, and adapt the control layer together with the client team.'],
                  ['03', 'Paid pilot', '$1k–$5k / month for 3–6 months with engineering and architecture support.'],
                  ['04', 'Extract pattern', 'Turn repeated fixes into reusable execution logic inside the product.'],
                ].map(([n, t, d], idx) => (
                  <div key={n} className={`rounded-2xl border p-3 ${idx === 1 ? 'border-blue-500 bg-blue-500/10' : idx === 3 ? 'border-green-500/30 bg-green-500/5' : 'border-slate-800 bg-slate-800/30'}`}>
                    <div className="text-2xl font-black text-slate-700 xl:text-3xl">{n}</div>
                    <div className="mt-2 text-base font-bold text-white xl:text-xl">{t}</div>
                    <div className="mt-2 text-xs leading-relaxed text-slate-300 xl:text-sm">{d}</div>
                  </div>
                ))}
              </div>
              <div className="rounded-2xl border border-emerald-500/20 bg-emerald-500/10 p-4 text-center text-base font-semibold text-white xl:text-2xl">
                Pilots → patterns → system.
              </div>
            </SlideContent>
          </Slide>
        ),
      },
      {
        title: 'Business model',
        node: (
          <Slide slideNumber={9} totalSlides={total - 1}>
            <SlideTitle>PRODUCT BUSINESS + CODEVELOPMENT</SlideTitle>
            <SlideContent>
              <div className="space-y-4">
                <div className="grid grid-cols-3 gap-4">
                  <div className="rounded-2xl border border-blue-500/20 bg-blue-500/10 p-4">
                    <div className="mb-2 text-sm font-bold uppercase tracking-wider text-blue-300 xl:text-base">Product business</div>
                    <div className="text-lg font-bold text-white xl:text-2xl">Execution governance system</div>
                    <p className="mt-2 text-sm text-slate-200 xl:text-base">The core sold is infrastructure as product: a deployed runtime layer that keeps enforcing how AI workflows are allowed to behave after the initial install is done.</p>
                  </div>
                  <div className="rounded-2xl border border-indigo-500/20 bg-indigo-500/10 p-4">
                    <div className="mb-2 text-sm font-bold uppercase tracking-wider text-indigo-300 xl:text-base">Deployment motion</div>
                    <div className="text-lg font-bold text-white xl:text-2xl">Codevelopment deployment</div>
                    <p className="mt-2 text-sm text-slate-200 xl:text-base">We co-develop the first workflow with the customer engineering team because infrastructure has to be fitted into a real stack once before it becomes the default system for the next workflows.</p>
                  </div>
                  <div className="rounded-2xl border border-emerald-500/20 bg-emerald-500/10 p-4">
                    <div className="mb-2 text-sm font-bold uppercase tracking-wider text-emerald-300 xl:text-base">Recurring model</div>
                    <div className="text-lg font-bold text-white xl:text-2xl">Product revenue + expansion</div>
                    <p className="mt-2 text-sm text-slate-200 xl:text-base">Annual product revenue, support, and expansion as more workflows and teams adopt the same installed system over time.</p>
                  </div>
                </div>
                <div className="grid grid-cols-3 gap-4">
                  <div className="rounded-2xl border border-slate-800 bg-slate-800/30 p-4">
                    <div className="mb-2 text-sm font-bold uppercase tracking-wider text-slate-300 xl:text-base">Why codevelopment exists</div>
                    <p className="text-sm leading-relaxed text-slate-200 xl:text-base">The first deployment extracts the real interfaces, policies, and failure modes from production. That is implementation of the product, not selling custom software forever.</p>
                  </div>
                  <div className="rounded-2xl border border-slate-800 bg-slate-800/30 p-4">
                    <div className="mb-2 text-sm font-bold uppercase tracking-wider text-slate-300 xl:text-base">Why this becomes a system</div>
                    <p className="text-sm leading-relaxed text-slate-200 xl:text-base">Every workflow we stabilize becomes reusable control logic --- that&apos;s how this becomes a system, not a service.</p>
                  </div>
                  <div className="rounded-2xl border border-amber-500/20 bg-amber-500/10 p-4">
                    <div className="mb-2 text-sm font-bold uppercase tracking-wider text-amber-300 xl:text-base">Closest analog</div>
                    <p className="text-sm leading-relaxed text-slate-100 xl:text-base"><span className="font-semibold text-white">Palantir</span> is the closer analog: product-first platforms deployed with forward-deployed engineers, where deep initial embedding gets the system into production and the platform becomes the standard operating layer inside the account.</p>
                  </div>
                </div>
              </div>
            </SlideContent>
          </Slide>
        ),
      },
      {
        title: 'Moat',
        node: (
          <Slide slideNumber={10} totalSlides={total - 1}>
            <SlideTitle>WHY THIS HOLDS</SlideTitle>
            <SlideContent>
              <div className="space-y-4">
                <div className="grid grid-cols-3 gap-4">
                  <div className="rounded-2xl border border-blue-500/20 bg-blue-500/10 p-4">
                    <div className="mb-2 text-sm font-bold uppercase tracking-wider text-blue-300 xl:text-base">Why this is scalable</div>
                    <p className="text-sm text-slate-100 xl:text-base">Every deployment reuses the same runtime primitives, policies, and adapters. That means implementation cost falls as the product surface becomes more complete.</p>
                  </div>
                  <div className="rounded-2xl border border-indigo-500/20 bg-indigo-500/10 p-4">
                    <div className="mb-2 text-sm font-bold uppercase tracking-wider text-indigo-300 xl:text-base">Why this is defensible</div>
                    <p className="text-sm text-slate-100 xl:text-base">Once our control layer sits in the execution path, removing it means losing enforcement, auditability, and learned workflow logic. That creates real switching cost.</p>
                  </div>
                  <div className="rounded-2xl border border-emerald-500/20 bg-emerald-500/10 p-4">
                    <div className="mb-2 text-sm font-bold uppercase tracking-wider text-emerald-300 xl:text-base">Why hyperscalers do not interfere</div>
                    <p className="text-sm text-slate-100 xl:text-base">AWS, OpenAI, and observability vendors stay horizontal. We go workflow-deep per customer, inside the specific execution logic they do not want to own.</p>
                  </div>
                </div>
                <div className="rounded-3xl border-2 border-blue-500 bg-blue-500/10 p-4 shadow-[0_0_50px_rgba(59,130,246,0.12)]">
                  <div className="mb-2 text-[10px] font-bold uppercase tracking-[0.25em] text-blue-300 xl:text-xs">Unavoidable layer</div>
                  <p className="text-base leading-relaxed text-white xl:text-2xl">If you remove us, <span className="font-bold text-blue-400">control disappears</span> --- not visibility. Your system goes back to guesswork.</p>
                </div>
                <div className="rounded-2xl border border-slate-800 bg-slate-800/30 p-4 text-sm text-slate-200 xl:text-lg">We touch execution governance only --- not customer app ownership, cloud infra, model hosting, or observability ownership.</div>
              </div>
            </SlideContent>
          </Slide>
        ),
      },
      {
        title: 'Growth path',
        node: (
          <Slide slideNumber={11} totalSlides={total - 1}>
            <SlideTitle>REALISTIC GROWTH PATH (2026-2035)</SlideTitle>
            <SlideContent>
              <div className="rounded-2xl border border-blue-500/20 bg-blue-500/10 p-3 text-center text-sm font-medium text-slate-100 xl:text-xl">
                Stay inside one narrow wedge: internal AI workflows where runtime control, auditability, and correctness matter in production.
              </div>
              <div className="grid grid-cols-3 gap-3">
                {[
                  ['2026', '10-20 pilots', 'Run design partner pilots. Converted production workflows should anchor around ~$100k ARR when the pain is real.'],
                  ['2027', '$300k-$500k ARR', 'Close the first recurring base and raise pre-seed only to keep pilot conversion and delivery moving.'],
                  ['2028', '$2M-$3M ARR + ~$1M funding', 'Turn repeated fixes into productized control patterns, hire carefully, and keep the wedge narrow.'],
                  ['2029', '$10M-$15M ARR', 'Reach this only if the same control layer repeats across 15-30 accounts. Plan for self-funded growth, not mandatory new capital.'],
                  ['2030-2032', '~$25M ARR by 2032', 'Expand within the same category: more workflows per account, more teams per account, stronger renewals, stable gross retention.'],
                  ['2033-2035', 'Stability and segment leadership', 'Hold category authority in the narrow segment. Any upside should come from adjacent internal workflows, not from chasing generic AI spend.'],
                ].map(([year, headline, detail], index) => (
                  <div
                    key={year}
                    className={`rounded-2xl border p-3 ${index === 1 || index === 2 ? 'border-blue-500/30 bg-blue-500/10' : index === 3 || index === 4 ? 'border-emerald-500/30 bg-emerald-500/10' : index === 5 ? 'border-amber-500/30 bg-amber-500/10' : 'border-slate-800 bg-slate-800/30'}`}
                  >
                    <div className="text-xs font-bold uppercase tracking-[0.22em] text-slate-400 xl:text-sm">{year}</div>
                    <div className="mt-1.5 text-base font-bold text-white xl:text-xl">{headline}</div>
                    <p className="mt-1.5 text-[11px] leading-relaxed text-slate-200 xl:text-xs">{detail}</p>
                  </div>
                ))}
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div className="rounded-2xl border border-slate-800 bg-slate-800/30 p-3 text-center text-xs text-slate-200 xl:text-sm">
                This is a disciplined operating plan for one controllable category --- not a top-down TAM projection and not a broad AI land grab.
                </div>
                <div className="rounded-2xl border border-emerald-500/20 bg-emerald-500/10 p-3 text-xs text-slate-100 xl:text-sm">
                  <div className="mb-1 text-[10px] font-bold uppercase tracking-[0.25em] text-emerald-300">Company proof by August</div>
                  Early pre-seed talks, patent pending/IP filing, and 2 professor validation reports should make the case that this company solves an important technical gap for the Canadian tech ecosystem.
                </div>
              </div>
            </SlideContent>
          </Slide>
        ),
      },
      {
        title: 'Segment dominance',
        node: (
          <Slide slideNumber={12} totalSlides={total - 1}>
            <SlideTitle>WHY THIS SEGMENT CAN STAY OURS</SlideTitle>
            <SlideContent>
              <div className="grid grid-cols-2 gap-4">
                <div className="rounded-2xl border border-blue-500/20 bg-blue-500/10 p-4">
                  <div className="mb-2 text-sm font-bold uppercase tracking-[0.25em] text-blue-300 xl:text-base">Narrow segment</div>
                  <p className="text-sm leading-relaxed text-slate-100 xl:text-lg">Internal, multi-step AI workflows that touch tools, systems, approvals, or records where runtime mistakes have operational or compliance cost.</p>
                </div>
                <div className="rounded-2xl border border-indigo-500/20 bg-indigo-500/10 p-4">
                  <div className="mb-2 text-sm font-bold uppercase tracking-[0.25em] text-indigo-300 xl:text-base">Market sentiment</div>
                  <p className="text-sm leading-relaxed text-slate-100 xl:text-lg">Production adoption is moving faster than controls. LangChain, PwC, and Deloitte all point to the same gap: more agents in production, weak governance maturity, rising budgets.</p>
                </div>
                <div className="rounded-2xl border border-emerald-500/20 bg-emerald-500/10 p-4">
                  <div className="mb-2 text-sm font-bold uppercase tracking-[0.25em] text-emerald-300 xl:text-base">Why hyperscalers do not crush this</div>
                  <p className="text-sm leading-relaxed text-slate-100 xl:text-lg">AWS owns infra and guardrails. Datadog and LangSmith own observability and debugging. We own workflow-specific runtime control inside mixed enterprise systems.</p>
                </div>
                <div className="rounded-2xl border border-amber-500/20 bg-amber-500/10 p-4">
                  <div className="mb-2 text-sm font-bold uppercase tracking-[0.25em] text-amber-300 xl:text-base">Dominance rule</div>
                  <p className="text-sm leading-relaxed text-slate-100 xl:text-lg">We do not chase consumer copilots, generic prompt tooling, or broad AI platforms. We stay where workflow depth compounds and integration makes us hard to remove.</p>
                </div>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div className="rounded-2xl border border-slate-800 bg-slate-800/30 p-4">
                  <div className="mb-2 text-sm font-bold uppercase tracking-[0.25em] text-slate-300 xl:text-base">Capturable market shape</div>
                  <p className="text-sm leading-relaxed text-slate-200 xl:text-lg">Hundreds of strong North America targets first, then a low-thousands global account universe. Dominance here means category authority in this wedge, not in all AI software.</p>
                </div>
                <div className="rounded-2xl border border-slate-800 bg-slate-800/30 p-4">
                  <div className="mb-2 text-sm font-bold uppercase tracking-[0.25em] text-slate-300 xl:text-base">Stability thesis</div>
                  <p className="text-sm leading-relaxed text-slate-200 xl:text-lg">A stable multi-$10M business comes first. Durable segment leadership comes from deeper workflow coverage per account, not from leaving the wedge too early.</p>
                </div>
              </div>
            </SlideContent>
          </Slide>
        ),
      },
      {
        title: 'Final position',
        node: (
          <Slide slideNumber={13} totalSlides={total - 1}>
            <div className="flex h-full flex-col justify-center">
              <h2 className="text-center text-2xl font-black tracking-[-0.05em] text-white xl:text-4xl">FINAL POSITION</h2>
              <div className="mt-4 grid grid-cols-3 gap-3">
                <div className="rounded-2xl border border-red-500/20 bg-red-500/5 p-4">
                  <div className="mb-2 text-xs font-bold uppercase tracking-[0.22em] text-red-400 xl:text-sm">Not</div>
                  <ul className="space-y-1.5 text-xs text-slate-300 xl:text-lg">
                    <li>A people-hours consulting firm</li>
                    <li>Managed workflow ops for customers</li>
                    <li>A replacement for AWS / Datadog / LangSmith</li>
                  </ul>
                </div>
                <div className="rounded-2xl border border-blue-500/20 bg-blue-500/10 p-4">
                  <div className="mb-2 text-xs font-bold uppercase tracking-[0.22em] text-blue-300 xl:text-sm">We are</div>
                  <p className="text-sm leading-tight text-white xl:text-xl">A <Highlight>product business with codevelopment deployment</Highlight> --- we sell the runtime control layer, and engineers help install the first version so it can become the standard system for the next workflows.</p>
                </div>
                <div className="rounded-2xl border border-emerald-500/20 bg-emerald-500/10 p-4">
                  <div className="mb-2 text-xs font-bold uppercase tracking-[0.22em] text-emerald-300 xl:text-sm">Market reality</div>
                  <p className="text-sm leading-tight text-white xl:text-xl">We stay in a narrow, high-pain wedge where the same controls repeat. That is what turns deployment work into a reusable system and makes the business scalable and defensible.</p>
                </div>
              </div>
              <div className="mt-4 rounded-3xl border-2 border-blue-500 bg-blue-500/10 p-4 shadow-[0_0_50px_rgba(59,130,246,0.12)]">
                <div className="mb-2 text-[10px] font-bold uppercase tracking-[0.25em] text-blue-300 xl:text-xs">Closing</div>
                <p className="text-base leading-relaxed text-white xl:text-2xl">We touch execution governance inside production workflows. We do not own customer application stacks, cloud infra, model hosting, or observability. That boundary keeps the business clear.</p>
                <p className="mt-2 text-sm font-semibold leading-relaxed text-blue-100 xl:text-xl">Closest analog: Palantir. Forward-deployed engineering gets the platform into real operations, but the long-term business is the installed system becoming a standard operating layer inside the account.</p>
              </div>
              <div className="mt-4 rounded-3xl border-2 border-emerald-500 bg-emerald-500/10 p-4 shadow-[0_0_50px_rgba(16,185,129,0.12)]">
                <div className="mb-2 text-[10px] font-bold uppercase tracking-[0.25em] text-emerald-300 xl:text-xs">Why the company needs to win now</div>
                <p className="text-base leading-relaxed text-white xl:text-2xl">Connector should be framed as a strategic Canadian company asset: a control and evidence layer for unstable agent systems, with product IP, runtime R&amp;D, and customer trust anchored in Canada.</p>
                <p className="mt-2 text-sm font-semibold leading-relaxed text-emerald-100 xl:text-xl">By end of August, the company target is to close 2 pilots, secure 4–5 LOIs, and advance $30K–$100K of early pre-seed investor conversations so the case stands on company traction and strategic value, not personal circumstance.</p>
              </div>
            </div>
          </Slide>
        ),
      },
    ]
  }, [])

  const [currentSlide, setCurrentSlide] = useState(0)

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'ArrowRight' || event.key === ' ') {
        setCurrentSlide((prev) => Math.min(prev + 1, slides.length - 1))
      }
      if (event.key === 'ArrowLeft') {
        setCurrentSlide((prev) => Math.max(prev - 1, 0))
      }
    }

    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [slides.length])

  const goPrev = () => setCurrentSlide((prev) => Math.max(prev - 1, 0))
  const goNext = () => setCurrentSlide((prev) => Math.min(prev + 1, slides.length - 1))

  const captureSlide = async (page: HTMLDivElement) => {
    await new Promise((resolve) => window.requestAnimationFrame(() => resolve(null)))
    await document.fonts.ready

    return toPng(page, {
      cacheBust: true,
      pixelRatio: 2,
      backgroundColor: '#0f172a',
      canvasWidth: 1600,
      canvasHeight: 900,
      width: 1600,
      height: 900,
    })
  }

  const handleDownloadPdf = async () => {
    const exportContainer = exportContainerRef.current

    if (!exportContainer || isExporting) {
      return
    }

    setIsExporting(true)
    setExportError(null)

    try {
      await new Promise((resolve) => window.requestAnimationFrame(() => resolve(null)))
      await new Promise((resolve) => setTimeout(resolve, 120))

      const pages = Array.from(exportContainer.querySelectorAll('[data-pdf-slide="true"]')) as HTMLDivElement[]

      if (pages.length === 0) {
        throw new Error('No slides available for PDF export.')
      }

      const pdf = new jsPDF({
        orientation: 'landscape',
        unit: 'px',
        format: [1600, 900],
        compress: true,
      })

      for (let index = 0; index < pages.length; index += 1) {
        const imageData = await captureSlide(pages[index])

        if (index > 0) {
          pdf.addPage([1600, 900], 'landscape')
        }

        pdf.addImage(imageData, 'PNG', 0, 0, 1600, 900, undefined, 'FAST')
      }

      pdf.save('connector-internal-workflow-control.pdf')
    } catch (error) {
      const message = error instanceof Error ? error.message : 'PDF export failed.'
      console.error('PDF export failed:', error)
      setExportError(message)
    } finally {
      setIsExporting(false)
    }
  }

  const handleFullscreen = async () => {
    if (!document.fullscreenElement) {
      await document.documentElement.requestFullscreen()
      return
    }
    await document.exitFullscreen()
  }

  return (
    <div className="min-h-screen bg-slate-950">
      <div className="print:hidden h-screen">{slides[currentSlide]?.node}</div>

      <div
        ref={exportContainerRef}
        className="pointer-events-none fixed left-[200vw] top-0 z-0 flex flex-col gap-0 opacity-100"
        aria-hidden="true"
      >
        {slides.map((slide, index) => (
          <div
            key={`pdf-${index}`}
            data-pdf-slide="true"
            className="flex h-[900px] w-[1600px] items-center justify-center overflow-hidden bg-slate-900"
          >
            <div className="flex h-[900px] w-[1600px] items-center justify-center overflow-hidden bg-slate-900">
              {slide.node}
            </div>
          </div>
        ))}
      </div>

      <div className="no-print fixed bottom-6 left-1/2 z-50 flex -translate-x-1/2 items-center gap-3 rounded-2xl border border-slate-700/60 bg-slate-900/85 px-4 py-3 shadow-2xl backdrop-blur-xl print:hidden">
        <button
          onClick={goPrev}
          disabled={currentSlide === 0}
          className="rounded-xl bg-slate-800 p-2.5 text-slate-200 transition hover:bg-slate-700 disabled:cursor-not-allowed disabled:opacity-40"
          title="Previous slide"
        >
          <ChevronLeft size={20} />
        </button>
        <div className="min-w-24 text-center text-xs font-semibold uppercase tracking-[0.25em] text-slate-400">
          {currentSlide + 1} / {slides.length}
        </div>
        <button
          onClick={goNext}
          disabled={currentSlide === slides.length - 1}
          className="rounded-xl bg-slate-800 p-2.5 text-slate-200 transition hover:bg-slate-700 disabled:cursor-not-allowed disabled:opacity-40"
          title="Next slide"
        >
          <ChevronRight size={20} />
        </button>
        <div className="mx-1 h-7 w-px bg-slate-700" />
        <button
          onClick={handleFullscreen}
          className="rounded-xl bg-slate-800 p-2.5 text-slate-200 transition hover:bg-slate-700"
          title="Toggle fullscreen"
        >
          <Maximize size={18} />
        </button>
        <button
          onClick={handleDownloadPdf}
          disabled={isExporting}
          className="inline-flex items-center gap-2 rounded-xl bg-blue-600 px-4 py-2.5 font-semibold text-white transition hover:bg-blue-500 disabled:cursor-wait disabled:opacity-60"
          title="Download as PDF"
        >
          <Download size={16} />
          {isExporting ? 'Exporting…' : 'PDF'}
        </button>
      </div>

      {exportError && (
        <div className="no-print fixed right-6 top-6 z-50 rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-200 shadow-xl print:hidden">
          {exportError}
        </div>
      )}
    </div>
  )
}

export default App

import { useState, type FormEvent } from 'react'

const API_PATH = import.meta.env.VITE_PILOT_SUBMIT_URL || '/api/submit-pilot'

type Status = 'idle' | 'submitting' | 'success' | 'error'

const PRODUCTS = [
  { slug: 'devguard',      label: 'DevGuard',      desc: 'Ready — coding-agent guardrails' },
  { slug: 'tracetramp',    label: 'TraceTramp',    desc: 'Ready — who did what' },
  { slug: 'witnessctl',    label: 'WitnessCtl',    desc: 'Ready — evidence trail' },
  { slug: 'conductor',     label: 'Conductor',     desc: 'Planned — multi-agent' },
  { slug: 'agentloop',     label: 'AgentLoop',     desc: 'Planned — fleet lifecycle' },
  { slug: 'ledgerlens',    label: 'LedgerLens',    desc: 'Planned — cost caps' },
  { slug: 'agentpassport', label: 'AgentPassport', desc: 'Planned — identity' },
  { slug: 'relay',         label: 'Relay',         desc: 'Planned — sit beneath your stack' },
  { slug: 'engram',        label: 'Engram',        desc: 'Planned — memory' },
  { slug: 'support-cx',    label: 'Support / CX',  desc: 'Planned — refunds & tickets' },
] as const

const ROLES = [
  'Developer',
  'ML / AI Engineer',
  'Platform Engineer',
  'Engineering Manager',
  'CTO / VP Engineering',
  'CISO / Security',
  'Founder',
  'Other',
] as const

const COMPANY_SIZES = ['1–10', '11–50', '51–200', '201–1000', '1000+'] as const

const USE_CASES = [
  'Agent governance & policy enforcement',
  'Cost & budget control',
  'Compliance & audit trail',
  'Memory management for agents',
  'Multi-agent orchestration',
  'Developer productivity tooling',
  'Regulated industry (healthcare, fintech)',
  'Other',
] as const

const TIMELINES = [
  'Evaluating now — ready to pilot',
  '1–3 months',
  '3–6 months',
  'Just researching',
] as const

interface FormProps {
  preselectedProduct?: string
}

export function PilotInterestForm({ preselectedProduct }: FormProps = {}) {
  const [status, setStatus]           = useState<Status>('idle')
  const [message, setMessage]         = useState('')
  const [selectedProducts, setSelected] = useState<Set<string>>(
    () => preselectedProduct ? new Set([preselectedProduct]) : new Set()
  )

  function toggleProduct(slug: string) {
    setSelected(prev => {
      const next = new Set(prev)
      if (next.has(slug)) next.delete(slug)
      else next.add(slug)
      return next
    })
  }

  function submitLabel() {
    const count = selectedProducts.size
    if (count === 0) return 'Request a conversation'
    if (count === 1) {
      const p = PRODUCTS.find(p => selectedProducts.has(p.slug))
      return `Talk about ${p?.label ?? 'this workflow'}`
    }
    return `Talk about ${count} workflows`
  }

  async function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault()
    setStatus('submitting')
    setMessage('')
    const fd = new FormData(e.currentTarget)
    const body = {
      name:           fd.get('name'),
      email:          fd.get('email'),
      company:        fd.get('company'),
      companySize:    fd.get('companySize'),
      role:           fd.get('role'),
      products:       [...selectedProducts],
      primaryUseCase: fd.get('primaryUseCase'),
      timeline:       fd.get('timeline'),
      useCase:        fd.get('useCase'),
      _hp:            fd.get('_hp'),
    }
    try {
      const res = await fetch(API_PATH, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
      const data = (await res.json().catch(() => ({}))) as { ok?: boolean; error?: string }
      if (!res.ok || !data.ok) {
        setStatus('error')
        setMessage(data.error || 'Something went wrong. Try again or email us.')
        return
      }
      setStatus('success')
      setMessage('Thanks — we will follow up shortly.')
      e.currentTarget.reset()
      setSelected(new Set())
    } catch {
      setStatus('error')
      setMessage('Network error. Check your connection or try again.')
    }
  }

  if (status === 'success') {
    return (
      <div className="pilot-form pilot-form--success card" role="status">
        <p className="pilot-form__success">{message}</p>
      </div>
    )
  }

  return (
    <form className="pilot-form card" onSubmit={onSubmit} noValidate>
      {/* Honeypot */}
      <p className="sr-only">Leave the next field empty. It catches bots.</p>
      <input type="text" name="_hp" tabIndex={-1} autoComplete="off" className="pilot-form__hp" aria-hidden="true" />

      {/* ── Product interest ────────────────────────────────────────────── */}
      <fieldset className="pilot-form__fieldset">
        <legend className="pilot-form__legend">
          Which products are you interested in?
          <span className="pilot-form__legend-hint"> (select all that apply)</span>
        </legend>
        <div className="pilot-form__chips">
          {PRODUCTS.map(p => (
            <button
              key={p.slug}
              type="button"
              className={`pilot-form__chip ${selectedProducts.has(p.slug) ? 'pilot-form__chip--active' : ''}`}
              onClick={() => toggleProduct(p.slug)}
              aria-pressed={selectedProducts.has(p.slug)}
            >
              <span className="chip-label">{p.label}</span>
              <span className="chip-desc">{p.desc}</span>
            </button>
          ))}
        </div>
      </fieldset>

      {/* ── Contact fields ───────────────────────────────────────────────── */}
      <div className="pilot-form__grid">
        <label className="pilot-form__field">
          <span>Name <span aria-hidden="true">*</span></span>
          <input name="name" type="text" required autoComplete="name" placeholder="Jane Smith" />
        </label>

        <label className="pilot-form__field">
          <span>Work email <span aria-hidden="true">*</span></span>
          <input name="email" type="email" required autoComplete="email" placeholder="jane@acme.com" />
        </label>

        <label className="pilot-form__field pilot-form__field--full">
          <span>Company <span aria-hidden="true">*</span></span>
          <input name="company" type="text" required autoComplete="organization" placeholder="Acme Inc." />
        </label>

        <label className="pilot-form__field">
          <span>Your role</span>
          <select name="role" required>
            <option value="">Select role…</option>
            {ROLES.map(r => <option key={r} value={r}>{r}</option>)}
          </select>
        </label>

        <label className="pilot-form__field">
          <span>Company size</span>
          <select name="companySize">
            <option value="">Select size…</option>
            {COMPANY_SIZES.map(s => <option key={s} value={s}>{s} people</option>)}
          </select>
        </label>

        <label className="pilot-form__field pilot-form__field--full">
          <span>Primary use case</span>
          <select name="primaryUseCase">
            <option value="">Select use case…</option>
            {USE_CASES.map(u => <option key={u} value={u}>{u}</option>)}
          </select>
        </label>

        <label className="pilot-form__field pilot-form__field--full">
          <span>When are you looking to start?</span>
          <select name="timeline">
            <option value="">Select timeline…</option>
            {TIMELINES.map(t => <option key={t} value={t}>{t}</option>)}
          </select>
        </label>

        <label className="pilot-form__field pilot-form__field--full">
          <span>What are you building? <span aria-hidden="true">*</span></span>
          <textarea
            name="useCase"
            required
            rows={4}
            placeholder="Briefly describe your agent workflow, the problem you're solving, and why you need governance infrastructure."
          />
        </label>
      </div>

      {status === 'error' && (
        <div className="pilot-form__error" role="alert">
          <p>{message}</p>
        </div>
      )}

      <div className="pilot-form__footer">
        <button
          type="submit"
          className="btn btn--primary pilot-form__submit"
          disabled={status === 'submitting'}
        >
          {status === 'submitting' ? 'Sending…' : submitLabel()}
        </button>
        <p className="pilot-form__privacy">
          We use your email only to follow up about the pilot — no marketing lists, no resale.
        </p>
      </div>
    </form>
  )
}

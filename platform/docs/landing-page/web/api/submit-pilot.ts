import type { VercelRequest, VercelResponse } from '@vercel/node'
import { sendPilotSubmissionEmails } from './_pilot-email'
import { insertPilotSubmission } from './_pilot-storage'

const MAX_LEN = { name: 120, email: 254, company: 120, useCase: 4000, role: 80 }

function isValidEmail(s: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s)
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (req.method === 'OPTIONS') {
    res.setHeader('Allow', 'POST, OPTIONS')
    return res.status(204).end()
  }
  if (req.method !== 'POST') {
    return res.status(405).json({ ok: false, error: 'Method not allowed' })
  }

  if (!process.env.POSTGRES_URL) {
    return res.status(503).json({
      ok: false,
      error: 'Server not configured for pilot submissions',
    })
  }

  const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body
  const name = String(body?.name ?? '').trim()
  const email = String(body?.email ?? '').trim()
  const company = String(body?.company ?? '').trim()
  const useCase = String(body?.useCase ?? '').trim()
  const role = String(body?.role ?? '').trim()
  const hp = String(body?._hp ?? '').trim()

  if (hp) {
    return res.status(200).json({ ok: true })
  }

  if (!name || !email || !company || !useCase) {
    return res.status(400).json({ ok: false, error: 'Missing required fields' })
  }
  if (!isValidEmail(email)) {
    return res.status(400).json({ ok: false, error: 'Invalid email' })
  }
  if (
    name.length > MAX_LEN.name ||
    email.length > MAX_LEN.email ||
    company.length > MAX_LEN.company ||
    useCase.length > MAX_LEN.useCase ||
    role.length > MAX_LEN.role
  ) {
    return res.status(400).json({ ok: false, error: 'Field too long' })
  }

  try {
    await insertPilotSubmission({
      id: crypto.randomUUID(),
      source: 'connector-landing',
      name,
      email,
      company,
      role: role || undefined,
      useCase,
    })
    await sendPilotSubmissionEmails({
      name,
      email,
      company,
      role: role || undefined,
      useCase,
    })
    return res.status(200).json({ ok: true })
  } catch (e) {
    const msg = e instanceof Error ? e.message : 'Request failed'
    return res.status(500).json({ ok: false, error: msg })
  }
}

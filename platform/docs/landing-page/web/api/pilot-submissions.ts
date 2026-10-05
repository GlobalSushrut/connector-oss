import type { VercelRequest, VercelResponse } from '@vercel/node'
import { listPilotSubmissions } from './_pilot-storage.js'

function isAuthorized(req: VercelRequest): boolean {
  const token = process.env.PILOT_SUBMISSIONS_TOKEN
  if (!token) {
    return false
  }

  const header = req.headers.authorization
  if (header && header === `Bearer ${token}`) {
    return true
  }

  const queryToken = typeof req.query.token === 'string' ? req.query.token : ''
  return queryToken === token
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET')
    return res.status(405).json({ ok: false, error: 'Method not allowed' })
  }

  if (!process.env.POSTGRES_URL) {
    return res.status(503).json({ ok: false, error: 'Server not configured for pilot submissions' })
  }

  if (!isAuthorized(req)) {
    return res.status(401).json({ ok: false, error: 'Unauthorized' })
  }

  const rawLimit = typeof req.query.limit === 'string' ? Number(req.query.limit) : 100

  try {
    const submissions = await listPilotSubmissions(rawLimit)
    return res.status(200).json({ ok: true, submissions })
  } catch (e) {
    const msg = e instanceof Error ? e.message : 'Request failed'
    return res.status(500).json({ ok: false, error: msg })
  }
}

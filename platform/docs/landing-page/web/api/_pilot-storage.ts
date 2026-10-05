export type PilotSubmission = {
  id: string
  submittedAt: string
  source: string
  name: string
  email: string
  company: string
  companySize: string | null
  role: string | null
  products: string | null
  primaryUseCase: string | null
  timeline: string | null
  useCase: string
}

let initPromise: Promise<void> | null = null

async function getSql() {
  const { sql } = await import('@vercel/postgres')
  return sql
}

async function ensureTable(): Promise<void> {
  if (!initPromise) {
    initPromise = getSql().then((sql) =>
      sql`
        CREATE TABLE IF NOT EXISTS pilot_submissions (
          id TEXT PRIMARY KEY,
          submitted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          source TEXT NOT NULL,
          name TEXT NOT NULL,
          email TEXT NOT NULL,
          company TEXT NOT NULL,
          company_size TEXT,
          role TEXT,
          products TEXT,
          primary_use_case TEXT,
          timeline TEXT,
          use_case TEXT NOT NULL
        )
      `.then(() => undefined),
    )
  }

  return initPromise
}

export async function insertPilotSubmission(input: {
  id: string
  source: string
  name: string
  email: string
  company: string
  companySize?: string
  role?: string
  products?: string
  primaryUseCase?: string
  timeline?: string
  useCase: string
}): Promise<void> {
  await ensureTable()
  const sql = await getSql()
  await sql`
    INSERT INTO pilot_submissions
      (id, source, name, email, company, company_size, role, products, primary_use_case, timeline, use_case)
    VALUES (
      ${input.id},
      ${input.source},
      ${input.name},
      ${input.email},
      ${input.company},
      ${input.companySize || null},
      ${input.role || null},
      ${input.products || null},
      ${input.primaryUseCase || null},
      ${input.timeline || null},
      ${input.useCase}
    )
  `
}

export async function listPilotSubmissions(limit = 100): Promise<PilotSubmission[]> {
  await ensureTable()
  const safeLimit = Number.isFinite(limit) ? Math.min(Math.max(Math.trunc(limit), 1), 500) : 100
  const sql = await getSql()
  const result = await sql<PilotSubmission>`
    SELECT
      id,
      source,
      name,
      email,
      company,
      role,
      use_case AS "useCase",
      submitted_at AS "submittedAt"
    FROM pilot_submissions
    ORDER BY submitted_at DESC
    LIMIT ${safeLimit}
  `
  return result.rows
}

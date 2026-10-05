// Single source of truth for the marketed product catalog.
//
// Snapshot of `platform/products/catalog.json` (copied by
// `scripts/sync-catalog.mjs` on build). Vercel only uploads this web
// directory, so the live import cannot reach outside the app root.
// The Leptos dashboard sidebar and `GET /api/v1/products` still read
// the canonical file in `platform/products/`.

import catalogData from './data/catalog.json'

export interface PluginCatalogItem {
  slug: string
  name: string
  short_desc: string
  long_desc: string
  icon_key: string
  category: string
  marketed: boolean
  default_enabled: boolean
  tagline: string
}

export interface ReferenceWorkflow {
  slug: string
  name: string
  short_desc: string
  tagline: string
}

interface CatalogFile {
  _schema_version: number
  plugins: PluginCatalogItem[]
  reference_workflows: ReferenceWorkflow[]
}

const catalog = catalogData as unknown as CatalogFile

export const plugins: readonly PluginCatalogItem[] = catalog.plugins
export const referenceWorkflows: readonly ReferenceWorkflow[] =
  catalog.reference_workflows

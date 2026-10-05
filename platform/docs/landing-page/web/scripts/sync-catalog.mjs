import { copyFileSync, existsSync, mkdirSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const destDir = resolve(root, 'src/data')
const dest = resolve(destDir, 'catalog.json')
const src = resolve(root, '../../../products/catalog.json')

mkdirSync(destDir, { recursive: true })
if (existsSync(src)) {
  copyFileSync(src, dest)
  console.log('synced catalog.json from platform/products')
} else if (!existsSync(dest)) {
  console.error('missing src/data/catalog.json and platform/products/catalog.json')
  process.exit(1)
}

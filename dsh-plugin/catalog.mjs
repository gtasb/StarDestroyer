/**
 * Providers and models of the installed dsh, as JSON. The console lists what dsh
 * can route to instead of keeping a list of its own.
 *
 *   node catalog.mjs <dsh>/node_modules
 */

import fs from 'node:fs'
import path from 'node:path'
import { pathToFileURL } from 'node:url'

const base = process.argv[2]
const all = await import(pathToFileURL(path.join(base, '@earendil-works', 'pi-ai', 'dist', 'providers', 'all.js')))

// Environment names and endpoints are recorded beside the dsh adapter.
const data = {}
try {
  const text = fs.readFileSync(path.join(base, '@deepseek-ai', 'dsh-llm-pi-ai', 'src', 'provider-data.generated.ts'), 'utf8')
  for (const m of text.matchAll(/^ {2}'?([\w.-]+)'?: \{ env: \[([^\]]*)\](?:, defaultBaseURL: '([^']*)')?/gm)) {
    data[m[1]] = { env: [...m[2].matchAll(/'([^']+)'/g)].map(x => x[1]), base: m[3] ?? '' }
  }
} catch { /* older or newer layout: names and models still come from the catalog */ }

console.log(JSON.stringify(all.builtinProviders().map(p => ({
  id: p.id, name: p.name ?? p.id,
  env: (data[p.id]?.env ?? []).filter(e => /_API_KEY$|_TOKEN$/.test(e)),
  base: data[p.id]?.base || p.baseUrl || '',
  models: all.getBuiltinModels(p.id).filter(m => !m.type || m.type === 'chat' || m.type === 'text')
    .map(m => ({ id: m.id, name: m.name ?? m.id, context: m.contextWindow ?? 0 })),
}))))

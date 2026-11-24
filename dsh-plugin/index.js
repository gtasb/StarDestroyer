/**
 * dsh bundle for StarDestroyer.
 *
 * The audit engine is Python; this plugin is the Cordis-side surface. Every
 * tool shells out to ../cli.py, which answers with one JSON object. Keeping the
 * boundary at a process makes the engine reusable from any host (MCP, web
 * console, dsh) without duplicating logic in TypeScript.
 */

import { execFile } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import path from 'node:path'

import { defineTool } from '@deepseek-ai/dsh-tools'

export const name = 'stardestroyer'
export const inject = ['tools']

const HERE = path.dirname(fileURLToPath(import.meta.url))
const CLI = process.env.STARDESTROYER_CLI ?? path.join(HERE, '..', 'cli.py')
const PYTHON = process.env.STARDESTROYER_PYTHON
  ?? (process.platform === 'win32' ? 'python' : 'python3')

/** Run one CLI tool; resolves to the parsed JSON object. */
function call(tool, args, signal) {
  return new Promise((resolve, reject) => {
    const child = execFile(
      PYTHON,
      [CLI, tool],
      { maxBuffer: 64 * 1024 * 1024, signal, windowsHide: true },
      (err, stdout, stderr) => {
        if (!stdout && err) return reject(new Error(stderr?.trim() || err.message))
        try {
          resolve(JSON.parse(stdout))
        } catch {
          reject(new Error(`cli returned non-JSON: ${String(stdout).slice(0, 200)}`))
        }
      },
    )
    child.stdin?.end(JSON.stringify(args ?? {}))
  })
}

const JSON_OUT = {
  schema: { type: 'object', additionalProperties: true },
  render: (_args, value) => [{ type: 'text', text: JSON.stringify(value, null, 2) }],
}

function tool(spec) {
  return defineTool({ output: JSON_OUT, ...spec })
}

export function apply(ctx) {
  ctx.tools.register(tool({
    name: 'sd_scan',
    description:
      'Audit a source tree. Profiles dependencies, writes project-specific rules, '
      + 'then runs taint analysis. Returns top findings with call chains and artifact paths.',
    parameters: {
      path: { type: 'string', required: true, description: 'Project source directory' },
      lang: { type: 'string', description: 'java | python | go (default java)' },
      auto: { type: 'boolean', description: 'Generate rules from dependencies first (default true)' },
    },
    execute: (args, exec) => call('audit_scan', {
      path: args.path, lang: args.lang ?? 'java', auto: args.auto ?? true,
    }, exec.signal),
  }))

  ctx.tools.register(tool({
    name: 'sd_jar_audit',
    description:
      'Recall pass over a compiled Java jar: builds a call graph and reports '
      + 'gadget chains that reach a sink (e.g. readObject -> Runtime.exec).',
    parameters: {
      jar: { type: 'string', required: true, description: 'Absolute path to a .jar' },
      mode: { type: 'string', description: 'gadget | web (default gadget)' },
      heap: { type: 'string', description: 'JVM heap for the build, e.g. 4g' },
    },
    execute: (args, exec) => call('audit_jar', {
      target_jar: args.jar, mode: args.mode ?? 'gadget', heap: args.heap ?? '4g',
    }, exec.signal),
  }))

  ctx.tools.register(tool({
    name: 'sd_sca',
    description:
      'Dependency tree (OpenSCA, transitive included) mapped to NVD CVEs whose '
      + 'CPE version range actually covers the installed version.',
    parameters: {
      path: { type: 'string', required: true, description: 'Project root' },
      max_lookups: { type: 'number', description: 'Cap on NVD queries (default 12)' },
    },
    execute: (args, exec) => call('sca_scan', {
      path: args.path, max_lookups: args.max_lookups ?? 12,
    }, exec.signal),
  }))

  ctx.tools.register(tool({
    name: 'sd_sca_triage',
    description:
      'Deterministic dependency-CVE gate (CVSS >= 7 or EPSS percentile >= 95, and never '
      + 'dropped as "unused" when there is no source to check). Returns the survivors plus '
      + '`candidates`: each one is a question you must answer by reading the code. '
      + 'Use your grep/read tools on the listed package and sinks, then call sd_sca_verdict.',
    parameters: {
      path: { type: 'string', required: true, description: 'Project root' },
      cvss_min: { type: 'number', description: 'CVSS floor, default 7.0' },
      epss_pct_min: { type: 'number', description: 'EPSS percentile floor, default 0.95' },
    },
    execute: (args, exec) => call('sca_triage', {
      path: args.path,
      cvss_min: args.cvss_min ?? 7.0,
      epss_pct_min: args.epss_pct_min ?? 0.95,
    }, exec.signal),
  }))

  ctx.tools.register(tool({
    name: 'sd_sca_verdict',
    description:
      'Record keep/ignore decisions made after reading the source. ignore requires '
      + 'evidence: a file:line you read, or a grep result showing no usage.',
    parameters: {
      path: { type: 'string', required: true, description: 'Project root' },
      verdicts: {
        type: 'array',
        description: 'Each: {cve, verdict:"keep"|"ignore", reason, evidence:[{file,line}|{check,result}]}',
      },
    },
    execute: (args, exec) => call('sca_record_verdicts', {
      path: args.path, verdicts: args.verdicts ?? [],
    }, exec.signal),
  }))

  ctx.tools.register(tool({
    name: 'sd_graph',
    description:
      'Build the asset graph: app -> technology/version -> dependency -> N-day, '
      + 'and app -> endpoint -> feature, with findings folded in. Nodes carry a fact status.',
    parameters: {
      path: { type: 'string', required: true, description: 'Project root' },
      with_scan: { type: 'boolean', description: 'Run an audit first and fold findings in (default true)' },
      lookup_cves: { type: 'boolean', description: 'Query NVD for dependencies (default true)' },
    },
    execute: (args, exec) => call('asset_graph_build', {
      path: args.path,
      with_scan: args.with_scan ?? true,
      lookup_cves: args.lookup_cves ?? true,
    }, exec.signal),
  }))

  ctx.tools.register(tool({
    name: 'sd_kb_search',
    description:
      'Retrieve knowledge-base chunks with their source paths. Nothing is injected '
      + 'into the prompt: the model must cite what it uses.',
    parameters: {
      query: { type: 'string', required: true, description: 'Search text' },
      k: { type: 'number', description: 'Number of chunks (default 5)' },
    },
    execute: (args, exec) => call('kb_search', {
      query: args.query, k: args.k ?? 5,
    }, exec.signal),
  }))

  ctx.tools.register(tool({
    name: 'sd_web_search',
    description:
      'Look up how an N-day is reached (gadget, sink, exploit path) via Tavily. '
      + 'Results carry URLs so a finding can cite them.',
    parameters: {
      query: { type: 'string', required: true, description: 'Search query, e.g. a CVE id' },
      max_results: { type: 'number', description: 'Default 5' },
    },
    execute: (args, exec) => call('web_search', {
      query: args.query, max_results: args.max_results ?? 5,
    }, exec.signal),
  }))
}

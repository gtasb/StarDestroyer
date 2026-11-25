/**
 * dsh plugin for one audit session.
 *
 * Loaded by core/agents.py through a --patch overlay. dsh owns the agent: loop,
 * model, context, retries. This adds three things it cannot know:
 *   - code navigation over the audited tree (sd_symbol, sd_callers, ...)
 *   - sd_submit, which checks every citation and sends back what does not hold
 *   - a guard: the session may read the audited tree and nothing else
 */

import { execFile, spawn } from 'node:child_process'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

export const name = 'stardestroyer-audit'
export const inject = ['tools']

const HERE = path.dirname(fileURLToPath(import.meta.url))
const TOOL = path.join(HERE, '..', 'core', 'agent_tool.py')
const PYTHON = process.env.STARDESTROYER_PYTHON ?? (process.platform === 'win32' ? 'python' : 'python3')
const ROOT = fs.realpathSync(process.env.SD_AUDIT_ROOT ?? '.')
const SPEC = JSON.parse(fs.readFileSync(process.env.SD_SPEC, 'utf8'))

// Not needed to judge code, and it would leave the machine with the prompt.
const SECRET = [/^\.env(\..*)?$/, /\.(pem|key|p12|pfx|jks|keystore)$/, /^id_(rsa|ed25519)/, /^\.(npmrc|pypirc|netrc|git-credentials)$/, /^credentials(\.json)?$/]

let reads = SPEC.resumed ? 1 : 0
const delegated = new Map()
const MAX_CHILDREN = Number(SPEC.subagents) || 0
const ACCESS = process.env.SD_ACCESS ?? 'readonly'
const SHELL = new Set(['bash', 'pwsh', 'job_output', 'job_list', 'job_kill'])

/** Why this path may not be read, or undefined. */
function refuse(given) {
  // Relative paths resolve against the session's directory, which is not ROOT.
  if (typeof given !== 'string' || !path.isAbsolute(given)) return `Pass an absolute path inside ${ROOT}`
  // Compare the text first: touching \\host\share would connect to it.
  const inside = (p) => { const r = path.relative(ROOT, p); return r === '' || (!r.startsWith('..') && !path.isAbsolute(r)) }
  const full = path.resolve(ROOT, given)
  if (!inside(full)) return `Only files inside ${ROOT} may be read`
  let real = full
  try { real = fs.realpathSync(full) } catch { /* missing: the tool reports it */ }
  if (!inside(real)) return `Only files inside ${ROOT} may be read`
  if (path.relative(ROOT, real).split(path.sep).some(part => SECRET.some(rx => rx.test(part.toLowerCase())))) return 'This file may hold secrets'
  return undefined
}

function guard(exec) {
  const args = exec.arguments ?? {}
  // Unguarded, except that other people's bundles may not answer for the audit.
  if (ACCESS === 'open' && !exec.name.startsWith('sd_') && exec.name !== 'subagent') { reads++; return undefined }
  if (exec.name === 'read') { const why = refuse(args.file_path); if (!why) reads++; return why }
  if (exec.name === 'grep' || exec.name === 'glob') {
    if (exec.name === 'glob' && (path.isAbsolute(String(args.pattern)) || String(args.pattern).includes('..'))) return 'Use a relative pattern and pass path'
    if (exec.name === 'grep' && /\.env|\.pem|\.key|id_rsa/i.test(String(args.include ?? ''))) return 'These files may hold secrets'
    const why = refuse(args.path)
    if (!why) reads++
    return why
  }
  const child = (exec.agent?.options?.subagentDepth ?? 0) > 0
  if (exec.name === 'subagent' && MAX_CHILDREN) {
    if (child) return 'Subagents may not delegate further'
    if (args.cwd || args.provider || args.model) return 'Leave out cwd, provider and model'
    const n = (delegated.get(exec.agent?.id) ?? 0) + 1
    delegated.set(exec.agent?.id, n)
    return n > MAX_CHILDREN ? `At most ${MAX_CHILDREN} subagents per session` : undefined
  }
  if (MAX_CHILDREN && ['wait_agent', 'list_agents', 'send_message'].includes(exec.name)) return undefined
  if (exec.name === 'sd_submit' && child) return 'Only the main agent submits; report back instead'
  if (ALLOWED.has(exec.name)) return undefined
  if (ACCESS === 'shell' && SHELL.has(exec.name)) {
    // Wider permissions need a person, and nobody is there to ask.
    if (args.sandbox_permissions) return 'Not available: commands run in the sandbox as it is'
    reads++
    return undefined
  }
  return 'Not available in an audit session'
}

/** core/agent_tool.py: the root and the spec come from the environment, never from the model. */
function call(tool, args, signal) {
  return new Promise((resolve, reject) => {
    const child = execFile(PYTHON, ['-X', 'utf8', TOOL, tool], { maxBuffer: 32 * 1024 * 1024, windowsHide: true }, (err, stdout, stderr) => {
      clearTimeout(timer)
      if (err && !stdout) return reject(new Error(stderr?.trim().split('\n').pop() || err.message))
      resolve(stdout)
    })
    const stop = () => process.platform === 'win32'
      ? spawn('taskkill', ['/PID', String(child.pid), '/T', '/F'], { windowsHide: true }) : child.kill('SIGKILL')
    const timer = setTimeout(stop, tool === 'sd_submit' ? 600000 : 180000) // rules are proved on submit
    signal?.addEventListener('abort', stop, { once: true })
    child.stdin?.on('error', () => {})
    child.stdin?.end(JSON.stringify(args ?? {}))
  })
}

const TEXT = { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] }
const S = { type: 'string' }
const schema = (required, properties) => ({ type: 'object', required, properties, additionalProperties: false })

const TOOLS = [
  ['sd_symbol', 'Where a class, method or MyBatis statement is defined. Owner.method is accepted.', schema(['name'], { name: S })],
  ['sd_callers', 'Call sites of a method and the method each one is in. owner is the declaring class or interface; its implementations are included.', schema(['method'], { method: S, owner: S })],
  ['sd_implementations', 'All implementations or subclasses of a type.', schema(['name'], { name: S })],
  ['sd_method', 'Full source of the method around a line, annotations included. file is relative to the project root.', schema(['file', 'line'], { file: S, line: { type: 'integer' } })],
  ['sd_endpoints', 'HTTP endpoints of the project, filtered by path, file or feature.', schema([], { filter: S })],
  ['sd_sinks', 'Dangerous API call sites and MyBatis ${} in the project, optionally for one class: sqli, cmd, deserialization, expression, ssrf, path_traversal, xxe, code_injection, ssti, nosqli, dom_xss, prototype_pollution, postmessage.', schema([], { class: S })],
  ['sd_advisory', 'What is known about a CVE.', schema(['cve'], { cve: S })],
]

const ENGINES = [
  ['sd_findings', 'What the engines and other agents have reported so far. engine: sast | secrets | tabby | agent.', schema([], { engine: S, filter: S })],
  ['sd_opengrep', 'Run one Opengrep rule you write over the project (or one path in it). rule: the rule as an object with id, languages, severity, message and pattern / patterns / mode: taint with pattern-sources and pattern-sinks.', schema(['rule'], { rule: { type: 'object', properties: {}, additionalProperties: true }, path: S })],
  ['sd_callgraph', 'Bytecode call graph of a compiled Java project. method: Class.method or method. direction: callers | callees | path; path needs to.', schema(['method'], { method: S, direction: S, to: S, depth: { type: 'integer' } })],
  ['sd_deps', 'Dependencies with their CVEs and what is known about reachability, filtered by name or CVE.', schema([], { filter: S })],
]
if (SPEC.engines) TOOLS.push(...ENGINES)

// By name: the profile may hold other plugins, our own interactive bundle among them, whose
// sd_* tools search the web, scan any path and record verdicts.
const ALLOWED = new Set([...TOOLS.map(t => t[0]), 'sd_submit', 'todo', 'todo_write'])

export function apply(ctx) {
  ctx.tools.guard(guard)
  if (process.env.SD_SESSION) {
    let told = false // the first session to speak is the task's own; subagents come later
    ctx.on('session/event', (session) => {
      if (told) return
      told = true
      try { fs.writeFileSync(process.env.SD_SESSION, JSON.stringify({ session: session.id, sig: process.env.SD_SESSION_SIG })) } catch { /* resuming is a convenience */ }
    })
  }
  if (process.env.SD_USAGE) {
    const spent = {}
    ctx.on('session/event', (session, event) => {
      const u = event.type === 'assistant/message' ? event.data?.usage : undefined
      if (!u) return
      const s = (spent[session.id] ??= { in: 0, out: 0, cached: 0 })
      s.in += (u.inputTokens ?? 0) + (u.cacheReadTokens ?? 0)
      s.out += u.outputTokens ?? 0
      s.cached += u.cacheReadTokens ?? 0
      try { fs.writeFileSync(process.env.SD_USAGE, JSON.stringify(spent)) } catch { /* accounting only */ }
    })
  }
  for (const [tool, description, parameters] of TOOLS) {
    ctx.tools.register({
      name: tool, description, parameters, output: TEXT,
      async execute(args, exec) { if (tool === 'sd_method') reads++; return call(tool, args, exec.signal) },
    })
  }
  if (process.env.SD_STREAM) {
    // A conversation is watched as it is written; stdout belongs to the protocol.
    const say = (m) => { try { process.stderr.write(`\u001eSD${JSON.stringify(m)}\n`) } catch { /* watching only */ } }
    ctx.on('agent/assistant-stream', ({ agent, frame }) => {
      if ((agent.options?.subagentDepth ?? 0) > 0) return
      if (frame.type === 'start') say({ s: agent.id, k: 'start' })
      const c = frame.type === 'chunk' ? frame.chunk : undefined
      if (c?.type === 'text-delta' && c.text) say({ s: agent.id, k: 'text', d: c.text })
      if (c?.type === 'reasoning-delta' && c.text) say({ s: agent.id, k: 'think', d: c.text })
    })
  }
  if (SPEC.chat) {
    ctx.on('session/event', (session, event) => { if (event.type === 'turn/start') delegated.delete(session.id) }) // per question
    return
  }
  ctx.tools.register({
    name: 'sd_submit',
    description: 'Submit your conclusion. Every citation is checked against the source; what does not match is returned for you to correct. Stop once it is accepted.',
    parameters: SPEC.schema, output: TEXT,
    async execute(args, exec) {
      if (!reads) return 'Not accepted: you have not read any source yet.'
      return call('sd_submit', args, exec.signal)
    },
  })
}

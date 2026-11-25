import { api, attempt, btn, check, chip, debounce, drawer, empty, gapNote, h, iconBtn, input, KIND, loading, pager, post, put, saveText, SEV, sevChip, STATUS, statusChip, table, toast } from "./util.js";
import { askAbout } from "./chat.js";

// ---- code viewer ----
const cache = new Map();
export async function codeView(pid, path, line, marks = []) {
  const key = pid + "\n" + path;
  let d = cache.get(key);
  if (!d) {
    d = await api(`/api/projects/${pid}/file?path=${encodeURIComponent(path)}`).catch(e => ({ ok: false, error: e.message }));
    if (d.ok) {
      if (cache.size > 30) cache.clear();
      cache.set(key, d);
      setTimeout(() => cache.delete(key), 15000);
    }
  }
  if (!d.ok) return empty("打不开源文件", `${path}：${d.error}`);
  const rank = { through: 0, source: 1, sink: 2 };
  const tagged = new Map();
  for (const m of marks) if (!tagged.has(m.line) || rank[m.kind] > rank[tagged.get(m.line)]) tagged.set(m.line, m.kind);
  const rows = d.lines.map((text, i) => h("div", { class: "ln" + (tagged.has(i + 1) ? " mark " + tagged.get(i + 1) : "") + (i + 1 === line ? " at" : "") },
    h("i", {}, i + 1), h("code", {}, text || " ")));
  const box = h("div", { class: "code" },
    h("div", { class: "code-h mono" }, d.path, line ? `:${line}` : "", d.truncated && chip("文件过大，只显示开头", "warn")),
    h("div", { class: "code-b" }, rows));
  requestAnimationFrame(() => { const at = rows[line - 1]; if (at) at.scrollIntoView({ block: "center" }); });
  return box;
}
export async function showFile(pid, path, line) {
  const slot = h("div", { class: "code-only" }, loading());
  drawer(path.split("/").pop(), slot);
  put(slot, await codeView(pid, path, line, [{ line, kind: "sink" }]));
}

// ---- one finding ----
const STEP = { source: "入口", sink: "汇聚点", sink_in_call: "汇聚点", through: "传播", entrypoint: "入口", propagation: "调用" };
export const REVIEW = { uphold: ["推翻不了", "bad"], refute: ["认为不成立", "warn"], uncertain: ["无法判断", "info"] };
const BACKEND = { dsh: "agent 会话", host: "宿主 agent" };
const authChip = r => [r.auth === "anonymous" && chip("免登录", "bad"), r.auth_default && chip(`默认配置：${{ anonymous: "免登录", login: "登录", permission: "权限" }[r.auth_default]}`, "warn", "只在默认或开发配置下成立，生产配置见鉴权")];
const AUTH = { anonymous: ["免登录可利用", "bad"], login: ["需登录", "warn"], permission: ["需权限", "info"] };
const role = kind => /sink/.test(kind) ? "sink" : /source|entry/.test(kind) ? "source" : "through";

export function showFinding(f, list, onChange) {
  let i = list.indexOf(f);
  const head = h("div", {}), steps = h("ol", { class: "steps" }), code = h("div", { class: "code-slot" }), actions = h("div", { class: "row" });
  const note = input({ placeholder: "备注（可选，写清理由方便以后回看）", "aria-label": "备注" });
  const pos = h("span", { class: "muted nw" });
  const d = drawer("发现详情", h("div", { class: "finding" }, h("div", { class: "f-left" }, head, h("h4", {}, "调用链"), steps), code),
    () => [iconBtn("play", "上一条 (k)", () => go(-1), "flip"), pos, iconBtn("play", "下一条 (j)", () => go(1)), note, actions]);
  const keys = e => {
    if (!d.box.isConnected) return removeEventListener("keydown", keys);
    if (/INPUT|TEXTAREA|SELECT/.test(e.target.tagName)) return;
    if (e.key === "j") go(1);
    if (e.key === "k") go(-1);
  };
  addEventListener("keydown", keys);
  d.box.tabIndex = -1;
  d.box.focus();

  function go(n) { if (list[i + n]) { i += n; f = list[i]; draw(); } }
  async function decide(verdict) {
    const saved = await attempt(post("/api/decisions", { keys: [f.suppress_key], verdict, note: note.value }), verdict ? "已标记" : "已撤销标记");
    if (!saved) return;
    onChange();
    if (verdict && list[i + 1]) go(1); else d.close();
  }
  function reviewNote(r) {
    if (!r) return null;
    const [label, kind] = REVIEW[r.verdict] || [r.verdict, ""];
    return h("div", { class: "ai" },
      h("div", { class: "row wrap" }, h("b", {}, "复核"), chip(label, kind), h("span", { class: "muted" }, `${BACKEND[r.backend] || r.backend}${r.model && r.model !== r.backend ? ` · ${r.model}` : ""} · ${r.at}`)),
      r.traced && h("p", {}, "续追：", r.traced),
      h("p", {}, r.reason),
      (r.evidence || []).map(e => h("button", { class: "quote", type: "button", onclick: () => open({ file: e.file, line: e.line }) }, h("code", {}, e.quote), h("small", { class: "mono" }, `${e.file}:${e.line}`))),
      r.unverified > 0 && h("p", { class: "c-warn" }, `${r.unverified} 条引用与源码对不上，未采纳`),
      (r.reads || []).length > 0 && h("p", { class: "muted", title: r.reads.join("\n") }, `读码 ${r.reads.length} 次`));
  }
  async function reviewNow() {
    if (!await attempt(post("/api/tasks", { ids: [f.project_id], kinds: ["review"], params: { keys: [f.suppress_key] } }), "已提交复核任务")) return;
    document.dispatchEvent(new Event("tasks-changed"));
  }
  async function open(step, el) {
    steps.querySelectorAll("li").forEach(x => x.classList.toggle("on", x === el));
    const marks = (f.trace || []).filter(s => s.file === step.file).map(s => ({ line: s.line, kind: role(s.kind) }));
    const shown = f;
    put(code, loading());
    const v = step.file ? await codeView(f.project_id, step.file, step.line, marks) : empty("这一步没有源码", "调用图来自字节码，只有类名和方法名");
    if (shown === f) put(code, v);
  }
  function draw() {
    note.value = (f.decision && f.decision.note) || "";
    pos.textContent = `${i + 1} / ${list.length}`;
    put(head,
      h("div", { class: "row wrap" }, statusChip(f.status), sevChip(f.severity), f.cwe && chip(f.cwe), AUTH[f.auth] && chip(`生产：${AUTH[f.auth][0]}`, AUTH[f.auth][1]), f.auth_default && chip(`默认配置：${(AUTH[f.auth_default] || ["?"])[0]}`, "warn"), chip(KIND[f.kind] || f.kind)),
      h("h2", { class: "f-title" }, f.message),
      h("p", { class: "mono muted" }, f.rule_id, f.also ? ` · 同时命中 ${f.also.join("、")}` : ""),
      h("dl", { class: "kv" },
        h("dt", {}, "项目"), h("dd", {}, f.project),
        h("dt", {}, "位置"), h("dd", { class: "mono" }, f.file, f.line ? `:${f.line}` : ""),
        h("dt", {}, "判定"), h("dd", {}, f.reason), h("dt", {}, "根因"), h("dd", {}, f.cause),
        f.impact && [h("dt", {}, "影响"), h("dd", {}, f.impact)],
        f.conditions && [h("dt", {}, "利用条件"), h("dd", {}, f.conditions)],
        f.fix && [h("dt", {}, "修复"), h("dd", {}, f.fix)],
        (f.entries || []).length > 0 && [h("dt", {}, "其他入口"), h("dd", { class: "mono" }, f.entries.map(e => h("div", {}, e)))],
        (f.also || []).length > 0 && [h("dt", {}, "其它后果"), h("dd", {}, f.also.map(e => h("div", {}, e)))],
        f.missing && [h("dt", {}, "缺口"), h("dd", {}, [].concat(f.missing).join("、"))],
        f.decision && [h("dt", {}, "人工结论"), h("dd", {}, `${f.reason}（${f.decision.at}）`)]),
      reviewNote(f.review));
    const trace = f.trace || [];
    put(steps, trace.map(s => {
      const li = h("li", { class: role(s.kind) }, h("button", { type: "button", onclick: () => open(s, li) },
        h("b", {}, STEP[s.kind] || s.kind), h("code", {}, s.text), s.note && h("span", { class: "muted" }, s.note),
        h("small", { class: "mono" }, s.file ? `${s.file}:${s.line ?? "?"}` : s.line ? `行 ${s.line}` : "")));
      return li;
    }));
    const disabled = !f.suppress_key, title = disabled ? "证据文件不可读，无法固定这条发现" : "";
    put(actions, f.decision && btn("撤销标记", () => decide("")),
      f.kind !== "tabby" && !f.decision && btn(f.review ? "重新复核" : "复核", reviewNow, { ico: "eye", disabled, title }),
      btn("问 agent", () => askAbout(f.project_id, f), { ico: "eye", disabled, title }),
      btn("误报", () => decide("false_positive"), { ico: "ban", disabled, title }),
      btn("接受风险", () => decide("accepted_risk"), { ico: "flag", disabled, title }),
      btn("确认是漏洞", () => decide("confirmed"), { kind: "danger", ico: "check", disabled, title }));
    const last = trace.length - 1;
    if (last >= 0) open(trace[last], steps.children[last]);
    else if (f.file && f.line) open({ file: f.file, line: f.line });
    else put(code, empty("没有调用链", ""));
  }
  draw();
}

// ---- list with facets ----
export function findingsView({ project, kind = "", run = "", artifact }) {
  const st = { status: "open", severity: "", rule: "", cause: "", group: "", q: "", page: 1, size: 50 };
  const sel = new Set();
  const facets = h("aside", { class: "facets" }), note = h("div", {}), bar = h("div", { class: "row" }), list = h("div", {}, loading());
  const search = input({ type: "search", placeholder: "搜索文件、规则、描述、CWE", oninput: debounce(e => set({ q: e.target.value })) });
  const root = h("div", { class: "findings" }, facets,
    h("div", { class: "f-main" }, h("div", { class: "toolbar" }, search, h("div", { class: "spacer" }), bar), artifact && gapNote(artifact.incomplete_reasons, artifact.covered, project.id), note, list));
  let data = null, seq = 0;

  async function load() {
    const mine = ++seq;
    const d = await attempt(api("/api/findings?" + new URLSearchParams({ ...st, kind, run, project_id: project ? project.id : "" })));
    if (!d || mine !== seq) return; // a newer filter is already on its way
    data = d;
    if (!d.items.length && st.page > 1) { st.page = 1; return load(); }
    draw();
  }
  function set(kw) { Object.assign(st, kw, { page: kw.page || 1 }); sel.clear(); load(); }

  function facet(title, name, labels, extra = []) {
    const counts = data.facets[name] || {};
    const keys = Object.keys(labels || counts).filter(k => counts[k] || st[name] === k);
    if (!labels) keys.sort((a, b) => counts[b] - counts[a]);
    return h("div", { class: "facet" }, h("h4", {}, title), extra,
      keys.map(k => h("button", { type: "button", class: st[name] === k ? "on" : "", "aria-pressed": String(st[name] === k), onclick: () => set({ [name]: st[name] === k ? "" : k }) },
        h("span", { class: labels ? "" : "mono" }, labels ? labels[k][0] : k), h("b", {}, counts[k] || 0))));
  }
  async function bulk(verdict) {
    if (await attempt(post("/api/decisions", { keys: [...sel], verdict }), `已处理 ${sel.size} 条`)) { sel.clear(); load(); }
  }
  async function review(keys) {
    const d = await attempt(post("/api/tasks", { ids: [project.id], kinds: ["review"], params: keys ? { keys } : {} }));
    if (!d) return;
    toast(d.tasks[0] && keys ? `已提交 ${keys.length} 条复核` : "已提交复核任务", "good");
    sel.clear();
    document.dispatchEvent(new Event("tasks-changed"));
    draw();
  }
  async function exportAs(fmt) {
    const text = await attempt(api(`/api/projects/${project.id}/export/${kind.split(",")[0]}/${fmt}?run=${encodeURIComponent(run)}`, { raw: true }));
    if (text) saveText(`${project.name}-${kind}.${fmt}`, text);
  }

  const columns = [
    { label: "严重度", cell: r => r.shown === "refuted" ? chip((SEV[r.severity] || SEV.unknown)[0], "mute") : sevChip(r.severity), class: "nw" },
    { label: "发现", cell: r => [h("div", { class: "t1" }, r.message), h("div", { class: "t2 mono" }, r.rule_id, authChip(r), (r.lines || []).length > 0 && chip(`同一方法另有 ${r.lines.length} 处`, "", `第 ${r.lines.join("、")} 行`))] },
    { label: "位置", cell: r => [h("div", { class: "mono t1 at", title: r.file }, r.file.split("/").pop(), r.line ? `:${r.line}` : ""), h("div", { class: "t2 mono dir", title: r.file }, r.file.split("/").slice(0, -1).join("/")), !project && h("div", { class: "t2" }, r.project)] },
    { label: "链", cell: r => `${(r.trace || []).length} 步`, class: "nw num" },
    { label: "状态", cell: r => [r.shown !== "refuted" && statusChip(r.status), r.decision ? chip("人工", "", r.reason) : r.review && chip(`复核：${(REVIEW[r.review.verdict] || [r.review.verdict])[0]}`, (REVIEW[r.review.verdict] || [])[1], r.review.reason)], class: "nw" },
  ];
  const grouping = () => check("按根因合并", !!st.group, v => set({ group: v ? "1" : "", cause: "" }), "一处缺失的检查往往在很多地方露头");
  function tools() {
    put(bar, sel.size === 0 && grouping(), sel.size > 0
      ? [h("span", { class: "muted nw" }, `已选 ${sel.size}`), project && !["tabby", "secrets"].includes(kind) && btn("复核", () => review([...sel]), { ico: "eye" }), btn("误报", () => bulk("false_positive"), { ico: "ban" }), btn("接受风险", () => bulk("accepted_risk"), { ico: "flag" }), btn("撤销标记", () => bulk(""))]
      : project && kind ? [!["tabby", "secrets"].includes(kind) && !run && btn("复核全部", () => review(), { ico: "eye", title: "让复核 agent 读源码逐条验证" }), ...[["md", "报告"], ["sarif", "SARIF"], ["json", "JSON"]].map(([f, label]) => btn(label, () => exportAs(f), { ico: "down", title: `导出 ${label}` }))] : []);
  }
  function draw() {
    const open = Object.entries(data.facets.status).reduce((n, [k, v]) => n + (k === "rejected" ? 0 : v), 0);
    const quick = [["open", "未排除", open], ["", "全部", open + (data.facets.status.rejected || 0)]].map(([v, label, n]) =>
      h("button", { type: "button", class: st.status === v ? "on" : "", onclick: () => set({ status: v }) }, h("span", {}, label), h("b", {}, n)));
    put(facets, facet("状态", "status", STATUS, quick), facet("严重度", "severity", SEV), facet("根因", "cause", null), facet("规则", "rule", null));
    tools();
    if (data.groups) {
      return put(list, table({
        columns: [{ label: "最高", cell: g => sevChip(g.severity), class: "nw" }, { label: "根因", cell: g => [h("div", { class: "t1" }, g.cause), h("div", { class: "t2" }, g.sample)] },
          { label: "已确认", cell: g => g.confirmed ? h("b", { class: "c-bad" }, g.confirmed) : "0", class: "num" }, { label: "复核不成立", cell: g => g.refuted || "—", class: "num" }, { label: "共", cell: g => g.count, class: "num" }, { label: "文件", cell: g => g.files, class: "num" }],
        rows: data.groups, id: g => g.cause, onRow: g => set({ cause: g.cause, group: "" }), emptyText: "没有发现",
      }));
    }
    const filtered = st.q || st.cause || st.rule || st.severity || st.status !== "open";
    put(list, table({
      columns, rows: data.items, id: r => r.suppress_key || r, selected: sel, canSelect: r => !!r.suppress_key, // no key, nothing to decide on
      onSelect: () => { draw(); }, onRow: r => showFinding(r, data.items, load),
      emptyText: filtered ? "没有符合筛选条件的发现" : artifact && artifact.complete === false ? "没有命中，但扫描不完整，不能当作没有漏洞" : "没有发现",
    }), pager(data.total, st.page, st.size, p => set({ page: p }), s => set({ size: s })));
  }
  load();
  return { el: root, reload: load };
}

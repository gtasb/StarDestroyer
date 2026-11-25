import { api, attempt, btn, chip, debounce, drawer, empty, h, iconBtn, input, loading, panel, pickPath, post, put, select, stat, table, toast } from "./util.js";
import { findingsView } from "./findings.js";
import { kindChips, newProject, num } from "./projects.js";
import { interrupted, taskTable } from "./tasks.js";

export const engines = list => h("div", { class: "engines" }, list.map(e => h("div", { class: "engine" }, h("i", { class: "dot " + (e.ready ? "on" : "") }),
  h("div", {}, h("b", {}, e.name), h("small", {}, e.why)), h("span", { class: e.ready ? "c-good" : "c-warn" }, e.ready ? "就绪" : e.fix || "未配置"))));

// ---- overview ----
export function overviewPage(root) {
  put(root, loading());
  async function load() {
    const d = await attempt(api("/api/overview")), he = d && await attempt(api("/api/health")), pr = he && await attempt(api("/api/projects"));
    if (!pr) return;
    const t = d.total, b = d.builtin;
    const score = p => ((num(p, "sast", "confirmed") || 0) + (p.audit.confirmed || 0)) * 3 + (num(p, "triage", "kept") || 0);
    const worst = pr.projects.filter(p => score(p) > 0).sort((x, y) => score(y) - score(x)).slice(0, 8);
    put(root,
      h("div", { class: "cols" },
        panel("项目概览", null, h("div", { class: "stats in" },
          stat("layers", t.projects, "项目", "good", "#/projects"), stat("bug", t.confirmed, "已确认", "bad", "#/findings"), stat("eye", t.needs_review, "待复核", "warn", "#/findings"),
          stat("box", t.vuln_deps, "风险依赖", "info", "#/projects"), stat("warn", t.gaps, "不完整的运行", "warn"))),
        panel("内置能力", null, h("div", { class: "stats in" },
          stat("rule", b.rules, "内置规则", "info", "#/rules"), stat("shield", b.classes, "漏洞类别", "good", "#/rules"), stat("globe", b.languages, "语言", "", "#/rules"),
          stat("layers", b.generated, "项目规则", "", "#/rules"), stat("book", b.docs, "知识文档", "", "#/kb")))),
      !pr.projects.length && panel(null, null, empty("从添加第一个项目开始", "选一个源码目录，控制台会识别语言和框架，然后在后台扫描", newProject())),
      h("div", { class: "cols" },
        panel("风险最高的项目", h("a", { href: "#/projects" }, "全部项目"), table({
          columns: [{ label: "项目", cell: p => h("div", { class: "t1" }, p.name) }, { label: "任务", cell: kindChips, class: "nw" },
            { label: "已确认", cell: p => (num(p, "sast", "confirmed") || 0) + (p.audit.confirmed || 0), class: "num" }, { label: "风险依赖", cell: p => num(p, "triage", "kept") ?? "—", class: "num" }],
          rows: worst, onRow: p => { location.hash = `#/p/${p.id}`; }, emptyText: "没有已确认的发现或风险依赖",
        })),
        panel("需要留意的覆盖缺口", null, d.gaps.length
          ? h("div", { class: "pad" }, d.gaps.map(g => h("a", { class: "line", href: `#/p/${g.id}/${g.kind}` }, chip(g.unknown ? "未记录" : "不完整", g.unknown ? "old" : "warn"), `${g.project} · ${g.label}`, h("span", { class: "muted" }, g.unknown ? "旧版本的运行，建议重扫" : `${g.gaps} 处`))))
          : empty("没有缺口", t.runs ? "已完成的运行都覆盖完整" : "还没有运行过"))),
      panel("最近任务", h("a", { href: "#/tasks" }, "全部任务"), interrupted(d.tasks, load), taskTable(d.tasks, load)),
      panel("引擎与服务", h("a", { href: "#/settings" }, "设置"), engines(he.engines)));
  }
  load();
  return { refresh: load };
}

export function findingsPage(root) {
  const v = findingsView({});
  put(root, panel("全部发现", h("span", { class: "muted" }, "各项目最近一次运行"), v.el));
  return { refresh: ended => { if (ended && ended.length) v.reload(); } };
}

// ---- intel ----
export function intelPage(root) {
  const product = input({ placeholder: "产品或 artifactId，如 log4j-core", "aria-label": "产品" }), version = input({ placeholder: "版本，可空", "aria-label": "版本" });
  const q = input({ placeholder: "CVE 编号或关键词", "aria-label": "检索词" });
  const out = h("div", {}, empty("查漏洞库", "按 NVD 的 CPE 版本区间判断是否受影响；没有 NVD key 时较慢"));
  const hits = h("div", {}, empty("联网检索", "需要 Tavily key；结果只作线索，不改判定"));
  const columns = [
    { label: "CVE", cell: c => h("span", { class: "mono" }, c.id), class: "nw" },
    { label: "CVSS", cell: c => c.score == null ? chip("未知") : chip(String(c.score), c.score >= 9 ? "bad" : c.score >= 7 ? "warn" : ""), class: "num" },
    { label: "CWE", cell: c => c.cwes.join(" "), class: "nw" }, { label: "摘要", cell: c => h("div", { class: "t2 wrap" }, c.summary) }, { label: "公开", cell: c => c.published, class: "nw" },
  ];
  async function lookup() {
    const name = product.value.trim(), ver = version.value.trim();
    if (!name) return;
    put(out, loading());
    const d = await attempt(api(`/api/nvd?product=${encodeURIComponent(name)}&version=${encodeURIComponent(ver)}`));
    if (!d) return put(out, empty("没有查到结果", "查询失败不代表没有漏洞"));
    const list = [...(ver ? d.affected : d.cves)].sort((a, b) => (b.score || 0) - (a.score || 0));
    put(out, d.error && h("div", { class: "gap" }, `结果不完整：${d.error}`),
      h("p", { class: "meta" }, ver ? `共 ${d.total} 个 CVE，影响 ${ver} 的有 ${d.affected.length} 个` : `共 ${d.total} 个 CVE`, list.length > 200 ? "，只显示前 200 个" : ""),
      table({ columns, rows: list.slice(0, 200), emptyText: "没有命中的 CVE", onRow: c => { q.value = c.id; search(); } }));
  }
  async function search() {
    const s = q.value.trim();
    if (!s) return;
    put(hits, loading());
    const d = await attempt(api(/^CVE-\d/i.test(s) ? `/api/nday?cve=${encodeURIComponent(s)}&product=${encodeURIComponent(product.value)}` : `/api/search?q=${encodeURIComponent(s)}`));
    put(hits, d && (d.results || []).length
      ? d.results.map(r => h("article", { class: "hit" }, h("a", { href: /^https?:/.test(r.url || "") ? r.url : null, target: "_blank", rel: "noreferrer noopener" }, r.title), h("small", { class: "mono" }, r.url), h("p", {}, r.content)))
      : empty("没有结果", ""));
  }
  for (const [els, fn] of [[[product, version], lookup], [[q], search]]) els.forEach(e => e.addEventListener("keydown", ev => { if (ev.key === "Enter") fn(); }));
  put(root, panel("漏洞库", null, h("div", { class: "toolbar" }, product, version, btn("查询", lookup, { kind: "primary", ico: "search" })), out),
    panel("联网检索", null, h("div", { class: "toolbar" }, q, btn("检索", search, { ico: "search" })), hits));
}

// ---- rules ----
export function rulesPage(root) {
  put(root, loading());
  (async () => {
    const d = await attempt(api("/api/rules"));
    if (!d) return put(root, empty("读取失败", ""));
    const st = { lang: "", q: "" }, body = h("div", {});
    const show = r => drawer(r.id, h("div", { class: "pad" }, h("p", {}, r.message), h("h4", {}, "汇聚点"), h("ul", { class: "mono" }, r.sinks.map(s => h("li", {}, s))), h("h4", {}, "规则"), h("pre", { class: "mono" }, r.yaml)));
    const columns = [
      { label: "规则", cell: r => [h("div", { class: "t1" }, r.message), h("div", { class: "t2 mono" }, r.id)] }, { label: "语言", cell: r => chip(r.lang), class: "nw" },
      { label: "CWE", cell: r => r.cwe, class: "nw" }, { label: "入口", cell: r => r.sources, class: "num" }, { label: "汇聚点", cell: r => r.sinks.length, class: "num" },
    ];
    const draw = () => put(body, table({ columns, rows: d.builtin.filter(r => (!st.lang || r.lang === st.lang) && (!st.q || `${r.id} ${r.message} ${r.cwe} ${r.sinks.join(" ")}`.toLowerCase().includes(st.q))), onRow: show, emptyText: "没有匹配的规则" }));
    draw();
    put(root,
      panel(`内置规则 ${d.builtin.length}`, null, h("div", { class: "toolbar" },
        input({ type: "search", placeholder: "搜索规则、CWE、汇聚点", oninput: debounce(e => { st.q = e.target.value.toLowerCase(); draw(); }, 120) }), h("div", { class: "spacer" }),
        select([["", "全部语言"], ["java", "Java"], ["python", "Python"], ["go", "Go"], ["js", "JavaScript / TypeScript"]], "", v => { st.lang = v; draw(); }, { "aria-label": "语言" })), body),
      panel(`按项目生成 ${d.generated.length}`, h("span", { class: "muted" }, "每条都用引擎验证过：命中漏洞样例，不误报安全样例"), table({
        columns: [{ label: "规则", cell: r => h("span", { class: "mono" }, r.id) }, { label: "项目", cell: r => r.project }, { label: "依据", cell: r => r.reason }],
        rows: d.generated, id: r => r.project + r.id, emptyText: "还没有；扫描时会按项目依赖生成",
      })));
  })();
}

// ---- knowledge base ----
export function kbPage(root) {
  const q = input({ type: "search", placeholder: "检索知识库，可以直接写问题", "aria-label": "检索" }), path = input({ class: "mono", placeholder: "文档目录（.md / .txt）", "aria-label": "文档目录" });
  const hits = h("div", {}, empty("按需检索", "结果带出处，不会自动拼进提示词")), docs = h("div", {}, loading());
  async function search() {
    if (!q.value.trim()) return;
    const d = await attempt(api(`/api/kb/search?q=${encodeURIComponent(q.value)}`));
    if (d) put(hits, d.hits.length ? [h("p", { class: "meta" }, `${d.count} 段 · ${d.total_chars} 字符`), d.hits.map(x => h("article", { class: "hit" }, h("b", {}, x.title), h("small", { class: "mono" }, x.path), h("p", {}, x.text)))] : empty("没有匹配的内容", ""));
  }
  const drop = x => async () => { if (await attempt(post("/api/kb/delete", { ids: [x.id] }), "已移除")) load(); };
  async function load() {
    const d = await attempt(api("/api/kb/docs"));
    if (d) put(docs, table({
      columns: [{ label: "文档", cell: x => [h("div", { class: "t1" }, x.title), h("div", { class: "t2 mono" }, x.path)] }, { label: "片段", cell: x => x.chunks, class: "num" },
        { label: "入库", cell: x => x.added_at, class: "nw" }, { label: "操作", cell: x => h("div", { class: "ops" }, iconBtn("trash", "移除", drop(x), "red")), class: "nw" }],
      rows: d.docs, emptyText: "还没有文档",
    }));
  }
  async function ingest() {
    const d = await attempt(post("/api/kb/ingest", { path: path.value.trim() }));
    if (!d) return;
    toast(`已入库 ${d.docs} 篇${d.failed.length ? `，${d.failed.length} 篇失败` : ""}`, d.failed.length ? "bad" : "good");
    load();
  }
  q.addEventListener("keydown", e => { if (e.key === "Enter") search(); });
  put(root, panel("检索", null, h("div", { class: "toolbar" }, q, btn("检索", search, { kind: "primary", ico: "search" })), hits),
    panel("文档", null, h("div", { class: "toolbar" }, path, btn("浏览", () => pickPath(v => { path.value = v; }, { start: path.value }), { ico: "folder" }), btn("入库", ingest, { ico: "plus" })), docs));
  load();
}

// ---- logs ----
export function logsPage(root) {
  const st = { level: "", q: "", auto: true }, out = h("div", { class: "log mono", tabindex: "0" }), info = h("span", { class: "muted mono" });
  let fresh = true;
  async function load() {
    const d = await attempt(api(`/api/logs?n=400&level=${st.level}&q=${encodeURIComponent(st.q)}`));
    if (!d) return;
    info.textContent = d.path;
    const stick = fresh || out.scrollHeight - out.scrollTop - out.clientHeight < 40;
    put(out, d.lines.length ? d.lines.map(l => h("div", { class: (/ (DEBUG|INFO|WARN|ERROR) /.exec(l) || ["", ""])[1].toLowerCase() }, l)) : h("p", { class: "muted" }, "没有日志"));
    if (stick) out.scrollTop = out.scrollHeight;
    fresh = false;
  }
  put(root, panel("日志", info, h("div", { class: "toolbar" },
    input({ type: "search", placeholder: "过滤", oninput: debounce(e => { st.q = e.target.value; fresh = true; load(); }) }),
    select([["", "全部级别"], ...["DEBUG", "INFO", "WARN", "ERROR"].map(x => [x, x])], "", v => { st.level = v; fresh = true; load(); }, { "aria-label": "级别" }),
    btn("刷新", load, { ico: "refresh" }), h("div", { class: "spacer" }),
    h("label", { class: "check" }, h("input", { type: "checkbox", checked: true, onchange: e => { st.auto = e.target.checked; } }), "自动刷新")), out));
  load();
  const timer = setInterval(() => { if (st.auto && document.visibilityState === "visible") load(); }, 4000);
  return { stop: () => clearInterval(timer) };
}

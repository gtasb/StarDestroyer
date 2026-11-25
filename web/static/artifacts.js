import { chip, debounce, drawer, gapNote, h, input, pager, panel, put, select, table } from "./util.js";
import { showFile } from "./findings.js";

const PAGE = 50;
const USE = { used: ["源码引用", "warn"], unused: ["未引用", "mute"], indirect: ["间接依赖", ""], transitive: ["间接依赖", ""], unknown: ["无法判断", ""] };
const cvss = r => r.cvss_unknown ? chip("未知") : chip(r.cvss.toFixed(1), r.cvss >= 9 ? "bad" : r.cvss >= 7 ? "warn" : "");

function cveDrawer(pid, r, deep) {
  const ref = e => {
    const m = /^(.*?):(\d+): (.*)$/.exec(e);
    return m ? h("button", { class: "line mono", type: "button", onclick: () => showFile(pid, m[1], +m[2]) }, `${m[1]}:${m[2]}`, h("span", { class: "muted" }, m[3])) : h("p", { class: "mono" }, e);
  };
  drawer(r.cve, h("div", { class: "pad" },
    h("div", { class: "row wrap" }, chip(`CVSS ${r.cvss_unknown ? "未知" : r.cvss}`, r.cvss >= 7 ? "bad" : ""), (r.cwes || []).map(c => chip(c))),
    h("p", {}, r.summary),
    h("dl", { class: "kv" },
      h("dt", {}, "依赖"), h("dd", { class: "mono" }, `${r.group ? r.group + ":" : ""}${[r.dependency, ...(r.also || [])].join("、")}@${r.version}`),
      r.via && [h("dt", {}, "怎么带进来的"), h("dd", { class: "mono" }, r.via)], h("dt", {}, "判定"), h("dd", {}, r.reason),
      h("dt", {}, "受影响区间"), h("dd", { class: "mono" }, (r.cpes || []).length ? r.cpes.map(c => h("div", {}, `${c.start || "*"} … ${c.end || "*"}`)) : "未记录"),
      h("dt", {}, "需核对的 sink"), h("dd", { class: "mono" }, (r.sinks || []).join("、") || "未映射")),
    h("h4", {}, "agent 追链"),
    deep ? [h("div", { class: "row wrap" }, chip(...REACH[deep.verdict]), deep.api && h("span", { class: "mono" }, deep.api)), h("p", {}, deep.reason),
      (deep.steps || []).map(s => h("button", { class: "quote", type: "button", onclick: () => showFile(pid, s.file, s.line) }, h("code", {}, s.quote), h("small", { class: "mono" }, `${s.file}:${s.line}`)))]
      : h("p", { class: "muted" }, "还没有审：到「agent 审计」里跑依赖 sink 追链"),
    h("h4", {}, "源码引用"),
    (r.usage_evidence || []).length ? r.usage_evidence.map(ref) : h("p", { class: "muted" }, "没有找到引用")));
}

const REACH = { reachable: ["可触达", "bad"], not_reachable: ["不可触达", "good"], unclear: ["不清楚", "warn"] };
export function triageView(pid, a, deep = {}) {
  const reach = deep.reach || {}, reachOf = r => reach[`${r.cve}|${r.group || r.dependency}|${r.version}`];
  const rank = r => ({ reachable: 0, unclear: 1 }[(reachOf(r) || {}).verdict] ?? (reachOf(r) ? 3 : 2));
  const un = a.unresolved || [];
  const score = (x, y) => (rank(x) - rank(y)) || (y.cvss - x.cvss) || ((y.percentile || 0) - (x.percentile || 0));
  // Modules of one framework share its CVEs; one row per CVE, the modules listed in it.
  const fold = list => {
    const by = new Map();
    for (const r of list) {
      const key = [r.cve, r.group || r.dependency, r.version, r.decision, r.usage].join("|");
      if (by.has(key)) by.get(key).also.push(r.dependency); else by.set(key, { ...r, also: [] });
    }
    return [...by.values()].sort(score);
  };
  const groups = { kept: fold(a.kept), ignored: fold(a.ignored), un };
  const st = { g: a.kept.length || !un.length ? "kept" : "un", q: "", page: 1 };
  const seg = h("div", { class: "seg" }), box = h("div", {});
  const search = input({ type: "search", placeholder: "搜索 CVE、依赖、类别", oninput: debounce(e => { st.q = e.target.value.toLowerCase(); st.page = 1; draw(); }, 120) });

  const missing = [
    { label: "依赖", cell: r => [h("div", { class: "t1 mono" }, `${r.name} ${r.version || "?"}`), h("div", { class: "t2 mono" }, r.vendor)] },
    { label: "为什么没有结论", cell: r => r.reason },
  ];
  const found = [
    { label: "CVE", cell: r => h("span", { class: "mono" }, r.cve), class: "nw" },
    { label: "依赖", cell: r => [h("div", { class: "t1 mono" }, `${r.dependency} ${r.version} `, r.also.length > 0 && chip(`+${r.also.length}`, "", r.also.join("、")), r.guessed && chip("版本推测", "warn", r.via)), h("div", { class: "t2 mono" }, r.group)] },
    { label: "CVSS", cell: cvss, class: "num" },
    { label: "EPSS", cell: r => r.percentile != null ? `${(r.percentile * 100).toFixed(1)}%` : "—", class: "num nw" },
    { label: "类别", cell: r => r.family || "—", class: "nw" },
    { label: "agent 判定", cell: r => reachOf(r) ? chip(...REACH[reachOf(r).verdict]) : h("span", { class: "muted" }, "未审"), class: "nw" },
    { label: "引用", cell: r => r.usage ? chip(...USE[r.usage]) : "—", class: "nw" },
    { label: "理由", cell: r => h("div", { class: "t2 wrap", title: (reachOf(r) || r).reason }, (reachOf(r) || r).reason) },
    { label: "复核", cell: r => r.decision === "kept" ? chip("已复核", "good") : st.g === "kept" ? chip("待复核", "warn") : chip("忽略", "mute"), class: "nw" },
  ];
  function draw() {
    put(seg, [["kept", "保留"], ["ignored", "忽略"], ["un", "无结论"]].map(([k, label]) => h("button", { type: "button", class: st.g === k ? "on" : "", "aria-pressed": String(st.g === k), onclick: () => { st.g = k; st.page = 1; draw(); } }, `${label} ${groups[k].length}`)));
    const list = groups[st.g].filter(r => !st.q || `${r.cve || ""} ${r.dependency || r.name} ${r.group || r.vendor || ""} ${r.family || ""} ${r.summary || ""}`.toLowerCase().includes(st.q));
    const none = st.q ? "没有匹配的结果" : st.g === "un" ? "所有依赖都查到了结论" : st.g === "kept" && a.complete === false ? "没有保留的 CVE，但结果不完整，不能当作没有" : "没有 CVE";
    put(box, table({
      columns: st.g === "un" ? missing : found, rows: list.slice((st.page - 1) * PAGE, st.page * PAGE), id: r => r,
      onRow: st.g === "un" ? null : r => cveDrawer(pid, r, reachOf(r)), emptyText: none,
    }), pager(list.length, st.page, PAGE, p => { st.page = p; draw(); }));
  }
  draw();
  const s = a.stats;
  return h("div", {},
    h("div", { class: "meta" }, `依赖 ${s.dependencies} · CVE ${s.cves} · 保留 ${s.kept} · 忽略 ${s.ignored} · 无结论 ${s.unresolved ?? un.length}（同一框架的模块合并为一行） · 来源 ${{ opensca: "OpenSCA 依赖树", "maven+opensca": "Maven POM 还原 + OpenSCA", maven: "Maven POM 还原" }[(a.sca || {}).source] || "构建文件"}`, s.test_skipped > 0 && ` · 测试依赖 ${s.test_skipped} 个不查（不进制品）`, s.indirect_skipped > 0 && h("b", { class: "c-warn" }, ` · 间接依赖 ${s.indirect_skipped} 个没有扫描（按设置）`)),
    gapNote(a.incomplete_reasons, a.covered, pid),
    panel(null, null, h("div", { class: "toolbar" }, seg, h("div", { class: "spacer" }), search), box));
}

const VERB = { GET: "good", POST: "info", PUT: "warn", PATCH: "warn", DELETE: "bad" };
const EP = { vulnerable: ["有漏洞", "bad"], suspicious: ["可疑", "warn"], ok: ["正常", "good"], unclear: ["不清楚", "warn"] };
const EAUTH = { anonymous: ["免登录", "bad"], login: ["登录", ""], permission: ["权限", "info"], unknown: ["未知", "mute"] };
export function surfaceView(pid, a, deep = {}) {
  const seen = deep.endpoints || {}, judge = e => seen[`${e.file}|${e.method} ${e.path}`];
  const eps = a.endpoints || [], deps = a.dependencies || [];
  const st = { q: "", m: "", v: "", page: 1, dp: 1 }, box = h("div", {}), dbox = h("div", {});
  const search = input({ type: "search", placeholder: "搜索路径、文件、功能", oninput: debounce(e => { st.q = e.target.value.toLowerCase(); st.page = 1; draw(); }, 120) });
  const verbs = [...new Set(eps.map(e => e.method))].sort();
  const columns = [
    { label: "方法", cell: e => chip(e.method, VERB[e.method] || ""), class: "nw" },
    { label: "路径", cell: e => h("span", { class: "mono t1" }, e.path) },
    { label: "鉴权", cell: e => judge(e) ? [chip(...EAUTH[judge(e).auth]), judge(e).auth_default && chip(`默认：${EAUTH[judge(e).auth_default][0]}`, "warn", "默认或开发配置下")] : h("span", { class: "muted" }, "—"), class: "nw" },
    { label: "agent 判定", cell: e => judge(e) ? chip(...EP[judge(e).verdict]) : h("span", { class: "muted" }, "未审"), class: "nw" },
    { label: "说明", cell: e => h("div", { class: "t2 wrap", title: judge(e) ? judge(e).note : "" }, judge(e) ? judge(e).note : "") },
    { label: "功能推断", cell: e => (e.features || []).map(f => chip(f)) },
    { label: "同文件发现", cell: e => e.findings ? h("b", { class: "c-bad" }, e.findings) : h("span", { class: "muted" }, "0"), class: "num" },
    { label: "位置", cell: e => [h("div", { class: "mono t1 at", title: e.file }, `${e.file.split("/").pop()}:${e.line}`), h("div", { class: "t2 mono dir", title: e.file }, e.file.split("/").slice(0, -1).join("/"))] },
  ];
  function draw() {
    const list = eps.filter(e => (!st.m || e.method === st.m) && (!st.v || (st.v === "none" ? !judge(e) : st.v === "anonymous" ? (judge(e) || {}).auth === "anonymous" : (judge(e) || {}).verdict === st.v)) && (!st.q || `${e.path} ${e.file} ${(e.features || []).join(" ")}`.toLowerCase().includes(st.q)))
      .sort((x, y) => (({ vulnerable: 0, suspicious: 1 }[(judge(x) || {}).verdict] ?? 2) - ({ vulnerable: 0, suspicious: 1 }[(judge(y) || {}).verdict] ?? 2)) || (y.findings || 0) - (x.findings || 0) || x.path.localeCompare(y.path));
    put(box, table({ columns, rows: list.slice((st.page - 1) * PAGE, st.page * PAGE), id: e => e, onRow: e => showFile(pid, e.file, e.line), emptyText: eps.length ? "没有匹配的端点" : "没有提取到端点" }),
      pager(list.length, st.page, PAGE, p => { st.page = p; draw(); }));
  }
  const dcols = [
    { label: "依赖", cell: d => h("span", { class: "mono" }, `${d.group ? d.group + ":" : ""}${d.name}`) },
    { label: "版本", cell: d => d.version || chip("未解析", "warn"), class: "mono nw" },
    { label: "类型", cell: d => d.direct ? "直接" : "间接", class: "nw" },
    { label: "语言", cell: d => d.language, class: "nw" },
  ];
  function drawDeps() {
    put(dbox, table({ columns: dcols, rows: deps.slice((st.dp - 1) * PAGE, st.dp * PAGE), id: d => d, emptyText: "没有依赖" }),
      pager(deps.length, st.dp, PAGE, p => { st.dp = p; drawDeps(); }));
  }
  draw();
  drawDeps();
  return h("div", {}, gapNote(a.incomplete_reasons, a.covered, pid),
    panel(`接口 ${eps.length}`, h("span", { class: "muted" }, `agent 已审 ${eps.filter(judge).length}`), h("div", { class: "toolbar" }, search, h("div", { class: "spacer" }),
      select([["", "全部判定"], ["vulnerable", "有漏洞"], ["suspicious", "可疑"], ["anonymous", "免登录"], ["unclear", "不清楚"], ["none", "未审"]], "", v => { st.v = v; st.page = 1; draw(); }, { "aria-label": "判定" }),
      select([["", "全部方法"], ...verbs.map(v => [v, v])], "", v => { st.m = v; st.page = 1; draw(); }, { "aria-label": "方法" })), box),
    panel(`依赖 ${deps.length}`, h("span", { class: "muted" }, "漏洞匹配见「依赖」页"), dbox));
}

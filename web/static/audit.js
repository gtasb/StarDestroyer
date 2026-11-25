import { api, attempt, btn, check, chip, drawer, dur, empty, field, h, loading, modal, panel, post, put, select, stat, table, toast } from "./util.js";
import { findingsView, showFile } from "./findings.js";

export const SCOPE = [
  ["chain", "断链续追", "引擎中途断掉的链，由 agent 接着追到底"], ["dependency", "依赖 sink 追链", "每个 CVE：漏洞 API 用没用到，外部输入能不能到"],
  ["sink", "sink 反向追链", "危险调用与 MyBatis ${}，反向追到入口"], ["endpoint", "接口审计", "逐个接口看鉴权、参数去向、越权等业务逻辑"],
  ["gap", "补引擎缺口", "引擎告警、没扫到的文件、没有结论的依赖：逐条由 agent 补上，补完缺口就关闭"],
  ["secret", "硬编码判真伪", "每个疑似凭据：是不是真的、能打开什么。agent 会读到所在文件，值会随源码发给模型；不想外发就勾掉"],
  ["review", "复核引擎结论", "引擎判为已确认的，由另一个 agent 尝试推翻"],
  ["hunt", "AI 自由审计", "引擎和线索都审完后再来一轮：先模仿已有规则写本项目的 SAST / 硬编码 / SCA 规则并重跑，再规划覆盖面，多个审计员带子 agent 深读、自己调引擎，覆盖复查员补漏，最后按新发现写变体规则。用量明显更大"],
];
const k = n => n >= 1e6 ? (n / 1e6).toFixed(1) + "M" : n >= 1e3 ? Math.round(n / 1e3) + "k" : String(n);

export function auditDialog(project, done) {
  const scope = new Set(SCOPE.map(s => s[0]));
  let max = "50";
  modal("agent 审计", h("div", { class: "form" },
    h("p", { class: "muted" }, "agent 在完整源码上追链。完成的单元不会重跑，随时可以停止和继续。"),
    field("范围", h("div", { class: "stack" }, SCOPE.map(([id, label, hint]) => h("div", {}, check(label, true, v => v ? scope.add(id) : scope.delete(id)), h("small", {}, hint))))),
    field("本次单元数", select([["20", "20"], ["50", "50"], ["100", "100"], ["300", "300"], ["0", "全部"]], max, v => { max = v; }, { "aria-label": "单元数" }), "每个单元是一次独立的 agent 会话，新发现还会再复核一次；先跑高价值的")),
  close => [btn("取消", close), btn("开始", async () => {
    if (!scope.size) return toast("至少选一项", "bad");
    const d = await attempt(post("/api/tasks", { ids: [project.id], kinds: ["audit"], params: { scope: [...scope], max_units: +max } }), "已开始");
    if (!d) return;
    close();
    document.dispatchEvent(new Event("tasks-changed"));
    done();
  }, { kind: "primary", ico: "play" })]);
}

const STATE = { done: ["完成", "good"], failed: ["失败", "bad"], answered: ["已答，待归档", "info"] };
function unitDrawer(pid, u) {
  const VERDICT = { exploitable: ["可利用", "bad"], safe: ["安全", "good"], unreachable: ["到不了", "mute"], unclear: ["不清楚", "warn"] };
  drawer(u.title, h("div", { class: "pad" },
    h("div", { class: "row wrap" }, chip(...(STATE[u.state] || [u.state])), chip(u.model || u.backend || "", "")),
    h("dl", { class: "kv" }, h("dt", {}, "结果"), h("dd", {}, u.note || u.error || ""), h("dt", {}, "读码"), h("dd", {}, `${u.reads ?? "—"} 次，${u.steps ?? "—"} 次工具调用${u.subagents ? `，子 agent ${u.subagents} 个` : ""}，${dur(u.seconds)}`),
      h("dt", {}, "token"), h("dd", {}, u.usage ? `输入 ${k(u.usage.in)}${u.usage.cached ? `（缓存 ${k(u.usage.cached)}）` : ""} · 输出 ${k(u.usage.out)}` : "—"), u.findings > 0 && [h("dt", {}, "新发现"), h("dd", {}, u.findings)]),
    h("h4", {}, "内容"), h("ul", { class: "mono" }, (u.items || []).map(i => h("li", {}, i))),
    (u.detail || []).length > 0 && [h("h4", {}, "逐处结论"), u.detail.map(s => h("div", { class: "line" }, chip(...VERDICT[s.verdict]), h("span", { class: "mono" }, `第 ${s.line} 行`), s.note))]));
}

const COVER = { covered: "good", finding: "bad", unclear: "warn", not_applicable: "mute" };
function areaDrawer(pid, a) {
  drawer(a.title, h("div", { class: "pad" }, h("dl", { class: "kv" }, h("dt", {}, "边界"), h("dd", {}, a.boundary), h("dt", {}, "为什么查"), h("dd", {}, a.why), h("dt", {}, "路径"), h("dd", { class: "mono" }, a.paths.map(p => h("div", {}, p)))),
    h("h4", {}, "覆盖记录"), (a.rows || []).length ? a.rows.map(r => h("div", { class: "line" }, chip(r.class, COVER[r.status]), h("span", {}, r.checked))) : h("p", { class: "muted" }, "还没查"),
    (a.uncovered || []).length > 0 && [h("h4", {}, "审计员认为范围外还值得查"), a.uncovered.map(x => h("p", {}, h("b", {}, x.title), " ", x.why))]));
}

export function auditView(project, reload) {
  const root = h("div", { class: "audit" }, loading());
  async function load() {
    const d = await attempt(api(`/api/projects/${project.id}/audit`));
    if (!d) return put(root, empty("读取失败", ""));
    const live = project.live.find(t => t.kind === "audit");
    const start = () => auditDialog(project, reload);
    if (!d.ready) return put(root, panel(null, null, empty("审计 agent 还不能用", d.why, btn("去设置", () => { location.hash = "#/settings"; }, { kind: "primary" }))));
    const parts = Object.entries(d.by).filter(([, b]) => b.total);
    const bar = ([id, b]) => h("div", { class: "bar wide" }, h("span", {}, b.label), h("i", {}, h("b", { style: { width: `${b.done / b.total * 100}%` } })), h("span", { class: "num nw" }, `${b.done} / ${b.total}`, b.failed > 0 && h("small", { class: "c-bad" }, ` ${b.failed} 失败`)));
    const brief = d.brief;
    put(root,
      h("div", { class: "stats" }, stat("layers", `${d.done}/${d.total}`, "工作单元", d.left ? "warn" : "good"), stat("bug", project.audit.confirmed ?? 0, "agent 确认", "bad"), stat("eye", project.audit.needs_review ?? 0, "待复核", "warn"),
        stat("plug", Object.values(d.endpoints).filter(e => e.auth === "anonymous").length, "免登录接口（生产）", "info"), stat("globe", k(d.usage.in + d.usage.out), d.usage.cached ? `token · ${Math.round(d.usage.cached / Math.max(1, d.usage.in) * 100)}% 输入命中缓存` : "token")),
      h("div", { class: "cols" },
        panel("进度", live ? h("span", { class: "chip info live" }, live.stage || "排队") : btn(d.done ? (d.left ? "继续" : "重新检查") : "开始审计", start, { kind: "primary", ico: "play" }),
          h("div", { class: "pad" }, parts.length ? parts.map(bar) : h("p", { class: "muted" }, "没有可审计的内容"), d.left > 0 && h("p", { class: "c-warn" }, `还有 ${d.left} 个单元没有审，未报出不代表没有`))),
        panel("侦察结论", h("span", { class: "muted" }, d.label), brief ? h("div", { class: "pad brief" }, h("p", {}, brief.summary), h("h4", {}, "鉴权"), h("p", {}, brief.auth), brief.environments && [h("h4", {}, "各环境"), h("p", {}, brief.environments)],
          brief.anonymous.length > 0 && [h("h4", {}, `免登录路径 ${brief.anonymous.length}`), h("ul", { class: "mono" }, brief.anonymous.map(x => h("li", {}, x)))], brief.defenses && [h("h4", {}, "全局防护"), h("p", {}, brief.defenses)], brief.hotspots && [h("h4", {}, "值得深挖"), h("p", {}, brief.hotspots)],
          h("h4", {}, "依据"), brief.evidence.map(e => h("button", { class: "quote", type: "button", onclick: () => showFile(project.id, e.file, e.line) }, h("code", {}, e.quote), h("small", { class: "mono" }, `${e.file}:${e.line}`)))) : empty("还没有侦察", "审计会先读懂架构、鉴权和免登录路径，再据此展开"))),
      (d.areas || []).length > 0 && panel("覆盖面", h("span", { class: "muted" }, "AI 自由审计：攻击面 × 攻击类"), table({
        columns: [{ label: "范围", cell: a => [h("div", { class: "t1" }, a.title, a.wave > 1 && chip("补充", "info")), h("div", { class: "t2 wrap" }, a.boundary)] }, { label: "路径", cell: a => h("div", { class: "t2 mono" }, a.paths.slice(0, 3).join("  "), a.paths.length > 3 ? ` 等 ${a.paths.length}` : "") },
          { label: "攻击类", cell: a => h("div", { class: "kinds" }, a.classes.map(c => { const r = (a.rows || []).find(x => x.class === c); return chip(c, COVER[(r || {}).status] || "", r ? r.checked : "还没查"); })) }],
        rows: d.areas, onRow: a => areaDrawer(project.id, a), emptyText: "",
      })),
      (d.rules || []).length > 0 && panel("AI 写的规则", h("span", { class: "muted" }, "用引擎验证过样例，之后每次扫描都会带上；命中要再经 agent 追链和复核"), table({
        columns: [{ label: "类型", cell: r => chip({ sast: "SAST", secrets: "硬编码", sca: "SCA" }[r.kind], "info"), class: "nw" }, { label: "规则", cell: r => [h("div", { class: "t1" }, r.title), h("div", { class: "t2 mono" }, r.id)] },
          { label: "为什么写", cell: r => h("div", { class: "t2 wrap" }, r.why) }, { label: "命中", cell: r => r.hits ?? "—", class: "num" },
          { label: "", cell: r => btn("停用", async e => { e.stopPropagation(); if (await attempt(post(`/api/projects/${project.id}/airules/delete`, { id: r.id }), "已停用，下次扫描生效")) load(); }), class: "nw" }],
        rows: d.rules, onRow: r => drawer(r.title, h("div", { class: "pad" }, h("p", {}, r.why), h("pre", { class: "mono" }, JSON.stringify(r.rule || { regex: r.regex, path: r.path, product: r.product, dependency: r.dependency }, null, 2)))), emptyText: "",
      })),
      panel("最近的单元", h("span", { class: "muted" }, "点开看逐处结论"), table({
        columns: [{ label: "类型", cell: u => chip((d.by[u.kind] || {}).label || u.kind), class: "nw" }, { label: "内容", cell: u => h("div", { class: "t1" }, u.title) }, { label: "状态", cell: u => [chip(...(STATE[u.state] || [u.state])), u.findings > 0 && chip(`${u.findings} 个发现`, "bad")], class: "nw" },
          { label: "结果", cell: u => h("div", { class: "t2 wrap" }, u.note || u.error || "") }, { label: "读码", cell: u => u.reads ?? "—", class: "num" }, { label: "用时", cell: u => dur(u.seconds), class: "nw" }],
        rows: d.recent, onRow: u => unitDrawer(project.id, u), emptyText: "还没有完成的单元",
      })),
      h("h3", {}, "agent 的发现"), findingsView({ project, kind: "agent" }).el);
  }
  load();
  return root;
}

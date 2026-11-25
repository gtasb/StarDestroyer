import { api, attempt, btn, check, chip, confirmBox, debounce, dur, empty, field, h, iconBtn, input, KIND, LANGS, loading, modal, pager, panel, patch, pickPath, post, put, select, sorted, stamp, stat, table, TASK, toast } from "./util.js";
import { findingsView } from "./findings.js";
import { surfaceView, triageView } from "./artifacts.js";
import { chatView } from "./chat.js";
import { auditDialog, auditView } from "./audit.js";
import { interrupted, taskTable } from "./tasks.js";

const KINDS = ["sast", "secrets", "triage", "graph", "tabby"];
const AGENT = "agent";
export const num = (p, kind, key) => ((p.runs[kind] || {}).summary || {})[key];
const total = (p, key) => (num(p, "sast", key) || 0) + (num(p, "secrets", key) || 0) + (num(p, "tabby", key) || 0) + (p.audit[key] || 0);
const highs = p => [num(p, "sast", "severity"), num(p, "secrets", "severity"), num(p, "tabby", "severity"), p.audit.severity].reduce((n, s) => n + ((s || {}).high || 0) + ((s || {}).critical || 0), 0);
const lastRun = p => KINDS.map(k => (p.runs[k] || {}).at || "").sort().pop();

const doneState = run => run.summary.complete === false ? ["warn", `完成但不完整（${run.summary.gaps} 处缺口）`]
  : run.summary.complete ? ["good", `完成于 ${stamp(run.at)}`] : ["old", `旧版本的运行，没有记录覆盖情况（${stamp(run.at)}）`];
function kindState(p, k) {
  const live = p.live.find(t => t.kind === k), last = (p.last || {})[k], run = p.runs[k];
  if (live) return ["info live", live.state === "queued" ? "排队中" : `运行中：${live.stage || "…"}`];
  if (last && last.state !== "done" && !(last.state === "cancelled" && run)) return ["bad", `${TASK[last.state][0]}：${last.error || ""}`];
  return run ? doneState(run) : ["", "未运行"];
}
function overall(p) {
  if (!p.exists) return ["路径失效", "bad"];
  if (p.live.length) return ["运行中", "info live"];
  const states = [...KINDS.map(k => kindState(p, k)[0]), agentState(p)[0]];
  if (states.includes("bad")) return ["有失败", "bad"];
  if (states.includes("warn")) return ["不完整", "warn"];
  if (states.includes("good")) return ["已完成", "good"];
  return states.includes("old") ? ["待重扫", "old"] : ["未扫描", "mute"];
}

function agentState(p) {
  const live = p.live.find(t => t.kind === "audit"), last = (p.last || {}).audit, a = p.audit;
  if (live) return ["info live", live.stage || "排队中"];
  if (last && last.state === "failed") return ["bad", `失败：${last.error}`];
  if (!a.planned) return ["", "未运行"];
  return a.complete ? ["good", `已审完 ${a.finished} 个单元`] : ["warn", `已审 ${a.finished} / ${a.planned} 个单元`];
}
// What the agent has not looked at yet; null when it is through.
const agentOwes = a => a.planned ? (a.complete ? null : `agent 还有 ${a.gaps} 个单元没审`) : "还没有做 agent 审计：引擎追不到的链、接口和 CVE 可触达性都没有人看";
export const kindChips = p => h("div", { class: "kinds" }, h("a", { class: "chip " + agentState(p)[0], href: `#/p/${p.id}/agent`, title: `agent 审计：${agentState(p)[1]}`, onclick: e => e.stopPropagation() }, "agent"), KINDS.map(k => {
  const [cls, title] = kindState(p, k);
  return h("a", { class: "chip " + cls, href: `#/p/${p.id}/${k}`, title: `${KIND[k]}：${title}`, onclick: e => e.stopPropagation() }, KIND[k]);
}));

// ---- dialogs ----
export function projectForm(existing, done) {
  const p = existing || {};
  const path = input({ class: "mono", value: p.path || "", placeholder: "源码目录", disabled: !!existing, "aria-label": "项目路径" });
  const name = input({ value: p.name || "", placeholder: "留空用目录名", "aria-label": "名称" });
  const jar = input({ class: "mono", value: p.jar || "", placeholder: "可选", "aria-label": "jar" });
  const note = input({ value: p.note || "", "aria-label": "备注" });
  let mode = p.build ? "build" : "jar";
  const product = h("div", {});
  const drawProduct = () => put(product, mode === "build"
    ? h("small", { class: "c-warn" }, "会在副本上运行项目自带的构建脚本和插件，等于在本机执行它的代码，并联网下载依赖。只对信任的项目打开。源码没变就复用上次的产物。")
    : h("div", { class: "row" }, jar, btn("浏览", () => pickPath(v => { jar.value = v; }, { jar: true, start: jar.value || path.value }), { ico: "folder" })));
  const how = select([["jar", "指定 jar 或 classes 目录"], ["build", "自动编译（Maven / Gradle）"]], mode, v => { mode = v; drawProduct(); }, { "aria-label": "编译产物" });
  drawProduct();
  const lang = select(LANGS, p.lang || "auto", null, { "aria-label": "语言" });
  const indirect = select([["", "按全局设置"], ["1", "扫描"], ["0", "不扫描，只看直接依赖"]], p.indirect || "", null, { "aria-label": "间接依赖" });
  const form = h("div", { class: "form" },
    field("项目路径", h("div", { class: "row" }, path, !existing && btn("浏览", () => pickPath(v => { path.value = v; }, { start: path.value }), { ico: "folder" })),
      existing ? "路径是项目标识，不能修改" : "源码目录，或单个源文件"),
    field("名称", name),
    field("语言", lang, "自动：扫描全部受支持的语言"),
    field("编译产物", h("div", { class: "stack" }, how, product), "Java 调用链（Tabby）需要字节码"),
    field("间接依赖", indirect, "依赖的依赖；关掉后不查它们的 CVE"),
    field("备注", note));
  modal(existing ? "编辑项目" : "新建项目", form, close => [btn("取消", close), btn(existing ? "保存" : "创建", async () => {
    const data = { name: name.value.trim(), lang: lang.value, jar: jar.value.trim(), build: mode === "build" ? "auto" : "", indirect: indirect.value, note: note.value.trim() };
    const d = await attempt(existing ? patch(`/api/projects/${p.id}`, data) : post("/api/projects", { ...data, path: path.value.trim() }), existing ? "已保存" : null);
    if (!d) return;
    close();
    if (!existing) toast(d.existed ? "该路径已是项目，已更新信息" : "项目已创建", "good");
    done(d.project);
  }, { kind: "primary" })]);
}

const WHAT = {
  sast: "污点分析，按依赖自动生成规则", secrets: "gitleaks + 自建规则：云密钥、配置口令、写死的加密密钥；值一律打码", triage: "依赖树 → NVD / EPSS，联网，首次较慢",
  graph: "提取端点、依赖与技术栈", tabby: "编译产物建调用图查利用链，耗时较长",
};
export function runDialog(list, done, preset) {
  const kinds = new Set(preset || ["sast", "secrets", "triage", "graph", "audit"]);
  const params = { lang: "", mode: "gadget", heap: "4g", max_units: 50 };
  const noJar = list.filter(p => !p.jar && !p.build).length, builds = list.filter(p => p.build).length;
  const form = h("div", { class: "form" },
    h("p", { class: "muted" }, list.length === 1 ? list[0].name : `已选 ${list.length} 个项目：${list.slice(0, 4).map(p => p.name).join("、")}${list.length > 4 ? "…" : ""}`),
    field("agent", h("div", { class: "stack" }, h("div", {}, check("agent 审计", kinds.has("audit"), v => v ? kinds.add("audit") : kinds.delete("audit")), h("small", {}, "引擎跑完后，agent 在完整源码上审接口、追断链和 sink、验证 CVE 可触达性，再互相复核")),
      h("div", {}, select([["20", "本次 20 个单元"], ["50", "本次 50 个单元"], ["100", "本次 100 个单元"], ["0", "全部单元"]], "50", v => { params.max_units = +v; }, { "aria-label": "单元数" })))),
    field("引擎", h("div", { class: "stack" }, KINDS.map(k => h("div", {}, check(KIND[k], kinds.has(k), v => v ? kinds.add(k) : kinds.delete(k)),
      h("small", {}, WHAT[k], k === "tabby" && builds ? "，先自动编译" : "", k === "tabby" && noJar ? `（${noJar} 个项目没有 jar，会跳过）` : ""))))),
    field("语言", select([["", "按项目设置"], ...LANGS], "", v => { params.lang = v; }, { "aria-label": "语言" })),
    field("间接依赖", select([["", "按项目设置"], ["1", "扫描"], ["0", "不扫描"]], "", v => { params.indirect = v; }, { "aria-label": "间接依赖" })),
    field("调用链", h("div", { class: "row" }, select([["gadget", "反序列化入口"], ["web", "Web 入口"]], "gadget", v => { params.mode = v; }, { "aria-label": "入口" }),
      input({ value: "4g", "aria-label": "JVM 堆", oninput: e => { params.heap = e.target.value.trim(); } })), "右侧是 JVM 堆大小"));
  form.append(field("断点续扫", check("从头开始", false, v => { params.fresh = v; }), "丢掉上次没跑完的进度；不勾则接着断开处跑，已审完的单元都保留"));
  modal("开始扫描", form, close => [btn("取消", close), btn("开始", async () => {
    if (!kinds.size) return toast("至少选一个任务", "bad");
    const d = await attempt(post("/api/tasks", { ids: list.map(p => p.id), kinds: [...KINDS, "audit"].filter(k => kinds.has(k)), params }));
    if (!d) return;
    close();
    toast(`已提交 ${d.tasks.length} 个任务`, "good");
    d.errors.forEach(e => toast(e, "bad"));
    document.dispatchEvent(new Event("tasks-changed"));
    if (done) done();
  }, { kind: "primary", ico: "play" })]);
}

async function removeProjects(list, done) {
  const live = list.reduce((n, p) => n + p.live.length, 0);
  const what = list.length === 1 ? `「${list[0].name}」` : ` ${list.length} 个项目`;
  if (!await confirmBox("删除项目", `从控制台移除${what}及其运行记录，不可恢复。源码不会被删除。${live ? `会先取消 ${live} 个正在运行的任务。` : ""}`, "删除")) return;
  if (await attempt(post("/api/projects/delete", { ids: list.map(p => p.id) }), "已删除")) done();
}
async function stopAll(p, done) {
  await Promise.all(p.live.map(t => attempt(post(`/api/tasks/${t.id}/cancel`))));
  document.dispatchEvent(new Event("tasks-changed"));
  done();
}
const goto = p => { location.hash = `#/p/${p.id}`; };
export const newProject = () => btn("新建项目", () => projectForm(null, goto), { kind: "primary", ico: "plus" });

// ---- list page ----
export function projectsPage(root) {
  const st = { q: "", page: 1, size: 20, sort: { i: 6, desc: true }, filter: "" };
  const sel = new Set();
  const left = h("div", { class: "row" }, newProject()), right = h("div", { class: "row" }), body = h("div", {}, loading());
  const search = input({ type: "search", placeholder: "搜索名称、路径、备注", oninput: debounce(e => { st.q = e.target.value.toLowerCase(); st.page = 1; draw(); }, 120) });
  put(root, panel("项目管理", null, h("div", { class: "toolbar" }, left, h("div", { class: "spacer" }), right, search), body));
  let all = [];

  async function load() {
    const d = await attempt(api("/api/projects"));
    if (!d) return;
    all = d.projects;
    [...sel].forEach(i => all.some(p => p.id === i) || sel.delete(i));
    draw();
  }
  const scanned = p => p.runs.sast || p.runs.tabby || p.audit.planned;
  const count = v => v == null ? h("span", { class: "muted" }, "—") : v ? h("b", {}, v) : h("span", { class: "muted" }, "0");
  const ops = p => h("div", { class: "ops" },
    iconBtn("open", "打开", () => goto(p), "blue"),
    iconBtn("play", "扫描", () => runDialog([p], load), "green", !p.exists),
    iconBtn("edit", "编辑", () => projectForm(p, load), "amber"),
    p.live.length ? iconBtn("stop", "停止全部任务", () => stopAll(p, load), "red") : iconBtn("trash", "删除", () => removeProjects([p], load), "red"));
  const columns = [
    { label: "项目", sort: p => p.name.toLowerCase(), cell: p => [h("div", { class: "t1" }, p.name, p.note && h("span", { class: "muted" }, ` · ${p.note}`)), h("div", { class: "t2 mono", title: p.path }, p.path)] },
    { label: "任务", cell: kindChips, class: "nw" },
    { label: "高危", sort: highs, cell: p => highs(p) ? h("b", { class: "c-bad" }, highs(p)) : count(scanned(p) ? 0 : null), class: "num" },
    { label: "已确认", sort: p => total(p, "confirmed"), cell: p => count(scanned(p) ? total(p, "confirmed") : null), class: "num" },
    { label: "风险依赖", sort: p => num(p, "triage", "kept") || 0, cell: p => [count(num(p, "triage", "kept")), num(p, "triage", "unresolved") > 0 && h("small", { class: "c-warn", title: "没查到结论的依赖" }, ` +${num(p, "triage", "unresolved")}?`)], class: "num nw" },
    { label: "端点", sort: p => num(p, "graph", "endpoints") || 0, cell: p => count(num(p, "graph", "endpoints")), class: "num" },
    { label: "最近运行", sort: p => lastRun(p) || "", cell: p => lastRun(p) ? stamp(lastRun(p)) : h("span", { class: "muted" }, "从未"), class: "nw" },
    { label: "状态", sort: p => overall(p)[0], cell: p => chip(...overall(p)), class: "nw" },
    { label: "操作", cell: ops, class: "nw" },
  ];

  function draw() {
    const states = {};
    all.forEach(p => { const s = overall(p)[0]; states[s] = (states[s] || 0) + 1; });
    const rows = sorted(all.filter(p => (!st.q || `${p.name} ${p.path} ${p.note || ""}`.toLowerCase().includes(st.q)) && (!st.filter || overall(p)[0] === st.filter)), columns, st.sort);
    st.page = Math.min(st.page, Math.max(1, Math.ceil(rows.length / st.size)));
    const chosen = all.filter(p => sel.has(p.id));
    const clear = () => { sel.clear(); load(); };
    put(left, newProject(),
      btn(chosen.length ? `扫描 ${chosen.length} 个` : "批量扫描", () => runDialog(chosen, clear), { ico: "play", disabled: !chosen.length }),
      btn(chosen.length ? `删除 ${chosen.length} 个` : "删除项目", () => removeProjects(chosen, clear), { kind: "danger", ico: "trash", disabled: !chosen.length }),
      btn("刷新", load, { ico: "refresh" }));
    put(right, select([["", `全部状态 (${all.length})`], ...Object.entries(states).map(([s, c]) => [s, `${s} (${c})`])], st.filter, v => { st.filter = v; st.page = 1; draw(); }, { "aria-label": "按状态筛选" }));
    put(body, all.length ? [table({
      columns, rows: rows.slice((st.page - 1) * st.size, st.page * st.size), selected: sel, onSelect: draw, onRow: goto, emptyText: "没有符合条件的项目",
      sort: st.sort, onSort: i => { st.sort = { i, desc: st.sort.i === i ? !st.sort.desc : true }; draw(); },
    }), pager(rows.length, st.page, st.size, p => { st.page = p; draw(); }, s => { st.size = s; st.page = 1; draw(); })]
      : empty("还没有项目", "把要审计的源码目录加进来，之后的扫描、复核和历史都归在项目下", newProject()));
  }
  load();
  return { refresh: load };
}

// ---- detail page ----
const scannedAny = p => p.runs.sast || p.audit.planned > 0;
const TABS = [["overview", "概览"], ["agent", "agent 审计"], ["chat", "对话"], ["sast", "发现"], ["secrets", "硬编码"], ["triage", "依赖"], ["graph", "攻击面"], ["tabby", "调用链"], ["history", "历史"]];
const BADGE = { sast: "reportable", triage: "kept", graph: "endpoints", tabby: "chains" };
const LABEL = { agent: "agent 审计", sast: "源码扫描", secrets: "硬编码", triage: "依赖筛选", graph: "攻击面", tabby: "调用链" };

export function projectPage(root, pid, tab = "overview", run = "") {
  const head = h("div", { class: "p-head" }), tabs = h("nav", { class: "tabs", "aria-label": "项目" }), body = h("div", {}, loading());
  put(root, head, tabs, body);
  let talk = null;
  let info = null, blank = false; // blank: no artifact on screen yet, so progress is worth redrawing

  async function load() {
    const d = await attempt(api(`/api/projects/${pid}`)), list = d && await attempt(api("/api/projects"));
    if (!d || !list) {
      put(head); put(tabs);
      return put(body, empty("项目不存在", "可能已被删除", btn("回到项目列表", () => { location.hash = "#/projects"; })));
    }
    const first = !info, p = list.projects.find(x => x.id === pid);
    info = { ...d, project: p };
    put(head, h("div", {}, h("h1", {}, p.name, " ", chip(...overall(p))),
      h("p", { class: "mono muted" }, p.path, !p.exists && h("b", { class: "c-bad" }, "　路径已不存在"))),
      h("div", { class: "spacer" }),
      p.live.map(t => h("span", { class: "chip info live" }, `${t.label}：${t.stage || "排队"}`)),
      p.live.length > 0 && btn("停止", () => stopAll(p, load), { ico: "stop" }),
      btn("编辑", () => projectForm(p, load), { ico: "edit" }),
      btn("agent 审计", () => auditDialog(p, load), { ico: "eye", disabled: !p.exists }),
      btn("扫描", () => runDialog([p], load), { kind: "primary", ico: "play", disabled: !p.exists }));
    put(tabs, TABS.map(([k, label]) => h("a", { href: `#/p/${pid}/${k}`, class: tab === k ? "on" : "", "aria-current": tab === k ? "page" : null }, label,
      k === "agent" ? p.audit.planned > 0 && h("i", {}, `${p.audit.finished}/${p.audit.planned}`)
        : k === "sast" ? scannedAny(p) && h("i", {}, (num(p, "sast", "reportable") || 0) + (p.audit.reportable || 0))
          : BADGE[k] && num(p, k, BADGE[k]) != null && h("i", {}, num(p, k, BADGE[k])))));
    if (first || blank || tab === "overview") draw();
  }

  function none(kind) {
    const p = info.project, live = p.live.find(t => t.kind === kind), last = p.last[kind];
    if (live) return empty("正在运行", live.stage || "排队中");
    if (last && last.state !== "done") return empty(`上次运行${TASK[last.state][0].replace(/^已/, "被")}`, last.error, btn("重试", () => runDialog([p], load, [kind]), { kind: "primary", ico: "refresh" }));
    if (kind === "tabby" && !p.jar && !p.build) return empty("还没有编译产物", "指定 jar / classes 目录，或打开自动编译", btn("设置 jar", () => projectForm(p, load), { kind: "primary", ico: "edit" }));
    return empty("还没有结果", WHAT[kind], btn("开始", () => runDialog([p], load, [kind]), { kind: "primary", ico: "play" }));
  }
  const oldRun = () => run && h("div", { class: "gap info" }, `正在查看历史运行 ${run.replace(/\.json$/, "")}　`, h("a", { href: `#/p/${pid}/${tab}` }, "回到最新"));

  async function draw() {
    if (tab === "overview") return put(body, overview());
    if (tab === "history") return put(body, await history());
    if (tab === "agent") return put(body, auditView(info.project, load));
    if (tab === "chat") return put(body, talk = chatView(info.project, run));
    if (!LABEL[tab]) return put(body, empty("没有这个页面", ""));
    if (!blank) put(body, loading());
    const d = await attempt(api(`/api/projects/${pid}/artifact/${tab}?run=${encodeURIComponent(run)}`));
    const a = d && d.data;
    blank = !a;
    if (!a && tab === "sast" && info.project.audit.reportable) return put(body, findingsView({ project: info.project, kind: "agent" }).el);
    if (!a) return put(body, run ? empty("这次运行的记录已不存在", "每类只保留最近 20 次") : none(tab));
    const deep = tab === "triage" || tab === "graph" ? await attempt(api(`/api/projects/${pid}/audit`)) : null;
    a.covered = d.covered;
    if (tab === "triage") return put(body, oldRun(), triageView(pid, a, deep || {}));
    if (tab === "graph") return put(body, oldRun(), surfaceView(pid, a, deep || {}));
    const meta = tab === "sast" ? coverage(a) : tab === "secrets" ? h("div", { class: "meta" }, `gitleaks ${a.by_engine.gitleaks} · 自建规则 ${a.by_engine.rules} · AI 规则 ${a.by_engine.ai || 0} · 值已打码，真假由 agent 判断（agent 审计的「硬编码判真伪」）`) : h("div", { class: "meta" }, `${a.mode === "web" ? "Web 入口" : "反序列化入口"} · 方法 ${a.graph.methods} · 调用边 ${a.graph.calls} · 多态边 ${a.graph.aliases ?? 0} · 最深 ${a.max_depth} 跳 · 候选链 ${a.chains_total ?? a.chains}`);
    const owes = tab === "sast" && !run && agentOwes(info.project.audit);
    put(body, oldRun(), meta, owes && h("p", { class: "c-warn" }, owes), findingsView({ project: info.project, kind: tab === "sast" && !run ? "sast,agent" : tab, run, artifact: owes ? { ...a, complete: false } : a }).el);
  }

  function coverage(a) {
    const c = a.coverage || {}, all = c.units_total || 1, missed = (c.units_blocked || 0) + (c.units_skipped || 0);
    const part = (n, cls, label) => n > 0 && h("span", { class: cls, style: { width: `${n / all * 100}%` }, title: `${label} ${n}` });
    return h("div", { class: "cov" },
      h("div", { class: "cov-bar" }, part(c.units_covered, "good", "已覆盖"), part(c.units_candidate, "bad", "有命中"), part(c.units_blocked, "warn", "解析失败"), part(c.units_skipped, "mute", "未扫描")),
      h("div", { class: "meta" }, `引擎：${a.language} · ${c.files} 个文件 · ${c.units_total} 个检查单元（文件 × 漏洞类别）：已覆盖 ${c.units_covered}，有命中 ${c.units_candidate}`,
        c.excluded > 0 && h("span", { title: "node_modules、构建产物、压缩文件、类型声明" }, ` · 跳过 ${c.excluded} 处第三方与构建产物`), missed > 0 && h("b", { class: "c-warn" }, `，未覆盖 ${missed}`), ` · 用时 ${dur(a.elapsed_s)}`,
        (a.generated_rules || []).length > 0 && ` · 项目规则 ${a.generated_rules.length} 条`));
  }

  function overview() {
    const p = info.project, scanned = p.runs.sast || p.runs.tabby || p.audit.planned, prof = info.profile, files = Object.entries(prof.file_counts || {}).sort((a, b) => b[1] - a[1]), all = files.reduce((n, [, v]) => n + v, 0) || 1;
    const risk = KINDS.filter(k => p.runs[k] && p.runs[k].summary.complete !== true);
    const owed = agentOwes(p.audit);
    const why = f => ((prof.framework_evidence || {})[f] || []).join("、");
    return [
      h("div", { class: "stats" },
        stat("bug", scanned ? highs(p) : null, "高危（不含复核不成立）", "bad", `#/p/${pid}/sast`), stat("shield", scanned ? total(p, "confirmed") : null, "已确认", "", `#/p/${pid}/sast`),
        stat("eye", scanned ? Math.max(0, total(p, "needs_review") - total(p, "refuted")) + total(p, "needs_dynamic") : null, "待复核", "warn", `#/p/${pid}/${total(p, "needs_dynamic") ? "tabby" : "sast"}`),
        stat("box", num(p, "triage", "kept"), "风险依赖", "info", `#/p/${pid}/triage`), stat("plug", num(p, "graph", "endpoints"), "端点", "good", `#/p/${pid}/graph`)),
      h("div", { class: "cols" },
        panel("技术画像", null, h("div", { class: "pad" },
          files.length ? files.map(([l, c]) => h("div", { class: "bar" }, h("span", {}, l), h("i", {}, h("b", { style: { width: `${c / all * 100}%` } })), h("span", { class: "num" }, c))) : h("p", { class: "muted" }, "没有识别到受支持的源文件"),
          h("dl", { class: "kv" },
            h("dt", {}, "框架"), h("dd", {}, (prof.frameworks || []).length ? prof.frameworks.map(f => chip(f, "", why(f))) : "未识别"),
            h("dt", {}, "构建文件"), h("dd", {}, (prof.build_files || []).join("、") || "无"),
            h("dt", {}, "声明依赖"), h("dd", {}, info.dependencies),
            p.build && [h("dt", {}, "编译产物"), h("dd", {}, "自动编译")], !p.build && p.jar && [h("dt", {}, "jar"), h("dd", { class: "mono" }, p.jar)]))),
        panel("覆盖缺口", null, h("div", { class: "pad" }, owed && h("a", { class: "line", href: `#/p/${pid}/agent` }, chip("agent", "warn"), owed), risk.length
          ? risk.filter(k => k !== AGENT).map(k => h("a", { class: "line", href: `#/p/${pid}/${k}` }, ...(p.runs[k].summary.complete === false ? [chip("不完整", "warn"), `${LABEL[k]}：${p.runs[k].summary.gaps} 处`] : [chip("未记录", "old"), `${LABEL[k]}：旧版本的运行，建议重扫`])))
          : h("p", { class: "muted" }, Object.keys(p.runs).length ? "已完成的运行都没有缺口" : "还没有运行过")))),
      panel("任务记录", null, interrupted(info.tasks, load, pid), taskTable(info.tasks, load, false)),
    ];
  }

  async function history() {
    const d = await attempt(api(`/api/projects/${pid}/runs`));
    if (!d) return empty("读取失败", "");
    const say = ({ kind, summary: s }) => kind === "sast" ? `${s.language || ""} · 已确认 ${s.confirmed ?? 0} · 待复核 ${s.needs_review ?? 0} · 已排除 ${s.rejected ?? 0}`
      : kind === "triage" ? `保留 ${s.kept} · 忽略 ${s.ignored} · 无结论 ${s.unresolved ?? "—"}` : kind === "graph" ? `端点 ${s.endpoints} · 依赖 ${s.dependencies}` : `候选链 ${s.chains ?? "—"}`;
    return panel("历史运行", h("span", { class: "muted" }, "每类保留最近 20 次"), table({
      columns: [{ label: "时间", cell: r => stamp(r.at), class: "nw" }, { label: "类型", cell: r => chip(KIND[r.kind]), class: "nw" }, { label: "结果", cell: say },
        { label: "完整性", cell: r => r.summary.complete == null ? chip("未记录") : r.summary.complete ? chip("完整", "good") : chip(`${r.summary.gaps} 处缺口`, "warn"), class: "nw" }],
      rows: d.runs, id: r => r.run, onRow: r => { location.hash = `#/p/${pid}/${r.kind}/${encodeURIComponent(r.run)}`; }, emptyText: "还没有运行记录",
    }));
  }

  load();
  return {
    stop: () => { if (talk) talk.stop(); },
    refresh: async ended => {
      await load();
      if (!run && ended && ended.some(t => t.project_id === pid && (t.kind === tab || tab === "history" || (["review", "audit"].includes(t.kind) && ["sast", "secrets", "agent", "triage", "graph"].includes(tab))))) draw();
    },
  };
}

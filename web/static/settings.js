import { api, attempt, btn, chip, field, h, input, loading, panel, post, put, select, toast } from "./util.js";
import { engines } from "./pages.js";

const GROUPS = [
  ["引擎", [["OPENGREP_BIN", "Opengrep", "留空自动查找 .work/og200/bin"], ["TABBY_JAR", "Tabby jar", "留空自动查找 .work/tabby/dist"],
    ["OPENSCA_BIN", "OpenSCA CLI", "留空自动查找 .work/opensca/bin"], ["GITLEAKS_BIN", "gitleaks", "硬编码扫描，留空从 PATH 查找；也可填 betterleaks"], ["BUILD_JAVA_HOME", "编译用 JDK", "自动编译时的 JDK 目录，留空用系统的"], ["DSH_BIN", "dsh", "审计 agent 的运行框架，留空从 PATH 查找"]]],
  ["数据源", [["NVD_API_KEY", "NVD", "提高查询限额，依赖多时明显更快"], ["TAVILY_API_KEY", "Tavily", "联网检索 CVE 分析"]]],
  ["依赖", [["SCA_INDIRECT", "间接依赖", "扫描依赖的依赖，默认扫描", [["", "默认（扫描）"], ["1", "扫描"], ["0", "不扫描，只看直接依赖"]]],
    ["SCA_MAVEN", "Maven 仓库", "还原父 POM 和间接依赖用；默认 Maven Central，可填镜像 https 地址，0 关闭。公开构件的坐标会发给它，自家 groupId 的不发"], ["POM_ROOTS", "POM 查找目录", "私有父 POM 在本机哪里，分号分隔；默认找项目旁边的仓库"],
    ["SCA_OSV", "OSV 批量查询", "会收到依赖的名字和版本；关掉后只用 NVD，慢很多", [["", "默认（开）"], ["1", "开"], ["0", "关"]]]]],
  ["其他", [["AUDIT_CONCURRENCY", "并行会话数", "agent 审计同时跑几个，默认 4"], ["REVIEW_MAX", "单次复核上限", "默认 20"],
    ["AUDIT_INTERFILE_DEPTH", "跨文件深度", "引擎，默认 20；更深的由 agent 续追"], ["SD_LOG_LEVEL", "日志级别", "DEBUG / INFO / WARN / ERROR"]]],
];
const ACCESS_NOTE = {
  shell: "agent 可以跑命令、主动调用命令行工具。命令在 dsh 沙箱里：只能写一个空的临时工作区，改不了被审项目，环境里没有 API key。沙箱不限制读取：恶意源码若诱导成功，能读到你的用户目录（含保存 key 的设置文件、.ssh），联网也不保证被拦。审不可信来源的代码请选只读守卫。",
  readonly: "没有 shell 和联网，只能读被审项目内的文件，密钥类文件除外。审不可信来源的代码用这一档。",
  open: "dsh 的全部工具都可用，包括联网和子 agent；命令仍在沙箱里。被审源码的内容可能被发到任意网站。只对自己的代码用。",
};
const save = values => post("/api/settings", { values });

// A model is picked from what the service itself lists; the catalog of the installed dsh
// stands in when it cannot be asked. Anything else can be typed.
const fetched = new Map();
function modelBox(p, value, where) {
  const ctx = n => n >= 1e6 ? `${+(n / 1e6).toFixed(1)}M` : n ? `${Math.round(n / 1000)}K` : "";
  const box = input({ class: "mono", "aria-label": "模型", value, autocomplete: "off", role: "combobox", placeholder: p.models.length ? "点开选择，或直接填写" : "点开自动获取，或直接填写" });
  const list = h("div", { class: "combo-list", role: "listbox", hidden: true }), note = h("small", {});
  let typed = false, asked = false;
  const at = () => `${p.id}|${where().base}`;
  const rows = () => (fetched.get(at()) || {}).models || p.models;
  function draw() {
    const q = typed ? box.value.trim().toLowerCase() : "";
    const hit = rows().filter(m => !q || `${m.id} ${m.name || ""}`.toLowerCase().includes(q));
    put(list, hit.slice(0, 300).map(m => h("button", { type: "button", role: "option", class: m.id === box.value.trim() ? "on" : "", onmousedown: e => e.preventDefault(), onclick: () => { box.value = m.id; typed = false; list.hidden = true; } },
      h("span", { class: "mono" }, m.id), h("small", {}, [m.name && m.name !== m.id ? m.name : "", ctx(m.context)].filter(Boolean).join(" · ")))),
    hit.length > 300 && h("p", { class: "muted" }, `还有 ${hit.length - 300} 个，输入关键字缩小范围`), !hit.length && h("p", { class: "muted" }, rows().length ? "没有匹配的，可以直接用填写的名字" : "还没有列表，可以直接填写"));
  }
  function say() {
    const f = fetched.get(at());
    put(note, f ? `已从 ${new URL(f.url).host} 获取 ${f.models.length} 个模型${f.hidden ? `，略去 ${f.hidden} 个非对话模型` : ""}` : p.models.length ? "显示的是 dsh 自带的目录；点「获取模型」向服务商取最新的" : "点「获取模型」向服务商取列表，也可以直接填写");
    note.className = "";
  }
  async function get(loud) {
    if (refresh.disabled) return;
    refresh.disabled = true;
    put(note, "正在获取…");
    const r = await post("/api/llm/models", { provider: p.id, ...where() }).catch(e => ({ error: e.message }));
    refresh.disabled = false;
    if (r.models) {
      fetched.set(at(), r);
      say();
      if (loud) { typed = false; list.hidden = false; box.focus(); }
    } else {
      put(note, r.error);
      note.className = "c-warn";
    }
    draw();
  }
  const refresh = btn("获取模型", () => get(true), { ico: "refresh" });
  const open = () => {
    list.hidden = false;
    draw();
    if (!asked && !fetched.has(at()) && (p.has_key || p.local || where().key)) { asked = true; get(false); }
  };
  box.addEventListener("focus", open);
  box.addEventListener("click", open);
  box.addEventListener("input", () => { typed = true; list.hidden = false; draw(); });
  box.addEventListener("keydown", e => { if (e.key === "Escape") list.hidden = true; });
  const el = h("div", { class: "combo" }, h("div", { class: "row" }, box, refresh), list, note);
  el.addEventListener("focusout", e => { if (!el.contains(e.relatedTarget)) list.hidden = true; });
  say();
  return { el, value: () => box.value.trim() };
}

// dsh routes the model; its installed catalog is what is offered here.
function modelPanel(d, keys, reload) {
  const box = h("div", {});
  const show = pid => {
    const p = d.providers.find(x => x.id === pid), mine = d.chosen.id === pid;
    const k = keys[p.key_name] || { set: false, value: "" }, env = k.source === "env";
    const key = input({ type: "password", class: "mono", autocomplete: "new-password", "aria-label": "API key", disabled: env, placeholder: k.set ? `已设置 ${k.value}` : p.has_key ? "已从环境变量读到" : p.local ? "可空" : "未设置" });
    const base = input({ class: "mono", "aria-label": "接口地址", value: mine ? d.chosen.base : "", placeholder: p.base || (pid === "custom" ? "https://…/v1" : "默认") });
    const model = modelBox(p, mine ? d.chosen.model : "", () => ({ base: pid === "deepseek-official" ? "" : base.value.trim(), key: key.value }));
    const apply = () => {
      const values = { LLM_PROVIDER: pid, LLM_MODEL: model.value(), LLM_BASE_URL: base.value.trim() };
      if (key.value) values[p.key_name] = key.value;
      return attempt(save(values));
    };
    const test = async e => {
      const b = e.currentTarget;
      if (!await apply()) return;
      b.disabled = true;
      toast("正在起一个 dsh 会话…");
      const r = await attempt(post("/api/llm/test"));
      if (r) toast(`${r.model}：${r.message}`, "good");
      reload();
    };
    put(box,
      field("API key", h("div", { class: "row" }, key, env ? chip("环境变量", "info", "由环境变量提供，这里改不了") : k.set && btn("清除", async () => { if (await attempt(save({ [p.key_name]: "" }), "已清除")) reload(); }))),
      pid !== "deepseek-official" && field("接口地址", base, p.local ? "任何兼容 OpenAI 协议的服务" : "用代理或中转时填写，留空用默认"),
      field("模型", model.el, pid === "deepseek-official" ? "留空用 dsh 默认" : ""),
      h("div", { class: "row" }, btn("保存并使用", async () => { if (await apply()) { toast("已保存，立即生效", "good"); reload(); } }, { kind: "primary" }), btn("测试会话", test)));
  };
  const pick = select(d.providers.map(p => [p.id, p.name + (p.has_key ? "　✓" : "")]), d.chosen.id, show, { "aria-label": "服务商" });
  show(d.chosen.id);
  return panel("审计 agent 的模型", d.ready ? chip(d.label, "good") : chip(d.why, "warn"), h("div", { class: "pad form narrow" },
    field("框架", h("span", { class: "mono" }, d.dsh || "没有找到 dsh"), "agent 跑在 DeepSeek Harness 上"),
    field("会话权限", h("div", { class: "stack" }, select(Object.entries(d.access_modes), d.access, async v => { if (await attempt(save({ AUDIT_ACCESS: v }), "已保存，下一个会话生效")) reload(); }, { "aria-label": "会话权限" }),
      h("small", { class: d.access === "readonly" ? "" : "c-warn" }, ACCESS_NOTE[d.access]))),
    field("服务商", pick, "会把相关源码发给所选服务商；不想外发就用本机模型"), box));
}

export function settingsPage(root) {
  put(root, loading());
  async function load() {
    const [d, m, he] = await Promise.all(["/api/settings", "/api/llm", "/api/health"].map(u => attempt(api(u))));
    if (!d || !m || !he) return;
    const edits = {};
    const clear = key => async () => { if (await attempt(save({ [key]: "" }), "已清除")) load(); };
    const row = ([key, label, hint, options]) => {
      const v = d.keys[key], env = v.source === "env";
      if (options) {
        const pick = select(options, v.value, val => { edits[key] = val; }, { "aria-label": label });
        pick.disabled = env;
        return h("div", { class: "set" }, h("div", {}, h("b", {}, label), h("small", {}, hint)), pick, env ? chip("环境变量", "info", "由环境变量提供，这里改不了") : h("span", {}));
      }
      const box = input({
        type: v.secret ? "password" : "text", class: "mono", value: v.secret ? "" : v.value, disabled: env, autocomplete: "new-password", "aria-label": label,
        placeholder: v.set && v.secret ? `已设置 ${v.value}` : "未设置", oninput: e => { edits[key] = e.target.value; },
      });
      return h("div", { class: "set" }, h("div", {}, h("b", {}, label), h("small", {}, hint)), box,
        env ? chip("环境变量", "info", "由环境变量提供，这里改不了") : v.set ? btn("清除", clear(key)) : h("span", {}));
    };
    async function saveAll() {
      const values = Object.fromEntries(Object.entries(edits).filter(([k, v]) => v !== "" || !d.keys[k].secret));
      if (!Object.keys(values).length) return toast("没有改动");
      if (await attempt(save(values), "已保存，立即生效")) load();
    }
    put(root, modelPanel(m, d.keys, load),
      GROUPS.map(([title, rows]) => panel(title, null, h("div", { class: "pad" }, rows.map(row)))),
      h("div", { class: "row save" }, btn("保存", saveAll, { kind: "primary" }), h("span", { class: "muted mono" }, d.path)),
      panel("当前状态", null, engines(he.engines)));
  }
  load();
}

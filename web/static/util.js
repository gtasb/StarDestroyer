// DOM, API and small UI pieces. Everything on screen may come from audited
// source, so nodes are built, never parsed: there is no innerHTML in this app.

const TOKEN = document.querySelector('meta[name="sd-token"]').content;

export const $ = (s, root = document) => root.querySelector(s);

export function h(tag, attrs = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k === "style") Object.assign(el.style, v);
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k in el && typeof v !== "string") el[k] = v;
    else el.setAttribute(k, v === true ? "" : v);
  }
  el.append(...kids.flat(Infinity).filter(x => x != null && x !== false).map(x => x instanceof Node ? x : String(x)));
  return el;
}
export const put = (el, ...kids) => { el.replaceChildren(...kids.flat(Infinity).filter(Boolean)); return el; };

// ---- api ----
export async function api(path, opts = {}) {
  let r;
  try {
    r = await fetch(path, { ...opts, headers: { ...opts.headers, "X-SD-Token": TOKEN } });
  } catch {
    banner("连不上控制台服务，可能已停止。");
    throw new Error("连不上控制台服务");
  }
  if (r.status !== 403) banner("");
  if (opts.raw) {
    if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error || r.statusText);
    return r.text();
  }
  const d = await r.json().catch(() => ({ ok: false, error: `服务返回了无法识别的内容（HTTP ${r.status}）` }));
  if (r.status === 403) { banner(d.error); throw new Error(d.error); }
  return d;
}
const body = (method, data) => ({ method, headers: { "Content-Type": "application/json" }, body: JSON.stringify(data || {}) });
export const post = (path, data) => api(path, body("POST", data));
export const patch = (path, data) => api(path, body("PATCH", data));

// Toast the error and return null, so callers can simply stop.
export async function attempt(promise, done) {
  try {
    const d = await promise;
    if (d && d.ok === false) { toast(d.error || "操作失败", "bad"); return null; }
    if (done) toast(done, "good");
    return d;
  } catch (e) { toast(e.message, "bad"); return null; }
}

function banner(text) {
  const el = $("#banner");
  el.textContent = text;
  el.hidden = !text;
}

// ---- icons (24x24 strokes) ----
const PATHS = {
  shield: "M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z M9 12l2 2 4-4",
  bug: "M9 9h6v6a3 3 0 0 1-6 0z M12 9V5 M5 9l4 2 M19 9l-4 2 M4 15h5 M20 15h-5 M6 20l3-3 M18 20l-3-3",
  eye: "M2 12s4-7 10-7 10 7 10 7-4 7-10 7-10-7-10-7z M12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6z",
  box: "M12 3l8 4.5v9L12 21l-8-4.5v-9z M4 7.5l8 4.5 8-4.5 M12 12v9",
  plug: "M9 3v5 M15 3v5 M6 8h12v3a6 6 0 0 1-12 0z M12 17v4",
  warn: "M12 4l9 16H3z M12 10v4 M12 17v.5",
  book: "M5 4h11a3 3 0 0 1 3 3v13H8a3 3 0 0 1-3-3z M5 17a3 3 0 0 1 3-3h11",
  rule: "M4 6h16 M4 12h10 M4 18h7 M17 15l2 2 3-4",
  layers: "M12 3l9 5-9 5-9-5z M3 13l9 5 9-5",
  globe: "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18z M3 12h18 M12 3c3 3 3 15 0 18 M12 3c-3 3-3 15 0 18",
  open: "M14 4h6v6 M20 4l-9 9 M18 14v6H4V6h6", play: "M7 5l12 7-12 7z",
  edit: "M4 20h4L19 9l-4-4L4 16z", trash: "M5 7h14 M10 7V4h4v3 M7 7l1 13h8l1-13",
  refresh: "M20 11a8 8 0 1 0-2 6 M20 5v6h-6", plus: "M12 5v14 M5 12h14", stop: "M6 6h12v12H6z",
  x: "M6 6l12 12 M18 6L6 18", folder: "M3 6h6l2 2h10v11H3z", file: "M6 3h8l4 4v14H6z M14 3v4h4",
  search: "M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14z M16 16l5 5", moon: "M20 14A8 8 0 1 1 10 4a6 6 0 0 0 10 10z",
  sun: "M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8z M12 2v3 M12 19v3 M2 12h3 M19 12h3 M5 5l2 2 M17 17l2 2 M19 5l-2 2 M7 17l-2 2",
  down: "M12 4v12 M7 11l5 5 5-5 M5 20h14", check: "M5 12l5 5 9-10", flag: "M6 21V4 M6 5h12l-3 4 3 4H6",
  ban: "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18z M6 6l12 12",
};
export function icon(name, size = 16) {
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  const attrs = { viewBox: "0 0 24 24", width: size, height: size, fill: "none", stroke: "currentColor", "stroke-width": 1.8, "stroke-linecap": "round", "stroke-linejoin": "round", "aria-hidden": "true" };
  for (const [k, v] of Object.entries(attrs)) svg.setAttribute(k, v);
  const p = document.createElementNS(ns, "path");
  p.setAttribute("d", PATHS[name] || "");
  svg.append(p);
  return svg;
}

// ---- pieces ----
export const btn = (label, onclick, { kind = "", ico, title, disabled } = {}) =>
  h("button", { class: "btn " + kind, type: "button", onclick, title, disabled }, ico && icon(ico), label && h("span", {}, label));
export const iconBtn = (ico, title, onclick, kind = "", disabled = false) =>
  h("button", { class: "ib " + kind, type: "button", title, "aria-label": title, disabled, onclick: e => { e.stopPropagation(); onclick(e); } }, icon(ico, 15));
export const chip = (text, kind = "", title) => h("span", { class: "chip " + kind, title }, text);
export const panel = (title, right, ...kids) => h("section", { class: "panel" },
  title && h("header", { class: "panel-h" }, h("h2", {}, title), h("div", { class: "spacer" }), right), ...kids);
export const stat = (ico, value, label, tone = "", href) => h(href ? "a" : "div", { class: "stat " + tone, href },
  icon(ico, 30), h("b", {}, value ?? "—"), h("span", {}, label));
export const empty = (title, hint, ...actions) => h("div", { class: "empty" }, h("p", { class: "e-t" }, title),
  hint && h("p", { class: "e-h" }, hint), actions.length > 0 && h("div", { class: "row center" }, actions));
export const loading = () => h("div", { class: "empty" }, h("p", { class: "e-h" }, "加载中…"));

// "0 findings" only means clean when the run was complete.
// What an engine could not do; `covered` says which agent work stands in for it.
export function gapNote(reasons, covered, pid) {
  if (!reasons || !reasons.length) return null;
  if (!covered || !covered.length) return h("div", { class: "gap" }, h("b", {}, icon("warn", 15), "结果不完整，未报出不代表没有"), h("ul", {}, reasons.map(r => h("li", {}, r))));
  const open = covered.filter(g => !g.closed);
  const state = g => g.closed ? chip("agent 已补上", "good") : g.left && !(g.total > g.done) ? chip(`agent 也没查清 ${g.left} 个`, "warn") : g.done ? chip(`agent 补到 ${g.done} / ${g.total}`, "info") : chip(g.total ? `等 agent 补（${g.total} 个单元）` : "等 agent 补", "warn");
  return h("div", { class: "gap" + (open.length ? "" : " info") }, h("b", {}, open.length > 0 && icon("warn", 15), open.length ? "引擎没做完的部分" : "引擎没做完的部分已由 agent 补上"),
    h("ul", {}, covered.map(g => h("li", {}, state(g), " ", g.text.replace(/^引擎告警：SemgrepWarning:\s*/, ""), g.more > 0 && ` （另有 ${g.more} 条规则同样的限制）`, h("small", { class: "muted" }, `　${g.how}`)))),
    open.length > 0 && pid && h("a", { href: `#/p/${pid}/agent` }, "去 agent 审计补上"));
}

export const STATUS = { confirmed: ["已确认", "bad"], needs_review: ["待复核", "warn"], needs_dynamic: ["需动态验证", "info"], refuted: ["复核不成立", "mute"], rejected: ["已排除", "mute"] };
export const SEV = { critical: ["严重", "bad"], high: ["高", "bad"], medium: ["中", "warn"], low: ["低", "info"], unknown: ["未知", "mute"] };
export const TASK = { queued: ["排队", "info"], running: ["运行中", "info live"], done: ["完成", "good"], failed: ["失败", "bad"], cancelled: ["已取消", "mute"], interrupted: ["已中断", "bad"] };
export const KIND = { sast: "源码", secrets: "硬编码", triage: "依赖", graph: "攻击面", tabby: "调用链", agent: "agent" };
export const LANGS = [["auto", "自动"], ["java", "Java"], ["python", "Python"], ["go", "Go"], ["js", "JavaScript / TypeScript"], ["php", "PHP"]];
export const statusChip = s => chip(...(STATUS[s] || [s, ""]));
export const sevChip = s => chip(...(SEV[s] || SEV.unknown));
export const stamp = s => s && /^\d{8}-\d{6}/.test(s) ? `${s.slice(0, 4)}-${s.slice(4, 6)}-${s.slice(6, 8)} ${s.slice(9, 11)}:${s.slice(11, 13)}` : (s || "—");
export const dur = s => s == null ? "—" : s < 60 ? `${Math.round(s)} 秒` : s < 3600 ? `${Math.floor(s / 60)} 分 ${Math.round(s % 60)} 秒` : `${Math.floor(s / 3600)} 时 ${Math.floor(s % 3600 / 60)} 分`;

export const input = attrs => h("input", { type: "text", spellcheck: "false", autocomplete: "off", ...attrs });
export const select = (options, value, onchange, attrs = {}) => h("select", { onchange: e => onchange && onchange(e.target.value), ...attrs },
  options.map(([v, label]) => h("option", { value: v, selected: v === value }, label)));
export const field = (label, control, hint) => h("div", { class: "field" }, h("span", {}, label), h("div", {}, control, hint && h("small", {}, hint)));
export const check = (label, checked, onchange, title) => h("label", { class: "check", title },
  h("input", { type: "checkbox", checked: !!checked, onchange: e => onchange(e.target.checked) }), label);

export function debounce(fn, ms = 250) { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; }

// columns: [{label, cell(row), class, sort(row)}]; selected: Set of ids
export function table({ columns, rows, id = r => r.id, selected, onSelect, canSelect = () => true, onRow, emptyText = "没有数据", sort, onSort }) {
  const all = selected && h("input", {
    type: "checkbox", "aria-label": "全选", checked: rows.some(canSelect) && rows.filter(canSelect).every(r => selected.has(id(r))),
    onchange: e => { rows.filter(canSelect).forEach(r => e.target.checked ? selected.add(id(r)) : selected.delete(id(r))); onSelect(); },
  });
  const head = columns.map((c, i) => h("th", { class: (c.class || "") + (c.sort && onSort ? " sortable" : ""), onclick: c.sort && onSort ? () => onSort(i) : null },
    c.label, sort && sort.i === i ? (sort.desc ? " ↓" : " ↑") : ""));
  const line = r => h("tr", {
    class: onRow ? "click" : "", tabindex: onRow ? "0" : null, onclick: onRow ? () => onRow(r) : () => {},
    onkeydown: e => { if (onRow && e.key === "Enter" && e.target === e.currentTarget) onRow(r); },
  }, selected && h("td", { class: "c-check", onclick: e => e.stopPropagation() }, canSelect(r) && h("input", {
    type: "checkbox", "aria-label": "选择", checked: selected.has(id(r)),
    onchange: e => { e.target.checked ? selected.add(id(r)) : selected.delete(id(r)); onSelect(); },
  })), columns.map(c => h("td", { class: c.class || "" }, c.cell(r))));
  const none = h("tr", {}, h("td", { class: "none", colspan: String(columns.length + (selected ? 1 : 0)) }, emptyText));
  return h("div", { class: "tw" }, h("table", {}, h("thead", {}, h("tr", {}, selected && h("th", { class: "c-check" }, all), head)),
    h("tbody", {}, rows.length ? rows.map(line) : none)));
}
export function sorted(rows, columns, sort) {
  const key = sort && columns[sort.i] && columns[sort.i].sort;
  if (!key) return rows;
  const out = [...rows].sort((a, b) => { const x = key(a), y = key(b); return x < y ? -1 : x > y ? 1 : 0; });
  return sort.desc ? out.reverse() : out;
}
const step = (t, title, disabled, onclick) => h("button", { class: "ib", type: "button", title, "aria-label": title, disabled, onclick }, t);
export function pager(total, page, size, go, resize) {
  const pages = Math.max(1, Math.ceil(total / size));
  return h("div", { class: "pager" }, h("span", {}, `共 ${total} 条`),
    step("‹", "上一页", page <= 1, () => go(page - 1)), h("b", {}, `${page} / ${pages}`), step("›", "下一页", page >= pages, () => go(page + 1)),
    resize && select([["20", "20 / 页"], ["50", "50 / 页"], ["100", "100 / 页"]], String(size), v => resize(+v), { "aria-label": "每页条数" }));
}

// ---- overlays ----
export function toast(text, kind = "") {
  const el = h("div", { class: "toast " + kind, role: "status" }, text);
  $("#toasts").append(el);
  setTimeout(() => el.remove(), kind === "bad" ? 7000 : 3500);
}

const stack = [];
function overlay(cls, title, content, foot, onClose) {
  const back = document.activeElement;
  const close = () => {
    if (!wrap.isConnected) return;
    wrap.remove();
    stack.splice(stack.indexOf(close), 1);
    if (back && back.focus) back.focus();
    if (onClose) onClose();
  };
  const box = h("div", { class: cls, role: "dialog", "aria-modal": "true", "aria-label": title },
    h("header", {}, h("h3", {}, title), h("div", { class: "spacer" }), iconBtn("x", "关闭", close)),
    h("div", { class: "o-body" }, content), foot && h("footer", {}, foot(close)));
  const wrap = h("div", { class: "overlay", onmousedown: e => { if (e.target === wrap) close(); } }, box);
  document.body.append(wrap);
  stack.push(close);
  const first = box.querySelector(".o-body input:not([disabled]), footer .primary, footer .danger");
  if (first) first.focus();
  return { close, box };
}
addEventListener("keydown", e => { if (e.key === "Escape" && stack.length) stack[stack.length - 1](); });
export const closeAll = () => [...stack].reverse().forEach(c => c());
export const modal = (title, content, foot, onClose) => overlay("modal", title, content, foot, onClose);
export const drawer = (title, content, foot) => overlay("drawer", title, content, foot);
export const confirmBox = (title, text, label) => new Promise(resolve => {
  let answer = false;
  modal(title, h("p", {}, text), close => [btn("取消", close), btn(label, () => { answer = true; close(); }, { kind: "danger" })], () => resolve(answer));
});

// ---- directory picker ----
export function pickPath(onPick, { jar = false, start = "" } = {}) {
  const list = h("div", { class: "fs" }), here = input({ class: "mono", value: start, "aria-label": "路径" });
  const m = modal(jar ? "选择 jar 或 classes 目录" : "选择项目目录",
    h("div", {}, h("div", { class: "row" }, here, btn("转到", () => load(here.value))), list),
    close => [btn("取消", close), btn("选择当前目录", () => {
      if (!here.value) return toast("请先进入一个目录", "bad");
      onPick(here.value);
      close();
    }, { kind: "primary" })]);
  here.addEventListener("keydown", e => { if (e.key === "Enter") load(here.value); });
  async function load(path) {
    const d = await attempt(api(`/api/fs?path=${encodeURIComponent(path)}&jar=${jar}`));
    if (!d) return;
    here.value = d.path;
    put(list, d.parent != null && h("button", { type: "button", onclick: () => load(d.parent) }, icon("folder"), "上一级"),
      d.items.map(i => h("button", { type: "button", onclick: () => i.dir ? load(i.path) : (onPick(i.path), m.close()) }, icon(i.dir ? "folder" : "file"), i.name)),
      !d.items.length && h("p", { class: "muted" }, "没有子目录"));
  }
  load(start);
}

export function saveText(name, text) {
  const a = h("a", { href: URL.createObjectURL(new Blob([text])), download: name });
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

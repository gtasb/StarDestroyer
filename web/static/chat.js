// A conversation with the agent about one project. Text is the model's and the model has
// read audited source, so Markdown becomes nodes here, never markup.
import { api, attempt, btn, chip, confirmBox, empty, h, icon, iconBtn, input, loading, modal, patch, post, put, select, toast } from "./util.js";
import { showFile } from "./findings.js";

// ---- Markdown ----
const FILE = /([\w@.\-/\\]+\.[A-Za-z]{1,6}):(\d+)/;
function inline(text, open) {
  const out = [], rx = /`([^`\n]+)`|\*\*([^*\n]+)\*\*|\[([^\]\n]+)\]\((https?:\/\/[^\s)]+)\)|(?<![\w*])\*([^*\n]+)\*(?![\w*])|([\w@.\-/\\]+\.[A-Za-z]{1,6}:\d+)/g;
  let at = 0;
  for (const m of text.matchAll(rx)) {
    if (m.index > at) out.push(text.slice(at, m.index));
    at = m.index + m[0].length;
    if (m[1] != null) out.push(file(m[1], open) || h("code", {}, m[1]));
    else if (m[2] != null) out.push(h("b", {}, inline(m[2], open)));
    else if (m[3] != null) out.push(h("a", { href: m[4], target: "_blank", rel: "noopener noreferrer" }, m[3]));
    else if (m[5] != null) out.push(h("em", {}, m[5]));
    else out.push(file(m[6], open) || m[6]);
  }
  if (at < text.length) out.push(text.slice(at));
  return out;
}
function file(text, open) {
  const m = text.match(FILE);
  return m && m[0] === text.replace(/-\d+$/, "") ? h("button", { class: "file", type: "button", onclick: () => open(m[1].replace(/\\/g, "/"), +m[2]) }, text) : null;
}
export function markdown(text, open) {
  const lines = text.split("\n"), out = [];
  let i = 0;
  while (i < lines.length) {
    const l = lines[i];
    let m;
    if ((m = l.match(/^\s*```(.*)$/))) {
      const code = [];
      while (++i < lines.length && !/^\s*```\s*$/.test(lines[i])) code.push(lines[i]);
      i++;
      const body = code.join("\n");
      out.push(h("div", { class: "md-code" }, h("div", { class: "row" }, h("small", {}, m[1].trim() || "代码"), h("div", { class: "spacer" }), iconBtn("file", "复制", () => copy(body))), h("pre", {}, h("code", {}, body))));
    } else if ((m = l.match(/^(#{1,6})\s+(.*)$/))) {
      out.push(h("h" + Math.min(6, m[1].length + 2), {}, inline(m[2], open)));
      i++;
    } else if (/^\s*([-*_])(\s*\1){2,}\s*$/.test(l)) {
      out.push(h("hr"));
      i++;
    } else if (/^\s*\|.*\|\s*$/.test(l) && /^\s*\|[\s:|-]+\|\s*$/.test(lines[i + 1] || "")) {
      const cells = r => r.trim().replace(/^\||\|$/g, "").split("|").map(c => c.trim());
      const head = cells(l), rows = [];
      i += 2;
      while (i < lines.length && /^\s*\|.*\|\s*$/.test(lines[i])) rows.push(cells(lines[i++]));
      out.push(h("div", { class: "md-table" }, h("table", {}, h("thead", {}, h("tr", {}, head.map(c => h("th", {}, inline(c, open))))), h("tbody", {}, rows.map(r => h("tr", {}, r.map(c => h("td", {}, inline(c, open)))))))));
    } else if (/^\s*>\s?/.test(l)) {
      const q = [];
      while (i < lines.length && /^\s*>\s?/.test(lines[i])) q.push(lines[i++].replace(/^\s*>\s?/, ""));
      out.push(h("blockquote", {}, markdown(q.join("\n"), open)));
    } else if (/^\s*([-*+]|\d+[.)])\s+/.test(l)) {
      const items = [];
      let deep = 0; // where the item's own text begins
      const base = l.match(/^\s*/)[0].length, ordered = /^\s*\d/.test(l), first = ordered ? +l.trim().match(/^\d+/)[0] : 1;
      while (i < lines.length) {
        const item = lines[i].match(/^(\s*)([-*+]|\d+[.)])\s+(.*)$/);
        if (item && item[1].length <= base + 1 && /^\d/.test(item[2]) === ordered) { items.push([item[3]]); deep = item[1].length + item[2].length + 1; i++; }
        else if (items.length && (/^\s{2,}\S/.test(lines[i]) || (lines[i].trim() === "" && /^\s{2,}\S/.test(lines[i + 1] || "")))) items.at(-1).push(lines[i++].replace(new RegExp(`^ {0,${deep}}`), ""));
        else break;
      }
      out.push(h(ordered ? "ol" : "ul", ordered ? { start: first } : {}, items.map(x => h("li", {}, x.length === 1 ? inline(x[0], open) : markdown(x.join("\n"), open)))));
    } else if (!l.trim()) i++;
    else {
      const p = [];
      while (i < lines.length && lines[i].trim() && !/^\s*(```|#{1,6}\s|>|([-*+]|\d+[.)])\s)/.test(lines[i]) && !(/^\s*\|.*\|\s*$/.test(lines[i]) && p.length === 0 && /^\s*\|[\s:|-]+\|\s*$/.test(lines[i + 1] || ""))) p.push(lines[i++]);
      if (!p.length) p.push(lines[i++]);
      out.push(h("p", {}, p.flatMap((x, n) => [n > 0 && h("br"), ...inline(x, open)])));
    }
  }
  return out;
}
async function copy(text) {
  try { await navigator.clipboard.writeText(text); toast("已复制", "good"); } catch { toast("复制失败", "bad"); }
}

// ---- one answer ----
let home = ""; // the project's root: a path is shown from there
const brief = v => {
  if (!v || typeof v !== "object") return String(v ?? "");
  const s = v.command || v.file_path || v.file || v.pattern || v.name || v.method || v.cve || v.description || v.path || v.filter || v.query || "";
  return String(s || Object.values(v).find(x => typeof x === "string") || "").replaceAll(home, "").replaceAll(home.replace(/\\/g, "/"), "").replace(/^[\\/](?=.)/, "").replace(/\s+/g, " ").slice(0, 120);
};
const TOOL = { running: ["运行中", "info live"], in_progress: ["运行中", "info live"], pending: ["等待", "info"], completed: ["完成", "good"], failed: ["失败", "bad"], stopped: ["已停止", "mute"] };
function part(p, open) {
  if (p.type === "note") return h("p", { class: "muted c-note" }, p.text);
  if (p.type === "think") return h("details", { class: "c-think", open: !!p.live }, h("summary", {}, p.live ? "思考中…" : "思考"), h("div", {}, p.text));
  if (p.type === "tool") {
    return h("details", { class: "c-tool" }, h("summary", {}, icon(p.status === "completed" ? "check" : p.status === "failed" ? "x" : "play", 14), h("b", { class: "mono" }, p.name), h("span", { class: "mono muted" }, brief(p.input)), p.status !== "completed" && chip(...(TOOL[p.status] || [p.status]))),
      h("h5", {}, "输入"), h("pre", {}, JSON.stringify(p.input, null, 2)), p.output && [h("h5", {}, "输出"), h("pre", {}, p.output)]);
  }
  return h("div", { class: "md" }, markdown(p.text, open));
}

const IDEAS = ["这个项目的鉴权是怎么做的？哪些接口免登录？", "画出一次典型请求从入口到数据库的路径", "已有发现里最值得先修的是哪几条？为什么？", "有没有越权风险：只靠前端传来的 id 取数据的接口？", "哪些地方拼接了 SQL 或用了 ${}？逐个判断能不能利用"];
let carried = [];
// From a finding: open the conversation with it attached.
export function askAbout(pid, finding) {
  carried = [finding];
  location.hash = `#/p/${pid}/chat/new`;
}

export function chatView(project, cid) {
  const pid = project.id, base = `/api/projects/${pid}/chats`;
  const side = h("aside", { class: "c-side" }), main = h("section", { class: "c-main" }, loading()), root = h("div", { class: "chat" }, side, main);
  let chat = null, gone = false, refs = carried.map(f => ({ key: f.suppress_key, message: f.message, file: f.file, line: f.line })), parts = [], view = [], busy = false;
  carried = [];
  home = project.path;
  const open = (path, line) => showFile(pid, path, line);
  const go = id => { history.replaceState(null, "", `#/p/${pid}/chat${id ? "/" + id : ""}`); };

  // ---- list ----
  async function list() {
    const d = await attempt(api(base));
    if (!d || gone) return null;
    put(side, btn("新对话", () => start(null), { kind: "primary", ico: "plus" }), h("div", { class: "c-list" }, d.chats.length ? d.chats.map(c => h("div", { class: "c-item" + (chat && chat.id === c.id ? " on" : "") },
      h("button", { type: "button", onclick: () => start(c.id) }, h("b", {}, c.title), h("small", {}, c.running ? "正在回答…" : (c.updated || "").slice(5, 16))),
      iconBtn("edit", "改名", () => rename(c)), iconBtn("trash", "删除", () => remove(c), "red"))) : h("p", { class: "muted" }, "还没有对话")));
    return d;
  }
  function rename(c) {
    const box = input({ value: c.title, "aria-label": "标题" });
    modal("改名", h("div", { class: "form" }, box), close => [btn("取消", close), btn("保存", async () => { if (await attempt(patch(`${base}/${c.id}`, { title: box.value }))) { close(); list(); } }, { kind: "primary" })]);
  }
  async function remove(c) {
    if (!await confirmBox("删除对话", `「${c.title}」会被删除，不可恢复。`, "删除")) return;
    if (!await attempt(post(`${base}/${c.id}/delete`))) return;
    if (chat && chat.id === c.id) start(null); else list();
  }

  // ---- conversation ----
  const feed = h("div", { class: "c-feed", "aria-live": "polite" }), status = h("p", { class: "muted c-status" });
  const box = h("textarea", { rows: 1, placeholder: "问关于这个项目的任何问题，Enter 发送，Shift+Enter 换行", "aria-label": "问题" });
  const tray = h("div", { class: "row wrap c-refs" }), bar = h("div", { class: "row wrap c-bar" });
  const grow = () => { box.style.height = "auto"; box.style.height = Math.min(220, box.scrollHeight + 2) + "px"; };
  box.addEventListener("input", grow);
  box.addEventListener("keydown", e => { if (e.key === "Enter" && !e.shiftKey && !e.isComposing) { e.preventDefault(); ask(); } });
  const near = () => feed.scrollHeight - feed.scrollTop - feed.clientHeight < 120;
  const down = () => { feed.scrollTop = feed.scrollHeight; };

  function bubble(m, i, all) {
    if (m.role === "user") return h("div", { class: "c-msg user" }, (m.refs || []).map(r => h("button", { class: "c-ref", type: "button", onclick: () => open(r.file, r.line) }, icon("bug", 13), r.message)), h("p", {}, m.text));
    const last = i === all.length - 1, words = m.parts.filter(p => p.type === "text").map(p => p.text).join("\n\n");
    const say = { stopped: "已停止", interrupted: "控制台重启，回答被打断", error: m.error }[m.state];
    return h("div", { class: "c-msg agent" }, m.parts.map(p => part(p, open)), say && h("p", { class: m.state === "error" ? "c-bad" : "c-warn" }, say),
      h("div", { class: "row c-foot" }, h("small", { class: "muted" }, `${(m.at || "").slice(5, 16)}${m.seconds ? ` · ${m.seconds} 秒` : ""}`), words && iconBtn("file", "复制回答", () => copy(words)),
        last && m.state !== "done" && m.state !== "running" && btn("继续", () => ask("继续，从刚才断开的地方接着答。"), { ico: "play" }), last && m.state !== "running" && iconBtn("refresh", "重新回答", () => ask(all.slice(0, i).findLast(x => x.role === "user").text))));
  }
  function drawBar() {
    const c = chat && chat.context;
    put(bar, chat && (chat.options || []).map(o => select(o.choices.map(x => [x.value, x.name]), o.value, v => { attempt(post(`${base}/${chat.id}/option`, { id: o.id, value: v })); }, { "aria-label": o.name, title: o.name })),
      c && c.size > 0 && h("small", { class: "muted", title: `${c.used} / ${c.size} token` }, `上下文 ${Math.max(1, Math.round(c.used / c.size * 100))}%`), h("div", { class: "spacer" }),
      busy ? btn("停止", () => attempt(post(`${base}/${chat.id}/stop`)), { kind: "danger", ico: "stop" }) : btn("发送", () => ask(), { kind: "primary", ico: "play" }));
  }
  function drawRefs() {
    put(tray, refs.map(r => h("span", { class: "c-ref" }, icon("bug", 13), r.message, iconBtn("x", "移除", () => { refs = refs.filter(x => x !== r); drawRefs(); }))));
  }
  function draw() {
    const all = chat ? chat.messages : [];
    put(feed, all.length ? all.map(bubble) : h("div", { class: "c-hello" }, h("h3", {}, "问问这个项目"), h("p", { class: "muted" }, "agent 能读完整源码、查已有发现、自己调引擎。回答里的文件位置可以点开。"),
      IDEAS.map(t => h("button", { type: "button", class: "c-idea", onclick: () => ask(t) }, t))));
    put(main, feed, status, h("div", { class: "c-ask" }, tray, box, bar));
    drawBar();
    drawRefs();
    grow();
    down();
  }

  // ---- live answer ----
  let frame = 0;
  function paint() {
    if (frame) return;
    frame = setTimeout(() => { // not a frame: those stop in a hidden tab
      frame = 0;
      const host = feed.querySelector(".c-msg.agent:last-child");
      if (!host || gone) return;
      const stick = near();
      parts.forEach((p, i) => {
        if (!p.dirty && view[i]) return;
        const node = part(p, open), old = view[i];
        if (old && old.open && p.type !== "think") node.open = true;
        if (old && p.type === "think" && !p.live) node.open = false;
        if (old) old.replaceWith(node); else host.insertBefore(node, host.querySelector(".c-foot"));
        view[i] = node;
        p.dirty = false;
      });
      while (view.length > parts.length) view.pop().remove();
      if (stick) down();
    }, 40);
  }
  function apply(e) {
    if (e.op === "add") parts.push({ ...e.part, dirty: true });
    else if (e.op === "append") { parts[e.i].text += e.d; parts[e.i].dirty = true; }
    else if (e.op === "set") parts[e.i] = { ...e.part, dirty: true };
    else if (e.op === "cut") parts.length = e.n;
    else if (e.op === "status") status.textContent = e.text;
    else if (e.op === "usage") { chat.context = e.usage; drawBar(); }
    paint();
  }
  async function follow(seq) {
    const id = chat.id;
    busy = true;
    drawBar();
    while (!gone && chat && chat.id === id) {
      let d;
      try { d = await api(`${base}/${id}/events?since=${seq}`); } catch { await new Promise(r => setTimeout(r, 2000)); continue; }
      if (gone || !chat || chat.id !== id) return;
      d.events.forEach(apply);
      seq = d.seq;
      if (d.over) break;
    }
    if (gone || !chat || chat.id !== id) return;
    busy = false;
    status.textContent = "";
    await show(id, true);
    list();
  }
  async function show(id, stay) {
    const d = await attempt(api(`${base}/${id}`));
    if (!d || gone) return;
    chat = d.chat;
    const live = chat.live;
    busy = !!live;
    const stick = !stay || near();
    parts = live ? live.parts.map(p => ({ ...p, dirty: true })) : [];
    view = [];
    const top = feed.scrollTop;
    draw();
    if (!stick) feed.scrollTop = top;
    status.textContent = live ? live.status : "";
    if (live) { paint(); follow(live.seq); }
  }
  async function start(id) {
    chat = null;
    busy = false;
    status.textContent = "";
    go(id);
    if (id) await show(id); else { draw(); box.focus({ preventScroll: true }); }
    list();
  }
  async function ask(text) {
    const words = (text ?? box.value).trim();
    if (!words || busy) return;
    busy = true;
    if (!chat) {
      const d = await attempt(post(base));
      if (!d) { busy = false; return; }
      chat = d.chat;
      go(chat.id);
    }
    const ok = await attempt(post(`${base}/${chat.id}/send`, { text: words, refs: refs.map(r => r.key) }));
    busy = false;
    if (!ok) return;
    if (text == null) box.value = "";
    refs = [];
    grow();
    await show(chat.id);
    list();
  }

  (async () => {
    const d = await list();
    if (!d) return;
    if (!d.ready) return put(main, empty("agent 还不能用", d.why, btn("去设置", () => { location.hash = "#/settings"; }, { kind: "primary" })));
    await start(cid === "new" ? null : d.chats.some(c => c.id === cid) ? cid : cid ? null : (d.chats[0] || {}).id || null);
  })();
  root.stop = () => { gone = true; };
  return root;
}

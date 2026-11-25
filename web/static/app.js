import { $, api, closeAll, h, iconBtn, put, toast } from "./util.js";
import { findingsPage, intelPage, kbPage, logsPage, overviewPage, rulesPage } from "./pages.js";
import { projectPage, projectsPage } from "./projects.js";
import { settingsPage } from "./settings.js";
import { tasksPage } from "./tasks.js";

const NAV = [
  ["", "总览", overviewPage], ["projects", "项目", projectsPage], ["findings", "发现", findingsPage], ["tasks", "任务", tasksPage],
  ["intel", "情报", intelPage], ["rules", "规则", rulesPage], ["kb", "知识库", kbPage], ["logs", "日志", logsPage], ["settings", "设置", settingsPage],
];
let page = null, live = new Map();

// ---- theme ----
function remembered() { try { return localStorage.getItem("sd-theme"); } catch { return null; } }
function theme(name) {
  document.documentElement.dataset.theme = name;
  put($("#theme"), iconBtn(name === "dark" ? "sun" : "moon", name === "dark" ? "切换到浅色" : "切换到深色", () => {
    const next = name === "dark" ? "light" : "dark";
    try { localStorage.setItem("sd-theme", next); } catch { /* private window */ }
    theme(next);
  }));
}
theme(remembered() === "light" ? "light" : "dark");

// ---- routes: #/page, #/p/<id>/<tab>/<run> ----
function route() {
  const [name = "", ...rest] = location.hash.replace(/^#\/?/, "").split("/").map(decodeURIComponent);
  if (page && page.stop) page.stop();
  closeAll();
  const nav = name === "p" ? "projects" : name;
  document.querySelectorAll("#nav a").forEach(a => {
    const on = a.dataset.p === nav;
    a.classList.toggle("on", on);
    if (on) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current");
  });
  // A fresh root per visit: a slow response for the previous page lands nowhere.
  const root = h("main", { id: "main" });
  $("#main").replaceWith(root);
  const entry = NAV.find(([p]) => p === name) || NAV[0];
  page = name === "p" ? projectPage(root, rest[0], rest[1] || "overview", rest[2] || "") : entry[2](root);
  scrollTo(0, 0);
}
put($("#nav"), NAV.map(([p, label]) => h("a", { href: "#/" + p, "data-p": p }, label)));
addEventListener("hashchange", route);
route();

// ---- task watcher: one poll drives the indicator and tells the page what ended ----
let timer;
async function poll() {
  clearTimeout(timer);
  try {
    if (document.visibilityState === "visible") {
      const d = await api("/api/tasks");
      const now = new Map(d.tasks.filter(t => t.state === "queued" || t.state === "running").map(t => [t.id, t]));
      const ended = d.tasks.filter(t => live.has(t.id) && !now.has(t.id));
      const moved = ended.length > 0 || [...now.values()].some(t => { const o = live.get(t.id); return !o || o.stage !== t.stage || o.state !== t.state; });
      ended.forEach(t => toast(`${t.project} · ${t.label}：${t.state === "done" ? (t.complete === false ? "完成，但不完整" : "完成") : t.error || t.state}`,
        t.state === "done" ? (t.complete === false ? "" : "good") : "bad"));
      live = now;
      put($("#running"), now.size ? h("a", { href: "#/tasks", class: "chip info live" }, `${now.size} 个任务`) : null);
      if (moved && page && page.refresh) page.refresh(ended);
    }
  } catch { /* the banner already says so */ }
  timer = setTimeout(poll, live.size ? 2000 : 8000);
}
document.addEventListener("tasks-changed", poll);
document.addEventListener("visibilitychange", poll);
poll();

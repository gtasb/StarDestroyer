import { api, attempt, btn, chip, confirmBox, drawer, dur, h, iconBtn, loading, panel, post, put, table, TASK } from "./util.js";

const LIVE = t => t.state === "queued" || t.state === "running";

function taskDrawer(t) {
  drawer(`${t.label} · ${t.project}`, h("div", { class: "pad" },
    h("dl", { class: "kv" },
      h("dt", {}, "状态"), h("dd", {}, chip(...TASK[t.state])),
      t.stage && [h("dt", {}, "进度"), h("dd", {}, t.stage)],
      h("dt", {}, "开始"), h("dd", {}, t.started || "—"), h("dt", {}, "用时"), h("dd", {}, dur(t.elapsed_s)),
      t.error && [h("dt", {}, "错误"), h("dd", { class: "c-bad" }, t.error)]),
    (t.gaps || []).length > 0 && [h("h4", {}, "覆盖缺口"), h("ul", {}, t.gaps.map(g => h("li", {}, g)))],
    (t.detail || []).length > 0 && [h("h4", {}, "输出"), h("pre", { class: "mono" }, t.detail.join("\n"))],
    t.state === "done" && h("p", {}, h("a", { href: `#/p/${t.project_id}/${t.kind === "review" ? "sast" : t.kind === "audit" ? "agent" : t.kind}` }, "查看结果"))));
}

export function taskTable(tasks, reload, withProject = true) {
  const act = (t, what) => async () => {
    if (!await attempt(post(`/api/tasks/${t.id}/${what}`))) return;
    document.dispatchEvent(new Event("tasks-changed"));
    reload();
  };
  const resume = ids => async () => {
    if (!await attempt(post("/api/tasks/resume", { ids }), "接着上次继续")) return;
    document.dispatchEvent(new Event("tasks-changed"));
    reload();
  };
  const reviewed = t => t.kind === "review" && t.summary ? `推翻不了 ${t.summary.upheld} · 认为不成立 ${t.summary.refuted} · 无法判断 ${t.summary.uncertain}` : "";
  const audited = t => t.kind === "audit" && t.summary ? `审了 ${t.summary.worked} 个单元，共 ${t.summary.done}/${t.summary.total} · 确认 ${t.summary.confirmed} · 待复核 ${t.summary.needs_review}` : "";
  const say = t => t.state === "running" ? (t.stage || "…") : [t.error, t.saved && `已完成 ${t.saved.done} / ${t.saved.total} 段，可以接着跑`].filter(Boolean).join("；") || [reviewed(t), audited(t), (t.gaps || [])[0]].filter(Boolean).join("；");
  return table({
    columns: [
      { label: "任务", cell: t => [h("div", { class: "t1" }, t.label), withProject && h("div", { class: "t2" }, t.project)], class: "nw" },
      { label: "状态", cell: t => [chip(...TASK[t.state]), t.state === "done" && t.complete === false && chip("不完整", "warn")], class: "nw" },
      { label: "说明", cell: t => h("div", { class: "t2 wrap" }, say(t)) },
      { label: "开始", cell: t => t.started || t.created, class: "nw" },
      { label: "用时", cell: t => dur(t.elapsed_s), class: "nw num" },
      { label: "操作", cell: t => h("div", { class: "ops" }, LIVE(t) ? iconBtn("stop", "取消", act(t, "cancel"), "red") : t.resumable ? iconBtn("play", "接着上次继续", resume([t.id]), "green") : iconBtn("refresh", "重新运行", act(t, "retry"), "green")), class: "nw" },
    ],
    rows: tasks, onRow: taskDrawer, emptyText: "没有任务",
  });
}

// Left behind when the console was closed or restarted.
export function interrupted(tasks, reload, projectId = "") {
  const n = tasks.filter(t => t.resumable && t.state === "interrupted").length;
  if (!n) return null;
  return h("div", { class: "gap info" }, h("b", {}, `${n} 个任务被控制台重启打断`), h("p", {}, "做完的部分都在：引擎从断开的那一段、agent 从没审完的单元和没说完的会话接着来。"),
    btn("全部继续", async () => {
      if (!await attempt(post("/api/tasks/resume", { project_id: projectId }), "接着上次继续")) return;
      document.dispatchEvent(new Event("tasks-changed"));
      reload();
    }, { kind: "primary", ico: "play" }));
}

export function tasksPage(root) {
  const body = h("div", {}, loading());
  async function load() { const d = await attempt(api("/api/tasks")); if (d) put(body, interrupted(d.tasks, load), taskTable(d.tasks, load)); }
  async function clear() {
    if (!await confirmBox("清除任务记录", "只清除已结束任务的记录，不影响扫描结果。", "清除")) return;
    if (await attempt(post("/api/tasks/clear"), "已清除")) load();
  }
  put(root, panel("任务", [btn("刷新", load, { ico: "refresh" }), btn("清除已结束", clear, { ico: "trash" })], body));
  load();
  return { refresh: load };
}

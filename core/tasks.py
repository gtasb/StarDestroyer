"""Background tasks for the console.

One task is one kind of run on one project. It survives page reloads, reports
what it is doing, can be cancelled (the engine's process tree goes with it), and
its result is filed under the project it was started for.
"""

import contextvars
import os
import pathlib
import threading
import time
import traceback
import uuid
from concurrent.futures import ThreadPoolExecutor

from . import build, checkpoint, logging, proc, projects, store

FILE = pathlib.Path(__file__).resolve().parents[1] / ".work" / "tasks" / "tasks.json"
KEEP = 300
WORKERS = 3
KINDS = {"sast": "源码扫描", "secrets": "硬编码", "triage": "依赖筛选", "graph": "攻击面", "tabby": "调用链", "audit": "agent 审计", "review": "复核"}
ENGINES = ("sast", "secrets", "triage", "graph", "tabby")
LIVE = ("queued", "running")
STOPPED = ("interrupted", "cancelled", "failed")


def _sast(p: dict, opt: dict) -> dict:
    from . import toolset
    return toolset.auto_scan(p["path"], opt.get("lang") or p.get("lang") or "auto")


def _secrets(p: dict, opt: dict) -> dict:
    from . import hardcoded
    return hardcoded.scan(p["path"])


def _review(p: dict, opt: dict) -> dict:
    from . import review
    recs = projects.findings(p["path"], "sast") + projects.findings(p["path"], "agent")
    if not recs:
        return {"ok": False, "error": "没有发现可复核"}
    if opt.get("keys"):
        recs = [r for r in recs if r.get("suppress_key") in opt["keys"]]
        for r in recs:  # an explicit request reviews again
            r.pop("review", None)
    if not review.pending(recs):
        return {"ok": False, "error": "没有待复核的发现（都已复核、已标记，或证据无法固定）"}
    out = review.run(recs, p["path"], len(recs) if opt.get("keys") else None)
    if not (out["upheld"] + out["refuted"] + out["uncertain"]):
        return {"ok": False, "error": out["error"] or "复核没有完成"}
    gaps = [f"{out['skipped']} 条超过单次上限，未复核"] if out["skipped"] else []
    if out["unavailable"]:
        gaps.append(f"{out['unavailable']} 条没有完成：{out['error'][:160]}")
    return {"ok": True, "complete": not gaps, "incomplete_reasons": gaps, "review": out}


def _audit(p: dict, opt: dict) -> dict:
    from . import audit
    scope = [k for k in opt.get("scope") or [] if k in audit.KINDS]
    cap = opt.get("max_units")
    width = os.environ.get("AUDIT_CONCURRENCY", "")
    return audit.run(p["path"], scope or None, 50 if cap is None else int(cap),
                     min(int(width), 12) if width.isdigit() and int(width) > 0 else audit.CONCURRENCY)


def _triage(p: dict, opt: dict) -> dict:
    from . import toolset
    return toolset.sca_triage_scan(p["path"], max_lookups=int(opt.get("max_lookups") or 60),
                                   indirect={"0": False, "1": True}.get(str(opt.get("indirect") or "")))


def _graph(p: dict, opt: dict) -> dict:
    from . import asset_graph, toolset
    # The source scan is its own task; folding one in here would run it twice.
    res = toolset.asset_graph_build(p["path"], lookup_cves=False, with_scan=False,
                                    findings=projects.findings(p["path"], "sast"))
    # CVEs are the triage task's job here; not asking twice is not a gap.
    if res.get("ok"):
        res["incomplete_reasons"] = [r for r in res["incomplete_reasons"] if r != asset_graph.NO_CVE]
        res["complete"] = not res["incomplete_reasons"]
    return res


def _tabby(p: dict, opt: dict) -> dict:
    from . import pipeline
    with _TABBY:
        proc.check()
        target, built = opt.get("jar") or p.get("jar") or "", None
        if p.get("build") and not opt.get("jar"):
            built = build.run(p["path"])
            if not built["ok"]:
                return built
            target = built["target"]
        res = pipeline.tabby_audit(target, None, opt.get("mode") or "gadget",
                                   opt.get("heap") or "4g", limit=2000, wait_s=24 * 3600)
        if built and res.get("ok"):
            res["build"] = {k: built[k] for k in ("jars", "notes", "reused", "tail")}
            res["incomplete_reasons"] = built["notes"] + (res.get("incomplete_reasons") or [])
            res["complete"] = not res["incomplete_reasons"]
        return res


_RUN = {"audit": _audit, "review": _review, "sast": _sast, "secrets": _secrets, "triage": _triage, "graph": _graph, "tabby": _tabby}
_TABBY = threading.Semaphore(1)  # one Soot JVM at a time


class Manager:
    def __init__(self):
        self._lock = threading.RLock()
        self._items: dict[str, dict] = {}
        self._controls: dict[str, proc.Control] = {}
        self._waiting: dict[str, tuple] = {}
        self._pool = ThreadPoolExecutor(max_workers=WORKERS, thread_name_prefix="sd-task")

    # ---- state ----
    def load(self) -> None:
        """Called once when the console starts; nothing can still be running then."""
        with self._lock:
            self._items = store.read(FILE, {})
            for t in self._items.values():
                if t["state"] in LIVE:
                    t.update(state="interrupted", ended=_now(), error="控制台重启，任务被中断")
            self._save()

    def _save(self) -> None:
        done = sorted((t for t in self._items.values() if t["state"] not in LIVE), key=lambda t: t["created_ts"])
        for t in done[:-KEEP] if len(done) > KEEP else []:
            self._items.pop(t["id"], None)
        store.write(FILE, self._items)

    def _set(self, tid: str, **kw) -> None:
        with self._lock:
            if tid in self._items:
                self._items[tid].update(kw)
                self._save()

    def list(self, project_id: str = "") -> list[dict]:
        with self._lock:
            items = [dict(t) for t in self._items.values() if not project_id or t["project_id"] == project_id]
        now = time.time()
        for t in items:
            end = t.get("ended_ts") or (now if t["state"] == "running" else t.get("started_ts"))
            t["elapsed_s"] = round(end - t["started_ts"], 1) if t.get("started_ts") and end else None
        items.sort(key=lambda t: t["created_ts"], reverse=True)
        seen = set()
        for t in items:  # the last of its kind, if it did not get to the end, can go on
            slot = (t["project_id"], t["kind"])
            t["resumable"] = slot not in seen and t["state"] in STOPPED
            seen.add(slot)
            if t["resumable"]:
                p = projects.get(t["project_id"])
                t["saved"] = checkpoint.summary(p["path"]).get(t["kind"]) if p else None
        return items

    def get(self, tid: str) -> dict | None:
        return next((t for t in self.list() if t["id"] == tid), None)

    # ---- actions ----
    def submit(self, project: dict, kind: str, params: dict | None = None) -> dict:
        if kind not in KINDS:
            return {"ok": False, "error": f"未知任务: {kind}"}
        params = {k: v for k, v in (params or {}).items()
                  if k in ("lang", "jar", "mode", "heap", "max_lookups", "keys", "scope", "max_units", "indirect", "fresh")}
        if kind == "tabby" and not (params.get("jar") or project.get("jar") or project.get("build")):
            return {"ok": False, "error": f"项目「{project['name']}」没有 jar：在编辑里填写，或打开自动编译"}
        with self._lock:
            for t in self._items.values():
                if (t["project_id"] == project["id"] and t["kind"] == kind and t["state"] in LIVE
                        and t["params"].get("keys") == params.get("keys")):
                    return {"ok": True, "task": dict(t), "duplicate": True}
            tid = uuid.uuid4().hex[:10]
            self._items[tid] = {
                "id": tid, "project_id": project["id"], "project": project["name"], "kind": kind,
                "label": KINDS[kind], "params": params, "state": "queued", "stage": "",
                "created": _now(), "created_ts": time.time(),
            }
            control = self._controls[tid] = proc.Control(lambda s: self._set(tid, stage=s))
            self._save()
            task = dict(self._items[tid])
            # The audit starts from what the engines found, so it waits for them.
            if kind == "audit" and self._engines_live(project["id"]):
                self._items[tid]["stage"] = "等引擎跑完"
                self._waiting[project["id"]] = (tid, project, kind, params, control)
                self._save()
                return {"ok": True, "task": dict(self._items[tid])}
        self._start(tid, project, kind, params, control)
        return {"ok": True, "task": task}

    def _start(self, *job) -> None:
        # A fresh context per task: the control must not leak between pool threads.
        self._pool.submit(contextvars.Context().run, self._execute, *job)

    def _engines_live(self, pid: str) -> bool:
        return any(t["project_id"] == pid and t["kind"] in ENGINES and t["state"] in LIVE for t in self._items.values())

    def _execute(self, tid: str, project: dict, kind: str, params: dict, control: proc.Control) -> None:
        proc.use(control)
        end = {}
        try:
            control.check()
            self._set(tid, state="running", started=_now(), started_ts=time.time())
            if params.get("fresh"):
                checkpoint.clear(project["path"], kind)
            res = _RUN[kind](project, params)
            control.check()
            if res.get("pending"):
                end = {"state": "failed", "error": "建图超时仍未完成"}
            elif not res.get("ok"):
                end = {"state": "failed", "error": res.get("error") or "未知错误",
                       "detail": (res.get("tail") or res.get("stderr_tail") or [])[-20:]}
            elif kind in ("review", "audit"):  # stored per finding and unit, not as a run
                end = {"state": "done", "complete": res["complete"], "gaps": res["incomplete_reasons"],
                       "summary": res.get("review") or {"worked": res["worked"], **res["progress"], **res["status_counts"]}}
            else:
                run = projects.save_artifact(project["path"], kind, res)
                end = {"state": "done", "run": pathlib.Path(run).name, "complete": res.get("complete"),
                       "gaps": (res.get("incomplete_reasons") or [])[:20],
                       "summary": projects.summarize(kind, res)}
                from . import audit
                if audit.load(project["path"])["units"] or kind in ("sast", "triage", "secrets", "tabby") and not res.get("complete", True):
                    audit.refresh(project["path"])  # new leads, new work
        except proc.Cancelled:
            end = {"state": "cancelled", "error": "已取消"}
        except Exception as exc:
            end = {"state": "failed", "error": f"{type(exc).__name__}: {exc}",
                   "detail": traceback.format_exc().splitlines()[-12:]}
            logging.error("tasks", "task crashed", task=tid, kind=kind, error=str(exc))
        finally:
            self._controls.pop(tid, None)
            self._set(tid, stage="", ended=_now(), ended_ts=time.time(), **(end or {"state": "failed"}))
            logging.info("tasks", "task ended", task=tid, kind=kind, state=end.get("state"))
            with self._lock:
                job = None
                if not self._engines_live(project["id"]):
                    job = self._waiting.pop(project["id"], None)
            if job and self._items.get(job[0], {}).get("state") == "queued":
                self._start(*job)

    def cancel(self, tid: str) -> dict:
        t = self.get(tid)
        if not t or t["state"] not in LIVE:
            return {"ok": False, "error": "任务不在运行"}
        control = self._controls.get(tid)
        if control:
            self._set(tid, stage="正在取消…")
            control.cancel()
        with self._lock:
            job = self._waiting.get(t["project_id"])
            if job and job[0] == tid:  # not started yet: nobody else will close it
                del self._waiting[t["project_id"]]
                self._set(tid, state="cancelled", stage="", error="已取消", ended=_now(), ended_ts=time.time())
        return {"ok": True}

    def cancel_project(self, pid: str) -> None:
        for t in self.list(pid):
            if t["state"] in LIVE:
                self.cancel(t["id"])

    def retry(self, tid: str) -> dict:
        t = self.get(tid)
        project = projects.get(t["project_id"]) if t else None
        if not project:
            return {"ok": False, "error": "任务或项目已不存在"}
        return self.submit(project, t["kind"], t["params"])

    def resume(self, ids=None, project_id: str = "") -> dict:
        """Take up what was stopped: finished parts and units are kept, the rest goes on.
        Without ids, everything a restart of the console interrupted."""
        todo = [t for t in self.list(project_id) if t["resumable"] and (t["id"] in ids if ids else t["state"] == "interrupted")]
        started, errors = [], []
        for t in sorted(todo, key=lambda t: t["created_ts"]):
            project = projects.get(t["project_id"])
            if not project:
                errors.append("项目已不存在")
                continue
            r = self.submit(project, t["kind"], {k: v for k, v in t["params"].items() if k != "fresh"})
            (started if r["ok"] else errors).append(r["task"] if r["ok"] else r["error"])
        if not todo:
            errors.append("没有可以继续的任务")
        return {"ok": bool(started), "tasks": started, "errors": errors, "error": errors[0] if errors and not started else None}

    def clear(self) -> dict:
        with self._lock:
            gone = [i for i, t in self._items.items() if t["state"] not in LIVE]
            for i in gone:
                del self._items[i]
            self._save()
        return {"ok": True, "removed": len(gone)}


def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


manager = Manager()

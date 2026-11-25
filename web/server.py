"""Self-hosted console. Thin over core/ -- same rules as adapters/.

Run: python web/run.py
"""

import json
import os
import pathlib
import secrets
import string
import sys
from contextlib import asynccontextmanager
from urllib.parse import urlsplit

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from core import (agents, airules, audit, chat, config, decisions, gaps, hardcoded, intel, kb, ledger, logging, pipeline, pools, projects,
                  providers, records, report, rulebase, rulegen, sarif, sca, toolset)
from core.engines import opengrep, tabby
from core.tasks import KINDS, manager

ROOT = pathlib.Path(__file__).resolve().parent


@asynccontextmanager
async def lifespan(_app):
    manager.load()
    yield
    chat.shutdown()
    for t in manager.list():
        manager.cancel(t["id"])


# /docs loads third-party script into this origin, where it could read the token.
app = FastAPI(title="StarDestroyer", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")

# This console starts processes and reads source, and any web page the user opens
# can send requests to 127.0.0.1. Three independent gates:
#   Host    a rebound DNS name still carries the attacker's hostname
#   Origin  a cross-site request says so
#   token   only a page that could read our HTML has it, so blind requests fail
ALLOWED_HOSTS = {"127.0.0.1", "localhost"}
TOKEN = secrets.token_urlsafe(32)


def _refuse(request: Request) -> str | None:
    h = request.headers
    host = h.get("host", "")
    if urlsplit(f"//{host}").hostname not in ALLOWED_HOSTS:
        return "Host 不被允许"
    if not request.url.path.startswith("/api/"):
        return None
    origin = h.get("origin")
    if origin is not None and origin != f"http://{host}":
        return "跨站请求被拒绝"
    if h.get("sec-fetch-site", "same-origin") not in ("same-origin", "none"):
        return "跨站请求被拒绝"
    if not secrets.compare_digest(h.get("x-sd-token", "").encode(), TOKEN.encode()):
        return "令牌无效，控制台可能已重启，请刷新页面"
    return None


@app.middleware("http")
async def guard(request: Request, call_next):
    try:
        why = _refuse(request)
    except ValueError:  # malformed Host
        why = "Host 不被允许"
    if why:
        resp = JSONResponse({"ok": False, "error": why}, 403)
    else:
        try:
            resp = await call_next(request)
        except Exception as exc:
            logging.error("web", "request failed", path=request.url.path, error=f"{type(exc).__name__}: {exc}")
            resp = JSONResponse({"ok": False, "error": f"{type(exc).__name__}: {exc}"}, 500)
    # Everything shown here may come from audited source: no inline script, no
    # third-party origin, nothing to frame or cache.
    resp.headers["Content-Security-Policy"] = (
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.exception_handler(RequestValidationError)
async def bad_request(_request, exc):
    return JSONResponse({"ok": False, "error": "请求参数无效：" + "；".join(
        f"{'.'.join(map(str, e['loc'][1:]))} {e['msg']}" for e in exc.errors()[:3])}, 422)


class ProjectReq(BaseModel):
    path: str
    name: str = ""
    lang: str = "auto"
    jar: str = ""
    build: str = ""
    indirect: str = ""
    note: str = ""


class ProjectEdit(BaseModel):
    name: str | None = None
    lang: str | None = None
    jar: str | None = None
    build: str | None = None
    indirect: str | None = None
    note: str | None = None


class IdsReq(BaseModel):
    ids: list[str]


class TaskReq(BaseModel):
    ids: list[str]
    kinds: list[str]
    params: dict = {}


class DecisionReq(BaseModel):
    keys: list[str]
    verdict: str = ""
    note: str = ""


class PathReq(BaseModel):
    path: str


class SettingsReq(BaseModel):
    values: dict


NO_PROJECT = {"ok": False, "error": "项目不存在"}


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return (ROOT / "index.html").read_text(encoding="utf-8").replace("__SD_TOKEN__", TOKEN)


# ---- overview ---------------------------------------------------------------
@app.get("/api/health")
def health() -> dict:
    caps = opengrep.capabilities()
    return {"ok": True, "running": sum(t["state"] in ("queued", "running") for t in manager.list()),
            "engines": [
                {"id": "opengrep", "name": "Opengrep", "ready": bool(caps.get("available")),
                 "why": "污点扫描", "fix": caps.get("error") or ""},
                {"id": "tabby", "name": "Tabby", "ready": tabby.available(), "why": "Java 调用图",
                 "fix": "设置 TABBY_JAR"},
                {"id": "opensca", "name": "OpenSCA", "ready": sca.available(), "why": "依赖树（缺失时只读构建文件）",
                 "fix": "设置 OPENSCA_BIN"},
                {"id": "gitleaks", "name": "gitleaks", "ready": bool(hardcoded.binary()), "why": "硬编码（缺失时只有自建规则）",
                 "fix": "安装 gitleaks，或设置 GITLEAKS_BIN"},
                {"id": "agent", "name": "审计 agent（dsh）", "ready": agents.ready()[0], "why": providers.label(),
                 "fix": agents.ready()[1]},
                {"id": "tavily", "name": "Tavily", "ready": intel.available(), "why": "联网检索",
                 "fix": "设置 TAVILY_API_KEY"},
            ]}


@app.get("/api/overview")
def overview() -> dict:
    items = projects.list_all()["projects"]
    total = {"projects": len(items), "confirmed": 0, "needs_review": 0, "vuln_deps": 0, "endpoints": 0, "gaps": 0, "runs": 0}
    gaps = []
    for p in items:
        for kind, meta in p["runs"].items():
            s = meta.get("summary") or {}
            if kind in ("sast", "tabby", "secrets"):
                total["confirmed"] += s.get("confirmed") or 0
                total["needs_review"] += (s.get("needs_review") or 0) + (s.get("needs_dynamic") or 0)
            if kind == "triage":
                total["vuln_deps"] += s.get("kept") or 0
            if kind == "graph":
                total["endpoints"] += s.get("endpoints") or 0
            total["runs"] += 1
            if s.get("complete") is not True:
                total["gaps"] += 1
                gaps.append({"project": p["name"], "id": p["id"], "kind": kind, "label": KINDS[kind],
                             "gaps": s.get("gaps"), "unknown": s.get("complete") is None})
    for p in items:
        s = p["audit"]
        total["confirmed"] += s.get("confirmed", 0)
        total["needs_review"] += s.get("needs_review", 0)
        if s and not s["complete"]:
            total["gaps"] += 1
            gaps.insert(0, {"project": p["name"], "id": p["id"], "kind": "agent", "label": "agent 审计", "gaps": s["gaps"], "unknown": False})
    generated = rulegen.load_manifest()
    return {"ok": True, "total": total, "gaps": gaps[:20],
            "builtin": {"rules": len(rulebase.RULES), "classes": len({c for v in ledger.CLASSES.values() for c in v}),
                        "families": len(rulegen.CATALOG), "generated": sum(len(m) for m in generated.values()),
                        "docs": len(kb.list_docs()), "languages": len(rulebase.SOURCES)},
            "tasks": manager.list()[:8], "projects": items}


def _closed(tasks: list[dict]) -> list[dict]:
    """A gap an agent has closed since is not a gap of that task any more."""
    paths: dict[str, str] = {}
    for t in tasks:
        if t["state"] == "done" and t.get("complete") is False and t.get("gaps") and t["kind"] not in ("review", "audit"):
            if t["project_id"] not in paths:
                paths[t["project_id"]] = (projects.get(t["project_id"]) or {}).get("path", "")
            if paths[t["project_id"]]:
                left = audit.uncovered(paths[t["project_id"]], t["kind"], t["gaps"])
                t.update(gaps=left, complete=not left, by_agent=True)
    return tasks


# ---- projects ---------------------------------------------------------------
@app.get("/api/projects")
def projects_list() -> dict:
    live: dict[str, list] = {}
    last: dict[tuple, dict] = {}
    for t in manager.list():
        if t["state"] in ("queued", "running"):
            live.setdefault(t["project_id"], []).append(t)
        last.setdefault((t["project_id"], t["kind"]), t)
    out = projects.list_all()
    for p in out["projects"]:
        p["live"] = live.get(p["id"], [])
        p["last"] = {k: {"state": t["state"], "error": t.get("error")} for (pid, k), t in last.items() if pid == p["id"]}
    return out


@app.post("/api/projects")
def projects_add(req: ProjectReq) -> dict:
    return projects.add(req.path, req.name, lang=req.lang, jar=req.jar, build=req.build, indirect=req.indirect, note=req.note)


@app.post("/api/projects/delete")
def projects_delete(req: IdsReq) -> dict:
    gone = []
    for pid in req.ids:
        manager.cancel_project(pid)
        if projects.remove(pid)["ok"]:
            gone.append(pid)
    return {"ok": True, "removed": gone}


@app.get("/api/projects/{pid}")
def project_get(pid: str) -> dict:
    p = next((x for x in projects.list_all()["projects"] if x["id"] == pid), None)
    if not p:
        return NO_PROJECT
    prof = toolset.project_profile(p["path"]) if p["exists"] else {}
    return {"ok": True, "project": p, "profile": {k: prof.get(k) for k in (
        "language", "file_counts", "frameworks", "framework_evidence", "build_files")},
        "dependencies": len(prof.get("dependencies") or []), "tasks": _closed(manager.list(pid)[:30])}


@app.patch("/api/projects/{pid}")
def project_edit(pid: str, req: ProjectEdit) -> dict:
    return projects.edit(pid, req.model_dump())


@app.get("/api/projects/{pid}/runs")
def project_runs(pid: str) -> dict:
    p = projects.get(pid)
    return {"ok": True, "runs": projects.history(p["path"])} if p else NO_PROJECT


@app.get("/api/projects/{pid}/artifact/{kind}")
def artifact(pid: str, kind: str, run: str = "") -> dict:
    p = projects.get(pid)
    if not p:
        return NO_PROJECT
    if kind not in projects.KINDS:
        return {"ok": False, "error": "未知产物"}
    data = projects.load_artifact(p["path"], kind, run)
    file = run or pathlib.Path((projects.latest(p["path"]).get(kind) or {}).get("file") or "").name
    if not run and (data or {}).get("incomplete_reasons") and kind in gaps.ENGINES and not any(g["kind"] == kind and g["run"] == file for g in audit.load(p["path"])["engine_gaps"]):
        audit.refresh(p["path"])
    return {"ok": True, "data": data, "covered": [g for g in audit.load(p["path"])["engine_gaps"] if g["kind"] == kind and g["run"] == file]}


@app.get("/api/projects/{pid}/audit")
def audit_get(pid: str) -> dict:
    p = projects.get(pid)
    if not p:
        return NO_PROJECT
    data = audit.load(p["path"])
    ok, why = agents.ready()
    return {"ok": True, **audit.progress(p["path"]), "endpoints": data["endpoints"], "reach": data["reach"],
            "ready": ok, "why": why, "label": providers.label()}


class RuleId(BaseModel):
    id: str


# ---- conversations ----
class SendReq(BaseModel):
    text: str
    refs: list[str] = []


class TitleReq(BaseModel):
    title: str


class OptionReq(BaseModel):
    id: str
    value: str


NO_CHAT = {"ok": False, "error": "没有这个对话"}


@app.get("/api/projects/{pid}/chats")
def chats(pid: str) -> dict:
    if not projects.get(pid):
        return NO_PROJECT
    ok, why = agents.ready()
    return {"ok": True, "chats": chat.listing(pid), "ready": ok, "why": why}


@app.post("/api/projects/{pid}/chats")
def chat_new(pid: str) -> dict:
    return {"ok": True, "chat": chat.create(pid)} if projects.get(pid) else NO_PROJECT


@app.get("/api/projects/{pid}/chats/{cid}")
def chat_get(pid: str, cid: str) -> dict:
    try:
        c = chat.get(pid, cid) if projects.get(pid) else None
    except KeyError:
        c = None
    return {"ok": True, "chat": c} if c else NO_CHAT


@app.patch("/api/projects/{pid}/chats/{cid}")
def chat_rename(pid: str, cid: str, req: TitleReq) -> dict:
    return _chat(pid, lambda p: chat.rename(pid, cid, req.title))


@app.post("/api/projects/{pid}/chats/{cid}/delete")
def chat_delete(pid: str, cid: str) -> dict:
    return _chat(pid, lambda p: chat.delete(pid, cid))


@app.post("/api/projects/{pid}/chats/{cid}/send")
def chat_send(pid: str, cid: str, req: SendReq) -> dict:
    return _chat(pid, lambda p: chat.send(p, cid, req.text, req.refs))


@app.get("/api/projects/{pid}/chats/{cid}/events")
def chat_events(pid: str, cid: str, since: int = 0) -> dict:
    return _chat(pid, lambda p: chat.events(pid, cid, max(0, since)))


@app.post("/api/projects/{pid}/chats/{cid}/stop")
def chat_stop(pid: str, cid: str) -> dict:
    return _chat(pid, lambda p: chat.stop(pid, cid))


@app.post("/api/projects/{pid}/chats/{cid}/option")
def chat_option(pid: str, cid: str, req: OptionReq) -> dict:
    return _chat(pid, lambda p: chat.set_option(pid, cid, req.id, req.value))


def _chat(pid: str, go) -> dict:
    p = projects.get(pid)
    if not p:
        return NO_PROJECT
    try:
        return go(p)
    except KeyError:
        return NO_CHAT


@app.post("/api/projects/{pid}/airules/delete")
def airule_delete(pid: str, req: RuleId) -> dict:
    p = projects.get(pid)
    return airules.remove(p["path"], req.id) if p else NO_PROJECT


@app.get("/api/projects/{pid}/file")
def file_read(pid: str, path: str) -> dict:
    p = projects.get(pid)
    return projects.read_source(p["path"], path) if p else NO_PROJECT


EXPORTS = {"md": ("markdown", "text/markdown"), "sarif": ("sarif", "application/json"),
           "json": ("findings_json", "application/json"), "ledger": ("ledger_json", "application/json")}


@app.get("/api/projects/{pid}/export/{kind}/{fmt}")
def export(pid: str, kind: str, fmt: str, run: str = ""):
    p = projects.get(pid)
    if not p or fmt not in EXPORTS or kind not in (*projects.KINDS, "agent"):
        return JSONResponse(NO_PROJECT, 404)
    key, mime = EXPORTS[fmt]
    if not run and kind in ("sast", "agent", "tabby", "secrets") and fmt != "ledger":
        return _export_now(p, kind, fmt, mime)
    art = projects.load_artifact(p["path"], kind, run) or {}
    name = (art.get("artifacts") or {}).get(key) or ""
    if not name or not projects.inside(pipeline.SCANS_DIR, name) or not pathlib.Path(name).is_file():
        return JSONResponse({"ok": False, "error": "这次运行没有该产物"}, 404)
    return PlainTextResponse(pathlib.Path(name).read_text(encoding="utf-8"), media_type=mime)


def _export_now(p: dict, kind: str, fmt: str, mime: str):
    """What the page shows: engine and agent findings with reviews and decisions applied.
    The files of a run hold only what the engine said at the time."""
    path = p["path"]
    art = projects.load_artifact(path, kind) if kind != "agent" else None
    leaks = projects.load_artifact(path, "secrets") if kind == "sast" else None
    if not art and not leaks and not (kind in ("sast", "agent") and audit.summary(path)):
        return JSONResponse({"ok": False, "error": "还没有可导出的结果"}, 404)
    rows = [r for k in (("sast", "agent", "secrets") if kind == "sast" else (kind,)) for r in projects.findings(path, k)]
    known = projects.findings(path, "secrets")
    if known:
        rows = hardcoded.scrub(rows, known, agents.base_of(path))
    rows.sort(key=lambda r: (_STATE.get(r["status"], 9), _ORDER.get(r.get("severity") or "unknown", 4), r["file"], r["line"] or 0))
    gaps = audit.uncovered(path, kind, (art or {}).get("incomplete_reasons") or [])
    if kind == "sast" and not art:
        gaps.append("没有做引擎扫描")
    if kind == "sast":
        gaps += audit.uncovered(path, "secrets", leaks.get("incomplete_reasons") or []) if leaks else ["没有做硬编码扫描"]
    if kind != "tabby":
        gaps += audit.gaps(path)
    if fmt == "json":
        text = json.dumps({"project": p["name"], "complete": not gaps, "incomplete_reasons": gaps, "findings": rows}, ensure_ascii=False, indent=2)
    else:
        open_ = [r for r in rows if r["status"] != "rejected"]
        text = (json.dumps(sarif.to_sarif(open_, gaps), ensure_ascii=False, indent=2) if fmt == "sarif"
                else report.render(open_, p["name"], gaps, top=0))
    return PlainTextResponse(text, media_type=mime)


# ---- findings ---------------------------------------------------------------
_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
_STATE = {"confirmed": 0, "needs_review": 1, "needs_dynamic": 2, "rejected": 3}


@app.get("/api/findings")
def findings(project_id: str = "", kind: str = "", run: str = "", status: str = "open", severity: str = "",
             rule: str = "", q: str = "", page: int = 1, size: int = 50, cause: str = "", group: str = "") -> dict:
    rows = []
    for p in projects.list_all()["projects"]:
        if project_id and p["id"] != project_id:
            continue
        for k in (kind.split(",") if kind else ["sast", "agent", "secrets", "tabby"]):
            if k in ("sast", "agent", "secrets", "tabby"):
                for r in projects.findings(p["path"], k, run if project_id else ""):
                    rows.append({**r, "project_id": p["id"], "project": p["name"], "kind": k, "cause": records.cause(r), "shown": "refuted" if pipeline.refuted(r) else r["status"]})
    facets = {"status": {}, "severity": {}, "rule": {}, "cause": {}}
    out = []
    needle = q.lower().strip()
    for r in rows:
        hit = {
            "status": not status or (r["status"] != "rejected" if status == "open" else r["shown"] == status),
            "cause": not cause or r["cause"] == cause,
            "severity": not severity or (r.get("severity") or "unknown") == severity,
            "rule": not rule or r["rule_id"] == rule,
        }
        if needle and needle not in f"{r['file']} {r['rule_id']} {r['message']} {r.get('cwe', '')}".lower():
            continue
        # Each facet counts what selecting it would show: filtered by the others only.
        for name, value in (("status", r["shown"]), ("cause", r["cause"]), ("severity", r.get("severity") or "unknown"), ("rule", r["rule_id"])):
            if all(v for k2, v in hit.items() if k2 != name):
                facets[name][value] = facets[name].get(value, 0) + 1
        if all(hit.values()):
            out.append(r)
    out.sort(key=lambda r: (_STATE.get(r["shown"], 9), _ORDER.get(r.get("severity") or "unknown", 9), r["project"], r["file"], r["line"] or 0))
    size = min(max(size, 1), 200)
    page = max(page, 1)
    if group:
        by: dict[str, dict] = {}
        for r in out:
            g = by.setdefault(r["cause"], {"cause": r["cause"], "count": 0, "confirmed": 0, "refuted": 0, "severity": "unknown", "files": set(), "sample": r["message"]})
            g["count"] += 1
            g["confirmed"] += r["shown"] == "confirmed"
            g["refuted"] += r["shown"] == "refuted"
            if r["shown"] != "refuted":
                g["severity"] = min(g["severity"], r.get("severity") or "unknown", key=lambda s: _ORDER.get(s, 9))
            g["files"].add(r["file"])
        groups = sorted(({**g, "files": len(g["files"])} for g in by.values()), key=lambda g: (_ORDER.get(g["severity"], 9), -g["confirmed"], -g["count"]))
        return {"ok": True, "total": len(out), "page": page, "size": size, "facets": facets, "groups": groups, "items": []}
    return {"ok": True, "total": len(out), "page": page, "size": size, "facets": facets,
            "items": out[(page - 1) * size:page * size]}


@app.post("/api/decisions")
def decide(req: DecisionReq) -> dict:
    results = [decisions.put(k, req.verdict, req.note) for k in req.keys]
    failed = [r for r in results if not r["ok"]]
    return {"ok": not failed, "done": len(results) - len(failed),
            "error": failed[0]["error"] if failed else None}


# ---- tasks ------------------------------------------------------------------
@app.get("/api/tasks")
def tasks(project_id: str = "") -> dict:
    return {"ok": True, "tasks": _closed(manager.list(project_id))}


@app.post("/api/tasks")
def tasks_start(req: TaskReq) -> dict:
    started, errors = [], []
    for pid in req.ids:
        p = projects.get(pid)
        if not p:
            errors.append("项目不存在")
            continue
        for kind in req.kinds:
            res = manager.submit(p, kind, req.params)
            (started if res["ok"] else errors).append(res["task"] if res["ok"] else res["error"])
    return {"ok": bool(started), "tasks": started, "errors": errors,
            "error": errors[0] if errors and not started else None}


class ResumeReq(BaseModel):
    ids: list[str] = []
    project_id: str = ""


@app.post("/api/tasks/resume")
def tasks_resume(req: ResumeReq) -> dict:
    return manager.resume(req.ids or None, req.project_id)


@app.post("/api/tasks/clear")
def tasks_clear() -> dict:
    return manager.clear()


@app.post("/api/tasks/{tid}/cancel")
def task_cancel(tid: str) -> dict:
    return manager.cancel(tid)


@app.post("/api/tasks/{tid}/retry")
def task_retry(tid: str) -> dict:
    return manager.retry(tid)


# ---- tools ------------------------------------------------------------------
@app.get("/api/fs")
def browse(path: str = "", jar: bool = False) -> dict:
    """Directory picker: names only, no contents."""
    if path.startswith(("\\\\", "//")):
        return {"ok": False, "error": "不支持网络路径"}
    if not path:
        if os.name == "nt":
            drives = [f"{c}:\\" for c in string.ascii_uppercase if os.path.exists(f"{c}:\\")]
            return {"ok": True, "path": "", "parent": None, "items": [
                {"name": d, "path": d, "dir": True} for d in drives]}
        path = "/"
    here = pathlib.Path(os.path.abspath(path))
    if not here.is_dir():
        here = here.parent
    items = []
    try:
        for e in os.scandir(here):
            try:
                if e.is_dir():
                    items.append({"name": e.name, "path": e.path, "dir": True})
                elif jar and e.name.lower().endswith((".jar", ".war")):
                    items.append({"name": e.name, "path": e.path, "dir": False})
            except OSError:
                continue
    except OSError as exc:
        return {"ok": False, "error": str(exc)}
    parent = "" if here.parent == here else str(here.parent)
    return {"ok": True, "path": str(here), "parent": parent,
            "items": sorted(items, key=lambda i: (not i["dir"], i["name"].lower()))[:1000]}


@app.get("/api/rules")
def rules() -> dict:
    names = {p["id"]: p["name"] for p in projects.list_all()["projects"]}
    return {"ok": True,
            "builtin": [{"id": r["id"], "lang": r["lang"], "cwe": r["cwe"], "message": r["message"],
                         "sources": len(r["sources"]), "sinks": r["sinks"], "yaml": rulebase.render(r)}
                        for r in rulebase.RULES],
            "generated": [{"id": rid, "project": names.get(key, meta.get("root", key)), **meta}
                          for key, m in rulegen.load_manifest().items() for rid, meta in m.items()]}


@app.get("/api/nvd")
def nvd_lookup(product: str, version: str = "") -> dict:
    return toolset.nvd_lookup(product.strip(), version.strip())


@app.get("/api/search")
def web_search(q: str) -> dict:
    return toolset.web_search(q)


@app.get("/api/nday")
def nday(cve: str, product: str = "") -> dict:
    return toolset.n_day_context(cve, product)


@app.get("/api/kb/search")
def kb_search(q: str, k: int = 8) -> dict:
    return {"ok": True, **toolset.rag_preview(q, k)}


@app.post("/api/kb/ingest")
def kb_ingest(req: PathReq) -> dict:
    return toolset.kb_ingest(req.path)


@app.post("/api/kb/delete")
def kb_delete(req: IdsReq) -> dict:
    return {"ok": True, "removed": sum(kb.remove(i)["ok"] for i in req.ids)}


@app.get("/api/kb/docs")
def kb_docs() -> dict:
    return {"ok": True, **toolset.kb_list()}


@app.get("/api/logs")
def logs(n: int = 300, level: str = "", q: str = "") -> dict:
    out = toolset.logs_tail(2000 if q else n, level)
    if q:
        out["lines"] = [x for x in out["lines"] if q.lower() in x.lower()][-n:]
    return {"ok": True, **out}


@app.get("/api/settings")
def settings_get() -> dict:
    return {"ok": True, **config.view(), "pools": pools.stats()}


@app.get("/api/llm")
def llm_get() -> dict:
    ok, why = agents.ready()
    c = providers.chosen()
    return {"ok": True, "providers": providers.listing(), "chosen": {"id": c["id"], "model": c["model"], "base": c["base"]},
            "label": providers.label(), "ready": ok, "why": why, "dsh": agents.dsh_bin(), "access": agents.access(), "access_modes": agents.ACCESS,
            "concurrency": os.environ.get("AUDIT_CONCURRENCY") or str(audit.CONCURRENCY)}


class ModelsReq(BaseModel):
    provider: str
    base: str = ""
    key: str = ""


@app.post("/api/llm/models")
def llm_models(req: ModelsReq) -> dict:
    return providers.models(req.provider, req.base, req.key)


@app.post("/api/llm/test")
def llm_test() -> dict:
    return agents.test()


@app.post("/api/settings")
def settings_set(req: SettingsReq) -> dict:
    config.save(req.values)
    return {"ok": True, **config.view()}

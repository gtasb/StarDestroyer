"""Self-hosted console. Thin over core/ -- same rules as adapters/.

Run: python web/run.py
"""

import asyncio
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from core import config, intel, jobs, llm, pipeline, pools, projects, sca, toolset
from core.engines import opengrep, tabby

config.apply()  # settings file -> env, before anything reads a credential

ROOT = pathlib.Path(__file__).resolve().parent
app = FastAPI(title="StarDestroyer")


class ScanReq(BaseModel):
    path: str = ""
    lang: str = "java"
    ai: bool = False
    verify: bool = False
    auto: bool = True
    project_id: str = ""


class JarReq(BaseModel):
    jar: str = ""
    mode: str = "gadget"
    heap: str = "4g"
    limit: int = 30
    project_id: str = ""


class GraphReq(BaseModel):
    path: str = ""
    lookup_cves: bool = True
    with_scan: bool = True
    project_id: str = ""


class TriageReq(BaseModel):
    path: str = ""
    cvss_min: float = 7.0
    epss_pct_min: float = 0.95
    project_id: str = ""


class KbIngestReq(BaseModel):
    path: str


class SettingsReq(BaseModel):
    values: dict


class ProjectReq(BaseModel):
    path: str
    name: str = ""


class ActivateReq(BaseModel):
    id: str


def _project(pid: str = "") -> dict | None:
    if pid:
        return projects.get(pid)
    idx = projects.list_all()
    return next((p for p in idx["projects"] if p["id"] == idx.get("active")), None)


def _save(proj: dict | None, kind: str, data: dict) -> dict:
    if proj and data.get("ok"):
        data["_artifact"] = projects.save_artifact(proj["path"], kind, data)
    return data


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return (ROOT / "index.html").read_text(encoding="utf-8")


@app.get("/api/health")
def health() -> dict:
    return {
        "opengrep": opengrep.capabilities(),
        "tabby": tabby.available(),
        "opensca": sca.available(),
        "deepseek": llm.available(),
        "tavily": intel.available(),
        "pools": pools.stats(),
    }


@app.get("/api/settings")
def settings_get() -> dict:
    return config.view()


@app.post("/api/settings")
def settings_set(req: SettingsReq) -> dict:
    config.save(req.values)
    return config.view()


@app.get("/api/projects")
def projects_list() -> dict:
    return projects.list_all()


@app.post("/api/projects")
def projects_add(req: ProjectReq) -> dict:
    res = projects.add(req.path, req.name)
    if res.get("ok"):
        res["list"] = projects.list_all()
    return res


@app.post("/api/projects/activate")
def projects_activate(req: ActivateReq) -> dict:
    return projects.activate(req.id)


@app.get("/api/artifacts")
def artifacts(project_id: str = "") -> dict:
    proj = _project(project_id)
    if not proj:
        return {"ok": False, "error": "未选择项目"}
    kinds = projects.latest(proj["path"])
    return {"ok": True, "project": proj, "kinds": kinds,
            "data": {k: projects.load_artifact(proj["path"], k) for k in kinds}}


@app.get("/api/file")
def file_read(project_id: str, path: str) -> dict:
    proj = _project(project_id)
    if not proj:
        return {"ok": False, "error": "未选择项目"}
    return projects.read_source(proj["path"], path)


@app.post("/api/scan")
async def scan(req: ScanReq) -> dict:
    proj = _project(req.project_id)
    path = req.path or (proj["path"] if proj else "")
    res = await toolset.audit_scan(path, req.lang, req.ai, req.verify, auto=req.auto)
    return _save(proj, "sast", res)


@app.post("/api/triage")
async def triage(req: TriageReq) -> dict:
    proj = _project(req.project_id)
    path = req.path or (proj["path"] if proj else "")
    async with pools.acquire("opengrep"):
        res = await asyncio.to_thread(toolset.sca_triage_scan, path,
                                      req.cvss_min, req.epss_pct_min)
    return _save(proj, "triage", res)


@app.post("/api/jar")
async def jar_audit(req: JarReq) -> dict:
    async with pools.acquire("tabby_ingest"):
        res = await asyncio.to_thread(pipeline.tabby_audit, req.jar, None,
                                      req.mode, req.heap, req.limit)
    return _save(_project(req.project_id), "tabby", res)


@app.post("/api/graph")
async def graph_build(req: GraphReq) -> dict:
    proj = _project(req.project_id)
    path = req.path or (proj["path"] if proj else "")
    res = await asyncio.to_thread(toolset.asset_graph_build, path,
                                  req.lookup_cves, req.with_scan)
    return _save(proj, "graph", res)


@app.get("/api/graph/summary")
def graph_summary(db: str) -> dict:
    return toolset.asset_graph_summary(db)


@app.get("/api/job/{job_id}")
def job(job_id: str) -> dict:
    return jobs.status(job_id)


@app.get("/api/logs")
def logs(n: int = 200, level: str = "") -> dict:
    return toolset.logs_tail(n, level)


@app.get("/api/kb/search")
def kb_search(q: str, k: int = 5) -> dict:
    return toolset.kb_search(q, k)


@app.post("/api/kb/ingest")
def kb_ingest(req: KbIngestReq) -> dict:
    return toolset.kb_ingest(req.path)


@app.get("/api/kb/docs")
def kb_docs() -> dict:
    return toolset.kb_list()

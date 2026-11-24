"""Self-hosted web console. Thin over core/ -- same rules as adapters/.

Run: python -m uvicorn web.server:app --port 8770
"""

import asyncio
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from core import jobs, llm, pipeline, pools, toolset
from core import intel
from core.engines import opengrep, tabby

ROOT = pathlib.Path(__file__).resolve().parent
app = FastAPI(title="Code Audit Console")


class ScanReq(BaseModel):
    path: str
    lang: str = "java"
    ai: bool = False
    verify: bool = False
    auto: bool = True


class JarReq(BaseModel):
    jar: str
    mode: str = "gadget"
    heap: str = "4g"
    limit: int = 30


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return (ROOT / "index.html").read_text(encoding="utf-8")


@app.get("/api/health")
def health() -> dict:
    return {
        "opengrep": opengrep.capabilities(),
        "tabby": tabby.available(),
        "deepseek": llm.available(),
        "tavily": intel.available(),
        "pools": pools.stats(),
    }


class GraphReq(BaseModel):
    path: str
    lookup_cves: bool = True
    with_scan: bool = True


@app.post("/api/graph")
async def graph_build(req: GraphReq) -> dict:
    return await asyncio.to_thread(toolset.asset_graph_build, req.path,
                                   req.lookup_cves, req.with_scan)


@app.get("/api/graph/summary")
def graph_summary(db: str) -> dict:
    return toolset.asset_graph_summary(db)


@app.get("/api/rag/preview")
def rag_preview(q: str, k: int = 5) -> dict:
    return toolset.rag_preview(q, k)


@app.post("/api/scan")
async def scan(req: ScanReq) -> dict:
    return await toolset.audit_scan(req.path, req.lang, req.ai, req.verify, auto=req.auto)


class KbIngestReq(BaseModel):
    path: str


@app.get("/api/kb/search")
def kb_search(q: str, k: int = 5) -> dict:
    return toolset.kb_search(q, k)


@app.post("/api/kb/ingest")
def kb_ingest(req: KbIngestReq) -> dict:
    return toolset.kb_ingest(req.path)


@app.get("/api/kb/docs")
def kb_docs() -> dict:
    return toolset.kb_list()


@app.post("/api/jar")
async def jar_audit(req: JarReq) -> dict:
    async with pools.acquire("tabby_ingest"):
        return await asyncio.to_thread(pipeline.tabby_audit, req.jar, None, req.mode, req.heap, req.limit)


@app.get("/api/job/{job_id}")
def job(job_id: str) -> dict:
    return jobs.status(job_id)
